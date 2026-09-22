"""Autonomous API investigation engine for BugTraceAI-API — Phase 6.

Replaces the legacy investigate.py. Key improvements:
  * New hypothesis lifecycle: proposed → testing → supported | refuted |
    inconclusive | blocked_auth | error (replaces ambiguous "pending/confirmed")
  * Pre-iteration checks: stop flag, max_total_tool_calls budget
  * Plan validation: JSON parsing with fallback strategies, tool whitelist check
  * Rate-limited execution with tool-level metrics
  * Response classification (informational vs. suspicious/critical) and
    similarity-based deduplication before adding findings
  * HTML/iframe extraction for clickjacking evidence
  * Safe binary output handling via separate replays
  * Loop termination: no new evidence for 2 consecutive iterations
"""
from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlparse

from lib.apex_client import _generate, get_active_provider
from lib.coverage import body_hash
from lib.evidence import save_artifact
from lib.findings_quality import is_not_found_response
from lib.http_policy import allowed_methods, is_allowed
from lib.investigation_models import (
    Hypothesis,
    InvestigatorBudget,
    InvestigatorState,
    IterationResult,
)
from lib.provider import Provider
from lib.scan_state import scan_state
from tools.auth_probe import run_auth_probe
from tools.authz_probe import run_authz_probe
from tools.blind_attack import run_blind_attack
from tools.coverage_probe import run_coverage_probe
from tools.schema_attack import run_schema_attack

logger = logging.getLogger("bugtrace-api.tools.investigate")
INVESTIGATION_TOOL_TIMEOUT = max(
    5.0, float(os.getenv("BTAI_INVESTIGATION_TOOL_TIMEOUT", "90"))
)

# ── Tool registry ──────────────────────────────────────────────────────────
_TOOL_RUNNERS: dict[str, Any] = {}


def _register_builtin_runners() -> None:
    """Register the built-in tool runners used by the investigation engine."""
    # coverage_probe (wrapper)
    async def _coverage_probe_runner(
        scan_id: str, tool_name: str, url: str, method: str,
        params: dict[str, Any], auth: dict[str, Any] | None,
        auth_alt: dict[str, Any] | None = None,
        allow_mutating: bool = False,
    ) -> list[dict[str, Any]]:
        op = {
            "method": method,
            "url": url,
            "auth_required": auth is not None,
            "parameters": [],
            "source": "investigation",
            "query_params": params or {},
        }
        if params:
            op["parameters"] = [{"name": k, "in": "query"} for k in params]
        rows = await run_coverage_probe(
            scan_id=scan_id,
            operations=[op],
            auth=auth,
            allow_mutating=allow_mutating,
        )
        return rows or []

    # auth_probe
    async def _auth_probe_runner(
        scan_id: str, tool_name: str, url: str, method: str,
        params: dict[str, Any], auth: dict[str, Any] | None,
        auth_alt: dict[str, Any] | None = None,
        allow_mutating: bool = False,
    ) -> list[dict[str, Any]]:
        op = {
            "method": method,
            "url": url,
            "auth_required": auth is not None,
            "parameters": [
                {"name": k, "in": "query"} for k in (params or {})
            ],
        }
        schema = {"paths": {urlparse(url).path or "/": {method.lower(): op}}}
        results = await run_auth_probe(
            scan_id=scan_id,
            target=url,
            schema_url="",
            schema_content=schema,
            auth=auth,
            auth_alt=auth_alt,
            allow_mutating=allow_mutating,
            schema_source="investigation_plan",
        )
        return results or []

    # authz_probe
    async def _authz_probe_runner(
        scan_id: str, tool_name: str, url: str, method: str,
        params: dict[str, Any], auth: dict[str, Any] | None,
        auth_alt: dict[str, Any] | None = None,
        allow_mutating: bool = False,
    ) -> list[dict[str, Any]]:
        if not auth or not auth_alt:
            return [{
                "type": "authz_probe_skipped",
                "title": "Authorization comparison blocked: dual credentials required",
                "severity": "info",
                "classification": "insufficient",
                "status": "blocked",
                "reason": "missing_auth_or_auth_alt",
                "endpoint": url,
                "source": "investigation_plan",
            }]
        op = {
            "method": method,
            "url": url,
            "auth_required": auth is not None,
            "parameters": [
                {"name": k, "in": "query"} for k in (params or {})
            ],
        }
        schema = {"paths": {urlparse(url).path or "/": {method.lower(): op}}}
        results = await run_authz_probe(
            scan_id=scan_id,
            target=url,
            schema_url="",
            schema_content=schema,
            auth=auth,
            auth_alt=auth_alt,
            allow_mutating=allow_mutating,
            schema_source="investigation_plan",
        )
        return results or []

    # schema_attack (schemathesis/offat/vulnapi)
    async def _schema_attack_runner(
        scan_id: str, tool_name: str, url: str, method: str,
        params: dict[str, Any], auth: dict[str, Any] | None,
        auth_alt: dict[str, Any] | None = None,
        allow_mutating: bool = False,
    ) -> list[dict[str, Any]]:
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Scoped investigation operation", "version": "1"},
            "servers": [{"url": f"{urlparse(url).scheme}://{urlparse(url).netloc}"}],
            "paths": {urlparse(url).path or "/": {
                method.lower(): {"operationId": f"{method.lower()}_{url}"}
            }}
        }
        schema_path = save_artifact(
            scan_id, "investigation", f"plan_schema_{int(time.time() * 1000)}", spec
        )
        results = await run_schema_attack(
            scan_id=scan_id,
            schema={"url": str(schema_path), "content": spec},
            target=url,
            auth=auth,
            allow_mutating=allow_mutating,
            persist_findings=False,
            artifact_phase="investigation",
            selected_tools=[tool_name],
        )
        return results or []

    # blind_attack (arjun/x8)
    async def _blind_attack_runner(
        scan_id: str, tool_name: str, url: str, method: str,
        params: dict[str, Any], auth: dict[str, Any] | None,
        auth_alt: dict[str, Any] | None = None,
        allow_mutating: bool = False,
    ) -> list[dict[str, Any]]:
        if not url.startswith(("http://", "https://")):
            raise ValueError("investigation blind attack requires an absolute inventory URL")
        endpoint_url = url
        results = await run_blind_attack(
            scan_id=scan_id,
            endpoints=[{"method": method, "url": endpoint_url}],
            target=endpoint_url,
            auth=auth,
        )
        return results or []

    # Register with original names so tests pass
    _TOOL_RUNNERS["coverage_probe"] = _coverage_probe_runner
    _TOOL_RUNNERS["auth_probe"] = _auth_probe_runner
    _TOOL_RUNNERS["authz_probe"] = _authz_probe_runner
    _TOOL_RUNNERS["schemathesis"] = _schema_attack_runner
    _TOOL_RUNNERS["offat"] = _schema_attack_runner
    _TOOL_RUNNERS["vulnapi"] = _schema_attack_runner
    _TOOL_RUNNERS["blinds"] = _blind_attack_runner
    _TOOL_RUNNERS["arjun"] = _blind_attack_runner
    _TOOL_RUNNERS["x8"] = _blind_attack_runner
    _TOOL_RUNNERS["manual_replay"] = _coverage_probe_runner


_register_builtin_runners()


def register_tool_runner(name: str, runner: Any) -> None:
    """Register a tool runner for use by the investigation engine."""
    _TOOL_RUNNERS[name] = runner
    logger.debug("Registered tool runner: %s", name)


def _get_runner(name: str) -> Any | None:
    return _TOOL_RUNNERS.get(name)


async def _execute_plan_step(
    runner: Any,
    *,
    scan_id: str,
    tool_name: str,
    url: str,
    method: str,
    params: dict[str, Any],
    auth: dict[str, Any] | None,
    auth_alt: dict[str, Any] | None = None,
    allow_mutating: bool = False,
) -> Any:
    """Execute either a ToolRunner object or an async callable.

    Built-in runners are deliberately lightweight async functions, while
    integrations may register objects exposing ``run``.  Keeping the
    compatibility boundary here prevents the investigation loop from making
    assumptions about the runner implementation.
    """
    kwargs = {
        "scan_id": scan_id,
        "tool_name": tool_name,
        "url": url,
        "method": method,
        "params": params,
        "auth": auth,
        "auth_alt": auth_alt,
        "allow_mutating": allow_mutating,
    }
    target = getattr(runner, "run", None)
    if target is None:
        target = runner
    if not callable(target):
        raise TypeError(f"tool runner is not callable: {type(runner).__name__}")
    from lib.evidence import execution_artifact_scope
    from uuid import uuid4
    token = execution_artifact_scope.set(f"{tool_name}-{uuid4().hex}")
    try:
        result = target(**kwargs)
        result = await result if inspect.isawaitable(result) else result
        save_artifact(scan_id, "investigation", "result", {"tool": tool_name, "method": method, "url": url, "observations": result})
        return result
    finally:
        execution_artifact_scope.reset(token)


# ── Plan validation ────────────────────────────────────────────────────────
def _path_matches_inventory(candidate: str, known: str) -> bool:
    """Return whether a planned path is an inventory operation or its template.

    The model may replace an OpenAPI path parameter with a concrete value, but
    it may not introduce a new path segment.  This deliberately conservative
    matcher is the boundary that prevents prompt examples from becoming
    network requests.
    """
    candidate_path = urlparse(candidate).path or "/"
    known_path = urlparse(known).path or "/"
    if candidate_path == known_path:
        return True
    known_parts = known_path.strip("/").split("/")
    candidate_parts = candidate_path.strip("/").split("/")
    if len(known_parts) != len(candidate_parts):
        return False
    return all(
        kp == cp or (
            len(kp) >= 2 and kp.startswith("{") and kp.endswith("}")
        ) or kp.startswith(":")
        for kp, cp in zip(known_parts, candidate_parts)
    )


def _endpoint_is_in_inventory(
    url: str,
    method: str,
    target: str,
    known_endpoints: list[dict[str, Any]] | None,
) -> bool:
    if not known_endpoints:
        return True
    candidate = urlparse(url)
    target_parsed = urlparse(target)
    if candidate.hostname is None or target_parsed.hostname is None:
        return False
    if candidate.hostname.lower() != target_parsed.hostname.lower():
        return False
    if candidate.port != target_parsed.port:
        return False
    for endpoint in known_endpoints:
        if not isinstance(endpoint, dict):
            continue
        endpoint_method = str(endpoint.get("method", "GET")).upper()
        if endpoint_method != method.upper():
            continue
        known_url = str(endpoint.get("url") or endpoint.get("endpoint") or "")
        if not known_url:
            continue
        if not known_url.startswith(("http://", "https://")):
            known_url = urljoin(target, known_url)
        known_parsed = urlparse(known_url)
        if known_parsed.hostname and known_parsed.hostname.lower() != candidate.hostname.lower():
            continue
        if known_parsed.port != candidate.port:
            continue
        if _path_matches_inventory(url, known_url):
            return True
    return False


def validate_plan(
    plan: dict[str, Any], *, target: str = "",
    known_endpoints: list[dict[str, Any]] | None = None,
) -> tuple[bool, list[str]]:
    """Validate a parsed plan. Returns (valid, errors)."""
    errors: list[str] = []
    if not isinstance(plan, dict):
        errors.append("plan is not an object")
        return False, errors

    hypotheses = plan.get("hypotheses") or []
    if not isinstance(hypotheses, list) or not hypotheses:
        errors.append("plan must contain at least one hypothesis")

    steps = plan.get("steps") or plan.get("plan", {}).get("steps", []) or []
    if not isinstance(steps, list) or not steps:
        errors.append("plan must contain at least one step")

    for i, step in enumerate(steps):
        step_id = step.get("id", f"S{i}")
        tool = str(step.get("tool", "coverage_probe")).lower()
        if tool not in {
            "coverage_probe", "auth_probe", "authz_probe",
            "schemathesis", "offat", "vulnapi",
            "blinds", "arjun", "x8", "manual_replay",
            "graphql_probe",
        }:
            errors.append(f"step {step_id}: unknown tool '{tool}'")
        method = str(step.get("method", "GET")).upper()
        if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            errors.append(f"step {step_id}: invalid method '{method}'")
        url = str(step.get("url", ""))
        if not url.startswith(("http://", "https://")):
            errors.append(f"step {step_id}: url must be absolute: '{url}'")
        elif target:
            expected_host = urlparse(target).hostname
            actual_host = urlparse(url).hostname
            if expected_host and actual_host and actual_host.lower() != expected_host.lower():
                errors.append(
                    f"step {step_id}: url host outside scan target: '{actual_host}'"
                )
            elif known_endpoints is not None and not _endpoint_is_in_inventory(
                url, method, target, known_endpoints
            ):
                errors.append(
                    f"step {step_id}: endpoint is not present in the discovered inventory: "
                    f"{method} {url}"
                )
        indicator = str(step.get("expected_indicator", "")).strip()
        if not indicator:
            errors.append(f"step {step_id}: missing expected_indicator")

    return len(errors) == 0, errors


# ── HTML / iframe extraction ──────────────────────────────────────────────
def extract_iframe_evidence(html_content: str, url: str) -> list[dict[str, Any]]:
    """Extract clickjacking-related evidence from HTML content.

    Returns a list of finding dicts if iframes/frameancestors issues are found.
    """
    findings: list[dict[str, Any]] = []
    low = html_content.lower()

    # 1. Detect iframe / frame usage
    if re.search(r"<iframe\b", low) or "frameborder" in low:
        findings.append({
            "type": "iframe_detected",
            "title": "Page loads content in an <iframe>",
            "severity": "low",
            "endpoint": url,
            "classification": "informational",
            "evidence": {"iframe_present": True, "frameborder_detected": "frameborder" in low},
        })

    # 2. Check X-Frame-Options
    xfo = re.search(r"x-frame-options\s*:\s*([^,\s\r\n]+)", low)
    if xfo:
        value = xfo.group(1).strip()
        if value not in ("deny", "sameorigin"):
            findings.append({
                "type": "x_frame_options",
                "title": f"X-Frame-Options: {value}",
                "severity": "medium",
                "endpoint": url,
                "classification": "suspicious",
                "evidence": {"x_frame_options": value},
            })

    # 3. Check CSP frame-ancestors
    csp = re.search(r"content-security-policy\s*:\s*([^,\s\r\n]+)", low)
    if csp and "frame-ancestors" in csp.group(1):
        findings.append({
            "type": "csp_frame_ancestors",
            "title": "CSP frame-ancestors directive present",
            "severity": "low",
            "endpoint": url,
            "classification": "informational",
            "evidence": {"csp_frame_ancestors": csp.group(1).strip()},
        })

    return findings


# ── Converters ─────────────────────────────────────────────────────────────
@dataclass
class ToolExecution:
    tool_name: str
    url: str
    method: str
    result: Any
    duration_ms: float = 0.0
    metrics: dict[str, Any] = field(default_factory=dict)


# ── Build the prompt files ────────────────────────────────────────────────
def _build_plan_prompt(
    target: str,
    endpoints: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    hypotheses: list[dict[str, Any]],
    iterations: list[dict[str, Any]],
    allow_mutating: bool,
    budget: dict[str, Any],
) -> str:
    """Build the planner prompt from config/prompts/investigation_planner.txt."""
    from lib.apex_client import _PROMPTS_DIR
    template_path = _PROMPTS_DIR / "investigation_planner.txt"
    try:
        tpl = template_path.read_text(encoding="utf-8")
    except OSError:
        tpl = (
            "You are the autonomous investigation planner for BugTraceAI-API.\n\n"
            "Given the target, known endpoints, current findings, and allowed tools,\n"
            "output ONLY JSON with this schema:\n"
            '{"hypotheses": [{"id":"H1","title":"...","category":"security",'
            '"target_endpoint":"/api/users/{id}","rationale":"...","confidence":0.7}],\n'
            '"plan": {"steps": [{"id":"S1","hypothesis_id":"H1","tool":"authz_probe",'
            '"method":"GET","url":"/api/users/1","params":{},"expected_indicator":"..."\n'
            '"rationale":"..."}}\n\nRules:\n'
            "- Only reference endpoints from the provided inventory.\n"
            "- Use safe methods unless mutating is explicitly allowed.\n"
            "- Prefer existing built-in tools.\n"
            "- Each hypothesis must include a falsifiable expected indicator.\n"
        )

    endpoints_sample = [
        {
            "method": str(e.get("method", "GET")).upper(),
            "url": str(e.get("url", ""))[:200],
            "status": e.get("status"),
            "source": e.get("source", ""),
        }
        for e in (endpoints or [])[:200]
    ]
    findings_sample = [
        {
            "id": f.get("id", ""),
            "title": f.get("title", f.get("name", "")),
            "severity": f.get("severity", "info"),
            "category": f.get("category", ""),
            "endpoint": f.get("endpoint", ""),
            "classification": f.get("classification", ""),
            "source_tools": f.get("source_tools", []),
            "evidence": f.get("evidence", {}),
        }
        for f in (findings or [])[:20]
    ]
    hypotheses_sample = [
        {
            "id": h.get("id", ""),
            "title": h.get("title", ""),
            "status": h.get("status", ""),
            "confidence": h.get("confidence", 0.5),
            "target_endpoint": h.get("target_endpoint"),
            "tests_run": h.get("tests_run", 0),
            "conclusion": h.get("conclusion"),
        }
        for h in (hypotheses or [])[:10]
    ]
    recent_iterations = iterations[-3:] if iterations else []
    budget_str = json.dumps(budget or {}, indent=2)
    allowed = ", ".join(sorted(allowed_methods(allow_mutating)))

    rendered = (
        tpl
        .replace("{{TARGET}}", str(target or ""))
        .replace("{{ENDPOINTS}}", json.dumps(endpoints_sample, indent=2, default=str))
        .replace("{{FINDINGS}}", json.dumps(findings_sample, indent=2, default=str))
        .replace("{{HYPOTHESES}}", json.dumps(hypotheses_sample, indent=2, default=str))
        .replace("{{RECENT_ITERATIONS}}", json.dumps(recent_iterations, indent=2, default=str))
        .replace("{{ALLOWED_METHODS}}", allowed)
        .replace("{{BUDGET}}", budget_str)
    )
    required = (
        "{{TARGET}}", "{{ENDPOINTS}}", "{{FINDINGS}}", "{{HYPOTHESES}}",
        "{{RECENT_ITERATIONS}}", "{{ALLOWED_METHODS}}", "{{BUDGET}}",
    )
    # A template with no markers silently produced context-free planning in
    # production. Fail closed instead of allowing that regression back in.
    if any(marker not in tpl for marker in required):
        raise RuntimeError("investigation planner prompt contract is missing context markers")
    if any(marker in rendered for marker in required):
        raise RuntimeError("investigation planner prompt still contains unresolved markers")
    return rendered


def _build_adjudicator_prompt(
    iteration: dict[str, Any],
    hypotheses: list[dict[str, Any]],
) -> str:
    """Build the adjudicator prompt from config/prompts/investigation_adjudicator.txt."""
    from lib.apex_client import _PROMPTS_DIR
    template_path = _PROMPTS_DIR / "investigation_adjudicator.txt"
    try:
        tpl = template_path.read_text(encoding="utf-8")
    except OSError:
        tpl = (
            "You are the autonomous investigation adjudicator for BugTraceAI-API.\n\n"
            "Given the iteration findings and the previous state, output ONLY JSON:\n"
            '{"adjudication":"...","hypothesis_updates":{"H1":"confirmed|false_positive|needs_review|insufficient"},'
            '"new_fingerprints":["fp1"],"repeat_fingerprints":["fp2"]}\n\nRules:\n'
            "- confirmed requires direct differential evidence between principals or auth states.\n"
            "- false_positive requires an explicit explanation.\n"
            "- needs_review when evidence is incomplete or ambiguous.\n"
            "- insufficient when no useful signal was obtained.\n"
            "- Do not downgrade prior confirmed without strong contradicting evidence.\n"
        )

    new_findings = iteration.get("findings", [])
    adjudication_prev = iteration.get("adjudication", "")

    # Compute fingerprints for the new findings so the adjudicator can compare
    fingerprints: list[str] = []
    for f in new_findings:
        fp = _compute_fingerprint(f)
        if fp:
            fingerprints.append(fp)

    rendered = (
        tpl
        .replace("{{ITERATION}}", json.dumps(iteration, indent=2, default=str))
        .replace("{{PREVIOUS_HYPOTHESES}}", json.dumps(hypotheses, indent=2, default=str))
        .replace("{{NEW_FINDINGS}}", json.dumps(new_findings[:10], indent=2, default=str))
        .replace("{{PREVIOUS_ADJUDICATION}}", str(adjudication_prev))
        .replace("{{NEW_FINGERPRINTS}}", json.dumps(fingerprints[:20], indent=2))
    )
    required = (
        "{{ITERATION}}", "{{PREVIOUS_HYPOTHESES}}", "{{NEW_FINDINGS}}",
        "{{PREVIOUS_ADJUDICATION}}", "{{NEW_FINGERPRINTS}}",
    )
    if any(marker not in tpl for marker in required):
        raise RuntimeError("investigation adjudicator prompt contract is missing context markers")
    if any(marker in rendered for marker in required):
        raise RuntimeError("investigation adjudicator prompt still contains unresolved markers")
    return rendered


def _compute_fingerprint(finding: dict[str, Any]) -> str | None:
    """Derive a short fingerprint from a finding using body hashing."""
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("category") or ""),
        str(finding.get("endpoint") or ""),
        str(finding.get("url") or ""),
        str(finding.get("method") or ""),
        str(finding.get("status") or ""),
        str(finding.get("body_hash") or ""),
        str(finding.get("classification") or ""),
    ]

    # Try body_hash from lib.coverage if response body is available
    resp_body = finding.get("response_body") or finding.get("evidence", {}).get("body")
    if isinstance(resp_body, (bytes, str)):
        bh = body_hash(resp_body)
        if bh:
            parts.append(bh)

    blob = " ".join(parts)
    if not blob.strip():
        return None

    import hashlib
    return hashlib.sha256(blob.encode()).hexdigest()[:12]


def _is_reportable_finding(value: dict[str, Any]) -> bool:
    """Distinguish a security finding from raw tool response evidence."""
    return any(
        str(value.get(key) or "").strip()
        for key in ("id", "title", "name", "severity", "classification", "finding_type")
    )


def _parse_json_response(text: str, name: str) -> dict[str, Any]:
    """Extract JSON from a model response; try multiple strategies."""
    text = text.strip()
    # Try parsing directly first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try to find JSON in code fences
    import re
    fence_match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Try to find the first { ... } block
    brace_depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == '{':
            if brace_depth == 0:
                start = i
            brace_depth += 1
        elif ch == '}':
            brace_depth -= 1
            if brace_depth == 0 and start >= 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    pass
    raise ValueError(f"Could not parse JSON from {name} response")


async def _generate_valid_plan(
    plan_text: str,
    *,
    planner_prompt: str,
    provider: Provider,
    scan_id: str,
    target: str = "",
    known_endpoints: list[dict[str, Any]] | None = None,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Parse a planner response and make one constrained repair attempt."""
    last_errors: list[str] = []
    candidate = plan_text
    for attempt in range(2):
        try:
            plan_data = _parse_json_response(candidate, "plan")
        except ValueError as exc:
            last_errors = [str(exc)]
        else:
            plan_data = _normalize_plan_data(plan_data, target=target)
            valid, errors = validate_plan(
                plan_data, target=target, known_endpoints=known_endpoints
            )
            if valid:
                return plan_data, []
            last_errors = errors
        if attempt == 1:
            break
        repair_prompt = (
            "Repair the following investigation plan. Return ONLY valid JSON, "
            "with a non-empty hypotheses array and steps array. Every step must "
            "use an allowed tool, an absolute URL, and expected_indicator.\n"
            f"Validation errors: {json.dumps(last_errors)}\n"
            f"Original planner response:\n{candidate[:12000]}\n"
            f"Context:\n{planner_prompt[:4000]}"
        )
        repaired = await _generate(repair_prompt, provider, scan_id=scan_id)
        candidate = repaired.get("text", "") if isinstance(repaired, dict) else ""
    return None, last_errors


def _normalize_plan_data(
    plan: dict[str, Any], *, target: str = ""
) -> dict[str, Any]:
    """Normalize harmless planner aliases before strict validation.

    Models commonly emit ``AUTO`` when they mean a safe default request and
    ``blind_attack`` when they mean the registered ``blinds`` runner.  Both
    are deterministic aliases; silently treating them as unknown would turn
    an otherwise usable plan into a zero-call failure.
    """
    normalized = json.loads(json.dumps(plan, default=str))
    steps = normalized.get("steps")
    if steps is None and isinstance(normalized.get("plan"), dict):
        steps = normalized["plan"].get("steps")
    if not isinstance(steps, list):
        return normalized
    for step in steps:
        if not isinstance(step, dict):
            continue
        tool = str(step.get("tool", "")).lower()
        if tool == "blind_attack":
            step["tool"] = "blinds"
        elif tool == "schema_attack":
            step["tool"] = "schemathesis"
        method = str(step.get("method", "GET")).upper()
        if method in {"AUTO", "ANY"}:
            step["method"] = "GET"
        url = str(step.get("url", "")).strip()
        if url and not url.startswith(("http://", "https://")) and target:
            # Models often copy the path from the inventory. Resolve it against
            # the scan origin before strict validation; never invent a host.
            step["url"] = urljoin(target, url)
        elif url and target:
            # Repair only well-known prompt placeholders. Other foreign
            # origins remain untouched and are rejected by scoped validation.
            parsed = urlparse(url)
            if parsed.hostname in {
                "target.example.com", "target.example", "api.example.com",
                "api.target.local", "example.com",
            }:
                step["url"] = urljoin(target, parsed.path or "/")
    return normalized


def _fallback_plan(
    target: str,
    hypotheses: list[Hypothesis],
    endpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a safe coverage plan when the provider returns unusable JSON."""
    urls: list[str] = []
    for hypothesis in hypotheses:
        candidate = str(hypothesis.target_endpoint or "").strip()
        if candidate:
            urls.append(candidate)
    for endpoint in endpoints:
        candidate = str(endpoint.get("url", "")).strip()
        if candidate:
            urls.append(candidate)
    selected: list[str] = []
    expected_host = urlparse(target).hostname
    for candidate in urls:
        candidate = re.sub(r"^[A-Za-z]+\s+", "", candidate)
        resolved = urljoin(target, candidate)
        if not resolved.startswith(("http://", "https://")):
            continue
        if expected_host and urlparse(resolved).hostname != expected_host:
            continue
        if not _endpoint_is_in_inventory(resolved, "GET", target, endpoints):
            continue
        if resolved not in selected:
            selected.append(resolved)
        if len(selected) >= 10:
            break
    if not selected:
        # Never turn a planner failure into a request to the scan root. The
        # root is only eligible when discovery explicitly recorded it.
        selected = []
    fallback_hypotheses = [h.model_dump() for h in hypotheses[:10]]
    if not fallback_hypotheses:
        fallback_hypotheses = [{
            "id": "H1",
            "title": "Verify target coverage",
            "category": "coverage",
            "target_endpoint": target,
            "rationale": "Provider plan was unavailable; run a safe baseline request",
            "confidence": 0.2,
        }]
    return {
        "hypotheses": fallback_hypotheses,
        "plan": {
            "steps": [
                {
                    "id": f"F{i}",
                    "hypothesis_id": next((str(h.id) for h in hypotheses if re.sub(r"^[A-Z]+\s+", "", h.target_endpoint).rstrip('/') == url.rstrip('/')), ""),
                    "tool": "coverage_probe",
                    "method": "GET",
                    "url": url,
                    "params": {},
                    "expected_indicator": "record response status and body fingerprint",
                }
                for i, url in enumerate(selected, start=1)
            ],
            "rationale": "Safe deterministic fallback after invalid provider output",
        },
    }


async def _post_iteration_adjudication(
    iteration_data: dict[str, Any],
    hypotheses: list[dict[str, Any]],
    provider: Provider,
    scan_id: str,
) -> dict[str, Any]:
    """Ask the model to adjudicate one iteration, failing closed on bad JSON."""
    prompt = _build_adjudicator_prompt(iteration_data, hypotheses)
    generated = await _generate(prompt, provider, scan_id=scan_id)
    text = generated.get("text", "") if isinstance(generated, dict) else ""
    try:
        parsed = _parse_json_response(text, "adjudicator")
    except ValueError as exc:
        logger.warning("[scan:%s] invalid adjudicator response: %s", scan_id, exc)
        return {
            "adjudication": "invalid_adjudicator_response",
            "hypothesis_updates": {},
            "new_fingerprints": [],
            "repeat_fingerprints": [],
            "error": str(exc),
        }
    return parsed if isinstance(parsed, dict) else {}


def _check_iteration_budget(
    started_monotonic: float,
    budget: InvestigatorBudget,
    total_tool_calls: int,
) -> str | None:
    """Return a stop reason when count or wall-clock budget is exhausted."""
    if total_tool_calls >= budget.max_total_tool_calls:
        return "max_total_tool_calls_reached"
    if budget.max_duration_seconds is not None:
        elapsed = time.monotonic() - started_monotonic
        if elapsed >= budget.max_duration_seconds:
            return "max_duration_reached"
    return None


# ── Main investigation loop ───────────────────────────────────────────────
async def run_investigation(
    scan_id: str,
    target: str,
    endpoints: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    auth: dict[str, Any] | None = None,
    auth_alt: dict[str, Any] | None = None,
    allow_mutating: bool = False,
    provider: Provider | None = None,
    budget: InvestigatorBudget | None = None,
    tool_runners: list[Any] | None = None,
    campaigns: dict[str, list[dict[str, Any]]] | None = None,
    campaign_hypotheses: list[dict[str, Any]] | None = None,
) -> InvestigatorState:
    """Run the autonomous investigation loop.

    Phase 6: Given the scan target, discovered endpoints, and quality-gated
    findings, formulate hypotheses about likely vulnerabilities, plan and
    execute targeted validation steps, and iterate until the budget is
    exhausted or all hypotheses reach a conclusive status.

    Returns an InvestigatorState documenting the full loop.
    """
    p = provider or get_active_provider()
    budget = budget or InvestigatorBudget()

    state = InvestigatorState(
        scan_id=scan_id,
        target=target,
        status="pending",
        budget=budget,
        started_at=datetime.now(UTC).isoformat(),
    )

    logger.info(
        f"[scan:{scan_id}] Investigation starting — "
        f"endpoints={len(endpoints)}, findings={len(findings)}, "
        f"provider={p.id}/{p.model}, budget=iter:{budget.max_iterations} "
        f"calls:{budget.max_total_tool_calls}"
    )

    if not p.enabled:
        logger.info(f"[scan:{scan_id}] Investigation disabled (provider disabled)")
        state.status = "completed"
        state.stop_reason = "disabled"
        return state

    # Register provided tool runners
    if tool_runners:
        for tr in tool_runners:
            register_tool_runner(tr.name, tr)

    # Initialize hypotheses from suspicious/high-confidence findings
    suspected_findings = [
        f for f in findings
        if not is_not_found_response(f)
        if (f.get("classification") in {"suspicious", "insufficient"}
            or f.get("severity") in {"high", "critical"})
    ]
    hypotheses: list[dict[str, Any]] = []
    for idx, finding in enumerate(suspected_findings[:10]):
        fid = finding.get("id", f"F-{idx:04d}")
        title = finding.get("title", finding.get("name", "Unknown"))
        endpoint = finding.get("endpoint", "")
        category = finding.get("category", "security")
        hypotheses.append({
            "id": f"H{idx+1}",
            "title": f"Investigate {title[:60]}",
            "category": category,
            "target_endpoint": endpoint,
            "rationale": f"Scanner reported this as {finding.get('severity', 'unknown')}; needs differential evidence",
            "confidence": float(finding.get("confidence", 0.5)),
            "status": "pending",
            "source_finding_id": fid,
        })

    if not hypotheses:
        # No suspicious findings to investigate — still run once for coverage check
        if not endpoints:
            logger.info(f"[scan:{scan_id}] Investigation: nothing to investigate")
            state.status = "completed"
            state.stop_reason = "no_targets"
            return state
        hypotheses.append({
            "id": "H1",
            "title": "Verify endpoint coverage completeness",
            "category": "coverage",
            "target_endpoint": target,
            "rationale": "No suspicious findings; checking if more endpoints exist",
            "confidence": 0.3,
            "status": "proposed",
        })
    elif campaign_hypotheses:
        # Merge pre-computed campaign hypotheses (from Phase 1/2 grouping)
        existing_ids = {h.get("id") for h in hypotheses}
        for ch in campaign_hypotheses:
            if ch.get("id") not in existing_ids:
                hypotheses.append(ch)

    state.hypotheses = [Hypothesis.from_dict(h) for h in hypotheses]
    state.status = "running"

    # Persist initial hypotheses
    save_artifact(scan_id, "investigation", "hypotheses", [h.model_dump() for h in state.hypotheses])

    total_tool_calls = 0
    investigation_started = time.monotonic()
    iterations: list[dict[str, Any]] = []
    consecutive_empty_iterations = 0
    observed_fingerprints: set[str] = set()

    for iteration_num in range(1, budget.max_iterations + 1):
        # ── PRE-ITERATION CHECKS ────────────────────────────────────
        if await _is_stopped(scan_id):
            state.status = "stopped"
            state.stop_reason = "user_requested_stop"
            break

        budget_reason = _check_iteration_budget(
            investigation_started, budget, total_tool_calls
        )
        if budget_reason:
            state.status = "partial"
            state.stop_reason = budget_reason
            break

        iter_budget = min(
            budget.max_tool_calls_per_iteration,
            budget.max_total_tool_calls - total_tool_calls,
        )
        if iter_budget <= 0:
            break

        # ── PLAN ──────────────────────────────────────────────────────
        plan_prompt = _build_plan_prompt(
            target=target,
            endpoints=endpoints,
            findings=findings,
            hypotheses=[h.model_dump() for h in state.hypotheses],
            iterations=iterations,
            allow_mutating=allow_mutating,
            budget={"max_iterations": budget.max_iterations,
                    "max_tool_calls_per_iteration": budget.max_tool_calls_per_iteration,
                    "max_total_tool_calls": budget.max_total_tool_calls,
                    "remaining": budget.max_total_tool_calls - total_tool_calls},
        )
        logger.info(f"[scan:{scan_id}] Investigation iteration {iteration_num}: planning ({len(state.hypotheses)} hypotheses, {total_tool_calls}/{budget.max_total_tool_calls} calls)")

        gen_result = await _generate(plan_prompt, p, scan_id=scan_id)
        plan_text = gen_result.get("text", "")
        if not plan_text:
            logger.warning(f"[scan:{scan_id}] Investigation iteration {iteration_num}: no plan generated")
            state.error = "no_plan_generated"
            state.status = "failed"
            break

        plan_data, plan_errors = await _generate_valid_plan(
            plan_text,
            planner_prompt=plan_prompt,
            provider=p,
            scan_id=scan_id,
            target=target,
            known_endpoints=endpoints,
        )
        if plan_data is None:
            logger.warning(
                f"[scan:{scan_id}] Investigation iteration {iteration_num}: "
                f"invalid plan after repair: {plan_errors}"
            )
            plan_data = _fallback_plan(target, state.hypotheses, endpoints)
            state.error = f"planner_fallback: {plan_errors}"

        raw_steps = plan_data.get("plan", {}).get("steps", plan_data.get("steps", []))
        if not raw_steps or not isinstance(raw_steps, list):
            logger.warning(f"[scan:{scan_id}] Investigation iteration {iteration_num}: empty steps")
            state.error = "empty_steps"
            state.status = "failed"
            break

        # Limit steps this iteration
        steps_to_run = raw_steps[:iter_budget]
        if not steps_to_run:
            logger.warning(f"[scan:{scan_id}] Investigation iteration {iteration_num}: no steps to execute")
            state.error = "empty_steps_in_plan"
            state.status = "failed"
            break

        # ── EXECUTE ───────────────────────────────────────────────────
        iteration_findings: list[dict[str, Any]] = []
        step_records: list[dict[str, Any]] = []
        tool_calls_this_iter = 0

        for step in steps_to_run:
            if total_tool_calls >= budget.max_total_tool_calls:
                break
            budget_reason = _check_iteration_budget(investigation_started, budget, total_tool_calls)
            if budget_reason:
                state.status, state.stop_reason = "partial", budget_reason
                break
            if await _is_stopped(scan_id):
                state.status = "stopped"
                state.stop_reason = "user_requested_stop"
                break

            tool_name = str(step.get("tool", "coverage_probe")).lower()
            method = str(step.get("method", "GET")).upper()
            url = str(step.get("url", ""))
            params = step.get("params") or {}
            hypothesis = next((h for h in state.hypotheses if str(h.id) == str(step.get("hypothesis_id"))), None)
            record = {"id": step.get("id"), "hypothesis_id": step.get("hypothesis_id"), "tool": tool_name, "method": method, "url": url, "status": "pending"}
            step_records.append(record)

            if not is_allowed(method, allow_mutating):
                logger.debug(f"[scan:{scan_id}] Skipping disallowed {method} {url}")
                record["status"] = "blocked_policy"
                continue

            runner = _get_runner(tool_name)
            if runner is None:
                logger.warning(f"[scan:{scan_id}] Unknown tool '{tool_name}' for step {step.get('id')}; falling back to coverage_probe")
                runner = _get_runner("coverage_probe")
                tool_name = "coverage_probe"

            try:
                tool_start = time.monotonic()
                result = await asyncio.wait_for(
                    _execute_plan_step(
                        runner,
                        scan_id=scan_id,
                        tool_name=tool_name,
                        url=url,
                        method=method,
                        params=params,
                        auth=auth,
                        auth_alt=auth_alt,
                        allow_mutating=allow_mutating,
                    ),
                    timeout=INVESTIGATION_TOOL_TIMEOUT,
                )
                tool_duration_ms = int((time.monotonic() - tool_start) * 1000)
                observations = result if isinstance(result, list) else [result]
                blocked = bool(observations) and all(isinstance(r, dict) and (r.get("status") in {"blocked", "error"} or r.get("skipped")) for r in observations)
                record.update(status="blocked" if blocked else "executed", duration_ms=tool_duration_ms, observations=observations)
                if hypothesis:
                    if blocked:
                        hypothesis.status = "blocked_auth" if tool_name == "authz_probe" else "error"
                    else:
                        hypothesis.tests_run += 1
                        hypothesis.last_test_at = datetime.now(UTC).isoformat()
                        hypothesis.status = "testing"

                if isinstance(result, list):
                    for item in result:
                        if not isinstance(item, dict):
                            continue
                        item.setdefault("source", "investigation_plan")
                        item.setdefault("provenance", {
                            "phase": "investigation",
                            "iteration": iteration_num,
                            "step": step.get("id", ""),
                            "tool": tool_name,
                        })
                        item["investigation_iteration"] = iteration_num
                        item["investigation_step"] = step.get("id", "")
                        iteration_findings.append(item)
                        if _is_reportable_finding(item):
                            await scan_state.add_finding(scan_id, item)
                elif isinstance(result, dict):
                    result.setdefault("source", "investigation_plan")
                    result.setdefault("provenance", {
                        "phase": "investigation",
                        "iteration": iteration_num,
                        "step": step.get("id", ""),
                        "tool": tool_name,
                    })
                    result["investigation_iteration"] = iteration_num
                    result["investigation_step"] = step.get("id", "")
                    iteration_findings.append(result)
                    if _is_reportable_finding(result):
                        await scan_state.add_finding(scan_id, result)

                total_tool_calls += 1
                tool_calls_this_iter += 1

                logger.info(
                    f"[scan:{scan_id}] Step {step.get('id')}: "
                    f"{tool_name} {method} {url[:80]} → "
                    f"{len(result if isinstance(result, list) else [result])} finding(s) "
                    f"({tool_duration_ms}ms)"
                )
            except Exception as exc:
                record.update(status="error", error=str(exc)[:500])
                if hypothesis:
                    hypothesis.status = "error"
                logger.warning(
                    f"[scan:{scan_id}] Step {step.get('id')} failed: {exc}"
                )
                # A failed/timeout tool call is evidence about the
                # investigation itself. Preserve it for the adjudicator and
                # count the attempt so it cannot be mistaken for a clean
                # zero-call iteration.
                total_tool_calls += 1
                tool_calls_this_iter += 1
                iteration_findings.append({
                    "type": "tool_execution_error",
                    "title": f"Investigation tool failed: {tool_name}",
                    "severity": "info",
                    "classification": "insufficient",
                    "status": "error",
                    "error": str(exc)[:500],
                    "endpoint": url,
                    "method": method,
                    "source": "investigation_plan",
                    "provenance": {
                        "phase": "investigation",
                        "iteration": iteration_num,
                        "step": step.get("id", ""),
                        "tool": tool_name,
                    },
                })

        # ── ADJUDICATE ────────────────────────────────────────────────
        iteration_data = {
            "iteration_number": iteration_num,
            "tool_calls": tool_calls_this_iter,
            "findings": iteration_findings,
            "steps": step_records,
            "adjudication": "",
            "timestamp": datetime.now(UTC).isoformat(),
        }
        logger.info(f"[scan:{scan_id}] Investigation iteration {iteration_num}: adjudicating ({tool_calls_this_iter} steps executed)")

        adj_data = await _post_iteration_adjudication(
            iteration_data,
            [h.model_dump() for h in state.hypotheses],
            p,
            scan_id,
        )

        iteration_data["adjudication"] = adj_data.get("adjudication", "")
        iteration_data["adjudication_result"] = adj_data

        # Persist the full iteration before considering any stop condition. In
        # the old loop the second empty iteration was discarded by `break`,
        # making the final report look more successful than the evidence trail.
        iterations.append(iteration_data)
        iter_key = f"iter_{iteration_num:03d}"
        save_artifact(scan_id, "investigation", iter_key, iteration_data)

        if adj_data.get("error") or adj_data.get("adjudication") == "invalid_adjudicator_response":
            state.error = "invalid_adjudicator_response"
            state.status = "failed"
            state.stop_reason = "adjudicator_invalid"
            logger.warning(
                "[scan:%s] Investigation stopped: adjudicator response was invalid",
                scan_id,
            )
            break

        # Track fingerprints
        fingerprints = {_compute_fingerprint(f) for f in iteration_findings if f.get("status") not in {"blocked", "error"}}
        fingerprints.discard(None)
        new_fps = sorted(fingerprints - observed_fingerprints)
        observed_fingerprints.update(fingerprints)
        iteration_data["evidence_comparison"] = {"new_fingerprints": new_fps, "delta_count": len(new_fps)}
        save_artifact(scan_id, "investigation", iter_key, iteration_data)
        # Check for no new evidence
        if not new_fps:
            consecutive_empty_iterations += 1
            logger.info(f"[scan:{scan_id}] No new fingerprints this iteration (streak: {consecutive_empty_iterations})")
        else:
            consecutive_empty_iterations = 0

        # Stop if no new evidence for 2 consecutive iterations
        # Apply the last adjudication before stopping, so final state includes
        # the last iteration rather than silently losing its conclusions.

        # Update hypotheses based on adjudication
        hyp_updates = adj_data.get("hypothesis_updates", {})
        status_map = {
            "confirmed": "supported",
            "false_positive": "refuted",
            "needs_review": "testing",
            "insufficient": "inconclusive",
        }
        for h in state.hypotheses:
            h_id = str(h.id)
            if h_id in hyp_updates:
                update = hyp_updates[h_id]
                raw_status = str(update.get("status", "inconclusive") if isinstance(update, dict) else update).strip().lower()
                normalized_status = status_map.get(raw_status)
                if normalized_status is None:
                    for alias in status_map:
                        if alias in raw_status:
                            normalized_status = status_map[alias]
                            break
                desired = normalized_status or raw_status
                # A model verdict cannot resolve an untested hypothesis or
                # cite unrelated coverage calls as differential evidence.
                refs = update.get("evidence_refs", []) if isinstance(update, dict) else []
                valid_refs = {r["id"] for r in step_records if r.get("hypothesis_id") == h_id and r["status"] == "executed"}
                if desired in {"supported", "refuted", "not_applicable"} and (not refs or not set(refs).issubset(valid_refs)):
                    desired = "inconclusive"
                if h.status not in {"blocked_auth", "error"}:
                    h.update_status(desired)
                if isinstance(update, dict):
                    h.conclusion = update.get("reason")

        # Add new hypotheses from the plan if any were created
        new_hyps = plan_data.get("hypotheses", [])
        if isinstance(new_hyps, list):
            existing_ids = {str(h.id) for h in state.hypotheses}
            for nh in new_hyps:
                nh_id = str(nh.get("id", ""))
                if nh_id and nh_id not in existing_ids:
                    state.hypotheses.append(Hypothesis.from_dict(nh))
                    existing_ids.add(nh_id)

        # ── STOP CONDITION: all hypotheses resolved ─────────────────
        conclusive = {"supported", "refuted", "not_applicable"}
        pending = [h for h in state.hypotheses if h.status not in conclusive]
        if not pending:
            state.status = "completed"
            state.stop_reason = "all_hypotheses_resolved"
            logger.info(f"[scan:{scan_id}] All hypotheses resolved after {iteration_num} iterations")
            break
        if state.status in {"stopped", "partial"}:
            break
        if consecutive_empty_iterations >= 2:
            state.status = "partial"
            state.stop_reason = "no_new_evidence"
            break

        # Update progress
        progress = min(0.95, 0.90 + (iteration_num / budget.max_iterations) * 0.05)
        await scan_state.update_scan(
            scan_id,
            current_phase="investigation",
            progress=progress,
        )
        await scan_state.update_tool_health(
            scan_id, "investigator",
            status="running",
            attempts=iteration_num,
            findings_count=len(iteration_findings),
            duration_ms=tool_calls_this_iter * 1000,
        )

    # ── FINALISE ────────────────────────────────────────────────────
    state.iterations = [
        IterationResult.from_dict(i) for i in iterations
    ]
    state.total_tool_calls = total_tool_calls
    state.finished_at = datetime.now(UTC).isoformat()

    # Keep investigation-only evidence separate from the provisional Phase 4
    # findings. The orchestrator's final aggregation merges this artifact so
    # the public report is built from the complete evidence set.
    investigation_evidence: list[dict[str, Any]] = []
    investigation_findings: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()
    for iteration in iterations:
        for finding in iteration.get("findings", []):
            if not isinstance(finding, dict):
                continue
            investigation_evidence.append(finding)
            if not _is_reportable_finding(finding):
                continue
            fingerprint = _compute_fingerprint(finding) or json.dumps(
                finding, sort_keys=True, default=str
            )
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)
            investigation_findings.append(finding)
    save_artifact(scan_id, "investigation", "findings", investigation_findings)
    save_artifact(scan_id, "investigation", "evidence", investigation_evidence)

    # Determine overall status (only if not already set by an early break)
    if state.status in ("pending", "running"):
        if all(h.is_resolved() for h in state.hypotheses):
            state.status = "completed"
            state.stop_reason = "hypotheses_supported"
        elif total_tool_calls == 0:
            state.status = "partial"
            state.stop_reason = "no_tool_calls"
        elif state.stop_reason is None:
            state.stop_reason = "budget_exhausted"
            state.status = "partial"

    # Persist final state and aggregate artifacts
    save_artifact(scan_id, "investigation", "state", state.model_dump())
    save_artifact(scan_id, "investigation", "hypotheses", [h.model_dump() for h in state.hypotheses])
    if iterations:
        save_artifact(scan_id, "investigation", "iterations", iterations)

    # Build iterations index
    iter_index = {
        "count": len(iterations),
        "iterations": [
            {
                "number": i.get("iteration_number"),
                "tool_calls": i.get("tool_calls"),
                "timestamp": i.get("timestamp"),
                "findings_count": len(i.get("findings", [])),
            }
            for i in iterations
        ],
    }
    save_artifact(scan_id, "investigation", "iterations_index", iter_index)

    # Update tool health to completed
    duration_ms = int(
        max(0.0, (datetime.now(UTC) - datetime.fromisoformat(state.started_at)).total_seconds()) * 1000
    ) if state.started_at else 0
    await scan_state.update_tool_health(
        scan_id, "investigator",
        status="ok" if state.status == "completed" else state.status,
        attempts=state.total_tool_calls,
        findings_count=len(iterations),
        duration_ms=duration_ms,
    )

    logger.info(
        f"[scan:{scan_id}] Investigation completed: "
        f"{len(state.hypotheses)} hypotheses ({sum(h.is_resolved() for h in state.hypotheses)} resolved), "
        f"{state.total_tool_calls} tool calls, "
        f"{len(iterations)} iterations, "
        f"status={state.status}, stop_reason={state.stop_reason}, "
        f"duration={duration_ms}ms"
    )
    return state


async def _is_stopped(scan_id: str) -> bool:
    """Check if a scan has been stopped."""
    try:
        return await scan_state.is_stopped(scan_id)
    except Exception:
        return False
