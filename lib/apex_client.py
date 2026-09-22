"""
apex_client.py — Async AI-provider integration for BugTraceAI-API.

Used by the orchestrator as Phase 5 (optional AI analysis). The active provider
(local Ollama, OpenRouter, Z.ai, Anthropic, …) is resolved from config/apex.json
via lib.provider — see that module for the config format.

If the active provider is not reachable / not configured, all functions degrade
gracefully and return empty results (the scan never fails because of Phase 5).
"""

import asyncio
import json
import logging
import os
import re
import time
from collections.abc import Awaitable, Callable
from datetime import UTC
from functools import lru_cache
from pathlib import Path
from typing import Any

import httpx

from lib.findings_quality import is_not_found_response
from lib.poc_validation import replay_safe_poc, replay_request, request_from_finding
from lib.provider import Provider, get_active_provider

logger = logging.getLogger("bugtrace-api.lib.apex_client")

# ── Prompts directory ──────────────────────────────────────────────────────
# Templates live in config/prompts/*.txt — keep them out of code so they can be
# edited, reviewed, and translated without touching logic. Override the location
# with $PROMPTS_DIR for tests / forks.
_PROMPTS_DIR = Path(
    os.environ.get("PROMPTS_DIR")
    or (Path(__file__).resolve().parent.parent / "config" / "prompts")
)


@lru_cache(maxsize=8)
def _load_prompt(name: str) -> str:
    """Load a prompt template from config/prompts/<name>.txt.

    Tokens in the template use the {{TOKEN}} form (e.g. {{TITLE}}, {{EVIDENCE}}).
    Because the placeholder for {{EVIDENCE}} is filled with a JSON dump that
    contains literal `{` and `}`, callers must do plain str.replace() (NOT
    str.format) so those braces are not re-interpreted as format fields.
    """
    path = _PROMPTS_DIR / f"{name}.txt"
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            f"prompt template not found: {path} "
            f"(set $PROMPTS_DIR or create the file)"
        ) from exc

# ── Backward-compatible module constants (derived from the active provider) ───
# These are read at import time and kept for callers/logging that reference them.
_ACTIVE = get_active_provider()
APEX_ENABLED      = _ACTIVE.enabled
APEX_MIN_SEVERITY = _ACTIVE.min_severity
APEX_MODEL        = _ACTIVE.model
OLLAMA_URL        = _ACTIVE.base_url   # legacy name; really the provider base_url

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Some scanners record the standards/documentation page for a finding as its
# endpoint. Keep that link in the evidence, but make the tested target the
# endpoint used for AI analysis and PoC generation.
_REFERENCE_URL_RE = re.compile(
    r"(?:developer\.mozilla\.org|cwe\.mitre\.org|owasp\.org|portswigger\.net/web-security)",
    re.IGNORECASE,
)

# Per-provider-request timeout (seconds). The item-level timeout below bounds
# the whole PoC+replay+review chain, including model failover.
GENERATE_TIMEOUT = 300
# Keep online analysis bounded and concurrent. Previously findings were handled
# serially, so a slow/refused OpenRouter response could consume the whole
# one-hour scan budget before a report became available.
APEX_CONCURRENCY = max(1, int(os.getenv("BTAI_APEX_CONCURRENCY", "4")))
APEX_ITEM_TIMEOUT = max(10, float(os.getenv("BTAI_APEX_ITEM_TIMEOUT", "180")))
# Quick health-check timeout
HEALTH_TIMEOUT   = 5


async def is_available(provider: Provider | None = None) -> bool:
    """Return True if the active provider is reachable and usable."""
    p = provider or get_active_provider()
    if p.kind == "ollama":
        try:
            async with httpx.AsyncClient(timeout=HEALTH_TIMEOUT) as client:
                r = await client.get(f"{p.base_url}/api/tags")
                r.raise_for_status()
                models = [m["name"] for m in r.json().get("models", [])]
                if p.model not in models:
                    logger.warning(f"[apex] Model '{p.model}' not found. Available: {models}")
                    return False
                return True
        except Exception as e:
            logger.warning(f"[apex] Ollama not reachable at {p.base_url}: {e}")
            return False
    # OpenAI-compatible providers are remote services.  A configured key and
    # URL are not enough: scans must prove that the online endpoint is
    # reachable before silently downgrading AI analysis.  Probe the provider's
    # low-cost models endpoint (OpenRouter and the other compatible gateways
    # expose this alongside /chat/completions) and keep the request bounded.
    if not p.api_key:
        logger.warning(f"[apex] Provider '{p.id}' has no API key configured")
        return False
    if not p.base_url:
        logger.warning(f"[apex] Provider '{p.id}' has no base_url configured")
        return False
    # Anthropic uses a different messages API and has no compatible /models
    # contract here; its existing request path performs the real reachability
    # check.  Keep the historical configuration check for that provider.
    if p.kind != "openai":
        return True
    base = str(p.base_url).rstrip("/")
    if base.endswith("/chat/completions"):
        base = base[: -len("/chat/completions")]
    models_url = f"{base}/models"
    try:
        async with httpx.AsyncClient(timeout=HEALTH_TIMEOUT, follow_redirects=True) as client:
            response = await client.get(
                models_url,
                headers={"Authorization": f"Bearer {p.api_key}", "Accept": "application/json"},
            )
            response.raise_for_status()
        return True
    except Exception as exc:
        logger.warning(f"[apex] Provider '{p.id}' online probe failed at {models_url}: {exc}")
        return False


def _severity(finding: dict[str, Any]) -> str:
    return (finding.get("severity") or finding.get("risk") or "info").lower()


def filter_findings(findings: list[dict[str, Any]], min_severity: str = APEX_MIN_SEVERITY) -> list[dict[str, Any]]:
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)
    return [
        f for f in findings
        if not is_not_found_response(f)
        and SEVERITY_RANK.get(_severity(f), 0) >= min_rank
    ]


def _finding_endpoint(finding: dict[str, Any], target: str = "") -> str:
    """Return the tested endpoint, not a standards/reference URL."""
    endpoint = finding.get("endpoint", finding.get("url", finding.get("path", "Unknown")))
    value = str(endpoint or "").strip()
    if target and (not value or _REFERENCE_URL_RE.search(value)):
        return str(target)
    return value or "Unknown"


def build_prompt(finding: dict[str, Any], target: str = "") -> str:
    """Render the PoC-builder prompt from config/prompts/poc_builder.txt.

    Tokens filled in (in this order so `{{EVIDENCE}}` — which contains literal
    braces from a JSON dump — does not break a `str.format` parser downstream):
      {{TARGET}}, {{TITLE}}, {{SEVERITY}}, {{CATEGORY}}, {{ENDPOINT}},
      {{TOOLS}}, {{EVIDENCE}}, {{CURL}}
    """
    title    = finding.get("title", finding.get("name", "Unknown"))
    severity = _severity(finding).upper()
    category = finding.get("category", finding.get("type", "Unknown"))
    endpoint = _finding_endpoint(finding, target)
    evidence = json.dumps(finding.get("evidence", finding.get("details", {})), indent=2, default=str)
    repro    = finding.get("repro", {})
    curl_cmd = repro.get("curl", finding.get("curl_example", "N/A"))
    tools    = ", ".join(finding.get("source_tools", finding.get("tools", [])))
    target_label = target or "target API"

    tpl = _load_prompt("poc_builder")
    return (
        tpl
        .replace("{{TARGET}}",   target_label)
        .replace("{{TITLE}}",    str(title))
        .replace("{{SEVERITY}}", str(severity))
        .replace("{{CATEGORY}}", str(category))
        .replace("{{ENDPOINT}}", str(endpoint))
        .replace("{{TOOLS}}",    tools)
        .replace("{{EVIDENCE}}", evidence)
        .replace("{{CURL}}",     curl_cmd)
    )


def build_review_prompt(
    finding: dict[str, Any], poc: str, validation: dict[str, Any], target: str,
) -> str:
    """Build a second-pass critical review prompt for one generated PoC."""
    template = _load_prompt("poc_review")
    return (
        template
        .replace("{{TARGET}}", target or "target API")
        .replace("{{TITLE}}", str(finding.get("title", finding.get("name", "Unknown"))))
        .replace("{{SEVERITY}}", _severity(finding).upper())
        .replace("{{ENDPOINT}}", _finding_endpoint(finding, target))
        .replace("{{POC}}", poc[:14000])
        .replace("{{VALIDATION}}", json.dumps(validation, indent=2, default=str)[:6000])
    )


def _parse_structured_review(text: str) -> dict[str, Any] | None:
    """Parse the critical review without treating any response as a verdict."""
    if not text:
        return None
    candidates = [text.strip()]
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        candidates.insert(0, fenced.group(1))
    start, end = text.find("{"), text.rfind("}")
    if start >= 0 and end > start:
        candidates.append(text[start:end + 1])
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(value, dict):
            continue
        verdict = str(value.get("verdict", "")).lower().strip()
        if verdict not in {"sound", "needs_revision", "weak_evidence", "not_exploitable"}:
            continue
        confidence = value.get("confidence")
        try:
            confidence = max(0.0, min(100.0, float(confidence))) if confidence is not None else None
        except (TypeError, ValueError):
            confidence = None
        issues = value.get("issues", [])
        if isinstance(issues, str):
            issues = [issues]
        return {
            "verdict": verdict,
            "confidence": confidence,
            "issues": issues if isinstance(issues, list) else [],
            "corrected_validation": value.get("corrected_validation"),
        }
    return None


def _semantic_report_status(review: dict[str, Any], validation: dict[str, Any]) -> str:
    """Map review + replay evidence to a conservative public status."""
    verdict = str(review.get("verdict") or "unparsed").lower()
    if validation.get("not_found"):
        return "refuted"
    if review.get("status") != "ok":
        return "inconclusive"
    if verdict in {"not_exploitable", "weak_evidence"}:
        return "inconclusive"
    if verdict == "needs_revision":
        return "needs_revision"
    if verdict == "sound" and validation.get("status") == "replayed" and validation.get("matches_evidence"):
        return "replay_matches_evidence"
    return "inconclusive"


def build_scan_review_prompt(
    findings: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    schema: dict[str, Any] | None,
    target: str,
    pocs: list[dict[str, Any]] | None = None,
) -> str:
    """Build a bounded whole-scan coverage and correlation review prompt."""
    compact_findings = [
        {
            "id": f.get("id"),
            "title": f.get("title", f.get("name")),
            "severity": _severity(f),
            "category": f.get("category"),
            "endpoint": _finding_endpoint(f, target),
            "source_tools": f.get("source_tools", f.get("tools", [])),
            "evidence_keys": sorted((f.get("evidence") or {}).keys()) if isinstance(f.get("evidence"), dict) else [],
        }
        for f in findings[:200]
    ]
    compact_endpoints = [
        {
            "method": str(e.get("method", "GET")).upper(),
            "url": str(e.get("url", ""))[:500],
            "status": e.get("status"),
            "source": e.get("source"),
        }
        for e in endpoints[:300]
        if isinstance(e, dict)
    ]
    schema_summary = {
        "available": bool(schema),
        "source": schema.get("source") if isinstance(schema, dict) else None,
        "url": schema.get("url") if isinstance(schema, dict) else None,
        "coverage": schema.get("coverage") if isinstance(schema, dict) else None,
        "coverage_status": schema.get("coverage_status") if isinstance(schema, dict) else "unknown",
        "paths_count": len((schema.get("content") or {}).get("paths", {})) if isinstance(schema, dict) and isinstance(schema.get("content"), dict) else 0,
    }
    compact_pocs = [
        {
            "finding_id": p.get("finding_id"),
            "endpoint": p.get("endpoint"),
            "validation": p.get("validation"),
            "review": (p.get("review") or {}).get("verdict")
                if isinstance(p.get("review"), dict) else None,
            "error": p.get("error"),
        }
        for p in (pocs or [])[:100]
        if isinstance(p, dict)
    ]
    template = _load_prompt("scan_review")
    return (
        template
        .replace("{{TARGET}}", target or "target API")
        .replace("{{FINDINGS}}", json.dumps(compact_findings, indent=2, default=str))
        .replace("{{ENDPOINTS}}", json.dumps(compact_endpoints, indent=2, default=str))
        .replace("{{SCHEMA}}", json.dumps(schema_summary, indent=2, default=str))
        .replace("{{POCS}}", json.dumps(compact_pocs, indent=2, default=str))
    )


# Phrases that signal a model declined the task. Matched against the start of the
# response only, so a legitimate PoC mentioning "cannot" in its remediation text
# is not mistaken for a refusal.
REFUSAL_MARKERS = (
    "i can't help", "i cannot help", "i can't assist", "i cannot assist",
    "i can't provide", "i cannot provide", "i won't provide", "i will not provide",
    "i'm not able to", "i am not able to", "i'm unable to", "i am unable to",
    "i can't create", "i cannot create", "i can't write", "i cannot write",
    "i'm sorry, but i can", "i am sorry, but i can", "sorry, i can't", "sorry, i cannot",
    "i must decline", "i have to decline", "i do not feel comfortable",
    "i don't feel comfortable", "as an ai", "i can't comply", "i cannot comply",
    "against my guidelines", "i'm not going to", "i am not going to",
)


def _is_refusal(text: str) -> bool:
    """Heuristic: did the model decline the task instead of producing a PoC?"""
    if not text or not text.strip():
        return True
    head = text.strip().lower()[:300]
    return any(m in head for m in REFUSAL_MARKERS)


async def _call_ollama(prompt: str, p: Provider, model: str) -> str:
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": p.options or {"temperature": 0.1, "num_predict": 2048},
    }
    async with httpx.AsyncClient(timeout=GENERATE_TIMEOUT) as client:
        r = await client.post(f"{p.base_url}/api/generate", json=payload)
        r.raise_for_status()
        data = r.json()
        return Generation(data.get("response", "").strip(), data.get("done_reason"), {"output_tokens": data.get("eval_count"), "input_tokens": data.get("prompt_eval_count")})


async def _call_openai(prompt: str, p: Provider, model: str) -> str:
    """Call any OpenAI-compatible /chat/completions endpoint (OpenRouter, Z.ai, …)."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
        **(p.options or {"temperature": 0.1, "max_tokens": 2048}),
    }
    headers = {
        "Authorization": f"Bearer {p.api_key}",
        "Content-Type": "application/json",
        **(p.headers or {}),
    }
    async with httpx.AsyncClient(timeout=GENERATE_TIMEOUT) as client:
        r = await client.post(p.base_url, json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
        choice = data["choices"][0]
        return Generation((choice["message"]["content"] or "").strip(), choice.get("finish_reason"), data.get("usage"))


async def _call_anthropic(prompt: str, p: Provider, model: str) -> str:
    """Call the native Anthropic Messages API (x-api-key auth, not OpenAI-compatible)."""
    payload = {
        "model": model,
        "max_tokens": (p.options or {}).get("max_tokens", 2048),
        "messages": [{"role": "user", "content": prompt}],
    }
    headers = {
        "x-api-key": p.api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
        **(p.headers or {}),
    }
    async with httpx.AsyncClient(timeout=GENERATE_TIMEOUT) as client:
        r = await client.post(p.base_url, json=payload, headers=headers)
        r.raise_for_status()
        data = r.json()
        text = "".join(
            block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
        ).strip()
        return Generation(text, data.get("stop_reason"), data.get("usage"))


class Generation(str):
    """String-compatible generation carrying provider completion metadata."""
    def __new__(cls, text, finish_reason=None, usage=None):
        obj = super().__new__(cls, text)
        obj.finish_reason = finish_reason
        obj.usage = usage
        return obj


async def _generate_once(prompt: str, p: Provider, model: str) -> str:
    """Dispatch a single generation call to the right backend for one model."""
    if p.kind == "ollama":
        return await _call_ollama(prompt, p, model)
    if p.kind == "anthropic":
        return await _call_anthropic(prompt, p, model)
    return await _call_openai(prompt, p, model)


async def _generate(prompt: str, p: Provider, scan_id: str = "") -> dict[str, Any]:
    """Generate a PoC, walking the model failover chain on errors or refusals.

    Tries p.model first, then each entry in p.model_failover in order. A model is
    skipped if the call errors OR the output looks like a refusal. Returns
    {"text", "model", "refused_chain"} — text may be empty if every model failed.
    """
    chain = [p.model] + [m for m in p.model_failover if m and m != p.model]
    refused_chain: list[str] = []
    last_err: str | None = None

    for idx, model in enumerate(chain):
        try:
            text = await _generate_once(prompt, p, model)
        except Exception as e:
            last_err = f"{model}: {e}"
            logger.warning(f"[scan:{scan_id}][apex] model '{model}' errored: {e}")
            refused_chain.append(f"{model} (error)")
            continue

        if _is_refusal(text):
            logger.warning(f"[scan:{scan_id}][apex] model '{model}' refused — trying next")
            refused_chain.append(f"{model} (refused)")
            continue

        if idx > 0:
            logger.info(f"[scan:{scan_id}][apex] failover succeeded with '{model}'")
        finish = getattr(text, "finish_reason", None)
        truncated = finish in {"length", "max_tokens"}
        return {"text": str(text), "model": model, "refused_chain": refused_chain,
                "finish_reason": finish, "usage": getattr(text, "usage", None),
                "truncated": truncated, "error": "generation_truncated" if truncated else None}

    # Exhausted the chain
    return {"text": "", "model": None, "refused_chain": refused_chain, "error": last_err}


async def analyze_findings(
    findings: list[dict[str, Any]],
    target: str = "",
    min_severity: str | None = None,
    provider: Provider | None = None,
    scan_id: str = "",
    # Legacy kwargs (ignored — kept so old callers don't break)
    ollama_url: str | None = None,
    model: str | None = None,
    on_result: Callable[[dict[str, Any]], Awaitable[None]] | None = None,
) -> list[dict[str, Any]]:
    """
    Run AI analysis on findings above min_severity threshold using the active provider.

    Returns a list of dicts with keys:
      finding_id, title, severity, endpoint, poc (markdown text), validation,
      review, error (if any)

    Never raises — individual failures are captured in the 'error' field.
    Skips entirely if the active provider is disabled or unavailable.
    """
    p = provider or get_active_provider()
    min_severity = min_severity or p.min_severity

    if not p.enabled:
        logger.info(f"[scan:{scan_id}][apex] AI analysis disabled — skipping")
        return []

    if not await is_available(p):
        logger.warning(f"[scan:{scan_id}][apex] Provider '{p.id}' unavailable — skipping AI analysis")
        return []

    to_analyze = filter_findings(findings, min_severity)
    if not to_analyze:
        logger.info(f"[scan:{scan_id}][apex] No findings above '{min_severity}' — skipping")
        return []

    chain_label = " → ".join([p.model] + [m for m in p.model_failover if m != p.model])
    logger.info(f"[scan:{scan_id}][apex] Analyzing {len(to_analyze)} finding(s) via '{p.name}' [{chain_label}]")
    results: list[dict[str, Any] | None] = [None] * len(to_analyze)
    started = time.monotonic()

    async def _analyze_one(index: int, finding: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        """Analyse one finding without allowing it to block its siblings."""
        i = index + 1
        fid = finding.get("id", f"F-{i:04d}")
        title = finding.get("title", finding.get("name", "Unknown"))
        sev = _severity(finding).upper()
        endpoint = _finding_endpoint(finding, target)
        logger.info(f"[scan:{scan_id}][apex] [{i}/{len(to_analyze)}] {fid} [{sev}] {title[:60]}")
        partial = {"finding_id": fid, "title": title, "severity": sev, "endpoint": endpoint,
                   "poc": "", "validation": {"status": "pending", "confirmed": False},
                   "review": {"status": "pending"}, "report_status": "inconclusive"}
        try:
            async def _work() -> dict[str, Any]:
                # Check the original observation before spending model tokens.
                validation = await replay_safe_poc(finding, "", target)
                partial["validation"] = validation
                if validation.get("not_found"):
                    partial.update(report_status="refuted", review={"status": "skipped", "reason": "deterministic_not_found_gate"})
                    return partial
                gen = await _generate(build_prompt(finding, target), p, scan_id=scan_id)
                poc_text = gen.get("text", "") or ""
                partial.update(poc=poc_text, model_used=gen.get("model"), generation={k: gen.get(k) for k in ("finish_reason", "usage", "truncated")})
                if gen.get("error"):
                    partial["error"] = gen["error"]
                    return partial
                review = await review_generated_poc(
                    finding, poc_text, validation, target, p, scan_id=scan_id
                ) if poc_text else {
                    "status": "skipped", "reason": "no PoC generated", "text": ""
                }
                partial["review"] = review
                # One bounded follow-up only; no prose/curl execution. It must
                # remain on the original path and pass the same replay policy.
                correction = review.get("corrected_validation")
                original, _ = request_from_finding(finding, target)
                if review.get("verdict") == "needs_revision" and isinstance(correction, dict) and original:
                    from urllib.parse import urlparse
                    if urlparse(str(correction.get("url", ""))).path == urlparse(original["url"]).path:
                        followup = await replay_request(correction, finding, target)
                        partial["followup_validation"] = followup
                        if followup.get("status") == "replayed":
                            review = await review_generated_poc(finding, poc_text, followup, target, p, scan_id=scan_id)
                            partial["review"] = review
                            validation = followup
                report_status = _semantic_report_status(review, validation)
                return {
                    **partial,
                    "finding_id": fid,
                    "title": title,
                    "severity": sev,
                    "endpoint": endpoint,
                    "poc": poc_text,
                    "validation": validation,
                    "review": review,
                    "report_status": report_status,
                    "model_used": gen.get("model"),
                    "failover_trail": gen.get("refused_chain") or [],
                    "error": gen.get("error") if not gen.get("text") else None,
                }

            return index, await asyncio.wait_for(_work(), timeout=APEX_ITEM_TIMEOUT)
        except TimeoutError:
            logger.warning(
                f"[scan:{scan_id}][apex] {fid} exceeded the per-finding budget "
                f"({APEX_ITEM_TIMEOUT:g}s)"
            )
            return index, {
                **partial,
                "report_status": "inconclusive",
                "error": f"per-finding timeout after {APEX_ITEM_TIMEOUT:g}s",
            }
        except Exception as e:
            logger.error(f"[scan:{scan_id}][apex] ERROR on {fid}: {e}")
            return index, {
                **partial,
                "finding_id": fid,
                "title": title,
                "severity": sev,
                "endpoint": endpoint,
                "poc": partial.get("poc", ""),
                "model_used": None,
                "failover_trail": [],
                "validation": {"status": "skipped", "confirmed": False, "reason": "generation error"},
                "review": {"status": "skipped", "reason": "generation error", "text": ""},
                "report_status": "inconclusive",
                "error": str(e),
            }

    semaphore = asyncio.Semaphore(APEX_CONCURRENCY)

    async def _bounded(index: int, finding: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        async with semaphore:
            return await _analyze_one(index, finding)

    tasks = [
        asyncio.create_task(_bounded(index, finding))
        for index, finding in enumerate(to_analyze)
    ]
    for completed in asyncio.as_completed(tasks):
        index, result = await completed
        results[index] = result
        if on_result is not None:
            try:
                await on_result(result)
            except Exception as callback_error:
                # A persistence callback must never cancel provider work.
                logger.warning(
                    f"[scan:{scan_id}][apex] Partial-result callback failed: {callback_error}"
                )

    final_results = [result for result in results if result is not None]
    elapsed = int((time.monotonic() - started) * 1000)
    logger.info(f"[scan:{scan_id}][apex] Done — {len(final_results)} finding review(s) in {elapsed}ms")
    return final_results


async def review_generated_poc(
    finding: dict[str, Any], poc: str, validation: dict[str, Any], target: str,
    provider: Provider | None = None, scan_id: str = "",
) -> dict[str, Any]:
    """Run a second, critical pass over a generated PoC."""
    p = provider or get_active_provider()
    if not p.enabled or not poc:
        return {"status": "skipped", "reason": "provider disabled or empty PoC", "text": ""}
    try:
        generated = await _generate(build_review_prompt(finding, poc, validation, target), p, scan_id=scan_id)
        if not generated.get("text"):
            return {
                "status": "error", "reason": generated.get("error") or "review unavailable",
                "text": "", "model_used": generated.get("model"),
                "failover_trail": generated.get("refused_chain") or [],
            }
        review_text = generated["text"]
        parsed_review = _parse_structured_review(review_text)
        return {
            "status": "truncated" if generated.get("truncated") else ("ok" if parsed_review else "review_unparsed"),
            "generation": {k: generated.get(k) for k in ("finish_reason", "usage", "truncated")},
            "verdict": parsed_review.get("verdict", "unparsed") if parsed_review else "unparsed",
            "confidence": parsed_review.get("confidence") if parsed_review else None,
            "issues": parsed_review.get("issues", []) if parsed_review else [],
            "corrected_validation": parsed_review.get("corrected_validation") if parsed_review else None,
            "text": review_text, "model_used": generated.get("model"),
            "failover_trail": generated.get("refused_chain") or [],
        }
    except Exception as exc:
        logger.warning(f"[scan:{scan_id}][apex] PoC review failed: {exc}")
        return {"status": "error", "reason": str(exc), "text": ""}


async def analyze_scan_overview(
    findings: list[dict[str, Any]], endpoints: list[dict[str, Any]],
    schema: dict[str, Any] | None, pocs: list[dict[str, Any]], target: str,
    provider: Provider | None = None, scan_id: str = "",
) -> dict[str, Any]:
    """Review the scan as a whole; produces advisory candidates only."""
    p = provider or get_active_provider()
    if not p.enabled:
        return {"status": "skipped", "reason": "provider disabled", "text": ""}
    if not findings and not endpoints and not schema:
        return {"status": "skipped", "reason": "nothing to review", "text": ""}
    if not await is_available(p):
        return {"status": "skipped", "reason": "provider unavailable", "text": ""}
    try:
        generated = await _generate(
            build_scan_review_prompt(findings, endpoints, schema, target, pocs),
            p, scan_id=scan_id,
        )
        if not generated.get("text"):
            return {"status": "error", "reason": generated.get("error") or "review unavailable", "text": ""}
        return {
            "status": "partial" if generated.get("truncated") else "ok", "text": generated["text"], "model_used": generated.get("model"),
            "findings_reviewed": len(findings), "endpoints_sampled": min(len(endpoints), 300),
            "pocs_reviewed": len(pocs), "failover_trail": generated.get("refused_chain") or [],
        }
    except Exception as exc:
        logger.warning(f"[scan:{scan_id}][apex] Whole-scan review failed: {exc}")
        return {"status": "error", "reason": str(exc), "text": ""}


def render_markdown_report(
    pocs: list[dict[str, Any]], target: str, model: str, scan_id: str,
    scan_overview: dict[str, Any] | None = None,
) -> str:
    """Render list of PoC dicts to a markdown string."""
    from datetime import datetime
    lines = [
        "# BugTraceAI-API — AI Analysis Report",
        "",
        f"**Scan ID:** `{scan_id}`  ",
        f"**Target:** `{target}`  ",
        f"**Primary model:** `{model}`  ",
        f"**Generated:** {datetime.now(UTC).isoformat()}  ",
        f"**Findings analyzed:** {len(pocs)}",
        "",
        "---",
        "",
    ]
    if scan_overview and scan_overview.get("text"):
        lines += ["## Whole-scan coverage review", "", scan_overview["text"], "", "---", ""]
    for res in pocs:
        used = res.get("model_used") or model
        trail = res.get("failover_trail") or []
        model_line = f"**Generated by:** `{used}`"
        if trail:
            model_line += f"  _(failover from: {', '.join(trail)})_"
        lines += [
            f"## [{res['severity']}] {res['title']}",
            f"**ID:** `{res['finding_id']}`  ",
            f"**Endpoint:** `{res['endpoint']}`  ",
            model_line,
            "",
            res.get("poc") or f"_ERROR: {res.get('error', 'unknown')}_",
            "",
            "### Safe replay validation",
            "```json",
            json.dumps(res.get("validation") or {}, indent=2, default=str),
            "```",
            "",
            "### Critical review",
            f"**Semantic status:** `{res.get('report_status', 'inconclusive')}`",
            "",
            (res.get("review") or {}).get("text") or f"_{(res.get('review') or {}).get('reason', 'not available')}_",
            "",
            "---",
            "",
        ]
    return "\n".join(lines)
