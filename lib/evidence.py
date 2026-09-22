"""Evidence & artifact management for BugTraceAI-API.

Scan directory layout (mirrors BugTraceAI-CLI style):

    reports/
    └── api.example.com_20260404_153045_a1b2c3d4e5f6/    ← {domain}_{timestamp}_{scan_id}
        ├── .scan_id                         ← scan UUID mapping
        ├── scan_config.json                 ← initial scan parameters
        ├── findings.json                    ← final findings list
        ├── report.json                      ← full unified report
        ├── endpoints.json                   ← all discovered endpoints
        ├── scan_metadata.json               ← timing, tools, stats
        ├── 10_discovery/                    ← Phase 1 outputs
        │   ├── kiterunner_endpoints.json
        │   ├── crawl_endpoints.json
        │   ├── all_endpoints.json
        │   ├── generated_openapi.json
        │   └── phase_summary.json
        ├── 20_schema_probe/                 ← Phase 2 outputs
        │   ├── schema_decision.json
        │   └── schema_info.json
        ├── 30_schema_attack/                ← Phase 3A outputs
        │   ├── findings_schemathesis.json
        │   ├── findings_offat.json
        │   └── attack_tool_health.json
        ├── 31_blind_attack/                 ← Phase 3B outputs
        │   └── findings_arjun.json
        └── 40_aggregation/                  ← Phase 4 outputs
            ├── unified_findings.json
            ├── findings_only.json
            ├── findings_{tool}.json
            ├── tool_health.json
            ├── endpoints_summary.json
            └── scan_metadata.json
"""
import json
import logging
import os
import re
import tempfile
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from lib.auth_header import auth_headers_dict

logger = logging.getLogger("bugtrace-api.lib.evidence")

REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/opt/bugtrace-api/reports"))

PHASE_MAP = {
    "discovery": "10_discovery",
    "schema_probe": "20_schema_probe",
    "schema_attack": "30_schema_attack",
    "blind_attack": "31_blind_attack",
    "auth_probe": "32_auth_probe",
    "authz_probe": "33_authz_probe",
    "aggregation": "40_aggregation",
    "apex_analysis": "50_apex_analysis",
    "investigation": "60_investigation",
}

# ── Scan directory registry ────────────────────────────────────────────────
# Maps scan_id → absolute Path of the scan directory.
_scan_dirs: dict[str, Path] = {}
execution_artifact_scope: ContextVar[str | None] = ContextVar("execution_artifact_scope", default=None)

_REFERENCE_URL_RE = re.compile(
    r"(?:developer\.mozilla\.org|cwe\.mitre\.org|owasp\.org|portswigger\.net/web-security)",
    re.IGNORECASE,
)


def _report_endpoint(finding: dict[str, Any], target: str) -> str:
    """Use the scan target when a tool recorded a documentation URL as endpoint."""
    endpoint = finding.get("endpoint") or finding.get("url")
    value = str(endpoint or "").strip()
    if target and (not value or _REFERENCE_URL_RE.search(value)):
        return str(target)
    return value or "—"


def _normalize_ai_poc_markdown(text: str, target: str) -> str:
    """Fix stale reference links in a persisted AI PoC header only.

    Reference links inside the evidence narrative remain intact; only the
    structured endpoint line is rewritten so portable reports agree with the
    findings table.
    """
    if not target:
        return text

    def replace(match: re.Match[str]) -> str:
        endpoint = match.group(2)
        if _REFERENCE_URL_RE.search(endpoint):
            return f"{match.group(1)} {target}"
        return match.group(0)

    return re.sub(
        r"^(\*\*Endpoint:\*\*)\s*(?:`)?(https?://[^`\s]+)(?:`)?\s*$",
        replace,
        text,
        flags=re.IGNORECASE | re.MULTILINE,
    )


def create_scan_dir(scan_id: str, target: str) -> Path:
    """Create a CLI-style scan directory: reports/{domain}_{YYYYMMDD_HHMMSS}_{scan_id}/

    scan_id is included (not just the second-granularity timestamp) so two scans
    of the same target started within the same second never collide onto one dir.

    Idempotent: if a directory is already registered for ``scan_id`` (e.g. the
    pending scan_manifest.json written at creation), that same directory is
    returned instead of creating a second one with a different timestamp.
    """
    if scan_id in _scan_dirs:
        existing = _scan_dirs[scan_id]
        if existing.exists():
            return existing

    try:
        domain = urlparse(target).netloc or target
        domain = domain.replace(":", "_").replace("/", "_")
    except Exception:
        domain = "unknown"

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    dir_name = f"{domain}_{timestamp}_{scan_id}"
    scan_dir = REPORTS_DIR / dir_name
    scan_dir.mkdir(parents=True, exist_ok=True)

    _scan_dirs[scan_id] = scan_dir
    (scan_dir / ".scan_id").write_text(scan_id)

    logger.info(f"[scan:{scan_id}] Created scan dir: {scan_dir}")
    return scan_dir


def get_scan_dir(scan_id: str) -> Path:
    """Resolve the scan directory for a scan_id."""
    if scan_id in _scan_dirs:
        return _scan_dirs[scan_id]
    # Search by .scan_id marker
    if REPORTS_DIR.exists():
        for d in sorted(REPORTS_DIR.iterdir(), reverse=True):
            marker = d / ".scan_id"
            if d.is_dir() and marker.exists() and marker.read_text().strip() == scan_id:
                _scan_dirs[scan_id] = d
                return d
    # Fallback
    fallback = REPORTS_DIR / scan_id
    fallback.mkdir(parents=True, exist_ok=True)
    _scan_dirs[scan_id] = fallback
    return fallback


# ── Scan manifest ─────────────────────────────────────────────────────────

def _manifest_path(scan_id: str) -> Path:
    return get_scan_dir(scan_id) / "scan_manifest.json"


def save_scan_manifest(
    scan_id: str,
    engine: str = "api",
    launch_origin: str = "api",
    status: str = "pending",
    target: str | None = None,
    launch_transport: str | None = None,
    started_at: str | None = None,
    finished_at: str | None = None,
    findings_count: int = 0,
    current_phase: str = "discovery",
    progress: float = 0.0,
    openapi_available: bool = False,
    error: str | None = None,
    warning: str | None = None,
    analysis_provider: str | None = None,
    analysis_model: str | None = None,
) -> Path:
    """Atomically write a public-safe scan_manifest.json in the scan directory.

    Contains scan_id, engine, launch_origin, optional launch_transport, current
    status, timestamps and a small set of public summary fields. Every
    lifecycle transition updates the same file so that rehydration after a
    restart always yields the latest provenance and status.
    """
    data: dict[str, Any] = {
        "scan_id": scan_id,
        "engine": engine,
        "launch_origin": launch_origin,
        "status": status,
        "current_phase": current_phase,
        "progress": progress,
        "started_at": started_at or datetime.now(UTC).isoformat(),
        "finished_at": finished_at,
        "findings_count": findings_count,
        "openapi_available": openapi_available,
    }
    if target is not None:
        data["target"] = target
    if launch_transport is not None:
        data["launch_transport"] = launch_transport
    if error is not None:
        data["error"] = error
    if warning is not None:
        data["warning"] = warning
    if analysis_provider is not None:
        data["analysis_provider"] = analysis_provider
    if analysis_model is not None:
        data["analysis_model"] = analysis_model
    # Atomic write: temp file in the same directory then rename.
    path = _manifest_path(scan_id)
    fd, tmp = tempfile.mkstemp(suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    logger.debug(f"[scan:{scan_id}] Saved scan_manifest.json: {path}")
    return path


def load_scan_manifest(scan_id: str) -> dict[str, Any] | None:
    """Load scan_manifest.json from disk, or return None if absent."""
    path = _manifest_path(scan_id)
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[scan:{scan_id}] Failed to load scan_manifest.json: {e}")
        return None


def _phase_dir(scan_id: str, phase: str) -> Path:
    execution = execution_artifact_scope.get()
    if execution:
        return get_scan_dir(scan_id) / "60_investigation" / "executions" / execution / PHASE_MAP.get(phase, phase)
    return get_scan_dir(scan_id) / PHASE_MAP.get(phase, phase)


# ── Artifact I/O ──────────────────────────────────────────────────────────

def save_artifact(scan_id: str, phase: str, name: str, data: Any, fmt: str = "json") -> Path:
    """Save an artifact inside a phase subdirectory."""
    try:
        phase_dir = _phase_dir(scan_id, phase)
        phase_dir.mkdir(parents=True, exist_ok=True)
        ext = "yaml" if fmt == "yaml" else "json"
        file_path = phase_dir / f"{name}.{ext}"
        with open(file_path, "w") as f:
            if fmt == "json":
                json.dump(data, f, indent=2, default=str)
            else:
                f.write(str(data))
        logger.info(f"[scan:{scan_id}] Saved: {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"[scan:{scan_id}] Failed to save artifact {name}: {e}")
        return Path("/dev/null")


def save_report(scan_id: str, name: str, data: Any, fmt: str = "json") -> Path:
    """Save a top-level report file in the scan root (like CLI's final_report)."""
    try:
        scan_dir = get_scan_dir(scan_id)
        ext = "yaml" if fmt == "yaml" else "json"
        file_path = scan_dir / f"{name}.{ext}"
        with open(file_path, "w") as f:
            if fmt == "json":
                json.dump(data, f, indent=2, default=str)
            else:
                f.write(str(data))
        logger.info(f"[scan:{scan_id}] Saved report: {file_path}")
        return file_path
    except Exception as e:
        logger.error(f"[scan:{scan_id}] Failed to save report {name}: {e}")
        return Path("/dev/null")


def render_scan_markdown(
    scan_id: str,
    target: str,
    status: dict[str, Any] | None,
    findings: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    tool_health: dict[str, Any] | None = None,
    ai_analysis: dict[str, Any] | None = None,
    coverage: dict[str, Any] | None = None,
    schema: dict[str, Any] | None = None,
    quality_summary: dict[str, Any] | None = None,
) -> str:
    """Standalone Markdown report for an API scan.

    This is the product output: facts, needs-validation items, and hardening
    are separate. It is written to disk at aggregation and rebuilt on download.
    """
    scan_status = status or {}
    provider = scan_status.get("analysis_provider") or (ai_analysis or {}).get("provider")
    model = scan_status.get("analysis_model") or (ai_analysis or {}).get("model")
    schema = schema or {}
    coverage = coverage or {}
    quality = quality_summary or {}
    by_class = quality.get("by_classification") or {}

    def _class_of(finding: dict[str, Any]) -> str:
        return str(finding.get("classification") or "insufficient")

    confirmed = [f for f in findings if _class_of(f) == "confirmed"]
    suspicious = [f for f in findings if _class_of(f) == "suspicious"]
    hardening = [f for f in findings if _class_of(f) == "hardening"]
    insufficient = [f for f in findings if _class_of(f) == "insufficient"]
    unlabelled = [
        f for f in findings
        if _class_of(f) not in {"confirmed", "suspicious", "hardening", "insufficient"}
    ]

    lines = [
        "# BugTraceAI API Scan Report",
        "",
        f"- **Scan ID:** `{scan_id}`",
        f"- **Target:** `{target}`",
        f"- **Status:** `{scan_status.get('status', 'unknown')}`",
        f"- **Confirmed vulnerabilities:** `{len(confirmed)}`",
        f"- **Needs validation:** `{len(suspicious)}`",
        f"- **Hardening observations:** `{len(hardening)}`",
        f"- **Insufficient evidence:** `{len(insufficient)}`",
        f"- **Endpoints recorded:** `{len(endpoints)}`",
    ]
    if schema:
        lines += [
            f"- **OpenAPI downloaded:** `{schema.get('downloaded', False)}`",
            f"- **OpenAPI parsed:** `{schema.get('parsed', False)}`",
            f"- **OpenAPI source:** `{schema.get('source', 'none')}`",
            f"- **OpenAPI format:** `{schema.get('format', 'unknown')}`",
            f"- **Paths:** `{schema.get('paths_count', 0)}`",
            f"- **Operations:** `{schema.get('operations_count', 0)}`",
        ]
        if schema.get("parse_error"):
            lines.append(f"- **OpenAPI parse error:** {schema['parse_error']}")
    if coverage:
        methods = coverage.get("methods") or {}
        discovery = coverage.get("discovery") or {}
        lines += [
            f"- **Operations tested:** `{methods.get('tested', coverage.get('tested', 0))}`",
            f"- **Mutating methods skipped:** `{methods.get('skipped_mutating', coverage.get('skipped', 0))}`",
            f"- **OpenAPI operations / wordlist / crawl:** "
            f"`{discovery.get('openapi_operations', 0)}` / "
            f"`{discovery.get('wordlist_endpoints', 0)}` / "
            f"`{discovery.get('crawl_endpoints', 0)}`",
        ]
    if provider:
        lines.append(f"- **AI provider:** `{provider}`")
    if model:
        lines.append(f"- **AI model:** `{model}`")
    if scan_status.get("warning"):
        lines.append(f"- **Warning:** {scan_status['warning']}")

    lines += [
        "",
        "## How to read this report",
        "",
        "- **Confirmed** — reproducible HTTP evidence for a real vulnerability.",
        "- **Needs validation** — suspicious behaviour; not confirmed. Do not treat as a vuln.",
        "- **Hardening** — missing headers or config with no demonstrated impact.",
        "- **Insufficient evidence** — scanner noise, public endpoints, or missing request/response.",
        "",
    ]

    def _emit_section(heading: str, rows: list[dict[str, Any]], empty: str) -> None:
        nonlocal lines
        lines.append(f"## {heading}")
        lines.append("")
        if not rows:
            lines.append(empty)
            lines.append("")
            return
        for index, finding in enumerate(rows, 1):
            title = finding.get("title") or finding.get("name") or "Untitled finding"
            severity = str(finding.get("severity") or "info").upper()
            endpoint = _report_endpoint(finding, target)
            reason = (
                finding.get("classification_reason")
                or (finding.get("evidence") or {}).get("summary")
                or (finding.get("repro") or {}).get("note")
                or ""
            )
            envelope = finding.get("evidence_envelope") if isinstance(finding.get("evidence_envelope"), dict) else {}
            lines += [
                f"### {index}. [{severity}] {title}",
                f"- **Endpoint:** `{endpoint}`",
            ]
            if reason:
                lines.append(f"- **Why:** {reason}")
            method = envelope.get("method") or (finding.get("repro") or {}).get("method")
            status_code = envelope.get("status_code")
            if method:
                lines.append(f"- **Method:** `{method}`")
            if status_code:
                lines.append(f"- **Observed status:** `{status_code}`")
            curl = (finding.get("repro") or {}).get("curl")
            if curl:
                lines += ["", "```", str(curl), "```"]
            preview = envelope.get("body_preview")
            if preview:
                lines += ["", "**Body preview**", "", "```", str(preview)[:800], "```"]
            lines += ["", "---", ""]

    _emit_section("Confirmed vulnerabilities", confirmed, "None.")
    _emit_section("Needs validation", suspicious, "None.")
    _emit_section("Hardening", hardening, "None.")
    _emit_section("Insufficient evidence", insufficient, "None.")
    if unlabelled:
        _emit_section("Unclassified scanner rows", unlabelled, "None.")

    if by_class:
        lines += [
            "## Quality summary",
            "",
            f"- confirmed: `{by_class.get('confirmed', 0)}`",
            f"- needs validation: `{by_class.get('suspicious', 0)}`",
            f"- hardening: `{by_class.get('hardening', 0)}`",
            f"- insufficient: `{by_class.get('insufficient', 0)}`",
            "",
        ]

    if ai_analysis:
        pocs = ai_analysis.get("pocs") or []
        scan_review = ai_analysis.get("scan_review") or {}
        if scan_review.get("text"):
            lines += ["## Whole-scan notes (advisory)", "", str(scan_review["text"]), ""]
        if pocs:
            lines += ["## AI enrichment (advisory, not confirmation)", ""]
            for poc in pocs:
                poc_title = poc.get("title") or poc.get("finding_id") or "Finding"
                poc_text = str(poc.get("poc") or "_No PoC generated._")
                lines += [f"### {poc_title}", _normalize_ai_poc_markdown(poc_text, target), ""]
                validation = poc.get("validation") or {}
                if validation:
                    lines += ["**Safe replay**", "", "```json", json.dumps(validation, indent=2, default=str), "```", ""]
                review = poc.get("review") or {}
                if review.get("text"):
                    lines += ["**Critical review**", "", str(review["text"]), ""]

    if tool_health:
        lines += ["## Tool summary", ""]
        for tool, health in tool_health.items():
            if isinstance(health, dict):
                state = health.get("status", "unknown")
                count = health.get("findings_count", 0)
                lines.append(f"- `{tool}` — **{state}**, {count} finding(s)")
            else:
                lines.append(f"- `{tool}` — {health}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def load_artifact(scan_id: str, phase: str, name: str) -> Any | None:
    """Load a JSON artifact written by a previous phase."""
    file_path = _phase_dir(scan_id, phase) / f"{name}.json"
    if not file_path.exists():
        logger.debug(f"[scan:{scan_id}] Artifact not found: {file_path}")
        return None
    try:
        with open(file_path) as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"[scan:{scan_id}] Failed to load {name}: {e}")
        return None


def list_artifacts(scan_id: str, phase: str) -> list[Path]:
    """List all JSON artifacts in a phase directory."""
    phase_dir = _phase_dir(scan_id, phase)
    if not phase_dir.exists():
        return []
    return sorted(phase_dir.glob("*.json"))


# ── Helpers ────────────────────────────────────────────────────────────────

def endpoints_to_openapi(target: str, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
    """Build an OpenAPI 3.0 spec from discovered endpoints."""
    try:
        parsed = urlparse(target)
        server_url = f"{parsed.scheme}://{parsed.netloc}"
        title = parsed.netloc
    except Exception:
        server_url = target.rstrip("/")
        title = target

    paths: dict[str, Any] = {}

    for ep in endpoints:
        method = ep.get("method", "GET").lower()
        if method not in ("get", "post", "put", "patch", "delete", "head", "options"):
            continue

        url = ep.get("url", "")
        status = ep.get("status", 200)

        try:
            parsed_url = urlparse(url)
            path = parsed_url.path or "/"
            query_string = parsed_url.query
        except Exception:
            continue

        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        parameters = []
        if query_string:
            for param_name, values in parse_qs(query_string, keep_blank_values=True).items():
                parameters.append({
                    "name": param_name,
                    "in": "query",
                    "required": False,
                    "schema": {"type": "string"},
                    "example": values[0] if values else "",
                })

        if path not in paths:
            paths[path] = {}

        response_entry = {
            str(status): {
                "description": f"HTTP {status}",
                "content": {
                    "application/json": {
                        "schema": {"type": "object"},
                    }
                },
            }
        }

        existing = paths[path].get(method)
        if existing:
            # Merge instead of overwrite. The upstream (method, url) dedup keeps
            # distinct raw URLs (different query string or status code) as separate
            # endpoints, so multiple entries legitimately collapse onto one
            # path+method here — overwriting would silently drop real query
            # params / response variety from the spec schemathesis/offat fuzz against.
            existing["responses"].update(response_entry)
            if parameters:
                existing_names = {p["name"] for p in existing.get("parameters", [])}
                new_params = [p for p in parameters if p["name"] not in existing_names]
                if new_params:
                    existing["parameters"] = existing.get("parameters", []) + new_params
            continue

        operation: dict[str, Any] = {
            "responses": response_entry,
            "tags": ["discovered"],
        }
        if parameters:
            operation["parameters"] = parameters

        paths[path][method] = operation

    return {
        "openapi": "3.0.0",
        "info": {
            "title": f"BugTraceAI Auto-Generated — {title}",
            "description": "OpenAPI spec synthesized from discovered endpoints. Used for automated security testing.",
            "version": "1.0.0",
        },
        "servers": [{"url": server_url}],
        "paths": paths,
    }


def _infer_json_schema(value: Any, max_depth: int = 3) -> dict[str, Any]:
    """Infer a JSON Schema from a sample value (limited depth)."""
    if max_depth <= 0:
        return {}
    if value is None:
        return {"nullable": True}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        # Try to detect common formats
        if len(value) >= 8 and ("T" in value or "-" in value[:5]):
            try:
                datetime.fromisoformat(value.replace("Z", "+00:00"))
                return {"type": "string", "format": "date-time"}
            except (ValueError, TypeError):
                pass
        if value.startswith(("http://", "https://")):
            return {"type": "string", "format": "uri"}
        return {"type": "string"}
    if isinstance(value, list):
        if not value:
            return {"type": "array", "items": {}}
        # Infer from first element
        return {"type": "array", "items": _infer_json_schema(value[0], max_depth - 1)}
    if isinstance(value, dict):
        properties = {}
        for k, v in list(value.items())[:20]:  # Cap to avoid huge schemas
            if k.startswith("_"):  # Skip HAL internals
                continue
            properties[k] = _infer_json_schema(v, max_depth - 1)
        schema: dict[str, Any] = {"type": "object"}
        if properties:
            schema["properties"] = properties
        return schema
    return {}


async def enrich_openapi_from_responses(
    openapi: dict[str, Any],
    target: str,
    auth: dict[str, Any] | None = None,
    max_endpoints: int = 30,
) -> dict[str, Any]:
    """Enrich an auto-generated OpenAPI spec by making real HTTP requests.

    For each GET endpoint, fetches the actual response and infers:
    - Response schema from the JSON body
    - Content-Type from headers
    This gives schemathesis/offat much richer data for fuzzing.
    """
    import httpx

    paths = openapi.get("paths", {})
    servers = openapi.get("servers", [])
    base_url = servers[0]["url"] if servers else target.rstrip("/")

    headers = {
        "User-Agent": "BugTraceAI/1.0",
        "Accept": "application/json, application/hal+json, */*",
    }
    headers.update(auth_headers_dict(auth))

    enriched_count = 0
    try:
        async with httpx.AsyncClient(
            headers=headers, verify=False, timeout=8.0, follow_redirects=True
        ) as client:
            for path, methods in list(paths.items())[:max_endpoints]:
                # Add POST request body schema if endpoint accepts POST — independent
                # of whether it also has a GET. This used to live inside the "get"
                # block below, so POST-only paths (logins, registration, "create"
                # endpoints — exactly the highest-value fuzzing surface) never got
                # a requestBody schema at all.
                if "post" in methods:
                    methods["post"].setdefault("requestBody", {
                        "content": {
                            "application/json": {
                                "schema": {"type": "object"},
                            }
                        },
                    })

                if "get" not in methods:
                    continue
                url = f"{base_url}{path}"
                try:
                    resp = await client.get(url)
                    content_type = resp.headers.get("content-type", "").split(";")[0].strip()

                    if resp.status_code == 200 and "json" in content_type:
                        try:
                            body = resp.json()
                            inferred = _infer_json_schema(body)
                            if inferred.get("properties") or inferred.get("items"):
                                ct = content_type or "application/json"
                                methods["get"]["responses"] = {
                                    "200": {
                                        "description": "OK",
                                        "content": {
                                            ct: {"schema": inferred},
                                        },
                                    }
                                }
                                enriched_count += 1
                        except Exception:
                            pass

                except Exception:
                    continue
    except Exception as e:
        logger.warning(f"OpenAPI enrichment failed: {e}")

    logger.info(f"Enriched {enriched_count}/{len(paths)} endpoints with real response schemas")
    return openapi
