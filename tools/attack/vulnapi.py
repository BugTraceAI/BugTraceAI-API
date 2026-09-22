"""vulnapi wrapper — auth / CORS / security-header scanner from a schema or URL."""
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from lib import sanitize_cmd_for_log
from lib.auth_header import auth_cli_flag
from lib.scan_state import scan_state
from lib.subprocess_runner import Status, run_json_tool

logger = logging.getLogger("bugtrace-api.tools.attack.vulnapi")

VULNAPI_BIN = Path(os.environ.get("VULNAPI_BIN", "/usr/local/bin/vulnapi"))


def _parse_vulnapi_output(data: Any, target: str) -> list[dict[str, Any]]:
    """Parse vulnapi v0.8.x JSON report into structured findings.

    v0.8.x structure: {reports: [{issues: [{id, name, cvss, status, ...}]}]}
    Only issues with status="failed" are actual vulnerabilities.
    """
    findings = []

    # Collect issues from reports[] (detailed per-scan results)
    all_issues: list[dict] = []
    for report in data.get("reports", []):
        for issue in report.get("issues", []):
            if issue.get("status") == "failed":
                all_issues.append(issue)

    # Fallback: also check curl.issues / openapi.issues for top-level summary
    for key in ("curl", "openapi"):
        section = data.get(key, {})
        if isinstance(section, dict):
            for issue in section.get("issues", []):
                if issue.get("status") == "failed":
                    # Avoid duplicates by id
                    if not any(i.get("id") == issue.get("id") for i in all_issues):
                        all_issues.append(issue)

    # Legacy format fallback (older vulnapi versions)
    if not all_issues:
        legacy = data.get("vulnerabilities", data.get("issues", data.get("results", [])))
        if isinstance(legacy, list):
            all_issues = [v for v in legacy if v]

    # Group by issue name to deduplicate across endpoints
    grouped: dict[str, list[dict]] = {}
    for v in all_issues:
        name = v.get("name", v.get("type", "Security issue"))
        grouped.setdefault(name, []).append(v)

    for name, issues in grouped.items():
        # Use highest CVSS score from the group
        best = max(issues, key=lambda i: (i.get("cvss", {}) or {}).get("score", 0))
        cvss = best.get("cvss", {})
        score = cvss.get("score", 0) if isinstance(cvss, dict) else 0
        severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low" if score > 0 else "info"
        owasp = best.get("classifications", {}).get("owasp", "")
        cwe = best.get("classifications", {}).get("cwe", "")

        # Collect all affected endpoints
        endpoints = []
        for issue in issues:
            candidate = str(issue.get("endpoint") or issue.get("url") or target)
            if "developer.mozilla.org" in candidate or "owasp.org" in candidate:
                candidate = target
            if candidate not in endpoints:
                endpoints.append(candidate)

        findings.append({
            "id": f"VULNAPI-{len(findings)+1:04d}",
            "title": f"[vulnapi] {name}",
            "severity": severity,
            "confidence": 0.85,
            "category": owasp or "API Security",
            "endpoint": endpoints[0],
            "affected_endpoints": endpoints,
            "affected_count": len(endpoints),
            "source_tools": ["vulnapi"],
            "evidence": best,
            "repro": {
                "note": f"{name}. {cwe}" if cwe else name,
                "cvss_score": str(score),
                "cvss_vector": cvss.get("vector", "") if isinstance(cvss, dict) else "",
            },
        })

    return findings


def _vulnapi_base_flags() -> list[str]:
    """Common flags for all vulnapi commands."""
    return ["--report-format", "json", "--no-progress", "--sqa-opt-out"]


def _vulnapi_auth_flags_openapi(auth: dict[str, Any]) -> list[str]:
    """Auth flags for vulnapi scan openapi (--security-schemes key=value).

    Note: vulnapi's openapi mode takes a different flag shape than its
    curl mode (``--security-schemes bearer=…`` vs ``-H Authorization: …``),
    so this is kept distinct from the generic ``auth_cli_flag`` helper.
    """
    token_type = (auth or {}).get("type", "")
    token = (auth or {}).get("token", "")
    if token_type == "bearer" and token:
        return ["--security-schemes", f"bearer={token}"]
    if token_type == "basic" and token:
        return ["-u", token]
    return []


async def _run_vulnapi_cmd(
    scan_id: str, target: str, cmd: list[str],
    started: float, max_attempts: int = 2, backoff_seconds: int = 2,
) -> list[dict[str, Any]] | None:
    """Execute vulnapi with the given command. Returns None on hard failure (to allow fallback).

    vulnapi v0.8.x writes JSON to --report-file, not stdout, and exits 1 when
    issues are found (both 0 and 1 are valid outcomes; only >1 is a hard error).
    Retries + health reporting are delegated to ``run_json_tool``.
    """
    with tempfile.NamedTemporaryFile(
        suffix=".json", prefix=f"vulnapi_{scan_id}_", delete=False
    ) as tmp:
        report_file = Path(tmp.name)
    cmd += ["--report-file", str(report_file)]

    logger.info(f"[scan:{scan_id}] Running vulnapi: {sanitize_cmd_for_log(cmd)}")

    def _parse(data: Any) -> list[dict[str, Any]]:
        return _parse_vulnapi_output(data, target)

    try:
        result = await run_json_tool(
            scan_id, "vulnapi", cmd, report_file,
            parse_fn=_parse,
            timeout=120.0, max_attempts=max_attempts, backoff_seconds=backoff_seconds,
            success_exit_codes=(0, 1),  # vulnapi returns 1 when it found issues
        )
        if result.status != Status.OK:
            logger.warning(
                f"[scan:{scan_id}] vulnapi failed ({result.status.value}: {result.error}), "
                f"returning None to allow curl fallback"
            )
            return None
        logger.info(f"[scan:{scan_id}] vulnapi: {len(result.findings)} finding(s)")
        return result.findings
    finally:
        try:
            report_file.unlink()
        except OSError:
            pass


async def run_vulnapi(
    scan_id: str,
    target: str,
    schema_url: str | None = None,
    auth: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run vulnapi for auth/CORS/header checks.

    Tries OpenAPI mode first (when a schema URL is available), falls back to
    curl mode if the OpenAPI mode parse fails.
    """
    started = time.monotonic()
    max_attempts = 2
    backoff_seconds = 2

    if not VULNAPI_BIN.exists():
        logger.info(f"[scan:{scan_id}] vulnapi binary not found, skipping")
        await scan_state.update_tool_health(
            scan_id, "vulnapi", status="not_installed", attempts=1, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="binary_not_found",
        )
        return []

    # Build command: prefer OpenAPI mode when schema available, fallback to curl
    if schema_url:
        cmd = [str(VULNAPI_BIN), "scan", "openapi", schema_url, *_vulnapi_base_flags()]
        if auth:
            cmd += _vulnapi_auth_flags_openapi(auth)
        findings = await _run_vulnapi_cmd(
            scan_id, target, cmd, started, max_attempts, backoff_seconds,
        )
        if findings is not None:
            return findings
        # Fallback to curl mode if OpenAPI parse fails
        logger.info(f"[scan:{scan_id}] vulnapi OpenAPI mode failed, falling back to curl mode")

    cmd = [str(VULNAPI_BIN), "scan", "curl", target, *_vulnapi_base_flags()]
    if auth:
        cmd += auth_cli_flag(auth)
    findings = await _run_vulnapi_cmd(
        scan_id, target, cmd, started, max_attempts, backoff_seconds,
    )
    return findings if findings is not None else []
