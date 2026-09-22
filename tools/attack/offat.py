"""OFFAT wrapper — OWASP API Security Top 10 scanner from an OpenAPI schema."""
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

from lib import sanitize_cmd_for_log
from lib.auth_header import auth_cli_flag
from lib.openapi import origin_of
from lib.subprocess_runner import run_json_tool

logger = logging.getLogger("bugtrace-api.tools.attack.offat")

# Patterns in result_details that indicate the test PASSED (not vulnerable)
_OFFAT_FP_PATTERNS = [
    "not vulnerable",
    "might not vulnerable",
    "does not perform any http method which is not documented",
    "no sqli",
    "no injection",
    "properly validates",
    "properly handles",
    "no sensitive data",
]

# HTTP status codes that are normal/expected and don't indicate a vuln
_OFFAT_BENIGN_STATUSES = {200, 204, 301, 302, 400, 401, 403, 404, 405, 415, 429}

# offat's JSON output never carries a `severity` field (checked 0.13.0-0.19.4) — every
# finding is inferred from its test_name instead of defaulting to one fixed severity.
# Ordered most-severe-first; test_name substrings taken from offat's own source.
_OFFAT_SEVERITY_KEYWORDS = [
    ("critical", ("sqli", "sql injection", "command injection", "os command")),
    ("high", ("xss", "html injection", "bola", "bopla", "mass assignment", "broken access control")),
    ("low", ("unsupported http method", "unsupported method")),
]


def _infer_offat_severity(test_name: str) -> str:
    """Map an offat test_name to a severity when offat's own row has none."""
    name = test_name.lower()
    for severity, keywords in _OFFAT_SEVERITY_KEYWORDS:
        if any(kw in name for kw in keywords):
            return severity
    return "medium"


def _is_offat_false_positive(row: dict[str, Any]) -> bool:
    """Check if an offat finding is a false positive based on evidence fields.

    offat's `result=True` means "test executed", NOT "vulnerability confirmed".
    The real signal is in `result_details`, `response_status_code`, and `data_leak`.
    """
    # 1. Check result_details for "not vulnerable" patterns. offat >=0.18 renamed
    # this field to vuln_details (result_details/result -> vuln_details/vulnerable) —
    # check both so an upstream offat upgrade can't silently defeat this filter.
    details = str(
        row.get("result_details", row.get("vuln_details", row.get("response_match_regex", "")))
    ).lower()
    for pattern in _OFFAT_FP_PATTERNS:
        if pattern in details:
            return True

    # 2. Status code analysis: 405 for "unsupported method" tests = correct behavior
    status = row.get("response_status_code", row.get("status_code", 0))
    test_name = str(row.get("test_name", row.get("name", ""))).lower()

    if "unsupported http method" in test_name and status == 405:
        return True  # Server correctly rejects unsupported methods
    if "bola" in test_name and "might not vulnerable" in details:
        return True
    if "bopla" in test_name and status in (400, 401, 403, 422):
        return True  # Server correctly rejects bad input

    # 3. data_leak false matches: offat regex matches normal response text
    data_leak = row.get("data_leak", {})
    if isinstance(data_leak, dict):
        leak_matches = data_leak.get("matches", [])
        if isinstance(leak_matches, list):
            # Filter out matches that are just normal API response content
            real_leaks = []
            for match in leak_matches:
                match_str = str(match).lower()
                # Skip: token field names in JSON, hex cookies, HAL links
                if any(benign in match_str for benign in (
                    "access_token", "token_type", "bearer",
                    "bigipserver", "0x", "_links", "_embedded",
                )):
                    continue
                real_leaks.append(match)
            if not real_leaks and leak_matches:
                return True  # All "leaks" were benign matches

    return False


def _parse_offat_output(data: Any, target: str) -> list[dict[str, Any]]:
    """Parse offat JSON results into structured findings.

    Applies false-positive filtering: offat's `result=True` means "test executed",
    not "vulnerability found". We check `result_details` and evidence fields
    to determine if the finding is real.
    """
    findings = []

    # offat output can be a list directly or {"results": [...]}
    rows: list[dict] = []
    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = data.get("results", data.get("test_results", []))

    fp_count = 0
    for r in rows:
        # offat marks failed tests in different ways across versions
        result_val = r.get("result", r.get("vulnerable", r.get("failed", None)))
        is_failed = (
            result_val is True
            or result_val == "failed"
            or result_val == "vulnerable"
            or str(result_val).lower() in ("true", "failed", "vulnerable")
        )
        if not is_failed:
            continue

        # ── FP filter: skip findings that are demonstrably not real ──
        if _is_offat_false_positive(r):
            fp_count += 1
            continue

        method = str(r.get("method", r.get("request", {}).get("method", "GET"))).upper()
        url = r.get("url", r.get("request", {}).get("url", target))
        test_name = r.get("test_name", r.get("name", "OWASP API check"))
        severity = r.get("severity") or _infer_offat_severity(test_name)

        evidence = dict(r) if isinstance(r, dict) else {}
        status = evidence.get("response_status_code", evidence.get("status_code"))
        if status not in (None, ""):
            evidence["response_code"] = str(status)
            evidence.setdefault("status_code", status)
        evidence.setdefault("http_method", method)
        evidence.setdefault("method", method)
        if url:
            evidence.setdefault("url", url)

        findings.append({
            "id": f"OFFAT-{len(findings)+1:04d}",
            "title": f"[OFFAT] {test_name}",
            "severity": severity,
            "confidence": 0.80,
            "category": "OWASP API Security Top 10",
            "endpoint": f"{method} {url}",
            "source_tools": ["offat"],
            "evidence": evidence,
            "repro": {"curl": f"curl -X {method} '{url}'", "method": method},
        })

    if fp_count:
        logger.info(f"offat FP filter: dropped {fp_count} false positive(s), kept {len(findings)} real finding(s)")

    return findings


def prepare_offat_spec(schema_url: str, target: str) -> str:
    """Offat's OpenAPIv3Parser rejects 3.1 specs. Rewrite a 3.0.3 copy with servers."""
    path = Path(schema_url)
    if not path.is_file():
        return schema_url
    try:
        spec = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return schema_url
    if not isinstance(spec, dict):
        return schema_url
    version = str(spec.get("openapi") or "")
    if version.startswith("3.1"):
        spec["openapi"] = "3.0.3"
    if not spec.get("servers"):
        spec["servers"] = [{"url": origin_of(target) or target.rstrip("/")}]
    out = path.with_name("offat_openapi.json")
    out.write_text(json.dumps(spec, indent=2), encoding="utf-8")
    return str(out)


async def run_offat(
    scan_id: str,
    schema_url: str,
    target: str,
    auth: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run OFFAT for OWASP API Top 10.

    OFFAT writes its JSON output to a file (not stdout), so we use a temp file
    handed to ``run_json_tool``, which parses it, retries on failure, and records
    tool health. ``returncode != 0`` is treated as an error (offat's default).
    """
    with tempfile.NamedTemporaryFile(
        suffix=".json", prefix=f"offat_{scan_id}_", delete=False
    ) as tmp:
        output_file = Path(tmp.name)

    spec_path = prepare_offat_spec(schema_url, target)
    cmd = ["offat", "-f", spec_path, "-t", target, "--format", "json", "-o", str(output_file), "-rl", "30"]
    cmd += auth_cli_flag(auth)

    logger.info(f"[scan:{scan_id}] Running offat: {sanitize_cmd_for_log(cmd)}")

    def _parse(data: Any) -> list[dict[str, Any]]:
        return _parse_offat_output(data, target)

    try:
        result = await run_json_tool(
            scan_id, "offat", cmd, output_file,
            parse_fn=_parse,
            timeout=300.0, max_attempts=2, backoff_seconds=2.0,
        )
        logger.info(f"[scan:{scan_id}] offat: {len(result.findings)} finding(s)")
        return result.findings
    finally:
        try:
            output_file.unlink()
        except OSError:
            pass
