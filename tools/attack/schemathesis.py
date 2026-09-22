"""Schemathesis wrapper — property-based API fuzzing from an OpenAPI schema."""
import asyncio
import logging
import os
import re
import time
from typing import Any

from lib import sanitize_cmd_for_log
from lib.auth_header import auth_cli_flag
from lib.evidence import _phase_dir
from lib.scan_state import scan_state

logger = logging.getLogger("bugtrace-api.tools.attack.schemathesis")


def _parse_schemathesis_output(output: str, target: str) -> list[dict[str, Any]]:
    """Parse schemathesis text output into structured findings."""
    findings = []

    # Quick bail if no failures
    if not re.search(r"\d+ failed", output, re.IGNORECASE):
        return []

    # Locate the FAILURES section
    failures_match = re.search(r"={5,}\s*FAILURES\s*={5,}", output)
    if not failures_match:
        # No structured failures block — create a generic finding from summary
        summary = re.search(r"(\d+) failed.+?in ([\d.]+s)", output)
        if summary:
            findings.append({
                "id": "ST-0001",
                "title": f"[Schemathesis] {summary.group(1)} check(s) failed",
                "severity": "medium",
                "confidence": 0.75,
                "category": "API Specification Conformance",
                "endpoint": target,
                "source_tools": ["schemathesis"],
                "evidence": {"summary": summary.group(0)},
                "repro": {"note": "Re-run schemathesis manually for full details"},
            })
        return findings

    failure_text = output[failures_match.end():]

    # Each failure block is surrounded by lines of underscores
    blocks = re.split(r"\n_{10,}.*?_{10,}\n", failure_text)

    for block in blocks:
        block = block.strip()
        if not block:
            continue

        # Extract HTTP method + path
        ep_match = re.search(
            r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/\S*)", block, re.IGNORECASE
        )
        if not ep_match:
            continue

        method = ep_match.group(1).upper()
        path = ep_match.group(2).split("?")[0]  # strip query string from path

        # Failing check name (lines starting with " - ")
        check_match = re.search(r"^[-–]\s+(.+)$", block, re.MULTILINE)
        check_name = check_match.group(1).strip() if check_match else "check_failed"

        # HTTP response status in the response block
        resp_match = re.search(r"HTTP/[\d.]+ (\d{3})", block)
        resp_code = resp_match.group(1) if resp_match else ""

        severity = "high" if resp_code.startswith("5") else "medium"
        endpoint_url = f"{target.rstrip('/')}{path}"

        findings.append({
            "id": f"ST-{len(findings)+1:04d}",
            "title": f"[Schemathesis] {check_name}: {method} {path}",
            "severity": severity,
            "confidence": 0.85,
            "category": "API Specification Conformance",
            "endpoint": f"{method} {endpoint_url}",
            "source_tools": ["schemathesis"],
            "evidence": {
                "check": check_name,
                "http_method": method,
                "path": path,
                "response_code": resp_code,
                "raw_snippet": block[:600],
            },
            "repro": {"curl": f"curl -X {method} '{endpoint_url}'"},
        })

    return findings


async def run_schemathesis(
    scan_id: str,
    schema_url: str,
    target: str,
    auth: dict[str, Any] | None = None,
    num_paths: int = 0,
    artifact_phase: str = "schema_attack",
) -> list[dict[str, Any]]:
    """Run schemathesis property-based fuzzing."""
    started = time.monotonic()

    # Keep the property-based phase bounded so it cannot starve aggregation or
    # online review. Small schemas still receive deeper fuzzing; larger ones
    # get broad method/path coverage without spending ten minutes on every
    # operation.
    rate_limit = "120/m"
    max_examples = "20"
    if num_paths <= 10:
        rate_limit = "120/m"
        max_examples = "100"
    if num_paths <= 3:
        rate_limit = "200/m"
        max_examples = "250"

    timeout_seconds = max(30, int(os.getenv("BTAI_SCHEMATHESIS_TIMEOUT", "300")))

    # Schemathesis 4: --url (not --base-url), --max-examples (not --hypothesis-max-examples).
    cmd = [
        "schemathesis", "run", schema_url,
        "--url", target,
        "--checks", "all",
        "--phases", "examples,coverage,fuzzing,stateful",
        "--rate-limit", rate_limit,
        "--request-timeout", "10",
        "--generation-maximize", "response_time",
        "--no-color",
        "--max-examples", max_examples,
    ]
    cmd += auth_cli_flag(auth)

    logger.info(f"[scan:{scan_id}] Running schemathesis: {sanitize_cmd_for_log(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
    except FileNotFoundError:
        logger.warning(f"[scan:{scan_id}] schemathesis not found in PATH")
        await scan_state.update_tool_health(
            scan_id, "schemathesis",
            status="not_installed", attempts=1, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="binary_not_found",
        )
        return []
    except Exception as e:
        logger.error(f"[scan:{scan_id}] Schemathesis failed: {e}")
        await scan_state.update_tool_health(
            scan_id, "schemathesis",
            status="error", attempts=1, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=str(e)[:500],
        )
        return []

    try:
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=timeout_seconds)
        except TimeoutError:
            process.kill()
            logger.warning(f"[scan:{scan_id}] Schemathesis timed out after {timeout_seconds}s")
            await scan_state.update_tool_health(
                scan_id, "schemathesis",
                status="timeout", attempts=1, findings_count=0,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=f"timed_out_{timeout_seconds}s",
            )
            return []

        output = stdout.decode(errors="replace")
        stdout_path = _phase_dir(scan_id, artifact_phase) / "schemathesis_stdout.txt"
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text(output, encoding="utf-8", errors="replace")
        if "No such option" in output or (
            process.returncode not in (0, 1, None) and "Usage:" in output
        ):
            err = next(
                (line.strip() for line in reversed(output.splitlines()) if line.strip()),
                "cli_error",
            )[:500]
            logger.warning(f"[scan:{scan_id}] Schemathesis CLI error: {err}")
            await scan_state.update_tool_health(
                scan_id, "schemathesis",
                status="error", attempts=1, findings_count=0,
                duration_ms=int((time.monotonic() - started) * 1000),
                error=err,
            )
            return []
        findings = _parse_schemathesis_output(output, target)
        logger.info(f"[scan:{scan_id}] Schemathesis: {len(findings)} finding(s)")
        await scan_state.update_tool_health(
            scan_id, "schemathesis",
            status="ok", attempts=1, findings_count=len(findings),
            duration_ms=int((time.monotonic() - started) * 1000),
            error=None,
        )
        return findings
    except Exception as e:
        logger.error(f"[scan:{scan_id}] Schemathesis parse/run error: {e}")
        await scan_state.update_tool_health(
            scan_id, "schemathesis",
            status="error", attempts=1, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=str(e)[:500],
        )
        return []
