import asyncio
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from lib import sanitize_cmd_for_log
from lib.auth_header import auth_cli_flag
from lib.scan_state import scan_state
from mcp_server import PARAMS_DIR, X8_BIN

logger = logging.getLogger("bugtrace-api.tools.blind_attack")


# ── arjun (JSON to file) ─────────────────────────────────────────────────────

def _arjun_parse(data: Any) -> list[str]:
    """Normalise arjun's two known JSON shapes into a flat param list.

    arjun output: {url: {method: [params]}} or {url: [params]}
    """
    params: list[str] = []
    if isinstance(data, dict):
        for val in data.values():
            if isinstance(val, dict):
                for p in val.values():
                    if isinstance(p, list):
                        params.extend(p)
            elif isinstance(val, list):
                params.extend(val)
    return params


async def run_arjun(
    scan_id: str,
    endpoint_url: str,
    method: str = "GET",
    auth: dict[str, Any] | None = None,
) -> "tuple[list[str], str | None]":
    """Run arjun parameter discovery on a single endpoint.

    Returns (params, error). error is None only on a genuine completed run
    (even if zero params were found) — callers use it to tell "found nothing"
    apart from "didn't run".
    """
    with tempfile.NamedTemporaryFile(
        suffix=".json", prefix=f"arjun_{scan_id}_", delete=False
    ) as tmp:
        output_file = Path(tmp.name)

    cmd = ["arjun", "-u", endpoint_url, "-oJ", str(output_file), "-q"]
    cmd += auth_cli_flag(auth)

    logger.info(f"[scan:{scan_id}] Running arjun on {endpoint_url}: {sanitize_cmd_for_log(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.warning(f"[scan:{scan_id}] arjun not found in PATH")
        return [], "binary_not_found"

    try:
        try:
            await asyncio.wait_for(process.communicate(), timeout=120)
        except TimeoutError:
            process.kill()
            logger.warning(f"[scan:{scan_id}] arjun timed out on {endpoint_url}")
            return [], "timeout"

        try:
            data = json.loads(output_file.read_text())
            return _arjun_parse(data), None
        except (FileNotFoundError, json.JSONDecodeError):
            return [], "parse_error"
    except Exception as e:
        logger.error(f"[scan:{scan_id}] arjun failed on {endpoint_url}: {e}")
        return [], str(e)
    finally:
        try:
            output_file.unlink()
        except OSError:
            pass


# ── x8 (JSON to stdout, last line) ──────────────────────────────────────────

def _x8_parse(stdout_b: bytes, returncode: int) -> "tuple[list[str], str | None]":
    """x8 prints human-readable progress lines before the JSON result, and
    those lines can themselves contain a literal ``[`` (e.g. a byte-size
    annotation like ``(200) [110] {0}``) — so neither find() nor rfind()
    on the whole blob reliably locates the real JSON start once
    found_params (a nested array) is non-empty. x8 always emits the
    JSON result as its own last non-empty line, so isolate by line.
    """
    if returncode != 0:
        return [], f"exit_{returncode}"
    try:
        raw = stdout_b.decode(errors="replace")
        json_line = next((ln for ln in reversed(raw.strip().splitlines()) if ln.strip()), "")
        if not json_line.startswith("["):
            return [], "parse_error"
        data = json.loads(json_line)
    except Exception:
        return [], "parse_error"
    # x8 JSON: [{method, url, status, size, found_params: [{name, value, ...}], injection_place}]
    params: list[str] = []
    for entry in data:
        for fp in entry.get("found_params", []):
            name = fp.get("name") if isinstance(fp, dict) else fp
            if name:
                params.append(name)
    return params, None


async def run_x8(
    scan_id: str,
    endpoint_url: str,
    method: str = "GET",
    auth: dict[str, Any] | None = None,
) -> "tuple[list[str], str | None]":
    """Run x8 parameter discovery on a single endpoint.

    Returns (params, error) — see ``run_arjun``'s docstring for the contract.
    """
    wordlist_path = PARAMS_DIR / "burp-parameter-names.txt"
    if not wordlist_path.exists():
        return [], "wordlist_not_found"

    cmd = [
        str(X8_BIN),
        "-u", endpoint_url,
        "-w", str(wordlist_path),
        "-X", method,
        "--output-format", "json",
        "--disable-progress-bar",
        "-c", "3",
        "-v", "0",
    ]
    cmd += auth_cli_flag(auth)

    logger.info(f"[scan:{scan_id}] Running x8 on {endpoint_url}: {sanitize_cmd_for_log(cmd)}")

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
    except FileNotFoundError:
        logger.warning(f"[scan:{scan_id}] x8 binary not found at {X8_BIN}")
        return [], "binary_not_found"

    try:
        try:
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=120)
        except TimeoutError:
            process.kill()
            logger.warning(f"[scan:{scan_id}] x8 timed out on {endpoint_url}")
            return [], "timeout"
        return _x8_parse(stdout, process.returncode)
    except Exception as e:
        logger.error(f"[scan:{scan_id}] x8 failed on {endpoint_url}: {e}")
        return [], str(e)


# ── main entry point ─────────────────────────────────────────────────────────

async def run_blind_attack(
    scan_id: str,
    endpoints: list[dict[str, Any]],
    target: str,
    auth: dict[str, Any] | None = None,
):
    """Main entry point for blind (no-schema) attacks.

    Tries x8 first (if binary available), falls back to arjun.
    Limits to top 15 endpoints to avoid hammering the target.
    """
    started = time.monotonic()
    target_endpoints = endpoints[:15] if len(endpoints) > 15 else endpoints

    if not target_endpoints:
        await scan_state.update_tool_health(
            scan_id, "blind_attack",
            status="ok", attempts=1, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=None,
        )
        return

    # Decide which tool to use: x8 (if binary exists and is executable) else arjun
    use_x8 = X8_BIN.exists() and os.access(str(X8_BIN), os.X_OK)
    tool_name = "x8" if use_x8 else "arjun"
    logger.info(f"[scan:{scan_id}] Blind attack using {tool_name} on {len(target_endpoints)} endpoints")

    tasks = []
    semaphore = asyncio.Semaphore(5)

    async def _run_with_limit(endpoint: dict[str, Any]) -> tuple[list[str], str | None]:
        url = endpoint["url"]
        method = endpoint.get("method", "GET")
        async with semaphore:
            if use_x8:
                return await run_x8(scan_id, url, method, auth)
            return await run_arjun(scan_id, url, method, auth)

    for endpoint in target_endpoints:
        tasks.append(_run_with_limit(endpoint))

    results = await asyncio.gather(*tasks)
    findings_count = 0
    errors = [error for _, error in results if error]

    for i, (params, _error) in enumerate(results):
        if params:
            url = target_endpoints[i]["url"]
            method = target_endpoints[i].get("method", "GET")
            logger.info(f"[scan:{scan_id}] {tool_name} discovered {len(params)} parameter(s) on {url}")

            qs = "&".join(f"{p}=1" for p in params[:20])
            finding = {
                "id": f"BLIND-{i+1:04d}",
                "title": f"[{tool_name}] Undocumented parameters on {method} {url}",
                "severity": "low",
                "confidence": 0.85,
                "category": "Information Disclosure",
                "endpoint": f"{method} {url}",
                "source_tools": [tool_name],
                "evidence": {"discovered_parameters": params},
                "repro": {"curl": f"curl -X {method} '{url}?{qs}'"},
            }
            await scan_state.add_finding(scan_id, finding)
            findings_count += 1

    duration_ms = int((time.monotonic() - started) * 1000)
    attempted = len(target_endpoints)
    if errors and len(errors) == attempted:
        health_status, health_error = "error", f"all {attempted} probe(s) failed: {errors[0]}"
    elif errors:
        health_status, health_error = "ok", f"{len(errors)}/{attempted} probe(s) failed: {errors[0]}"
    else:
        health_status, health_error = "ok", None

    await scan_state.update_tool_health(
        scan_id, tool_name,
        status=health_status, attempts=attempted,
        findings_count=findings_count, duration_ms=duration_ms,
        error=health_error,
    )
    # M-5: Also register under phase name for consistent telemetry
    await scan_state.update_tool_health(
        scan_id, "blind_attack",
        status=health_status, attempts=attempted,
        findings_count=findings_count, duration_ms=duration_ms,
        error=health_error,
    )
