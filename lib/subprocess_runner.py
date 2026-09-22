"""Reusable async-subprocess-with-retry runner for every tool wrapper.

The tool wrappers (kiterunner, offat, vulnapi, arjun, x8) all used to duplicate
the same pattern: spawn → wait_for(timeout) → check returncode → record health
→ backoff-and-retry on failure. This module centralises the boilerplate so a
new tool wrapper only has to declare *what* it runs and *how* to interpret
the result.

Three call shapes are supported via three helpers, chosen to match how each
tool actually behaves in production:

  • :func:`run_json_tool` — tool writes JSON to a file. Returns parsed dict/list
                            plus a structured status (offat, vulnapi).
  • :func:`run_text_tool` — tool writes parseable text to stdout (kiterunner).
  • :func:`run_stream_tool` — tool produces live stdout that you parse as it
                              streams in (kiterunner is also a consumer of
                              this pattern via ``on_line`` callbacks).

All three return a :class:`SubprocessResult` with the same shape, so callers
can build health updates uniformly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from lib.scan_state import scan_state

logger = logging.getLogger("bugtrace-api.subprocess_runner")


class Status(StrEnum):
    """Outcome of a subprocess run — matches scan_state tool_health.status."""
    OK = "ok"
    TIMEOUT = "timeout"
    ERROR = "error"
    NOT_INSTALLED = "not_installed"


@dataclass
class SubprocessResult:
    """Uniform result from any of the run_*_tool helpers."""
    status: Status
    attempts: int
    duration_ms: int
    error: str | None = None
    data: Any = None              # parsed JSON / accumulated text / list of endpoints
    findings: list[dict[str, Any]] = field(default_factory=list)


async def _record_health(
    scan_id: str,
    tool_name: str,
    result: SubprocessResult,
) -> None:
    """Mirror the result into ``scan_state.tool_health`` (one call per result)."""
    await scan_state.update_tool_health(
        scan_id,
        tool_name,
        status=result.status.value,
        attempts=result.attempts,
        findings_count=len(result.findings) if result.findings else 0,
        duration_ms=result.duration_ms,
        error=result.error,
    )


async def _spawn_and_wait(
    cmd: list[str],
    timeout: float,
    *,
    stdout: Any = asyncio.subprocess.PIPE,
    stderr: Any = asyncio.subprocess.PIPE,
) -> tuple[asyncio.subprocess.Process, bytes, bytes, bool]:
    """Spawn ``cmd``, wait for it, return (process, stdout, stderr, timed_out)."""
    process = await asyncio.create_subprocess_exec(*cmd, stdout=stdout, stderr=stderr)
    timed_out = False
    try:
        stdout_b, stderr_b = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        timed_out = True
        stdout_b, stderr_b = b"", b""
    return process, stdout_b, stderr_b, timed_out


async def run_json_tool(
    scan_id: str,
    tool_name: str,
    cmd: list[str],
    output_path: Path,
    parse_fn: Callable[[Any], list[dict[str, Any]]],
    *,
    timeout: float = 300.0,
    max_attempts: int = 2,
    backoff_seconds: float = 2.0,
    stderr_in_stdout: bool = True,
    success_exit_codes: tuple[int, ...] = (0,),
) -> SubprocessResult:
    """Run a tool that writes a JSON report to ``output_path``.

    ``parse_fn`` receives the parsed JSON and returns the list of findings.
    Exit codes not in ``success_exit_codes`` are treated as errors and retried.
    Use ``success_exit_codes=(0, 1)`` for tools like vulnapi that return 1 to
    signal "vulnerabilities found".
    """
    started = time.monotonic()
    last_error: str | None = None
    output_file = str(output_path)

    for attempt in range(1, max_attempts + 1):
        try:
            process, _stdout_b, stderr_b, timed_out = await _spawn_and_wait(
                cmd, timeout,
                stdout=asyncio.subprocess.DEVNULL if not stderr_in_stdout else asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            res = SubprocessResult(
                status=Status.NOT_INSTALLED, attempts=1,
                duration_ms=int((time.monotonic() - started) * 1000),
                error="binary_not_found",
            )
            await _record_health(scan_id, tool_name, res)
            return res

        if timed_out:
            last_error = f"timed_out_{int(timeout)}s"
            logger.warning(f"[scan:{scan_id}] {tool_name} timed out after {int(timeout)}s (attempt {attempt}/{max_attempts})")
            if attempt < max_attempts:
                await asyncio.sleep(backoff_seconds * attempt)
                continue
            res = SubprocessResult(status=Status.TIMEOUT, attempts=attempt,
                                   duration_ms=int((time.monotonic() - started) * 1000),
                                   error=last_error)
            await _record_health(scan_id, tool_name, res)
            return res

        err = stderr_b.decode(errors="replace").strip()
        rc = process.returncode

        if rc not in success_exit_codes:
            last_error = f"exit_code_{rc}"
            logger.warning(
                f"[scan:{scan_id}] {tool_name} exited with code {rc} "
                f"(attempt {attempt}/{max_attempts}). stderr={err[:500]}"
            )
            if attempt < max_attempts:
                await asyncio.sleep(backoff_seconds * attempt)
                continue
            res = SubprocessResult(status=Status.ERROR, attempts=attempt,
                                   duration_ms=int((time.monotonic() - started) * 1000),
                                   error=last_error)
            await _record_health(scan_id, tool_name, res)
            return res

        if not Path(output_file).exists() or Path(output_file).stat().st_size == 0:
            last_error = "empty_output_file"
            logger.warning(
                f"[scan:{scan_id}] {tool_name} produced no JSON output (attempt {attempt}/{max_attempts}). "
                f"stderr={err[:500]}"
            )
            if attempt < max_attempts:
                await asyncio.sleep(backoff_seconds * attempt)
                continue
            res = SubprocessResult(status=Status.ERROR, attempts=attempt,
                                   duration_ms=int((time.monotonic() - started) * 1000),
                                   error=last_error)
            await _record_health(scan_id, tool_name, res)
            return res

        try:
            raw = Path(output_file).read_text()
            data = json.loads(raw)
        except (json.JSONDecodeError, OSError) as parse_err:
            last_error = f"output_parse_error:{parse_err}"
            logger.warning(f"[scan:{scan_id}] {tool_name} parse error: {parse_err} (attempt {attempt}/{max_attempts})")
            if attempt < max_attempts:
                await asyncio.sleep(backoff_seconds * attempt)
                continue
            res = SubprocessResult(status=Status.ERROR, attempts=attempt,
                                   duration_ms=int((time.monotonic() - started) * 1000),
                                   error=last_error)
            await _record_health(scan_id, tool_name, res)
            return res

        findings = parse_fn(data)
        res = SubprocessResult(
            status=Status.OK, attempts=attempt,
            duration_ms=int((time.monotonic() - started) * 1000),
            data=data, findings=findings,
        )
        await _record_health(scan_id, tool_name, res)
        return res

    # Should be unreachable — every branch above returns.
    res = SubprocessResult(
        status=Status.ERROR, attempts=max_attempts,
        duration_ms=int((time.monotonic() - started) * 1000),
        error=last_error,
    )
    await _record_health(scan_id, tool_name, res)
    return res


async def run_stream_tool(
    scan_id: str,
    tool_name: str,
    cmd: list[str],
    on_line: Callable[[str], dict[str, Any] | None],
    *,
    timeout: float = 300.0,
    max_attempts: int = 2,
    backoff_seconds: float = 2.0,
) -> SubprocessResult:
    """Run a tool that streams parseable lines to stdout (kiterunner).

    ``on_line`` is called for every non-empty stdout line. It may be sync or async.
    Returning a dict appends it to the result's ``data`` list; returning None discards.
    The runner returns when the process exits or the per-stream wall-clock
    timeout fires (in which case partial data is kept).
    """
    started = time.monotonic()
    last_error: str | None = None
    is_async_on_line = asyncio.iscoroutinefunction(on_line)

    for attempt in range(1, max_attempts + 1):
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except FileNotFoundError:
            res = SubprocessResult(
                status=Status.NOT_INSTALLED, attempts=1,
                duration_ms=int((time.monotonic() - started) * 1000),
                error="binary_not_found",
            )
            await _record_health(scan_id, tool_name, res)
            return res

        endpoints: list[dict[str, Any]] = []
        timed_out = False
        drain_done = asyncio.Event()

        async def _drain() -> None:
            nonlocal timed_out
            try:
                assert process.stdout is not None
                async for raw_line in process.stdout:
                    line = raw_line.decode(errors="replace")
                    if is_async_on_line:
                        parsed = await on_line(line)
                    else:
                        parsed = on_line(line)
                    if parsed is not None:
                        endpoints.append(parsed)
            except asyncio.CancelledError:
                pass
            finally:
                drain_done.set()

        drain_task = asyncio.create_task(_drain())

        try:
            await asyncio.wait_for(drain_done.wait(), timeout=timeout)
        except TimeoutError:
            timed_out = True
            drain_task.cancel()
            try:
                await drain_task
            except asyncio.CancelledError:
                pass
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except TimeoutError:
                process.kill()
                await process.wait()

        if not drain_done.is_set():
            # still draining — wait for it to finish cleanup
            try:
                await asyncio.wait_for(drain_done.wait(), timeout=2.0)
            except TimeoutError:
                drain_task.cancel()

        await process.wait()

        if timed_out:
            last_error = f"{tool_name}_timeout_{int(timeout)}s"
            logger.warning(
                f"[scan:{scan_id}] {tool_name} timed out after {int(timeout)}s "
                f"(attempt {attempt}/{max_attempts}) — returning {len(endpoints)} partial result(s)"
            )
            res = SubprocessResult(
                status=Status.TIMEOUT, attempts=attempt,
                duration_ms=int((time.monotonic() - started) * 1000),
                data=endpoints, error=last_error,
            )
            await _record_health(scan_id, tool_name, res)
            return res

        if process.returncode != 0:
            last_error = f"exit_code_{process.returncode}"
            logger.warning(
                f"[scan:{scan_id}] {tool_name} exited with code {process.returncode} "
                f"(attempt {attempt}/{max_attempts})"
            )
            if attempt < max_attempts:
                await asyncio.sleep(backoff_seconds * attempt)
                continue
            res = SubprocessResult(
                status=Status.ERROR, attempts=attempt,
                duration_ms=int((time.monotonic() - started) * 1000),
                data=endpoints, error=last_error,
            )
            await _record_health(scan_id, tool_name, res)
            return res

        res = SubprocessResult(
            status=Status.OK, attempts=attempt,
            duration_ms=int((time.monotonic() - started) * 1000),
            data=endpoints,
        )
        await _record_health(scan_id, tool_name, res)
        return res

    res = SubprocessResult(
        status=Status.ERROR, attempts=max_attempts,
        duration_ms=int((time.monotonic() - started) * 1000),
        data=endpoints, error=last_error,
    )
    await _record_health(scan_id, tool_name, res)
    return res



async def run_quick_subprocess(
    scan_id: str,
    tool_name: str,
    cmd: list[str],
    parse_fn: Callable[[bytes, int], tuple[Any, str | None]],
    *,
    timeout: float = 120.0,
) -> SubprocessResult:
    """One-shot subprocess run with no retry — used for per-endpoint probes
    (arjun/x8) where the runner is the one providing concurrency via gather().

    ``parse_fn`` receives ``(stdout_bytes, returncode)`` and returns
    ``(data, error_str)``. ``error_str`` is None on success.
    """
    started = time.monotonic()
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        res = SubprocessResult(
            status=Status.NOT_INSTALLED, attempts=1,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="binary_not_found",
        )
        await _record_health(scan_id, tool_name, res)
        return res

    try:
        stdout_b, _stderr_b = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        res = SubprocessResult(
            status=Status.TIMEOUT, attempts=1,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="timeout",
        )
        await _record_health(scan_id, tool_name, res)
        return res

    data, err = parse_fn(stdout_b, process.returncode)
    if err is not None:
        res = SubprocessResult(
            status=Status.ERROR, attempts=1,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=err, data=data,
        )
    else:
        res = SubprocessResult(
            status=Status.OK, attempts=1,
            duration_ms=int((time.monotonic() - started) * 1000),
            data=data,
        )
    await _record_health(scan_id, tool_name, res)
    return res
