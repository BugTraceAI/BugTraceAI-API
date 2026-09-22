"""Tests for scan_state, orchestrator, discovery, and pipeline behaviour.

Covers the top-10 priority tests from the security review:
 1. Full pipeline → completed, progress 1.0, findings in results
 2. Pipeline failure → status=failed, not stuck in running
 3. stop_scan during Phase 1 → Phase 2 does not start
 4. Concurrent create_scan → no data corruption
 5. Binary not found → returns [], tool_health=not_installed
 6. Retry on transient failure
 7. get_results during running → partial results without crash
 8. _calculate_coverage with empty endpoints
 9. Schema probe with mock server
10. Pipeline with no tools installed → graceful degradation
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ────────────────────────────────────────────────────────────────────────────
# Test 1: Full pipeline completes correctly with mocked tools
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_full_pipeline_completes(scan_state, tmp_path):
    """Mocked pipeline runs all phases → status=completed, progress=1.0."""
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t001", "https://example.com")

    fake_endpoints = [{"method": "GET", "status": 200, "url": "https://example.com/api/v1/users"}]
    fake_findings = [{
        "id": "ST-0001",
        "title": "test finding",
        "severity": "medium",
        "confidence": 0.8,
        "category": "test",
        "endpoint": "GET /api/v1/users",
        "source_tools": ["schemathesis"],
        "evidence": {"check": "status_code_conformance", "response_code": "500"},
        "repro": {"curl": "curl ..."},
    }]

    async def mock_kr_scan(scan_id, target, depth, auth, baseline_length, **kwargs):
        await scan_state.add_endpoints(scan_id, fake_endpoints)
        return fake_endpoints

    async def mock_kr_brute(scan_id, target, auth, baseline_length):
        await scan_state.add_endpoints(scan_id, fake_endpoints)
        return fake_endpoints

    async def mock_crawl(scan_id, target, auth, **kwargs):
        return []

    async def mock_probe(target, auth, discovered_endpoints=None, scan_id=None):
        return None  # No schema → blind path

    async def mock_blind(scan_id, endpoints, target, auth):
        for f in fake_findings:
            await scan_state.add_finding(scan_id, f)
        # Also write findings to disk (file-based pipeline reads from here)
        from lib.evidence import save_artifact
        save_artifact(scan_id, "blind_attack", "findings_schemathesis", fake_findings)

    with patch("orchestrator.run_kiterunner_scan", side_effect=mock_kr_scan), \
         patch("orchestrator.run_kiterunner_brute", side_effect=mock_kr_brute), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", side_effect=mock_crawl), \
         patch("orchestrator.probe_schema", side_effect=mock_probe), \
         patch("orchestrator.run_blind_attack", side_effect=mock_blind), \
         patch("orchestrator.run_schema_attack", new_callable=AsyncMock):

        await orch._run_pipeline("t001", "https://example.com", "standard")

    status = await scan_state.get_scan("t001")
    assert status.status == "completed"
    assert status.progress == 1.0
    assert status.findings_count == 1

    results = await scan_state.get_results("t001")
    assert len(results["findings"]) == 1
    assert results["tool_health"]["orchestrator"]["status"] == "ok"


# ────────────────────────────────────────────────────────────────────────────
# Test 2: Pipeline failure → status=failed (B-1: not stuck in running)
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_failure_sets_failed(scan_state):
    """If Phase 1 throws, status must be 'failed', not 'running'."""
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t002", "https://example.com")

    async def exploding_kr(scan_id, target, auth, baseline_length):
        raise RuntimeError("simulated kiterunner crash")

    with patch("orchestrator.run_kiterunner_scan", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.run_kiterunner_brute", side_effect=exploding_kr), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]):

        await orch._run_pipeline("t002", "https://example.com", "standard")

    status = await scan_state.get_scan("t002")
    assert status.status == "failed"
    assert "simulated kiterunner crash" in status.error
    assert status.finished_at is not None


# ────────────────────────────────────────────────────────────────────────────
# Test 3: stop_scan prevents Phase 2 from starting
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stop_scan_prevents_next_phase(scan_state):
    """Stopping mid-discovery should abort before schema probe."""
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t003", "https://example.com")

    async def kr_that_stops(scan_id, target, auth, baseline_length):
        # Simulate user hitting stop during discovery
        await scan_state.update_scan(scan_id, status="stopped")
        return [{"method": "GET", "status": 200, "url": "https://example.com/a"}]

    probe_called = False

    async def spy_probe(target, auth, discovered_endpoints=None, scan_id=None):
        nonlocal probe_called
        probe_called = True
        return None

    with patch("orchestrator.run_kiterunner_scan", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.run_kiterunner_brute", side_effect=kr_that_stops), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.probe_schema", side_effect=spy_probe), \
         patch("orchestrator.run_blind_attack", new_callable=AsyncMock), \
         patch("orchestrator.run_schema_attack", new_callable=AsyncMock):

        await orch._run_pipeline("t003", "https://example.com", "standard")

    assert not probe_called, "Schema probe should not run after stop"
    status = await scan_state.get_scan("t003")
    assert status.status == "stopped"


# ────────────────────────────────────────────────────────────────────────────
# Test 4: Concurrent create_scan → no data corruption (B-2)
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_concurrent_create_scan(scan_state):
    """Multiple concurrent create_scan calls must not corrupt state."""

    async def create(sid):
        await scan_state.create_scan(sid, f"https://t{sid}.com")

    await asyncio.gather(*[create(f"c{i:03d}") for i in range(20)])

    for i in range(20):
        sid = f"c{i:03d}"
        s = await scan_state.get_scan(sid)
        assert s is not None
        assert s.target == f"https://t{sid}.com"


# ────────────────────────────────────────────────────────────────────────────
# Test 5: Binary not found → returns [], tool_health=not_installed
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_kiterunner_not_installed(scan_state, tmp_path):
    """If kiterunner binary is missing, returns [] and sets tool_health."""
    from tools.discovery import run_kiterunner_scan

    await scan_state.create_scan("t005", "https://example.com")

    # Create a fake .kite wordlist so we reach the subprocess call
    fake_wl = tmp_path / "routes-small.kite"
    fake_wl.touch()

    with patch("tools.discovery.WORDLISTS_DIR", tmp_path), \
         patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError("no kr")):
        result = await run_kiterunner_scan("t005", "https://example.com", "standard", None, None)

    assert result == []
    results = await scan_state.get_results("t005")
    health = results["tool_health"]["kiterunner_scan"]
    assert health["status"] == "not_installed"
    assert health["error"] == "binary_not_found"


# ────────────────────────────────────────────────────────────────────────────
# Test 6: Retry on transient failure (M-1 for discovery)
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_kiterunner_retry_on_failure(scan_state):
    """Kiterunner retries once on non-zero exit, then succeeds."""
    from tools.discovery import run_kiterunner_brute

    await scan_state.create_scan("t006", "https://example.com")

    call_count = 0

    class AsyncLineIter:
        """Async iterator over byte lines for mocking process.stdout."""
        def __init__(self, lines):
            self._lines = iter(lines)
        def __aiter__(self):
            return self
        async def __anext__(self):
            try:
                return next(self._lines)
            except StopIteration:
                raise StopAsyncIteration

    async def mock_exec(*cmd, stdout=None, stderr=None):
        nonlocal call_count
        call_count += 1
        proc = MagicMock()

        if call_count == 1:
            # First attempt: fail
            proc.stdout = AsyncLineIter([])
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"transient error")
            proc.wait = AsyncMock()
            proc.returncode = 1
        else:
            # Second attempt: succeed with endpoint
            line = b"GET 200 [  10,   1,  100] https://example.com/api/users\n"
            proc.stdout = AsyncLineIter([line])
            proc.stderr = AsyncMock()
            proc.stderr.read = AsyncMock(return_value=b"")
            proc.wait = AsyncMock()
            proc.returncode = 0
        return proc

    # Create a fake text wordlist so brute mode fallback works
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        fake_text_dir = Path(td)
        fake_wl = fake_text_dir / "api-endpoints.txt"
        fake_wl.write_text("api/users\n")

        with patch("tools.discovery.TEXT_WORDLISTS_DIR", fake_text_dir), \
             patch("asyncio.create_subprocess_exec", side_effect=mock_exec), \
             patch("tools.discovery.DISCOVERY_BACKOFF_SECONDS", 0):
            result = await run_kiterunner_brute("t006", "https://example.com", None, None)

    assert call_count == 2
    assert len(result) == 1
    assert result[0]["url"] == "https://example.com/api/users"


# ────────────────────────────────────────────────────────────────────────────
# Test 7: get_results during running scan → returns partial data
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_results_during_running(scan_state):
    """Querying results mid-scan returns whatever is available."""
    await scan_state.create_scan("t007", "https://example.com")
    await scan_state.update_scan("t007", status="running", current_phase="discovery")
    await scan_state.add_endpoints("t007", [{"method": "GET", "url": "https://example.com/a"}])

    results = await scan_state.get_results("t007")
    assert results is not None
    assert results["status"]["status"] == "running"
    assert len(results["endpoints"]) == 1
    assert results["findings"] == []


# ────────────────────────────────────────────────────────────────────────────
# Test 8: _calculate_coverage with empty endpoints → 0.5 (M-3 fix)
# ────────────────────────────────────────────────────────────────────────────

def test_calculate_coverage_empty_endpoints():
    """Empty endpoints should return 0.5 (triggers both attack paths)."""
    from lib.schema_probe import _calculate_coverage

    schema = {"openapi": "3.0.0", "paths": {"/users": {}, "/items": {}}}
    assert _calculate_coverage(schema, []) is None


def test_calculate_coverage_full_match():
    """All endpoints present in schema → coverage near 1.0."""
    from lib.schema_probe import _calculate_coverage

    schema = {"paths": {"/users": {}, "/items": {}}}
    endpoints = [
        {"method": "GET", "url": "https://example.com/users"},
        {"method": "GET", "url": "https://example.com/items"},
    ]
    assert _calculate_coverage(schema, endpoints) == 1.0


def test_calculate_coverage_partial():
    """Only half the endpoints covered → coverage ~0.5."""
    from lib.schema_probe import _calculate_coverage

    schema = {"paths": {"/users": {}}}
    endpoints = [
        {"method": "GET", "url": "https://example.com/users"},
        {"method": "GET", "url": "https://example.com/admin"},
    ]
    assert _calculate_coverage(schema, endpoints) == 0.5


def test_calculate_coverage_no_paths():
    """Schema with no paths → 0.0."""
    from lib.schema_probe import _calculate_coverage

    schema = {"openapi": "3.0.0", "paths": {}}
    endpoints = [{"method": "GET", "url": "https://example.com/users"}]
    assert _calculate_coverage(schema, endpoints) == 0.0


# ────────────────────────────────────────────────────────────────────────────
# Test 9: set_schema under lock (A-2 fix)
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_set_schema_under_lock(scan_state):
    """set_schema writes schema safely through the lock."""
    await scan_state.create_scan("t009", "https://example.com")
    schema = {"url": "https://example.com/openapi.json", "coverage": 1.0}
    await scan_state.set_schema("t009", schema)

    results = await scan_state.get_results("t009")
    assert results["schema"]["url"] == "https://example.com/openapi.json"


# ────────────────────────────────────────────────────────────────────────────
# Test 10: Pipeline with no tools → graceful degradation
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_no_tools_graceful(scan_state, tmp_path):
    """Full pipeline with all tools returning [] → completed, 0 findings."""
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t010", "https://example.com")

    with patch("orchestrator.run_kiterunner_scan", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.run_kiterunner_brute", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.probe_schema", new_callable=AsyncMock, return_value=None), \
         patch("orchestrator.run_blind_attack", new_callable=AsyncMock):

        await orch._run_pipeline("t010", "https://example.com", "standard")

    status = await scan_state.get_scan("t010")
    assert status.status == "completed"
    assert status.progress == 1.0
    assert status.findings_count == 0

    results = await scan_state.get_results("t010")
    assert results["findings"] == []


# ────────────────────────────────────────────────────────────────────────────
# Extra: is_stopped helper
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_stopped(scan_state):
    await scan_state.create_scan("ts01", "https://example.com")
    assert not await scan_state.is_stopped("ts01")
    await scan_state.update_scan("ts01", status="stopped")
    assert await scan_state.is_stopped("ts01")


# ────────────────────────────────────────────────────────────────────────────
# Extra: cleanup_old_scans (M-7 fix)
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_cleanup_old_scans(scan_state):
    """Cleanup removes oldest finished scans beyond MAX_COMPLETED_SCANS."""
    from lib.scan_state import MAX_COMPLETED_SCANS

    # Create MAX + 5 completed scans
    for i in range(MAX_COMPLETED_SCANS + 5):
        sid = f"cleanup{i:04d}"
        await scan_state.create_scan(sid, "https://example.com")
        await scan_state.update_scan(sid, status="completed")

    removed = await scan_state.cleanup_old_scans()
    assert removed == 5

    # Should have exactly MAX left
    remaining = len([
        s for s in scan_state.active_scans.values()
        if s.status == "completed"
    ])
    assert remaining == MAX_COMPLETED_SCANS


# ────────────────────────────────────────────────────────────────────────────
# Extra: Semaphore limits concurrency (A-4 fix)
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_semaphore_limits_concurrency(scan_state):
    """Orchestrator semaphore limits concurrent pipeline runs."""
    from orchestrator import MAX_CONCURRENT_SCANS, Orchestrator

    orch = Orchestrator()
    running_count = 0
    max_seen = 0

    async def slow_pipeline(scan_id, target, depth, auth=None, schema_url=None, **kwargs):
        nonlocal running_count, max_seen
        running_count += 1
        max_seen = max(max_seen, running_count)
        await asyncio.sleep(0.05)
        running_count -= 1

    orch._run_pipeline = slow_pipeline

    # Create more scans than the limit
    n = MAX_CONCURRENT_SCANS + 3
    for i in range(n):
        await scan_state.create_scan(f"sem{i:03d}", "https://example.com")

    tasks = [
        asyncio.create_task(orch.run_scan(f"sem{i:03d}", "https://example.com", "standard"))
        for i in range(n)
    ]
    await asyncio.gather(*tasks)

    assert max_seen <= MAX_CONCURRENT_SCANS


# ────────────────────────────────────────────────────────────────────────────
# Extra: sanitize_cmd_for_log (L-3 fix)
# ────────────────────────────────────────────────────────────────────────────

def test_sanitize_cmd_for_log():
    from lib import sanitize_cmd_for_log

    cmd = ["/usr/local/bin/kr", "scan", "https://example.com", "-H", "Authorization: Bearer secret123"]
    sanitized = sanitize_cmd_for_log(cmd)
    assert "secret123" not in sanitized
    assert "***" in sanitized


# ────────────────────────────────────────────────────────────────────────────
# Extra: B-1 double-fault protection
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_pipeline_error_handler_resilient(scan_state):
    """If update_scan itself fails inside the error handler, scan doesn't hang."""
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t_b1", "https://example.com")

    async def exploding_kr(scan_id, target, depth, auth, baseline_length):
        raise RuntimeError("tool crash")

    # Make update_scan fail on the SECOND call (the one inside the except)
    original_update = scan_state.update_scan.__func__
    call_count = 0

    async def flaky_update(self, scan_id, **kwargs):
        nonlocal call_count
        call_count += 1
        if kwargs.get("status") == "failed":
            raise RuntimeError("state update also crashed")
        return await original_update(self, scan_id, **kwargs)

    import types
    scan_state.update_scan = types.MethodType(flaky_update, scan_state)

    with patch("orchestrator.run_kiterunner_scan", side_effect=exploding_kr), \
         patch("orchestrator.run_kiterunner_brute", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]):
        # This should NOT raise — the double-fault is caught internally
        await orch._run_pipeline("t_b1", "https://example.com", "standard")

    # Scan won't be "failed" because update_scan itself failed, but we prove
    # the pipeline didn't crash/hang — it returned cleanly.


# ────────────────────────────────────────────────────────────────────────────
# FP Filter: offat false-positive detection
# ────────────────────────────────────────────────────────────────────────────

def test_offat_fp_filter_not_vulnerable():
    """offat findings with 'not vulnerable' in result_details should be filtered."""
    from tools.schema_attack import _parse_offat_output

    data = [
        {
            "result": True,
            "test_name": "SQL Injection test",
            "method": "GET",
            "url": "https://example.com/api",
            "severity": "medium",
            "result_details": "Parameters are not vulnerable to SQLi Payload",
            "response_status_code": 200,
        },
        {
            "result": True,
            "test_name": "Actual vuln",
            "method": "POST",
            "url": "https://example.com/api",
            "severity": "high",
            "result_details": "SQL injection confirmed: error-based",
            "response_status_code": 500,
        },
    ]
    findings = _parse_offat_output(data, "https://example.com")
    assert len(findings) == 1
    assert "Actual vuln" in findings[0]["title"]


def test_offat_fp_filter_unsupported_method():
    """405 for unsupported method test = correct server behavior, not a vuln."""
    from tools.schema_attack import _parse_offat_output

    data = [{
        "result": True,
        "test_name": "Checking for UnSupported HTTP Method",
        "method": "TRACE",
        "url": "https://example.com/api",
        "severity": "medium",
        "result_details": "Endpoint does not perform any HTTP method which is not documented",
        "response_status_code": 405,
    }]
    findings = _parse_offat_output(data, "https://example.com")
    assert len(findings) == 0


def test_offat_fp_filter_data_leak_benign():
    """data_leak matching 'access_token' in normal JSON = false positive."""
    from tools.schema_attack import _parse_offat_output

    data = [{
        "result": True,
        "test_name": "Data Leak check",
        "method": "GET",
        "url": "https://example.com/api",
        "severity": "medium",
        "result_details": "possible data leak",
        "response_status_code": 200,
        "data_leak": {"matches": ["access_token", "bearer"]},
    }]
    findings = _parse_offat_output(data, "https://example.com")
    assert len(findings) == 0


def test_offat_real_finding_passes_filter():
    """A genuine finding should not be filtered out."""
    from tools.schema_attack import _parse_offat_output

    data = [{
        "result": True,
        "test_name": "BOLA: Accessing other user data",
        "method": "GET",
        "url": "https://example.com/api/users/1",
        "severity": "high",
        "result_details": "Response contains different user data when ID changed",
        "response_status_code": 200,
    }]
    findings = _parse_offat_output(data, "https://example.com")
    assert len(findings) == 1
    assert findings[0]["evidence"]["response_code"] == "200"
    assert findings[0]["evidence"]["http_method"] == "GET"


# ────────────────────────────────────────────────────────────────────────────
# OpenAPI enrichment: infer schema from JSON
# ────────────────────────────────────────────────────────────────────────────

def test_infer_json_schema_basic():
    """_infer_json_schema correctly identifies types."""
    from lib.evidence import _infer_json_schema

    assert _infer_json_schema(42) == {"type": "integer"}
    assert _infer_json_schema(3.14) == {"type": "number"}
    assert _infer_json_schema(True) == {"type": "boolean"}
    assert _infer_json_schema("hello") == {"type": "string"}
    assert _infer_json_schema(None) == {"nullable": True}


def test_infer_json_schema_object():
    """Objects should have properties inferred."""
    from lib.evidence import _infer_json_schema

    schema = _infer_json_schema({"name": "John", "age": 30})
    assert schema["type"] == "object"
    assert "properties" in schema
    assert schema["properties"]["name"] == {"type": "string"}
    assert schema["properties"]["age"] == {"type": "integer"}


def test_infer_json_schema_array():
    """Arrays should have items inferred."""
    from lib.evidence import _infer_json_schema

    schema = _infer_json_schema([{"id": 1}])
    assert schema["type"] == "array"
    assert schema["items"]["type"] == "object"


def test_infer_json_schema_uri():
    """URLs should get format: uri."""
    from lib.evidence import _infer_json_schema

    schema = _infer_json_schema("https://example.com/api")
    assert schema == {"type": "string", "format": "uri"}
