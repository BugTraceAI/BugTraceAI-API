"""Regression tests for the 8 HIGH-severity bugs found in the 2026-07-26 logic audit.

 1. REST /api/scan now registers a cancellable task (DELETE used to be a no-op)
 2. Stop requests during/after Phase 3 or 4 no longer get overwritten by "completed"
 3. run_x8 extracts parameter *names*, not raw found_params dicts
 4. offat findings get a severity inferred from test_name, not a fixed "medium"
 5. run_blind_attack's tool_health reflects real x8/arjun failures, not always "ok"
 6. _find_free_port never assigns the same port to both the MCP and REST servers
 7. create_scan_dir never collides for two scans of the same target in the same second
 8. --ignore-length is only threaded through kiterunner on a genuine SPA catch-all
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ────────────────────────────────────────────────────────────────────────────
# Fix 1: REST start_scan registers a cancellable task
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_start_scan_registers_task_so_stop_actually_works(scan_state):
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def slow_run_scan(scan_id, target, depth, auth=None, schema_url=None, **kwargs):
        await asyncio.sleep(10)

    with patch.object(orchestrator, "run_scan", side_effect=slow_run_scan):
        req = ScanRequest(target="https://example.com")
        resp = await api_server.start_scan(req)
        scan_id = resp["scan_id"]

        try:
            # This is the actual regression: before the fix, active_tasks never
            # got an entry for REST-started scans, so cancel_scan was a no-op.
            assert scan_id in orchestrator.active_tasks
            cancelled = await orchestrator.cancel_scan(scan_id)
            assert cancelled is True
        finally:
            task = orchestrator.active_tasks.pop(scan_id, None)
            if task and not task.done():
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task


# ────────────────────────────────────────────────────────────────────────────
# Fix 2: stop after Phase 3/4 must not be overwritten by "completed"
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_stop_after_attacks_prevents_aggregation_and_apex(scan_state):
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t_stop3", "https://example.com")

    aggregation_called = False
    apex_called = False

    async def attacks_that_stop(scan_id, target, auth, **kwargs):
        await scan_state.update_scan(scan_id, status="stopped")

    async def spy_aggregation(*args, **kwargs):
        nonlocal aggregation_called
        aggregation_called = True

    async def spy_apex(*args, **kwargs):
        nonlocal apex_called
        apex_called = True

    with patch("orchestrator.run_kiterunner_scan", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.run_kiterunner_brute", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.probe_schema", new_callable=AsyncMock, return_value=None), \
         patch.object(Orchestrator, "_phase_attacks", side_effect=attacks_that_stop), \
         patch.object(Orchestrator, "_phase_aggregation", side_effect=spy_aggregation), \
         patch.object(Orchestrator, "_phase_apex_analysis", side_effect=spy_apex):

        await orch._run_pipeline("t_stop3", "https://example.com", "standard")

    assert not aggregation_called, "Phase 4 must not run after a stop request"
    assert not apex_called, "Phase 5 must not run after a stop request"
    status = await scan_state.get_scan("t_stop3")
    assert status.status == "stopped"


# ────────────────────────────────────────────────────────────────────────────
# Fix 3: x8 extracts parameter names, not raw found_params dicts
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_x8_extracts_param_names_not_dicts(scan_state, tmp_path):
    """Regression for both x8 bugs found in the audit:
    1. found_params entries are dicts, not strings — must extract the name.
    2. x8's human-readable progress line contains a literal "[" of its own
       (e.g. "(200) [110] {0}") that breaks naive find()/rfind() bracket
       scanning once found_params (a nested array) is non-empty. This is the
       *exact* stdout shape captured from the real x8 4.3.0 binary — not a
       simplified synthetic payload — so it exercises both bugs together.
    """
    from tools.blind_attack import run_x8

    fake_wordlist = tmp_path / "burp-parameter-names.txt"
    fake_wordlist.write_text("foo\nadmin\n")

    x8_output = (
        b"urls:         http://127.0.0.1:8124/\n"
        b"methods:      GET\n"
        b"wordlist len: 4\n"
        b"\n"
        b"GET http://127.0.0.1:8124/?%s (200) [110] {0}\n"
        b"\n"
        b'[{"method":"GET","url":"http://127.0.0.1:8124/","status":200,"size":110,'
        b'"found_params":[{"name":"foo","value":null,"diffs":"-3,1 +3,1","status":200,'
        b'"size":175,"reason_kind":"Text"},{"name":"admin","value":null,"diffs":"-4,1 +4,1",'
        b'"status":200,"size":180,"reason_kind":"Text"}],"injection_place":"Path"}]'
    )

    async def mock_exec(*cmd, stdout=None, stderr=None):
        proc = MagicMock()
        proc.communicate = AsyncMock(return_value=(x8_output, b""))
        proc.returncode = 0
        return proc

    with patch("tools.blind_attack.PARAMS_DIR", tmp_path), \
         patch("asyncio.create_subprocess_exec", side_effect=mock_exec):
        params, error = await run_x8("t_x8", "http://example.com/api", "GET")

    assert error is None
    assert params == ["foo", "admin"]
    assert all(isinstance(p, str) for p in params), "params must be usable directly in a curl querystring"


# ────────────────────────────────────────────────────────────────────────────
# Fix 4: offat severity inferred from test_name, not hardcoded "medium"
# ────────────────────────────────────────────────────────────────────────────

def test_offat_severity_inferred_from_test_name_when_missing():
    from tools.schema_attack import _parse_offat_output

    data = [
        {"result": True, "test_name": "SQLi Test", "method": "GET", "url": "http://x/",
         "result_details": "SQL injection confirmed: error-based", "response_status_code": 500},
        {"result": True, "test_name": "BOLA Path Trailing Slash Test", "method": "GET", "url": "http://x/1",
         "result_details": "Response contains different user data when ID changed", "response_status_code": 200},
        {"result": True, "test_name": "Checking for Broken Access Control:", "method": "GET", "url": "http://x/2",
         "result_details": "unauthorized action succeeded", "response_status_code": 200},
        {"result": True, "test_name": "Some Unknown Check", "method": "GET", "url": "http://x/3",
         "result_details": "unexpected behavior observed", "response_status_code": 200},
    ]
    findings = _parse_offat_output(data, "http://x")
    by_title = {f["title"]: f["severity"] for f in findings}

    assert by_title["[OFFAT] SQLi Test"] == "critical"
    assert by_title["[OFFAT] BOLA Path Trailing Slash Test"] == "high"
    assert by_title["[OFFAT] Checking for Broken Access Control:"] == "high"
    assert by_title["[OFFAT] Some Unknown Check"] == "medium"  # unclassified fallback, not a silent default


def test_offat_severity_respects_real_field_if_ever_present():
    from tools.schema_attack import _parse_offat_output

    data = [{"result": True, "test_name": "SQLi Test", "severity": "info", "method": "GET",
             "url": "http://x/", "result_details": "confirmed", "response_status_code": 500}]
    findings = _parse_offat_output(data, "http://x")
    assert findings[0]["severity"] == "info"


# ────────────────────────────────────────────────────────────────────────────
# Fix 5: blind_attack tool_health reflects real x8/arjun failures
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_blind_attack_tool_health_reports_error_on_total_failure(scan_state):
    from tools.blind_attack import run_blind_attack

    await scan_state.create_scan("t_blind_health", "https://example.com")
    endpoints = [
        {"method": "GET", "url": "https://example.com/api/a"},
        {"method": "GET", "url": "https://example.com/api/b"},
    ]

    async def failing_arjun(scan_id, url, method="GET", auth=None):
        return [], "timeout"

    with patch("tools.blind_attack.X8_BIN") as mock_x8_bin, \
         patch("tools.blind_attack.run_arjun", side_effect=failing_arjun):
        mock_x8_bin.exists.return_value = False  # force the arjun path
        await run_blind_attack("t_blind_health", endpoints, "https://example.com")

    results = await scan_state.get_results("t_blind_health")
    health = results["tool_health"]["blind_attack"]
    assert health["status"] == "error"
    assert "timeout" in health["error"]


@pytest.mark.asyncio
async def test_blind_attack_tool_health_ok_when_no_errors(scan_state):
    from tools.blind_attack import run_blind_attack

    await scan_state.create_scan("t_blind_health_ok", "https://example.com")
    endpoints = [{"method": "GET", "url": "https://example.com/api/a"}]

    async def clean_arjun(scan_id, url, method="GET", auth=None):
        return [], None  # ran fine, genuinely found nothing

    with patch("tools.blind_attack.X8_BIN") as mock_x8_bin, \
         patch("tools.blind_attack.run_arjun", side_effect=clean_arjun):
        mock_x8_bin.exists.return_value = False
        await run_blind_attack("t_blind_health_ok", endpoints, "https://example.com")

    results = await scan_state.get_results("t_blind_health_ok")
    health = results["tool_health"]["blind_attack"]
    assert health["status"] == "ok"
    assert health["error"] is None


# ────────────────────────────────────────────────────────────────────────────
# Fix 6: _find_free_port never double-assigns a port across two calls
# ────────────────────────────────────────────────────────────────────────────

def test_find_free_port_respects_exclude():
    import socket

    from main import _find_free_port

    host = "127.0.0.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, 0))
    occupied_port = sock.getsockname()[1]
    try:
        found = _find_free_port(host, occupied_port, retries=3, exclude=frozenset({occupied_port + 1}))
        assert found != occupied_port      # already occupied
        assert found != occupied_port + 1  # explicitly excluded (the actual fix)
    finally:
        sock.close()


# ────────────────────────────────────────────────────────────────────────────
# Fix 7: create_scan_dir never collides across scans in the same second
# ────────────────────────────────────────────────────────────────────────────

def test_create_scan_dir_unique_per_scan_same_second():
    import lib.evidence as ev

    dir_a = ev.create_scan_dir("scanA-111", "https://example.com")
    dir_b = ev.create_scan_dir("scanB-222", "https://example.com")

    assert dir_a != dir_b
    assert (dir_a / ".scan_id").read_text() == "scanA-111"
    assert (dir_b / ".scan_id").read_text() == "scanB-222"


# ────────────────────────────────────────────────────────────────────────────
# Fix 8: --ignore-length only threaded through on a genuine SPA catch-all
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_ignore_length_not_applied_on_normal_404(scan_state):
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t_baseline_404", "https://example.com")
    captured = {}

    async def capture_scan(scan_id, target, depth, auth, baseline_length, allow_mutating=False):
        captured["scan"] = baseline_length
        return []

    async def capture_brute(scan_id, target, auth, baseline_length):
        captured["brute"] = baseline_length
        return []

    with patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value={"status": 404, "length": 22, "catch_all": False, "signatures": []}), \
         patch("orchestrator.run_kiterunner_scan", side_effect=capture_scan), \
         patch("orchestrator.run_kiterunner_brute", side_effect=capture_brute), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]):
        await orch._phase_discovery("t_baseline_404", "https://example.com", "standard", None, allow_mutating=True)

    assert captured["scan"] is None
    assert captured["brute"] is None


@pytest.mark.asyncio
async def test_ignore_length_applied_on_real_spa_catchall(scan_state):
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t_baseline_200", "https://example.com")
    captured = {}

    async def capture_scan(scan_id, target, depth, auth, baseline_length, allow_mutating=False):
        captured["scan"] = baseline_length
        return []

    async def capture_brute(scan_id, target, auth, baseline_length):
        captured["brute"] = baseline_length
        return []

    with patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value={"status": 200, "length": 4321, "catch_all": True, "signatures": [{"status": 200, "length": 4321}]}), \
         patch("orchestrator.run_kiterunner_scan", side_effect=capture_scan), \
         patch("orchestrator.run_kiterunner_brute", side_effect=capture_brute), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]):
        await orch._phase_discovery("t_baseline_200", "https://example.com", "standard", None, allow_mutating=True)

    assert captured["scan"] == [4321]
    assert captured["brute"] == [4321]
