"""Phase 1: scan mode=safe|audit resolves allow_mutating without changing defaults."""
from unittest.mock import AsyncMock, patch

import pytest

from lib.http_policy import AUDIT_NO_AUTH_WARNING, resolve_audit_mode


@pytest.mark.asyncio
async def test_schemathesis_persists_stdout(monkeypatch, scan_state):
    import asyncio

    from lib.evidence import _phase_dir, create_scan_dir
    from tools.attack.schemathesis import run_schemathesis

    await scan_state.create_scan("stout", "https://example.com")
    create_scan_dir("stout", "https://example.com")

    class FakeProc:
        returncode = 0

        async def communicate(self):
            return (b"===== FAILURES =====\nGET /x\nHTTP/1.1 500\n1 failed in 0.1s", None)

        def kill(self):
            return None

    captured: list[str] = []

    async def fake_exec(*args, **_kwargs):
        captured.extend(str(a) for a in args)
        return FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    await run_schemathesis("stout", "https://example.com/openapi.json", "https://example.com")
    assert "--url" in captured
    assert "--base-url" not in captured
    assert "--max-examples" in captured
    path = _phase_dir("stout", "schema_attack") / "schemathesis_stdout.txt"
    assert path.exists()
    assert "FAILURES" in path.read_text()


def test_resolve_audit_turns_on_mutating_unless_explicit_false():
    assert resolve_audit_mode("audit", False, mutating_explicit=False) == ("audit", True)
    assert resolve_audit_mode("audit", False, mutating_explicit=True) == ("audit", False)
    assert resolve_audit_mode("audit", True, mutating_explicit=True) == ("audit", True)
    assert resolve_audit_mode("safe", False, mutating_explicit=False) == ("safe", False)
    assert resolve_audit_mode("safe", True, mutating_explicit=True) == ("safe", True)
    assert resolve_audit_mode("nope", False, mutating_explicit=False) == ("safe", False)


def test_scan_request_defaults_remain_safe():
    from api_server import ScanRequest

    req = ScanRequest(target="https://example.com", launch_origin="web-api")
    assert req.mode == "safe"
    assert req.allow_mutating is False
    assert "allow_mutating" not in req.model_fields_set


def test_scan_request_audit_explicit_opt_out():
    from api_server import ScanRequest
    from lib.http_policy import resolve_audit_mode

    req = ScanRequest(target="https://example.com", mode="audit", allow_mutating=False)
    mode, mutating = resolve_audit_mode(
        req.mode, req.allow_mutating, mutating_explicit="allow_mutating" in req.model_fields_set
    )
    assert mode == "audit"
    assert mutating is False


@pytest.mark.asyncio
async def test_audit_mode_enables_kite_and_records_config(scan_state):
    from lib.evidence import load_artifact
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("mode_audit", "https://example.com")

    kite_called = False

    async def spy_kite(scan_id, target, depth, auth, baseline_length, allow_mutating=False):
        nonlocal kite_called
        kite_called = True
        return []

    with patch("orchestrator.run_kiterunner_scan", side_effect=spy_kite), \
         patch("orchestrator.run_kiterunner_brute", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.probe_schema", new_callable=AsyncMock, return_value=None), \
         patch("orchestrator.run_blind_attack", new_callable=AsyncMock), \
         patch("orchestrator.run_schema_attack", new_callable=AsyncMock):
        await orch._run_pipeline(
            "mode_audit", "https://example.com", "standard",
            allow_mutating=True, mode="audit",
        )

    config = load_artifact("mode_audit", "discovery", "scan_config")
    assert config["mode"] == "audit"
    assert config["allow_mutating"] is True
    assert kite_called is True
    health = (await scan_state.get_results("mode_audit"))["tool_health"]
    assert health.get("kiterunner_scan", {}).get("status") != "skipped"


@pytest.mark.asyncio
async def test_audit_with_explicit_false_stays_safe(scan_state):
    from lib.evidence import load_artifact
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("mode_optout", "https://example.com")

    seen: dict = {}

    async def spy_kite(*args, **kwargs):
        seen["called"] = True
        seen["allow_mutating"] = kwargs.get("allow_mutating")
        return []

    with patch("orchestrator.run_kiterunner_scan", side_effect=spy_kite), \
         patch("orchestrator.run_kiterunner_brute", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.probe_schema", new_callable=AsyncMock, return_value=None), \
         patch("orchestrator.run_blind_attack", new_callable=AsyncMock), \
         patch("orchestrator.run_schema_attack", new_callable=AsyncMock):
        await orch._run_pipeline(
            "mode_optout", "https://example.com", "standard",
            allow_mutating=False, mode="audit",
        )

    config = load_artifact("mode_optout", "discovery", "scan_config")
    assert config["mode"] == "audit"
    assert config["allow_mutating"] is False
    assert seen.get("called") is True
    assert seen.get("allow_mutating") is False
    health = (await scan_state.get_results("mode_optout"))["tool_health"]
    assert health.get("kiterunner_scan", {}).get("status") != "skipped"


@pytest.mark.asyncio
async def test_audit_without_auth_sets_warning(scan_state):
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("mode_warn", "https://example.com")

    with patch("orchestrator.run_kiterunner_scan", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.run_kiterunner_brute", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.detect_baseline", new_callable=AsyncMock, return_value=(404, None)), \
         patch("orchestrator.run_api_crawl", new_callable=AsyncMock, return_value=[]), \
         patch("orchestrator.probe_schema", new_callable=AsyncMock, return_value=None), \
         patch("orchestrator.run_blind_attack", new_callable=AsyncMock), \
         patch("orchestrator.run_schema_attack", new_callable=AsyncMock):
        await orch._run_pipeline(
            "mode_warn", "https://example.com", "standard",
            auth=None, allow_mutating=True, mode="audit",
        )

    status = await scan_state.get_scan("mode_warn")
    assert status.warning == AUDIT_NO_AUTH_WARNING


@pytest.mark.asyncio
async def test_rest_audit_resolves_mutating_before_launch(scan_state):
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    captured = {}

    async def fake_run(scan_id, target, depth, auth=None, schema_url=None, **kwargs):
        captured.update(kwargs)
        captured["scan_id"] = scan_id

    with patch.object(orchestrator, "run_scan", side_effect=fake_run):
        req = ScanRequest(target="https://example.com", mode="audit")
        resp = await api_server.start_scan(req)
        task = orchestrator.active_tasks.pop(resp["scan_id"], None)
        if task:
            await task

    assert captured.get("mode") == "audit"
    assert captured.get("allow_mutating") is True
    status = await scan_state.get_scan(captured["scan_id"])
    assert status.warning == AUDIT_NO_AUTH_WARNING
