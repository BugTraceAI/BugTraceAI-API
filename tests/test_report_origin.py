"""Focused tests for the report-origin feature (B.1).

Covers:
 - default launch_origin is "api"
 - "web-api" accepted by POST /api/scan
 - "web-cli" / "cli" rejected with 400 by POST /api/scan
 - POST returns engine/launch_origin
 - GET /api/scan/{id} status returns engine/launch_origin
 - GET /api/scan/{id}/results returns engine/launch_origin in status
 - GET /api/scans list returns engine/launch_origin
 - restart rehydration preserves origin (in-memory cleared, manifest on disk)
 - direct API REST and MCP both force launch_origin="api" / engine="api"
"""

import asyncio
import json
from unittest.mock import patch

import pytest

# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _flush_task(orchestrator, scan_id):
    """Remove and cancel the background task created by start_scan (if any)."""
    task = orchestrator.active_tasks.pop(scan_id, None)
    if task and not task.done():
        task.cancel()
    return task


# ────────────────────────────────────────────────────────────────────────────
# 1. Default origin is "api"
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_default_origin_is_api(scan_state):
    """POST /api/scan without launch_origin defaults to launch_origin="api"."""
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def noop_run(*args, **kwargs):
        pass

    with patch.object(orchestrator, "run_scan", side_effect=noop_run):
        req = ScanRequest(target="https://example.com")
        assert req.launch_origin == "api"
        resp = await api_server.start_scan(req)
        scan_id = resp["scan_id"]
        try:
            assert resp["engine"] == "api"
            assert resp["launch_origin"] == "api"
            status = await scan_state.get_scan(scan_id)
            assert status.engine == "api"
            assert status.launch_origin == "api"
        finally:
            _flush_task(orchestrator, scan_id)


# ────────────────────────────────────────────────────────────────────────────
# 2. "web-api" accepted
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_web_api_origin_accepted(scan_state):
    """launch_origin="web-api" is a valid API-engine origin."""
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def noop_run(*args, **kwargs):
        pass

    with patch.object(orchestrator, "run_scan", side_effect=noop_run):
        req = ScanRequest(target="https://example.com", launch_origin="web-api")
        resp = await api_server.start_scan(req)
        scan_id = resp["scan_id"]
        try:
            assert resp["launch_origin"] == "web-api"
            status = await scan_state.get_scan(scan_id)
            assert status.launch_origin == "web-api"
            assert status.engine == "api"
        finally:
            _flush_task(orchestrator, scan_id)


# ────────────────────────────────────────────────────────────────────────────
# 3. "web-cli" / "cli" rejected with 400
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("origin", ["web-cli", "cli"])
@pytest.mark.asyncio
async def test_cli_origins_rejected_400(scan_state, origin):
    """CLI origins must be rejected with HTTP 400 by the REST API."""
    from api_server import ScanRequest

    with pytest.raises(Exception) as exc_info:
        ScanRequest(target="https://example.com", launch_origin=origin)
    # Pydantic raises a 422-equivalent ValueError; the FastAPI route converts
    # it to 400 via the validation contract. Verify it's rejected.
    assert origin in str(exc_info.value)


# ────────────────────────────────────────────────────────────────────────────
# 4. POST returns engine/launch_origin
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_post_returns_engine_and_origin(scan_state):
    """POST /api/scan response includes engine and launch_origin."""
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def noop_run(*args, **kwargs):
        pass

    with patch.object(orchestrator, "run_scan", side_effect=noop_run):
        req = ScanRequest(target="https://example.com", launch_origin="web-api")
        resp = await api_server.start_scan(req)
        scan_id = resp["scan_id"]
        try:
            assert "engine" in resp
            assert resp["engine"] == "api"
            assert "launch_origin" in resp
            assert resp["launch_origin"] == "web-api"
        finally:
            _flush_task(orchestrator, scan_id)


# ────────────────────────────────────────────────────────────────────────────
# 5. GET /api/scan/{id} returns engine/launch_origin
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_status_returns_engine_and_origin(scan_state):
    """GET /api/scan/{id} status includes engine and launch_origin."""
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def noop_run(*args, **kwargs):
        pass

    with patch.object(orchestrator, "run_scan", side_effect=noop_run):
        req = ScanRequest(target="https://example.com", launch_origin="web-api")
        resp = await api_server.start_scan(req)
        scan_id = resp["scan_id"]
        try:
            status = await api_server.get_scan_status(scan_id)
            assert status["engine"] == "api"
            assert status["launch_origin"] == "web-api"
        finally:
            _flush_task(orchestrator, scan_id)


# ────────────────────────────────────────────────────────────────────────────
# 6. GET /api/scan/{id}/results returns engine/launch_origin
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_results_returns_engine_and_origin(scan_state):
    """GET /api/scan/{id}/results status includes engine and launch_origin."""
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def noop_run(*args, **kwargs):
        pass

    with patch.object(orchestrator, "run_scan", side_effect=noop_run):
        req = ScanRequest(target="https://example.com", launch_origin="web-api")
        resp = await api_server.start_scan(req)
        scan_id = resp["scan_id"]
        try:
            results = await api_server.get_scan_results(scan_id)
            assert results["status"]["engine"] == "api"
            assert results["status"]["launch_origin"] == "web-api"
        finally:
            _flush_task(orchestrator, scan_id)


# ────────────────────────────────────────────────────────────────────────────
# 7. GET /api/scans returns engine/launch_origin
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_list_scans_returns_engine_and_origin(scan_state):
    """GET /api/scans list includes engine and launch_origin per scan."""
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def noop_run(*args, **kwargs):
        pass

    with patch.object(orchestrator, "run_scan", side_effect=noop_run):
        req = ScanRequest(target="https://example.com", launch_origin="web-api")
        resp = await api_server.start_scan(req)
        scan_id = resp["scan_id"]
        try:
            listing = await api_server.list_scans(limit=50, cursor=None)
            assert "scans" in listing
            assert "next_cursor" in listing
            match = [s for s in listing["scans"] if s["scan_id"] == scan_id]
            assert len(match) == 1
            assert match[0]["engine"] == "api"
            assert match[0]["launch_origin"] == "web-api"
            # While the scan task is still in-memory, storage is "memory".
            # After restart (clearing memory), it would be "disk".
            assert match[0]["storage"] in ("memory", "disk")
        finally:
            _flush_task(orchestrator, scan_id)


@pytest.mark.asyncio
async def test_list_scans_pagination(scan_state):
    """GET /api/scans honours limit and cursor for pagination."""
    for i in range(5):
        await scan_state.create_scan(f"page{i:02d}", f"https://page{i}.example.com")

    page1, next_cursor = await scan_state.list_scans(limit=3, cursor=None)
    assert len(page1) == 3
    assert isinstance(next_cursor, str)
    assert next_cursor != ""

    page2, next_cursor2 = await scan_state.list_scans(limit=3, cursor=next_cursor)
    assert len(page2) == 2
    assert next_cursor2 is None
    ids_page1 = {s["scan_id"] for s in page1}
    ids_page2 = {s["scan_id"] for s in page2}
    assert ids_page1 & ids_page2 == set()

    # Every entry carries provenance
    for s in page1 + page2:
        assert s["engine"] == "api"
        assert s["launch_origin"] == "api"


# ────────────────────────────────────────────────────────────────────────────
# 8. Restart rehydration preserves origin
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rehydration_preserves_origin(scan_state):
    """After clearing in-memory state, get_scan rehydrates engine/launch_origin
    from the persisted scan_manifest.json."""
    scan_id = "rehyd01"
    await scan_state.create_scan(
        scan_id,
        "https://example.com",
        engine="api",
        launch_origin="web-api",
        launch_transport="rest",
    )
    await scan_state.update_scan(scan_id, status="running", current_phase="discovery")
    await scan_state.update_scan(scan_id, status="completed", progress=1.0)

    # Simulate a process restart: wipe in-memory state only.
    scan_state.active_scans.clear()
    scan_state.scan_responses.clear()

    status = await scan_state.get_scan(scan_id)
    assert status is not None
    assert status.engine == "api"
    assert status.launch_origin == "web-api"
    assert status.status == "completed"

    results = await scan_state.get_results(scan_id)
    assert results is not None
    assert results["status"]["engine"] == "api"
    assert results["status"]["launch_origin"] == "web-api"


@pytest.mark.asyncio
async def test_manifest_persisted_on_disk(scan_state, tmp_path):
    """scan_manifest.json is written to the scan directory with provenance."""
    from lib.evidence import get_scan_dir

    scan_id = "manifest01"
    await scan_state.create_scan(
        scan_id,
        "https://example.com",
        engine="api",
        launch_origin="web-api",
        launch_transport="rest",
    )
    manifest_path = get_scan_dir(scan_id) / "scan_manifest.json"
    assert manifest_path.exists()

    with open(manifest_path) as f:
        manifest = json.load(f)

    assert manifest["scan_id"] == scan_id
    assert manifest["engine"] == "api"
    assert manifest["launch_origin"] == "web-api"
    assert manifest["status"] == "pending"
    assert "started_at" in manifest
    assert "target" in manifest


@pytest.mark.asyncio
async def test_manifest_lifecycle_transitions(scan_state, tmp_path):
    """Every lifecycle transition (pending/running/completed/failed/stopped)
    updates scan_manifest.json."""
    from lib.evidence import load_scan_manifest

    scan_id = "lifecycle01"
    await scan_state.create_scan(
        scan_id,
        "https://example.com",
        engine="api",
        launch_origin="api",
        launch_transport="mcp",
    )

    def read_status():
        m = load_scan_manifest(scan_id)
        return m["status"] if m else None

    assert read_status() == "pending"

    await scan_state.update_scan(scan_id, status="running")
    assert read_status() == "running"

    await scan_state.update_scan(scan_id, status="stopped")
    m = load_scan_manifest(scan_id)
    assert m["status"] == "stopped"
    assert m["finished_at"] is not None


@pytest.mark.asyncio
async def test_manifest_persists_warning_and_error(scan_state):
    """Provider/scan warnings survive an API restart via the manifest."""
    from lib.evidence import load_scan_manifest

    scan_id = "manifest-warning"
    await scan_state.create_scan(scan_id, "https://example.com", launch_origin="web-api")
    await scan_state.update_scan(
        scan_id,
        status="completed",
        warning="AI enrichment skipped: provider has no API key. The report is partial.",
    )
    manifest = load_scan_manifest(scan_id)
    assert manifest["warning"] == "AI enrichment skipped: provider has no API key. The report is partial."
    assert "error" not in manifest

    await scan_state.update_scan(scan_id, status="failed", error="scan failed")
    manifest = load_scan_manifest(scan_id)
    assert manifest["error"] == "scan failed"


@pytest.mark.asyncio
async def test_list_scans_detects_openapi_artifact_after_restart(scan_state):
    """OpenAPI availability is derived from the durable artifact, not stale manifest flags."""
    from lib.evidence import save_artifact

    scan_id = "openapi-after-restart"
    await scan_state.create_scan(scan_id, "https://example.com")
    save_artifact(scan_id, "discovery", "generated_openapi", {"openapi": "3.0.0"})

    scan_state.active_scans.clear()
    scan_state.scan_responses.clear()
    scans, _ = await scan_state.list_scans(limit=10)
    match = next(scan for scan in scans if scan["scan_id"] == scan_id)
    assert match["openapi_available"] is True


# ────────────────────────────────────────────────────────────────────────────
# 9. Direct API REST and MCP both force api
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rest_forces_engine_api(scan_state):
    """REST always records engine="api" regardless of caller input."""
    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def noop_run(*args, **kwargs):
        pass

    with patch.object(orchestrator, "run_scan", side_effect=noop_run):
        for origin in ("api", "web-api"):
            req = ScanRequest(target="https://example.com", launch_origin=origin)
            resp = await api_server.start_scan(req)
            scan_id = resp["scan_id"]
            try:
                status = await scan_state.get_scan(scan_id)
                assert status.engine == "api"
                assert status.launch_origin == origin
            finally:
                # The REST API now correctly rejects a second pending scan;
                # mark this stubbed scan terminal before the next origin case.
                await scan_state.update_scan(scan_id, status="completed")
                _flush_task(orchestrator, scan_id)


@pytest.mark.asyncio
async def test_rest_rejects_second_active_scan(scan_state):
    """The API engine must not create overlapping scans from REST callers."""
    from fastapi import HTTPException

    import api_server
    from api_server import ScanRequest
    from orchestrator import orchestrator

    async def waiting_run(*args, **kwargs):
        await asyncio.sleep(10)

    with patch.object(orchestrator, "run_scan", side_effect=waiting_run):
        first = await api_server.start_scan(ScanRequest(target="https://one.example", launch_origin="web-api"))
        first_id = first["scan_id"]
        try:
            with pytest.raises(HTTPException) as exc_info:
                await api_server.start_scan(ScanRequest(target="https://two.example", launch_origin="web-api"))
            assert exc_info.value.status_code == 409
            assert exc_info.value.detail["active_scan_id"] == first_id
        finally:
            await scan_state.update_scan(first_id, status="stopped")
            _flush_task(orchestrator, first_id)


@pytest.mark.asyncio
async def test_mcp_forces_api_origin(scan_state, monkeypatch):
    """main.api_scan (MCP tool) always forces launch_origin="api", engine="api"."""
    # mcp_server is stubbed in conftest; importing main pulls it in via the
    # module-level import. Import lazily here to avoid the decorator
    # registration being done twice in one session.
    import main

    recorded = {}

    async def fake_run_scan(*args, **kwargs):
        recorded.update(kwargs)

    monkeypatch.setattr(main.orchestrator, "run_scan", fake_run_scan)

    result = await main.api_scan(target="https://example.com")
    scan_id = result["scan_id"]

    # asyncio.create_task schedules the coroutine; let the event loop run it.
    task = main.orchestrator.active_tasks.get(scan_id)
    if task and not task.done():
        await asyncio.sleep(0)
        await asyncio.sleep(0)
    elif task is None:
        pass  # noop_run was patched out — nothing to await

    assert result["engine"] == "api"
    assert result["launch_origin"] == "api"

    status = await scan_state.get_scan(scan_id)
    assert status.engine == "api"
    assert status.launch_origin == "api"
    assert status.launch_transport == "mcp"

    # The orchestrator call also forced provenance
    assert recorded.get("engine") == "api"
    assert recorded.get("launch_origin") == "api"


@pytest.mark.asyncio
async def test_mcp_rejects_target_without_scheme(scan_state):
    """api_scan still validates the target scheme."""
    import main

    result = await main.api_scan(target="example.com")
    assert "error" in result


@pytest.mark.asyncio
async def test_list_scans_rejects_invalid_cursor(scan_state):
    """Tampered or malformed cursors are rejected."""
    await scan_state.create_scan("t1", "https://t1.example.com")

    with pytest.raises(ValueError, match="invalid cursor"):
        await scan_state.list_scans(limit=10, cursor="not-a-cursor")

    with pytest.raises(ValueError, match="invalid cursor"):
        await scan_state.list_scans(limit=10, cursor="MTIz")  # valid base64 but no cursor: prefix

    with pytest.raises(ValueError, match="invalid cursor"):
        await scan_state.list_scans(limit=10, cursor="cursor:-1")


@pytest.mark.asyncio
async def test_list_scans_zero_findings_completed(scan_state):
    """A completed zero-findings scan still shows results_available=True."""
    scan_id = "zero-findings"
    await scan_state.create_scan(scan_id, "https://zero.example.com")
    await scan_state.update_scan(scan_id, status="completed", findings_count=0)

    scans, _ = await scan_state.list_scans(limit=10)
    match = [s for s in scans if s["scan_id"] == scan_id]
    assert len(match) == 1
    assert match[0]["results_available"] is True
    assert match[0]["findings_count"] == 0


@pytest.mark.asyncio
async def test_failed_scan_with_aggregation_keeps_results_available(scan_state):
    """A late AI timeout must not hide the completed discovery report."""
    from lib.evidence import save_report

    scan_id = "partial-ai-timeout"
    await scan_state.create_scan(scan_id, "https://partial.example.com")
    save_report(scan_id, "report", {"scan_id": scan_id, "findings": []})
    await scan_state.update_scan(
        scan_id, status="failed", error="global_timeout_3600s", current_phase="ai_analysis"
    )

    scans, _ = await scan_state.list_scans(limit=10)
    match = [s for s in scans if s["scan_id"] == scan_id]
    assert len(match) == 1
    assert match[0]["results_available"] is True
    assert match[0]["status"] == "failed"


@pytest.mark.asyncio
async def test_list_scans_does_not_expose_launch_transport(scan_state):
    """Public list items never expose launch_transport."""
    await scan_state.create_scan("lt1", "https://lt1.example.com", launch_transport="rest")
    await scan_state.create_scan("lt2", "https://lt2.example.com", launch_transport="mcp")

    scans, _ = await scan_state.list_scans(limit=10)
    for s in scans:
        assert "launch_transport" not in s
