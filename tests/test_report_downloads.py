import io
import json
import zipfile

import pytest


@pytest.mark.asyncio
async def test_report_zip_contains_phase_artifacts_and_portable_exports(scan_state):
    from api_server import download_scan_report_zip
    from lib.evidence import save_artifact, save_report

    scan_id = "zip-scan-1"
    await scan_state.create_scan(scan_id, "https://example.com/api")
    await scan_state.update_scan(scan_id, status="completed", progress=1.0, findings_count=1)
    save_artifact(scan_id, "discovery", "generated_openapi", {
        "openapi": "3.0.0",
        "info": {"title": "example"},
        "paths": {"/health": {"get": {"responses": {"200": {"description": "OK"}}}}},
    })
    findings = [{
        "id": "API-1",
        "title": "Example finding",
        "severity": "medium",
        "confidence": 0.8,
        "category": "API",
        "endpoint": "https://example.com/api/health",
        "source_tools": ["test"],
        "evidence": {},
        "repro": {},
    }]
    save_artifact(scan_id, "aggregation", "findings_only", findings)
    scan_state.scan_responses[scan_id]["findings"] = findings
    save_report(scan_id, "scan_metadata", {"scan_id": scan_id})

    response = await download_scan_report_zip(scan_id)
    payload = b"".join([chunk async for chunk in response.body_iterator])

    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        names = set(archive.namelist())
        root = next(iter(names)).split("/", 1)[0]
        assert f"{root}/10_discovery/generated_openapi.json" in names
        assert f"{root}/40_aggregation/findings_only.json" in names
        assert f"{root}/scan_metadata.json" in names
        assert f"{root}/report.md" in names
        assert f"{root}/openapi.json" in names
        assert "Example finding" in archive.read(f"{root}/report.md").decode()
        assert json.loads(archive.read(f"{root}/openapi.json"))["openapi"] == "3.0.0"


@pytest.mark.asyncio
async def test_handoff_endpoint_and_export_preserve_operations_without_secrets(scan_state):
    from api_server import download_scan_artifact, get_scan_handoff
    from lib.evidence import save_artifact

    scan_id = "handoff-scan-1"
    await scan_state.create_scan(scan_id, "https://example.com/api")
    await scan_state.update_scan(scan_id, status="completed", progress=1.0)
    save_artifact(scan_id, "schema_probe", "published_openapi", {
        "openapi": "3.0.0",
        "paths": {"/users": {"get": {"responses": {"200": {"description": "OK"}}}}},
    })
    save_artifact(scan_id, "schema_probe", "openapi_operations", [{
        "method": "GET", "url": "https://example.com/api/users", "headers": {"Authorization": "secret"},
    }])
    save_artifact(scan_id, "aggregation", "findings_only", [])

    response = await get_scan_handoff(scan_id)
    payload = json.loads(response.body.decode())
    assert payload["handoff_version"] == 1
    assert payload["operations"][0]["method"] == "GET"
    assert payload["operations"][0]["headers"]["Authorization"] == "[REDACTED]"

    artifact = await download_scan_artifact(scan_id, "handoff")
    assert json.loads(artifact.body.decode())["producer"]["scan_id"] == scan_id
