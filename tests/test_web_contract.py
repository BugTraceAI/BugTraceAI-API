"""BugTraceAI-WEB contract: existing keys stay, extras are additive."""
import pytest


@pytest.mark.asyncio
async def test_get_results_envelope_contains_web_keys(scan_state):
    await scan_state.create_scan("web1", "https://example.com", launch_origin="web-api")
    await scan_state.add_finding("web1", {
        "id": "VULNAPI-0001",
        "title": "T",
        "severity": "info",
        "confidence": 0.5,
        "category": "C",
        "endpoint": "https://example.com",
        "source_tools": ["vulnapi"],
        "evidence": {"id": "headers.cors"},
        "repro": {"note": "n"},
    })
    results = await scan_state.get_results("web1")
    for key in ("status", "findings", "endpoints", "schema", "tool_health", "ai_analysis"):
        assert key in results
    status = results["status"]
    for key in ("scan_id", "target", "engine", "launch_origin", "status", "progress", "findings_count"):
        assert key in status
    assert status["engine"] == "api"
    assert status["launch_origin"] == "web-api"
    assert status["progress"] <= 1.0
    finding = results["findings"][0]
    for key in ("id", "title", "severity", "confidence", "category", "endpoint", "source_tools", "evidence", "repro"):
        assert key in finding
    assert "coverage" in results
    assert "quality_summary" in results


def test_scan_request_keeps_web_fields():
    from api_server import ScanRequest

    req = ScanRequest(target="https://example.com", launch_origin="web-api", depth="standard")
    assert req.allow_mutating is False
    assert req.mode == "safe"
    assert req.auth is None
    dumped = req.model_dump()
    assert dumped["target"] == "https://example.com"
    assert dumped["launch_origin"] == "web-api"
