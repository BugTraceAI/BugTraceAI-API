"""Regression cases from scan 2590680a: real HTTP, no external targets/LLM."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, patch

import pytest

from lib.apex_client import Generation, _generate, analyze_findings
from lib.coverage import summarize_coverage
from lib.evidence import load_artifact, save_artifact
from lib.findings_quality import is_not_found_response
from lib.inventory import merge_inventory
from lib.openapi import extract_operations
from lib.poc_validation import replay_safe_poc, request_from_finding, validate_request
from lib.review_projection import project_reviews, review_quality
from tools.coverage_probe import run_coverage_probe


@pytest.fixture
def api_fixture():
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("X-Test-Auth")))
            status, body, kind = 200, '{"error":"Not found"}', "application/json"
            if self.path == "/api/products":
                body = '[{"id":1}]'
            elif self.path == "/api/private" and self.headers.get("X-Test-Auth") == "fixture":
                body = '{"role":"user"}'
            elif self.path.startswith("/api/threads?q=original"):
                status, body = 500, "Internal Server Error"
            elif self.path.startswith("/openapi.json/"):
                body, kind = "<html>SPA</html>", "text/html"
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.end_headers()
            self.wfile.write(body.encode())
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", requests
    server.shutdown()
    server.server_close()
    thread.join()


def test_offat_envelope_filtered_before_model():
    from lib.apex_client import filter_findings
    findings = [{"id": str(i), "severity": "medium", "evidence": {"response_code": 200, "response_body": '{"error":"Not found"}'}} for i in range(22)]
    assert all(is_not_found_response(f) for f in findings)
    assert filter_findings(findings) == []


@pytest.mark.asyncio
async def test_spec_url_inventory_and_real_coverage(api_fixture):
    origin, requests = api_fixture
    spec = {"openapi": "3.1.0", "paths": {"/api/products": {"get": {}}, "/missing": {"get": {}}, "/api/create": {"post": {}}}}
    ops = extract_operations(spec, origin + "/openapi.json")
    assert ops[0]["url"] == origin + "/api/products"
    rows = await run_coverage_probe("fixture", ops)
    assert len([p for p, _ in requests if not p.startswith("/__bt_negative_")]) == 2
    assert all("openapi.json" not in path for path, _ in requests)
    assert rows[1]["rejection_reason"] == "not_found"
    summary = summarize_coverage(rows)
    assert summary["tested"] == 2 and summary["verified_operations"] == 1
    assert summary["verified_coverage"] == 1 / 3
    inventory, excluded = merge_inventory([], ops, rows, origin)
    assert len(inventory) == 2 and len(excluded) == 1
    assert inventory[0]["source"] == "openapi"


@pytest.mark.asyncio
async def test_replay_keeps_original_query_and_headers(api_fixture):
    origin, requests = api_fixture
    finding = {"evidence": {"url": origin + "/api/threads?q=original", "method": "GET", "response_code": 500, "response_body": "Internal Server Error"}}
    result = await replay_safe_poc(finding, "curl " + origin + "/api/threads?q=test", origin)
    assert result["status_code"] == 500 and result["matches_evidence"]
    assert not result["confirmed"]
    assert requests[-1][0] == "/api/threads?q=original"
    finding = {"request_spec": {"method": "GET", "url": origin + "/api/private", "headers": {"X-Test-Auth": "fixture"}}}
    result = await replay_safe_poc(finding, "", origin)
    assert result["body_preview"] == '{"role":"user"}'
    assert requests[-1][1] == "fixture"
    assert not result["matches_evidence"]  # No original body to compare.


def test_replay_rejects_inexact_or_out_of_scope_requests():
    assert validate_request({"method": "GET", "url": "https://test:8443/x"}, "https://test")
    assert validate_request({"method": "GET", "url": "http://test/x"}, "https://test")
    assert validate_request({"method": "GET", "url": "https://test/x", "headers": {"Authorization": "<redacted>"}}, "https://test")
    assert request_from_finding({"evidence": {"url": "https://test/x", "query_params": ["unknown"]}}, "https://test")[1]


@pytest.mark.asyncio
async def test_execution_artifacts_do_not_overwrite_initial_phase():
    from tools.investigate import _execute_plan_step
    save_artifact("fixture", "schema_probe", "attack_openapi", {"original": True})
    async def runner(**kwargs):
        save_artifact("fixture", "schema_probe", "attack_openapi", {"original": False})
        return []
    await _execute_plan_step(runner, scan_id="fixture", tool_name="offat", url="https://test/api", method="GET", params={}, auth=None)
    assert load_artifact("fixture", "schema_probe", "attack_openapi") == {"original": True}


@pytest.mark.asyncio
async def test_truncation_is_not_success():
    from lib.provider import get_active_provider
    p = get_active_provider()
    with patch("lib.apex_client._generate_once", AsyncMock(return_value=Generation("partial answer", "length", {"tokens": 20}))):
        result = await _generate("test", p)
    assert result["text"] == "partial answer" and result["truncated"]
    assert result["error"] == "generation_truncated"
    assert result["usage"] == {"tokens": 20}


def test_review_projection_does_not_confirm_replay_or_count_errors_as_pocs():
    findings = [{"id": "f", "classification": "suspicious", "severity": "medium"}]
    reviews = [{"finding_id": "f", "report_status": "refuted", "validation": {"not_found": True, "evidence_id": "e1"}, "review": {"status": "skipped"}}]
    projected = project_reviews(findings, reviews)
    assert projected[0]["classification"] == "refuted"
    assert projected[0]["scanner_assessment"]["severity"] == "medium"
    assert findings[0]["classification"] == "suspicious"
    reviews[0].update(error="timeout")
    assert review_quality(reviews, {"status": "ok"}, 1)["status"] == "partial"
    assert review_quality(reviews, {"status": "ok"}, 1)["pocs_count"] == 0


@pytest.mark.asyncio
async def test_new_not_found_preflight_uses_zero_model_calls(api_fixture):
    from lib.provider import get_active_provider
    origin, _ = api_fixture
    p = get_active_provider()
    with patch("lib.apex_client.is_available", AsyncMock(return_value=True)), patch("lib.apex_client._generate", AsyncMock()) as generate:
        result = await analyze_findings([{"id": "f", "severity": "high", "endpoint": origin + "/absent"}], target=origin, provider=p)
    generate.assert_not_called()
    assert result[0]["report_status"] == "refuted"


@pytest.mark.asyncio
async def test_schema_runner_executes_only_selected_tool():
    from tools.attack import run_schema_attack
    with patch("tools.attack.run_schemathesis", AsyncMock(return_value=[])) as schema, patch("tools.attack.run_offat", AsyncMock(return_value=[{"id": "f"}])) as offat, patch("tools.attack.run_vulnapi", AsyncMock(return_value=[])) as vuln:
        result = await run_schema_attack("fixture", {"url": "/tmp/spec.json"}, "https://test", selected_tools=["offat"], persist_findings=False)
    schema.assert_not_called()
    vuln.assert_not_called()
    offat.assert_called_once()
    assert result == [{"id": "f"}]
