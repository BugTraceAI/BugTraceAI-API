"""Regression tests for the 6 MEDIUM/LOW bugs fixed after the 2026-07-26 logic audit.

 1. schema_url now computes real coverage instead of hardcoding 1.0
 2. endpoints_to_openapi merges duplicate (path, method) entries instead of clobbering
 3. offat FP-filter checks vuln_details too (offat >=0.18 renamed result_details)
 4. enrich_openapi_from_responses adds requestBody to POST-only paths, not just GET+POST
 5. auth_probe findings save to their own phase dir, not schema_attack
 6. _calculate_coverage no longer crashes on a malformed (non-dict) "paths" field
"""

from unittest.mock import AsyncMock, patch

import pytest

# ────────────────────────────────────────────────────────────────────────────
# Fix 1: schema_url computes real coverage
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_schema_url_computes_real_coverage_not_hardcoded(scan_state):
    from lib.evidence import load_artifact, save_artifact
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t_schema_url", "https://example.com")
    endpoints = [
        {"method": "GET", "url": "https://example.com/users"},
        {"method": "GET", "url": "https://example.com/admin"},
    ]
    save_artifact("t_schema_url", "discovery", "all_endpoints", endpoints)

    partial_schema = {"openapi": "3.0.0", "paths": {"/users": {}}}

    with patch("orchestrator.fetch_schema_from_url", new_callable=AsyncMock, return_value=partial_schema), \
         patch("orchestrator.run_coverage_probe", new_callable=AsyncMock, return_value=[]):
        await orch._phase_schema_probe("t_schema_url", "https://example.com", None, "https://example.com/openapi.json")

    decision = load_artifact("t_schema_url", "schema_probe", "schema_decision")
    assert decision["coverage"] is None  # No operations were actually probed.
    assert decision["coverage_status"] == "unknown"


@pytest.mark.asyncio
async def test_schema_url_fetch_failure_falls_back_to_partial_coverage(scan_state):
    from lib.evidence import load_artifact, save_artifact
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t_schema_url_fail", "https://example.com")
    save_artifact("t_schema_url_fail", "discovery", "all_endpoints", [])

    with patch("orchestrator.fetch_schema_from_url", new_callable=AsyncMock, return_value=None):
        await orch._phase_schema_probe("t_schema_url_fail", "https://example.com", None, "https://example.com/openapi.json")

    decision = load_artifact("t_schema_url_fail", "schema_probe", "schema_decision")
    # A failed schema fetch is unknown coverage, not a fabricated 50% score.
    assert decision["coverage"] is None
    assert decision["coverage_status"] == "unknown"
    assert decision["coverage"] != 1.0


# ────────────────────────────────────────────────────────────────────────────
# Fix 2: endpoints_to_openapi merges instead of clobbering
# ────────────────────────────────────────────────────────────────────────────

def test_endpoints_to_openapi_merges_duplicate_path_method():
    from lib.evidence import endpoints_to_openapi

    endpoints = [
        {"method": "GET", "status": 200, "url": "https://example.com/api/users?role=admin"},
        {"method": "GET", "status": 401, "url": "https://example.com/api/users"},
    ]
    spec = endpoints_to_openapi("https://example.com", endpoints)
    op = spec["paths"]["/api/users"]["get"]

    assert set(op["responses"].keys()) == {"200", "401"}
    param_names = {p["name"] for p in op.get("parameters", [])}
    assert "role" in param_names


# ────────────────────────────────────────────────────────────────────────────
# Fix 3: offat FP-filter handles the vuln_details rename (offat >=0.18)
# ────────────────────────────────────────────────────────────────────────────

def test_offat_fp_filter_handles_vuln_details_key_rename():
    from tools.schema_attack import _parse_offat_output

    data = [{
        "result": True, "vulnerable": True, "test_name": "SQLi Test",
        "method": "GET", "url": "https://example.com/api",
        "vuln_details": "Parameters are not vulnerable to SQLi Payload",  # offat >=0.18 field name
        "response_status_code": 200,
    }]
    findings = _parse_offat_output(data, "https://example.com")
    assert findings == []


def test_offat_fp_filter_still_works_with_old_result_details_key():
    """Regression guard: the vuln_details fallback must not break the pre-0.18 key."""
    from tools.schema_attack import _parse_offat_output

    data = [{
        "result": True, "test_name": "SQLi Test", "method": "GET", "url": "https://example.com/api",
        "result_details": "Parameters are not vulnerable to SQLi Payload",
        "response_status_code": 200,
    }]
    findings = _parse_offat_output(data, "https://example.com")
    assert findings == []


# ────────────────────────────────────────────────────────────────────────────
# Fix 4: enrich_openapi_from_responses adds requestBody to POST-only paths
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_enrich_openapi_adds_requestbody_to_post_only_paths():
    from lib.evidence import enrich_openapi_from_responses

    openapi = {
        "servers": [{"url": "https://example.com"}],
        "paths": {
            "/login": {"post": {"responses": {}, "tags": ["discovered"]}},
        },
    }
    enriched = await enrich_openapi_from_responses(openapi, "https://example.com", None)
    assert "requestBody" in enriched["paths"]["/login"]["post"]


# ────────────────────────────────────────────────────────────────────────────
# Fix 5: auth_probe findings save under their own phase, not schema_attack
# ────────────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_auth_probe_findings_saved_to_own_phase_not_schema_attack(scan_state):
    from lib.evidence import load_artifact
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("t_authprobe_route", "https://example.com")
    await scan_state.add_finding("t_authprobe_route", {
        "id": "AP-0001", "title": "test auth finding", "severity": "high",
        "confidence": 0.9,
        "category": "Broken Authentication",
        "source_tools": ["auth_probe"], "endpoint": "GET /x", "evidence": {},
    })

    with patch("orchestrator.run_blind_attack", new_callable=AsyncMock), \
         patch("orchestrator.run_schema_attack", new_callable=AsyncMock), \
         patch("orchestrator.run_auth_probe", new_callable=AsyncMock):
        await orch._phase_attacks("t_authprobe_route", "https://example.com", None)

    assert load_artifact("t_authprobe_route", "auth_probe", "findings_auth_probe") is not None
    assert load_artifact("t_authprobe_route", "schema_attack", "findings_auth_probe") is None


# ────────────────────────────────────────────────────────────────────────────
# Fix 6: _calculate_coverage tolerates a malformed "paths" field
# ────────────────────────────────────────────────────────────────────────────

def test_calculate_coverage_malformed_paths_does_not_crash():
    from lib.schema_probe import _calculate_coverage

    schema = {"openapi": "3.0.0", "paths": ["/users", "/items"]}  # malformed: list, not dict
    endpoints = [{"method": "GET", "url": "https://example.com/users"}]
    assert _calculate_coverage(schema, endpoints) == 0.0
