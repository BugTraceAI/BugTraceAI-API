"""Quality gate: header grouping, classification, evidence, no invented vulns."""
import json
from pathlib import Path

import pytest

from lib.findings_quality import (
    CLASS_CONFIRMED,
    CLASS_HARDENING,
    CLASS_INSUFFICIENT,
    CLASS_SUSPICIOUS,
    _has_http_evidence,
    classify_finding,
    is_not_found_response,
    is_header_hardening,
    normalize_findings,
)


def _vulnapi_header(name, check_id, score=5.1, endpoint="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/CORS"):
    return {
        "id": f"VULNAPI-{name[:8]}",
        "title": f"[vulnapi] {name}",
        "severity": "medium" if score >= 4 else "info",
        "confidence": 0.85,
        "category": "API8:2023 Security Misconfiguration",
        "endpoint": endpoint,
        "source_tools": ["vulnapi"],
        "evidence": {
            "id": check_id,
            "name": name,
            "status": "failed",
            "cvss": {"score": score, "vector": "CVSS:4.0/AV:N"},
        },
        "repro": {"note": name, "cvss_score": str(score)},
    }


def test_header_findings_are_grouped_as_hardening():
    raw = [
        _vulnapi_header("CORS Headers are missing", "security_misconfiguration.http_headers_cors_missing"),
        _vulnapi_header("CSP Header is not set", "security_misconfiguration.csp_missing", score=0),
        _vulnapi_header("HSTS Header is missing", "security_misconfiguration.http_headers_hsts_missing", score=0),
        _vulnapi_header("X-Frame-Options Header is missing", "security_misconfiguration.http_headers_frame_options_missing"),
        _vulnapi_header("X-Content-Type-Options Header is missing", "security_misconfiguration.http_headers_content_options_missing", score=0),
    ]
    normalized, summary = normalize_findings(raw, target="https://api.example.com")
    assert summary["grouped_header_findings"] == 5
    assert len(normalized) == 1
    grouped = normalized[0]
    assert grouped["classification"] == CLASS_HARDENING
    assert grouped["severity"] == "info"
    assert grouped["validation_status"] == "observed"
    assert grouped["endpoint"] == "https://api.example.com"
    assert grouped["title"].startswith("Hardening:")
    assert grouped["category"] == "Hardening"
    assert grouped["evidence"]["summary"]
    assert grouped["cvss"]["score"] == 0.0
    assert is_header_hardening(raw[0])


def test_unauthenticated_root_is_not_a_vuln():
    raw = [{
        "id": "VULNAPI-0001",
        "title": "[vulnapi] Operation May Accepts Unauthenticated Requests",
        "severity": "info",
        "confidence": 0.85,
        "category": "API8:2023 Security Misconfiguration",
        "endpoint": "https://api.example.com",
        "source_tools": ["vulnapi"],
        "evidence": {
            "id": "discover.accept_unauthenticated_operation",
            "name": "Operation May Accepts Unauthenticated Requests",
            "status": "failed",
            "cvss": {"score": 0},
        },
        "repro": {"note": "root"},
    }]
    normalized, _ = normalize_findings(raw, target="https://api.example.com")
    assert normalized[0]["classification"] == CLASS_INSUFFICIENT
    assert normalized[0]["severity"] == "info"
    assert normalized[0]["validation_status"] == "needs_validation"
    assert normalized[0]["title"].startswith("Insufficient evidence:")
    assert normalized[0]["category"] == "Insufficient evidence"


def test_auth_400_is_not_bypass():
    raw = [{
        "id": "AP-0001",
        "title": "[AuthProbe] Unauthenticated access: POST /login",
        "severity": "high",
        "confidence": 0.75,
        "category": "Broken Authentication / Missing Authorization",
        "endpoint": "POST https://api.example.com/login",
        "source_tools": ["auth_probe"],
        "evidence": {
            "http_method": "POST",
            "path": "/login",
            "response_code": "422",
            "response_snippet": '{"detail":[{"loc":["body","password"]}]}',
        },
        "repro": {"curl": "curl -X POST https://api.example.com/login"},
    }]
    normalized, _ = normalize_findings(raw, target="https://api.example.com")
    assert normalized[0]["classification"] == CLASS_INSUFFICIENT
    assert normalized[0]["severity"] == "info"
    assert normalized[0]["title"].startswith("Insufficient evidence:")


def test_param_discovery_is_insufficient():
    raw = [{
        "id": "BLIND-0001",
        "title": "[x8] Undocumented parameters on GET https://api.example.com/users",
        "severity": "low",
        "confidence": 0.85,
        "category": "Information Disclosure",
        "endpoint": "GET https://api.example.com/users",
        "source_tools": ["x8"],
        "evidence": {"params": ["debug"]},
        "repro": {"curl": "curl 'https://api.example.com/users?debug=1'"},
    }]
    normalized, _ = normalize_findings(raw, target="https://api.example.com")
    assert normalized[0]["classification"] == CLASS_INSUFFICIENT
    assert normalized[0]["title"].startswith("Insufficient evidence:")


def test_http_200_not_found_is_dropped_before_investigation():
    raw = [{
        "id": "OFFAT-404-1",
        "title": "Needs validation: BOLA Path Trailing Slash Test",
        "severity": "medium",
        "confidence": 0.8,
        "category": "Needs validation",
        "endpoint": "GET https://api.example.com/api/products/7",
        "source_tools": ["offat"],
        "evidence": {
            "method": "GET",
            "response_code": "200",
            "response_snippet": '{"error":"Not found"}',
            "test_name": "BOLA Path Trailing Slash Test",
        },
    }]

    normalized, summary = normalize_findings(raw, target="https://api.example.com")

    assert normalized == []
    assert summary["dropped_not_found"] == 1
    assert summary["discarded_not_found_samples"][0]["endpoint"].endswith("/products/7")


def test_real_json_error_message_is_not_dropped_when_resource_exists():
    raw = [{
        "id": "SQLI-1",
        "title": "SQL injection error response",
        "severity": "high",
        "endpoint": "GET https://api.example.com/api/products/7",
        "source_tools": ["offat"],
        "evidence": {
            "method": "GET",
            "response_code": "500",
            "response_snippet": '{"error":"syntax error near SELECT"}',
        },
    }]

    assert not is_not_found_response(raw[0])
    normalized, summary = normalize_findings(raw, target="https://api.example.com")
    assert len(normalized) == 1
    assert summary["dropped_not_found"] == 0


def test_secrets_are_redacted():
    raw = [{
        "id": "OFFAT-0001",
        "title": "[OFFAT] sqli",
        "severity": "high",
        "confidence": 0.8,
        "category": "OWASP API Security Top 10",
        "endpoint": "GET https://api.example.com/users",
        "source_tools": ["offat"],
        "evidence": {
            "http_method": "GET",
            "response_code": "500",
            "request_headers": {"Authorization": "Bearer supersecret-token-value"},
            "response_snippet": "syntax error",
        },
        "repro": {"curl": "curl -H 'Authorization: Bearer supersecret-token-value' https://api.example.com/users"},
    }]
    normalized, _ = normalize_findings(
        raw, target="https://api.example.com",
        auth={"type": "bearer", "token": "supersecret-token-value"},
    )
    blob = str(normalized[0]["evidence"]) + str(normalized[0]["repro"])
    assert "supersecret-token-value" not in blob
    assert normalized[0]["classification"] == CLASS_SUSPICIOUS


@pytest.mark.asyncio
async def test_aggregation_replaces_live_findings_with_quality_gate(scan_state):
    """Live GET /results must match the quality-gated list, not the raw tool dump."""
    from lib.evidence import save_artifact
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("qg1", "https://api.example.com")
    raw = [
        {
            "id": "VULNAPI-0001",
            "title": "[vulnapi] CORS Headers are missing",
            "severity": "medium",
            "confidence": 0.85,
            "category": "API8:2023 Security Misconfiguration",
            "endpoint": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/CORS",
            "source_tools": ["vulnapi"],
            "evidence": {
                "id": "security_misconfiguration.http_headers_cors_missing",
                "name": "CORS Headers are missing",
                "status": "failed",
                "cvss": {"score": 5.1},
            },
            "repro": {"note": "CORS", "cvss_score": "5.1"},
        },
        {
            "id": "VULNAPI-0002",
            "title": "[vulnapi] HSTS Header is missing",
            "severity": "info",
            "confidence": 0.85,
            "category": "API8:2023 Security Misconfiguration",
            "endpoint": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/HSTS",
            "source_tools": ["vulnapi"],
            "evidence": {
                "id": "security_misconfiguration.http_headers_hsts_missing",
                "name": "HSTS Header is missing",
                "status": "failed",
                "cvss": {"score": 0},
            },
            "repro": {"note": "HSTS"},
        },
    ]
    for finding in raw:
        await scan_state.add_finding("qg1", finding)
    save_artifact("qg1", "schema_attack", "findings_vulnapi", raw)
    save_artifact("qg1", "discovery", "all_endpoints", [])
    save_artifact("qg1", "discovery", "phase_summary", {})
    save_artifact("qg1", "schema_probe", "schema_decision", {"source": "discovered", "paths_count": 4, "parsed": True})

    await orch._phase_aggregation("qg1", "https://api.example.com", "standard", 0.0)
    results = await scan_state.get_results("qg1")
    assert len(results["findings"]) == 1
    assert results["findings"][0]["classification"] == "hardening"
    assert results["findings"][0]["severity"] == "info"
    assert results["findings"][0]["title"].startswith("Hardening:")
    assert results["status"]["findings_count"] == 1
    from lib.evidence import get_scan_dir
    report_md = (get_scan_dir("qg1") / "report.md").read_text()
    assert "## Hardening" in report_md
    assert "## Confirmed vulnerabilities" in report_md


def test_prepare_offat_spec_downgrades_openapi_31(tmp_path):
    from tools.attack.offat import prepare_offat_spec

    src = tmp_path / "published_openapi.json"
    src.write_text(json.dumps({
        "openapi": "3.1.0",
        "info": {"title": "x", "version": "1"},
        "paths": {},
    }))
    out = prepare_offat_spec(str(src), "https://api.example.com/v2")
    spec = json.loads(Path(out).read_text())
    assert spec["openapi"] == "3.0.3"
    assert spec["servers"][0]["url"] == "https://api.example.com"


def test_offat_status_alias_is_http_evidence():
    from tools.attack.offat import _parse_offat_output

    parsed = _parse_offat_output(
        [{
            "result": True,
            "test_name": "sqli on /users",
            "method": "GET",
            "url": "https://api.example.com/users",
            "response_status_code": 500,
            "result_details": "error based sql",
        }],
        "https://api.example.com",
    )
    assert len(parsed) == 1
    evidence = parsed[0]["evidence"]
    assert evidence["response_code"] == "500"
    assert evidence["http_method"] == "GET"
    assert evidence["response_status_code"] == 500
    assert _has_http_evidence(parsed[0])
    classification, _reason = classify_finding(parsed[0], "https://api.example.com")
    assert classification == CLASS_SUSPICIOUS
    assert classification != CLASS_CONFIRMED
    assert classification != CLASS_INSUFFICIENT


def test_schemathesis_5xx_is_never_confirmed():
    finding = {
        "id": "ST-0001",
        "title": "[Schemathesis] status_code_conformance: GET /x",
        "severity": "high",
        "confidence": 0.85,
        "category": "API Specification Conformance",
        "endpoint": "GET https://api.example.com/x",
        "source_tools": ["schemathesis"],
        "evidence": {
            "check": "status_code_conformance",
            "http_method": "GET",
            "path": "/x",
            "response_code": "500",
            "raw_snippet": "HTTP/1.1 500",
        },
        "repro": {"curl": "curl -X GET 'https://api.example.com/x'"},
    }
    classification, _reason = classify_finding(finding, "https://api.example.com")
    assert classification == CLASS_SUSPICIOUS
    assert classification != CLASS_CONFIRMED


@pytest.mark.asyncio
async def test_aggregation_redacts_auth_when_passed(scan_state):
    from lib.evidence import get_scan_dir, save_artifact
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("qg_tok", "https://api.example.com")
    raw = [{
        "id": "OFFAT-0001",
        "title": "[OFFAT] sqli",
        "severity": "high",
        "confidence": 0.8,
        "category": "OWASP API Security Top 10",
        "endpoint": "GET https://api.example.com/users",
        "source_tools": ["offat"],
        "evidence": {
            "test_name": "sqli",
            "method": "GET",
            "http_method": "GET",
            "url": "https://api.example.com/users",
            "response_code": "500",
            "response_status_code": 500,
            "request_headers": {"Authorization": "Bearer supersecret-token-value"},
        },
        "repro": {
            "curl": "curl -H 'Authorization: Bearer supersecret-token-value' https://api.example.com/users",
            "method": "GET",
        },
    }]
    save_artifact("qg_tok", "schema_attack", "findings_offat", raw)
    save_artifact("qg_tok", "discovery", "all_endpoints", [])
    save_artifact("qg_tok", "discovery", "phase_summary", {})
    save_artifact("qg_tok", "schema_probe", "schema_decision", {"source": "discovered", "parsed": True})
    await orch._phase_aggregation(
        "qg_tok",
        "https://api.example.com",
        "standard",
        0.0,
        auth={"type": "bearer", "token": "supersecret-token-value"},
    )
    blob = (get_scan_dir("qg_tok") / "findings.json").read_text()
    assert "supersecret-token-value" not in blob
    results = await scan_state.get_results("qg_tok")
    assert results["findings"]
    assert results["findings"][0]["classification"] != CLASS_CONFIRMED


def test_dedup_same_cause_and_endpoint():
    raw = [
        _vulnapi_header("CORS Headers are missing", "headers.cors"),
        _vulnapi_header("CORS Headers are missing", "headers.cors"),
    ]
    normalized, summary = normalize_findings(raw, target="https://api.example.com")
    assert len(normalized) == 1
    assert summary["grouped_header_findings"] == 2
