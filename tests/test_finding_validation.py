"""Regression tests for the Finding validation added to lib/scan_state.py.

After the 2026-09-11 refactor, `add_finding` validates every incoming dict
against the `Finding` Pydantic model and rejects malformed entries with a
warning log instead of corrupting the scan's findings list.

These tests cover:
  1. Valid findings pass through cleanly
  2. Missing required fields raise ValueError
  3. Bad severity values are rejected, good ones normalised to lowercase
  4. Confidence outside [0, 1] is clamped
  5. Non-string repro values are coerced to str
  6. Extra fields are preserved (so tool-specific payload is not lost)
  7. Empty source_tools is rejected
"""
import pytest

from lib.scan_state import Finding
from lib.scan_state import _decorate_findings_for_api

# ── Valid findings pass through ───────────────────────────────────────────────

def test_valid_finding_passes_cleanly():
    raw = {
        "id": "VULNAPI-0001",
        "title": "[vulnapi] Missing Security Header",
        "severity": "high",
        "confidence": 0.85,
        "category": "OWASP API Top 10",
        "endpoint": "GET /api/v1/users",
        "source_tools": ["vulnapi"],
        "evidence": {"check_id": "HS001"},
        "repro": {"note": "HS001. CWE-942"},
    }
    validated = Finding.validate_dict(raw)
    assert validated["id"] == "VULNAPI-0001"
    assert validated["severity"] == "high"
    assert validated["confidence"] == 0.85
    assert validated["evidence"] == {"check_id": "HS001"}


def test_extra_fields_are_preserved():
    """Tool-specific extra keys must survive validation."""
    raw = {
        "id": "OFFAT-0100",
        "title": "SQLi",
        "severity": "medium",
        "confidence": 0.8,
        "category": "API Security",
        "endpoint": "POST /login",
        "source_tools": ["offat"],
        "evidence": {},
        "repro": {},
        "offat_test_id": "sqli_001",
        "offat_response_body": "<html>...error...",
    }
    validated = Finding.validate_dict(raw)
    assert validated["offat_test_id"] == "sqli_001"
    assert validated["offat_response_body"] == "<html>...error..."


def test_api_finding_view_includes_normalized_context_and_model_enrichment():
    finding = {
        "id": "VULNAPI-0004",
        "title": "Missing CORS header",
        "severity": "medium",
        "confidence": 0.85,
        "category": "API8:2023 Security Misconfiguration",
        "endpoint": "https://example.test/api/v1",
        "affected_count": 3,
        "source_tools": ["vulnapi"],
        "evidence": {
            "id": "headers.cors",
            "name": "CORS headers are missing",
            "status": "failed",
            "cvss": {"vector": "CVSS:4.0/AV:N"},
        },
        "repro": {"note": "Missing response header"},
    }
    decorated = _decorate_findings_for_api([finding], {
        "model": "minimax/minimax-m3",
        "pocs": [{
            "finding_id": "VULNAPI-0004",
            "model_used": "minimax/minimax-m3",
            "poc": "## Assessment\nThe header is absent.",
        }],
    })[0]

    assert decorated["detail_context"]["check_id"] == "headers.cors"
    assert decorated["detail_context"]["observed_status"] == "failed"
    assert decorated["detail_context"]["affected_endpoints"] == 3
    assert decorated["ai_enrichment"]["model"] == "minimax/minimax-m3"
    assert "header is absent" in decorated["ai_enrichment"]["poc"]


# ── Bad required fields are rejected ─────────────────────────────────────────

def test_missing_id_raises():
    with pytest.raises(ValueError, match="id"):
        Finding.validate_dict({
            "title": "T", "severity": "low", "confidence": 0.5,
            "category": "C", "endpoint": "E", "source_tools": ["t"],
        })


def test_missing_title_raises():
    with pytest.raises(ValueError, match="title"):
        Finding.validate_dict({
            "id": "X", "severity": "low", "confidence": 0.5,
            "category": "C", "endpoint": "E", "source_tools": ["t"],
        })


def test_empty_source_tools_raises():
    with pytest.raises(ValueError, match="source_tools"):
        Finding.validate_dict({
            "id": "X", "title": "T", "severity": "low", "confidence": 0.5,
            "category": "C", "endpoint": "E", "source_tools": [],
        })


def test_empty_endpoint_raises():
    with pytest.raises(ValueError, match="endpoint"):
        Finding.validate_dict({
            "id": "X", "title": "T", "severity": "low", "confidence": 0.5,
            "category": "C", "endpoint": "", "source_tools": ["t"],
        })


# ── Severity normalisation and validation ─────────────────────────────────────

def test_severity_normalised_to_lowercase():
    validated = Finding.validate_dict({
        "id": "X", "title": "T", "severity": "HIGH",
        "confidence": 0.5, "category": "C", "endpoint": "E", "source_tools": ["t"],
    })
    assert validated["severity"] == "high"


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_valid_severity_values(severity):
    validated = Finding.validate_dict({
        "id": "X", "title": "T", "severity": severity,
        "confidence": 0.5, "category": "C", "endpoint": "E", "source_tools": ["t"],
    })
    assert validated["severity"] == severity


def test_invalid_severity_raises():
    with pytest.raises(ValueError, match="severity"):
        Finding.validate_dict({
            "id": "X", "title": "T", "severity": "ultra",
            "confidence": 0.5, "category": "C", "endpoint": "E", "source_tools": ["t"],
        })


# ── Confidence clamping ───────────────────────────────────────────────────────

def test_confidence_clamped_to_1_when_too_high():
    validated = Finding.validate_dict({
        "id": "X", "title": "T", "severity": "low",
        "confidence": 1.5, "category": "C", "endpoint": "E", "source_tools": ["t"],
    })
    assert validated["confidence"] == 1.0


def test_confidence_clamped_to_0_when_negative():
    validated = Finding.validate_dict({
        "id": "X", "title": "T", "severity": "low",
        "confidence": -0.3, "category": "C", "endpoint": "E", "source_tools": ["t"],
    })
    assert validated["confidence"] == 0.0


def test_confidence_coerced_from_string():
    validated = Finding.validate_dict({
        "id": "X", "title": "T", "severity": "low",
        "confidence": "0.7", "category": "C", "endpoint": "E", "source_tools": ["t"],
    })
    assert validated["confidence"] == 0.7


# ── Repro coercion ────────────────────────────────────────────────────────────

def test_repro_values_coerced_to_str():
    validated = Finding.validate_dict({
        "id": "X", "title": "T", "severity": "low",
        "confidence": 0.5, "category": "C", "endpoint": "E",
        "source_tools": ["t"],
        "repro": {"cvss_score": 9.8, "port": 443},
    })
    assert validated["repro"]["cvss_score"] == "9.8"
    assert validated["repro"]["port"] == "443"


def test_repro_defaults_to_empty_dict():
    validated = Finding.validate_dict({
        "id": "X", "title": "T", "severity": "low",
        "confidence": 0.5, "category": "C", "endpoint": "E", "source_tools": ["t"],
    })
    assert validated["repro"] == {}


# ── Integration with add_finding ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_add_finding_skips_malformed(scan_state):
    """Malformed findings should be skipped with a warning, not stored."""
    from lib.scan_state import scan_state as state

    await state.create_scan("t_malformed", "https://example.com")

    bad_finding = {
        "id": "BAD-001",
        "title": "Missing severity",  # no severity field
        "confidence": 0.5,
        "category": "Test",
        "endpoint": "GET /x",
        "source_tools": ["test"],
    }
    await state.add_finding("t_malformed", bad_finding)

    results = await state.get_results("t_malformed")
    assert len(results["findings"]) == 0


@pytest.mark.asyncio
async def test_add_finding_accepts_valid(scan_state):
    """Valid findings should be stored normally."""
    from lib.scan_state import scan_state as state

    await state.create_scan("t_valid", "https://example.com")

    good_finding = {
        "id": "GOOD-001",
        "title": "Valid finding",
        "severity": "high",
        "confidence": 0.9,
        "category": "Auth",
        "endpoint": "GET /api",
        "source_tools": ["test"],
    }
    await state.add_finding("t_valid", good_finding)

    results = await state.get_results("t_valid")
    assert len(results["findings"]) == 1
    assert results["findings"][0]["id"] == "GOOD-001"
    assert results["findings"][0]["severity"] == "high"  # normalised


@pytest.mark.asyncio
async def test_add_finding_clamps_confidence(scan_state):
    """Confidence outside [0, 1] should be clamped on storage."""
    from lib.scan_state import scan_state as state

    await state.create_scan("t_clamp", "https://example.com")

    finding = {
        "id": "CLAMP-001",
        "title": "Too much confidence",
        "severity": "low",
        "confidence": 1.5,  # will be clamped
        "category": "Test",
        "endpoint": "GET /x",
        "source_tools": ["test"],
    }
    await state.add_finding("t_clamp", finding)

    results = await state.get_results("t_clamp")
    assert results["findings"][0]["confidence"] == 1.0
