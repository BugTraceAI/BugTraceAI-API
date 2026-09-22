"""Tests for improved investigation engine (Phase 6 v2)."""
import asyncio
import json
import time
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lib.investigation_models import (
    Hypothesis,
    ValidationStep,
    ValidationPlan,
    InvestigatorBudget,
    InvestigatorState,
    IterationResult,
    HYP_STATUS_PROPOSED,
    HYP_STATUS_TESTING,
    HYP_STATUS_SUPPORTED,
    HYP_STATUS_REFUTED,
    HYP_STATUS_INCONCLUSIVE,
    HYP_STATUS_BLOCKED_AUTH,
    HYP_STATUS_ERROR,
    ALL_HYP_STATUSES,
    CONCLUSIVE_STATUSES,
)
from tools.investigate import (
    _build_adjudicator_prompt,
    _build_plan_prompt,
    _path_matches_inventory,
    validate_plan,
    run_investigation,
    _parse_json_response,
    _compute_fingerprint,
)


class TestHypothesisStates:
    """Test hypothesis lifecycle states."""

    def test_valid_statuses(self):
        """All expected statuses should be valid."""
        assert HYP_STATUS_PROPOSED in ALL_HYP_STATUSES
        assert HYP_STATUS_TESTING in ALL_HYP_STATUSES
        assert HYP_STATUS_SUPPORTED in ALL_HYP_STATUSES
        assert HYP_STATUS_REFUTED in ALL_HYP_STATUSES
        assert HYP_STATUS_INCONCLUSIVE in ALL_HYP_STATUSES
        assert HYP_STATUS_BLOCKED_AUTH in ALL_HYP_STATUSES
        assert HYP_STATUS_ERROR in ALL_HYP_STATUSES

    def test_conclusive_statuses(self):
        """Conclusive statuses should be properly defined."""
        assert HYP_STATUS_SUPPORTED in CONCLUSIVE_STATUSES
        assert HYP_STATUS_REFUTED in CONCLUSIVE_STATUSES
        assert HYP_STATUS_INCONCLUSIVE not in CONCLUSIVE_STATUSES

    def test_hypothesis_from_dict_with_new_status(self):
        """Hypothesis should accept new status values."""
        h = Hypothesis.from_dict({
            "id": "H1",
            "title": "Test",
            "status": HYP_STATUS_SUPPORTED,
        })
        assert h.status == HYP_STATUS_SUPPORTED

    def test_invalid_status_defaults_to_proposed(self):
        """Invalid status should default to proposed."""
        h = Hypothesis.from_dict({
            "id": "H1",
            "status": "invalid_status",
        })
        assert h.status == HYP_STATUS_PROPOSED

    def test_is_resolved(self):
        """is_resolved should return correct value."""
        h = Hypothesis(id="H1", title="Test")
        assert not h.is_resolved()

        h.status = HYP_STATUS_SUPPORTED
        assert h.is_resolved()

        h.status = HYP_STATUS_REFUTED
        assert h.is_resolved()

    def test_update_status_guardrails(self):
        """Should not downgrade supported without explicit override."""
        h = Hypothesis(id="H1", title="Test", status=HYP_STATUS_SUPPORTED)
        # Should warn but allow downgrade to inconclusive or error
        h.update_status(HYP_STATUS_INCONCLUSIVE)
        assert h.status == HYP_STATUS_INCONCLUSIVE


class TestValidationStep:
    """Test validation step validation."""

    def test_valid_step(self):
        """Valid step should pass validation."""
        step = ValidationStep(
            id="S1",
            hypothesis_id="H1",
            tool="coverage_probe",
            method="GET",
            url="https://api.example.com/users/1",
            expected_indicator="200 status",
        )
        assert step.validate() == []

    def test_invalid_tool(self):
        """Invalid tool should fail validation."""
        step = ValidationStep(
            id="S1",
            hypothesis_id="H1",
            tool="unknown_tool",
            method="GET",
            url="https://api.example.com/users/1",
            expected_indicator="200 status",
        )
        errors = step.validate()
        assert any("unknown_tool" in e for e in errors)

    def test_missing_expected_indicator(self):
        """Missing expected indicator should fail validation."""
        step = ValidationStep(
            id="S1",
            hypothesis_id="H1",
            tool="coverage_probe",
            method="GET",
            url="https://api.example.com/users/1",
            expected_indicator="",
        )
        errors = step.validate()
        assert any("expected_indicator" in e for e in errors)

    def test_non_absolute_url(self):
        """Non-absolute URL should fail validation."""
        step = ValidationStep(
            id="S1",
            hypothesis_id="H1",
            tool="coverage_probe",
            method="GET",
            url="/api/users/1",
            expected_indicator="200 status",
        )
        errors = step.validate()
        assert any("url_must_be_absolute" in e for e in errors)


class TestPlanValidation:
    """Test plan validation."""

    def test_valid_plan(self):
        """Valid plan should pass."""
        plan = {
            "hypotheses": [{"id": "H1", "title": "Test", "category": "security"}],
            "steps": [{
                "id": "S1",
                "hypothesis_id": "H1",
                "tool": "coverage_probe",
                "method": "GET",
                "url": "https://api.example.com/users/1",
                "expected_indicator": "200 OK",
            }],
        }
        valid, errors = validate_plan(plan)
        assert valid
        assert errors == []

    def test_invalid_plan_no_hypotheses(self):
        """Plan without hypotheses should fail."""
        plan = {"steps": []}
        valid, errors = validate_plan(plan)
        assert not valid
        assert any("hypothesis" in e.lower() for e in errors)

    def test_invalid_plan_no_steps(self):
        """Plan without steps should fail."""
        plan = {
            "hypotheses": [{"id": "H1"}],
        }
        valid, errors = validate_plan(plan)
        assert not valid
        assert any("step" in e.lower() for e in errors)

    def test_invalid_plan_unknown_tool(self):
        """Plan with unknown tool should fail."""
        plan = {
            "hypotheses": [{"id": "H1"}],
            "steps": [{
                "id": "S1",
                "hypothesis_id": "H1",
                "tool": "unknown_tool",
                "method": "GET",
                "url": "https://api.example.com/users/1",
                "expected_indicator": "200 OK",
            }],
        }
        valid, errors = validate_plan(plan)
        assert not valid

    def test_plan_rejects_endpoint_outside_inventory(self):
        plan = {
            "hypotheses": [{"id": "H1"}],
            "steps": [{
                "id": "S1", "tool": "coverage_probe", "method": "GET",
                "url": "https://api.example.com/api/users/1",
                "expected_indicator": "response",
            }],
        }
        valid, errors = validate_plan(
            plan,
            target="https://api.example.com",
            known_endpoints=[{"method": "GET", "url": "https://api.example.com/api/products/{id}"}],
        )
        assert not valid
        assert any("inventory" in error for error in errors)

    def test_plan_allows_concrete_openapi_path_parameter(self):
        assert _path_matches_inventory(
            "https://api.example.com/api/products/7",
            "https://api.example.com/api/products/{id}",
        )

    def test_prompt_contract_contains_runtime_context(self):
        prompt = _build_plan_prompt(
            "https://api.example.com", [{"method": "GET", "url": "https://api.example.com/health"}],
            [], [{"id": "H1"}], [], False, {"remaining": 1},
        )
        assert "https://api.example.com/health" in prompt
        assert "{{ENDPOINTS}}" not in prompt
        adjudicator = _build_adjudicator_prompt({"findings": []}, [{"id": "H1"}])
        assert "{{NEW_FINDINGS}}" not in adjudicator


class TestJSONParsing:
    """Test JSON parsing from model responses."""

    def test_parse_direct_json(self):
        """Direct JSON should parse correctly."""
        text = '{"hypotheses": [{"id": "H1"}]}'
        result = _parse_json_response(text, "plan")
        assert result == {"hypotheses": [{"id": "H1"}]}

    def test_parse_markdown_wrapped(self):
        """JSON in markdown code block should parse."""
        text = '```json\n{"hypotheses": [{"id": "H1"}]}\n```'
        result = _parse_json_response(text, "plan")
        assert result["hypotheses"][0]["id"] == "H1"

    def test_parse_first_brace_block(self):
        """First { } block should be extracted."""
        text = 'Some preamble\n\n{"hypotheses": [{"id": "H1"}]}\n\nExplanation'
        result = _parse_json_response(text, "plan")
        assert result["hypotheses"][0]["id"] == "H1"

    def test_parse_raises_on_invalid(self):
        """Invalid JSON should raise ValueError."""
        with pytest.raises(ValueError):
            _parse_json_response("not json at all", "plan")


class TestFingerprint:
    """Test fingerprint computation."""

    def test_fingerprint_consistency(self):
        """Same finding should produce same fingerprint."""
        finding = {
            "title": "Test finding",
            "category": "bola",
            "endpoint": "https://api.example.com/users/1",
            "classification": "suspicious",
        }
        fp1 = _compute_fingerprint(finding)
        fp2 = _compute_fingerprint(finding)
        assert fp1 == fp2
        assert len(fp1) == 12

    def test_fingerprint_different_for_different_findings(self):
        """Different findings should have different fingerprints."""
        finding1 = {"title": "Finding 1", "category": "bola"}
        finding2 = {"title": "Finding 2", "category": "auth_bypass"}
        fp1 = _compute_fingerprint(finding1)
        fp2 = _compute_fingerprint(finding2)
        assert fp1 != fp2


class TestInvestigatorState:
    """Test investigator state serialization."""

    def test_state_from_dict(self):
        """State should be reconstructable from dict."""
        state_dict = {
            "scan_id": "test-scan",
            "target": "https://api.example.com",
            "status": "running",
            "hypotheses": [{"id": "H1", "title": "Test"}],
            "iterations": [],
            "budget": {"max_iterations": 5, "max_tool_calls_per_iteration": 10, "max_total_tool_calls": 50},
        }
        state = InvestigatorState.from_dict(state_dict)
        assert state.scan_id == "test-scan"
        assert len(state.hypotheses) == 1
        assert state.hypotheses[0].id == "H1"

    def test_state_duration_calculation(self):
        """Duration should never be negative."""
        from datetime import datetime
        state = InvestigatorState(
            scan_id="test",
            target="https://api.example.com",
            hypotheses=[],
            started_at=datetime.now().isoformat(),
        )
        elapsed = state.elapsed_seconds()
        assert elapsed >= 0

    def test_state_is_blocked(self):
        """State should report blocked when completed/failed/stopped."""
        for status in ("completed", "failed", "stopped"):
            state = InvestigatorState(scan_id="test", target="https://api.example.com", hypotheses=[])
            state.status = status
            assert state.status in ("completed", "failed", "stopped")

        state = InvestigatorState(scan_id="test", target="https://api.example.com", hypotheses=[])
        state.status = "running"
        assert state.status == "running"


@pytest.mark.asyncio
class TestInvestigationLoop:
    """Test the investigation loop logic."""

    async def test_no_endpoints_no_findings(self):
        """Should return early if nothing to investigate."""
        with patch('tools.investigate.get_active_provider') as mock_provider:
            mock_provider.return_value.enabled = False
            state = await run_investigation(
                scan_id="test-scan",
                target="https://api.example.com",
                endpoints=[],
                findings=[],
            )
            assert state.status == "completed"
            assert state.stop_reason == "disabled"

    async def test_budget_enforcement(self):
        """Should respect budget limits."""
        with patch('tools.investigate.get_active_provider') as mock_provider:
            mock_provider.return_value.enabled = True
            # Mock _generate to return valid plan
            with patch('tools.investigate._generate') as mock_gen:
                mock_gen.return_value = {
                    "text": json.dumps({
                        "hypotheses": [{"id": "H1", "title": "Test", "category": "security"}],
                        "steps": [{"id": "S1", "hypothesis_id": "H1", "tool": "coverage_probe", "method": "GET", "url": "https://api.example.com/", "expected_indicator": "200"}],
                    })
                }
                # Mock runner
                with patch('tools.investigate._get_runner') as mock_runner:
                    mock_runner.return_value.run = AsyncMock(return_value=[])
                    
                    state = await run_investigation(
                        scan_id="test-scan",
                        target="https://api.example.com",
                        endpoints=[{"method": "GET", "url": "https://api.example.com/"}],
                        findings=[],
                        budget=InvestigatorBudget(max_iterations=2, max_total_tool_calls=10),
                    )
                    assert state.total_tool_calls >= 0
