"""Tests for investigation models."""

import json

import pytest

from lib.investigation_models import (
    EvidenceComparison,
    Hypothesis,
    InvestigatorBudget,
    InvestigatorState,
    IterationResult,
    ValidationPlan,
    ValidationStep,
)


class TestHypothesis:
    def test_defaults(self):
        h = Hypothesis(id="H1", title="Test")
        assert h.id == "H1"
        assert h.category == "security"
        assert h.confidence == 0.5
        assert h.status == "proposed"

    def test_from_dict(self):
        d = {"id": "H2", "title": "X", "confidence": 0.9}
        h = Hypothesis.from_dict(d)
        assert h.id == "H2"
        assert h.confidence == 0.9

    def test_from_instance(self):
        h1 = Hypothesis(id="H1")
        h2 = Hypothesis.from_dict(h1)
        assert h2.id == "H1"


class TestValidationStep:
    def test_defaults(self):
        s = ValidationStep(id="S1", hypothesis_id="H1")
        assert s.method == "GET"
        assert s.params == {}

    def test_from_dict(self):
        d = {
            "id": "S2",
            "hypothesis_id": "H1",
            "tool": "auth_probe",
            "method": "POST",
            "url": "/api/login",
        }
        s = ValidationStep.from_dict(d)
        assert s.tool == "auth_probe"
        assert s.method == "POST"


class TestValidationPlan:
    def test_empty(self):
        p = ValidationPlan()
        assert p.steps == []

    def test_from_dict_with_steps(self):
        d = {
            "steps": [
                {"id": "S1", "hypothesis_id": "H1", "tool": "coverage_probe", "url": "/"},
            ],
            "rationale": "Check root",
        }
        p = ValidationPlan.from_dict(d)
        assert len(p.steps) == 1
        assert p.steps[0].id == "S1"


class TestEvidenceComparison:
    def test_defaults(self):
        c = EvidenceComparison()
        assert c.delta_count == 0

    def test_from_dict(self):
        d = {
            "new_fingerprints": ["a", "b"],
            "repeat_fingerprints": ["c"],
            "delta_count": 2,
        }
        c = EvidenceComparison.from_dict(d)
        assert len(c.new_fingerprints) == 2
        assert c.repeat_fingerprints == ["c"]


class TestIterationResult:
    def test_from_dict(self):
        d = {
            "iteration_number": 1,
            "tool_calls": 3,
            "findings": [{"id": "f1"}],
            "adjudication": "ok",
        }
        r = IterationResult.from_dict(d)
        assert r.iteration_number == 1
        assert r.tool_calls == 3
        assert len(r.findings) == 1
        assert r.adjudication == "ok"


class TestInvestigatorBudget:
    def test_defaults(self):
        b = InvestigatorBudget()
        assert b.max_iterations == 5
        assert b.max_tool_calls_per_iteration == 10
        assert b.max_total_tool_calls == 50

    def test_custom(self):
        b = InvestigatorBudget(max_iterations=3, max_total_tool_calls=20)
        assert b.max_iterations == 3
        assert b.max_total_tool_calls == 20


class TestInvestigatorState:
    def test_defaults(self):
        s = InvestigatorState(scan_id="test123")
        assert s.status == "pending"
        assert s.hypotheses == []
        assert s.iterations == []
        assert s.total_tool_calls == 0

    def test_from_dict(self):
        d = {
            "scan_id": "abc",
            "target": "http://example.com",
            "status": "running",
            "total_tool_calls": 5,
            "hypotheses": [{"id": "H1", "title": "test"}],
            "iterations": [
                {"iteration_number": 1, "tool_calls": 3, "adjudication": "ok"}
            ],
        }
        s = InvestigatorState.from_dict(d)
        assert s.scan_id == "abc"
        assert s.status == "running"
        assert s.total_tool_calls == 5
        assert len(s.hypotheses) == 1
        assert len(s.iterations) == 1

    def test_serialization_roundtrip(self):
        s1 = InvestigatorState(scan_id="x", target="http://example.com")
        s2 = InvestigatorState.from_dict(s1.model_dump())
        assert s2.scan_id == "x"
        assert s2.target == "http://example.com"


class TestJSONSchemaShape:
    def test_state_to_json(self):
        s = InvestigatorState(
            scan_id="test",
            target="http://example.com",
            budget=InvestigatorBudget(max_iterations=2),
        )
        s.hypotheses.append(Hypothesis(id="H1", title="X"))
        s.iterations.append(
            IterationResult(iteration_number=1, tool_calls=1, adjudication="ok")
        )

        data = s.model_dump()
        assert "scan_id" in data
        assert "hypotheses" in data
        assert "iterations" in data

        json_str = json.dumps(data, default=str)
        parsed = json.loads(json_str)
        assert parsed["scan_id"] == "test"
