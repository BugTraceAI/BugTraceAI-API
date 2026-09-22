"""Tests for the investigation loop controller."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from lib.investigation_models import InvestigatorBudget
from tools.investigate import (
    _TOOL_RUNNERS,
    _check_iteration_budget,
    _compute_fingerprint,
    _execute_plan_step,
    _generate_valid_plan,
    _is_reportable_finding,
    _normalize_plan_data,
    _parse_json_response,
    register_tool_runner,
    run_investigation,
)


@pytest.fixture
def mock_provider():
    p = MagicMock()
    p.enabled = True
    p.id = "openrouter"
    p.model = "minimax-m3"
    p.api_key = "test-key"
    p.is_local = False
    p.min_severity = "info"
    p.base_url = "https://openrouter.ai/api/v1"
    p.kind = "openai"
    p.headers = {}
    p.options = None
    p.model_failover = []
    return p


@pytest.fixture
def mock_scan_state():
    state = MagicMock()
    state.get_scan = AsyncMock(return_value=None)
    state.get_results = AsyncMock(return_value={
        "findings": [],
        "endpoints": [],
        "schema": {},
        "tool_health": {},
    })
    state.update_scan = AsyncMock()
    state.replace_findings = AsyncMock()
    state.add_finding = AsyncMock()
    state.set_ai_analysis = AsyncMock()
    state.update_tool_health = AsyncMock()
    state.lock = asyncio.Lock()
    state.scan_responses = {}
    state.is_stopped = AsyncMock(return_value=False)
    return state


def _sample_finding():
    return {
        "id": "f1",
        "title": "Suspicious endpoint",
        "severity": "medium",
        "category": "security",
        "endpoint": "/api/users/1",
        "classification": "suspicious",
        "source_tools": ["auth_probe"],
        "evidence": {"response_code": 403},
    }


class TestToolRunnerRegistration:
    def test_builtin_runners_registered(self):
        expected = {"coverage_probe", "auth_probe", "authz_probe",
                    "schemathesis", "offat", "vulnapi",
                    "blinds", "arjun", "x8", "manual_replay"}
        assert expected.issubset(set(_TOOL_RUNNERS.keys()))

    def test_register_custom_runner(self):
        async def fake_runner(*args, **kwargs):
            return [{"finding": "test"}]
        register_tool_runner("custom_tool", fake_runner)
        assert "custom_tool" in _TOOL_RUNNERS
        assert _TOOL_RUNNERS["custom_tool"] is fake_runner

    @pytest.mark.asyncio
    async def test_execute_plan_step_accepts_async_callable(self):
        received = {}

        async def runner(**kwargs):
            received.update(kwargs)
            return [{"ok": True}]

        result = await _execute_plan_step(
            runner,
            scan_id="scan1",
            tool_name="coverage_probe",
            url="https://api.example.com/users",
            method="GET",
            params={},
            auth=None,
            allow_mutating=False,
        )

        assert result == [{"ok": True}]
        assert received["scan_id"] == "scan1"
        assert received["url"].endswith("/users")

    @pytest.mark.asyncio
    async def test_execute_plan_step_accepts_tool_runner_object(self):
        class Runner:
            async def run(self, **kwargs):
                return kwargs["method"]

        result = await _execute_plan_step(
            Runner(),
            scan_id="scan1",
            tool_name="manual_replay",
            url="https://api.example.com/",
            method="HEAD",
            params={},
            auth=None,
            allow_mutating=False,
        )
        assert result == "HEAD"


class TestPlanRepair:
    def test_raw_response_is_evidence_not_finding(self):
        assert not _is_reportable_finding({"status": 200, "body_hash": "abc"})
        assert _is_reportable_finding({"title": "Missing auth"})

    def test_normalize_model_aliases(self):
        plan = _normalize_plan_data({
            "steps": [
                {"tool": "blind_attack", "method": "AUTO"},
                {"tool": "schema_attack", "method": "ANY"},
            ]
        })
        assert plan["steps"][0]["tool"] == "blinds"
        assert plan["steps"][0]["method"] == "GET"
        assert plan["steps"][1]["tool"] == "schemathesis"
        assert plan["steps"][1]["method"] == "GET"

    def test_normalize_relative_urls_against_target(self):
        plan = _normalize_plan_data(
            {"steps": [{"tool": "coverage_probe", "url": "/api/users/1"}]},
            target="https://api.example.com/api/v1",
        )
        assert plan["steps"][0]["url"] == "https://api.example.com/api/users/1"

    def test_normalize_prompt_placeholder_host(self):
        plan = _normalize_plan_data(
            {"steps": [{"tool": "coverage_probe", "url": "https://target.example.com/api/users/1"}]},
            target="https://bugstore.example/api/v1",
        )
        assert plan["steps"][0]["url"] == "https://bugstore.example/api/users/1"

    @pytest.mark.asyncio
    async def test_invalid_plan_gets_one_repair_attempt(self):
        provider = MagicMock()
        repaired = {
            "text": json.dumps({
                "hypotheses": [{"id": "H1", "title": "coverage"}],
                "steps": [{
                    "id": "S1", "hypothesis_id": "H1", "tool": "coverage_probe",
                    "method": "GET", "url": "https://api.example.com/",
                    "expected_indicator": "200",
                }],
            })
        }
        with patch("tools.investigate._generate", new_callable=AsyncMock) as generate:
            generate.return_value = repaired
            plan, errors = await _generate_valid_plan(
                "not json",
                planner_prompt="planner context",
                provider=provider,
                scan_id="scan1",
            )
        assert errors == []
        assert plan["steps"][0]["tool"] == "coverage_probe"
        generate.assert_awaited_once()


def test_iteration_budget_honours_duration():
    budget = InvestigatorBudget(max_duration_seconds=1)
    assert _check_iteration_budget(time.monotonic() - 2, budget, 0) == "max_duration_reached"


class TestJSONParsing:
    def test_plain_json(self):
        assert _parse_json_response('{"a": 1}', "test") == {"a": 1}

    def test_code_fence(self):
        assert _parse_json_response("```json\n{\"a\": 1}\n```", "test") == {"a": 1}

    def test_brace_finding(self):
        result = _parse_json_response("some text {\n\"key\": \"value\"\n} more text", "test")
        assert result["key"] == "value"

    def test_invalid_raises(self):
        with pytest.raises(ValueError, match="Could not parse JSON"):
            _parse_json_response("not json at all", "test")


class TestFingerprint:
    def test_fingerprint_with_body_hash(self):
        finding = {
            "title": "Test",
            "category": "security",
            "endpoint": "/api/test",
            "classification": "suspicious",
            "response_body": b"some response body",
        }
        fp = _compute_fingerprint(finding)
        assert fp is not None
        assert len(fp) == 12

    def test_fingerprint_without_body(self):
        finding = {
            "title": "Test",
            "category": "security",
            "endpoint": "/api/test",
            "classification": "suspicious",
        }
        fp = _compute_fingerprint(finding)
        assert fp is not None
        assert len(fp) == 12

    def test_fingerprint_empty_finding(self):
        assert _compute_fingerprint({}) is None

    def test_fingerprint_with_string_body(self):
        finding = {
            "title": "Test",
            "category": "security",
            "endpoint": "/api/test",
            "classification": "suspicious",
            "evidence": {"body": "test body content"},
        }
        fp = _compute_fingerprint(finding)
        assert fp is not None
        assert len(fp) == 12


class TestInvestigationNoProvider:
    @pytest.mark.asyncio
    async def test_returns_completed_when_provider_disabled(self, mock_scan_state):
        with patch("tools.investigate.scan_state", mock_scan_state):
            disabled = MagicMock()
            disabled.enabled = False
            disabled.id = "local"
            disabled.model = "test"
            disabled.api_key = ""
            disabled.is_local = True
            disabled.min_severity = "info"
            disabled.base_url = "http://localhost:11434"
            disabled.kind = "ollama"
            disabled.headers = {}
            disabled.options = None
            disabled.model_failover = []

            state = await run_investigation(
                scan_id="scan1",
                target="http://example.com",
                endpoints=[],
                findings=[],
                provider=disabled,
            )
            assert state.status == "completed"
            assert state.stop_reason == "disabled"


class TestInvestigationEmptyEndpoints:
    @pytest.mark.asyncio
    async def test_returns_completed_when_no_endpoints(self, mock_scan_state):
        with patch("tools.investigate.scan_state", mock_scan_state):
            p = MagicMock()
            p.enabled = True
            p.id = "test"
            p.model = "m"
            p.api_key = "k"
            p.is_local = False
            p.min_severity = "info"
            p.base_url = "http://x"
            p.kind = "openai"
            p.headers = {}
            p.options = None
            p.model_failover = []

            state = await run_investigation(
                scan_id="scan1",
                target="http://example.com",
                endpoints=[],
                findings=[],
                provider=p,
            )
            assert state.status == "completed"
            assert state.stop_reason == "no_targets"


class TestRealBuiltinRunnerPath:
    @pytest.mark.asyncio
    async def test_investigation_executes_builtin_async_runner(self, mock_scan_state):
        """The loop must execute the registered function, not require .run()."""
        provider = MagicMock()
        provider.enabled = True
        provider.id = "test"
        provider.model = "test-model"
        provider.api_key = "key"
        provider.is_local = False
        provider.min_severity = "info"
        provider.base_url = "http://provider"
        provider.kind = "openai"
        provider.headers = {}
        provider.options = None
        provider.model_failover = []

        planner = json.dumps({
            "hypotheses": [{"id": "H1", "title": "Coverage"}],
            "steps": [{
                "id": "S1", "hypothesis_id": "H1", "tool": "coverage_probe",
                "method": "GET", "url": "https://api.example.com/",
                "expected_indicator": "response recorded",
            }],
        })
        adjudicator = json.dumps({
            "adjudication": "no issue",
            "hypothesis_updates": {"H1": "inconclusive"},
            "new_fingerprints": ["fp1"],
            "repeat_fingerprints": [],
        })

        async def fake_generate(prompt, provider, scan_id=""):
            return {"text": planner if "investigation planner" in prompt else adjudicator}

        with patch("tools.investigate.scan_state", mock_scan_state), \
             patch("tools.investigate._generate", fake_generate), \
             patch("tools.investigate.run_coverage_probe", new_callable=AsyncMock) as probe:
            probe.return_value = []
            state = await run_investigation(
                scan_id="builtin-runner-test",
                target="https://api.example.com",
                endpoints=[{"method": "GET", "url": "https://api.example.com/"}],
                findings=[],
                provider=provider,
                budget=InvestigatorBudget(max_iterations=1, max_total_tool_calls=10),
            )

        assert state.status == "partial"
        assert state.total_tool_calls == 1
        probe.assert_awaited_once()


class TestStopConditions:
    @pytest.mark.asyncio
    async def test_stop_when_all_hypotheses_resolved(self, mock_scan_state):
        """Stop when adjudicator confirms all hypotheses in a single iteration."""
        with patch("tools.investigate.scan_state", mock_scan_state):
            p = MagicMock()
            p.enabled = True
            p.id = "test"
            p.model = "m"
            p.api_key = "k"
            p.is_local = False
            p.min_severity = "info"
            p.base_url = "http://x"
            p.kind = "openai"
            p.headers = {}
            p.options = None
            p.model_failover = []

            async def fake_generate(prompt, provider, scan_id=""):
                if "planner" in prompt.lower():
                    return {
                        "text": json.dumps({
                            "hypotheses": [{"id": "H1", "title": "Test", "target_endpoint": "/api/test"}],
                            "plan": {"steps": [
                                {"id": "S1", "hypothesis_id": "H1", "tool": "coverage_probe",
                                 "method": "GET", "url": "http://example.com/api/test", "params": {}, "expected_indicator": "200"}
                            ]}
                        }),
                        "model": "test",
                    }
                else:
                    # Confirms hypothesis immediately -> all_hypotheses_resolved
                    return {
                        "text": json.dumps({
                            "adjudication": "supported",
                            "hypothesis_updates": {"H1": "supported"},
                            "new_fingerprints": ["fp1"],
                            "repeat_fingerprints": [],
                        }),
                        "model": "test",
                    }

            with patch("tools.investigate._generate", fake_generate):
                with patch("tools.investigate.run_coverage_probe", new_callable=AsyncMock) as mock_probe:
                    mock_probe.return_value = [{"id": "f1", "title": "test"}]

                    budget = InvestigatorBudget(max_iterations=5, max_total_tool_calls=10, max_tool_calls_per_iteration=2)

                    state = await run_investigation(
                        scan_id="scan1",
                        target="http://example.com",
                        endpoints=[{"method": "GET", "url": "http://example.com/api/test", "status": 200}],
                        findings=[_sample_finding()],
                        provider=p,
                        budget=budget,
                    )

                    assert state.status == "partial"
                    assert state.stop_reason == "no_new_evidence"
                    assert len(state.iterations) >= 1

    @pytest.mark.asyncio
    async def test_stop_when_no_new_fingerprints_twice(self, mock_scan_state):
        with patch("tools.investigate.scan_state", mock_scan_state):
            p = MagicMock()
            p.enabled = True
            p.id = "test"
            p.model = "m"
            p.api_key = "k"
            p.is_local = False
            p.min_severity = "info"
            p.base_url = "http://x"
            p.kind = "openai"
            p.headers = {}
            p.options = None
            p.model_failover = []

            adj_calls = 0

            async def fake_generate(prompt, provider, scan_id=""):
                nonlocal adj_calls
                if "planner" in prompt.lower():
                    return {
                        "text": json.dumps({
                            "hypotheses": [{"id": "H1", "title": "Test", "target_endpoint": "/api/test"}],
                            "plan": {"steps": [
                                {"id": "S1", "hypothesis_id": "H1", "tool": "coverage_probe",
                                 "method": "GET", "url": "http://example.com/api/test", "params": {}, "expected_indicator": "200"}
                            ]}
                        }),
                        "model": "test",
                    }
                else:
                    adj_calls += 1
                    if adj_calls >= 2:
                        return {
                            "text": json.dumps({
                                "adjudication": "no new evidence",
                                "hypothesis_updates": {},
                                "new_fingerprints": [],
                                "repeat_fingerprints": ["fp1"],
                            }),
                            "model": "test",
                        }
                    return {
                        "text": json.dumps({
                            "adjudication": "found something",
                            "hypothesis_updates": {"H1": "needs_review"},
                            "new_fingerprints": ["fp1", "fp2"],
                            "repeat_fingerprints": [],
                        }),
                        "model": "test",
                    }

            with patch("tools.investigate._generate", fake_generate):
                with patch("tools.investigate.run_coverage_probe", new_callable=AsyncMock) as mock_probe:
                    mock_probe.return_value = [{"id": "f1", "title": "test"}]

                    budget = InvestigatorBudget(max_iterations=5, max_total_tool_calls=20, max_tool_calls_per_iteration=5)

                    state = await run_investigation(
                        scan_id="scan1",
                        target="http://example.com",
                        endpoints=[{"method": "GET", "url": "http://example.com/api/test", "status": 200}],
                        findings=[_sample_finding()],
                        provider=p,
                        budget=budget,
                    )

                    assert state.status == "partial"
                    assert state.stop_reason == "no_new_evidence"
                    assert len(state.iterations) >= 2


class TestInvestigationWithFindings:
    @pytest.mark.asyncio
    async def test_generates_hypotheses_and_iterations(self, mock_scan_state):
        mock_scan_state.get_scan = AsyncMock(return_value=MagicMock(
            target="http://example.com",
            allow_mutating=False,
            status="completed",
        ))
        mock_scan_state.get_results = AsyncMock(return_value={
            "findings": [_sample_finding()],
            "endpoints": [{"method": "GET", "url": "http://example.com/api/users/1", "status": 403}],
            "schema": {},
            "tool_health": {},
        })

        plan_calls = 0

        async def fake_generate(prompt, provider, scan_id=""):
            nonlocal plan_calls
            plan_calls += 1
            if "planner" in prompt.lower():
                return {
                    "text": json.dumps({
                        "hypotheses": [
                            {"id": "H1", "title": "Broken Auth", "target_endpoint": "/api/users/1"}
                        ],
                        "plan": {
                            "steps": [
                                {
                                    "id": "S1",
                                    "hypothesis_id": "H1",
                                    "tool": "coverage_probe",
                                    "method": "GET",
                                    "url": "http://example.com/api/users/1",
                                    "params": {},
                                    "expected_indicator": "403",
                                }
                            ]
                        }
                    }),
                    "model": "test",
                }
            else:
                return {
                    "text": json.dumps({
                        "adjudication": "suspected",
                        "hypothesis_updates": {"H1": "needs_review"},
                        "new_fingerprints": ["fp1"],
                        "repeat_fingerprints": [],
                    }),
                    "model": "test",
                }

        with patch("tools.investigate.scan_state", mock_scan_state):
            with patch("tools.investigate.get_active_provider") as mock_get_provider:
                provider = MagicMock()
                provider.enabled = True
                provider.id = "test"
                provider.model = "m"
                provider.api_key = "k"
                provider.is_local = False
                provider.min_severity = "info"
                provider.base_url = "http://x"
                provider.kind = "openai"
                provider.headers = {}
                provider.options = None
                provider.model_failover = []
                mock_get_provider.return_value = provider

                with patch("tools.investigate._generate", fake_generate):
                    with patch("tools.investigate.run_coverage_probe", new_callable=AsyncMock) as mock_probe:
                        mock_probe.return_value = []

                        budget = InvestigatorBudget(
                            max_iterations=2,
                            max_total_tool_calls=10,
                            max_tool_calls_per_iteration=2,
                        )

                        state = await run_investigation(
                            scan_id="scan1",
                            target="http://example.com",
                            endpoints=[{"method": "GET", "url": "http://example.com/api/users/1", "status": 403}],
                            findings=[_sample_finding()],
                            provider=provider,
                            budget=budget,
                        )

                        assert state.status == "partial"
                        assert state.total_tool_calls >= 0
                        assert len(state.iterations) <= 2
                        assert len(state.hypotheses) >= 1


class TestArtifactPersistence:
    @pytest.mark.asyncio
    async def test_saves_artifacts(self, mock_scan_state):
        with patch("tools.investigate.scan_state", mock_scan_state):
            p = MagicMock()
            p.enabled = True
            p.id = "test"
            p.model = "m"
            p.api_key = "k"
            p.is_local = False
            p.min_severity = "info"
            p.base_url = "http://x"
            p.kind = "openai"
            p.headers = {}
            p.options = None
            p.model_failover = []

            call_count = 0

            async def fake_generate(prompt, provider, scan_id=""):
                nonlocal call_count
                call_count += 1
                if "plan" in prompt.lower():
                    return {
                        "text": json.dumps({
                            "hypotheses": [{"id": "H1", "title": "Test", "target_endpoint": "/api/test"}],
                            "plan": {"steps": [
                                {"id": "S1", "hypothesis_id": "H1", "tool": "coverage_probe",
                                 "method": "GET", "url": "http://example.com/api/test", "params": {}, "expected_indicator": "200"}
                            ]}
                        }),
                        "model": "test",
                    }
                else:
                    return {
                        "text": json.dumps({
                            "adjudication": "ok",
                            "hypothesis_updates": {"H1": "insufficient"},
                            "new_fingerprints": [],
                            "repeat_fingerprints": [],
                        }),
                        "model": "test",
                    }

            with patch("tools.investigate._generate", fake_generate):
                with patch("tools.investigate.run_coverage_probe", new_callable=AsyncMock) as mock_probe:
                    mock_probe.return_value = []

                    budget = InvestigatorBudget(max_iterations=2, max_total_tool_calls=10, max_tool_calls_per_iteration=2)

                    with patch("tools.investigate.save_artifact") as mock_save:
                        await run_investigation(
                            scan_id="scan1",
                            target="http://example.com",
                            endpoints=[{"method": "GET", "url": "http://example.com/api/test", "status": 200}],
                            findings=[_sample_finding()],
                            provider=p,
                            budget=budget,
                        )

                        save_calls = [call[0][2] for call in mock_save.call_args_list]
                        assert "state" in save_calls
                        assert "hypotheses" in save_calls
                        assert "iterations_index" in save_calls
