"""Tests for orchestrator integration with new phases."""
import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestOrchestratorCampaignIntegration:
    """Test that orchestrator passes campaigns to investigation."""

    @pytest.mark.asyncio
    async def test_phase_investigation_passes_campaigns(self):
        """_phase_investigation should load and pass campaigns to run_investigation."""
        from orchestrator import Orchestrator

        orch = Orchestrator()

        mock_state = MagicMock()
        mock_state.get_results = AsyncMock(return_value={
            "findings": [{"title": "Test finding", "category": "bola"}],
            "endpoints": [{"url": "https://api.example.com/users"}],
            "schema": None,
        })
        mock_state.get_scan = AsyncMock(return_value=None)

        mock_run = AsyncMock(return_value=MagicMock(
            hypotheses=[],
            total_tool_calls=0,
            status="completed",
            stop_reason="no_targets",
            error=None,
        ))
        with patch('orchestrator.scan_state', mock_state), \
             patch('orchestrator._run_investigation', mock_run):

            await orch._phase_investigation(
                scan_id="test-scan",
                target="https://api.example.com",
                auth={"bearer": "token"},
                allow_mutating=False,
            )

            mock_run.assert_called_once()
            call_kwargs = mock_run.call_args.kwargs
            assert "campaigns" in call_kwargs
            assert "campaign_hypotheses" in call_kwargs

    @pytest.mark.asyncio
    async def test_phase_investigation_empty_campaigns(self):
        """Should handle empty campaigns gracefully when there are no results."""
        from orchestrator import Orchestrator

        orch = Orchestrator()

        mock_state = MagicMock()
        mock_state.get_results = AsyncMock(return_value={
            "findings": [],
            "endpoints": [],
            "schema": None,
        })
        mock_state.get_scan = AsyncMock(return_value=None)

        with patch('orchestrator.scan_state', mock_state), \
             patch('orchestrator._run_investigation') as mock_run:

            await orch._phase_investigation(
                scan_id="test-scan",
                target="https://api.example.com",
            )

            mock_run.assert_not_called()


class TestCampaignGroupingInPipeline:
    """Test that campaigns are created in the pipeline."""

    @pytest.mark.asyncio
    async def test_phase_discovery_creates_campaigns(self):
        """Discovery phase should create campaigns artifact."""
        from lib.campaign_grouping import group_into_campaigns

        findings = [
            {"title": "BOLA vulnerability", "category": "access_control", "endpoint": "https://api.example.com/users/1"},
            {"title": "BOLA on orders", "category": "access_control", "endpoint": "https://api.example.com/orders/1"},
        ]

        campaigns = group_into_campaigns(findings)

        assert "bola" in campaigns
        assert len(campaigns["bola"]) == 2

    @pytest.mark.asyncio
    async def test_campaign_hypotheses_pre_computed(self):
        """Campaign hypotheses should be pre-computed in discovery."""
        from lib.campaign_grouping import (
            group_into_campaigns,
            campaigns_to_hypotheses,
        )

        findings = [
            {"title": "BOLA on /api/users", "category": "access_control", "classification": "suspicious"},
            {"title": "Auth bypass on /admin", "category": "authentication", "classification": "high_risk"},
        ]

        campaigns = group_into_campaigns(findings)
        hypotheses = campaigns_to_hypotheses(campaigns, "https://api.example.com", [])

        assert len(hypotheses) >= 1
        assert all(h.get("id", "").startswith("H") for h in hypotheses)


class TestEndToEndFlow:
    """Test the complete flow from findings to investigation."""

    @pytest.mark.asyncio
    async def test_findings_to_campaigns_to_hypotheses(self):
        """Full flow: findings → campaigns → hypotheses → investigation."""
        from lib.campaign_grouping import (
            group_into_campaigns,
            campaigns_to_hypotheses,
        )
        from tools.investigate import run_investigation

        raw_findings = [
            {"title": f"BOLA variant {i}", "category": "access_control"}
            for i in range(10)
        ]

        campaigns = group_into_campaigns(raw_findings)
        assert "bola" in campaigns
        assert len(campaigns["bola"]) == 10

        hypotheses = campaigns_to_hypotheses(campaigns, "https://api.example.com", [])
        assert len(hypotheses) <= 3

        with patch('tools.investigate.get_active_provider') as mock_provider:
            mock_provider.return_value.enabled = False

            state = await run_investigation(
                scan_id="e2e-test",
                target="https://api.example.com",
                endpoints=[],
                findings=[],
                campaigns=campaigns,
                campaign_hypotheses=hypotheses,
            )

            assert state.status in ("completed", "disabled")


@pytest.mark.asyncio
async def test_pipeline_renders_report_after_investigation(scan_state):
    """The final report phases must consume autonomous-investigation output."""
    from orchestrator import Orchestrator

    orch = Orchestrator()
    await scan_state.create_scan("ordered-scan", "https://api.example.com")
    events = []

    async def phase_discovery(*args, **kwargs):
        events.append("discovery")

    async def phase_schema(*args, **kwargs):
        events.append("schema")

    async def phase_attacks(*args, **kwargs):
        events.append("attacks")

    async def phase_aggregation(*args, **kwargs):
        events.append("aggregation")

    async def phase_investigation(*args, **kwargs):
        events.append("investigation")

    async def phase_apex(*args, **kwargs):
        events.append("report")

    with patch.object(orch, "_phase_discovery", side_effect=phase_discovery), \
         patch.object(orch, "_phase_schema_probe", side_effect=phase_schema), \
         patch.object(orch, "_phase_attacks", side_effect=phase_attacks), \
         patch.object(orch, "_phase_aggregation", side_effect=phase_aggregation), \
         patch.object(orch, "_phase_investigation", side_effect=phase_investigation), \
         patch.object(orch, "_phase_apex_analysis", side_effect=phase_apex):
        await orch._run_pipeline("ordered-scan", "https://api.example.com", "standard")

    assert events == [
        "discovery", "schema", "attacks", "aggregation",
        "investigation", "aggregation", "report",
    ]
