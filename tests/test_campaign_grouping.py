"""Tests for campaign grouping module."""
import pytest
from lib.campaign_grouping import (
    group_into_campaigns,
    campaigns_to_hypotheses,
    summarize_campaigns,
    CAMPAIGN_BOLA,
    CAMPAIGN_BFLA,
    CAMPAIGN_AUTH_BYPASS,
    CAMPAIGN_UNKNOWN,
)


def test_group_bola_findings():
    """BOLA-related findings should group together."""
    findings = [
        {"title": "BOLA on /api/users/1", "category": "access_control"},
        {"title": "BOLA on /api/orders/1", "category": "access_control"},
    ]
    campaigns = group_into_campaigns(findings)
    assert CAMPAIGN_BOLA in campaigns
    assert len(campaigns[CAMPAIGN_BOLA]) >= 2


def test_group_auth_bypass_findings():
    """Auth bypass findings should group together."""
    findings = [
        {"title": "Unauthenticated access to /api/admin", "category": "authentication"},
        {"title": "Missing authorization header", "category": "authentication"},
    ]
    campaigns = group_into_campaigns(findings)
    assert CAMPAIGN_AUTH_BYPASS in campaigns


def test_unknown_campaign_for_unmatched_findings():
    """Findings that don't match known patterns go to unknown."""
    findings = [
        {"title": "Some random finding", "category": "general"},
    ]
    campaigns = group_into_campaigns(findings)
    assert CAMPAIGN_UNKNOWN in campaigns


def test_campaigns_to_hypotheses():
    """Convert campaigns to hypotheses."""
    campaigns = {
        CAMPAIGN_BOLA: [
            {"title": "BOLA on users", "classification": "suspicious"},
        ],
        CAMPAIGN_UNKNOWN: [
            {"title": "Unknown finding", "classification": "insufficient"},
        ],
    }
    hypotheses = campaigns_to_hypotheses(campaigns, "https://api.example.com", [])
    assert len(hypotheses) >= 2
    assert all(h.get("id", "").startswith("H") for h in hypotheses)
    assert all(0 <= h.get("confidence", 0) <= 1 for h in hypotheses)


def test_summarize_campaigns():
    """Summarize campaign stats."""
    campaigns = {
        CAMPAIGN_BOLA: [{"title": "BOLA"}],
        CAMPAIGN_UNKNOWN: [{"title": "Unknown"}],
    }
    summary = summarize_campaigns(campaigns)
    assert summary["total_campaigns"] == 2
    assert summary["total_findings"] == 2


def test_multiple_tool_findings_deduplication():
    """Simulate 28 offat variants reducing to fewer campaigns."""
    # Simulate what would happen with many similar offat BOLA findings
    findings = []
    for i in range(28):
        findings.append({
            "title": f"BOLA variant {i}",
            "category": "access_control",
            "endpoint": f"https://api.example.com/api/users/{i}",
            "source_tools": ["offat"],
        })
    
    campaigns = group_into_campaigns(findings)
    assert CAMPAIGN_BOLA in campaigns
    # All should be grouped into one campaign
    assert len(campaigns[CAMPAIGN_BOLA]) == 28
    
    hypotheses = campaigns_to_hypotheses(campaigns, "https://api.example.com", [])
    # Should reduce to ~1-2 hypotheses instead of 28
    assert len(hypotheses) <= 3


def test_empty_findings():
    """Empty findings should produce empty campaigns."""
    campaigns = group_into_campaigns([])
    assert len(campaigns) == 0
