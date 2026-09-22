"""Group findings into investigation campaigns based on vulnerability class.

Instead of investigating every finding individually, related findings are
grouped into campaigns. Each campaign becomes one hypothesis in the
investigation engine.
"""
from __future__ import annotations

import hashlib
from typing import Any

# Campaign categories
CAMPAIGN_BOLA = "bola"
CAMPAIGN_BFLA = "bfla"
CAMPAIGN_AUTH_BYPASS = "auth_bypass"
CAMPAIGN_MASS_ASSIGNMENT = "mass_assignment"
CAMPAIGN_OPEN_REDIRECT = "open_redirect"
CAMPAIGN_SSRF = "ssrf"
CAMPAIGN_HEADER_HARDENING = "header_hardening"
CAMPAIGN_CATCH_ALL = "catch_all"
CAMPAIGN_PARAM_DISCOVERY = "param_discovery"
CAMPAIGN_GRAPHQL = "graphql"
CAMPAIGN_UNKNOWN = "unknown"

CAMPAIGN_PATTERNS: list[tuple[str, list[str]]] = [
    (CAMPAIGN_BOLA, ["identifier", "independent", "access", "object", "resource", "ownership", "bola"]),
    (CAMPAIGN_BFLA, ["admin", "role", "privilege", "authority", "bfla"]),
    (CAMPAIGN_AUTH_BYPASS, ["unauthenticated", "missing auth", "no token", "authorization", "auth bypass"]),
    (CAMPAIGN_MASS_ASSIGNMENT, ["mass assign", "overflow", "property", "field injection"]),
    (CAMPAIGN_OPEN_REDIRECT, ["redirect", "open redirect", "url param"]),
    (CAMPAIGN_SSRF, ["ssrf", "server side", "request forgery"]),
    (CAMPAIGN_HEADER_HARDENING, ["header", "csp", "cors", "hsts", "security header"]),
    (CAMPAIGN_PARAM_DISCOVERY, ["undocumented", "parameter", "arjun", "x8"]),
    (CAMPAIGN_CATCH_ALL, ["catch-all", "not found", "generic error"]),
]


def normalize_signal(findings: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """Normalize and deduplicate scanner signals before campaign grouping.

    Scanner tools often emit the same response under different field names or
    with an empty placeholder endpoint.  Keep the first complete record for a
    stable signal and merge useful source-tool metadata from duplicates.
    """
    normalized: list[dict[str, Any]] = []
    by_key: dict[str, dict[str, Any]] = {}
    for raw in findings or []:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        endpoint = str(item.get("endpoint") or item.get("url") or "").strip()
        title = str(item.get("title") or item.get("name") or "").strip()
        category = str(item.get("category") or item.get("type") or "general").strip().lower()
        item["endpoint"] = endpoint
        item["title"] = title or category
        item["category"] = category
        source_tools = item.get("source_tools") or item.get("sources") or []
        if isinstance(source_tools, str):
            source_tools = [source_tools]
        item["source_tools"] = list(dict.fromkeys(str(s) for s in source_tools if s))
        key = hashlib.sha256(
            "|".join((category, title.lower(), endpoint.lower())).encode("utf-8")
        ).hexdigest()[:16]
        if key not in by_key:
            item["signal_fingerprint"] = key
            by_key[key] = item
            normalized.append(item)
            continue
        existing = by_key[key]
        existing["source_tools"] = list(dict.fromkeys(
            existing.get("source_tools", []) + item["source_tools"]
        ))
        if item.get("evidence") and not existing.get("evidence"):
            existing["evidence"] = item["evidence"]
        if item.get("severity") in {"critical", "high"} and existing.get("severity") not in {"critical"}:
            existing["severity"] = item["severity"]
    return normalized


def findings_to_campaigns(findings: list[dict[str, Any]] | None) -> dict[str, list[dict[str, Any]]]:
    """Normalize scanner output and group it into investigation campaigns."""
    return group_into_campaigns(normalize_signal(findings))


def generate_campaign_hypotheses(
    findings: list[dict[str, Any]] | None,
    target: str,
    endpoints: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Convenience API used by discovery and callers outside the orchestrator."""
    return campaigns_to_hypotheses(
        findings_to_campaigns(findings), target, endpoints or []
    )


def group_into_campaigns(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group findings into campaign buckets based on category/title."""
    campaigns: dict[str, list[dict[str, Any]]] = {}

    for finding in findings:
        text = " ".join([
            str(finding.get("title") or ""),
            str(finding.get("category") or ""),
            str(finding.get("classification") or ""),
            str(finding.get("evidence", {}).get("id") or ""),
        ]).lower()

        matched = False
        for campaign, patterns in CAMPAIGN_PATTERNS:
            if any(p in text for p in patterns):
                campaigns.setdefault(campaign, []).append(finding)
                matched = True
                break
        if not matched:
            campaigns.setdefault(CAMPAIGN_UNKNOWN, []).append(finding)

    return campaigns


def campaigns_to_hypotheses(
    campaigns: dict[str, list[dict[str, Any]]],
    target: str,
    endpoints: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Convert campaigns into initial hypothesis objects for the investigation engine."""
    hypotheses = []
    for campaign, findings in campaigns.items():
        if not findings:
            continue

        # Determine category and endpoint
        category = _campaign_to_category(campaign)
        endpoint = _pick_campaign_endpoint(findings, endpoints, target)

        # Build rationale from findings
        titles = [f.get("title", "")[:80] for f in findings[:5]]
        rationale = "; ".join(titles[:3])

        # Calculate confidence
        confirmed = sum(1 for f in findings if f.get("classification") == "confirmed")
        suspicious = sum(1 for f in findings if f.get("classification") == "suspicious")
        confidence = min(1.0, (confirmed * 0.9 + suspicious * 0.5) / max(len(findings), 1))

        hypotheses.append({
            "id": f"H{len(hypotheses)+1}",
            "title": f"Potential {category.replace('_', ' ')} issue on {endpoint}",
            "category": category,
            "target_endpoint": endpoint,
            "rationale": rationale,
            "confidence": round(confidence, 2),
            "source_findings": [f.get("id", "") for f in findings[:10]],
            "finding_count": len(findings),
        })

    # Sort by confidence descending
    hypotheses.sort(key=lambda h: h["confidence"], reverse=True)
    return hypotheses


def _campaign_to_category(campaign: str) -> str:
    mapping = {
        CAMPAIGN_BOLA: "broken_access_control",
        CAMPAIGN_BFLA: "broken_access_control",
        CAMPAIGN_AUTH_BYPASS: "authentication",
        CAMPAIGN_MASS_ASSIGNMENT: "injection",
        CAMPAIGN_OPEN_REDIRECT: "validation",
        CAMPAIGN_SSRF: "injection",
        CAMPAIGN_HEADER_HARDENING: "hardening",
        CAMPAIGN_CATCH_ALL: "information_disclosure",
        CAMPAIGN_PARAM_DISCOVERY: "information_disclosure",
        CAMPAIGN_GRAPHQL: "graphql",
        CAMPAIGN_UNKNOWN: "general",
    }
    return mapping.get(campaign, "general")


def _pick_campaign_endpoint(
    findings: list[dict[str, Any]],
    endpoints: list[dict[str, Any]],
    target: str,
) -> str:
    """Pick the most representative endpoint for a campaign."""
    for f in findings:
        ep = f.get("endpoint") or f.get("evidence", {}).get("path")
        if ep and ep.startswith("http"):
            return ep
    if endpoints:
        return endpoints[0].get("url", target)
    return target


def summarize_campaigns(campaigns: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    """Generate a summary of campaign groups."""
    summary = {
        "total_campaigns": len(campaigns),
        "total_findings": sum(len(f) for f in campaigns.values()),
        "campaigns": {},
    }
    for campaign, findings in campaigns.items():
        summary["campaigns"][campaign] = {
            "count": len(findings),
            "category": _campaign_to_category(campaign),
        }
    return summary
