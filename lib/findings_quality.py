"""Finding quality gate: classification, header grouping, CVSS, evidence, dedup.

Tools emit noisy, overlapping rows. Aggregation runs this module so the
WEB contract keeps the same finding shape while adding:

- classification: confirmed | suspicious | hardening | insufficient
- validation_status: confirmed | needs_validation | observed
- grouped header observations instead of six medium "vulns"
- evidence envelope when the tool supplied request/response facts
- CVSS only when it matches the classification
- secret redaction
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from lib.redact import redact_headers, redact_obj, secrets_from_auth

CLASS_CONFIRMED = "confirmed"
CLASS_SUSPICIOUS = "suspicious"
CLASS_HARDENING = "hardening"
CLASS_INSUFFICIENT = "insufficient"

VALIDATION_CONFIRMED = "confirmed"
VALIDATION_NEEDS = "needs_validation"
VALIDATION_OBSERVED = "observed"

_HEADER_NAME_RE = re.compile(
    r"(?i)\b(cors|content-security-policy|\bcsp\b|x-frame-options|"
    r"frame-ancestors|strict-transport-security|\bhsts\b|"
    r"x-content-type-options|nosniff|x-xss-protection|referrer-policy|"
    r"permissions-policy|security header|cookie (?:httponly|secure|expires|flags?))\b"
)

_HEADER_ID_RE = re.compile(
    r"(?i)(http_headers_|headers\.cors|csp_|hsts|content_options|"
    r"frame_options|cookie_httponly|cookie_secure|cookie_expires)"
)

_UNAUTH_RE = re.compile(
    r"(?i)(unauthenticated|accepts unauthenticated|broken authentication|"
    r"missing authorization|missing authentication)"
)

_PUBLIC_PATH_RE = re.compile(
    r"(?i)/(health|ready|readiness|live|liveness|status|version|info|"
    r"docs|redoc|swagger|openapi|favicon|login|register|oauth|token|"
    r"well-known)(/|$)"
)

_REFERENCE_URL_RE = re.compile(
    r"(?:developer\.mozilla\.org|cwe\.mitre\.org|owasp\.org|portswigger\.net/web-security)",
    re.IGNORECASE,
)

_JSONISH_CT = re.compile(r"(json|hal\+json|problem\+json)", re.IGNORECASE)
_NOT_FOUND_VALUES = {
    "not found",
    "not_found",
    "resource not found",
    "endpoint not found",
    "route not found",
    "no such resource",
    "404",
}
_NOT_FOUND_TEXT_RE = re.compile(
    r"(?i)^(?:not found|not_found|resource not found|endpoint not found|"
    r"route not found|no such resource|404)[.! ]*$"
)


def _text_of(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("category") or ""),
        str(evidence.get("id") or evidence.get("name") or evidence.get("check") or ""),
        str(evidence.get("test_name") or ""),
    ]
    return " ".join(parts)


def is_header_hardening(finding: dict[str, Any]) -> bool:
    text = _text_of(finding)
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    check_id = str(evidence.get("id") or "")
    if _HEADER_ID_RE.search(check_id) or _HEADER_ID_RE.search(text):
        # Wildcard CORS + credentials is not mere hardening.
        return not _is_dangerous_cors(finding)
    return bool(_HEADER_NAME_RE.search(text)) and "wildcard" not in text.lower()


def _is_dangerous_cors(finding: dict[str, Any]) -> bool:
    text = _text_of(finding).lower()
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    blob = json.dumps(evidence, default=str).lower()
    if "allow-origin" in blob and '"*"' in blob and "allow-credentials" in blob and "true" in blob:
        return True
    return "wildcard" in text and "credential" in text


def is_unauth_observation(finding: dict[str, Any]) -> bool:
    """Match title/check only — not category, which is often 'Missing Authorization'."""
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    blob = " ".join(
        [
            str(finding.get("title") or ""),
            str(evidence.get("id") or ""),
            str(evidence.get("name") or ""),
            str(evidence.get("check") or ""),
        ]
    )
    return bool(_UNAUTH_RE.search(blob))


def is_param_discovery(finding: dict[str, Any]) -> bool:
    tools = {str(t).lower() for t in (finding.get("source_tools") or [])}
    title = str(finding.get("title") or "").lower()
    if tools & {"arjun", "x8"}:
        return True
    return "undocumented parameter" in title


def is_public_path(endpoint: str) -> bool:
    try:
        path = urlparse(endpoint.split()[-1] if " " in endpoint else endpoint).path or "/"
    except Exception:
        path = endpoint
    if path in {"", "/"}:
        return True
    return bool(_PUBLIC_PATH_RE.search(path))


def _endpoint_for(finding: dict[str, Any], target: str) -> str:
    endpoint = str(finding.get("endpoint") or "").strip()
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    if not endpoint or _REFERENCE_URL_RE.search(endpoint):
        alt = str(evidence.get("path") or evidence.get("url") or target or "").strip()
        method = str(finding.get("repro", {}).get("method") or evidence.get("http_method") or evidence.get("method") or "").strip()
        if alt and not _REFERENCE_URL_RE.search(alt):
            return f"{method} {alt}".strip() if method and not alt.upper().startswith(method.upper()) else alt
        return target
    return endpoint


def _method_of(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    repro = finding.get("repro") if isinstance(finding.get("repro"), dict) else {}
    for value in (repro.get("method"), evidence.get("http_method"), evidence.get("method")):
        if value:
            return str(value).upper()
    endpoint = str(finding.get("endpoint") or "")
    match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", endpoint, re.IGNORECASE)
    return match.group(1).upper() if match else "GET"


def _status_of(finding: dict[str, Any]) -> str | None:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    repro = finding.get("repro") if isinstance(finding.get("repro"), dict) else {}
    for value in (
        evidence.get("response_code"),
        evidence.get("status_code"),
        evidence.get("response_status_code"),
        evidence.get("http_status"),
        repro.get("status") if str(repro.get("status", "")).isdigit() else None,
    ):
        if value not in (None, "", [], {}):
            return str(value)
    return None


def _response_bodies(finding: dict[str, Any]) -> list[str]:
    """Extract response bodies from the evidence shapes emitted by tools.

    Attack tools do not all use the same key (``response_snippet``, ``body``,
    ``raw_snippet`` and ``response`` are all in the wild), so the quality gate
    must inspect them before handing a finding to an LLM.
    """
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    bodies: list[str] = []
    for key in ("response_body", "response_snippet", "body", "raw_snippet", "response"):
        value = evidence.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, dict):
            value = value.get("body") or value.get("text") or value.get("content")
        if value not in (None, "", [], {}):
            bodies.append(value if isinstance(value, str) else json.dumps(value, default=str))
    repro = finding.get("repro") if isinstance(finding.get("repro"), dict) else {}
    for key in ("response", "response_body"):
        value = repro.get(key)
        if value not in (None, "", [], {}):
            bodies.append(value if isinstance(value, str) else json.dumps(value, default=str))
    return bodies


def is_not_found_response(finding: dict[str, Any]) -> bool:
    """Return True for a response that proves the tested resource is absent.

    Some APIs incorrectly return HTTP 200 for ``{"error":"Not found"}``.
    Treat that as scanner noise, not as a vulnerability candidate.  A real
    JSON object that merely contains a normal ``message`` field is retained.
    """
    status = _status_of(finding)
    if status in {"404", "410"}:
        return True

    for raw_body in _response_bodies(finding):
        text = raw_body.strip()
        if not text:
            continue
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        if isinstance(payload, dict):
            for key in ("error", "error_code", "error_message", "detail", "message", "status"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip().lower() in _NOT_FOUND_VALUES:
                    return True
        # Plain-text or HTML negative controls are only accepted when the
        # complete body is the marker, preventing a real response mentioning
        # “not found” from being discarded.
        if _NOT_FOUND_TEXT_RE.fullmatch(text):
            return True
        if re.search(r"(?i)<title>\s*(?:404|not found)\s*</title>", text) and len(text) <= 2048:
            return True
    return False


def _cause_key(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    return str(
        evidence.get("id")
        or evidence.get("check")
        or evidence.get("test_name")
        or finding.get("title")
        or "unknown"
    ).strip().lower()


def _fingerprint(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    payload = {
        "cause": _cause_key(finding),
        "endpoint": str(finding.get("endpoint") or ""),
        "method": _method_of(finding),
        "status": _status_of(finding),
        "check": evidence.get("id") or evidence.get("check"),
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def _has_http_evidence(finding: dict[str, Any]) -> bool:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    repro = finding.get("repro") if isinstance(finding.get("repro"), dict) else {}
    if _status_of(finding) and (
        evidence.get("response_snippet")
        or evidence.get("body")
        or evidence.get("raw_snippet")
        or repro.get("curl")
        or evidence.get("http_method")
    ):
        return True
    return bool(evidence.get("request") or evidence.get("response"))


def _cvss_for(classification: str, severity: str, finding: dict[str, Any]) -> dict[str, Any] | None:
    """Return a CVSS 3.1 object only when it is justified by classification."""
    if classification == CLASS_HARDENING:
        return {
            "version": "3.1",
            "score": 0.0,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            "reason": "Hardening observation; no demonstrated impact",
        }
    if classification == CLASS_INSUFFICIENT:
        return None
    if classification == CLASS_SUSPICIOUS:
        return {
            "version": "3.1",
            "score": 3.7,
            "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            "reason": "Suspicious behaviour; needs validation",
        }
    # confirmed — use tool CVSS if present and non-zero, else a conservative map
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    tool_cvss = evidence.get("cvss") if isinstance(evidence.get("cvss"), dict) else {}
    score = tool_cvss.get("score")
    try:
        score_f = float(score)
    except (TypeError, ValueError):
        score_f = 0.0
    if score_f > 0:
        return {
            "version": str(tool_cvss.get("version") or "3.1"),
            "score": score_f,
            "vector": tool_cvss.get("vector") or "",
            "reason": "Copied from scanner because classification is confirmed",
        }
    severity_score = {"critical": 9.1, "high": 7.5, "medium": 5.3, "low": 3.1, "info": 0.0}
    mapped = severity_score.get(severity, 0.0)
    if mapped <= 0:
        return None
    vectors = {
        "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "high": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "medium": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "low": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    }
    return {
        "version": "3.1",
        "score": mapped,
        "vector": vectors.get(severity, ""),
        "reason": "Mapped from confirmed severity; no scanner CVSS",
    }


def _cap_severity(severity: str, classification: str) -> str:
    severity = (severity or "info").lower()
    if classification == CLASS_HARDENING:
        return "info"
    if classification == CLASS_INSUFFICIENT:
        return "info" if severity in {"critical", "high", "medium"} else severity
    if classification == CLASS_SUSPICIOUS and severity in {"critical", "high"}:
        return "medium"
    return severity if severity in {"critical", "high", "medium", "low", "info"} else "info"


def _envelope(finding: dict[str, Any], *, classification: str, reason: str) -> dict[str, Any]:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    repro = finding.get("repro") if isinstance(finding.get("repro"), dict) else {}
    headers = evidence.get("headers") or evidence.get("response_headers")
    body = (
        evidence.get("response_body")
        or evidence.get("response_snippet")
        or evidence.get("body")
        or evidence.get("raw_snippet")
        or ""
    )
    request = evidence.get("request") or repro.get("curl") or ""
    return {
        "endpoint": finding.get("endpoint"),
        "method": _method_of(finding),
        "request": request,
        "status_code": _status_of(finding),
        "response_headers": redact_headers(headers) if headers else {},
        "body_preview": str(body)[:400] if body else "",
        "parameters": evidence.get("parameters") or [],
        "timestamp": datetime.now(UTC).isoformat(),
        "confidence": finding.get("confidence"),
        "classification": classification,
        "classification_reason": reason,
    }


_TITLE_PREFIX = {
    CLASS_CONFIRMED: None,
    CLASS_SUSPICIOUS: "Needs validation",
    CLASS_HARDENING: "Hardening",
    CLASS_INSUFFICIENT: "Insufficient evidence",
}
_CATEGORY = {
    CLASS_CONFIRMED: "Confirmed",
    CLASS_SUSPICIOUS: "Needs validation",
    CLASS_HARDENING: "Hardening",
    CLASS_INSUFFICIENT: "Insufficient evidence",
}
_TOOL_PREFIX = re.compile(
    r"^\[(?:vulnapi|offat|authprobe|schemathesis|x8|arjun|blind)\]\s*",
    re.IGNORECASE,
)
_CLASS_PREFIX = re.compile(
    r"^(?:needs validation|insufficient evidence|hardening|confirmed):\s*",
    re.IGNORECASE,
)


def _core_title(title: str) -> str:
    text = _TOOL_PREFIX.sub("", str(title or "").strip())
    text = _CLASS_PREFIX.sub("", text)
    return text.strip() or str(title or "Finding")


def present_finding(item: dict[str, Any], classification: str, reason: str) -> dict[str, Any]:
    """Rewrite title/category/summary so the finding is honest on its own.

    Any consumer (REST, MCP, markdown, zip) should be able to tell confirmed
    vulns from hardening and from 'needs validation' without extra UI logic.
    """
    core = _core_title(str(item.get("title") or "Finding"))
    prefix = _TITLE_PREFIX.get(classification)
    item["title"] = f"{prefix}: {core}" if prefix else core
    if classification != CLASS_CONFIRMED:
        item["category"] = _CATEGORY.get(classification) or item.get("category") or "API finding"
    evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
    evidence["summary"] = reason
    evidence["description"] = reason
    evidence["classification"] = classification
    if classification != CLASS_CONFIRMED:
        evidence["status"] = item.get("validation_status") or VALIDATION_NEEDS
    item["evidence"] = evidence
    repro = item.get("repro") if isinstance(item.get("repro"), dict) else {}
    repro["note"] = reason
    repro["status"] = str(item.get("validation_status") or VALIDATION_NEEDS)
    item["repro"] = {str(k): str(v) for k, v in repro.items()}
    return item


def _group_headers(header_findings: list[dict[str, Any]], target: str) -> dict[str, Any] | None:
    if not header_findings:
        return None
    names: list[str] = []
    tools: list[str] = []
    endpoints: list[str] = []
    for finding in header_findings:
        title = str(finding.get("title") or "")
        names.append(re.sub(r"^\[.*?\]\s*", "", title).strip() or title)
        for tool in finding.get("source_tools") or []:
            if tool not in tools:
                tools.append(str(tool))
        endpoint = _endpoint_for(finding, target)
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    names = list(dict.fromkeys(names))
    listed = ", ".join(names[:8])
    if len(names) > 8:
        listed += f" (+{len(names) - 8} more)"
    grouped = {
        "id": "HDR-0001",
        "title": f"Hardening: missing or weak security headers ({listed})",
        "severity": "info",
        "confidence": 0.6,
        "category": "Hardening",
        "endpoint": endpoints[0] if endpoints else target,
        "affected_endpoints": endpoints,
        "affected_count": len(endpoints),
        "source_tools": tools or ["vulnapi"],
        "classification": CLASS_HARDENING,
        "validation_status": VALIDATION_OBSERVED,
        "evidence": {
            "kind": "hardening",
            "status": "observed",
            "missing_or_weak_headers": names,
            "note": (
                "Missing CORS/CSP/HSTS/X-Frame-Options/nosniff on a JSON API is "
                "not a demonstrated vulnerability. Grouped as a single hardening "
                "observation."
            ),
        },
        "repro": {
            "note": "Inspect response headers on the JSON endpoints. No exploit PoC.",
            "status": VALIDATION_OBSERVED,
            "cvss_score": "0",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        },
        "cvss": _cvss_for(CLASS_HARDENING, "info", {}),
        "evidence_envelope": {
            "endpoint": endpoints[0] if endpoints else target,
            "method": "GET",
            "classification": CLASS_HARDENING,
            "classification_reason": "Browser/transport headers with no demonstrated impact",
        },
    }
    return present_finding(
        grouped,
        CLASS_HARDENING,
        "Browser/transport headers with no demonstrated impact on this JSON API",
    )


def classify_finding(finding: dict[str, Any], target: str) -> tuple[str, str]:
    """Return (classification, reason) for a single raw finding."""
    tools = {str(t).lower() for t in (finding.get("source_tools") or [])}
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    if "authz_probe" in tools and evidence.get("authz_compared"):
        status = str(evidence.get("response_code") or evidence.get("status_code") or "")
        reason = str(evidence.get("classification_reason") or "Comparative dual-principal access")
        if status.startswith("2") and evidence.get("object_id"):
            return CLASS_CONFIRMED, reason
        if status.startswith("2") and evidence.get("kind") == "bfla":
            if finding.get("classification") == CLASS_CONFIRMED:
                return CLASS_CONFIRMED, reason
            return CLASS_SUSPICIOUS, reason
    if is_header_hardening(finding):
        return CLASS_HARDENING, "Security-header absence without demonstrated impact"
    if _is_dangerous_cors(finding):
        if _has_http_evidence(finding):
            return CLASS_CONFIRMED, "CORS wildcard with credentials"
        return CLASS_SUSPICIOUS, "CORS wildcard/credentials reported without request evidence"
    if is_param_discovery(finding):
        return CLASS_INSUFFICIENT, "Parameter discovery is not a vulnerability"
    if is_unauth_observation(finding):
        endpoint = _endpoint_for(finding, target)
        status = _status_of(finding)
        if is_public_path(endpoint):
            return CLASS_INSUFFICIENT, "Public/documentation/health path is not broken auth"
        if status in {"400", "422"}:
            return CLASS_INSUFFICIENT, "400/422 means the handler ran, not that auth was bypassed"
        if status and status.startswith("2") and _has_http_evidence(finding) and not is_public_path(endpoint):
            # Accessible ≠ vuln unless we compared auth vs unauth.
            if finding.get("evidence", {}).get("auth_compared"):
                return CLASS_CONFIRMED, "Comparative unauth vs auth evidence"
            return CLASS_SUSPICIOUS, "Unauthenticated 2xx without a comparative baseline"
        return CLASS_INSUFFICIENT, "Unauthenticated access claimed without HTTP evidence"
    if not _has_http_evidence(finding):
        return CLASS_INSUFFICIENT, "No request/response evidence"
    if "schemathesis" in tools:
        check = str(evidence.get("check") or finding.get("title") or "").lower()
        return CLASS_SUSPICIOUS, (
            "Schemathesis conformance/fuzz check is not a confirmed vulnerability"
            if "status_code" in check or "conformance" in check or "failed" in check
            else "Schemathesis finding needs validation; not confirmed"
        )
    severity = str(finding.get("severity") or "").lower()
    if severity in {"critical", "high"} and _has_http_evidence(finding):
        return CLASS_SUSPICIOUS, "High-severity scanner hit; treat as needs validation until replayed"
    return CLASS_SUSPICIOUS, "Scanner reported a defect; evidence is incomplete for confirmation"


def normalize_findings(
    findings: list[dict[str, Any]],
    *,
    target: str,
    auth: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Quality-gate a raw finding list. Returns (normalized, summary)."""
    secrets = secrets_from_auth(auth)
    header_rows: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    discarded_not_found: list[dict[str, Any]] = []
    dropped = 0
    seen: set[str] = set()
    counts = {
        CLASS_CONFIRMED: 0,
        CLASS_SUSPICIOUS: 0,
        CLASS_HARDENING: 0,
        CLASS_INSUFFICIENT: 0,
    }

    for raw in findings:
        if not isinstance(raw, dict):
            dropped += 1
            continue
        item = redact_obj(dict(raw), secrets)
        item["endpoint"] = _endpoint_for(item, target)
        if is_not_found_response(item):
            dropped += 1
            discarded_not_found.append({
                "id": item.get("id"),
                "title": item.get("title"),
                "endpoint": item.get("endpoint"),
                "status": _status_of(item),
                "reason": "Response proves resource/route is not found",
            })
            continue
        if is_header_hardening(item):
            header_rows.append(item)
            continue
        fingerprint = _fingerprint(item)
        if fingerprint in seen:
            dropped += 1
            continue
        seen.add(fingerprint)

        classification, reason = classify_finding(item, target)
        severity = _cap_severity(str(item.get("severity") or "info"), classification)
        item["severity"] = severity
        item["classification"] = classification
        item["validation_status"] = (
            VALIDATION_CONFIRMED if classification == CLASS_CONFIRMED
            else VALIDATION_OBSERVED if classification == CLASS_HARDENING
            else VALIDATION_NEEDS
        )
        item["classification_reason"] = reason
        cvss = _cvss_for(classification, severity, item)
        if cvss:
            item["cvss"] = cvss
            repro = item.get("repro") if isinstance(item.get("repro"), dict) else {}
            repro["cvss_score"] = str(cvss.get("score", ""))
            if cvss.get("vector"):
                repro["cvss_vector"] = str(cvss["vector"])
            item["repro"] = {str(k): str(v) for k, v in repro.items()}
            evidence = item.get("evidence") if isinstance(item.get("evidence"), dict) else {}
            evidence["cvss"] = cvss
            item["evidence"] = evidence
        item["evidence_envelope"] = _envelope(item, classification=classification, reason=reason)
        present_finding(item, classification, reason)
        counts[classification] = counts.get(classification, 0) + 1
        kept.append(item)

    grouped = _group_headers(header_rows, target)
    if grouped:
        kept.insert(0, grouped)
        counts[CLASS_HARDENING] += 1
        dropped += max(0, len(header_rows) - 1)

    order = {CLASS_CONFIRMED: 0, CLASS_SUSPICIOUS: 1, CLASS_HARDENING: 2, CLASS_INSUFFICIENT: 3}
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    kept.sort(
        key=lambda f: (
            order.get(str(f.get("classification")), 9),
            sev_order.get(str(f.get("severity")), 9),
            str(f.get("id") or ""),
        )
    )
    summary = {
        "input_count": len(findings),
        "output_count": len(kept),
        "dropped_duplicates_or_noise": dropped,
        "dropped_not_found": len(discarded_not_found),
        "discarded_not_found_samples": discarded_not_found[:20],
        "grouped_header_findings": len(header_rows),
        "by_classification": counts,
    }
    return kept, summary
