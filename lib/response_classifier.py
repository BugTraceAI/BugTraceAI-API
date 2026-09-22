"""Deterministic response classification.

Before any finding is created, every HTTP response is classified as one of:

- ``success`` — semantically meaningful response that could carry data.
- ``error_application`` — HTTP 200 with error-like JSON body (e.g. ``{"error":"Not found"}``).
- ``catch_all`` — HTML equivalent to the homepage/main page.
- ``not_found`` — the resource does not exist (e.g. unknown ID).
- ``redirect`` — HTTP redirection.
- ``auth_challenge`` — 401/403 that requires credentials.
- ``empty`` — no content / 204 / 304.

The classifier uses: HTTP code, Content-Type, body hash, structure,
error markers, similarity to controls, and redirect behaviour.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("bugtrace-api.lib.response_classifier")

# Markers that indicate an application-level error regardless of HTTP code
ERROR_JSON_MARKERS = re.compile(
    r'"error"|"error_code"|"error_message"|"message"|"status"\s*:\s*"error"'
    r'|"not_found"|"not found"|"404"'
    , re.IGNORECASE
)
APP_ERROR_KEYS = {"error", "error_code", "error_message", "message", "status", "detail"}


@dataclass
class ClassificationResult:
    category: str  # success | error_application | catch_all | not_found | redirect | auth_challenge | empty
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)
    is_reliable: bool = True  # False if the classification is uncertain

    def is_confirmed_vulnerable(self) -> bool:
        """Only 'success' with high confidence can feed a real finding."""
        return self.category == "success" and self.confidence >= 0.7


class ResponseClassifier:
    """Classifies HTTP responses against known controls."""

    def __init__(
        self,
        baseline_status: int = 0,
        baseline_length: int = 0,
        baseline_hash: str = "",
        catch_all_hash: str = "",
        catch_all_status: int = 0,
    ):
        self.baseline_status = baseline_status
        self.baseline_length = baseline_length
        self.baseline_hash = baseline_hash
        self.catch_all_hash = catch_all_hash
        self.catch_all_status = catch_all_status

    def classify(
        self,
        status_code: int,
        content_type: str,
        body: bytes | str,
        url: str,
        *,
        redirect_url: str | None = None,
        control_not_found_status: int = 404,
        control_not_found_hash: str = "",
    ) -> ClassificationResult:
        """Classify a single HTTP response."""
        if isinstance(body, bytes):
            body_text = body.decode("utf-8", errors="replace")
        else:
            body_text = body

        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        body_hash = hashlib.sha256(body_bytes).hexdigest()[:16]
        normalized_body = self._normalize_body(body_text, content_type)

        evidence = {
            "status_code": status_code,
            "content_type": content_type,
            "body_hash": body_hash,
            "body_length": len(body_bytes),
            "normalized_body": normalized_body[:200] if len(normalized_body) > 200 else normalized_body,
            "url": url,
        }

        # 1. Redirect
        if status_code in (301, 302, 303, 307, 308):
            return ClassificationResult(
                category="redirect",
                confidence=0.9,
                evidence={**evidence, "redirect_url": redirect_url},
            )

        # 2. Auth challenge
        if status_code in (401, 403):
            return ClassificationResult(
                category="auth_challenge",
                confidence=0.9,
                evidence=evidence,
            )

        # 3. Empty
        if status_code in (204, 304) or not body_text.strip():
            return ClassificationResult(category="empty", confidence=0.95, evidence=evidence)

        # 4. Check if it's a catch-all (HTML matching homepage)
        if self._is_html(content_type) and self._is_catch_all(body_text, body_hash):
            return ClassificationResult(
                category="catch_all",
                confidence=0.85,
                evidence=evidence,
            )

        # 5. Check for application-level error despite 200
        if status_code == 200 and self._looks_like_error_json(body_text, content_type):
            return ClassificationResult(
                category="error_application",
                confidence=0.9,
                evidence=evidence,
            )

        # 6. Not found (e.g. impossible ID)
        if status_code == control_not_found_status and body_hash == control_not_found_hash:
            return ClassificationResult(category="not_found", confidence=0.9, evidence=evidence)

        # 7. Success — but validate it's not a false positive
        if status_code == 200:
            if self._is_application_json(content_type):
                return ClassificationResult(category="success", confidence=0.8, evidence=evidence)
            if self._has_meaningful_content(body_text, content_type):
                return ClassificationResult(category="success", confidence=0.75, evidence=evidence)
            return ClassificationResult(category="success", confidence=0.5, evidence=evidence)

        # 8. Default: treat as success for 2xx codes
        if 200 <= status_code < 300:
            return ClassificationResult(category="success", confidence=0.6, evidence=evidence)

        return ClassificationResult(category="unknown", confidence=0.3, evidence=evidence)

    def compare_responses(
        self,
        responses: list[dict],
    ) -> list[dict]:
        """Compare multiple responses and return their differences."""
        differences: list[dict] = []
        for i, resp in enumerate(responses):
            diff = {
                "index": i,
                "status_code": resp.get("status_code"),
                "body_hash": resp.get("body_hash", ""),
                "content_type": resp.get("content_type", ""),
                "body_length": resp.get("body_length", 0),
                "normalized_body": resp.get("normalized_body", ""),
                "category": resp.get("category", "unknown"),
            }
            differences.append(diff)
        return differences

    # ── Internal helpers ──────────────────────────────────────────

    def _is_html(self, content_type: str) -> bool:
        return "text/html" in content_type or "application/xhtml+xml" in content_type

    def _is_catch_all(self, body_text: str, body_hash: str) -> bool:
        if self.catch_all_hash and body_hash == self.catch_all_hash:
            return True
        # Look for SPA shell indicators
        if "id=\"app\"" in body_text or "id=\"root\"" in body_text:
            return True
        if "<div id=" in body_text and '<script src=' in body_text:
            return True
        return False

    def _looks_like_error_json(self, body_text: str, content_type: str) -> bool:
        if not self._is_application_json(content_type) and "json" not in content_type:
            return False
        try:
            data = json.loads(body_text)
        except (json.JSONDecodeError, ValueError):
            return False
        if not isinstance(data, dict):
            return False
        error_keys = APP_ERROR_KEYS & set(data.keys())
        if error_keys:
            return True
        # Check body text markers
        if ERROR_JSON_MARKERS.search(body_text):
            return True
        return False

    def _is_application_json(self, content_type: str) -> bool:
        return "application/json" in content_type

    def _has_meaningful_content(self, body_text: str, content_type: str) -> bool:
        if self._is_application_json(content_type):
            try:
                data = json.loads(body_text)
                if isinstance(data, dict) and data:
                    return True
                if isinstance(data, list) and data:
                    return True
            except (json.JSONDecodeError, ValueError):
                return False
        # Non-JSON: check if it's substantial text
        stripped = body_text.strip()
        return len(stripped) > 50 and "<html" not in stripped[:20].lower()

    def _normalize_body(self, body_text: str, content_type: str) -> str:
        if self._is_application_json(content_type):
            try:
                data = json.loads(body_text)
                return json.dumps(data, sort_keys=True, ensure_ascii=False)
            except (json.JSONDecodeError, ValueError):
                return body_text
        return body_text


def build_controls(
    known_routes: list[dict],
    target: str,
    auth: dict | None = None,
) -> dict:
    """Build the set of control references needed for classification.

    - A route that is known and valid.
    - A route that is guaranteed not to exist.
    - An impossible identifier.
    - The exact variant the tool wants to test.
    """
    controls: dict[str, Any] = {
        "known_route": _pick_known_route(known_routes),
        "not_found_route": f"{target.rstrip('/')}/__bt_nonexistent_xyz_12345",
        "impossible_id": "0" * 32,
    }
    return controls


def _pick_known_route(endpoints: list[dict]) -> dict | None:
    """Pick a known real route to use as a control."""
    for ep in endpoints:
        if ep.get("status") is not None and ep["status"] < 400:
            return ep
    return endpoints[0] if endpoints else None
