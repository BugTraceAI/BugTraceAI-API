"""Redact secrets from logs, findings, evidence, and reports.

Tokens must never appear in scan artifacts. This module is conservative:
header names that look like credentials are stripped to ``***``, and known
token-shaped values in text are masked.
"""
from __future__ import annotations

import re
from typing import Any

_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-api-token",
    "api-key",
    "api_key",
    "x-auth-token",
    "x-access-token",
    "x-csrf-token",
    "x-session-token",
}

# Do not treat "token: GET" (HTTP method after the word token) as a secret.
_TOKENISH = re.compile(
    r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*"
    r"|((?:api[_-]?key|secret|password)\s*[:=]\s*)([^\s,;\"']+)"
    r"|(\btoken\s*[:=]\s*)(?!GET\b|POST\b|PUT\b|PATCH\b|DELETE\b|HEAD\b|OPTIONS\b)([A-Za-z0-9\-._~+/]{8,})"
)


def is_sensitive_header(name: str) -> bool:
    lowered = name.strip().lower()
    if lowered in _SENSITIVE_HEADER_NAMES:
        return True
    return "api-key" in lowered or "api_key" in lowered or lowered.endswith("-token")


def redact_headers(headers: Any) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    redacted: dict[str, str] = {}
    for key, value in headers.items():
        name = str(key)
        if is_sensitive_header(name):
            redacted[name] = "***"
        else:
            redacted[name] = redact_text(str(value))
    return redacted


def redact_text(text: str, extra_secrets: list[str] | None = None) -> str:
    if not text:
        return text
    out = _TOKENISH.sub(_mask_tokenish, text)
    for secret in extra_secrets or []:
        if secret and len(secret) >= 4:
            out = out.replace(secret, "***")
    return out


def _mask_tokenish(match: re.Match[str]) -> str:
    if match.group(1):
        return f"{match.group(1)}***"
    if match.group(2):
        return f"{match.group(2)}***"
    if match.group(4):
        return f"{match.group(4)}***"
    return "***"


def secrets_from_auth(auth: dict[str, Any] | None) -> list[str]:
    if not isinstance(auth, dict):
        return []
    secrets: list[str] = []
    for key in ("token", "api_key", "value", "cookie"):
        value = auth.get(key)
        if isinstance(value, str) and value.strip():
            secrets.append(value.strip())
    return secrets


def redact_obj(value: Any, extra_secrets: list[str] | None = None) -> Any:
    """Recursively redact headers and token-shaped strings in a JSON-like object."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, inner in value.items():
            if is_sensitive_header(str(key)):
                out[key] = "***"
            elif str(key).lower() in {"token", "api_key", "password", "secret", "authorization"}:
                out[key] = "***" if inner else inner
            else:
                out[key] = redact_obj(inner, extra_secrets)
        return out
    if isinstance(value, list):
        return [redact_obj(item, extra_secrets) for item in value]
    if isinstance(value, str):
        return redact_text(value, extra_secrets)
    return value
