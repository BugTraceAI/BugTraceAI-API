"""Auth-header / CLI-arg builders shared by every tool wrapper.

Centralises the "bearer vs basic" branching that was duplicated in six places
(discovery.py, blind_attack.py, schema_attack.py, schema_probe.py, evidence.py,
auth_probe.py) and makes it impossible for one tool to forget to support a
new auth kind (e.g. "cookie") — you change it here, every tool gets it.
"""
from __future__ import annotations

from typing import Any


def auth_header(auth: dict[str, Any] | None) -> str | None:
    """Return a single ``Authorization`` header value or ``None``.

    Recognised kinds for this helper: ``bearer`` and ``basic``. Cookie and
    API-key auth live on :func:`auth_headers_dict` because they are not
    Authorization values. Missing/unknown kinds return None.
    """
    if not auth:
        return None
    kind = (auth.get("type") or "").lower()
    token = auth.get("token") or auth.get("value") or ""
    if not token:
        return None
    if kind == "bearer":
        return f"Bearer {token}"
    if kind == "basic":
        return f"Basic {token}"
    return None


def auth_headers_dict(auth: dict[str, Any] | None) -> dict[str, str]:
    """Return headers for httpx-based callers. Never mutates input.

    Recognised kinds: ``bearer``, ``basic``, ``cookie``, ``api_key`` /
    ``header``. Optional ``headers`` map is merged last.
    """
    if not auth:
        return {}
    headers: dict[str, str] = {}
    kind = (auth.get("type") or "").lower()
    token = str(auth.get("token") or auth.get("value") or "")
    if kind == "bearer" and token:
        headers["Authorization"] = f"Bearer {token}"
    elif kind == "basic" and token:
        headers["Authorization"] = f"Basic {token}"
    elif kind == "cookie" and token:
        cookie_name = str(auth.get("name") or auth.get("cookie") or "")
        headers["Cookie"] = f"{cookie_name}={token}" if cookie_name and "=" not in token else token
    elif kind in {"api_key", "apikey", "header"} and token:
        header_name = str(auth.get("header") or auth.get("name") or "X-API-Key")
        headers[header_name] = token
    extra = auth.get("headers")
    if isinstance(extra, dict):
        for key, value in extra.items():
            if key and value is not None:
                headers[str(key)] = str(value)
    return headers


def auth_cli_flag(auth: dict[str, Any] | None) -> list[str]:
    """Return curl-style ``-H`` flags for every configured auth header.

    Empty list when no auth — append the result directly to ``cmd``.
    """
    flags: list[str] = []
    for name, value in auth_headers_dict(auth).items():
        flags.extend(["-H", f"{name}: {value}"])
    return flags
