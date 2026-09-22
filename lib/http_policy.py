"""Safe-by-default HTTP method policy for BugTraceAI-API.

GET, HEAD and OPTIONS are always allowed. POST, PUT, PATCH and DELETE are
mutating and require an explicit ``allow_mutating=True`` grant on the scan.

This policy is the single gate used by crawl, auth probe, coverage probe,
schema-attack spec filtering, and (via import) AI PoC replay.
"""
from __future__ import annotations

from collections.abc import Iterable

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
ALL_HTTP_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "TRACE"})


def normalize_method(method: str | None) -> str:
    return str(method or "GET").strip().upper() or "GET"


def is_mutating(method: str | None) -> bool:
    return normalize_method(method) in MUTATING_METHODS


def is_allowed(method: str | None, allow_mutating: bool = False) -> bool:
    method = normalize_method(method)
    if method in SAFE_METHODS:
        return True
    return bool(allow_mutating) and method in MUTATING_METHODS


def allowed_methods(allow_mutating: bool = False) -> frozenset[str]:
    if allow_mutating:
        return frozenset(SAFE_METHODS | MUTATING_METHODS)
    return SAFE_METHODS


def filter_methods(methods: Iterable[str], allow_mutating: bool = False) -> list[str]:
    allowed = allowed_methods(allow_mutating)
    out: list[str] = []
    seen: set[str] = set()
    for method in methods:
        normalized = normalize_method(method)
        if normalized in allowed and normalized not in seen:
            seen.add(normalized)
            out.append(normalized)
    return out


AUDIT_NO_AUTH_WARNING = "audit mode without auth: BOLA/BFLA skipped"


def resolve_audit_mode(
    mode: str | None,
    allow_mutating: bool,
    *,
    mutating_explicit: bool,
) -> tuple[str, bool]:
    """Resolve scan ``mode`` against an optional explicit ``allow_mutating``.

    ``audit`` turns on mutating methods unless the caller set
    ``allow_mutating=False``. ``safe`` leaves ``allow_mutating`` as provided
    (default False). Unknown modes fall back to ``safe``.
    """
    resolved = str(mode or "safe").strip().lower()
    if resolved not in {"safe", "audit"}:
        resolved = "safe"
    if resolved == "audit" and not mutating_explicit:
        return resolved, True
    return resolved, bool(allow_mutating)


def skip_reason(method: str | None, allow_mutating: bool = False) -> str | None:
    """Return why a method was not sent, or None if it is allowed."""
    if is_allowed(method, allow_mutating):
        return None
    return (
        f"{normalize_method(method)} skipped: mutating methods require "
        "allow_mutating=true"
    )
