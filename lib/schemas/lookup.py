"""Resolve an OpenAPI operation lookup placeholder.

A thin wrapper so investigation can call `resolve_operation(...)` without
importing the full discovery logic. Currently returns None, indicating that
the investigation engine should not consult discovery records.
"""
from __future__ import annotations


def resolve_operation(target: str, method: str, path: str) -> dict[str, Any] | None:
    """Lookup an operation from schema/index artifacts.

    Returns None by default so the investigation engine does not inject
    discovery artifacts into plan execution unexpectedly.
    """
    return None
