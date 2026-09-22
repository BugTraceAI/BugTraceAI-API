"""Per-request coverage ledger for API scans.

Separates discovery coverage (what exists), method coverage (what was
actually sent), and auth coverage (unauth vs auth). Records are facts,
not findings.
"""
from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from lib.http_policy import is_allowed, normalize_method, skip_reason

SOURCE_OPENAPI = "openapi"
SOURCE_CRAWL = "crawl"
SOURCE_WORDLIST = "wordlist"
SOURCE_USER = "user_provided"


def body_hash(body: bytes | str | None) -> str | None:
    if body is None:
        return None
    if isinstance(body, str):
        data = body.encode("utf-8", errors="replace")
    else:
        data = body
    return hashlib.sha256(data).hexdigest()[:16]


def path_of(url: str) -> str:
    try:
        path = urlparse(url).path or "/"
    except Exception:
        return "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    return path or "/"


def coverage_row(
    *,
    method: str,
    url: str,
    source: str,
    status: int | None = None,
    duration_ms: int | None = None,
    size: int | None = None,
    content_type: str | None = None,
    auth_used: bool = False,
    auth_required: bool | None = None,
    hashed: str | None = None,
    parameters: list[str] | None = None,
    skipped: str | None = None,
    allow_header: str | None = None,
) -> dict[str, Any]:
    return {
        "method": normalize_method(method),
        "url": url,
        "path": path_of(url),
        "source": source,
        "status": status,
        "duration_ms": duration_ms,
        "size": size,
        "content_type": (content_type or "").split(";")[0].strip() or None,
        "auth_used": bool(auth_used),
        "auth_required": auth_required,
        "body_hash": hashed,
        "parameters": parameters or [],
        "skipped": skipped,
        "allow": allow_header,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def summarize_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Split coverage into discovery / methods / auth facts."""
    by_source: dict[str, int] = {}
    methods: dict[str, int] = {}
    tested = 0
    skipped = 0
    statuses: dict[str, int] = {}
    openapi_ops = 0
    wordlist = 0
    crawl = 0
    auth_compared = 0

    seen_pairs: set[tuple[str, str]] = set()
    for row in rows:
        source = str(row.get("source") or "unknown")
        by_source[source] = by_source.get(source, 0) + 1
        method = normalize_method(row.get("method"))
        methods[method] = methods.get(method, 0) + 1
        pair = (method, str(row.get("path") or path_of(str(row.get("url") or ""))))
        seen_pairs.add(pair)
        if source == SOURCE_OPENAPI:
            openapi_ops += 1
        elif source == SOURCE_WORDLIST:
            wordlist += 1
        elif source == SOURCE_CRAWL:
            crawl += 1
        if row.get("skipped"):
            skipped += 1
        elif row.get("status") is not None:
            tested += 1
            key = str(row.get("status"))
            statuses[key] = statuses.get(key, 0) + 1
        if row.get("auth_compared") and row.get("auth_used") in (True, False):
            auth_compared += 1

    return {
        "total_records": len(rows),
        "unique_operations": len(seen_pairs),
        "tested": tested,
        "verified_operations": sum(bool(r.get("operation_verified")) for r in rows),
        "request_coverage": tested / len(seen_pairs) if seen_pairs else None,
        "verified_coverage": sum(bool(r.get("operation_verified")) for r in rows) / len(seen_pairs) if seen_pairs else None,
        "coverage_status": "measured" if seen_pairs else "unknown",
        "skipped": skipped,
        "by_source": by_source,
        "by_method": methods,
        "by_status": statuses,
        "discovery": {
            "openapi_operations": openapi_ops,
            "wordlist_endpoints": wordlist,
            "crawl_endpoints": crawl,
        },
        "methods": {
            "tested": tested,
            "skipped_mutating": skipped,
        },
        "auth": {
            "compared": auth_compared,
        },
    }


def mark_skipped(method: str, url: str, source: str, allow_mutating: bool) -> dict[str, Any] | None:
    reason = skip_reason(method, allow_mutating)
    if not reason:
        return None
    return coverage_row(method=method, url=url, source=source, skipped=reason)


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def is_method_allowed(method: str, allow_mutating: bool) -> bool:
    return is_allowed(method, allow_mutating)
