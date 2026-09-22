"""Safe coverage probe of published OpenAPI operations.

Sends only policy-allowed methods. Records facts (status, size, hash,
duration) without creating findings.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from lib.auth_header import auth_headers_dict
from lib.coverage import body_hash, coverage_row, elapsed_ms
from lib.http_policy import is_allowed, skip_reason
from lib.findings_quality import is_not_found_response

logger = logging.getLogger("bugtrace-api.tools.coverage_probe")

MAX_OPERATIONS = 200
MAX_CONCURRENT = 5
TIMEOUT = 8.0


async def run_coverage_probe(
    scan_id: str,
    operations: list[dict[str, Any]],
    auth: dict[str, Any] | None = None,
    allow_mutating: bool = False,
) -> list[dict[str, Any]]:
    if not operations:
        return []
    headers = {
        "User-Agent": "BugTraceAI-API/1.2",
        "Accept": "application/json, */*",
    }
    headers.update(auth_headers_dict(auth))
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    rows: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        headers=headers, verify=False, timeout=TIMEOUT, follow_redirects=False
    ) as client:
        # Compare HTML fallbacks against explicit negative controls, never
        # classify an endpoint as absent merely because it serves HTML.
        baseline_hashes = set()
        origins = {f"{urlparse(str(op.get('url', ''))).scheme}://{urlparse(str(op.get('url', ''))).netloc}" for op in operations}
        for origin in origins:
            samples = []
            for _ in range(2):
                try:
                    response = await client.get(f"{origin}/__bt_negative_{uuid4().hex}")
                    if "text/html" in response.headers.get("content-type", "").lower():
                        samples.append(body_hash(response.content))
                except httpx.HTTPError:
                    pass
            if len(samples) == 2 and samples[0] == samples[1]:
                baseline_hashes.add(samples[0])
        tasks = [
            _probe_one(client, semaphore, op, bool(auth), allow_mutating)
            for op in operations[:MAX_OPERATIONS]
        ]
        results = await asyncio.gather(*tasks)
    for row in results:
        if row:
            if row.get("response_kind") == "html" and row.get("body_hash") in baseline_hashes:
                row["rejection_reason"] = "matches_negative_control"
                row["operation_verified"] = False
            rows.append(row)
    logger.info(f"[scan:{scan_id}] Coverage probe: {len(rows)} operation record(s)")
    return rows


async def _probe_one(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    operation: dict[str, Any],
    auth_used: bool,
    allow_mutating: bool,
) -> dict[str, Any]:
    method = str(operation.get("method") or "GET")
    url = str(operation.get("url") or "")
    source = str(operation.get("source") or "openapi")
    if not is_allowed(method, allow_mutating):
        return coverage_row(
            method=method,
            url=url,
            source=source,
            auth_required=operation.get("auth_required"),
            parameters=[p.get("name") for p in operation.get("parameters") or [] if isinstance(p, dict)],
            skipped=skip_reason(method, allow_mutating),
        )
    async with semaphore:
        started = time.monotonic()
        try:
            response = await client.request(method, url, params=operation.get("query_params") or None)
            row = coverage_row(
                method=method,
                url=url,
                source=source,
                status=response.status_code,
                duration_ms=elapsed_ms(started),
                size=len(response.content or b""),
                content_type=response.headers.get("content-type"),
                auth_used=auth_used,
                auth_required=operation.get("auth_required"),
                hashed=body_hash(response.content),
                parameters=[p.get("name") for p in operation.get("parameters") or [] if isinstance(p, dict)],
                allow_header=response.headers.get("allow"),
            )
            row["response_body"] = response.text[:2000]
            absent = is_not_found_response({"evidence": {"response_code": response.status_code, "response_body": response.text}})
            if absent:
                row["rejection_reason"] = "not_found"
            # An HTML shell is not evidence that a JSON API operation exists.
            row["response_kind"] = "html" if "text/html" in response.headers.get("content-type", "").lower() else "api"
            row["operation_verified"] = not absent and row["response_kind"] != "html"
            return row
        except Exception as exc:
            return coverage_row(
                method=method,
                url=url,
                source=source,
                auth_used=auth_used,
                auth_required=operation.get("auth_required"),
                skipped=f"error: {exc}"[:200],
            )
