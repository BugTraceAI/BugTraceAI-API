"""Catch-all / placeholder response detection.

A target that returns the same 2xx body for unknown paths is not a list of
real endpoints. Detection is by response *shape* (status, size, hash, empty
body, not-found JSON) — never by hostname or path names of a specific lab.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Any
from urllib.parse import urlparse

import httpx

from lib.auth_header import auth_headers_dict

logger = logging.getLogger("bugtrace-api.lib.catchall")

EMPTY_BODY_MAX = 2
_NOT_FOUND_BODY = re.compile(
    r'(?i)"error"\s*:\s*"(not found|not_found|404)"|"detail"\s*:\s*"not found"|'
    r'"message"\s*:\s*"not found"|<title>\s*404'
)
_NONCE_PATHS = (
    "/bugtrace_baseline_probe_x7k9m2",
    "/__bt_nonce_a9f3c1__/no-such-route",
)


def body_hash(body: bytes | str | None) -> str | None:
    if body is None:
        return None
    data = body.encode("utf-8", errors="replace") if isinstance(body, str) else body
    return hashlib.sha256(data).hexdigest()[:16]


def is_placeholder_body(body: str | bytes | None) -> bool:
    if body is None:
        return False
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    stripped = text.strip()
    if len(stripped) <= EMPTY_BODY_MAX:
        return True
    return bool(_NOT_FOUND_BODY.search(stripped))


def _sig(status: int | None, size: int | None, hashed: str | None = None) -> dict[str, Any]:
    return {"status": status, "length": size, "hash": hashed}


async def detect_baseline(
    target: str,
    auth: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """GET two nonce paths. Same 2xx shape on both → catch-all.

    Uses GET (the method wordlists actually send). HEAD-only probes miss
    APIs that 405 HEAD and 200 GET on unknown routes.
    """
    headers = {
        "User-Agent": "BugTraceAI-API/1.2",
        "Accept": "application/json, */*",
    }
    headers.update(auth_headers_dict(auth))
    base = target.rstrip("/")
    samples: list[dict[str, Any]] = []

    async with httpx.AsyncClient(
        headers=headers, verify=False, timeout=8.0, follow_redirects=True
    ) as client:
        for path in _NONCE_PATHS:
            url = f"{base}{path}"
            try:
                resp = await client.get(url)
                samples.append({
                    "url": url,
                    "method": "GET",
                    **_sig(resp.status_code, len(resp.content or b""), body_hash(resp.content)),
                    "placeholder": is_placeholder_body(resp.content),
                })
            except Exception as exc:
                logger.warning(f"Baseline GET {url} failed: {exc}")
                samples.append({"url": url, "method": "GET", "status": 0, "length": None, "hash": None})

    live = [s for s in samples if (s.get("status") or 0) > 0]
    catch_all = False
    if len(live) >= 2:
        a, b = live[0], live[1]
        same_shape = a.get("status") == b.get("status") and a.get("length") == b.get("length")
        if same_shape and 200 <= int(a["status"]) < 300:
            catch_all = True
        if a.get("hash") and a.get("hash") == b.get("hash") and 200 <= int(a["status"]) < 300:
            catch_all = True
        if a.get("placeholder") and b.get("placeholder") and 200 <= int(a["status"]) < 300:
            catch_all = True
    elif len(live) == 1 and 200 <= int(live[0]["status"]) < 300 and (
        (live[0].get("length") or 0) <= EMPTY_BODY_MAX or live[0].get("placeholder")
    ):
        catch_all = True

    primary = live[0] if live else {"status": 0, "length": None, "hash": None}
    signatures = []
    seen: set[tuple] = set()
    for sample in live:
        key = (sample.get("status"), sample.get("length"), sample.get("hash"))
        if key in seen:
            continue
        seen.add(key)
        signatures.append(_sig(sample.get("status"), sample.get("length"), sample.get("hash")))

    result = {
        "status": int(primary.get("status") or 0),
        "length": primary.get("length"),
        "hash": primary.get("hash"),
        "catch_all": catch_all,
        "signatures": signatures,
        "samples": samples,
    }
    logger.info(
        f"Baseline GET → HTTP {result['status']}, length={result['length']}, "
        f"catch_all={catch_all}, signatures={len(signatures)}"
    )
    return result


def is_noise_endpoint(endpoint: dict[str, Any], baseline: dict[str, Any] | None) -> bool:
    """True if this hit looks like a catch-all / empty / not-found placeholder."""
    status = endpoint.get("status")
    try:
        status_i = int(status) if status is not None else -1
    except (TypeError, ValueError):
        status_i = -1
    size = endpoint.get("size")
    try:
        size_i = int(size) if size is not None else None
    except (TypeError, ValueError):
        size_i = None
    hashed = endpoint.get("body_hash")
    source = str(endpoint.get("source") or "")

    if 200 <= status_i < 300 and size_i is not None and size_i <= EMPTY_BODY_MAX:
        return True
    raw_body = endpoint.get("body")
    if raw_body is None:
        raw_body = endpoint.get("body_preview")
    if raw_body is not None and is_placeholder_body(raw_body):
        return True

    baseline = baseline or {}
    for sig in baseline.get("signatures") or []:
        if hashed and sig.get("hash") and hashed == sig.get("hash"):
            return True
        if (
            status_i == sig.get("status")
            and size_i is not None
            and size_i == sig.get("length")
            and 200 <= status_i < 300
        ):
            return True
    return bool(source == "wordlist" and 200 <= status_i < 300 and size_i is not None and size_i <= 8)


def filter_noise(
    endpoints: list[dict[str, Any]],
    baseline: dict[str, Any] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    kept: list[dict[str, Any]] = []
    discarded: list[dict[str, Any]] = []
    for endpoint in endpoints:
        if is_noise_endpoint(endpoint, baseline):
            discarded.append(endpoint)
        else:
            kept.append(endpoint)
    return kept, discarded


def origin_candidates(target: str) -> list[str]:
    """Scan target plus host origin (spec often lives at /openapi.json, not under /api/v1)."""
    target = target.rstrip("/")
    parsed = urlparse(target)
    out = [target]
    if parsed.scheme and parsed.netloc:
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin != target:
            out.append(origin)
    return out
