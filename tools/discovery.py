import logging
import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from lib import sanitize_cmd_for_log
from lib.auth_header import auth_cli_flag, auth_headers_dict
from lib.catchall import is_noise_endpoint, is_placeholder_body
from lib.coverage import body_hash, coverage_row
from lib.http_policy import allowed_methods, is_allowed
from lib.scan_state import scan_state
from lib.subprocess_runner import SubprocessResult, run_stream_tool
from mcp_server import KR_BIN, TEXT_WORDLISTS_DIR, WORDLISTS_DIR

logger = logging.getLogger("bugtrace-api.tools.discovery")

# Retry config for discovery tools (M-1)
DISCOVERY_MAX_ATTEMPTS = 2
DISCOVERY_BACKOFF_SECONDS = 2

# Cap kiterunner wall-clock time so it never blocks the whole discovery phase
KR_MAX_SECONDS = 300  # 5 minutes


def _parse_kr_line(line: str) -> dict[str, Any] | None:
    """Parse one line of kiterunner text output."""
    line = line.strip()
    if not line:
        return None
    pattern = (
        r"^(?P<method>\w+)\s+"
        r"(?P<status>\d+)\s+"
        r"\[\s*(?P<words>\d+),\s*(?P<lines>\d+),\s*(?P<chars>\d+)\]\s+"
        r"(?P<url>https?://\S+)"
    )
    m = re.match(pattern, line)
    if not m:
        return None
    return {
        "method": m.group("method"),
        "status": int(m.group("status")),
        "url": m.group("url"),
        "source": "wordlist",
        "size": int(m.group("chars")),
    }


async def _run_kr(
    scan_id: str,
    tool_name: str,
    cmd: list[str],
) -> SubprocessResult:
    """Run kiterunner with streaming stdout, retry on failure.

    Shared by both kr scan and kr brute modes.
    ``tool_name`` is used for logging and ``scan_state`` health keys.
    """
    async def _on_line(line: str) -> dict[str, Any] | None:
        """Parse each stdout line; return parsed endpoint or None to discard."""
        parsed = _parse_kr_line(line)
        if parsed:
            await scan_state.add_endpoints(scan_id, [parsed])
            return parsed
        return None

    return await run_stream_tool(
        scan_id=scan_id,
        tool_name=tool_name,
        cmd=cmd,
        on_line=_on_line,
        timeout=KR_MAX_SECONDS,
        max_attempts=DISCOVERY_MAX_ATTEMPTS,
        backoff_seconds=DISCOVERY_BACKOFF_SECONDS,
    )


def _build_ignore_length(baseline_length: int | list[int] | None) -> list[str]:
    """Build --ignore-length args. 0-byte catch-alls must be included."""
    values: list[int] = []
    if isinstance(baseline_length, list):
        values = [int(n) for n in baseline_length if n is not None and int(n) >= 0]
    elif isinstance(baseline_length, int) and baseline_length >= 0:
        values = [baseline_length]
    flags: list[str] = []
    for n in sorted(set(values)):
        flags.extend(["--ignore-length", str(n)])
    return flags


def _build_auth_args(auth: dict[str, Any] | None) -> list[str]:
    return auth_cli_flag(auth)


async def run_kiterunner_scan(
    scan_id: str,
    target: str,
    depth: str = "standard",
    auth: dict[str, Any] | None = None,
    baseline_length: int | list[int] | None = None,
    allow_mutating: bool = False,
) -> list[dict[str, Any]]:
    """kr scan with .kite wordlists — smart API-aware probing.

    Safe mode forces GET so the kite pass still runs without POST/PUT/DELETE.
    """
    wordlist = "routes-small.kite" if depth != "deep" else "routes-large.kite"
    wordlist_path = WORDLISTS_DIR / wordlist
    if not wordlist_path.exists():
        wordlist_path = WORDLISTS_DIR / "routes-small.kite"
    if not wordlist_path.exists():
        logger.warning(f"[scan:{scan_id}] kr scan: no .kite wordlist found, skipping")
        await scan_state.update_tool_health(
            scan_id, "kiterunner_scan", status="error", attempts=0,
            findings_count=0, duration_ms=0, error="no_kite_wordlist",
        )
        return []

    cmd = [
        str(KR_BIN),
        "scan", target,
        "-w", str(wordlist_path),
        "-x", "5",
        "-o", "text",
        "-q",
    ]
    cmd += _build_ignore_length(baseline_length)
    if not allow_mutating:
        cmd += ["--force-method", "GET"]
    cmd += ["--quarantine-threshold", "8"]
    cmd += _build_auth_args(auth)

    logger.info(f"[scan:{scan_id}] kr scan (.kite): {sanitize_cmd_for_log(cmd)}")
    result = await _run_kr(scan_id, "kiterunner_scan", cmd)
    # result.data is already accumulated endpoints; health was recorded by _run_kr
    return result.data or []


async def run_kiterunner_brute(
    scan_id: str,
    target: str,
    auth: dict[str, Any] | None = None,
    baseline_length: int | list[int] | None = None,
) -> list[dict[str, Any]]:
    """kr brute with merged text wordlists — brute-force endpoint discovery.

    Uses the unified api-endpoints.txt (SecLists + Assetnote merged).
    Applies false-positive filtering ported from api-routes-mcp:
      --disable-precheck   → prevents SPA catch-all from aborting scan
      --max-redirects 0    → preserves real status codes and content-length
      --fail-status-codes  → filters 404s at kr level (Express reflected-path FPs)
      --ignore-length      → filters baseline content-length (SPA catch-all FPs)
    """
    wordlist_path = TEXT_WORDLISTS_DIR / "api-endpoints.txt"
    if not wordlist_path.exists():
        logger.warning(f"[scan:{scan_id}] kr brute: api-endpoints.txt not found, skipping")
        await scan_state.update_tool_health(
            scan_id, "kiterunner_brute", status="error", attempts=0,
            findings_count=0, duration_ms=0, error="no_text_wordlist",
        )
        return []

    cmd = [
        str(KR_BIN),
        "brute", target,
        "-w", str(wordlist_path),
        "-x", "5",
        "-o", "text",
        "-q",
        "--disable-precheck",             # skip preflight — SPA catch-all won't abort
        "--max-redirects", "0",           # don't follow redirects — preserve real status/length
        "--fail-status-codes", "404",    # filter 404s at kr level — Express FP prevention
        "--quarantine-threshold", "8",   # abort host if consecutive wildcard hits
    ]
    cmd += _build_ignore_length(baseline_length)
    cmd += _build_auth_args(auth)

    logger.info(f"[scan:{scan_id}] kr brute (text): {sanitize_cmd_for_log(cmd)}")
    result = await _run_kr(scan_id, "kiterunner_brute", cmd)
    return result.data or []


# ── Baseline detection (from api-routes-mcp) ───────────────────────────────

async def detect_baseline(target: str, auth: dict[str, Any] | None = None) -> dict[str, Any]:
    """GET nonce paths to detect catch-all 2xx (not HEAD — wordlists send GET)."""
    from lib.catchall import detect_baseline as _detect

    return await _detect(target, auth)


# ── Smart API Crawler ───────────────────────────────────────────────────────

# Common paths to seed the crawler (beyond root)
_SEED_PATHS = [
    "/", "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/graphql", "/health", "/status", "/info", "/version",
    "/docs", "/swagger", "/openapi.json", "/swagger.json",
]


def _extract_links_from_json(data: Any, base_url: str) -> set[str]:
    """Recursively extract URLs/paths from a JSON response (including HAL _links)."""
    links: set[str] = set()

    if isinstance(data, dict):
        # HAL+JSON: _links contains { "rel": {"href": "/path"} } or lists
        if "_links" in data:
            _extract_hal_links(data["_links"], base_url, links)

        # _embedded may contain nested resources with their own _links
        if "_embedded" in data and isinstance(data["_embedded"], dict):
            for resource_list in data["_embedded"].values():
                if isinstance(resource_list, list):
                    for item in resource_list:
                        links.update(_extract_links_from_json(item, base_url))
                elif isinstance(resource_list, dict):
                    links.update(_extract_links_from_json(resource_list, base_url))

        # Generic: look for common URL-like keys
        for key in ("href", "url", "uri", "link", "endpoint", "path", "location"):
            if key in data and isinstance(data[key], str):
                links.add(_resolve_url(data[key], base_url))

        # Recurse into all values
        for key, val in data.items():
            if key in ("_links", "_embedded"):
                continue  # already handled
            if isinstance(val, (dict, list)):
                links.update(_extract_links_from_json(val, base_url))

    elif isinstance(data, list):
        for item in data:
            links.update(_extract_links_from_json(item, base_url))

    return links


def _extract_hal_links(links_obj: Any, base_url: str, out: set[str]) -> None:
    """Parse HAL _links object into absolute URLs."""
    if not isinstance(links_obj, dict):
        return
    for rel, link_data in links_obj.items():
        if rel == "curies":
            continue  # skip CURIE definitions
        if isinstance(link_data, dict):
            href = link_data.get("href", "")
            if href:
                out.add(_resolve_url(href, base_url))
        elif isinstance(link_data, list):
            for item in link_data:
                if isinstance(item, dict):
                    href = item.get("href", "")
                    if href:
                        out.add(_resolve_url(href, base_url))


def _resolve_url(href: str, base_url: str) -> str:
    """Resolve a relative href against a base URL."""
    href = href.strip()
    if href.startswith(("http://", "https://")):
        return href
    return urljoin(base_url.rstrip("/") + "/", href.lstrip("/"))


def _is_same_origin(url: str, target: str) -> bool:
    """Check if url belongs to the same origin as target."""
    try:
        return urlparse(url).netloc == urlparse(target).netloc
    except Exception:
        return False


async def run_api_crawl(
    scan_id: str,
    target: str,
    auth: dict[str, Any] | None = None,
    max_depth: int = 4,
    max_urls: int = 200,
    allow_mutating: bool = False,
) -> list[dict[str, Any]]:
    """Smart API crawler: follows HAL _links, JSON hrefs, and common API paths.

    BFS traversal up to max_depth levels, max_urls total requests.
    Returns list of endpoint dicts compatible with the pipeline.
    """
    started = time.monotonic()
    target_url = target.rstrip("/")
    visited: set[str] = set()
    endpoints: list[dict[str, Any]] = []

    headers = {"User-Agent": "BugTraceAI/1.0", "Accept": "application/json, application/hal+json, */*"}
    headers.update(auth_headers_dict(auth))

    # Seed queue: root + common paths
    seen_urls: set[str] = set()
    queue: list[tuple] = []  # (url, depth)
    for seed in _SEED_PATHS:
        seed_url = f"{target_url}{seed}"
        if seed_url not in seen_urls:
            seen_urls.add(seed_url)
            queue.append((seed_url, 0))

    logger.info(f"[scan:{scan_id}] API Crawl: starting with {len(queue)} seed URLs (max_depth={max_depth})")

    async with httpx.AsyncClient(
        headers=headers, verify=False, timeout=10.0, follow_redirects=True
    ) as client:
        while queue and len(visited) < max_urls:
            url, depth = queue.pop(0)

            if url in visited:
                continue
            visited.add(url)

            # Only crawl same-origin URLs
            if not _is_same_origin(url, target_url):
                continue

            try:
                started_req = time.monotonic()
                resp = await client.get(url)
                status_code = resp.status_code
                content_type = resp.headers.get("content-type", "")

                endpoint = coverage_row(
                    method="GET",
                    url=url,
                    source="crawl",
                    status=status_code,
                    duration_ms=int((time.monotonic() - started_req) * 1000),
                    size=len(resp.content or b""),
                    content_type=content_type,
                    auth_used=bool(auth),
                    hashed=body_hash(resp.content),
                    allow_header=resp.headers.get("allow"),
                )

                # Record only if it is not a 404 and not a placeholder/empty catch-all.
                if status_code != 404 and not is_placeholder_body(resp.content) and not is_noise_endpoint(endpoint, None):
                    endpoint["body_preview"] = (resp.text or "")[:80]
                    endpoints.append(endpoint)
                    await scan_state.add_endpoints(scan_id, [endpoint])

                # Probe additional methods. Mutating verbs require allow_mutating.
                extra_methods = [m for m in allowed_methods(allow_mutating) if m != "GET"]
                if status_code in (200, 201, 204, 301, 302, 401, 403, 405):
                    for method in extra_methods:
                        if not is_allowed(method, allow_mutating):
                            continue
                        try:
                            method_started = time.monotonic()
                            method_resp = await client.request(method, url)
                            if method_resp.status_code not in (404, 405):
                                method_ep = coverage_row(
                                    method=method,
                                    url=url,
                                    source="crawl",
                                    status=method_resp.status_code,
                                    duration_ms=int((time.monotonic() - method_started) * 1000),
                                    size=len(method_resp.content or b""),
                                    content_type=method_resp.headers.get("content-type", ""),
                                    auth_used=bool(auth),
                                    hashed=body_hash(method_resp.content),
                                    allow_header=method_resp.headers.get("allow"),
                                )
                                endpoints.append(method_ep)
                                await scan_state.add_endpoints(scan_id, [method_ep])
                        except Exception:
                            pass

                # Parse response body for more links (only within depth limit)
                if depth < max_depth and status_code == 200:
                    content_type = resp.headers.get("content-type", "").lower()

                    if "json" in content_type:
                        try:
                            data = resp.json()
                            discovered_links = _extract_links_from_json(data, target_url)
                            for link in discovered_links:
                                if link not in seen_urls and _is_same_origin(link, target_url):
                                    seen_urls.add(link)
                                    queue.append((link, depth + 1))
                        except Exception:
                            pass

                    elif "text" in content_type or "html" in content_type:
                        url_pattern = re.compile(
                            rf'(?:href|src|action)=["\']({re.escape(urlparse(target_url).scheme)}://[^"\']+|/[^"\']*)["\']',
                            re.IGNORECASE,
                        )
                        for match in url_pattern.finditer(resp.text):
                            found = _resolve_url(match.group(1), target_url)
                            if found not in seen_urls and _is_same_origin(found, target_url):
                                seen_urls.add(found)
                                queue.append((found, depth + 1))

            except httpx.TimeoutException:
                logger.debug(f"[scan:{scan_id}] Crawl timeout: {url}")
            except Exception as e:
                logger.debug(f"[scan:{scan_id}] Crawl error for {url}: {e}")

    duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(f"[scan:{scan_id}] API Crawl completed: {len(endpoints)} endpoints from {len(visited)} URLs in {duration_ms}ms")

    await scan_state.update_tool_health(
        scan_id,
        "api_crawl",
        status="ok",
        attempts=1,
        findings_count=len(endpoints),
        duration_ms=duration_ms,
        error=None,
    )

    return endpoints
