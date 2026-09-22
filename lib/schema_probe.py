import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx

from lib.auth_header import auth_headers_dict
from lib.catchall import origin_candidates
from lib.openapi import (
    OpenAPIDocument,
    extract_operations,
    fetch_openapi,
    looks_like_openapi,
    parse_openapi,
)
from lib.scan_state import scan_state

logger = logging.getLogger("bugtrace-api.lib.schema_probe")

COMMON_SCHEMA_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/openapi",
    "/swagger.json",
    "/swagger.yaml",
    "/swagger.yml",
    "/swagger",
    "/api-docs",
    "/api-docs.json",
    "/api-json",
    "/v1/api-docs",
    "/v2/api-docs",
    "/v3/api-docs",
    "/v3/api-docs.yaml",
    "/docs",
    "/redoc",
    "/docs/openapi.json",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/openapi.yaml",
    "/api/schema",
    "/api/schema.yaml",
    "/api/v1/openapi.json",
    "/api/v1/swagger.json",
    "/api/v2/openapi.json",
    "/api/v3/openapi.json",
    "/api/docs",
    "/api/docs/swagger.json",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/swagger/v1/swagger.json",
    "/swagger/v1/swagger.yaml",
    "/swagger/v2/swagger.json",
    "/swagger/index.html",
    "/v1/swagger.json",
    "/v1/openapi.json",
    "/v2/swagger.json",
    "/v2/openapi.json",
    "/v3/swagger.json",
    "/v3/openapi.json",
    "/.well-known/openapi.json",
]


def _calculate_coverage(schema: dict, endpoints: list) -> float | None:
    """Estimate how well the schema covers discovered endpoints (0.0–1.0)."""
    if not endpoints:
        # M-3: No endpoints discovered → can't confirm coverage, return moderate
        # value so orchestrator runs both schema + blind paths
        return None
    paths = schema.get("paths", {})
    if not isinstance(paths, dict) or not paths:
        return 0.0

    schema_paths = set(paths.keys())

    def _normalize_path(path: str) -> str:
        if not path:
            return "/"
        p = path.strip()
        if not p.startswith("/"):
            p = f"/{p}"
        if p != "/":
            p = p.rstrip("/")
        return p

    def _schema_path_to_regex(schema_path: str) -> re.Pattern:
        # Convert OpenAPI placeholders into one path segment matcher.
        escaped = re.escape(_normalize_path(schema_path))
        pattern = re.sub(r"\\\{[^/]+\\\}", r"[^/]+", escaped)
        return re.compile(rf"^{pattern}$")

    def _path_candidates(endpoint_path: str) -> list[str]:
        # Try full path plus suffixes to tolerate API prefixes like /api/v1 or /v3.
        normalized = _normalize_path(endpoint_path)
        parts = [p for p in normalized.split("/") if p]
        if not parts:
            return ["/"]
        candidates = [normalized]
        for i in range(1, len(parts)):
            candidates.append("/" + "/".join(parts[i:]))
        return candidates

    schema_regexes = [_schema_path_to_regex(sp) for sp in schema_paths]

    matched = 0
    for ep in endpoints:
        url = ep.get("url", "")
        ep_path = _normalize_path(urlparse(url).path if url.startswith(("http://", "https://")) else url)
        candidates = _path_candidates(ep_path)

        for rx in schema_regexes:
            if any(rx.match(candidate) for candidate in candidates):
                matched += 1
                break

    return min(1.0, matched / max(len(endpoints), 1))


def _schema_like_urls(target: str, discovered_endpoints: list | None) -> list[str]:
    """Extra spec candidates taken from discovery, not mixed into coverage."""
    urls: list[str] = []
    seen: set[str] = set()
    for endpoint in discovered_endpoints or []:
        url = str(endpoint.get("url") or "")
        lowered = url.lower()
        if not url or url in seen:
            continue
        if any(token in lowered for token in ("openapi", "swagger", "api-docs", "api-json")):
            seen.add(url)
            urls.append(url)
    return urls


async def fetch_schema_from_url(schema_url: str, auth: dict[str, Any] | None = None) -> dict | None:
    """Fetch and parse a user-provided schema URL as OpenAPI/Swagger (JSON or YAML).

    Returns the parsed dict, or None if it can't be fetched or isn't parseable.
    Callers should treat None as "coverage unknown", not "no schema"
    (schemathesis/offat can still be pointed at the URL directly).
    """
    document = await fetch_openapi(schema_url, auth, source="user_provided")
    if document.parsed and isinstance(document.spec, dict):
        return document.spec
    return None


async def fetch_schema_document(
    schema_url: str,
    auth: dict[str, Any] | None = None,
    source: str = "user_provided",
) -> OpenAPIDocument:
    return await fetch_openapi(schema_url, auth, source=source)


def document_to_schema_payload(document: OpenAPIDocument, endpoints: list | None = None) -> dict[str, Any]:
    coverage = None
    if document.spec:
        coverage = _calculate_coverage(document.spec, endpoints or [])
    elif document.parsed:
        coverage = 0.0
    payload: dict[str, Any] = {
        "url": document.url,
        "content": document.spec,
        "coverage": coverage,
        "coverage_status": "unknown" if coverage is None else "schema_discovery_overlap",
        "source": document.source,
        "downloaded": document.downloaded,
        "parsed": document.parsed,
        "format": document.format,
        "paths_count": document.paths_count,
        "operations_count": document.operations_count,
        "parse_error": document.parse_error,
        "status_code": document.status_code,
        "content_type": document.content_type,
        "ref_stats": document.ref_stats,
        "attempts": document.attempts,
    }
    if document.spec:
        payload["operations"] = extract_operations(document.spec, document.url)
    return payload


async def probe_schema(
    target: str,
    auth: dict[str, Any] | None = None,
    discovered_endpoints: list | None = None,
    scan_id: str | None = None,
) -> dict[str, Any] | None:
    """Probes a target for OpenAPI/Swagger schemas and actually parses them."""
    started = time.monotonic()
    candidates: list[str] = []
    seen: set[str] = set()
    for base in origin_candidates(target):
        for path in COMMON_SCHEMA_PATHS:
            url = f"{base.rstrip('/')}{path}"
            if url not in seen:
                seen.add(url)
                candidates.append(url)
    candidates.extend(_schema_like_urls(target.rstrip("/"), discovered_endpoints))

    headers = {
        "User-Agent": "BugTraceAI-API/1.2",
        "Accept": (
            "application/json, application/yaml, application/x-yaml, text/yaml, "
            "application/vnd.oai.openapi+json, */*"
        ),
    }
    headers.update(auth_headers_dict(auth))

    last_error = None
    async with httpx.AsyncClient(headers=headers, verify=False, timeout=8.0, follow_redirects=True) as client:
        for url in candidates:
            try:
                logger.debug(f"Probing schema: {url}")
                response = await client.get(url)
                if response.status_code >= 300:
                    continue
                document = parse_openapi(
                    response.content,
                    response.headers.get("content-type", ""),
                    str(response.url),
                )
                document.source = "discovered"
                document.downloaded = True
                document.status_code = response.status_code
                document.content_type = response.headers.get("content-type")
                if document.parsed and document.spec:
                    logger.info(
                        f"Schema found at {document.url} "
                        f"({document.format}, {document.paths_count} paths, "
                        f"{document.operations_count} operations)"
                    )
                    if scan_id:
                        await scan_state.update_tool_health(
                            scan_id,
                            "schema_probe",
                            status="ok",
                            attempts=1,
                            findings_count=document.operations_count,
                            duration_ms=int((time.monotonic() - started) * 1000),
                            error=None,
                        )
                    return document_to_schema_payload(document, discovered_endpoints)

                content_type = (response.headers.get("content-type") or "").lower()
                text = response.text
                if "html" in content_type or "swagger" in text.lower() or "openapi" in text.lower():
                    from lib.openapi import extract_swagger_ui_spec_urls

                    for spec_url in extract_swagger_ui_spec_urls(text, str(response.url)):
                        nested = await fetch_openapi(spec_url, auth, source="discovered")
                        if nested.parsed and nested.spec:
                            logger.info(f"Schema found via Swagger UI at {nested.url}")
                            if scan_id:
                                await scan_state.update_tool_health(
                                    scan_id,
                                    "schema_probe",
                                    status="ok",
                                    attempts=1,
                                    findings_count=nested.operations_count,
                                    duration_ms=int((time.monotonic() - started) * 1000),
                                    error=None,
                                )
                            return document_to_schema_payload(nested, discovered_endpoints)
                last_error = document.parse_error
            except Exception as e:
                logger.debug(f"Probe failed for {url}: {e}")
                last_error = str(e)
                continue

    if scan_id:
        await scan_state.update_tool_health(
            scan_id,
            "schema_probe",
            status="no_schema",
            attempts=1,
            findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=last_error,
        )

    return None


def looks_like_spec(data: Any) -> bool:
    return looks_like_openapi(data)
