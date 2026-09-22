"""Canonical OpenAPI URL normalization.

Resolves the true base URL of an OpenAPI document independently of where
the file itself is hosted. Separates the document location from the
operation base URL so that ``/openapi.json/api/...``-style corruption
cannot happen.
"""
from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("bugtrace-api.lib.url_normalizer")


def resolve_base_url(spec: dict, document_url: str, target: str) -> str:
    """Return the canonical base URL for OpenAPI operations.

    Priority:
    1. ``servers[0].url`` (absolute) — used directly.
    2. ``servers[0].url`` (relative) — resolved against the target host.
    3. ``host`` + ``basePath``/``schemes`` — classic OpenAPI fields.
    4. Fallback: the scan *target* itself.
    """
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        raw = servers[0].get("url") if isinstance(servers[0], dict) else ""
        cleaned = _strip_template_vars(str(raw))
        if cleaned.startswith(("http://", "https://")):
            return cleaned.rstrip("/")
        if cleaned.startswith("/"):
            return f"{_origin_of(target)}{cleaned.rstrip('/')}"

    host = spec.get("host")
    base_path = spec.get("basePath") or ""
    schemes = spec.get("schemes")
    if isinstance(host, str) and host:
        scheme = str(schemes[0]) if isinstance(schemes, list) and schemes else "https"
        return f"{scheme}://{host}{str(base_path).rstrip('/')}"

    return target.rstrip("/")


def _origin_of(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url.rstrip("/")


def _strip_template_vars(url: str) -> str:
    """Remove {var} template placeholders from a server URL."""
    return re.sub(r"\{[^}]+\}", "", url)


def validate_url_in_scope(url: str, allowed_hosts: list[str]) -> bool:
    """Check that *url* belongs to one of the *allowed_hosts*."""
    parsed = urlparse(url)
    if not parsed.netloc:
        return False
    for host in allowed_hosts:
        if parsed.netloc == host or parsed.netloc.endswith(f".{host}"):
            return True
    return False


def normalize_openapi_urls(spec: dict, document_url: str, target: str) -> dict[str, str]:
    """Return a dict mapping every operation path to its canonical URL.

    The result never contains a path that starts with the document's own
    file path (e.g. ``/openapi.json/api/...``).
    """
    base = resolve_base_url(spec, document_url, target)
    base_parsed = urlparse(base)
    base_path = (base_parsed.path or "").rstrip("/")
    origin = f"{base_parsed.scheme}://{base_parsed.netloc}"
    document_path = urlparse(document_url).path

    result: dict[str, str] = {}

    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return result

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        concrete = _concrete_path(path)
        # Ensure the URL starts with origin and does NOT double the base path
        full_path = f"{base_path}/{concrete}" if base_path else f"/{concrete}"
        full_path = _deduplicate_slashes(full_path)
        if full_path.startswith("/"):
            full_url = f"{origin}{full_path}"
        else:
            full_url = f"{origin}/{full_path}"
        
        # Sanity: reject URL that would place operations under the document file
        if document_path and full_url.startswith(document_path.rstrip("/") + "/"):
            logger.warning(
                "URL %s would be under document path %s — skipping",
                full_url, document_path,
            )
            continue
        result[path] = full_url

    return result


def _concrete_path(path: str) -> str:
    """Replace path parameters with concrete placeholders."""
    return re.sub(r"\{[^}]+\}", "1", path)


def _deduplicate_slashes(url: str) -> str:
    """Collapse multiple consecutive slashes into one."""
    return re.sub(r"/{2,}", "/", url)


def extract_canonical_operations(spec: dict, target: str, document_url: str) -> list[dict[str, Any]]:
    """Build the canonical inventory of operations from a resolved spec.

    Every operation carries: method, spec_path, url (canonical), parameters,
    content_types, auth_required, operation_id, summary, tags, source.
    """
    from lib.openapi import normalize_method, _normalize_parameters, _request_content_types, _security_required, _concrete_path as oc_concrete
    from lib.http_policy import ALL_HTTP_METHODS

    HTTP_METHODS = {m.lower() for m in ALL_HTTP_METHODS}
    operations: list[dict[str, Any]] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return operations

    canonical_urls = normalize_openapi_urls(spec, document_url, target)
    global_security = spec.get("security")
    global_parameters = spec.get("parameters") if isinstance(spec.get("parameters"), list) else []

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_params = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            op_params = operation.get("parameters") if isinstance(operation.get("parameters"), list) else []
            parameters = _normalize_parameters(global_parameters + path_params + op_params)
            content_types = _request_content_types(operation)
            security = operation.get("security", global_security)
            auth_required = _security_required(security)
            canonical_url = canonical_urls.get(path) or f"{target.rstrip('/')}/{path.lstrip('/')}"
            operations.append({
                "method": normalize_method(method),
                "path": str(path),
                "url": canonical_url,
                "spec_path": str(path),
                "parameters": parameters,
                "content_types": content_types,
                "auth_required": auth_required,
                "operation_id": operation.get("operationId") or "",
                "summary": operation.get("summary") or "",
                "tags": list(operation.get("tags") or []) if isinstance(operation.get("tags"), list) else [],
                "source": "openapi",
            })
    return operations


def to_canon(url: str) -> str:
    """Normalize a URL to its canonical form (collapse double slashes)."""
    return _deduplicate_slashes(url)
