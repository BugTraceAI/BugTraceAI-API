"""OpenAPI / Swagger document loading, parsing, $ref resolution, and inventory.

This module is the single place that decides whether a response is a spec,
how many paths/operations it contains, and which operations are documented.
It never treats a wordlist-generated document as a published spec.
"""
from __future__ import annotations

import copy
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from lib.auth_header import auth_headers_dict
from lib.http_policy import ALL_HTTP_METHODS, normalize_method

logger = logging.getLogger("bugtrace-api.lib.openapi")

HTTP_METHODS = {m.lower() for m in ALL_HTTP_METHODS}

ACCEPT_HEADER = (
    "application/json, application/yaml, application/x-yaml, text/yaml, "
    "application/vnd.oai.openapi+json, application/vnd.oai.openapi, */*"
)

_SWAGGER_UI_URL = re.compile(
    r"""(?:url|configUrl)\s*:\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)
_SWAGGER_UI_URLS = re.compile(
    r"""urls\s*:\s*\[(.*?)\]""",
    re.IGNORECASE | re.DOTALL,
)
_SWAGGER_UI_URLS_ITEM = re.compile(
    r"""url\s*:\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)


@dataclass
class OpenAPIDocument:
    """Parsed OpenAPI/Swagger document plus fetch diagnostics."""

    url: str
    spec: dict[str, Any] | None = None
    downloaded: bool = False
    parsed: bool = False
    format: str = "unknown"  # json | yaml | unknown
    source: str = "discovered"
    paths_count: int = 0
    operations_count: int = 0
    parse_error: str | None = None
    status_code: int | None = None
    content_type: str | None = None
    redirected_from: str | None = None
    ref_stats: dict[str, int] = field(default_factory=dict)
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def as_decision(self, coverage: float = 0.0) -> dict[str, Any]:
        return {
            "has_schema": bool(self.parsed and self.spec and self.paths_count > 0),
            "url": self.url,
            "source": self.source,
            "coverage": coverage,
            "paths_count": self.paths_count,
            "operations_count": self.operations_count,
            "downloaded": self.downloaded,
            "parsed": self.parsed,
            "format": self.format,
            "parse_error": self.parse_error,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "ref_stats": self.ref_stats,
        }


def looks_like_openapi(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    if data.get("openapi") or data.get("swagger"):
        return True
    paths = data.get("paths")
    return isinstance(paths, dict)


def count_paths(spec: dict[str, Any] | None) -> int:
    paths = (spec or {}).get("paths")
    if not isinstance(paths, dict):
        return 0
    return sum(1 for key in paths if key != "$ref")


def count_operations(spec: dict[str, Any] | None) -> int:
    paths = (spec or {}).get("paths")
    if not isinstance(paths, dict):
        return 0
    total = 0
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        total += sum(1 for method in path_item if method.lower() in HTTP_METHODS)
    return total


def _load_yaml(text: str) -> Any:
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError("PyYAML is required to parse YAML OpenAPI documents") from exc
    return yaml.safe_load(text)


def parse_openapi(
    raw: bytes | str,
    content_type: str = "",
    url: str = "",
) -> OpenAPIDocument:
    """Parse JSON or YAML bytes/text into an OpenAPIDocument.

    Content-Type is a hint only. JSON is tried first, then YAML. A document
    is accepted when it looks like OpenAPI/Swagger (openapi/swagger key or
    a paths object).
    """
    doc = OpenAPIDocument(url=url or "", downloaded=True)
    content_type = (content_type or "").lower()
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    text = text.lstrip("\ufeff")

    data: Any = None
    json_error: str | None = None
    yaml_error: str | None = None

    prefer_yaml = any(token in content_type for token in ("yaml", "yml")) or url.endswith(
        (".yaml", ".yml")
    )

    def try_json() -> Any:
        nonlocal json_error
        try:
            return json.loads(text)
        except Exception as exc:
            json_error = str(exc)
            return None

    def try_yaml() -> Any:
        nonlocal yaml_error
        try:
            return _load_yaml(text)
        except Exception as exc:
            yaml_error = str(exc)
            return None

    if prefer_yaml:
        data = try_yaml()
        if looks_like_openapi(data):
            doc.format = "yaml"
        else:
            data = try_json()
            if looks_like_openapi(data):
                doc.format = "json"
    else:
        data = try_json()
        if looks_like_openapi(data):
            doc.format = "json"
        else:
            data = try_yaml()
            if looks_like_openapi(data):
                doc.format = "yaml"

    if not looks_like_openapi(data):
        doc.parsed = False
        doc.parse_error = json_error or yaml_error or "response is not an OpenAPI/Swagger document"
        return doc

    assert isinstance(data, dict)
    resolved, ref_stats = resolve_refs(data, base_url=url)
    doc.spec = resolved
    doc.parsed = True
    doc.ref_stats = ref_stats
    doc.paths_count = count_paths(resolved)
    doc.operations_count = count_operations(resolved)
    doc.content_type = content_type or None
    return doc


def _unescape_pointer(token: str) -> str:
    return token.replace("~1", "/").replace("~0", "~")


def json_pointer(doc: dict[str, Any], pointer: str) -> Any:
    if not pointer or pointer == "#":
        return doc
    if pointer.startswith("#"):
        pointer = pointer[1:]
    if pointer.startswith("/"):
        pointer = pointer[1:]
    node: Any = doc
    if not pointer:
        return node
    for token in pointer.split("/"):
        key = _unescape_pointer(token)
        if isinstance(node, list):
            node = node[int(key)]
        elif isinstance(node, dict):
            node = node[key]
        else:
            raise KeyError(pointer)
    return node


def resolve_refs(
    spec: dict[str, Any],
    base_url: str = "",
    *,
    allow_external: bool = True,
    max_depth: int = 12,
) -> tuple[dict[str, Any], dict[str, int]]:
    """Resolve internal JSON Pointer $refs. External refs are same-origin only.

    Returns a deep copy so the original document is not mutated. Cycles become
    an empty object instead of recursing forever.
    """
    root = copy.deepcopy(spec)
    stats = {"internal": 0, "external": 0, "failed": 0, "cycles": 0}
    resolving: set[str] = set()
    cache: dict[str, Any] = {}
    origin = urlparse(base_url).netloc if base_url else ""

    def _resolve(node: Any, depth: int) -> Any:
        if depth > max_depth:
            stats["failed"] += 1
            return node
        if isinstance(node, list):
            return [_resolve(item, depth + 1) for item in node]
        if not isinstance(node, dict):
            return node
        ref = node.get("$ref")
        if not isinstance(ref, str) or not ref:
            return {key: _resolve(value, depth + 1) for key, value in node.items()}

        extras = {key: value for key, value in node.items() if key != "$ref"}
        if ref in resolving:
            stats["cycles"] += 1
            return extras or {}
        if ref in cache:
            resolved = copy.deepcopy(cache[ref])
            if extras and isinstance(resolved, dict):
                resolved.update(extras)
            return resolved

        try:
            if ref.startswith("#"):
                stats["internal"] += 1
                resolving.add(ref)
                target = json_pointer(root, ref)
                resolved = _resolve(copy.deepcopy(target), depth + 1)
                resolving.discard(ref)
                cache[ref] = resolved
            elif allow_external and base_url:
                abs_url = urljoin(base_url, ref)
                if origin and urlparse(abs_url).netloc != origin:
                    stats["failed"] += 1
                    return node
                stats["external"] += 1
                resolving.add(ref)
                fetched = _fetch_external_ref_sync(abs_url)
                resolved = _resolve(fetched, depth + 1) if fetched is not None else node
                resolving.discard(ref)
                cache[ref] = resolved
            else:
                stats["failed"] += 1
                return node
        except Exception:
            stats["failed"] += 1
            resolving.discard(ref)
            return node

        if extras and isinstance(resolved, dict):
            merged = copy.deepcopy(resolved)
            merged.update(extras)
            return merged
        return resolved

    return _resolve(root, 0), stats


def _fetch_external_ref_sync(url: str) -> Any | None:
    """Best-effort same-origin $ref fetch. Failures are recorded by the caller."""
    try:
        with httpx.Client(timeout=8.0, follow_redirects=True, verify=False) as client:
            response = client.get(url, headers={"Accept": ACCEPT_HEADER, "User-Agent": "BugTraceAI-API/1.2"})
            if response.status_code >= 300:
                return None
            parsed = parse_openapi(response.content, response.headers.get("content-type", ""), url)
            if parsed.spec is not None:
                return parsed.spec
            try:
                return response.json()
            except Exception:
                try:
                    return _load_yaml(response.text)
                except Exception:
                    return None
    except Exception:
        return None


def extract_operations(spec: dict[str, Any], target: str) -> list[dict[str, Any]]:
    """Flatten OpenAPI paths into concrete operation records.

    Path parameters are left as `{name}` in `spec_path` and replaced with
    example/default/`1` only in `url` so coverage can still match the template.
    """
    operations: list[dict[str, Any]] = []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return operations

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
            concrete = _concrete_path(str(path), parameters)
            operations.append({
                "method": normalize_method(method),
                "path": str(path),
                "url": join_spec_url(target, concrete, spec),
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


def filter_spec_methods(spec: dict[str, Any], allowed: IterableLike) -> dict[str, Any]:
    """Return a copy of ``spec`` containing only allowed HTTP methods."""
    allowed_set = {normalize_method(m) for m in allowed}
    filtered = copy.deepcopy(spec)
    paths = filtered.get("paths")
    if not isinstance(paths, dict):
        return filtered
    new_paths: dict[str, Any] = {}
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        kept: dict[str, Any] = {}
        for key, value in path_item.items():
            if key.lower() in HTTP_METHODS:
                if normalize_method(key) in allowed_set:
                    kept[key] = value
            else:
                kept[key] = value
        if any(k.lower() in HTTP_METHODS for k in kept):
            new_paths[path] = kept
    filtered["paths"] = new_paths
    return filtered


IterableLike = Any


def origin_of(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return url.rstrip("/")


def join_spec_url(target: str, spec_path: str, spec: dict[str, Any] | None = None) -> str:
    """Join a scan target with an OpenAPI path without doubling prefixes.

    ``https://host/api/v1`` + ``/api/items/`` → ``https://host/api/items/``
    ``https://host/v1`` + ``/users`` → ``https://host/v1/users``
    """
    base = _server_base(spec, target) if spec is not None else target.rstrip("/")
    path = spec_path if str(spec_path).startswith("/") else f"/{spec_path}"
    parsed = urlparse(base)
    if not parsed.scheme or not parsed.netloc:
        return f"{base.rstrip('/')}{path}"
    origin = f"{parsed.scheme}://{parsed.netloc}"
    base_path = (parsed.path or "").rstrip("/")
    if base_path and (path == base_path or path.startswith(base_path + "/")):
        return f"{origin}{path}"
    if base_path:
        base_parts = [p for p in base_path.split("/") if p]
        path_parts = [p for p in path.split("/") if p]
        if base_parts and path_parts and path_parts[0] == base_parts[0] and not path.startswith(base_path):
            return f"{origin}{path}"
    return f"{origin}{base_path}{path}"


def _server_base(spec: dict[str, Any], target: str) -> str:
    target = target.rstrip("/")
    servers = spec.get("servers")
    if isinstance(servers, list) and servers:
        url = str(servers[0].get("url") or "") if isinstance(servers[0], dict) else ""
        url = re.sub(r"\{[^}]+\}", "", url)
        if url.startswith(("http://", "https://")):
            return url.rstrip("/")
        if url.startswith("/"):
            return f"{origin_of(target)}{url.rstrip('/')}"
    host = spec.get("host")
    base_path = spec.get("basePath") or ""
    if isinstance(host, str) and host:
        scheme = "https"
        schemes = spec.get("schemes")
        if isinstance(schemes, list) and schemes:
            scheme = str(schemes[0])
        return f"{scheme}://{host}{str(base_path).rstrip('/')}"
    # OpenAPI defaults to the origin root when servers/basePath are absent.
    # The document URL is NOT the API base (/openapi.json/api/... is invalid).
    return f"{origin_of(target)}{str(base_path).rstrip('/')}"


def _normalize_parameters(raw: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        location = str(item.get("in") or "query")
        if not name or (name, location) in seen:
            continue
        seen.add((name, location))
        example = item.get("example")
        if example is None:
            schema = item.get("schema") if isinstance(item.get("schema"), dict) else {}
            example = schema.get("example", schema.get("default"))
        out.append({
            "name": name,
            "in": location,
            "required": bool(item.get("required")),
            "example": example,
        })
    return out


def _request_content_types(operation: dict[str, Any]) -> list[str]:
    types: list[str] = []
    body = operation.get("requestBody")
    if isinstance(body, dict):
        content = body.get("content")
        if isinstance(content, dict):
            types.extend(str(k) for k in content)
    consumes = operation.get("consumes")
    if isinstance(consumes, list):
        types.extend(str(x) for x in consumes)
    return list(dict.fromkeys(types))


def _security_required(security: Any) -> bool | None:
    """True if the operation requires auth, False if explicitly public, None if unknown."""
    if security is None:
        return None
    if security == [] or security == [{}]:
        return False
    if isinstance(security, list) and security:
        return True
    return None


def _concrete_path(path: str, parameters: list[dict[str, Any]]) -> str:
    examples = {
        p["name"]: p.get("example")
        for p in parameters
        if p.get("in") == "path" and p.get("example") not in (None, "")
    }

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        value = examples.get(name, "1")
        return str(value)

    return re.sub(r"\{([^}]+)\}", replace, path)


def extract_swagger_ui_spec_urls(html: str, page_url: str) -> list[str]:
    """Pull spec URLs out of a Swagger UI HTML page."""
    found: list[str] = []
    for match in _SWAGGER_UI_URL.finditer(html):
        found.append(match.group(1))
    block = _SWAGGER_UI_URLS.search(html)
    if block:
        for match in _SWAGGER_UI_URLS_ITEM.finditer(block.group(1)):
            found.append(match.group(1))
    resolved: list[str] = []
    seen: set[str] = set()
    for spec_url in found:
        absolute = urljoin(page_url if page_url.endswith("/") else page_url + "/", spec_url)
        if absolute not in seen:
            seen.add(absolute)
            resolved.append(absolute)
    return resolved


async def fetch_openapi(
    url: str,
    auth: dict[str, Any] | None = None,
    *,
    timeout: float = 10.0,
    source: str = "discovered",
) -> OpenAPIDocument:
    """Download and parse an OpenAPI/Swagger document from a URL."""
    headers = {
        "User-Agent": "BugTraceAI-API/1.2",
        "Accept": ACCEPT_HEADER,
    }
    headers.update(auth_headers_dict(auth))
    doc = OpenAPIDocument(url=url, source=source)
    try:
        async with httpx.AsyncClient(
            headers=headers, verify=False, timeout=timeout, follow_redirects=True
        ) as client:
            response = await client.get(url)
    except Exception as exc:
        doc.parse_error = f"download failed: {exc}"
        return doc

    doc.downloaded = True
    doc.status_code = response.status_code
    doc.content_type = response.headers.get("content-type")
    if str(response.url) != url:
        doc.redirected_from = url
        doc.url = str(response.url)
    doc.attempts.append({
        "url": url,
        "final_url": str(response.url),
        "status": response.status_code,
        "content_type": doc.content_type,
    })
    if response.status_code >= 300:
        doc.parse_error = f"HTTP {response.status_code}"
        return doc

    parsed = parse_openapi(response.content, doc.content_type or "", doc.url)
    parsed.source = source
    parsed.downloaded = True
    parsed.status_code = doc.status_code
    parsed.redirected_from = doc.redirected_from
    parsed.attempts = doc.attempts
    parsed.content_type = doc.content_type

    if parsed.parsed:
        return parsed

    content_type = (doc.content_type or "").lower()
    text = response.text
    if "html" in content_type or "<html" in text[:400].lower():
        for spec_url in extract_swagger_ui_spec_urls(text, str(response.url)):
            nested = await fetch_openapi(spec_url, auth, timeout=timeout, source=source)
            nested.attempts = doc.attempts + nested.attempts
            if nested.parsed:
                return nested
        parsed.parse_error = "HTML page did not yield a parseable OpenAPI document"
    return parsed
