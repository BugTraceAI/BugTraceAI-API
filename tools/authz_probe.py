"""BOLA / BFLA comparative probe (two principals, same object).

Copies the HTTP client pattern from ``tools/auth_probe.py``. Does **not** use
the auth_probe BOLA stub (same URL, id=1, only after unauth 2xx).

Requires ``auth`` and ``auth_alt``. Confirms only when principal B receives
principal A's object (BOLA) or principal A reaches an admin/function path (BFLA).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from typing import Any

import httpx

from lib.auth_header import auth_headers_dict
from lib.coverage import body_hash
from lib.evidence import save_artifact
from lib.http_policy import is_allowed
from lib.openapi import extract_operations, join_spec_url
from lib.redact import redact_headers, redact_text
from lib.scan_state import scan_state

logger = logging.getLogger("bugtrace-api.tools.authz_probe")

PROBE_TIMEOUT = 10.0
MAX_CONCURRENT = 5
MAX_COLLECTIONS = 5
MAX_IDS = 15
MAX_BFLA = 20

def _looks_like_id_name(name: str) -> bool:
    """True for typical object-key names in any API, not a target-specific list.

    Matches ``id``, ``uuid``, ``guid``, ``pk``, ``*id`` / ``*_id`` (userId,
    pet_id, invoiceId). A lone path parameter is also treated as the object key
    even when it is ``sku`` or ``slug``.
    """
    n = str(name or "").strip()
    if not n:
        return False
    lowered = n.lower()
    if lowered in {"id", "_id", "uuid", "guid", "pk"}:
        return True
    return lowered.endswith(("id", "_id"))

_PUBLIC_PATH_RE = re.compile(
    r"(?i)/(health|ready|readiness|live|liveness|status|version|info|"
    r"docs|redoc|swagger|openapi|favicon|login|register|oauth|token|"
    r"well-known)(/|$)"
)
_NOT_FOUND_BODY = re.compile(
    r'(?i)"error"\s*:\s*"(not found|not_found)"|"detail"\s*:\s*"not found"'
)
_ADMIN_RE = re.compile(
    r"/(admin|manage|internal|debug|secure-portal)(/|$)|\b(admin|manage|internal)\b",
    re.IGNORECASE,
)


def _is_public_path(path: str) -> bool:
    if path in {"", "/"}:
        return True
    return bool(_PUBLIC_PATH_RE.search(path))


def _is_not_found_body(body: str) -> bool:
    text = (body or "").strip()
    if not text:
        return False
    return bool(_NOT_FOUND_BODY.search(text))


def _is_generic_error(parsed: Any, body: str) -> bool:
    if _is_not_found_body(body):
        return True
    if parsed is None:
        return not (body or "").strip()
    if parsed in ([], {}):
        return True
    return bool(
        isinstance(parsed, dict)
        and parsed
        and set(parsed.keys()) <= {"error", "detail", "message"}
    )


def _parse_json(body: str, content_type: str) -> Any:
    if "json" not in (content_type or "").lower() and not (body or "").lstrip().startswith(("{", "[")):
        return None
    try:
        return json.loads(body)
    except Exception:
        return None


def extract_ids(payload: Any, extra_keys: tuple[str, ...] = ()) -> list[str]:
    """Pull object identifiers from a JSON list/object. Order-preserving, capped."""
    found: list[str] = []
    seen: set[str] = set()
    extra = {str(k) for k in extra_keys if k}

    def walk(node: Any) -> None:
        if len(found) >= MAX_IDS:
            return
        if isinstance(node, list):
            for item in node:
                walk(item)
        elif isinstance(node, dict):
            for key, value in node.items():
                if value in (None, "", [], {}):
                    continue
                if not (_looks_like_id_name(str(key)) or str(key) in extra):
                    continue
                if isinstance(value, (list, dict)):
                    continue
                text = str(value)
                if text not in seen:
                    seen.add(text)
                    found.append(text)
            for value in node.values():
                if isinstance(value, (list, dict)):
                    walk(value)

    walk(payload)
    return found[:MAX_IDS]


def _path_params(operation: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for param in operation.get("parameters") or []:
        if not isinstance(param, dict):
            continue
        if str(param.get("in") or "") != "path":
            continue
        name = str(param.get("name") or "")
        if name:
            names.append(name)
    return names


def _id_path_param(operation: dict[str, Any]) -> str | None:
    names = _path_params(operation)
    for name in names:
        if _looks_like_id_name(name):
            return name
    if len(names) == 1:
        return names[0]
    return None


def _is_collection(operation: dict[str, Any]) -> bool:
    return operation.get("method") == "GET" and not _path_params(operation)


def _is_item(operation: dict[str, Any]) -> bool:
    return bool(_id_path_param(operation))


def _collection_matches_item(collection_path: str, item_path: str) -> bool:
    prefix = collection_path.rstrip("/")
    return item_path.startswith(prefix + "/{")


def _substitute(spec_path: str, param_name: str, value: str) -> str:
    return spec_path.replace("{" + param_name + "}", str(value))


def _is_admin_op(operation: dict[str, Any]) -> bool:
    blob = " ".join(
        [
            str(operation.get("path") or ""),
            str(operation.get("operation_id") or ""),
            str(operation.get("summary") or ""),
            " ".join(str(t) for t in (operation.get("tags") or [])),
        ]
    )
    return bool(_ADMIN_RE.search(blob))


async def _probe_endpoint(
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    async with semaphore:
        try:
            resp = await client.request(method, url, headers=headers or {})
            raw = resp.text
            parsed = _parse_json(raw, resp.headers.get("content-type", ""))
            return {
                "status_code": resp.status_code,
                "headers": redact_headers(dict(resp.headers)),
                "body": redact_text(raw[:500]),
                "json": parsed,
                "size": len(resp.content or b""),
                "content_type": resp.headers.get("content-type", ""),
                "body_hash": body_hash(resp.content),
            }
        except httpx.TimeoutException:
            return {"status_code": -1, "error": "timeout", "body": "", "json": None}
        except Exception as exc:
            return {"status_code": -1, "error": str(exc)[:200], "body": "", "json": None}


def _ok(result: dict[str, Any]) -> bool:
    status = int(result.get("status_code") or -1)
    return 200 <= status < 300


def _denied(result: dict[str, Any]) -> bool:
    return int(result.get("status_code") or -1) in {401, 403}


def _body_has_id(result: dict[str, Any], oid: str) -> bool:
    blob = result.get("body") or ""
    if _is_generic_error(result.get("json"), blob):
        return False
    return str(oid) in blob


def _finding(
    counter: int,
    *,
    kind: str,
    title: str,
    severity: str,
    classification: str,
    endpoint: str,
    method: str,
    path: str,
    url: str,
    oid: str | None,
    result_a: dict[str, Any],
    result_b: dict[str, Any] | None,
    result_unauth: dict[str, Any] | None,
    reason: str,
) -> dict[str, Any]:
    primary = result_b or result_a
    status = primary.get("status_code")
    snippet = str(primary.get("body") or "")[:400]
    similar = False
    if result_b:
        similar = body_hash(result_a.get("body") or "") == body_hash(result_b.get("body") or "")
    validation = "confirmed" if classification == "confirmed" else "needs_validation"
    evidence = {
        "kind": kind,
        "http_method": method,
        "path": path,
        "response_code": str(status),
        "status_code": status,
        "response_snippet": snippet,
        "principal_a_status": result_a.get("status_code"),
        "principal_b_status": (result_b or {}).get("status_code"),
        "unauth_status": (result_unauth or {}).get("status_code"),
        "object_id": oid,
        "auth_compared": True,
        "authz_compared": True,
        "bodies_similar": similar,
        "classification_reason": reason,
    }
    return {
        "id": f"AZ-{counter:04d}",
        "title": title,
        "severity": severity,
        "confidence": 0.86 if classification == "confirmed" else 0.55,
        "category": (
            "Broken Object Level Authorization"
            if kind == "bola"
            else "Broken Function Level Authorization"
        ),
        "endpoint": f"{method} {url}",
        "source_tools": ["authz_probe"],
        "classification": classification,
        "validation_status": validation,
        "evidence": evidence,
        "repro": {
            "method": method,
            "curl": f"curl -s -X {method} '{url}'",
            "status": str(status),
            "note": reason,
        },
    }


async def run_authz_probe(
    scan_id: str,
    target: str,
    schema_url: str,
    schema_content: dict[str, Any] | None = None,
    auth: dict[str, Any] | None = None,
    auth_alt: dict[str, Any] | None = None,
    allow_mutating: bool = False,
    schema_source: str | None = None,
) -> list[dict[str, Any]]:
    started = time.monotonic()
    auth_headers = auth_headers_dict(auth)
    alt_headers = auth_headers_dict(auth_alt)
    if not auth_headers or not alt_headers:
        logger.info(f"[scan:{scan_id}] AuthzProbe: skipped (need auth and auth_alt)")
        await scan_state.update_tool_health(
            scan_id, "authz_probe",
            status="skipped", attempts=0, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="missing_dual_auth",
        )
        return []

    if schema_source == "auto_generated":
        await scan_state.update_tool_health(
            scan_id, "authz_probe",
            status="skipped", attempts=0, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="auto_generated_schema",
        )
        return []

    schema = schema_content
    if not schema or not schema.get("paths"):
        await scan_state.update_tool_health(
            scan_id, "authz_probe",
            status="skipped", attempts=0, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="no_schema_paths",
        )
        return []

    operations = extract_operations(schema, target)
    collections = [op for op in operations if _is_collection(op) and not _is_public_path(op["path"])][:MAX_COLLECTIONS]
    items = [op for op in operations if _is_item(op) and not _is_public_path(op["path"])]
    admin_ops = [
        op for op in operations
        if _is_admin_op(op)
        and not _is_public_path(op["path"])
        and not _path_params(op)
        and is_allowed(op["method"], allow_mutating)
    ][:MAX_BFLA]

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    findings: list[dict[str, Any]] = []
    counter = 0
    probed = 0

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=PROBE_TIMEOUT,
        verify=False,
        headers={
            "User-Agent": "BugTraceAI-AuthzProbe/1.2",
            "Accept": "application/json",
        },
    ) as client:
        for collection in collections:
            if not is_allowed(collection["method"], allow_mutating):
                continue
            if collection.get("auth_required") is False:
                continue
            listed_a = await _probe_endpoint(
                client, semaphore, collection["method"], collection["url"], auth_headers
            )
            listed_b = await _probe_endpoint(
                client, semaphore, collection["method"], collection["url"], alt_headers
            )
            listed_unauth = await _probe_endpoint(
                client, semaphore, collection["method"], collection["url"], {}
            )
            probed += 3
            if not _ok(listed_a) or _is_generic_error(listed_a.get("json"), listed_a.get("body") or ""):
                continue
            # Public collection: unauthenticated GET already returns objects. Not BOLA.
            if _ok(listed_unauth) and not _is_generic_error(
                listed_unauth.get("json"), listed_unauth.get("body") or ""
            ):
                continue
            extra = tuple(
                _id_path_param(item) or ""
                for item in items
                if _collection_matches_item(collection["path"], item["path"])
            )
            extra = tuple(name for name in extra if name)
            ids_a = extract_ids(listed_a.get("json"), extra_keys=extra)
            ids_b = set(extract_ids(listed_b.get("json"), extra_keys=extra)) if _ok(listed_b) else set()
            unique_a = [oid for oid in ids_a if oid not in ids_b]
            matching_items = [
                item for item in items
                if _collection_matches_item(collection["path"], item["path"])
                and is_allowed(item["method"], False)
            ]
            if not unique_a and ids_a and ids_b.intersection(ids_a) and _denied(listed_unauth):
                counter += 1
                findings.append(_finding(
                    counter,
                    kind="bola",
                    title=f"BOLA: principal B listed the same objects as A on {collection['path']}",
                    severity="high",
                    classification="confirmed",
                    endpoint=f"{collection['method']} {collection['url']}",
                    method=collection["method"],
                    path=collection["path"],
                    url=collection["url"],
                    oid=",".join(ids_a[:5]),
                    result_a=listed_a,
                    result_b=listed_b,
                    result_unauth=listed_unauth,
                    reason=(
                        "Protected collection returned the same object IDs to two principals; "
                        "unauthenticated access is denied"
                    ),
                ))
            for oid in unique_a:
                for item in matching_items:
                    param = _id_path_param(item)
                    if not param:
                        continue
                    concrete = _substitute(item["path"], param, oid)
                    url = join_spec_url(target, concrete, schema)
                    result_a = await _probe_endpoint(client, semaphore, "GET", url, auth_headers)
                    result_b = await _probe_endpoint(client, semaphore, "GET", url, alt_headers)
                    result_unauth = await _probe_endpoint(client, semaphore, "GET", url, {})
                    probed += 3
                    if not _ok(result_a):
                        continue
                    if _ok(result_unauth) and _body_has_id(result_unauth, oid):
                        continue
                    if _denied(result_b) or not _ok(result_b):
                        continue
                    if not _body_has_id(result_b, oid):
                        continue
                    counter += 1
                    findings.append(_finding(
                        counter,
                        kind="bola",
                        title=f"BOLA: principal B read object {oid} via GET {item['path']}",
                        severity="high",
                        classification="confirmed",
                        endpoint=f"GET {url}",
                        method="GET",
                        path=item["path"],
                        url=url,
                        oid=oid,
                        result_a=result_a,
                        result_b=result_b,
                        result_unauth=result_unauth,
                        reason=(
                            f"Object {oid} appeared only in principal A's list; principal B "
                            "still read it. Unauthenticated access is denied."
                        ),
                    ))

        for op in admin_ops:
            if not is_allowed(op["method"], allow_mutating):
                continue
            if op["method"] != "GET" and not allow_mutating:
                continue
            result_a = await _probe_endpoint(
                client, semaphore, op["method"], op["url"], auth_headers
            )
            probed += 1
            if not _ok(result_a) or _is_generic_error(result_a.get("json"), result_a.get("body") or ""):
                continue
            result_unauth = await _probe_endpoint(
                client, semaphore, op["method"], op["url"], {}
            )
            probed += 1
            classification = "confirmed" if _denied(result_unauth) else "suspicious"
            counter += 1
            findings.append(_finding(
                counter,
                kind="bfla",
                title=f"BFLA: principal A reached {op['method']} {op['path']}",
                severity="high" if classification == "confirmed" else "medium",
                classification=classification,
                endpoint=f"{op['method']} {op['url']}",
                method=op["method"],
                path=op["path"],
                url=op["url"],
                oid=None,
                result_a=result_a,
                result_b=None,
                result_unauth=result_unauth,
                reason="Low-privilege principal reached an admin/internal operation",
            ))

    duration_ms = int((time.monotonic() - started) * 1000)
    save_artifact(scan_id, "authz_probe", "findings_authz_probe", findings)
    save_artifact(scan_id, "authz_probe", "probe_summary", {
        "collections": len(collections),
        "item_ops": len(items),
        "admin_ops": len(admin_ops),
        "probed": probed,
        "findings_count": len(findings),
        "duration_ms": duration_ms,
        "allow_mutating": allow_mutating,
    })
    await scan_state.update_tool_health(
        scan_id, "authz_probe",
        status="ok" if findings else "clean",
        attempts=probed,
        findings_count=len(findings),
        duration_ms=duration_ms,
        error=None,
    )
    for finding in findings:
        await scan_state.add_finding(scan_id, finding)
    logger.info(f"[scan:{scan_id}] AuthzProbe: {len(findings)} finding(s) in {duration_ms}ms")
    return findings
