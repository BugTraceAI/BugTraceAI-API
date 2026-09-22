"""Unauthenticated vs authenticated endpoint comparison.

Findings are emitted only when there is comparative evidence, or when a
spec-declared protected operation returns 2xx without a token. Public
paths, 400/422 validation errors, and auto-generated specs without
security requirements are not vulnerabilities.
"""

import asyncio
import logging
import os
import re
import time
import urllib.parse as urllib_parse
from pathlib import Path
from typing import Any

import httpx

from lib.auth_header import auth_headers_dict
from lib.coverage import body_hash
from lib.evidence import save_artifact
from lib.http_policy import is_allowed
from lib.openapi import join_spec_url, parse_openapi
from lib.redact import redact_headers, redact_text
from lib.scan_state import scan_state

logger = logging.getLogger("bugtrace-api.tools.auth_probe")

PROBE_TIMEOUT = 10.0
MAX_CONCURRENT = 5
MAX_ENDPOINTS = 200

_PUBLIC_PATH_RE = re.compile(
    r"(?i)/(health|ready|readiness|live|liveness|status|version|info|"
    r"docs|redoc|swagger|openapi|favicon|login|register|oauth|token|"
    r"well-known)(/|$)"
)


def _is_security_absent(operation: dict[str, Any], global_security: list) -> bool:
    """Return True if this operation has no effective security requirement."""
    if "security" in operation:
        op_sec = operation["security"]
        if op_sec == [] or op_sec == [{}]:
            return True
        if op_sec:
            return False
        return True
    return bool(not global_security)


def _security_required(operation: dict[str, Any], global_security: list) -> bool | None:
    if "security" in operation:
        op_sec = operation["security"]
        if op_sec == [] or op_sec == [{}]:
            return False
        if op_sec:
            return True
        return None
    if global_security:
        return True
    return None


_NOT_FOUND_BODY = re.compile(
    r'(?i)"error"\s*:\s*"(not found|not_found)"|"detail"\s*:\s*"not found"'
)


def _is_not_found_body(body: str) -> bool:
    text = (body or "").strip()
    if not text:
        return False
    return bool(_NOT_FOUND_BODY.search(text))


def _extract_endpoints(schema: dict[str, Any], target: str) -> list[dict[str, Any]]:
    endpoints = []
    global_security = schema.get("security", [])
    paths = schema.get("paths", {})
    http_methods = {"get", "post", "put", "patch", "delete", "head", "options"}

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in http_methods:
                continue
            if not isinstance(operation, dict):
                continue
            concrete_path = re.sub(r"\{[^}]+\}", "1", path)
            full_url = join_spec_url(target, concrete_path, schema)
            endpoints.append({
                "method": method.upper(),
                "path": path,
                "url": full_url,
                "summary": operation.get("summary", ""),
                "operation_id": operation.get("operationId", ""),
                "auth_required": _security_required(operation, global_security),
                "security_absent": _is_security_absent(operation, global_security),
            })

    return endpoints[:MAX_ENDPOINTS]


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
            body = resp.text[:500]
            return {
                "status_code": resp.status_code,
                "headers": redact_headers(dict(resp.headers)),
                "body": redact_text(body),
                "size": len(resp.content or b""),
                "content_type": resp.headers.get("content-type", ""),
                "body_hash": body_hash(resp.content),
            }
        except httpx.TimeoutException:
            return {"status_code": -1, "error": "timeout"}
        except Exception as e:
            return {"status_code": -1, "error": str(e)[:200]}


def _is_public_path(path: str) -> bool:
    if path in {"", "/"}:
        return True
    return bool(_PUBLIC_PATH_RE.search(path))


def _bodies_similar(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return body_hash(left) == body_hash(right) or left[:120] == right[:120]


async def run_auth_probe(
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
    logger.info(f"[scan:{scan_id}] AuthProbe: starting against {target}")

    if schema_source == "auto_generated":
        logger.info(f"[scan:{scan_id}] AuthProbe: skipping auto-generated schema (no security contract)")
        await scan_state.update_tool_health(
            scan_id, "auth_probe",
            status="skipped", attempts=0, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="auto_generated_schema",
        )
        return []

    schema = schema_content
    if schema is None:
        schema = await _fetch_schema(schema_url, scan_id)

    if not schema or not schema.get("paths"):
        logger.warning(f"[scan:{scan_id}] AuthProbe: no schema paths — skipping")
        await scan_state.update_tool_health(
            scan_id, "auth_probe",
            status="skipped", attempts=0, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error="no_schema_paths",
        )
        return []

    endpoints = _extract_endpoints(schema, target)
    logger.info(f"[scan:{scan_id}] AuthProbe: {len(endpoints)} operation(s) in spec")
    if not endpoints:
        await scan_state.update_tool_health(
            scan_id, "auth_probe",
            status="ok", attempts=0, findings_count=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            error=None,
        )
        return []

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    findings: list[dict[str, Any]] = []
    finding_counter = 0
    probed = 0
    skipped_mutating = 0
    auth_headers = auth_headers_dict(auth)

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=PROBE_TIMEOUT,
        verify=False,
        headers={
            "User-Agent": "BugTraceAI-AuthProbe/1.2",
            "Accept": "application/json",
        },
    ) as client:
        for ep in endpoints:
            if not is_allowed(ep["method"], allow_mutating):
                skipped_mutating += 1
                continue
            if _is_public_path(ep["path"]):
                continue
            probed += 1
            unauth = await _probe_endpoint(client, semaphore, ep["method"], ep["url"])
            authed = None
            if auth_headers:
                authed = await _probe_endpoint(
                    client, semaphore, ep["method"], ep["url"], headers=auth_headers
                )

            unauth_status = unauth.get("status_code", -1)
            if unauth_status < 0:
                continue
            # Validation errors are not an auth bypass.
            if unauth_status in (400, 404, 405, 415, 422, 429):
                continue
            if 401 <= unauth_status <= 403:
                continue

            if not (200 <= unauth_status < 300):
                continue
            if _is_not_found_body(str(unauth.get("body") or "")):
                continue

            auth_required = ep.get("auth_required")
            if auth_required is False:
                # Spec says public. Accessible is expected.
                continue

            authed_status = authed.get("status_code") if authed else None
            compared = authed is not None
            similar = compared and _bodies_similar(
                str(unauth.get("body") or ""), str(authed.get("body") or "")
            )

            if auth_required is True and compared and similar:
                classification = "confirmed"
                validation_status = "confirmed"
                severity = "high"
                confidence = 0.86
                title = f"[AuthProbe] Protected operation reachable without auth: {ep['method']} {ep['path']}"
                reason = "Spec requires security; unauth and auth responses match"
            elif auth_required is True and not compared:
                classification = "suspicious"
                validation_status = "needs_validation"
                severity = "medium"
                confidence = 0.55
                title = f"[AuthProbe] Spec-protected operation returned 2xx without a token: {ep['method']} {ep['path']}"
                reason = "No comparative authenticated baseline"
            else:
                # Object-level access is owned by authz_probe (two principals + real IDs).
                continue

            finding_counter += 1
            finding = {
                "id": f"AP-{finding_counter:04d}",
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "category": "Broken Authentication / Missing Authorization",
                "endpoint": f"{ep['method']} {ep['url']}",
                "source_tools": ["auth_probe"],
                "classification": classification,
                "validation_status": validation_status,
                "evidence": {
                    "http_method": ep["method"],
                    "path": ep["path"],
                    "response_code": str(unauth_status),
                    "response_snippet": unauth.get("body", "")[:400],
                    "response_headers": unauth.get("headers") or {},
                    "content_type": unauth.get("content_type"),
                    "auth_required_by_spec": auth_required,
                    "auth_compared": compared,
                    "auth_status": authed_status,
                    "bodies_similar": similar,
                    "summary": ep.get("summary", ""),
                    "classification_reason": reason,
                },
                "repro": {
                    "curl": f"curl -s -X {ep['method']} '{ep['url']}'",
                    "method": ep["method"],
                    "status": str(unauth_status),
                    "note": reason,
                },
            }
            findings.append(finding)
            logger.info(
                f"[scan:{scan_id}] AuthProbe: [{classification}] {ep['method']} {ep['path']} → HTTP {unauth_status}"
            )

    duration_ms = int((time.monotonic() - started) * 1000)
    save_artifact(scan_id, "auth_probe", "findings_auth_probe", findings)
    save_artifact(scan_id, "auth_probe", "probe_summary", {
        "endpoints_in_spec": len(endpoints),
        "endpoints_probed": probed,
        "skipped_mutating": skipped_mutating,
        "findings_count": len(findings),
        "duration_ms": duration_ms,
        "allow_mutating": allow_mutating,
    })

    await scan_state.update_tool_health(
        scan_id, "auth_probe",
        status="ok" if findings else "clean",
        attempts=probed,
        findings_count=len(findings),
        duration_ms=duration_ms,
        error=None,
    )
    for finding in findings:
        await scan_state.add_finding(scan_id, finding)
    return findings


async def _fetch_schema(schema_url: str, scan_id: str) -> dict[str, Any] | None:
    if not schema_url:
        return None

    parsed = urllib_parse.urlparse(schema_url)

    if parsed.scheme in ("", "file"):
        path = Path(schema_url).resolve()
        safe_root = Path(os.environ.get("REPORTS_DIR", "/opt/bugtrace-api/reports")).resolve()
        try:
            path.relative_to(safe_root)
        except ValueError:
            logger.warning(f"[scan:{scan_id}] AuthProbe: blocked local schema outside reports dir: {path}")
            return None
        try:
            raw = path.read_bytes()
            document = parse_openapi(raw, url=str(path))
            return document.spec
        except Exception as e:
            logger.warning(f"[scan:{scan_id}] AuthProbe: failed to read local schema {schema_url}: {e}")
            return None

    if parsed.scheme not in ("http", "https"):
        logger.warning(f"[scan:{scan_id}] AuthProbe: unsupported schema scheme: {parsed.scheme}")
        return None

    try:
        host = parsed.hostname or ""
        if _is_private_host(host):
            logger.warning(f"[scan:{scan_id}] AuthProbe: blocked private schema host: {host}")
            return None
    except Exception as e:
        logger.warning(f"[scan:{scan_id}] AuthProbe: failed to validate schema host {schema_url}: {e}")
        return None

    try:
        async with httpx.AsyncClient(timeout=15.0, verify=False, follow_redirects=True) as client:
            resp = await client.get(schema_url)
            resp.raise_for_status()
            document = parse_openapi(resp.content, resp.headers.get("content-type", ""), schema_url)
            return document.spec
    except Exception as e:
        logger.warning(f"[scan:{scan_id}] AuthProbe: failed to fetch schema {schema_url}: {e}")
        return None


def _is_private_host(host: str) -> bool:
    if not host:
        return True
    host = host.lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    if host.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.",
                        "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                        "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                        "172.29.", "172.30.", "172.31.")):
        return True
    if host.startswith("169.254.") or host.endswith(".local") or host == "metadata.google.internal":
        return True
    return False
