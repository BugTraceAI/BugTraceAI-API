"""Safe, evidence-based replay of model-generated PoC requests.

The AI phase must never execute arbitrary shell text returned by a model.  This
module extracts only a curl request, rejects shell syntax and state-changing
methods, and replays GET/HEAD/OPTIONS directly through httpx.  A successful
replay means that the request was observed again; it is deliberately *not* a
claim that exploitation has been proven.
"""

from __future__ import annotations

import re
import shlex
import time
import json
import hashlib
from typing import Any
from urllib.parse import urlparse

import httpx

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_SHELL_SYNTAX = re.compile(r"(?:\$\(|\$\{|`|;|&&|\|\||(?<!\\)\||>|<)" )
_CURL_LINE = re.compile(r"(?:^|\s)curl(?:\s|$)([^\n]+)", re.IGNORECASE)
_UNRESOLVED_PLACEHOLDER = re.compile(
    r"(?:\$[A-Za-z_][A-Za-z0-9_]*|\{\{?[^}]+\}?\}|<[^>]+>)"
)


def _join_continuations(text: str) -> str:
    lines: list[str] = []
    pending = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if pending:
            pending += " " + line
        else:
            pending = line
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
        else:
            lines.append(pending)
            pending = ""
    if pending:
        lines.append(pending)
    return "\n".join(lines)


def _extract_command(poc: str) -> str | None:
    for line in _join_continuations(poc).splitlines():
        match = _CURL_LINE.search(line)
        if match:
            command = f"curl {match.group(1).strip()}"
            if not _SHELL_SYNTAX.search(command):
                return command
    return None


def _parse_command(command: str, target: str) -> tuple[str, str] | tuple[None, str]:
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError as exc:
        return None, f"invalid curl syntax: {exc}"
    if not tokens or tokens[0].lower() != "curl":
        return None, "no curl command found"

    method = "GET"
    url = ""
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-X", "--request"}:
            if index + 1 >= len(tokens):
                return None, "curl request method is missing"
            method = tokens[index + 1].upper()
            index += 2
            continue
        if token.startswith("--request="):
            method = token.split("=", 1)[1].upper()
            index += 1
            continue
        if token in {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form"}:
            return None, "state-changing request body rejected by safe validator"
        if token.startswith(("--data", "--form")):
            return None, "state-changing request body rejected by safe validator"
        if token in {"-H", "--header", "-u", "--user", "-e", "--referer", "--cookie"}:
            # Headers/auth are intentionally not replayed.  The validator is a
            # public, unauthenticated observation and never receives secrets.
            index += 2
            continue
        if token.startswith(("http://", "https://")):
            url = token
        elif token.startswith("/") and not url:
            url = target.rstrip("/") + token
        index += 1

    if method not in SAFE_METHODS:
        return None, f"HTTP method {method} is not allowed by safe validator"
    if not url:
        return None, "curl command did not contain an absolute or target-relative URL"
    if _UNRESOLVED_PLACEHOLDER.search(url):
        return None, "request URL contains an unresolved placeholder"
    parsed = urlparse(url)
    target_parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or parsed.hostname != target_parsed.hostname:
        return None, "request URL is outside the scan target origin"
    if target_parsed.port and parsed.port and parsed.port != target_parsed.port:
        return None, "request URL uses a different target port"
    if parsed.username or parsed.password:
        return None, "embedded URL credentials are rejected"
    return method, url


async def replay_safe_poc(
    finding: dict[str, Any],
    poc: str,
    target: str,
) -> dict[str, Any]:
    """Replay the original structured observation, never a curl scraped from prose."""
    request, error = request_from_finding(finding, target)
    if error:
        return {"status": "skipped_unsafe", "reason": error, "confirmed": False}
    return await replay_request(request, finding, target)


def request_from_finding(finding: dict[str, Any], target: str):
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    repro = finding.get("repro") if isinstance(finding.get("repro"), dict) else {}
    request = finding.get("request_spec") or evidence.get("request_spec")
    if not isinstance(request, dict):
        endpoint = str(evidence.get("url") or finding.get("endpoint") or repro.get("url") or "")
        parts = endpoint.split(" ", 1)
        method = str(evidence.get("method") or repro.get("method") or "GET").upper()
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            method, endpoint = parts[0].upper(), parts[1]
        query = evidence.get("query_params") or {}
        if query and not isinstance(query, dict):
            return None, "query parameters have no executable name/value mapping"
        request = {"method": method, "url": endpoint, "query": query,
                   "headers": evidence.get("request_headers") or {},
                   "body": evidence.get("request_body")}
    request = dict(request)
    request.setdefault("method", "GET")
    error = validate_request(request, target)
    return (None, error) if error else (request, None)


def validate_request(request: dict[str, Any], target: str) -> str | None:
    try:
        url = str(request.get("url") or "")
        parsed, scope = urlparse(url), urlparse(target)
        def origin(p):
            return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)
        if parsed.scheme not in {"http", "https"} or origin(parsed) != origin(scope):
            return "request outside target origin"
        if parsed.username or parsed.password or _UNRESOLVED_PLACEHOLDER.search(url):
            return "request contains credentials or unresolved placeholders"
        if str(request.get("method")).upper() not in SAFE_METHODS or request.get("body"):
            return "request blocked by safe replay policy"
        headers = request.get("headers") or {}
        if not isinstance(headers, dict) or any(str(k).lower() in {"host", "content-length", "transfer-encoding"} or "\n" in str(v) or "\r" in str(v) for k, v in headers.items()):
            return "invalid request headers"
        if any("redact" in str(v).lower() for v in headers.values()):
            return "authentication/header value is redacted; original credentials required"
        if not isinstance(request.get("query") or {}, dict):
            return "invalid query mapping"
    except (TypeError, ValueError):
        return "invalid request specification"
    return None


async def replay_request(request: dict[str, Any], finding: dict[str, Any], target: str) -> dict[str, Any]:
    error = validate_request(request, target)
    if error:
        return {"status": "skipped_unsafe", "reason": error, "confirmed": False}
    method, url = str(request["method"]).upper(), str(request["url"])
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=8.0,
            headers={"User-Agent": "BugTraceAI-API/ai-validator", "Accept": "*/*"},
        ) as client:
            response = await client.request(method, url, headers=request.get("headers") or {}, params=request.get("query") or None)
        elapsed_ms = int((time.monotonic() - started) * 1000)
        evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
        expected = evidence.get("response_code") or evidence.get("status")
        expected_code = int(expected) if str(expected).isdigit() else None
        from lib.findings_quality import _response_bodies, is_not_found_response
        bodies = _response_bodies(finding)
        body_matches = any(body.strip() == response.text.strip() for body in bodies)
        absent = is_not_found_response({"evidence": {"response_code": response.status_code, "response_body": response.text}})
        evidence_id = hashlib.sha256(json.dumps([method, str(response.url), response.status_code, response.text], ensure_ascii=False).encode()).hexdigest()[:20]
        return {
            "status": "replayed",
            "method": method,
            "url": url,
            "evidence_id": evidence_id,
            "request_source": "structured_original",
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type"),
            "response_headers": {
                key: response.headers[key]
                for key in ("access-control-allow-origin", "content-security-policy", "x-frame-options", "www-authenticate")
                if key in response.headers
            },
            "body_preview": response.text[:500],
            "duration_ms": elapsed_ms,
            "matches_evidence": bool(bodies) and body_matches and (expected_code is None or response.status_code == expected_code),
            "not_found": absent,
            "confirmed": False,
            "note": "Safe replay observed a response; exploitation is not automatically confirmed.",
        }
    except Exception as exc:
        return {
            "status": "error",
            "method": method,
            "url": url,
            "duration_ms": int((time.monotonic() - started) * 1000),
            "reason": str(exc)[:500],
            "confirmed": False,
        }
