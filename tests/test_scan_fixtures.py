"""In-process fixtures: a clean JSON API and a vulnerable JSON API.

These tests do not hit the network. They exercise schema probe, coverage,
auth probe, and the quality gate against Starlette apps via httpx ASGI.
"""
from __future__ import annotations

import httpx
import pytest
import yaml
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

CLEAN_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "clean", "version": "1.0.0"},
    "servers": [{"url": "http://clean.test"}],
    "paths": {
        "/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        "/items": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "ok"}, "401": {"description": "auth"}},
            }
        },
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}

VULN_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "vuln", "version": "1.0.0"},
    "servers": [{"url": "http://vuln.test"}],
    "paths": {
        "/health": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
        "/users/{id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}


def _clean_app():
    async def openapi(_request: Request):
        return JSONResponse(CLEAN_SPEC)

    async def openapi_yaml(_request: Request):
        return Response(yaml.safe_dump(CLEAN_SPEC), media_type="application/yaml")

    async def health(_request: Request):
        return JSONResponse({"status": "ok"})

    async def items(request: Request):
        if request.headers.get("authorization") != "Bearer good":
            return JSONResponse({"detail": "unauthorized"}, status_code=401)
        return JSONResponse([{"id": 1}])

    return Starlette(routes=[
        Route("/openapi.json", openapi),
        Route("/openapi.yaml", openapi_yaml),
        Route("/health", health),
        Route("/items", items),
    ])


def _vuln_app():
    async def openapi(_request: Request):
        return JSONResponse(VULN_SPEC)

    async def openapi_yaml(_request: Request):
        return Response(yaml.safe_dump(VULN_SPEC), media_type="application/yaml")

    async def health(_request: Request):
        return JSONResponse({"status": "ok"})

    async def user(request: Request):
        # Broken auth: always returns another user's record.
        return JSONResponse({"id": request.path_params["id"], "email": "victim@example.com"})

    return Starlette(routes=[
        Route("/openapi.json", openapi),
        Route("/openapi.yaml", openapi_yaml),
        Route("/health", health),
        Route("/users/{id}", user),
    ])


@pytest.mark.asyncio
async def test_yaml_openapi_is_parsed_with_nonzero_paths(monkeypatch):
    from lib.openapi import fetch_openapi

    transport = httpx.ASGITransport(app=_clean_app())

    async def handler(request):
        async with httpx.AsyncClient(transport=transport, base_url="http://clean.test") as client:
            return await client.send(request)

    # fetch_openapi constructs its own client; patch AsyncClient to use ASGI.
    real_client = httpx.AsyncClient

    class ASGIClient(real_client):
        def __init__(self, *args, **kwargs):
            kwargs.pop("verify", None)
            kwargs["transport"] = httpx.ASGITransport(app=_clean_app())
            kwargs.setdefault("base_url", "http://clean.test")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", ASGIClient)
    doc = await fetch_openapi("http://clean.test/openapi.yaml", source="discovered")
    assert doc.parsed is True
    assert doc.format == "yaml"
    assert doc.paths_count == 2
    assert doc.operations_count == 2


@pytest.mark.asyncio
async def test_clean_api_auth_probe_does_not_flag_health_or_protected_items(monkeypatch, scan_state):
    from tools.auth_probe import run_auth_probe

    class ASGIClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs.pop("verify", None)
            kwargs["transport"] = httpx.ASGITransport(app=_clean_app())
            kwargs.setdefault("base_url", "http://clean.test")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", ASGIClient)
    await scan_state.create_scan("clean1", "http://clean.test")
    findings = await run_auth_probe(
        "clean1",
        "http://clean.test",
        "memory",
        schema_content=CLEAN_SPEC,
        auth={"type": "bearer", "token": "good"},
        allow_mutating=False,
        schema_source="discovered",
    )
    titles = " ".join(f["title"] for f in findings)
    assert "/health" not in titles
    assert findings == []


@pytest.mark.asyncio
async def test_vulnerable_api_reports_protected_route_without_token(monkeypatch, scan_state):
    from tools.auth_probe import run_auth_probe

    class ASGIClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs.pop("verify", None)
            kwargs["transport"] = httpx.ASGITransport(app=_vuln_app())
            kwargs.setdefault("base_url", "http://vuln.test")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", ASGIClient)
    await scan_state.create_scan("vuln1", "http://vuln.test")
    findings = await run_auth_probe(
        "vuln1",
        "http://vuln.test",
        "memory",
        schema_content=VULN_SPEC,
        auth={"type": "bearer", "token": "good"},
        allow_mutating=False,
        schema_source="discovered",
    )
    assert findings, "protected /users/{id} returning 2xx without auth must be reported"
    assert findings[0]["classification"] in {"confirmed", "suspicious"}
    assert findings[0]["evidence"]["auth_compared"] is True
    assert "users" in findings[0]["endpoint"]


@pytest.mark.asyncio
async def test_auth_probe_skips_auto_generated_schema(scan_state):
    from tools.auth_probe import run_auth_probe

    await scan_state.create_scan("gen1", "http://clean.test")
    findings = await run_auth_probe(
        "gen1",
        "http://clean.test",
        "/tmp/generated.json",
        schema_content=CLEAN_SPEC,
        schema_source="auto_generated",
    )
    assert findings == []


@pytest.mark.asyncio
async def test_crawl_does_not_send_delete_by_default(monkeypatch, scan_state):
    from tools import discovery as discovery_mod

    methods_seen: list[str] = []

    class RecorderTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            methods_seen.append(request.method)
            return httpx.Response(200, json={"ok": True}, headers={"content-type": "application/json"})

    class ASGIClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs.pop("verify", None)
            kwargs["transport"] = RecorderTransport()
            kwargs.setdefault("base_url", "http://clean.test")
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", ASGIClient)
    await scan_state.create_scan("crawl1", "http://clean.test")
    await discovery_mod.run_api_crawl("crawl1", "http://clean.test", allow_mutating=False, max_depth=0, max_urls=5)
    assert "DELETE" not in methods_seen
    assert "POST" not in methods_seen
    assert "PUT" not in methods_seen
    assert "GET" in methods_seen
    assert "OPTIONS" in methods_seen or "HEAD" in methods_seen


def test_web_results_contract_keys():
    """WEB reads these keys; additive extras are fine, removals are not."""
    from lib.scan_state import Finding

    finding = Finding.validate_dict({
        "id": "X",
        "title": "T",
        "severity": "info",
        "confidence": 0.5,
        "category": "Hardening",
        "endpoint": "https://example.com",
        "source_tools": ["vulnapi"],
        "evidence": {"id": "headers.cors"},
        "repro": {"note": "n"},
        "classification": "hardening",
        "validation_status": "observed",
    })
    assert {"id", "title", "severity", "confidence", "category", "endpoint", "source_tools", "evidence", "repro"}.issubset(finding)
    results_keys = {"status", "findings", "endpoints", "schema", "tool_health", "ai_analysis"}
    # Document the live envelope; extras coverage/quality_summary are additive.
    assert "coverage" not in results_keys
