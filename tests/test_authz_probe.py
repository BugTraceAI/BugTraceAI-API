"""BOLA/BFLA dual-principal probe — ASGI fixtures, no network."""
from __future__ import annotations

import json

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from lib.findings_quality import CLASS_CONFIRMED, classify_finding
from tools.authz_probe import extract_ids, run_authz_probe

AUTH_A = {"type": "bearer", "token": "user-a-token"}
AUTH_B = {"type": "bearer", "token": "user-b-token"}

SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "orders", "version": "1.0.0"},
    "servers": [{"url": "http://orders.test"}],
    "paths": {
        "/orders": {
            "get": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/orders/{id}": {
            "get": {
                "security": [{"bearerAuth": []}],
                "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/admin/users": {
            "get": {
                "security": [{"bearerAuth": []}],
                "tags": ["admin"],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/admin/reset": {
            "post": {
                "security": [{"bearerAuth": []}],
                "responses": {"200": {"description": "ok"}},
            }
        },
    },
    "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
}


def _who(request: Request) -> str | None:
    auth = request.headers.get("authorization") or ""
    if auth == "Bearer user-a-token":
        return "a"
    if auth == "Bearer user-b-token":
        return "b"
    return None


def _app(*, bola: bool, bfla: bool, not_found_item: bool = False):
    methods_seen: list[str] = []

    async def orders(request: Request):
        methods_seen.append(request.method)
        who = _who(request)
        if who is None:
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        if who == "a":
            return JSONResponse([{"id": 7, "owner": "a"}])
        return JSONResponse([{"id": 9, "owner": "b"}])

    async def order(request: Request):
        methods_seen.append(request.method)
        oid = request.path_params["id"]
        who = _who(request)
        if who is None:
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        if not_found_item:
            return JSONResponse({"error": "Not found"})
        if oid == "7" and who == "a":
            return JSONResponse({"id": 7, "owner": "a"})
        if oid == "9" and who == "b":
            return JSONResponse({"id": 9, "owner": "b"})
        if oid == "7" and who == "b":
            if bola:
                return JSONResponse({"id": 7, "owner": "a"})
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        return JSONResponse({"detail": "forbidden"}, status_code=403)

    async def admin_users(request: Request):
        methods_seen.append(request.method)
        who = _who(request)
        if who is None:
            return JSONResponse({"detail": "Not authenticated"}, status_code=401)
        if who == "a":
            if bfla:
                return JSONResponse([{"id": 1, "email": "victim@example.com"}])
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        return JSONResponse([{"id": 1, "email": "admin-only@example.com"}])

    async def admin_reset(request: Request):
        methods_seen.append(request.method)
        return JSONResponse({"ok": True})

    app = Starlette(routes=[
        Route("/orders", orders),
        Route("/orders/{id}", order),
        Route("/admin/users", admin_users),
        Route("/admin/reset", admin_reset, methods=["POST"]),
    ])
    app.state.methods_seen = methods_seen
    return app


def _patch_client(monkeypatch, app, host="http://orders.test"):
    class ASGIClient(httpx.AsyncClient):
        def __init__(self, *args, **kwargs):
            kwargs.pop("verify", None)
            kwargs["transport"] = httpx.ASGITransport(app=app)
            kwargs.setdefault("base_url", host)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", ASGIClient)
    return app


def test_extract_ids_from_list_and_nested():
    assert extract_ids([{"id": 7, "owner": "a"}, {"id": 8}]) == ["7", "8"]
    assert extract_ids({"data": [{"uuid": "abc"}]}) == ["abc"]
    assert extract_ids({"error": "Not found"}) == []
    assert extract_ids([{"petId": 3, "name": "fido"}]) == ["3"]


@pytest.mark.asyncio
async def test_bola_with_arbitrary_path_param_name(monkeypatch, scan_state):
    """Object key comes from the spec (`petId`), not a hardcoded product/order name."""

    async def pets(request: Request):
        who = _who(request)
        if who is None:
            return JSONResponse({"detail": "unauth"}, status_code=401)
        if who == "a":
            return JSONResponse([{"petId": 3, "owner": "a"}])
        return JSONResponse([{"petId": 9, "owner": "b"}])

    async def pet(request: Request):
        oid = request.path_params["petId"]
        who = _who(request)
        if who is None:
            return JSONResponse({"detail": "unauth"}, status_code=401)
        if oid == "3":
            return JSONResponse({"petId": 3, "owner": "a"})
        if oid == "9" and who == "b":
            return JSONResponse({"petId": 9, "owner": "b"})
        return JSONResponse({"detail": "forbidden"}, status_code=403)

    app = Starlette(routes=[
        Route("/pets", pets),
        Route("/pets/{petId}", pet),
    ])
    _patch_client(monkeypatch, app, host="http://pets.test")
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "pets", "version": "1.0.0"},
        "servers": [{"url": "http://pets.test"}],
        "paths": {
            "/pets": {
                "get": {
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {"description": "ok"}},
                }
            },
            "/pets/{petId}": {
                "get": {
                    "security": [{"bearerAuth": []}],
                    "parameters": [{"name": "petId", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    }
    await scan_state.create_scan("az_pet", "http://pets.test")
    findings = await run_authz_probe(
        "az_pet", "http://pets.test", "memory",
        schema_content=spec, auth=AUTH_A, auth_alt=AUTH_B,
        schema_source="discovered",
    )
    bola = [f for f in findings if f["evidence"].get("kind") == "bola"]
    assert len(bola) == 1
    assert bola[0]["evidence"]["object_id"] == "3"
    assert "/pets/3" in bola[0]["endpoint"]


@pytest.mark.asyncio
async def test_clean_dual_auth_has_no_bola_or_bfla(monkeypatch, scan_state):
    app = _patch_client(monkeypatch, _app(bola=False, bfla=False))
    await scan_state.create_scan("az_clean", "http://orders.test")
    findings = await run_authz_probe(
        "az_clean", "http://orders.test", "memory",
        schema_content=SPEC, auth=AUTH_A, auth_alt=AUTH_B, allow_mutating=False,
        schema_source="discovered",
    )
    assert findings == []
    assert "POST" not in app.state.methods_seen


@pytest.mark.asyncio
async def test_bola_confirmed_same_object_id(monkeypatch, scan_state):
    _patch_client(monkeypatch, _app(bola=True, bfla=False))
    await scan_state.create_scan("az_bola", "http://orders.test")
    findings = await run_authz_probe(
        "az_bola", "http://orders.test", "memory",
        schema_content=SPEC, auth=AUTH_A, auth_alt=AUTH_B, allow_mutating=False,
        schema_source="discovered",
    )
    bola = [f for f in findings if f["evidence"].get("kind") == "bola"]
    assert len(bola) == 1
    finding = bola[0]
    assert finding["classification"] == "confirmed"
    assert finding["evidence"]["object_id"] == "7"
    assert finding["evidence"]["authz_compared"] is True
    assert "7" in finding["endpoint"]
    assert "owner" in finding["evidence"]["response_snippet"]
    blob = json.dumps(finding)
    assert "user-a-token" not in blob
    assert "user-b-token" not in blob
    cls, _reason = classify_finding(finding, "http://orders.test")
    assert cls == CLASS_CONFIRMED
    assert finding["evidence"]["unauth_status"] == 401


@pytest.mark.asyncio
async def test_not_found_body_is_not_bola(monkeypatch, scan_state):
    _patch_client(monkeypatch, _app(bola=True, bfla=False, not_found_item=True))
    await scan_state.create_scan("az_nf", "http://orders.test")
    findings = await run_authz_probe(
        "az_nf", "http://orders.test", "memory",
        schema_content=SPEC, auth=AUTH_A, auth_alt=AUTH_B,
        schema_source="discovered",
    )
    assert [f for f in findings if f["evidence"].get("kind") == "bola"] == []


@pytest.mark.asyncio
async def test_missing_auth_alt_skips(scan_state):
    await scan_state.create_scan("az_skip", "http://orders.test")
    findings = await run_authz_probe(
        "az_skip", "http://orders.test", "memory",
        schema_content=SPEC, auth=AUTH_A, auth_alt=None,
        schema_source="discovered",
    )
    assert findings == []
    results = await scan_state.get_results("az_skip")
    assert results["tool_health"]["authz_probe"]["error"] == "missing_dual_auth"
    assert results["tool_health"]["authz_probe"]["status"] == "skipped"


@pytest.mark.asyncio
async def test_bfla_when_user_reaches_admin(monkeypatch, scan_state):
    _patch_client(monkeypatch, _app(bola=False, bfla=True))
    await scan_state.create_scan("az_bfla", "http://orders.test")
    findings = await run_authz_probe(
        "az_bfla", "http://orders.test", "memory",
        schema_content=SPEC, auth=AUTH_A, auth_alt=AUTH_B, allow_mutating=False,
        schema_source="discovered",
    )
    bfla = [f for f in findings if f["evidence"].get("kind") == "bfla"]
    assert len(bfla) == 1
    assert bfla[0]["classification"] == "confirmed"
    assert "/admin/users" in bfla[0]["endpoint"]
    assert bfla[0]["evidence"]["unauth_status"] == 401


@pytest.mark.asyncio
async def test_public_catalog_is_not_bola(monkeypatch, scan_state):
    """Unauth GET 200 on the collection is a public catalog, not BOLA."""
    methods_seen: list[str] = []

    async def products(request: Request):
        methods_seen.append(request.method)
        return JSONResponse([{"id": 1, "name": "widget"}])

    async def product(request: Request):
        methods_seen.append(request.method)
        return JSONResponse({"id": 1, "name": "widget"})

    app = Starlette(routes=[
        Route("/products", products),
        Route("/products/{id}", product),
    ])
    _patch_client(monkeypatch, app, host="http://shop.test")
    spec = {
        "openapi": "3.0.0",
        "info": {"title": "shop", "version": "1.0.0"},
        "servers": [{"url": "http://shop.test"}],
        "paths": {
            "/products": {"get": {"security": [], "responses": {"200": {"description": "ok"}}}},
            "/products/{id}": {
                "get": {
                    "security": [],
                    "parameters": [{"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }
    await scan_state.create_scan("az_pub", "http://shop.test")
    findings = await run_authz_probe(
        "az_pub", "http://shop.test", "memory",
        schema_content=spec, auth=AUTH_A, auth_alt=AUTH_B,
        schema_source="discovered",
    )
    assert [f for f in findings if f["evidence"].get("kind") == "bola"] == []


def test_auth_probe_bola_stub_is_not_confirmed_by_category():
    finding = {
        "id": "AP-0001",
        "title": "[AuthProbe] Possible BOLA (needs validation): GET /items/{id}",
        "severity": "medium",
        "confidence": 0.5,
        "category": "Broken Authentication / Missing Authorization",
        "endpoint": "GET https://api.example.com/items/1",
        "source_tools": ["auth_probe"],
        "evidence": {
            "http_method": "GET",
            "path": "/items/{id}",
            "response_code": "200",
            "response_snippet": '{"id":1}',
            "auth_compared": True,
        },
        "repro": {"curl": "curl -s -X GET 'https://api.example.com/items/1'", "method": "GET"},
    }
    classification, _reason = classify_finding(finding, "https://api.example.com")
    assert classification != CLASS_CONFIRMED


@pytest.mark.asyncio
async def test_mutating_admin_post_skipped_without_grant(monkeypatch, scan_state):
    app = _patch_client(monkeypatch, _app(bola=False, bfla=False))
    await scan_state.create_scan("az_post", "http://orders.test")
    await run_authz_probe(
        "az_post", "http://orders.test", "memory",
        schema_content=SPEC, auth=AUTH_A, auth_alt=AUTH_B, allow_mutating=False,
        schema_source="discovered",
    )
    assert "POST" not in app.state.methods_seen
