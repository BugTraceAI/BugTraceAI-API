import asyncio
import io
import json
import logging
import zipfile
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from lib.evidence import get_scan_dir, load_artifact, render_scan_markdown
from lib.http_policy import AUDIT_NO_AUTH_WARNING, resolve_audit_mode
from lib.openapi import extract_operations
from lib.provider import (
    active_provider_id,
    get_active_provider,
    get_provider_profile,
    list_provider_profiles,
    provider_api_key,
    provider_models,
    set_active_provider,
    set_provider_api_key,
    set_provider_model,
    set_provider_model_chain,
)
from lib.scan_state import ALLOWED_LAUNCH_ORIGINS, scan_state
from orchestrator import orchestrator

logger = logging.getLogger("bugtrace-api.api_server")

_VERSION_FILE = Path(__file__).parent / "VERSION"
VERSION = _VERSION_FILE.read_text().strip() if _VERSION_FILE.exists() else "unknown"

app = FastAPI(title="BugTraceAI API Testing REST Interface", version=VERSION)

# The API engine accepts only origins that launched via the API engine. CLI
# origins (web-cli / cli) belong to the CLI engine and are rejected (B.1 #3).
API_LAUNCH_ORIGINS = ("web-api", "api")
ACTIVE_SCAN_STATUSES = {"pending", "running", "initializing", "queued"}
_scan_start_lock = asyncio.Lock()


class ScanRequest(BaseModel):
    """Launch an API scan.

    ``mode=safe`` (default) only sends GET/HEAD/OPTIONS. ``mode=audit``
    enables POST/PUT/PATCH/DELETE and method-aware kite discovery; it
    **mutates** the target. Explicit ``allow_mutating=false`` overrides
    audit back to safe methods.
    """

    target: str
    depth: str = "standard"
    auth: dict[str, Any] | None = None
    auth_alt: dict[str, Any] | None = None
    schema_url: str | None = None
    launch_origin: Literal["web-api", "api"] = "api"
    # POST/PUT/PATCH/DELETE are off unless the caller opts in.
    allow_mutating: bool = False
    mode: Literal["safe", "audit"] = "safe"

    @field_validator("launch_origin")
    @classmethod
    def _validate_launch_origin(cls, v: str) -> str:
        if v not in ALLOWED_LAUNCH_ORIGINS:
            raise ValueError(
                f"launch_origin '{v}' not in {sorted(ALLOWED_LAUNCH_ORIGINS)}"
            )
        if v not in API_LAUNCH_ORIGINS:
            raise ValueError(f"launch_origin '{v}' belongs to the CLI engine, not the API engine")
        return v


class ProviderRequest(BaseModel):
    provider: str
    # Optional so a provider switch can keep its already configured key.
    api_key: str | None = None
    # Optional so a model change can keep the existing provider and key.
    model: str | None = None
    # Ordered primary + fallback models.  The API accepts up to three; the
    # legacy single ``model`` field remains supported for older clients.
    models: list[str] | None = None

    @field_validator("models")
    @classmethod
    def _validate_models_length(cls, value: list[str] | None) -> list[str] | None:
        if value is not None and len(value) > 3:
            raise ValueError("At most three provider models may be selected")
        return value


class ProviderTestRequest(BaseModel):
    provider: str
    api_key: str | None = None
    model: str | None = None


class InvestigationRequest(BaseModel):
    """Launch an autonomous investigation loop over an existing scan."""

    scan_id: str
    max_iterations: int = Field(default=5, ge=1, le=20)
    max_tool_calls_per_iteration: int = Field(default=10, ge=1, le=50)
    max_total_tool_calls: int = Field(default=50, ge=10, le=200)
    auth: dict[str, Any] | None = None
    auth_alt: dict[str, Any] | None = None


def _mask_api_key(api_key: str | None) -> str:
    if not api_key:
        return ""
    return f"{api_key[:4]}…{api_key[-5:]}" if len(api_key) > 9 else "••••"


def _provider_payload(provider_id: str) -> dict[str, Any]:
    profile = get_provider_profile(provider_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found")
    key = provider_api_key(provider_id)
    return {
        **profile,
        "provider": profile["id"],
        "api_key_configured": bool(key),
        "api_key_hint": _mask_api_key(key) if key else profile.get("api_key_hint", ""),
        "active": provider_id == active_provider_id(),
    }


async def _test_provider(
    provider_id: str,
    api_key_override: str | None = None,
    model_override: str | None = None,
) -> dict[str, Any]:
    """Perform a small provider health request without returning provider data."""
    profile = get_provider_profile(provider_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found")
    raw = profile
    models = provider_models(provider_id, raw)
    model = model_override.strip() if model_override is not None else str(profile.get("model", ""))
    if model not in models:
        return {"success": False, "message": f"Model '{model}' is not available for this provider."}
    key = api_key_override.strip() if api_key_override and api_key_override.strip() else provider_api_key(provider_id)
    kind = raw.get("kind", "ollama")
    base_url = raw.get("base_url", "")
    if not base_url:
        return {"success": False, "message": "Provider has no base URL configured."}
    if kind != "ollama" and not key:
        return {"success": False, "message": "No API key provided and none configured."}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            if kind == "ollama":
                response = await client.get(f"{base_url.rstrip('/')}/api/tags")
            elif kind == "anthropic":
                response = await client.post(
                    base_url,
                    headers={
                        "x-api-key": key,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": model.replace("anthropic/", "", 1),
                        "max_tokens": 5,
                        "messages": [{"role": "user", "content": "Answer only yes."}],
                    },
                )
            else:
                headers = {
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                    **(raw.get("headers") or {}),
                }
                response = await client.post(
                    base_url,
                    headers=headers,
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": "Answer only yes."}],
                        "max_tokens": 5,
                    },
                )
    except httpx.TimeoutException:
        return {"success": False, "message": "Connection timed out. Check the provider URL."}
    except httpx.HTTPError:
        return {"success": False, "message": "Connection failed while contacting the provider."}
    except Exception:
        return {"success": False, "message": "Connection failed while contacting the provider."}

    if response.status_code in (200, 201):
        return {"success": True, "message": "API key validated successfully."}
    if response.status_code == 401:
        return {"success": False, "message": "Invalid API key. Please check and try again."}
    if response.status_code == 403:
        return {"success": False, "message": "API key rejected or insufficient permissions."}
    if response.status_code == 429:
        return {"success": False, "message": "Rate limited — the key may be valid. Try again later."}
    return {"success": False, "message": f"Provider returned HTTP {response.status_code}."}


@app.get("/api/providers")
async def list_providers() -> list[dict[str, Any]]:
    return [_provider_payload(profile["id"]) for profile in list_provider_profiles()]


@app.get("/api/provider")
async def current_provider() -> dict[str, Any]:
    return _provider_payload(active_provider_id())


@app.get("/api/providers/{provider_id}")
async def provider_detail(provider_id: str) -> dict[str, Any]:
    return _provider_payload(provider_id)


@app.put("/api/provider")
async def update_provider(request: ProviderRequest) -> dict[str, Any]:
    provider_id = request.provider.strip()
    if not get_provider_profile(provider_id):
        raise HTTPException(status_code=404, detail=f"Provider '{provider_id}' not found")
    if "api_key" in request.model_fields_set:
        try:
            set_provider_api_key(provider_id, request.api_key)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if "models" in request.model_fields_set:
        try:
            set_provider_model_chain(provider_id, request.models or [])
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    elif "model" in request.model_fields_set:
        try:
            set_provider_model(provider_id, request.model or "")
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    try:
        set_active_provider(provider_id)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return {"message": f"Switched to provider: {_provider_payload(provider_id)['name']}", **_provider_payload(provider_id)}


@app.post("/api/provider/test")
async def test_provider(request: ProviderTestRequest) -> dict[str, Any]:
    return await _test_provider(request.provider.strip(), request.api_key, request.model)


@app.post("/api/scan")
async def start_scan(req: ScanRequest):
    target = req.target.strip()
    if not target.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Target must start with http:// or https://")

    # Treat a trailing slash as presentation detail. Discovery joins paths to
    # this base URL; normalising here prevents requests such as `/api/v1//docs`
    # and keeps report targets stable across WEB and direct REST launches.
    target = target.rstrip("/") or target

    import uuid
    async with _scan_start_lock:
        scans, _ = await scan_state.list_scans(limit=200)
        active = next(
            (scan for scan in scans if str(scan.get("status", "")).lower() in ACTIVE_SCAN_STATUSES),
            None,
        )
        if active:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "An API scan is already running",
                    "active_scan_id": active.get("scan_id"),
                },
            )

        scan_id = str(uuid.uuid4())[:12]

        mode, allow_mutating = resolve_audit_mode(
            req.mode,
            req.allow_mutating,
            mutating_explicit="allow_mutating" in req.model_fields_set,
        )
        warning = AUDIT_NO_AUTH_WARNING if mode == "audit" and not req.auth else None

        return await orchestrator.launch_api_scan(
            scan_id,
            target,
            req.depth,
            req.auth,
            req.schema_url,
            engine="api",
            launch_origin=req.launch_origin,
            launch_transport="rest",
            allow_mutating=allow_mutating,
            auth_alt=req.auth_alt,
            mode=mode,
            warning=warning,
        )

@app.get("/api/scan/{scan_id}")
async def get_scan_status(scan_id: str):
    status = await scan_state.get_scan(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return status.model_dump()

@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    results = await scan_state.get_results(scan_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return results

@app.get("/api/scan/{scan_id}/openapi")
async def get_scan_openapi(scan_id: str):
    """Return the OpenAPI 3.0 spec auto-generated from discovered endpoints.

    Available once the discovery phase completes. The spec can be imported
    directly into Bruno, Postman, Insomnia, or the BugTraceAI WEB scanner.
    Works for both in-progress and past scans (loaded from disk).
    """
    spec = load_artifact(scan_id, "schema_probe", "published_openapi") or load_artifact(
        scan_id, "discovery", "generated_openapi"
    )
    if not spec:
        raise HTTPException(
            status_code=404,
            detail="OpenAPI spec not yet available — discovery phase may still be running or scan not found"
        )
    return JSONResponse(content=spec, media_type="application/json")


_HANDOFF_SECRET_KEYS = {
    "api_key", "apikey", "authorization", "cookie", "password", "passwd",
    "secret", "token", "access_token", "refresh_token", "totp_secret",
}


def _handoff_safe(value: Any) -> Any:
    """Copy handoff data while excluding credentials and session material."""
    if isinstance(value, dict):
        return {
            str(key): "[REDACTED]" if str(key).lower() in _HANDOFF_SECRET_KEYS
            else _handoff_safe(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_handoff_safe(item) for item in value]
    return value


async def _build_handoff(scan_id: str) -> dict[str, Any]:
    """Build the versioned API→CLI handoff from durable scan artifacts."""
    status = await scan_state.get_scan(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    results = await scan_state.get_results(scan_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} results not found")

    published = load_artifact(scan_id, "schema_probe", "published_openapi")
    generated = load_artifact(scan_id, "discovery", "generated_openapi")
    spec = published or generated
    schema_info = load_artifact(scan_id, "schema_probe", "schema_info")
    if not isinstance(schema_info, dict):
        schema_info = results.get("schema") if isinstance(results.get("schema"), dict) else {}
    schema_info = dict(schema_info)
    schema_info.update({
        "has_published": bool(published),
        "source": schema_info.get("source") or ("published" if published else "auto_generated" if generated else "none"),
        "paths_count": int(schema_info.get("paths_count") or len((spec or {}).get("paths") or {})),
        "operations_count": int(schema_info.get("operations_count") or 0),
        "parsed": bool(schema_info.get("parsed", bool(spec))),
    })
    if spec and not schema_info["operations_count"]:
        schema_info["operations_count"] = sum(
            1 for item in (spec.get("paths") or {}).values() if isinstance(item, dict)
            for method in item if str(method).lower() in {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
        )
    schema_info["spec"] = _handoff_safe(spec) if isinstance(spec, dict) else None
    schema_info = _handoff_safe(schema_info)

    operations = load_artifact(scan_id, "schema_probe", "openapi_operations")
    if not isinstance(operations, list):
        operations = extract_operations(spec, status.target) if isinstance(spec, dict) else []
    endpoints = load_artifact(scan_id, "discovery", "all_endpoints")
    if not isinstance(endpoints, list):
        endpoints = results.get("endpoints", []) or []
    findings = load_artifact(scan_id, "aggregation", "findings_only")
    if not isinstance(findings, list):
        findings = results.get("findings", []) or []
    scan_status = status.model_dump()
    investigation_state = load_artifact(scan_id, "investigation", "state")
    investigation_hypotheses = load_artifact(scan_id, "investigation", "hypotheses")
    investigation_iterations_index = load_artifact(scan_id, "investigation", "iterations_index")
    return {
        "handoff_version": 1,
        "producer": {
            "service": "bugtraceai-api",
            "version": VERSION,
            "scan_id": scan_id,
        },
        "target": status.target,
        "mode": scan_status.get("mode") or ("audit" if scan_status.get("allow_mutating") else "safe"),
        "allow_mutating": bool(scan_status.get("allow_mutating", False)),
        "schema": schema_info,
        "operations": _handoff_safe(operations),
        "endpoints": _handoff_safe(endpoints),
        "findings": _handoff_safe(findings),
        "quality_summary": _handoff_safe(results.get("quality_summary") or {}),
        "tool_health": _handoff_safe(results.get("tool_health") or {}),
        "warnings": [scan_status["warning"]] if scan_status.get("warning") else [],
        "investigation": _handoff_safe({
            "state": investigation_state,
            "hypotheses": investigation_hypotheses,
            "iterations_index": investigation_iterations_index,
        }) if investigation_state else None,
    }


@app.get("/api/scan/{scan_id}/handoff")
async def get_scan_handoff(scan_id: str):
    """Return the versioned API → CLI handoff handoff pack."""
    return JSONResponse(content=await _build_handoff(scan_id), media_type="application/json")


MAX_REPORT_ZIP_SIZE_BYTES = 500 * 1024 * 1024


def _report_export_files(report_dir: Path) -> list[Path]:
    """Return durable scan files while excluding transient/private links."""
    root = report_dir.resolve()
    files: list[Path] = []
    for path in report_dir.rglob("*"):
        if (
            path.is_symlink()
            or not path.is_file()
            or path.name.endswith((".lock", ".tmp"))
            or path.name in {".report-artifacts.lock", ".repeater-refresh-pending.json"}
        ):
            continue
        try:
            path.resolve().relative_to(root)
        except ValueError:
            continue
        files.append(path)
    return files


@app.get("/api/scan/{scan_id}/report-zip")
async def download_scan_report_zip(scan_id: str):
    """Download the complete durable API scan report as a CLI-style ZIP.

    The archive contains every phase artifact plus generated portable
    ``report.md`` and ``openapi.json`` entries when those artifacts exist.
    Provider secrets are never persisted in the scan directory.
    """
    status = await scan_state.get_scan(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    results = await scan_state.get_results(scan_id)
    if not results:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} results not found")

    report_dir = get_scan_dir(scan_id)
    # Rebuild the portable root report on every request. Older scans may have
    # persisted a report before endpoint/reference URL normalization was added;
    # archiving that stale root file would make the ZIP disagree with the live
    # report download and the findings table.
    export_files = [
        path for path in _report_export_files(report_dir)
        if path.relative_to(report_dir).as_posix() != "report.md"
    ]
    existing_names = {path.relative_to(report_dir).as_posix() for path in export_files}
    generated: dict[str, bytes] = {}

    markdown = render_scan_markdown(
        scan_id=scan_id,
        target=status.target,
        status=status.model_dump(),
        findings=results.get("findings", []) or [],
        endpoints=results.get("endpoints", []) or [],
        tool_health=results.get("tool_health", {}) or {},
        ai_analysis=results.get("ai_analysis"),
        coverage=results.get("coverage"),
        schema=results.get("schema") if isinstance(results.get("schema"), dict) else None,
        quality_summary=results.get("quality_summary"),
    )
    generated["report.md"] = markdown.encode("utf-8")

    openapi = load_artifact(scan_id, "schema_probe", "published_openapi") or load_artifact(
        scan_id, "discovery", "generated_openapi"
    )
    if openapi is not None and "openapi.json" not in existing_names:
        generated["openapi.json"] = (json.dumps(openapi, indent=2, default=str) + "\n").encode("utf-8")

    generated["bugtraceai-handoff-v1.json"] = (
        json.dumps(await _build_handoff(scan_id), indent=2, default=str) + "\n"
    ).encode("utf-8")

    total_size = sum(path.stat().st_size for path in export_files) + sum(len(content) for content in generated.values())
    if total_size > MAX_REPORT_ZIP_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Report too large to zip ({total_size // (1024 * 1024)} MB). Max: {MAX_REPORT_ZIP_SIZE_BYTES // (1024 * 1024)} MB",
        )

    archive_root = report_dir.name
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(export_files):
            archive.write(path, f"{archive_root}/{path.relative_to(report_dir).as_posix()}")
        for name, content in sorted(generated.items()):
            archive.writestr(f"{archive_root}/{name}", content)

    zip_buffer.seek(0)
    filename = f"{archive_root}.zip"
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(zip_buffer.getbuffer().nbytes),
        },
    )


@app.get("/api/scan/{scan_id}/downloads/{artifact}")
async def download_scan_artifact(scan_id: str, artifact: str):
    """Download portable API-scan artifacts.

    ``findings.json`` contains the complete normalized findings list,
    ``report.md`` is a compact human-readable report, and ``openapi.json`` is
    the generated OpenAPI 3 document suitable for Postman, Bruno, Insomnia, or
    a later BugTraceAI-CLI import.  The files are rebuilt from durable
    artifacts on every request, so downloads continue to work after a restart.
    """
    status = await scan_state.get_scan(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    normalized = artifact.strip().lower()
    if normalized in {"openapi", "openapi.json", "swagger", "swagger.json"}:
        spec = load_artifact(scan_id, "schema_probe", "published_openapi") or load_artifact(
            scan_id, "discovery", "generated_openapi"
        )
        if not spec:
            raise HTTPException(status_code=404, detail="OpenAPI spec is not available for this scan yet")
        payload = json.dumps(spec, indent=2, default=str) + "\n"
        filename = f"bugtraceai-api-{scan_id}-openapi.json"
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if normalized in {"findings", "findings.json", "all-findings", "all-findings.json"}:
        findings = load_artifact(scan_id, "aggregation", "findings_only")
        if not isinstance(findings, list):
            results = await scan_state.get_results(scan_id)
            findings = (results or {}).get("findings", [])
        payload = json.dumps(findings or [], indent=2, default=str) + "\n"
        filename = f"bugtraceai-api-{scan_id}-findings.json"
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if normalized in {"report", "report.md", "markdown", "markdown.md"}:
        results = await scan_state.get_results(scan_id)
        if not results:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} results not found")
        payload = render_scan_markdown(
            scan_id=scan_id,
            target=status.target,
            status=status.model_dump(),
            findings=results.get("findings", []) or [],
            endpoints=results.get("endpoints", []) or [],
            tool_health=results.get("tool_health", {}) or {},
            ai_analysis=results.get("ai_analysis"),
            coverage=results.get("coverage"),
            schema=results.get("schema") if isinstance(results.get("schema"), dict) else None,
            quality_summary=results.get("quality_summary"),
        )
        filename = f"bugtraceai-api-{scan_id}-report.md"
        return Response(
            content=payload,
            media_type="text/markdown",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    if normalized in {"handoff", "handoff.json", "bugtraceai-handoff-v1.json"}:
        payload = json.dumps(await _build_handoff(scan_id), indent=2, default=str) + "\n"
        filename = f"bugtraceai-api-{scan_id}-handoff-v1.json"
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    raise HTTPException(status_code=404, detail="Unknown scan artifact")

@app.delete("/api/scan/{scan_id}")
async def stop_scan(scan_id: str):
    status = await scan_state.get_scan(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    if status.status in ["completed", "failed", "stopped"]:
        return {
            "scan_id": scan_id,
            "status": "stopped",
            "engine": status.engine,
            "launch_origin": status.launch_origin,
            "message": f"Scan {scan_id} already finished."
        }

    await scan_state.update_scan(scan_id, status="stopped")
    await orchestrator.cancel_scan(scan_id)
    return {
        "scan_id": scan_id,
        "status": "stopped",
        "engine": "api",
        "launch_origin": status.launch_origin,
    }

@app.get("/api/scans")
async def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
):
    try:
        scans, next_cursor = await scan_state.list_scans(limit=limit, cursor=cursor)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"scans": scans, "next_cursor": next_cursor}

@app.get("/health")
async def health_check():
    provider = get_active_provider()
    try:
        scans, _ = await scan_state.list_scans(limit=1)
        scan_count = len(scans)
    except Exception:
        scan_count = 0
    return {
        "status": "ok",
        "service": "bugtraceai-api",
        "version": VERSION,
        "provider": provider.id,
        "provider_name": provider.name,
        "model": provider.model,
        "api_key_configured": bool(provider.api_key) if not provider.is_local else True,
        "scans_total": scan_count,
    }


@app.post("/api/investigate")
async def start_investigation(req: InvestigationRequest):
    status = await scan_state.get_scan(req.scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {req.scan_id} not found")
    results = await scan_state.get_results(req.scan_id)
    if not results:
        raise HTTPException(status_code=400, detail=f"Scan {req.scan_id} has no results yet")

    endpoints = results.get("endpoints", []) or []
    findings = results.get("findings", []) or []

    from lib.investigation_models import InvestigatorBudget
    from tools.investigate import run_investigation

    state = await run_investigation(
        scan_id=req.scan_id,
        target=status.target,
        endpoints=endpoints,
        findings=findings,
        auth=req.auth,
        auth_alt=req.auth_alt,
        # Older persisted ScanStatus records (and the public status model)
        # do not expose the launch flag.  Investigation must remain safe by
        # default instead of turning a missing field into a 500 response.
        allow_mutating=bool(getattr(status, "allow_mutating", False)),
        provider=get_active_provider(),
        budget=InvestigatorBudget(
            max_iterations=req.max_iterations,
            max_tool_calls_per_iteration=req.max_tool_calls_per_iteration,
            max_total_tool_calls=req.max_total_tool_calls,
        ),
    )
    return state.model_dump()


@app.get("/api/investigate/{scan_id}")
async def get_investigation(scan_id: str):
    status = await scan_state.get_scan(scan_id)
    if not status:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    artifact = load_artifact(scan_id, "investigation", "state")
    if not artifact:
        raise HTTPException(status_code=404, detail="Investigation not started for this scan")
    return artifact
