import argparse
import asyncio
import logging
import os
import socket

import api_server
import mcp_server

logger = logging.getLogger("bugtrace-api.main")

def _find_free_port(host: str, preferred: int, retries: int = 10, exclude: frozenset = frozenset()) -> int:
    for offset in range(retries):
        port = preferred + offset
        if port in exclude:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"No free port found near {preferred}")

async def _run_both(host: str, mcp_port: int, api_port: int) -> None:
    import uvicorn
    from starlette.middleware.cors import CORSMiddleware

    actual_mcp = _find_free_port(host, mcp_port)
    # Exclude the port MCP just claimed — otherwise a busy mcp_port can search
    # its way onto api_port, and this search then "frees" and reclaims it too.
    actual_api = _find_free_port(host, api_port, exclude=frozenset({actual_mcp}))

    mcp_app, transport_name = mcp_server._create_mcp_app(host, actual_mcp)

    api_app = CORSMiddleware(
        api_server.app,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    cfg_mcp = uvicorn.Config(mcp_app, host=host, port=actual_mcp, log_level="info")
    cfg_api = uvicorn.Config(api_app, host=host, port=actual_api, log_level="info")

    srv_mcp = uvicorn.Server(cfg_mcp)
    srv_api = uvicorn.Server(cfg_api)
    srv_mcp.install_signal_handlers = lambda: None

    if actual_mcp != mcp_port:
        logger.warning(f"MCP port {mcp_port} busy, using {actual_mcp}")
    if actual_api != api_port:
        logger.warning(f"API port {api_port} busy, using {actual_api}")

    logger.info(f"MCP ({transport_name}) -> {host}:{actual_mcp}")
    logger.info(f"REST API -> {host}:{actual_api}")

    await asyncio.gather(srv_mcp.serve(), srv_api.serve())

# Tools for MCP (previously these were defined directly in main)
import uuid

from lib.http_policy import AUDIT_NO_AUTH_WARNING, resolve_audit_mode
from lib.scan_state import scan_state
from orchestrator import orchestrator


@mcp_server.mcp_server.tool()
async def api_scan(
    target: str,
    depth: str = "standard",
    auth: dict | None = None,
    schema_url: str | None = None,
    allow_mutating: bool | None = None,
    auth_alt: dict | None = None,
    mode: str = "safe",
) -> dict:
    """Start a fully automated API security scan.

    ``mode=safe`` (default) only sends GET/HEAD/OPTIONS. ``mode=audit``
    enables mutating methods and kite scan; it **mutates** the target.
    Pass ``allow_mutating=false`` with audit to opt back out.

    MCP always records launch_origin="api" (B.1 #3); it never accepts a
    caller-supplied origin. launch_transport="mcp" is internal audit detail and
    is not returned in public scan responses.
    """
    if not target.startswith(("http://", "https://")):
        return {"error": "Target must start with http:// or https://"}

    resolved_mode, resolved_mutating = resolve_audit_mode(
        mode,
        bool(allow_mutating),
        mutating_explicit=allow_mutating is not None,
    )
    warning = AUDIT_NO_AUTH_WARNING if resolved_mode == "audit" and not auth else None

    scan_id = str(uuid.uuid4())[:12]
    return await orchestrator.launch_api_scan(
        scan_id,
        target,
        depth,
        auth,
        schema_url,
        engine="api",
        launch_origin="api",
        launch_transport="mcp",
        allow_mutating=resolved_mutating,
        auth_alt=auth_alt,
        mode=resolved_mode,
        warning=warning,
    )
@mcp_server.mcp_server.tool()
async def get_scan_status(scan_id: str) -> dict:
    """Get the current status of a scan."""
    status = await scan_state.get_scan(scan_id)
    if not status:
        return {"error": f"Scan {scan_id} not found"}
    return status.model_dump()


@mcp_server.mcp_server.tool()
async def get_results(scan_id: str) -> dict:
    """Get the findings and results of a scan."""
    results = await scan_state.get_results(scan_id)
    if not results:
        return {"error": f"Scan {scan_id} not found."}
    return results


@mcp_server.mcp_server.tool()
async def stop_scan(scan_id: str) -> dict:
    """Stop a running scan."""
    status = await scan_state.get_scan(scan_id)
    if not status:
        return {"error": f"Scan {scan_id} not found"}

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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BugTraceAI-API MCP+REST Server")
    parser.add_argument("--sse", "--http", action="store_true", dest="http", help="Use HTTP transport (runs REST API too)")
    parser.add_argument("--host", default="0.0.0.0", help="Host IP")
    parser.add_argument(
        "--port",
        type=int,
        default=os.environ.get("MCP_PORT"),
        required=False,
        help="Port for MCP server (supplied by the deployment environment)",
    )
    parser.add_argument(
        "--api-port", type=int,
        default=os.environ.get("API_PORT"),
        help="Port for FastAPI REST server (supplied by the deployment environment)",
    )
    args = parser.parse_args()

    if args.http:
        asyncio.run(_run_both(args.host, args.port, args.api_port))
    else:
        mcp_server.run_mcp_server("stdio", args.host, args.port)
