import logging
import os
import sys
from pathlib import Path

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# Setup logging
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("bugtrace-api")

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

# Initialize FastMCP
mcp_server = FastMCP(
    "bugtrace-api",
    dependencies=["mcp", "pydantic", "httpx", "schemathesis", "offat", "vulnapi"]
)

# Configuration from environment
KR_BIN = Path(os.environ.get("KR_BIN", "/usr/local/bin/kr"))
X8_BIN = Path(os.environ.get("X8_BIN", "/usr/local/bin/x8"))
WORDLISTS_DIR = Path(os.environ.get("WORDLISTS_DIR", "/opt/kiterunner/wordlists"))
TEXT_WORDLISTS_DIR = Path(os.environ.get("TEXT_WORDLISTS_DIR", "/opt/wordlists"))
PARAMS_DIR = Path(os.environ.get("PARAMS_DIR", "/opt/params"))
SCANS_DIR = Path(os.environ.get("SCANS_DIR", "/opt/bugtrace-api/scans"))
REPORTS_DIR = Path(os.environ.get("REPORTS_DIR", "/opt/bugtrace-api/reports"))

_LAN_TRANSPORT_SECURITY = TransportSecuritySettings(
    enable_dns_rebinding_protection=False,
)


def _create_mcp_app(host: str = "0.0.0.0", port: int = 8004):
    """Create the MCP ASGI app (Streamable HTTP, with SSE fallback)."""
    from starlette.middleware.cors import CORSMiddleware

    mcp_server.settings.host = host
    mcp_server.settings.port = port
    mcp_server.settings.transport_security = _LAN_TRANSPORT_SECURITY

    # Prefer Streamable HTTP (MCP spec 2025-03-26+), fall back to SSE
    if hasattr(mcp_server, "streamable_http_app"):
        app = mcp_server.streamable_http_app()
        transport_name = "Streamable HTTP"
    else:
        app = mcp_server.sse_app()
        transport_name = "SSE (legacy)"

    app = CORSMiddleware(
        app,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["*"],
    )
    return app, transport_name


@mcp_server.tool()
async def investigate_api(
    scan_id: str,
    max_iterations: int = 5,
    max_tool_calls_per_iteration: int = 10,
    max_total_tool_calls: int = 50,
) -> dict:
    """Run an autonomous security investigation over a completed scan.

    This tool launches the BugTraceAI investigation engine which:
    1. Formulates security hypotheses from scan findings
    2. Plans targeted validation steps to test each hypothesis
    3. Executes validations safely using specialized security tools
    4. Iterates based on evidence until convergence or budget exhaustion
    5. Returns final investigation state with confirmed vulnerabilities

    Args:
        scan_id: UUID of the completed scan to investigate
        max_iterations: Maximum investigation cycles (default: 5)
        max_tool_calls_per_iteration: Max tool calls per iteration (default: 10)
        max_total_tool_calls: Absolute limit on tool calls (default: 50)

    Returns:
        Investigation state dict containing:
        - status: 'completed', 'failed', or 'stopped'
        - hypotheses: List of investigated security hypotheses with status
        - iterations: Detailed logs of each investigation cycle
        - total_tool_calls: Number of security validations performed
        - stop_reason: Why investigation ended

    Example:
        result = await investigate_api(
            scan_id="550e8400-e29b-41d4-a716-446655440000",
            max_iterations=3,
            max_tool_calls_per_iteration=5
        )
    """
    from lib.investigation_models import InvestigatorBudget
    from lib.provider import get_active_provider
    from lib.scan_state import scan_state
    from tools.investigate import run_investigation

    status = await scan_state.get_scan(scan_id)
    if not status:
        return {"error": f"Scan {scan_id} not found"}

    results = await scan_state.get_results(scan_id)
    if not results:
        return {"error": f"Scan {scan_id} has no results yet"}

    budget = InvestigatorBudget(
        max_iterations=max_iterations,
        max_tool_calls_per_iteration=max_tool_calls_per_iteration,
        max_total_tool_calls=max_total_tool_calls,
    )

    state = await run_investigation(
        scan_id=scan_id,
        target=status.target,
        endpoints=results.get("endpoints", []) or [],
        findings=results.get("findings", []) or [],
        auth=None,
        allow_mutating=bool(status.allow_mutating),
        provider=get_active_provider(),
        budget=budget,
    )

    return state.model_dump()


def run_mcp_server(
    transport: str = "stdio",
    host: str = "0.0.0.0",
    port: int = 8004,
) -> None:
    if transport in ("sse", "http"):
        import uvicorn

        app, transport_name = _create_mcp_app(host, port)
        logger.info(f"Starting BugTraceAI-API MCP Server ({transport_name}) on {host}:{port}")
        uvicorn.run(app, host=host, port=port)
    else:
        logger.info("Starting BugTraceAI-API MCP Server (STDIO)")
        mcp_server.run(transport="stdio")
