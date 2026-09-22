"""Shared fixtures for BugTraceAI-API tests."""
import sys
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ── Stub out heavy external deps before any project import ─────────────────
# mcp_server imports mcp.server.fastmcp which may not exist in test env.
# We mock the entire module so tool modules can be imported cleanly.

_mock_mcp = MagicMock()
_mock_mcp.mcp_server = MagicMock()
_mock_mcp.mcp_server.tool = MagicMock(return_value=lambda fn: fn)
_mock_mcp.KR_BIN = Path("/usr/local/bin/kr")
_mock_mcp.X8_BIN = Path("/usr/local/bin/x8")
_mock_mcp.WORDLISTS_DIR = Path("/opt/kiterunner/wordlists")
_mock_mcp.TEXT_WORDLISTS_DIR = Path("/opt/wordlists")
_mock_mcp.PARAMS_DIR = Path("/opt/params")
_mock_mcp.SCANS_DIR = Path("/tmp/bugtrace-api-test/scans")
_mock_mcp._LAN_TRANSPORT_SECURITY = None
_mock_mcp.run_mcp_server = MagicMock()

sys.modules.setdefault("mcp_server", _mock_mcp)
sys.modules.setdefault("mcp", MagicMock())
sys.modules.setdefault("mcp.server", MagicMock())
sys.modules.setdefault("mcp.server.fastmcp", MagicMock())
sys.modules.setdefault("mcp.server.transport_security", MagicMock())

# Add project root to path so `lib` / `tools` resolve
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture(autouse=True)
def _reset_scan_state(tmp_path):
    """Reset the ScanState singleton before each test, using tmp for artifacts."""
    from lib.scan_state import ScanState, scan_state

    # Tests occasionally replace instance methods to simulate failures. Remove
    # those overrides before taking the canonical class methods so one test
    # cannot leak behaviour into the next one.
    scan_state.__dict__.pop("create_scan", None)
    scan_state.__dict__.pop("update_scan", None)
    ScanState._reset()
    state = scan_state  # Same instance all modules reference

    # Override artifact path creation to use tmp
    async def _patched_create(self, scan_id, target, engine="api", launch_origin="api", launch_transport=None):
        async with self.lock:
            from lib.evidence import create_scan_dir
            from lib.scan_state import ScanStatus
            # Register the scan dir in tmp reports so manifests and artifacts
            # are file-based in tests too.
            create_scan_dir(scan_id, target)
            self.active_scans[scan_id] = ScanStatus(
                scan_id=scan_id,
                target=target,
                engine=engine,
                launch_origin=launch_origin,
                launch_transport=launch_transport,
                started_at=datetime.now(UTC).isoformat(),
            )
            artifacts_path = str(tmp_path / "scans" / scan_id)
            self.scan_responses[scan_id] = {
                "endpoints": [],
                "findings": [],
                "schema": None,
                "tool_health": {},
                "artifacts_path": artifacts_path,
            }
            Path(artifacts_path).mkdir(parents=True, exist_ok=True)
            from lib.evidence import save_scan_manifest
            save_scan_manifest(
                scan_id=scan_id,
                engine=engine,
                launch_origin=launch_origin,
                launch_transport=launch_transport,
                status="pending",
                target=target,
                started_at=datetime.now(UTC).isoformat(),
            )

    import types
    state.create_scan = types.MethodType(_patched_create, state)

    # Point evidence module at tmp so file-based pipeline works in tests
    import lib.evidence as _ev
    _orig_reports_dir = _ev.REPORTS_DIR
    _ev.REPORTS_DIR = tmp_path / "reports"
    import lib.scan_state as _ss
    _orig_scan_state_reports_dir = _ss.REPORTS_DIR
    _ss.REPORTS_DIR = _ev.REPORTS_DIR
    _ev._scan_dirs.clear()

    yield state

    # Restore original methods and artifact roots, including any instance
    # overrides installed by an individual test.
    state.__dict__.pop("create_scan", None)
    state.__dict__.pop("update_scan", None)
    _ev.REPORTS_DIR = _orig_reports_dir
    _ss.REPORTS_DIR = _orig_scan_state_reports_dir
    _ev._scan_dirs.clear()
    ScanState._reset()


@pytest.fixture
def scan_state(_reset_scan_state):
    """Provide the singleton ScanState (already reset)."""
    return _reset_scan_state
