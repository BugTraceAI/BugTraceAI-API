"""Schema-based attack tools (Phase 3A): schemathesis, offat, vulnapi.

Split from the monolithic ``tools/schema_attack.py`` so each tool lives in its
own file and can be evolved independently. The public API surface used by the
orchestrator (``run_schema_attack``) is re-exported here for backward compat.
"""
from tools.attack.offat import run_offat
from tools.attack.schemathesis import run_schemathesis
from tools.attack.vulnapi import run_vulnapi


async def run_schema_attack(
    scan_id, schema, target, auth=None, allow_mutating=False,
    *, persist_findings: bool = True, artifact_phase: str = "schema_attack", selected_tools=None,
):
    """Run all three schema-based tools in parallel.

    This is the orchestrator-facing entry point kept for backward compatibility
    with the old ``tools.schema_attack.run_schema_attack`` import path.
    """
    import asyncio
    import json
    import logging
    from pathlib import Path

    from lib.evidence import save_artifact
    from lib.http_policy import allowed_methods
    from lib.openapi import filter_spec_methods
    from lib.scan_state import scan_state

    logger = logging.getLogger("bugtrace-api.tools.attack")

    schema_url = schema.get("url")
    if not schema_url:
        logger.warning(f"[scan:{scan_id}] Schema URL missing, skipping schema attack")
        return []

    # Count paths for adaptive schemathesis config. Prefer the in-memory spec
    # (YAML included) over a remote URL that we may not have parsed yet.
    num_paths = int(schema.get("paths_count") or 0)
    spec = schema.get("content") if isinstance(schema.get("content"), dict) else None
    try:
        schema_path = Path(schema_url)
        if spec is None and schema_path.exists():
            with open(schema_path) as f:
                spec = json.load(f)
        if spec and not num_paths:
            num_paths = len(spec.get("paths", {}) or {})
        if spec is not None and not allow_mutating:
            from lib.evidence import _phase_dir
            filtered = filter_spec_methods(spec, allowed_methods(False))
            safe_path = _phase_dir(scan_id, "schema_probe") / "attack_openapi.json"
            safe_path.parent.mkdir(parents=True, exist_ok=True)
            safe_path.write_text(json.dumps(filtered, indent=2, default=str))
            schema_url = str(safe_path)
            num_paths = len(filtered.get("paths", {}) or {})
            logger.info(
                f"[scan:{scan_id}] Schema attack restricted to GET/HEAD/OPTIONS "
                f"({num_paths} paths)"
            )
    except Exception:
        pass

    tools = {
        "schemathesis": lambda: run_schemathesis(
            scan_id, schema_url, target, auth,
            num_paths=num_paths, artifact_phase=artifact_phase,
        ),
        "offat": lambda: run_offat(scan_id, schema_url, target, auth),
        "vulnapi": lambda: run_vulnapi(scan_id, target, schema_url, auth),
    }
    tool_names = list(selected_tools) if selected_tools is not None else list(tools)
    if any(name not in tools for name in tool_names):
        raise ValueError("Unknown schema attack tool")
    results = await asyncio.gather(*(tools[name]() for name in tool_names), return_exceptions=True)
    all_findings = []
    for tool_name, tool_findings in zip(tool_names, results, strict=False):
        if isinstance(tool_findings, Exception):
            logger.error(f"[scan:{scan_id}] Schema attack tool raised exception: {tool_findings}")
            if persist_findings:
                save_artifact(scan_id, "schema_attack", f"findings_{tool_name}", [])
            continue
        tool_findings = tool_findings or []
        all_findings.extend(item for item in tool_findings if isinstance(item, dict))
        # Save per-tool findings to disk for aggregation phase
        if persist_findings:
            save_artifact(scan_id, "schema_attack", f"findings_{tool_name}", tool_findings)
            for finding in tool_findings:
                await scan_state.add_finding(scan_id, finding)

    # Investigation callers need the observations immediately. Previously the
    # function returned None and only wrote fixed phase files, so the model saw
    # zero findings and later executions overwrote the initial artifacts.
    return all_findings
