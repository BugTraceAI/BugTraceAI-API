import asyncio
import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

from lib.apex_client import (
    analyze_findings,
    analyze_scan_overview,
    render_markdown_report,
)
from lib.campaign_grouping import campaigns_to_hypotheses, group_into_campaigns
from lib.catchall import filter_noise
from lib.coverage import SOURCE_OPENAPI, SOURCE_WORDLIST, summarize_coverage
from lib.evidence import (
    create_scan_dir,
    endpoints_to_openapi,
    enrich_openapi_from_responses,
    get_scan_dir,
    list_artifacts,
    load_artifact,
    render_scan_markdown,
    save_artifact,
    save_report,
)
from lib.findings_quality import normalize_findings
from lib.http_policy import AUDIT_NO_AUTH_WARNING
from lib.openapi import extract_operations
from lib.provider import get_active_provider
from lib.scan_state import scan_state
from lib.schema_probe import (
    _calculate_coverage,
    fetch_schema_from_url,
    probe_schema,
)
from tools.auth_probe import run_auth_probe
from tools.authz_probe import run_authz_probe
from tools.blind_attack import run_blind_attack
from tools.coverage_probe import run_coverage_probe
from tools.discovery import detect_baseline, run_api_crawl, run_kiterunner_brute, run_kiterunner_scan
from tools.investigate import run_investigation as _run_investigation
from tools.schema_attack import run_schema_attack


def _campaign_for_endpoint(endpoint: dict[str, Any], campaigns: dict[str, list]) -> str:
    """Determine which campaign an endpoint belongs to."""
    target_text = " ".join([
        str(endpoint.get("method") or ""),
        str(endpoint.get("url") or ""),
        str(endpoint.get("source") or ""),
    ]).lower()

    patterns = {
        "bola": ["identifier", "resource", "object", "access", "ownership"],
        "auth_bypass": ["unauth", "auth", "authorization", "token"],
        "ssrf": ["ssrf", "server side", "request"],
        "graphql": ["graphql", "query"],
    }

    for campaign, pattern_list in patterns.items():
        if any(p in target_text for p in pattern_list):
            return campaign
    return "other"

logger = logging.getLogger("bugtrace-api.orchestrator")

# Max concurrent scans (A-4)
MAX_CONCURRENT_SCANS = 3
# Global scan timeout in seconds (M-4) — higher to accommodate Apex AI analysis
MAX_SCAN_DURATION = 3600  # 60 minutes


class Orchestrator:
    def __init__(self):
        self.active_tasks: dict[str, asyncio.Task] = {}
        self._semaphore: asyncio.Semaphore | None = None

    @property
    def semaphore(self) -> asyncio.Semaphore:
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        return self._semaphore

    async def run_scan(
        self,
        scan_id: str,
        target: str,
        depth: str,
        auth: dict[str, Any] | None = None,
        schema_url: str | None = None,
        engine: str = "api",
        launch_origin: str = "api",
        launch_transport: str | None = None,
        allow_mutating: bool = False,
        auth_alt: dict[str, Any] | None = None,
        mode: str = "safe",
    ):
        """Main pipeline execution for a scan (with concurrency limit)."""
        async with self.semaphore:
            try:
                await asyncio.wait_for(
                    self._run_pipeline(
                        scan_id, target, depth, auth, schema_url,
                        engine=engine, launch_origin=launch_origin,
                        launch_transport=launch_transport,
                        allow_mutating=allow_mutating,
                        auth_alt=auth_alt,
                        mode=mode,
                    ),
                    timeout=MAX_SCAN_DURATION,
                )
            except TimeoutError:
                logger.error(f"[scan:{scan_id}] Pipeline exceeded global timeout of {MAX_SCAN_DURATION}s")
                try:
                    await self._finalize_partial_scan(
                        scan_id, f"global_timeout_{MAX_SCAN_DURATION}s"
                    )
                except Exception:
                    logger.exception(f"[scan:{scan_id}] Failed to update state after global timeout")
            except asyncio.CancelledError:
                logger.info(f"[scan:{scan_id}] Pipeline cancelled (stop requested)")
                try:
                    await scan_state.update_scan(scan_id, status="stopped")
                except Exception:
                    pass
            finally:
                self.active_tasks.pop(scan_id, None)
                # Periodically clean old scans from memory (M-7)
                try:
                    await scan_state.cleanup_old_scans()
                except Exception:
                    pass

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan task (A-1)."""
        task = self.active_tasks.get(scan_id)
        if task and not task.done():
            task.cancel()
            return True
        return False

    async def _finalize_partial_scan(self, scan_id: str, error: str) -> None:
        """Expose discovery/aggregation evidence when a later phase times out.

        The previous timeout handler only flipped the manifest to ``failed``.
        That made the WEB app hide a perfectly useful report and discarded any
        PoCs already produced by online provider failover. Finalisation is
        deliberately best-effort and never replaces the original timeout.
        """
        pocs = load_artifact(scan_id, "apex_analysis", "pocs") or []
        if not isinstance(pocs, list):
            pocs = []
        review = load_artifact(scan_id, "apex_analysis", "scan_review")
        if not isinstance(review, dict) or review.get("status") in {None, "running", "pending"}:
            review = {
                "status": "partial",
                "reason": error,
                "text": "",
            }
            save_artifact(scan_id, "apex_analysis", "scan_review", review)

        live_before = await scan_state.get_scan(scan_id)
        payload = {
            "status": "partial",
            "provider": live_before.analysis_provider if live_before else None,
            "model": live_before.analysis_model if live_before else None,
            "pocs_count": len(pocs),
            "pocs": pocs,
            "scan_review": review,
            "reason": error,
        }
        await scan_state.set_ai_analysis(scan_id, payload)
        save_artifact(scan_id, "apex_analysis", "pocs", pocs)
        await scan_state.update_tool_health(
            scan_id, "ai_analysis", status="partial", attempts=1,
            findings_count=len(pocs), error=error,
        )
        await scan_state.update_tool_health(
            scan_id, "orchestrator", status="timeout", attempts=1,
            findings_count=0, error=error,
        )
        await scan_state.update_scan(
            scan_id,
            status="failed",
            error=error,
            warning=(
                f"Partial report: {error}. Discovery and security checks are available; "
                "online AI enrichment did not finish."
            ),
        )

        # Re-render the public report with the terminal status and any partial
        # AI results, so the reports page can open it after a timeout.
        live = await scan_state.get_scan(scan_id)
        results = await scan_state.get_results(scan_id)
        if not results:
            return
        status = live.model_dump() if live else results.get("status", {})
        markdown = render_scan_markdown(
            scan_id=scan_id,
            target=status.get("target", ""),
            status=status,
            findings=results.get("findings", []),
            endpoints=results.get("endpoints", []),
            tool_health=results.get("tool_health", {}),
            ai_analysis=results.get("ai_analysis"),
            coverage=results.get("coverage"),
            schema=results.get("schema"),
            quality_summary=results.get("quality_summary"),
        )
        (get_scan_dir(scan_id) / "report.md").write_text(markdown)
        unified = load_artifact(scan_id, "aggregation", "unified_findings") or {}
        if isinstance(unified, dict):
            unified["status"] = status
            unified["ai_analysis"] = results.get("ai_analysis")
            save_report(scan_id, "report", unified)

    async def _run_pipeline(
        self,
        scan_id: str,
        target: str,
        depth: str,
        auth: dict[str, Any] | None = None,
        schema_url: str | None = None,
        engine: str = "api",
        launch_origin: str = "api",
        launch_transport: str | None = None,
        allow_mutating: bool = False,
        auth_alt: dict[str, Any] | None = None,
        mode: str = "safe",
    ):
        """Internal pipeline logic — file-based handoff between phases.

        Each phase writes its output to disk; the next phase reads from disk.
        This gives us full evidence trail and makes phases independent.
        """
        started = time.monotonic()
        logger.info(f"[scan:{scan_id}] Starting orchestrator for target: {target}")

        # Create CLI-style scan directory: reports/{domain}_{timestamp}_{scan_id}/
        create_scan_dir(scan_id, target)

        warning = AUDIT_NO_AUTH_WARNING if mode == "audit" and not auth else None
        await scan_state.update_scan(
            scan_id,
            status="running",
            current_phase="discovery",
            progress=0.1,
            **({"warning": warning} if warning else {}),
        )
        await scan_state.update_tool_health(
            scan_id, "orchestrator", status="running",
            attempts=1, findings_count=0, duration_ms=0, error=None,
        )

        # Save scan config so any phase can read it
        save_artifact(scan_id, "discovery", "scan_config", {
            "scan_id": scan_id,
            "target": target,
            "depth": depth,
            "auth": bool(auth),
            "auth_alt": bool(auth_alt),
            "allow_mutating": bool(allow_mutating),
            "mode": mode,
            "schema_url": schema_url,
            "engine": engine,
            "launch_origin": launch_origin,
            "launch_transport": launch_transport,
            "started_at": datetime.now(UTC).isoformat(),
        })

        try:
            # ── PHASE 1: Discovery ──────────────────────────────────────
            # Writes → 10_discovery/{kiterunner_scan,kiterunner_brute,crawl,all}_endpoints.json
            #          10_discovery/generated_openapi.json
            #          10_discovery/phase_summary.json
            await self._phase_discovery(scan_id, target, depth, auth, allow_mutating=allow_mutating)

            if await scan_state.is_stopped(scan_id):
                return

            # ── PHASE 2: Schema Probing ─────────────────────────────────
            # Reads  ← 10_discovery/all_endpoints.json
            #          10_discovery/generated_openapi.json
            # Writes → 20_schema_probe/schema_info.json
            #          20_schema_probe/schema_decision.json
            await self._phase_schema_probe(scan_id, target, auth, schema_url)

            if await scan_state.is_stopped(scan_id):
                return

            # ── PHASE 3: Attacks ────────────────────────────────────────
            # Reads  ← 10_discovery/all_endpoints.json
            #          20_schema_probe/schema_decision.json
            # Writes → 30_schema_attack/findings_{tool}.json
            #          31_blind_attack/findings_{tool}.json
            #          30_schema_attack/phase_summary.json
            #          31_blind_attack/phase_summary.json
            await self._phase_attacks(
                scan_id, target, auth, allow_mutating=allow_mutating, auth_alt=auth_alt
            )

            if await scan_state.is_stopped(scan_id):
                return

            # ── PHASE 4: Aggregation ────────────────────────────────────
            # Reads  ← ALL previous phase directories (scans everything)
            # Writes → 40_aggregation/{unified_findings, findings_only,
            #           findings_{tool}, tool_health, endpoints_summary,
            #           scan_metadata}.json
            await self._phase_aggregation(scan_id, target, depth, started, auth=auth)

            if await scan_state.is_stopped(scan_id):
                return

            # ── PHASE 5: Autonomous Investigation ──────────────────────
            # Reads  ← provisional 40_aggregation findings
            # Writes → 60_investigation/{state,hypotheses,findings,iterations}
            await self._phase_investigation(scan_id, target, auth=auth,
                                            allow_mutating=allow_mutating,
                                            auth_alt=auth_alt)

            if await scan_state.is_stopped(scan_id):
                return

            # ── PHASE 6: Final aggregation ─────────────────────────────
            # Merge investigation evidence before any user-facing report is
            # rendered. This pass is cheap and does not repeat attacks.
            await self._phase_aggregation(scan_id, target, depth, started, auth=auth)

            if await scan_state.is_stopped(scan_id):
                return

            # ── PHASE 7: AI Analysis / final report (optional) ─────────
            # Reads the final, investigation-enriched aggregation output.
            await self._phase_apex_analysis(scan_id, target)

            if await scan_state.is_stopped(scan_id):
                return

            await scan_state.update_scan(scan_id, status="completed", progress=1.0)
            results = await scan_state.get_results(scan_id)
            await scan_state.update_tool_health(
                scan_id, "orchestrator", status="ok", attempts=1,
                findings_count=len(results.get("findings", [])) if results else 0,
                duration_ms=int((time.monotonic() - started) * 1000), error=None,
            )
            await self._sync_final_report(scan_id, target)
            logger.info(f"[scan:{scan_id}] Pipeline completed successfully.")

        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.exception(f"[scan:{scan_id}] Pipeline failed: {e}")
            try:
                await scan_state.update_scan(scan_id, status="failed", error=str(e))
                await scan_state.update_tool_health(
                    scan_id, "orchestrator", status="error", attempts=1,
                    findings_count=0,
                    duration_ms=int((time.monotonic() - started) * 1000),
                    error=str(e)[:500],
                )
            except Exception:
                logger.exception(f"[scan:{scan_id}] Failed to update scan state after pipeline error")

    # ─── Phase implementations ──────────────────────────────────────────

    async def _phase_discovery(
        self,
        scan_id: str,
        target: str,
        depth: str,
        auth: dict[str, Any] | None,
        allow_mutating: bool = False,
    ):
        """Phase 1: Run discovery tools in parallel and write all results to disk.

        Three parallel passes:
          1. kr scan  (.kite wordlists) — smart API-aware probing
          2. kr brute (merged text wordlists) — brute-force with FP filtering
          3. API crawl — follow links, HAL+JSON, probe methods

        Baseline detection runs first (once) to share --ignore-length across both kr passes.
        """
        logger.info(f"[scan:{scan_id}] Phase 1: Discovery")
        phase_started = time.monotonic()

        # GET nonce paths (not HEAD). Wordlists send GET; HEAD 405 + GET 200
        # catch-alls are common and must be filtered by GET shape.
        baseline_raw = await detect_baseline(target, auth)
        if isinstance(baseline_raw, dict):
            baseline = baseline_raw
        else:
            status, length = (*baseline_raw, None, None)[:2] if isinstance(baseline_raw, tuple) else (0, None)
            baseline = {
                "status": status or 0,
                "length": length,
                "catch_all": status == 200,
                "signatures": [],
            }
        baseline_status = int(baseline.get("status") or 0)
        baseline_length = baseline.get("length")
        catch_all = bool(baseline.get("catch_all"))
        ignore_lengths: list[int] = []
        for sig in baseline.get("signatures") or []:
            n = sig.get("length")
            if n is not None and int(n) >= 0:
                ignore_lengths.append(int(n))
        if catch_all and baseline_length is not None:
            ignore_lengths.append(int(baseline_length))
        ignore_lengths = sorted(set(ignore_lengths))
        effective_ignore_length: int | list[int] | None = ignore_lengths or None
        if catch_all:
            logger.warning(
                f"[scan:{scan_id}] Catch-all detected (GET HTTP {baseline_status}, "
                f"length={baseline_length}) — filtering matching wordlist/crawl hits"
            )

        # Always run kite. Safe mode forces GET so we still discover routes.
        kr_scan_coro = run_kiterunner_scan(
            scan_id, target, depth, auth, effective_ignore_length,
            allow_mutating=allow_mutating,
        )

        discovery_results = await asyncio.gather(
            kr_scan_coro,
            run_kiterunner_brute(scan_id, target, auth, effective_ignore_length),
            run_api_crawl(scan_id, target, auth, allow_mutating=allow_mutating),
        )

        kr_scan_endpoints = discovery_results[0] if len(discovery_results) > 0 else []
        kr_brute_endpoints = discovery_results[1] if len(discovery_results) > 1 else []
        crawl_endpoints = discovery_results[2] if len(discovery_results) > 2 else []

        # Save per-tool results (even empty — evidence of what ran)
        save_artifact(scan_id, "discovery", "kiterunner_scan_endpoints", kr_scan_endpoints)
        save_artifact(scan_id, "discovery", "kiterunner_brute_endpoints", kr_brute_endpoints)
        save_artifact(scan_id, "discovery", "crawl_endpoints", crawl_endpoints)

        # Deduplicate across all sources
        seen = set()
        endpoints = []
        for sublist in discovery_results:
            for e in sublist:
                e.setdefault("source", SOURCE_WORDLIST)
                key = (e.get("method", "GET"), e.get("url", ""))
                if key not in seen:
                    seen.add(key)
                    endpoints.append(e)

        kept, discarded = filter_noise(endpoints, baseline)
        if discarded:
            logger.warning(
                f"[scan:{scan_id}] Discarded {len(discarded)} catch-all/placeholder "
                f"endpoint(s); kept {len(kept)}"
            )
        endpoints = kept

        # Group only the quality-gated inventory.  Grouping before this point
        # allowed catch-all/placeholder responses to become hypotheses.
        campaigns = group_into_campaigns(endpoints)
        for ep in endpoints:
            ep["campaign"] = _campaign_for_endpoint(ep, campaigns)
        campaign_hypotheses = campaigns_to_hypotheses(campaigns, target, endpoints)
        save_artifact(scan_id, "discovery", "campaigns", campaigns)
        save_artifact(scan_id, "discovery", "campaign_hypotheses", campaign_hypotheses)

        save_artifact(scan_id, "discovery", "all_endpoints", endpoints)
        save_artifact(scan_id, "discovery", "discarded_catchall", {
            "count": len(discarded),
            "sample": discarded[:20],
        })
        await scan_state.replace_endpoints(scan_id, endpoints)

        # Generate synthetic OpenAPI from discovered endpoints
        if endpoints:
            generated_openapi = endpoints_to_openapi(target, endpoints)
            # Enrich with real response schemas for better fuzzing
            generated_openapi = await enrich_openapi_from_responses(generated_openapi, target, auth)
            save_artifact(scan_id, "discovery", "generated_openapi", generated_openapi)
            logger.info(f"[scan:{scan_id}] Generated enriched OpenAPI with {len(generated_openapi.get('paths', {}))} paths")

        # Phase summary
        save_artifact(scan_id, "discovery", "phase_summary", {
            "total_endpoints": len(endpoints),
            "kiterunner_scan_count": len(kr_scan_endpoints),
            "kiterunner_brute_count": len(kr_brute_endpoints),
            "crawl_count": len(crawl_endpoints),
            "baseline_status": baseline_status,
            "baseline_length": baseline_length,
            "catch_all": catch_all,
            "discarded_catchall": len(discarded),
            "allow_mutating": allow_mutating,
            "kiterunner_scan_skipped": False,
            "duration_ms": int((time.monotonic() - phase_started) * 1000),
        })

        if catch_all or discarded:
            live = await scan_state.get_scan(scan_id)
            noise_note = (
                f"Catch-all/placeholder GET discarded {len(discarded)} discovery hit(s) "
                f"(probe HTTP {baseline_status}, length={baseline_length}). "
                "0 findings after this filter does not mean the API is clean."
            )
            prev = (live.warning if live else None) or ""
            warning = f"{prev} {noise_note}".strip()
            await scan_state.update_scan(scan_id, warning=warning, progress=0.3)
        else:
            await scan_state.update_scan(scan_id, progress=0.3)

        if not endpoints:
            logger.warning(f"[scan:{scan_id}] No live endpoints found in discovery phase.")

    async def _phase_schema_probe(self, scan_id: str, target: str, auth: dict[str, Any] | None, schema_url: str | None):
        """Phase 2: Probe for schema. Reads endpoints from disk, writes schema decision to disk."""
        logger.info(f"[scan:{scan_id}] Phase 2: Schema Probe")
        await scan_state.update_scan(scan_id, current_phase="schema_probe", progress=0.4)

        endpoints = load_artifact(scan_id, "discovery", "all_endpoints") or []
        generated_openapi = load_artifact(scan_id, "discovery", "generated_openapi")
        scan_config = load_artifact(scan_id, "discovery", "scan_config") or {}
        allow_mutating = bool(scan_config.get("allow_mutating"))

        schema = None
        if schema_url:
            logger.info(f"[scan:{scan_id}] Using provided schema URL: {schema_url}")
            schema_content = await fetch_schema_from_url(schema_url, auth)
            if schema_content:
                coverage = _calculate_coverage(schema_content, endpoints)
                operations = extract_operations(schema_content, target)
                schema = {
                    "url": schema_url,
                    "content": schema_content,
                    "coverage": coverage,
                    "source": "user_provided",
                    "downloaded": True,
                    "parsed": True,
                    "format": "yaml" if str(schema_url).lower().endswith((".yaml", ".yml")) else "json",
                    "paths_count": len(schema_content.get("paths") or {}),
                    "operations_count": len(operations),
                    "operations": operations,
                }
            else:
                # Couldn't fetch/parse it ourselves (schemathesis/offat may still
                # resolve the URL directly) — don't assume full coverage.
                schema = {
                    "url": schema_url,
                    "coverage": None,
                    "coverage_status": "unknown",
                    "source": "user_provided",
                    "downloaded": False,
                    "parsed": False,
                    "format": "unknown",
                    "paths_count": 0,
                    "operations_count": 0,
                    "parse_error": "schema_fetch_or_parse_failed",
                }
            await scan_state.update_tool_health(
                scan_id, "schema_probe", status="provided",
                attempts=1, findings_count=int(schema.get("operations_count") or 0),
                duration_ms=0, error=schema.get("parse_error"),
            )
        else:
            schema = await probe_schema(
                target, auth, discovered_endpoints=endpoints, scan_id=scan_id,
            )

        published = bool(
            schema
            and schema.get("source") != "auto_generated"
            and isinstance(schema.get("content"), dict)
            and (schema.get("paths_count") or len((schema.get("content") or {}).get("paths") or {})) > 0
        )

        if published and isinstance(schema.get("content"), dict):
            save_artifact(scan_id, "schema_probe", "published_openapi", schema["content"])
            operations = extract_operations(schema["content"], target)
            from lib.inventory import merge_inventory
            operations, out_of_scope = merge_inventory([], operations, [], target)
            save_artifact(scan_id, "schema_probe", "out_of_scope_operations", out_of_scope)
            save_artifact(scan_id, "schema_probe", "openapi_operations", operations)
            try:
                coverage_rows = await run_coverage_probe(
                    scan_id, operations, auth=auth, allow_mutating=allow_mutating
                )
            except Exception as exc:
                logger.warning(f"[scan:{scan_id}] Coverage probe failed: {exc}")
                coverage_rows = []
            save_artifact(scan_id, "schema_probe", "coverage_ledger", coverage_rows)
            save_artifact(scan_id, "schema_probe", "coverage_summary", summarize_coverage(coverage_rows))
            measured = summarize_coverage(coverage_rows)
            schema["coverage"] = measured["verified_coverage"]
            schema["coverage_status"] = measured["coverage_status"]
            # Merge OpenAPI-confirmed operations into the classified endpoint list
            # without rewriting wordlist/crawl records.
            classified = list(endpoints)
            seen = {(e.get("method", "GET"), e.get("url", "")) for e in classified}
            for op in operations:
                key = (op.get("method", "GET"), op.get("url", ""))
                if key not in seen:
                    seen.add(key)
                    classified.append({
                        "method": op.get("method"),
                        "url": op.get("url"),
                        "status": None,
                        "source": SOURCE_OPENAPI,
                        "auth_required": op.get("auth_required"),
                        "spec_path": op.get("spec_path"),
                    })
            spec_keys = {(op["method"], op["url"]) for op in operations}
            discovery_only = [e for e in endpoints if (e.get("method", "GET"), e.get("url")) not in spec_keys]
            discovered_observations = await run_coverage_probe(scan_id, discovery_only, auth=auth, allow_mutating=False) if discovery_only else []
            save_artifact(scan_id, "schema_probe", "discovery_validation", discovered_observations)
            classified, excluded = merge_inventory(endpoints, operations, coverage_rows + discovered_observations, target)
            save_artifact(scan_id, "schema_probe", "classified_endpoints", classified)
            save_artifact(scan_id, "schema_probe", "excluded_endpoints", excluded)

        # Fallback is labelled separately and never counted as a published spec.
        fallback = None
        if not published and generated_openapi and generated_openapi.get("paths"):
            from lib.evidence import _phase_dir
            openapi_path = _phase_dir(scan_id, "discovery") / "generated_openapi.json"
            fallback = {
                "url": str(openapi_path),
                "content": generated_openapi,
                "coverage": None,
                "coverage_status": "unknown_auto_generated",
                "source": "auto_generated",
                "downloaded": False,
                "parsed": True,
                "format": "json",
                "paths_count": len(generated_openapi.get("paths") or {}),
                "operations_count": sum(
                    1 for item in generated_openapi.get("paths", {}).values()
                    if isinstance(item, dict)
                    for method in item
                    if str(method).lower() in {"get", "put", "post", "delete", "options", "head", "patch"}
                ),
            }
            logger.info(
                f"[scan:{scan_id}] No published schema — fallback auto-generated OpenAPI "
                f"({fallback['paths_count']} paths) is labelled, not mixed"
            )
            await scan_state.update_tool_health(
                scan_id, "schema_probe", status="auto_generated",
                attempts=1, findings_count=fallback["paths_count"],
                duration_ms=0, error=None,
            )

        active = schema if published or (schema and schema.get("source") == "user_provided") else fallback
        content = (active or {}).get("content") if isinstance((active or {}).get("content"), dict) else {}
        paths_count = int((active or {}).get("paths_count") or (len(content.get("paths") or {}) if content else 0))
        operations_count = int((active or {}).get("operations_count") or 0)
        schema_decision = {
            "has_schema": bool(published or (schema and schema.get("source") == "user_provided")),
            "has_fallback_schema": bool(fallback),
            "url": (schema or fallback or {}).get("url") if (schema or fallback) else None,
            "source": (schema or fallback or {}).get("source", "none") if (schema or fallback) else "none",
            "coverage": (schema or fallback or {}).get("coverage") if (schema or fallback) else None,
            "coverage_status": (schema or fallback or {}).get("coverage_status", "unknown") if (schema or fallback) else "unknown",
            "paths_count": paths_count,
            "operations_count": operations_count,
            "downloaded": bool((schema or {}).get("downloaded")),
            "parsed": bool((schema or {}).get("parsed") or (content and paths_count)),
            "format": (schema or fallback or {}).get("format", "unknown") if (schema or fallback) else "unknown",
            "parse_error": (schema or {}).get("parse_error"),
            "mode": scan_config.get("mode", "safe"),
            "allow_mutating": bool(scan_config.get("allow_mutating")),
        }
        save_artifact(scan_id, "schema_probe", "schema_decision", schema_decision)
        save_artifact(scan_id, "schema_probe", "schema_info", schema_decision)

        if active:
            await scan_state.set_schema(scan_id, {**schema_decision, "content": content or None})
        elif schema:
            await scan_state.set_schema(scan_id, {**schema_decision, **{k: v for k, v in schema.items() if k != "content"}})

    async def _phase_attacks(
        self,
        scan_id: str,
        target: str,
        auth: dict[str, Any] | None,
        allow_mutating: bool = False,
        auth_alt: dict[str, Any] | None = None,
    ):
        """Phase 3: Run attacks. Reads schema_decision + endpoints from disk."""
        logger.info(f"[scan:{scan_id}] Phase 3: Attacks")
        await scan_state.update_scan(scan_id, current_phase="attack", progress=0.6)

        endpoints = load_artifact(scan_id, "schema_probe", "classified_endpoints")
        if endpoints is None:
            endpoints = load_artifact(scan_id, "discovery", "all_endpoints") or []
        schema_decision = load_artifact(scan_id, "schema_probe", "schema_decision") or {}
        published_spec = load_artifact(scan_id, "schema_probe", "published_openapi")

        has_schema = schema_decision.get("has_schema", False)
        parsed = bool(schema_decision.get("parsed"))
        paths_count = int(schema_decision.get("paths_count") or 0)
        coverage = schema_decision.get("coverage")
        coverage_value = float(coverage) if isinstance(coverage, (int, float)) else 0.0
        schema_url = schema_decision.get("url")
        source = schema_decision.get("source", "none")
        usable_published = bool(has_schema and schema_url and parsed and paths_count > 0 and source != "auto_generated")

        generated = load_artifact(scan_id, "discovery", "generated_openapi") or {}
        generated_paths = len(generated.get("paths") or {}) if isinstance(generated, dict) else 0

        if usable_published:
            from lib.evidence import _phase_dir
            local_spec = _phase_dir(scan_id, "schema_probe") / "published_openapi.json"
            attack_url = str(local_spec) if local_spec.exists() else schema_url
            schema = {
                "url": attack_url,
                "coverage": coverage,
                "source": source,
                "content": published_spec if isinstance(published_spec, dict) else None,
                "paths_count": paths_count,
            }
            run_blind = coverage_value < 0.7 or not endpoints
            logger.info(
                f"[scan:{scan_id}] Phase 3: published schema "
                f"(coverage={'unknown' if coverage is None else f'{coverage_value:.2f}'}, paths={paths_count}, blind={run_blind})"
            )
            coros = [
                run_schema_attack(scan_id, schema, target, auth, allow_mutating=allow_mutating),
                run_auth_probe(
                    scan_id, target, attack_url,
                    schema_content=published_spec if isinstance(published_spec, dict) else None,
                    auth=auth, auth_alt=auth_alt,
                    allow_mutating=allow_mutating, schema_source=source,
                ),
                run_authz_probe(
                    scan_id, target, attack_url,
                    schema_content=published_spec if isinstance(published_spec, dict) else None,
                    auth=auth, auth_alt=auth_alt,
                    allow_mutating=allow_mutating, schema_source=source,
                ),
            ]
            if run_blind:
                coros.append(run_blind_attack(scan_id, endpoints, target, auth))
            await asyncio.gather(*coros)
        elif generated_paths and generated_paths <= 200:
            # Tools first, even without a published spec: use the *filtered*
            # generated inventory (never the catch-all wordlist dump).
            from lib.evidence import _phase_dir
            gen_path = _phase_dir(scan_id, "discovery") / "generated_openapi.json"
            schema = {
                "url": str(gen_path),
                "coverage": None,
                "source": "auto_generated",
                "content": generated,
                "paths_count": generated_paths,
            }
            logger.info(
                f"[scan:{scan_id}] Phase 3: tools on filtered generated spec "
                f"({generated_paths} paths), then blind"
            )
            coros = [
                run_schema_attack(scan_id, schema, target, auth, allow_mutating=allow_mutating),
            ]
            if endpoints:
                coros.append(run_blind_attack(scan_id, endpoints, target, auth))
            await asyncio.gather(*coros)
        else:
            logger.info(f"[scan:{scan_id}] Phase 3B: Blind Attack only (no usable spec)")
            if endpoints:
                await run_blind_attack(scan_id, endpoints, target, auth)

        # Save attack phase summaries from tool_health
        results = await scan_state.get_results(scan_id)
        tool_health = results.get("tool_health", {}) if results else {}
        attack_tools = ["schemathesis", "offat", "vulnapi", "arjun", "x8"]
        attack_summary = {t: tool_health.get(t, {}) for t in attack_tools if t in tool_health}
        save_artifact(scan_id, "schema_attack", "attack_tool_health", attack_summary)

        # Mirror in-memory findings back to disk per-tool artifacts.
        # Aggregation reads these directly from disk, so even if the API
        # server restarts mid-scan, findings already collected by a tool
        # are visible in the file-based pipeline.
        findings = results.get("findings", []) if results else []
        phase_for_tool = {
            "arjun": "blind_attack",
            "x8": "blind_attack",
            "auth_probe": "auth_probe",
            "authz_probe": "authz_probe",
        }
        for f in findings:
            for tool in f.get("source_tools", []):
                phase = phase_for_tool.get(tool, "schema_attack")
                # Append-or-create: per-tool artifact may already exist from the
                # tool itself; we only need to ensure in-memory findings reach
                # disk for the aggregation phase. Each tool's own module already
                # saved its native findings, so we only add cross-source ones.
                # (The aggregation phase dedupes by finding id, so duplicates
                # are harmless.)
                existing = load_artifact(scan_id, phase, f"findings_{tool}") or []
                fid = f.get("id")
                if not any(x.get("id") == fid for x in existing):
                    existing.append(f)
                    save_artifact(scan_id, phase, f"findings_{tool}", existing)

    async def _phase_aggregation(
        self,
        scan_id: str,
        target: str,
        depth: str,
        pipeline_started: float,
        auth: dict[str, Any] | None = None,
    ):
        """Phase 4: Aggregate everything by reading all phase files from disk."""
        logger.info(f"[scan:{scan_id}] Phase 4: Aggregation")
        await scan_state.update_scan(scan_id, current_phase="aggregation", progress=0.9)

        # The published schema inventory is authoritative, not wordlist-only discovery.
        endpoints = load_artifact(scan_id, "schema_probe", "classified_endpoints")
        if endpoints is None:
            endpoints = load_artifact(scan_id, "discovery", "all_endpoints") or []
        discovery_summary = load_artifact(scan_id, "discovery", "phase_summary") or {}

        # Read schema decision from Phase 2
        schema_decision = load_artifact(scan_id, "schema_probe", "schema_decision") or {}

        # Collect ALL findings from Phase 3 (read from disk)
        all_findings = []
        seen_ids = set()
        for phase in ("schema_attack", "blind_attack", "auth_probe", "authz_probe"):
            for path in list_artifacts(scan_id, phase):
                if path.name.startswith("findings_"):
                    tool_findings = load_artifact(scan_id, phase, path.stem)
                    if isinstance(tool_findings, list):
                        for f in tool_findings:
                            fid = f.get("id") or hashlib.md5(
                                json.dumps(f, sort_keys=True, default=str).encode()
                            ).hexdigest()[:12]
                            if fid not in seen_ids:
                                seen_ids.add(fid)
                                all_findings.append(f)

        # Phase 6 evidence is intentionally kept in its own artifact. The
        # first aggregation is provisional; the second pass runs after the
        # autonomous investigator and becomes the authoritative input to the
        # final report.
        investigation_findings = load_artifact(scan_id, "investigation", "findings") or []
        if isinstance(investigation_findings, list):
            for finding in investigation_findings:
                if not isinstance(finding, dict):
                    continue
                fid = finding.get("id") or hashlib.md5(
                    json.dumps(finding, sort_keys=True, default=str).encode()
                ).hexdigest()[:12]
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    all_findings.append(finding)

        # ── Quality gate: classify, group headers, redact, dedup ─────
        scan_config = load_artifact(scan_id, "discovery", "scan_config") or {}
        verified_findings, quality_summary = normalize_findings(
            all_findings, target=target, auth=auth
        )
        quality_summary = {
            **quality_summary,
            "mode": scan_config.get("mode", "safe"),
            "allow_mutating": bool(scan_config.get("allow_mutating")),
            "catch_all": bool(discovery_summary.get("catch_all")),
            "discarded_catchall": int(discovery_summary.get("discarded_catchall") or 0),
            "kept_endpoints": int(discovery_summary.get("total_endpoints") or len(endpoints)),
        }
        save_artifact(scan_id, "aggregation", "quality_summary", quality_summary)
        if quality_summary.get("dropped_duplicates_or_noise"):
            logger.info(
                f"[scan:{scan_id}] Aggregation quality gate: "
                f"{quality_summary['input_count']} → {quality_summary['output_count']} "
                f"(dropped {quality_summary['dropped_duplicates_or_noise']}, "
                f"headers grouped={quality_summary.get('grouped_header_findings', 0)})"
            )

        all_findings = verified_findings
        coverage_summary = load_artifact(scan_id, "schema_probe", "coverage_summary") or {}

        # Read tool health from in-memory state (tools write here during execution)
        results = await scan_state.get_results(scan_id)
        tool_health = results.get("tool_health", {}) if results else {}

        # === Write aggregated artifacts ===

        # 1. Unified findings (full report)
        unified = {
            "scan_id": scan_id,
            "target": target,
            "total_endpoints": len(endpoints),
            "total_findings": len(all_findings),
            "schema_source": schema_decision.get("source", "none"),
            "findings": all_findings,
            "endpoints": endpoints,
            "tool_health": tool_health,
            "coverage": coverage_summary,
            "quality_summary": quality_summary,
            "schema": schema_decision,
        }
        save_artifact(scan_id, "aggregation", "unified_findings", unified)

        # 2. Findings only
        save_artifact(scan_id, "aggregation", "findings_only", all_findings)

        # 3. Per-tool findings in aggregation (copies for convenience)
        tool_groups: dict[str, list] = {}
        for f in all_findings:
            for tool in f.get("source_tools", ["unknown"]):
                tool_groups.setdefault(tool, []).append(f)
        for tool_name, tool_list in tool_groups.items():
            save_artifact(scan_id, "aggregation", f"findings_{tool_name}", tool_list)

        # 4. Tool health
        save_artifact(scan_id, "aggregation", "tool_health", tool_health)

        # 5. Endpoints summary
        save_artifact(scan_id, "aggregation", "endpoints_summary", endpoints)

        # 6. Scan metadata
        scan_config = load_artifact(scan_id, "discovery", "scan_config") or {}
        metadata = {
            "scan_id": scan_id,
            "target": target,
            "depth": depth,
            "total_endpoints": len(endpoints),
            "total_findings": len(all_findings),
            "schema_source": schema_decision.get("source", "none"),
            "duration_seconds": round(time.monotonic() - pipeline_started, 2),
            "tools_used": list(tool_health.keys()),
            "started_at": scan_config.get("started_at"),
            "discovery": discovery_summary,
            "schema": schema_decision,
            "mode": scan_config.get("mode", "safe"),
            "allow_mutating": bool(scan_config.get("allow_mutating")),
        }
        save_artifact(scan_id, "aggregation", "scan_metadata", metadata)

        # ── Top-level reports (scan root, easy to find) ─────────────
        save_report(scan_id, "findings", all_findings)
        save_report(scan_id, "endpoints", endpoints)
        save_report(scan_id, "report", unified)
        save_report(scan_id, "scan_metadata", metadata)

        live = await scan_state.get_scan(scan_id)
        markdown = render_scan_markdown(
            scan_id=scan_id,
            target=target,
            status=live.model_dump() if live else {"status": "running"},
            findings=all_findings,
            endpoints=endpoints,
            tool_health=tool_health,
            coverage=coverage_summary,
            schema=schema_decision,
            quality_summary=quality_summary,
        )
        (get_scan_dir(scan_id) / "report.md").write_text(markdown)

        # Update in-memory findings so live GET /results matches disk
        await scan_state.replace_findings(scan_id, all_findings)
        await scan_state.set_coverage(scan_id, coverage_summary, quality_summary)
        await scan_state.update_scan(scan_id, findings_count=len(all_findings))

    async def _phase_apex_analysis(self, scan_id: str, target: str):
        """Phase 5 (optional): provider-backed AI PoC generation.

        Reads findings from Phase 4 aggregation output.
        Writes → 50_apex_analysis/pocs.json
                 50_apex_analysis/report.md

        Gracefully skipped if APEX_ENABLED=false or Ollama is not reachable.
        """
        from lib.evidence import get_scan_dir
        provider = get_active_provider()
        results = await scan_state.get_results(scan_id)
        findings = results.get("findings", []) if results else []

        async def _store_ai(payload: dict[str, Any]) -> None:
            await scan_state.set_ai_analysis(scan_id, payload)
            # Persist even skipped/error outcomes so a restarted API can show
            # the truth in the report instead of returning ai_analysis=null.
            save_artifact(scan_id, "apex_analysis", "pocs", payload.get("pocs") or [])
            save_artifact(scan_id, "apex_analysis", "scan_review", payload.get("scan_review") or {
                "status": payload.get("status") or "skipped",
                "reason": payload.get("skipped") or payload.get("reason") or payload.get("note") or "not run",
                "text": "",
            })

        if not provider.enabled:
            logger.info(f"[scan:{scan_id}] Phase 5: AI analysis disabled (APEX_ENABLED=false)")
            await _store_ai({
                "provider": getattr(provider, "id", None),
                "skipped": "disabled",
                "note": "AI enrichment disabled (APEX_ENABLED=false).",
                "pocs_count": 0,
                "pocs": [],
            })
            return

        logger.info(
            f"[scan:{scan_id}] Phase 5: AI analysis "
            f"(provider={provider.id}, model={provider.model}, min_severity={provider.min_severity})"
        )
        await scan_state.update_scan(
            scan_id,
            current_phase="ai_analysis",
            progress=0.95,
            analysis_provider=provider.id,
            analysis_model=provider.model,
        )
        phase_started = time.monotonic()

        if not findings:
            logger.info(f"[scan:{scan_id}] Phase 5: No confirmed findings — still running scan overview")
            note = (
                "No confirmed findings to turn into PoCs. Tool reports and discovery "
                "are still reviewed. 0 confirmed is not a clean-API verdict if catch-all "
                "hits were discarded or tools were skipped."
            )
            if not provider.api_key and not provider.is_local:
                await _store_ai({
                    "provider": provider.id,
                    "model": provider.model,
                    "skipped": "no_findings",
                    "note": note,
                    "pocs_count": 0,
                    "pocs": [],
                })
                await scan_state.update_tool_health(
                    scan_id, "ai_analysis", status="skipped",
                    attempts=0, findings_count=0,
                    duration_ms=int((time.monotonic() - phase_started) * 1000),
                    error="no_findings",
                )
                return
            # Fall through: overview can still describe schema, endpoints, tool health.

        if not provider.enabled:
            await scan_state.update_scan(
                scan_id,
                warning="AI enrichment is disabled; discovery and security checks completed normally.",
            )
        elif not provider.is_local and not provider.api_key:
            # Provider configuration is intentionally optional for the API
            # scanner: discovery/attack phases remain useful without AI. Make
            # that degraded-but-successful outcome explicit in the public scan
            # status instead of leaving the user to infer it from server logs.
            await scan_state.update_scan(
                scan_id,
                warning=(
                    f"AI enrichment skipped: provider '{provider.name}' has no API key. "
                    "The report is partial; without a provider you may miss more than half of the complete analysis, "
                    "including prioritisation and PoC generation. Discovery and security checks completed normally."
                ),
            )

        partial_pocs: list[dict[str, Any]] = []

        async def _on_ai_result(result: dict[str, Any]) -> None:
            partial_pocs.append(result)
            await _store_ai({
                "status": "partial",
                "provider": provider.id,
                "model": provider.model,
                "pocs_count": len(partial_pocs),
                "pocs": list(partial_pocs),
                "scan_review": {
                    "status": "pending",
                    "reason": "Finding-level online analysis is still running",
                    "text": "",
                },
            })

        pocs = await analyze_findings(
            findings=findings,
            target=target,
            provider=provider,
            min_severity=provider.min_severity,
            scan_id=scan_id,
            on_result=_on_ai_result,
        )

        overview = await analyze_scan_overview(
            findings=findings,
            endpoints=results.get("endpoints", []) if results else [],
            schema=results.get("schema") if results else None,
            pocs=pocs,
            target=target,
            provider=provider,
            scan_id=scan_id,
        )
        status_counts: dict[str, int] = {}
        for poc in pocs:
            label = str(poc.get("report_status") or "inconclusive")
            status_counts[label] = status_counts.get(label, 0) + 1
        overview["semantic_status_counts"] = status_counts
        from lib.review_projection import project_reviews, review_quality
        from lib.apex_client import filter_findings
        quality = review_quality(pocs, overview, len(filter_findings(findings, provider.min_severity)))
        overview["status"] = quality["status"]
        overview["review_quality"] = quality
        projected = project_reviews(findings, pocs)
        save_artifact(scan_id, "apex_analysis", "pre_review_findings", findings)
        save_artifact(scan_id, "apex_analysis", "reviewed_findings", projected)
        await scan_state.replace_findings(scan_id, projected)
        unified = load_artifact(scan_id, "aggregation", "unified_findings") or {}
        unified.update(findings=projected, total_findings=len(projected))
        unified.setdefault("quality_summary", {}).update(ai_review=quality)
        save_artifact(scan_id, "aggregation", "unified_findings", unified)
        save_artifact(scan_id, "aggregation", "findings_only", projected)
        save_report(scan_id, "findings", projected)
        save_report(scan_id, "report", unified)
        await scan_state.set_coverage(scan_id, unified.get("coverage", {}), unified["quality_summary"])
        live = await scan_state.get_scan(scan_id)
        final_markdown = render_scan_markdown(scan_id=scan_id, target=target,
            status=live.model_dump() if live else {}, findings=projected,
            endpoints=unified.get("endpoints", []), tool_health=unified.get("tool_health", {}),
            coverage=unified.get("coverage", {}), schema=unified.get("schema", {}),
            quality_summary=unified["quality_summary"])
        (get_scan_dir(scan_id) / "report.md").write_text(final_markdown)

        # Save structured PoCs as JSON
        save_artifact(scan_id, "apex_analysis", "pocs", pocs)
        save_artifact(scan_id, "apex_analysis", "scan_review", overview)

        # Save human-readable markdown report as .md files
        md = render_markdown_report(pocs, target, provider.model, scan_id, scan_overview=overview)

        from lib.evidence import _phase_dir, get_scan_dir
        # Phase artifact: 50_apex_analysis/report.md
        apex_dir = _phase_dir(scan_id, "apex_analysis")
        apex_dir.mkdir(parents=True, exist_ok=True)
        (apex_dir / "report.md").write_text(md)
        # Top-level: reports/{domain}/apex_report.md
        (get_scan_dir(scan_id) / "apex_report.md").write_text(md)

        # Store in scan_state for API access
        async with scan_state.lock:
            if scan_id in scan_state.scan_responses:
                scan_state.scan_responses[scan_id]["ai_analysis"] = {
                    "status": (overview or {}).get("status") or "ok",
                    "provider": provider.id,
                    "model": provider.model,
                    "pocs_count": quality["pocs_count"],
                    "reviews_count": len(pocs),
                    "pocs": pocs,
                    "scan_review": overview,
                    "report_md": md,
                }

        elapsed = int((time.monotonic() - phase_started) * 1000)
        await scan_state.update_tool_health(
            # Public health keys are provider-neutral; the on-disk phase name
            # remains ``apex_analysis`` only for backwards-compatible artifact
            # paths and rehydration.
            scan_id, "ai_analysis", status=quality["status"],
            attempts=1, findings_count=len(pocs), duration_ms=elapsed, error=None,
        )
        logger.info(f"[scan:{scan_id}] Phase 5: {len(pocs)} reviews, {quality['pocs_count']} confirmed PoCs, whole-scan review={overview.get('status')} in {elapsed}ms")

    async def _sync_final_report(self, scan_id: str, target: str):
        """One final projection for REST, restart hydration, JSON and Markdown."""
        from lib.evidence import get_scan_dir
        results = await scan_state.get_results(scan_id) or {}
        unified = load_artifact(scan_id, "aggregation", "unified_findings") or {}
        investigation = load_artifact(scan_id, "investigation", "state") or {}
        quality = dict(unified.get("quality_summary") or {})
        ai = results.get("ai_analysis") or {}
        quality["investigation_status"] = investigation.get("status", "not_run")
        quality["status"] = "partial" if investigation.get("status") in {"partial", "failed", "stopped"} or ai.get("status") == "partial" else "completed"
        health = results.get("tool_health") or {}
        unified.update(tool_health=health, quality_summary=quality, ai_analysis=ai,
                       findings=results.get("findings", []), investigation=investigation)
        save_artifact(scan_id, "aggregation", "tool_health", health)
        save_artifact(scan_id, "aggregation", "quality_summary", quality)
        save_artifact(scan_id, "aggregation", "unified_findings", unified)
        save_report(scan_id, "report", unified)
        save_report(scan_id, "findings", unified["findings"])
        await scan_state.set_coverage(scan_id, unified.get("coverage", {}), quality)
        live = await scan_state.get_scan(scan_id)
        if quality["status"] == "partial":
            previous = live.warning or "" if live else ""
            await scan_state.update_scan(scan_id, warning=(previous + " Analysis incomplete: unresolved investigation or AI review errors; see quality summary.").strip())
        markdown = render_scan_markdown(scan_id=scan_id, target=target, status=live.model_dump() if live else {},
            findings=unified["findings"], endpoints=unified.get("endpoints", []), tool_health=health,
            coverage=unified.get("coverage", {}), schema=unified.get("schema", {}), quality_summary=quality)
        (get_scan_dir(scan_id) / "report.md").write_text(markdown)

    async def _phase_investigation(self, scan_id: str, target: str,
                                   auth: dict[str, Any] | None = None,
                                   allow_mutating: bool = False,
                                   auth_alt: dict[str, Any] | None = None):
        """Phase 6 (optional): autonomous investigation loop.

        Reads quality-gated findings from Phase 4, endpoints/schema/campaigns
        from Phase 1/2, then runs an LLM-driven investigation that formulates
        hypotheses, plans targeted tool calls, and iterates until budget
        exhaustion or hypothesis confirmation.

        Writes -> 60_investigation/{state,hypotheses,validation_plan,iterations}
        """
        logger.info(f"[scan:{scan_id}] Phase 6: Investigation")
        provider = get_active_provider()
        if not provider.enabled:
            logger.info(f"[scan:{scan_id}] Phase 6: Investigation disabled (provider disabled)")
            return
        results = await scan_state.get_results(scan_id)
        findings = results.get("findings", []) if results else []
        endpoints = results.get("endpoints", []) if results else []
        campaigns = load_artifact(scan_id, "discovery", "campaigns") or {}
        campaign_hypotheses = load_artifact(scan_id, "discovery", "campaign_hypotheses") or []
        if not endpoints and not findings and not campaigns:
            logger.info(f"[scan:{scan_id}] Phase 6: Nothing to investigate")
            return
        try:
            state = await _run_investigation(
                scan_id=scan_id,
                target=target,
                endpoints=endpoints,
                findings=findings,
                campaigns=campaigns,
                campaign_hypotheses=campaign_hypotheses,
                auth=auth,
                auth_alt=auth_alt,
                allow_mutating=allow_mutating,
                provider=provider,
            )
            if state.error:
                logger.warning(f"[scan:{scan_id}] Phase 6: Investigation error: {state.error}")
            logger.info(
                f"[scan:{scan_id}] Phase 6: Investigation complete - "
                f"{len(state.hypotheses)} hypotheses, "
                f"{state.total_tool_calls} tool calls, "
                f"status={state.status}, stop_reason={state.stop_reason}"
            )
        except Exception as exc:
            logger.exception(f"[scan:{scan_id}] Phase 6: Investigation failed: {exc}")
            await scan_state.update_scan(
                scan_id,
                warning=(
                    f"{(await scan_state.get_scan(scan_id)).warning or ''} "
                    f"Investigation failed: {exc}".strip()
                ),
            )


    async def launch_api_scan(
        self,
        scan_id: str,
        target: str,
        depth: str = "standard",
        auth: dict[str, Any] | None = None,
        schema_url: str | None = None,
        engine: str = "api",
        launch_origin: str = "api",
        launch_transport: str | None = None,
        allow_mutating: bool = False,
        auth_alt: dict[str, Any] | None = None,
        mode: str = "safe",
        warning: str | None = None,
    ) -> dict[str, Any]:
        """Centralised API scan startup used by both REST and MCP.

        Generates/receives the scan ID in one place, creates the scan directory
        and manifest, registers exactly one cancellable task, and returns the
        canonical response dict.
        """
        await scan_state.create_scan(
            scan_id,
            target,
            engine=engine,
            launch_origin=launch_origin,
            launch_transport=launch_transport,
        )
        if warning:
            await scan_state.update_scan(scan_id, warning=warning)
        task = asyncio.create_task(
            self.run_scan(
                scan_id, target, depth, auth, schema_url,
                engine=engine, launch_origin=launch_origin,
                launch_transport=launch_transport,
                allow_mutating=allow_mutating,
                auth_alt=auth_alt,
                mode=mode,
            )
        )
        self.active_tasks[scan_id] = task

        def _on_done(t: asyncio.Task) -> None:
            if t.cancelled():
                return
            exc = t.exception()
            if exc:
                logger.error(f"[scan:{scan_id}] Background task failed: {exc}")

        task.add_done_callback(_on_done)

        return {
            "scan_id": scan_id,
            "status": "started",
            "engine": engine,
            "launch_origin": launch_origin,
            "message": f"Scan {scan_id} started.",
        }

orchestrator = Orchestrator()
