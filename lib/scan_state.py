import asyncio
import base64
import json
import logging
from datetime import UTC, datetime
from typing import Annotated, Any, Optional

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from lib.evidence import (
    REPORTS_DIR,
    create_scan_dir,
    get_scan_dir,
    load_artifact,
    load_scan_manifest,
    save_scan_manifest,
)
from lib.provider import list_provider_profiles

logger = logging.getLogger("bugtrace-api.lib.scan_state")


def _provider_for_model(model: Any) -> str | None:
    """Resolve a provider id from a persisted model identifier.

    Older API scan manifests predate provider provenance and only retain the
    model used by the AI phase in each PoC.  Reconstructing the provider from
    the configured model catalog keeps those historical reports truthful
    without guessing from the currently active provider.
    """
    normalized = str(model or "").strip()
    if not normalized:
        return None
    for profile in list_provider_profiles():
        if normalized in {str(value).strip() for value in profile.get("models", [])}:
            return str(profile.get("id") or "") or None
    # OpenRouter model ids conventionally include a provider/model namespace;
    # retain a conservative fallback for older custom model entries.
    if "/" in normalized:
        return "openrouter"
    return None


def _poc_model(pocs: Any) -> str | None:
    if not isinstance(pocs, list):
        return None
    for poc in pocs:
        if isinstance(poc, dict) and poc.get("model_used"):
            return str(poc["model_used"])
    return None


def _coerce_repro(v: Any) -> dict[str, str]:
    """Coerce every value in ``repro`` to str (pydantic v2 BeforeValidator)."""
    if not isinstance(v, dict):
        raise ValueError("repro must be a dict")
    return {str(k): str(val) for k, val in v.items()}


ReproDict = Annotated[dict[str, str], BeforeValidator(_coerce_repro)]


def _finding_detail_context(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a compact, human-readable context block for the report UI.

    Tool evidence remains available unchanged. This normalized subset makes
    the expanded finding row useful without forcing the browser to interpret
    every scanner-specific JSON shape itself.
    """
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    repro = finding.get("repro") if isinstance(finding.get("repro"), dict) else {}
    cvss = evidence.get("cvss") if isinstance(evidence.get("cvss"), dict) else {}
    context: dict[str, Any] = {}

    def first(*values: Any) -> Any:
        return next((value for value in values if value not in (None, "", [], {})), None)

    values = {
        "check_id": first(evidence.get("id"), evidence.get("check_id"), evidence.get("rule_id")),
        "summary": first(
            evidence.get("description"), evidence.get("summary"), evidence.get("message"),
            evidence.get("details"), repro.get("note"), evidence.get("name"),
        ),
        "observed_status": first(evidence.get("status"), evidence.get("result"), repro.get("status")),
        "cvss_vector": first(cvss.get("vector"), repro.get("cvss_vector")),
        "method": first(repro.get("method"), evidence.get("method"), evidence.get("http_method")),
        "parameter": first(repro.get("parameter"), evidence.get("parameter")),
        "payload": first(repro.get("payload"), evidence.get("payload")),
        "classification": first(finding.get("classification"), evidence.get("classification")),
        "validation_status": first(finding.get("validation_status"), repro.get("status")),
        "cvss_score": first(
            (cvss.get("score") if isinstance(cvss, dict) else None),
            repro.get("cvss_score"),
        ),
        "affected_endpoints": first(
            finding.get("affected_count"),
            len(finding.get("affected_endpoints", [])) if isinstance(finding.get("affected_endpoints"), list) else None,
        ),
    }
    for key, value in values.items():
        if value not in (None, "", [], {}):
            context[key] = value
    return context


def _decorate_findings_for_api(
    findings: list[dict[str, Any]], ai_analysis: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """Decorate API findings with normalized details and matching AI output."""
    pocs = ai_analysis.get("pocs", []) if isinstance(ai_analysis, dict) else []
    by_finding_id = {
        str(poc.get("finding_id")): poc
        for poc in pocs
        if isinstance(poc, dict) and poc.get("finding_id")
    }
    decorated: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        context = _finding_detail_context(item)
        if context:
            item["detail_context"] = context
        poc = by_finding_id.get(str(item.get("id")))
        if poc:
            item["ai_enrichment"] = {
                "status": "generated" if poc.get("poc") else "error",
                "model": poc.get("model_used") or (ai_analysis or {}).get("model"),
                "poc": poc.get("poc") or "",
                "error": poc.get("error"),
                "failover_trail": poc.get("failover_trail") or [],
                "validation": poc.get("validation") or {},
                "review": poc.get("review") or {},
            }
        decorated.append(item)
    return decorated


class Finding(BaseModel):
    """Normalised finding — every tool wrapper must emit dicts conforming to this.

    Validation is intentionally lenient on *extra* fields (so the aggregation
    phase can keep tool-specific payload) but strict on the *contract* fields
    (required keys, normalised severity, clamped confidence).
    """

    model_config = ConfigDict(extra="allow", populate_by_name=True)

    id: str
    title: str
    severity: str
    confidence: float
    category: str
    endpoint: str
    source_tools: list[str]
    evidence: dict[str, Any] = Field(default_factory=dict)
    repro: ReproDict = Field(default_factory=dict)
    classification: str | None = None
    validation_status: str | None = None

    @field_validator("classification")
    @classmethod
    def _classification_field(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        s = str(v).strip().lower()
        allowed = {"confirmed", "suspicious", "hardening", "insufficient"}
        if s not in allowed:
            raise ValueError(f"classification '{s}' not in {allowed}")
        return s

    @field_validator("id", "title", "category", "endpoint")
    @classmethod
    def _non_empty_str(cls, v: str) -> str:
        s = str(v).strip()
        if not s:
            raise ValueError("field must be non-empty")
        return s

    @field_validator("severity")
    @classmethod
    def _normalise_severity(cls, v: Any) -> str:
        s = str(v).strip().lower()
        allowed = {"critical", "high", "medium", "low", "info"}
        if s not in allowed:
            raise ValueError(f"severity '{s}' not in {allowed}")
        return s

    @field_validator("confidence")
    @classmethod
    def _clamp_confidence(cls, v: Any) -> float:
        f = float(v)
        if f < 0.0:
            return 0.0
        if f > 1.0:
            return 1.0
        return f

    @field_validator("source_tools")
    @classmethod
    def _non_empty_tools(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("source_tools must be non-empty")
        return [str(t) for t in v]

    @field_validator("repro")
    @classmethod
    def _coerce_repro_values(cls, v: dict[str, Any]) -> dict[str, str]:
        return {k: str(val) for k, val in v.items()}

    @classmethod
    def validate_dict(cls, raw: dict[str, Any]) -> dict[str, Any]:
        """Validate ``raw`` and return a clean dict.

        Raises ``ValueError`` with a concise message when the contract is
        violated, so callers (add_finding) can log and skip the bad finding.
        """
        try:
            validated = cls.model_validate(raw)
        except Exception as e:
            msgs = []
            try:
                for err in e.errors():
                    loc = ".".join(str(x) for x in err.get("loc", []))
                    msgs.append(f"{loc}: {err['msg']}")
            except Exception:
                msgs = [str(e)]
            raise ValueError("; ".join(msgs)) from e
        return validated.model_dump()

# Canonical launch origins (B.1). These are the only four supported values for
# new scans; API REST accepts only "web-api" or "api", MCP always records "api".
ALLOWED_LAUNCH_ORIGINS = {"web-cli", "web-api", "cli", "api"}


class ScanStatus(BaseModel):
    scan_id: str
    target: str
    engine: str = "api"  # "cli" or "api"
    launch_origin: str = "api"  # web-cli, web-api, cli, api
    launch_transport: str | None = None  # optional "rest" | "mcp" audit detail
    status: str = "pending"  # pending, running, completed, failed, stopped
    current_phase: str = "discovery" # discovery, schema_probe, schema_attack, blind_attack, aggregation, ai_analysis
    progress: float = 0.0
    started_at: str
    finished_at: str | None = None
    findings_count: int = 0
    error: str | None = None
    warning: str | None = None
    # Public provenance for the optional AI enrichment phase.  Keeping this on
    # the status/manifest makes it clear that "AI analysis" may use OpenRouter,
    # Anthropic, Z.ai, or local Ollama; it is not synonymous with Apex/local.
    analysis_provider: str | None = None
    analysis_model: str | None = None

    @field_validator("current_phase", mode="before")
    @classmethod
    def _phase_field(cls, v: str) -> str:
        """Normalize the pre-provider public label on rehydrated scans."""
        return "ai_analysis" if str(v).lower() == "apex_analysis" else v

    @field_validator("engine")
    @classmethod
    def _engine_field(cls, v: str) -> str:
        if v != "api":
            raise ValueError("ScanStatus engine for BugTraceAI-API must be 'api'")
        return v

    @field_validator("launch_origin")
    @classmethod
    def _launch_origin_field(cls, v: str) -> str:
        if v not in ALLOWED_LAUNCH_ORIGINS:
            raise ValueError(
                f"launch_origin '{v}' not in {sorted(ALLOWED_LAUNCH_ORIGINS)}"
            )
        return v

MAX_COMPLETED_SCANS = 100

class ScanState:
    _instance: Optional['ScanState'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.active_scans = {}
            cls._instance._lock: asyncio.Lock | None = None
            cls._instance.scan_responses = {} # Store raw responses/findings per scan
        return cls._instance

    @staticmethod
    def _openapi_artifact_exists(scan_id: str) -> bool:
        """Return whether discovery produced any durable OpenAPI artifact."""
        scan_dir = get_scan_dir(scan_id)
        return any(
            (scan_dir / relative).is_file()
            for relative in (
                "20_schema_probe/published_openapi.json",
                "10_discovery/generated_openapi.json",
            )
        )

    @staticmethod
    def _results_artifact_exists(scan_id: str) -> bool:
        """Return whether a terminal scan has a report that can be opened.

        A timed-out AI phase still has a complete discovery/aggregation report.
        Treating ``failed`` as synonymous with ``no results`` hid that useful
        evidence from the WEB reports page.
        """
        scan_dir = get_scan_dir(scan_id)
        return any(
            (scan_dir / relative).is_file()
            for relative in (
                "40_aggregation/unified_findings.json",
                "report.json",
                "findings.json",
            )
        )

    @property
    def lock(self) -> asyncio.Lock:
        """Lazy-init lock inside the running event loop (fixes B-2)."""
        if self._lock is None:
            self._lock = asyncio.Lock()
        return self._lock

    async def create_scan(
        self,
        scan_id: str,
        target: str,
        engine: str = "api",
        launch_origin: str = "api",
        launch_transport: str | None = None,
    ) -> None:
        """Create in-memory state and persist the public scan manifest.

        ``launch_origin`` is the canonical B.1 value captured at creation time.
        ``launch_transport`` is optional audit metadata (e.g. "mcp") and is
        deliberately kept out of the public scan response/list DTOs.
        """
        async with self.lock:
            now = datetime.now(UTC).isoformat()
            # Register the canonical scan directory so that the pending manifest
            # is written into the same dir the orchestrator later reuses. This
            # guarantees the manifest location is stable across a restart.
            create_scan_dir(scan_id, target)
            self.active_scans[scan_id] = ScanStatus(
                scan_id=scan_id,
                target=target,
                engine=engine,
                launch_origin=launch_origin,
                status="pending",
                started_at=now,
                launch_transport=launch_transport,
            )
            self.scan_responses[scan_id] = {
                "endpoints": [],
                "findings": [],
                "schema": None,
                "tool_health": {},
                "ai_analysis": None,
                "coverage": None,
                "quality_summary": None,
                "artifacts_path": ""
            }
            save_scan_manifest(
                scan_id=scan_id,
                engine=engine,
                launch_origin=launch_origin,
                launch_transport=launch_transport,
                status="pending",
                target=target,
                started_at=now,
            )

    async def update_scan(self, scan_id: str, **kwargs) -> None:
        async with self.lock:
            if scan_id in self.active_scans:
                scan = self.active_scans[scan_id]
                for key, value in kwargs.items():
                    if hasattr(scan, key):
                        setattr(scan, key, value)

                # If status is finished, set finished_at if not set
                if scan.status in ["completed", "failed", "stopped"] and not scan.finished_at:
                    scan.finished_at = datetime.now(UTC).isoformat()

                # Persist the latest public status on every update.
                save_scan_manifest(
                    scan_id=scan_id,
                    engine=scan.engine,
                    launch_origin=scan.launch_origin,
                    launch_transport=scan.launch_transport,
                    status=scan.status,
                    target=scan.target,
                    started_at=scan.started_at,
                    finished_at=scan.finished_at,
                    findings_count=scan.findings_count,
                    current_phase=scan.current_phase,
                    progress=scan.progress,
                    openapi_available=self._openapi_artifact_exists(scan_id),
                    error=scan.error,
                    warning=scan.warning,
                    analysis_provider=scan.analysis_provider,
                    analysis_model=scan.analysis_model,
                )

    async def _rehydrate(self, scan_id: str) -> bool:
        """Rehydrate a persisted scan into memory.

        Returns True when the manifest was loaded. If a scan is already active,
        it is left alone; this preserves live findings while still guaranteeing
        that a rehydrated status carries the persisted provenance.
        """
        if scan_id in self.active_scans:
            return False

        manifest = await asyncio.to_thread(load_scan_manifest, scan_id)
        if not manifest:
            return False

        try:
            status = ScanStatus.model_validate(manifest)
        except Exception as e:
            logger.warning(
                f"[scan:{scan_id}] Ignoring invalid scan manifest: {e}"
            )
            return False

        # Load persisted results from disk artifacts (defect 3).
        unified = await asyncio.to_thread(
            load_artifact, scan_id, "aggregation", "unified_findings"
        )
        if not isinstance(unified, dict):
            unified = {}

        findings = unified.get("findings", []) or []
        endpoints = unified.get("endpoints", []) or []
        tool_health = unified.get("tool_health", {}) or {}

        schema_info = await asyncio.to_thread(
            load_artifact, scan_id, "schema_probe", "schema_info"
        )
        if not isinstance(schema_info, dict):
            schema_info = {}

        ai_analysis = None
        pocs = await asyncio.to_thread(
            load_artifact, scan_id, "apex_analysis", "pocs"
        )
        if not isinstance(pocs, list):
            pocs = []
        scan_review = await asyncio.to_thread(
            load_artifact, scan_id, "apex_analysis", "scan_review"
        )
        if not isinstance(scan_review, dict):
            scan_review = None
        ai_health = tool_health.get("ai_analysis") if isinstance(tool_health, dict) else None
        if pocs or scan_review or ai_health or status.analysis_provider:
            md = ""
            try:
                md = (get_scan_dir(scan_id) / "apex_report.md").read_text()
            except Exception:
                pass
            # Manifests written before provider provenance was introduced may
            # still have null fields.  PoC records retain the exact model, so
            # recover both values when rehydrating those historical scans.
            recovered_model = status.analysis_model or _poc_model(pocs)
            recovered_provider = status.analysis_provider or _provider_for_model(recovered_model)
            if recovered_model and not status.analysis_model:
                status.analysis_model = recovered_model
            if recovered_provider and not status.analysis_provider:
                status.analysis_provider = recovered_provider
            ai_analysis = {
                "status": (scan_review or {}).get("status") if isinstance(scan_review, dict) else None,
                "provider": status.analysis_provider,
                "model": status.analysis_model,
                "pocs_count": sum(bool((p.get("validation") or {}).get("confirmed")) for p in pocs),
                "reviews_count": len(pocs),
                "pocs": pocs,
                "scan_review": scan_review,
                "report_md": md,
            }

        async with self.lock:
            self.active_scans[scan_id] = status
            coverage = unified.get("coverage")
            quality_summary = unified.get("quality_summary")
            self.scan_responses[scan_id] = {
                "endpoints": endpoints,
                "findings": findings,
                "schema": schema_info if schema_info else None,
                "tool_health": tool_health,
                "ai_analysis": ai_analysis,
                "coverage": coverage,
                "quality_summary": quality_summary,
                "artifacts_path": str(get_scan_dir(scan_id)),
            }
        return True

    async def get_scan(self, scan_id: str) -> ScanStatus | None:
        async with self.lock:
            scan = self.active_scans.get(scan_id)
        if scan:
            return scan

        # Rehydrate from disk after a restart/cleanup.
        if await self._rehydrate(scan_id):
            async with self.lock:
                return self.active_scans.get(scan_id)
        return None

    async def list_scans(
        self, limit: int = 50, cursor: str | None = None
    ) -> tuple[list[dict[str, Any]], str | None]:
        """List persisted and live scans, newest first, with opaque cursor support.

        Returns a ``(page, next_cursor)`` tuple. ``next_cursor`` is an opaque
        string for the next page (or ``None`` when there are no more pages).
        """
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if limit > 200:
            raise ValueError("limit must be <= 200")

        scans: list[dict[str, Any]] = []
        seen: set[str] = set()

        # Start from persisted manifests, which are the durable source of truth.
        if REPORTS_DIR.exists():
            for manifest_path in sorted(
                REPORTS_DIR.glob("*/scan_manifest.json"), reverse=True
            ):
                try:
                    manifest = await asyncio.to_thread(
                        json.loads, manifest_path.read_text()
                    )
                    scan_id = manifest["scan_id"]
                    if scan_id in seen:
                        continue
                    seen.add(scan_id)
                    analysis_provider = manifest.get("analysis_provider")
                    analysis_model = manifest.get("analysis_model")
                    if not analysis_model or not analysis_provider:
                        persisted_pocs = await asyncio.to_thread(
                            load_artifact, scan_id, "apex_analysis", "pocs"
                        )
                        analysis_model = analysis_model or _poc_model(persisted_pocs)
                        analysis_provider = analysis_provider or _provider_for_model(analysis_model)
                    scans.append(
                        {
                            "scan_id": scan_id,
                            "target": manifest.get("target", ""),
                            "engine": "api",
                            "launch_origin": manifest.get("launch_origin", "api"),
                            "status": manifest.get("status", "pending"),
                            "current_phase": (
                                "ai_analysis"
                                if str(manifest.get("current_phase", "discovery")).lower() == "apex_analysis"
                                else manifest.get("current_phase", "discovery")
                            ),
                            "progress": float(manifest.get("progress", 0.0)),
                            "started_at": manifest.get("started_at"),
                            "finished_at": manifest.get("finished_at"),
                            "findings_count": int(
                                manifest.get("findings_count", 0)
                            ),
                            "analysis_provider": analysis_provider,
                            "analysis_model": analysis_model,
                            "results_available": (
                                manifest.get("status") == "completed"
                                or (
                                    manifest.get("status") in {"failed", "stopped"}
                                    and self._results_artifact_exists(scan_id)
                                )
                            ),
                            "openapi_available": manifest.get(
                                "openapi_available", False
                            ) or (manifest_path.parent / "10_discovery" / "generated_openapi.json").is_file(),
                            "storage": "disk",
                        }
                    )
                except Exception as e:
                    logger.warning(
                        f"[scan] Ignoring invalid manifest {manifest_path}: {e}"
                    )

        # Merge live scans (newer in-memory state wins) and deduplicate by id.
        async with self.lock:
            for scan_id, scan in list(self.active_scans.items()):
                if scan_id in seen:
                    # Keep the persisted list item but update the live values.
                    for item in scans:
                        if item["scan_id"] == scan_id:
                            item.update(
                                {
                                    "target": scan.target,
                                    "engine": "api",
                                    "launch_origin": scan.launch_origin,
                                    "status": scan.status,
                                    "current_phase": scan.current_phase,
                                    "progress": scan.progress,
                                    "started_at": scan.started_at,
                                    "finished_at": scan.finished_at,
                                    "findings_count": scan.findings_count,
                                    "analysis_provider": scan.analysis_provider,
                                    "analysis_model": scan.analysis_model,
                                    "results_available": (
                                        scan.status == "completed"
                                        or (
                                            scan.status in {"failed", "stopped"}
                                            and self._results_artifact_exists(scan_id)
                                        )
                                    ),
                                    "openapi_available": self._openapi_artifact_exists(
                                        scan_id
                                    ),
                                    "storage": "memory",
                                }
                            )
                            break
                    continue

                seen.add(scan_id)
                scans.append(
                    {
                        "scan_id": scan_id,
                        "target": scan.target,
                        "engine": "api",
                        "launch_origin": scan.launch_origin,
                        "status": scan.status,
                        "current_phase": scan.current_phase,
                        "progress": scan.progress,
                        "started_at": scan.started_at,
                        "finished_at": scan.finished_at,
                        "findings_count": scan.findings_count,
                        "analysis_provider": scan.analysis_provider,
                        "analysis_model": scan.analysis_model,
                        "results_available": (
                            scan.status == "completed"
                            or (
                                scan.status in {"failed", "stopped"}
                                and self._results_artifact_exists(scan_id)
                            )
                        ),
                        "openapi_available": self._openapi_artifact_exists(scan_id),
                        "storage": "memory",
                    }
                )

        # Stable newest-first by started_at, then scan_id.
        scans.sort(
            key=lambda item: (item.get("started_at") or "", item.get("scan_id", "")),
            reverse=True,
        )

        # Opaque validated cursor: base64-encoded index string.
        if cursor:
            try:
                decoded = base64.b64decode(cursor).decode()
                if not decoded.startswith("cursor:"):
                    raise ValueError("invalid cursor format")
                cursor_index = int(decoded[7:])
            except Exception as e:
                raise ValueError("invalid cursor") from e
            if cursor_index < 0 or cursor_index > len(scans):
                raise ValueError("invalid cursor")
        else:
            cursor_index = 0

        page = scans[cursor_index:cursor_index + limit]
        next_cursor = (
            _encode_cursor(cursor_index + limit)
            if cursor_index + limit < len(scans)
            else None
        )
        return page, next_cursor


    async def replace_findings(self, scan_id: str, findings: list[dict[str, Any]]) -> None:
        """Replace the in-memory finding list with the quality-gated aggregation."""
        async with self.lock:
            if scan_id not in self.scan_responses:
                return
            cleaned: list[dict[str, Any]] = []
            for finding in findings:
                try:
                    cleaned.append(Finding.validate_dict(finding))
                except ValueError as e:
                    logger.warning(f"[scan:{scan_id}] Skipping malformed finding: {e}")
            self.scan_responses[scan_id]["findings"] = cleaned
            if scan_id in self.active_scans:
                self.active_scans[scan_id].findings_count = len(cleaned)

    async def set_coverage(
        self,
        scan_id: str,
        coverage: dict[str, Any] | None,
        quality_summary: dict[str, Any] | None = None,
    ) -> None:
        async with self.lock:
            if scan_id not in self.scan_responses:
                return
            self.scan_responses[scan_id]["coverage"] = coverage
            if quality_summary is not None:
                self.scan_responses[scan_id]["quality_summary"] = quality_summary

    async def add_finding(self, scan_id: str, finding: dict[str, Any]) -> None:
        async with self.lock:
            if scan_id not in self.scan_responses:
                return
            try:
                finding = Finding.validate_dict(finding)
            except ValueError as e:
                logger.warning(
                    f"[scan:{scan_id}] Skipping malformed finding: {e}"
                )
                return
            self.scan_responses[scan_id]["findings"].append(finding)
            self.active_scans[scan_id].findings_count = len(
                self.scan_responses[scan_id]["findings"]
            )

    async def replace_endpoints(self, scan_id: str, endpoints: list[dict[str, Any]]) -> None:
        async with self.lock:
            if scan_id in self.scan_responses:
                self.scan_responses[scan_id]["endpoints"] = list(endpoints)

    async def add_endpoints(self, scan_id: str, endpoints: list[dict[str, Any]]) -> None:
        async with self.lock:
            if scan_id not in self.scan_responses:
                return
            # Merge and deduplicate endpoints
            existing = { (e['method'], e['url']) for e in self.scan_responses[scan_id]["endpoints"] }
            for e in endpoints:
                if (e['method'], e['url']) not in existing:
                    self.scan_responses[scan_id]["endpoints"].append(e)

    async def update_tool_health(
        self,
        scan_id: str,
        tool_name: str,
        status: str,
        attempts: int = 1,
        findings_count: int = 0,
        duration_ms: int | None = None,
        error: str | None = None,
    ) -> None:
        async with self.lock:
            if scan_id not in self.scan_responses:
                return
            health = self.scan_responses[scan_id].setdefault("tool_health", {})
            current = {
                "status": status,
                "attempts": attempts,
                "findings_count": findings_count,
                "duration_ms": duration_ms,
                "error": error,
            }
            previous = health.get(tool_name)
            if isinstance(previous, dict):
                history = list(previous.get("history") or [])
                history.append({k: v for k, v in previous.items() if k != "history"})
                current["history"] = history[-20:]
            health[tool_name] = current

    async def set_schema(self, scan_id: str, schema: dict[str, Any] | None) -> None:
        """Set schema for a scan under lock (fixes A-2)."""
        async with self.lock:
            if scan_id in self.scan_responses:
                self.scan_responses[scan_id]["schema"] = schema

    async def set_ai_analysis(self, scan_id: str, analysis: dict[str, Any] | None) -> None:
        """Persist the latest AI/online review snapshot for live API reads."""
        async with self.lock:
            if scan_id in self.scan_responses:
                self.scan_responses[scan_id]["ai_analysis"] = analysis

    async def is_stopped(self, scan_id: str) -> bool:
        """Check if scan has been stopped."""
        async with self.lock:
            scan = self.active_scans.get(scan_id)
            return scan is not None and scan.status == "stopped"

    async def get_results(self, scan_id: str) -> dict[str, Any] | None:
        # Rehydrate if needed so we can read persisted provenance.
        if scan_id not in self.active_scans:
            await self._rehydrate(scan_id)

        async with self.lock:
            if scan_id in self.active_scans:
                return {
                    "status": self.active_scans[scan_id].model_dump(),
                    "findings": _decorate_findings_for_api(
                        list(self.scan_responses[scan_id]["findings"]),
                        self.scan_responses[scan_id].get("ai_analysis"),
                    ),
                    "endpoints": list(self.scan_responses[scan_id]["endpoints"]),
                    "schema": self.scan_responses[scan_id]["schema"],
                    "tool_health": dict(self.scan_responses[scan_id].get("tool_health", {})),
                    "ai_analysis": self.scan_responses[scan_id].get("ai_analysis"),
                    "coverage": self.scan_responses[scan_id].get("coverage"),
                    "quality_summary": self.scan_responses[scan_id].get("quality_summary"),
                }
        return None

    async def cleanup_old_scans(self) -> int:
        """Remove completed/failed scans beyond MAX_COMPLETED_SCANS (fixes M-7)."""
        async with self.lock:
            finished = [
                (sid, scan) for sid, scan in self.active_scans.items()
                if scan.status in ("completed", "failed", "stopped")
            ]
            finished.sort(key=lambda x: x[1].finished_at or "")
            to_remove = finished[:-MAX_COMPLETED_SCANS] if len(finished) > MAX_COMPLETED_SCANS else []
            removed_ids = []
            for sid, _ in to_remove:
                del self.active_scans[sid]
                self.scan_responses.pop(sid, None)
                removed_ids.append(sid)
            # Clean evidence module's scan dir cache for removed scans
            if removed_ids:
                try:
                    from lib.evidence import _scan_dirs
                    for sid in removed_ids:
                        _scan_dirs.pop(sid, None)
                except ImportError:
                    pass
            return len(to_remove)

    @classmethod
    def _reset(cls):
        """Reset singleton state for testing (keeps same instance)."""
        if cls._instance is not None:
            cls._instance.active_scans.clear()
            cls._instance.scan_responses.clear()
            cls._instance._lock = None

scan_state = ScanState()


def _encode_cursor(index: int) -> str:
    return base64.b64encode(f"cursor:{index}".encode()).decode()
