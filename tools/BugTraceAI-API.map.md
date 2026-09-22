# BugTraceAI-API Map

Map of **BugTraceAI-API**: the external API surface (MCP + REST), the internal pipeline phases it triggers, and the modules touched by each phase.

Code version: `VERSION` (`v0.x`, read from `VERSION`). Server: `main.py`.

---

## 1. Puntos de entrada

| Surface | Transport | Default port | File |
|---|---|---|---|
| MCP (4 tools) | stdio, o Streamable HTTP/SSE | `8004` (MCP), `8005` (REST) | `mcp_server.py`, `main.py` |
| REST (6 rutas) | HTTP (FastAPI + uvicorn) | `8005` | `api_server.py` |

- `main.py --http` starts MCP and REST in parallel (`_run_both`). Without `--http`, only MCP stdio is started.
- If the MCP/REST port is occupied, `_find_free_port` selects the next free port (excluding the port already claimed by the other server).

---

## 2. API externa — REST (FastAPI)

App: `app = FastAPI(title="BugTraceAI API Testing REST Interface", version=VERSION)` (`api_server.py:18`)

| Method | Route | Handler | Description | Errors |
|---|---|---|---|---|
| `POST` | `/api/scan` | `start_scan` | Starts an asynchronous scan. Body: `ScanRequest`. Returns `{scan_id, status: "started", message}` | `400` when target does not start with `http(s)://` |
| `GET` | `/api/scan/{scan_id}` | `get_scan_status` | Scan status (`ScanStatus.model_dump()`) | `404` if missing |
| `GET` | `/api/scan/{scan_id}/results` | `get_scan_results` | Findings + endpoints + tool_health + ai_analysis | `404` if missing |
| `GET` | `/api/scan/{scan_id}/openapi` | `get_scan_openapi` | OpenAPI 3.0 generated during discovery (importable by Bruno/Postman/Insomnia) | `404` if discovery has not produced it yet |
| `DELETE` | `/api/scan/{scan_id}` | `stop_scan` | Stops an active scan | `404` if missing; message if already finished |
| `GET` | `/health` | `health_check` | Healthcheck `{status, service, version}` | — |

### Modelos Pydantic

**`ScanRequest`** (`api_server.py:20`)
| Campo | Tipo | Default |
|---|---|---|
| `target` | `str` | (requerido) |
| `depth` | `str` | `"standard"` |
| `auth` | `Optional[Dict[str, Any]]` | `None` |
| `schema_url` | `Optional[str]` | `None` |

---

## 3. API externa — MCP tools

Tools are registered with `@mcp_server.mcp_server.tool()` in `main.py`. Errors are returned as `{"error": ...}` rather than raised.

| Tool | Signature | Description |
|---|---|---|
| `api_scan` | `api_scan(target, depth="standard", auth=None, schema_url=None)` | Starts an asynchronous scan. Returns `{scan_id, status, message}` |
| `get_scan_status` | `get_scan_status(scan_id)` | Returns scan status |
| `get_results` | `get_results(scan_id)` | Returns complete results (findings, endpoints, tool_health, ai_analysis) |
| `stop_scan` | `stop_scan(scan_id)` | Stops an active scan |

Note: MCP `api_scan` and `stop_scan` share the REST `/api/scan` (POST/DELETE) logic. The flow is identical: validate target → `scan_state.create_scan` → `asyncio.create_task(orchestrator.run_scan(...))` → register in `orchestrator.active_tasks`.

---

## 4. In-memory state (singleton)

`lib/scan_state.py` — `scan_state = ScanState()` (singleton with `__new__` and a lazy `asyncio.Lock`).

**`ScanStatus`** (`scan_state.py:23`)

| Campo | Tipo | Default |
|---|---|---|
| `scan_id` | `str` | — |
| `target` | `str` | — |
| `status` | `str` | `"pending"` → `running` → `completed` / `failed` / `stopped` |
| `current_phase` | `str` | `"discovery"` |
| `progress` | `float` | `0.0` |
| `started_at` | `str` | (ISO) |
| `finished_at` | `Optional[str]` | `None` |
| `findings_count` | `int` | `0` |
| `error` / `warning` | `Optional[str]` | `None` |

**`scan_responses[scan_id]`** = `{endpoints, findings, schema, tool_health, ai_analysis, artifacts_path}` — estado en memoria que alimenta `get_results`.

Limits: `MAX_CONCURRENT_SCANS = 3` (semaphore in `orchestrator.py`), `MAX_SCAN_DURATION = 3600`s (global timeout), `MAX_COMPLETED_SCANS = 100` (cleanup after each scan).

---

## 5. Internal pipeline (`orchestrator.run_scan`)

`run_scan(scan_id, target, depth, auth, schema_url)` → `_run_pipeline`, with file-backed hand-off between phases. Each phase writes artifacts and the next phase reads them. Progress moves through `0.1` → `0.3` → `0.4` → `0.6` → `0.9` → `0.95` → `1.0`.

### Phase 1 — Discovery (`orchestrator.py`)
Paralelo (3 pasadas) + baseline:

| Sub-step | Tool/function | Artifact |
|---|---|---|
| Baseline detection (SPA catch-all, `--ignore-length`) | `detect_baseline` (`tools/discovery.py`) | — |
| Kiterunner scan (wordlists `.kite`) | `run_kiterunner_scan` | `10_discovery/kiterunner_scan_endpoints.json` |
| Kiterunner brute (wordlists de texto) | `run_kiterunner_brute` | `10_discovery/kiterunner_brute_endpoints.json` |
| API crawl (HAL+JSON, link-follow) | `run_api_crawl` | `10_discovery/crawl_endpoints.json` |
| Deduplication `(method, url)` | — | `10_discovery/all_endpoints.json` |
| Enriched synthetic OpenAPI | `endpoints_to_openapi` + `enrich_openapi_from_responses` (`lib/evidence.py`) | `10_discovery/generated_openapi.json` |
| Resumen | — | `10_discovery/phase_summary.json` |

### Phase 2 — Schema Probe (`orchestrator.py`)
| Schema source | Priority | Condition |
|---|---|---|
| User-provided `schema_url` | 1 | `fetch_schema_from_url` (`lib/schema_probe.py`), coverage calculated with `_calculate_coverage` |
| `probe_schema` (descubrimiento local) | 2 | `lib/schema_probe.py` |
| Phase 1 generated OpenAPI | 3 (fallback) | `generated_openapi.paths` is non-empty |

Writes `20_schema_probe/schema_decision.json` + `schema_info.json` (same content) and persists the schema in memory (`scan_state.set_schema`).

### Phase 3 — Attacks (`orchestrator.py`)
Bifurcation follows `schema_decision` (coverage ≥ 0.7 plus endpoints → schema attack; otherwise add a blind attack):

| Tool | Tool/function | Findings in |
|---|---|---|
| Schemathesis (fuzzing schema) | `run_schema_attack` (`tools/schema_attack.py`) | `30_schema_attack/findings_{tool}.json` |
| Offat / VulnAPI (ataques con schema) | `run_schema_attack` | `30_schema_attack/findings_{tool}.json` |
| Arjun (param brute) / X8 (header brute) | `run_blind_attack` (`tools/blind_attack.py`) | `31_blind_attack/findings_{tool}.json` |
| Auth probe | `run_auth_probe` (`tools/auth_probe.py`) | `32_auth_probe/findings_auth_probe.json` |

It also writes `30_schema_attack/attack_tool_health.json` (per-tool summary).

### Phase 4 — Aggregation (`orchestrator.py`)
Reads all previous-phase artifacts and writes:

- `40_aggregation/unified_findings.json` (reporte completo)
- `40_aggregation/findings_only.json`
- `40_aggregation/findings_{tool}.json` (per tool)
- `40_aggregation/tool_health.json`
- `40_aggregation/endpoints_summary.json`
- `40_aggregation/scan_metadata.json`
- `40_aggregation/dropped_findings.json` (only when findings were filtered)

**Quality filter**: drops findings without `evidence` and arjun/x8 `low` findings with `confidence < 0.6`.

Top-level scan files (`save_report`): `findings.json`, `endpoints.json`, `report.json`, `scan_metadata.json`.

### Phase 5 — AI analysis and quality review (optional)

Runs when `APEX_ENABLED=true` and the selected provider is available. The phase is
provider-neutral (local Ollama, OpenRouter, Z.ai, or Anthropic) and uses the configured
minimum severity. The development configuration defaults to `info`, so informational and
low-severity findings are not silently omitted.

For every eligible finding the AI:

1. generates a root-cause explanation and a reproducible PoC;
2. performs a safe replay of only same-origin `GET`, `HEAD`, or `OPTIONS` requests (never
   shell execution, request bodies, credentials, or state-changing methods);
3. runs a second critical review that can downgrade the claim or require revision.

The phase also submits bounded scan context (findings, endpoint sample, schema summary) to
a whole-scan reviewer. It reports correlations, duplicate groups, evidence gaps, and
prioritized **candidate** checks. Candidate checks are advisory and are never promoted to
confirmed vulnerabilities without scanner evidence.

Artifacts:

- `50_apex_analysis/pocs.json` — PoC, safe replay telemetry, and critical review per finding
- `50_apex_analysis/scan_review.json` — whole-scan coverage review and candidate checks
- `50_apex_analysis/report.md` — human-readable AI report containing both review layers
- `reports/{domain}/apex_report.md` — top-level copy of the report
- `scan_responses[scan_id]["ai_analysis"]` — API representation for `get_results`

The AI phase is evidence-aware, but it does not independently prove newly discovered
vulnerabilities and does not execute exploit payloads. A successful safe replay only means
that a response was observed again.

---

## 6. Scan directory layout

```
reports/{domain}_{YYYYMMDD_HHMMSS}/
├── 10_discovery/          # endpoints, generated_openapi, phase_summary
├── 20_schema_probe/       # schema_decision, schema_info
├── 30_schema_attack/      # findings_{tool}, attack_tool_health
├── 31_blind_attack/       # findings_{tool}
├── 32_auth_probe/         # findings_auth_probe
├── 40_aggregation/        # unified_findings, findings_only, tool_health, ...
├── 50_apex_analysis/      # pocs.json, scan_review.json, report.md (if enabled)
├── findings.json          # top-level copy
├── endpoints.json         # top-level copy
├── report.json            # top-level copy
├── scan_metadata.json     # top-level copy
└── apex_report.md         # top-level (if enabled)
```

Paths are implemented in `lib/evidence.py` (`create_scan_dir`, `_phase_dir`, `save_artifact`, `load_artifact`, `list_artifacts`, `save_report`, `get_scan_dir`).

---

## 7. Scan lifecycle (complete sequence)

1. **`POST /api/scan`** (or MCP `api_scan`) validates `target`, creates the scan, and registers an asynchronous task.
2. `run_scan` acquires the semaphore (`MAX_CONCURRENT_SCANS=3`) and applies the 60-minute global timeout.
3. `_run_pipeline` creates the evidence directory, marks the scan `running`, and executes Phases 1–5 with stop checks between phases.
4. On completion the scan is `completed`, progress is `1.0`, orchestrator health is `ok`, and old scans are cleaned up.
5. Failures become `failed` with an error; global timeout uses `global_timeout_3600s`; cancellation becomes `stopped`.

---

## 8. Module dependency matrix

| Module | Depends on | Exports |
|---|---|---|
| `main.py` | `mcp_server`, `api_server`, `lib.scan_state`, `orchestrator` | MCP tools |
| `api_server.py` | `lib.scan_state`, `lib.evidence` (`load_artifact`), `orchestrator` | FastAPI app |
| `mcp_server.py` | `mcp.server.fastmcp` | `mcp_server`, `run_mcp_server`, `_create_mcp_app` |
| `orchestrator.py` | `lib.scan_state`, `lib.schema_probe`, `tools.discovery`, `tools.schema_attack`, `tools.blind_attack`, `tools.auth_probe`, `lib.evidence`, `lib.apex_client` | `Orchestrator`, `orchestrator` |
| `lib/scan_state.py` | pydantic | `ScanState`, `scan_state`, `ScanStatus`, `Finding` |
| `lib/evidence.py` | pathlib | `create_scan_dir`, `save_artifact`, `load_artifact`, `list_artifacts`, `save_report`, `endpoints_to_openapi`, `enrich_openapi_from_responses`, `_phase_dir`, `get_scan_dir`, `_scan_dirs` |
| `lib/schema_probe.py` | — | `probe_schema`, `fetch_schema_from_url`, `_calculate_coverage` |
| `lib/apex_client.py` | httpx, provider, safe validator | `analyze_findings`, `review_generated_poc`, `analyze_scan_overview`, `render_markdown_report` |
| `lib/poc_validation.py` | httpx | `replay_safe_poc` (same-origin, non-mutating replay only) |
| `tools/discovery.py` | — | `run_kiterunner_scan`, `run_kiterunner_brute`, `run_api_crawl`, `detect_baseline` |
| `tools/schema_attack.py` | — | `run_schema_attack` |
| `tools/blind_attack.py` | — | `run_blind_attack` |
| `tools/auth_probe.py` | — | `run_auth_probe` |

---

## 9. Notes

- **`GET /api/scan/{id}/openapi`** works for current and historical scans: it reads `10_discovery/generated_openapi.json` from disk (`load_artifact`), not memory.
- **`get_results`** depends on in-memory state; after `cleanup_old_scans` removes a scan (>100 completed scans), it can return `404` even though disk artifacts remain.
- **Environment configuration** includes `KR_BIN`, `X8_BIN`, `WORDLISTS_DIR`, `TEXT_WORDLISTS_DIR`, `PARAMS_DIR`, `SCANS_DIR`, `REPORTS_DIR`, `API_PORT`, `APEX_ENABLED`, `APEX_PROVIDER`, and `APEX_MIN_SEVERITY`.
