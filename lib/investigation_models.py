"""Pydantic models for the autonomous API investigation loop.

Hypothesis lifecycle states:
    proposed → testing → supported | refuted | inconclusive | blocked_auth | error

The old "pending | confirmed | suspicious | insufficient" states were
ambiguous: they mixed intent ("I think this might be a BOLA") with outcome
("the evidence shows it IS a BOLA"). The new states separate the
investigation *stage* from the *conclusion*.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import UTC, datetime
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

logger = logging.getLogger("bugtrace-api.lib.investigation_models")

# ── Hypothesis lifecycle ────────────────────────────────────────────────────
HYP_STATUS_PROPOSED = "proposed"
HYP_STATUS_TESTING = "testing"
HYP_STATUS_SUPPORTED = "supported"
HYP_STATUS_REFUTED = "refuted"
HYP_STATUS_INCONCLUSIVE = "inconclusive"
HYP_STATUS_BLOCKED_AUTH = "blocked_auth"
HYP_STATUS_ERROR = "error"
HYP_STATUS_NOT_APPLICABLE = "not_applicable"

ALL_HYP_STATUSES = frozenset({
    HYP_STATUS_PROPOSED, HYP_STATUS_TESTING, HYP_STATUS_SUPPORTED,
    HYP_STATUS_REFUTED, HYP_STATUS_INCONCLUSIVE, HYP_STATUS_BLOCKED_AUTH,
    HYP_STATUS_ERROR, HYP_STATUS_NOT_APPLICABLE,
})

CONCLUSIVE_STATUSES = {HYP_STATUS_SUPPORTED, HYP_STATUS_REFUTED, HYP_STATUS_NOT_APPLICABLE}

VALID_TOOLS = frozenset({
    "schema_lookup", "http_request", "http_compare", "auth_differential",
    "path_variant", "response_classify", "safe_replay", "graphql_probe",
    "coverage_probe", "auth_probe", "authz_probe", "schemathesis",
    "offat", "vulnapi", "blinds", "arjun", "x8", "manual_replay",
})

# ── Coercion helpers ────────────────────────────────────────────────────────
def _coerce_str(v: Any) -> str:
    return str(v) if v is not None else ""


SafeStr = Annotated[str, BeforeValidator(_coerce_str)]


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: SafeStr = Field(min_length=1)
    title: SafeStr = Field(default="", min_length=1)
    category: SafeStr = "security"
    target_endpoint: SafeStr = ""
    rationale: SafeStr = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    # New lifecycle states
    status: str = HYP_STATUS_PROPOSED
    # Track how many tests were run and their outcomes
    tests_run: int = 0
    last_test_at: str = ""
    conclusion: str | None = None

    @classmethod
    def from_dict(cls, d: dict[str, Any] | Any) -> "Hypothesis":
        if isinstance(d, cls):
            return d
        status = str(d.get("status", HYP_STATUS_PROPOSED)).strip()
        if status not in ALL_HYP_STATUSES:
            logger.warning(f"Hypothesis {d.get('id')} has unknown status '{status}'; defaulting to proposed")
            status = HYP_STATUS_PROPOSED
        result = cls(
            id=str(d.get("id", f"h-{len(d)}")),
            title=str(d.get("title", "Untitled hypothesis")),
            category=str(d.get("category", "security")),
            target_endpoint=str(d.get("target_endpoint", "")),
            rationale=str(d.get("rationale", "")),
            confidence=float(d.get("confidence", 0.5)),
            status=status,
            tests_run=int(d.get("tests_run", 0)),
            last_test_at=str(d.get("last_test_at", "")),
            conclusion=str(d.get("conclusion")) if d.get("conclusion") else None,
        )
        if d.get("source_finding_id"):
            result.source_finding_id = d["source_finding_id"]
        return result

    def fingerprint(self) -> str:
        """Short hash identifying this hypothesis for comparison."""
        blob = json.dumps({
            "id": self.id, "title": self.title, "category": self.category,
            "endpoint": self.target_endpoint, "status": self.status,
        }, sort_keys=True)
        return hashlib.sha256(blob.encode()).hexdigest()[:12]

    def is_resolved(self) -> bool:
        return self.status in CONCLUSIVE_STATUSES

    def update_status(self, new_status: str) -> None:
        """Transition to a new status, with guardrails."""
        if new_status not in ALL_HYP_STATUSES:
            logger.warning(f"Ignoring invalid status transition to '{new_status}'")
            return
        # Never downgrade a confirmed hypothesis without explicit override
        if self.status == HYP_STATUS_SUPPORTED and new_status not in {
            HYP_STATUS_SUPPORTED, HYP_STATUS_INCONCLUSIVE, HYP_STATUS_ERROR
        }:
            logger.warning(
                f"Hypothesis {self.id}: downgrading from supported to {new_status} — "
                "only inconclusive or error allowed"
            )
            return
        self.status = new_status


class ValidationStep(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: SafeStr = Field(min_length=1)
    hypothesis_id: SafeStr
    tool: SafeStr = "manual_replay"  # e.g., "schemathesis", "auth_probe", "manual_replay"
    method: SafeStr = "GET"
    url: SafeStr = ""
    params: dict[str, Any] = Field(default_factory=dict)
    body: dict[str, Any] | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    expected_indicator: SafeStr = ""
    reason: SafeStr = ""
    success_criteria: list[str] = Field(default_factory=list)
    stop_if: list[str] = Field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict[str, Any] | Any) -> "ValidationStep":
        if isinstance(d, cls):
            return d
        params = d.get("params")
        if not isinstance(params, dict):
            params = {}
        body = d.get("body")
        if not isinstance(body, dict):
            body = None
        headers = d.get("headers")
        if not isinstance(headers, dict):
            headers = {}
        success_criteria = d.get("success_criteria")
        if not isinstance(success_criteria, list):
            success_criteria = []
        stop_if = d.get("stop_if")
        if not isinstance(stop_if, list):
            stop_if = []
        return cls(
            id=str(d.get("id", f"step-{len(d)}")),
            hypothesis_id=str(d.get("hypothesis_id", "")),
            tool=str(d.get("tool", "coverage_probe")),
            method=str(d.get("method", "GET")).upper(),
            url=str(d.get("url", "")),
            params=params,
            body=body,
            headers=headers,
            expected_indicator=str(d.get("expected_indicator", "")),
            reason=str(d.get("reason", "")),
            success_criteria=[str(s) for s in success_criteria],
            stop_if=[str(s) for s in stop_if],
        )

    def validate(self) -> list[str]:
        """Return a list of validation errors. Empty list means valid."""
        errors: list[str] = []
        if str(self.tool).lower() not in VALID_TOOLS:
            errors.append(f"unknown_tool:{self.tool}")
        if str(self.method).upper() not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
            errors.append(f"invalid_method:{self.method}")
        if not str(self.url).startswith(("http://", "https://")):
            errors.append(f"url_must_be_absolute:{self.url}")
        if not str(self.expected_indicator).strip():
            errors.append("missing_expected_indicator")
        return errors


class ValidationPlan(BaseModel):
    model_config = ConfigDict(extra="allow")

    steps: list[ValidationStep] = Field(default_factory=list)
    rationale: SafeStr = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any] | Any) -> "ValidationPlan":
        if isinstance(d, cls):
            return d
        steps = d.get("steps", [])
        if not isinstance(steps, list):
            steps = []
        return cls(
            steps=[ValidationStep.from_dict(s) for s in steps],
            rationale=str(d.get("rationale", "")),
        )


class EvidenceComparison(BaseModel):
    model_config = ConfigDict(extra="allow")

    new_fingerprints: list[str] = Field(default_factory=list)
    repeat_fingerprints: list[str] = Field(default_factory=list)
    delta_count: int = 0
    similarity: float | None = Field(default=None, ge=0.0, le=1.0)

    @classmethod
    def from_dict(cls, d: dict[str, Any] | Any) -> "EvidenceComparison":
        if isinstance(d, cls):
            return d
        return cls(
            new_fingerprints=list(d.get("new_fingerprints", [])),
            repeat_fingerprints=list(d.get("repeat_fingerprints", [])),
            delta_count=int(d.get("delta_count", 0)),
            similarity=(
                float(d["similarity"])
                if d.get("similarity") is not None else None
            ),
        )


class IterationResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    iteration_number: int
    tool_calls: int
    findings: list[dict[str, Any]] = Field(default_factory=list)
    evidence_comparison: EvidenceComparison | None = None
    adjudication: str = ""

    @classmethod
    def from_dict(cls, d: dict[str, Any] | Any) -> "IterationResult":
        if isinstance(d, cls):
            return d
        comp = d.get("evidence_comparison")
        if isinstance(comp, dict):
            comp = EvidenceComparison.from_dict(comp)
        elif comp is None:
            comp = EvidenceComparison()
        return cls(
            iteration_number=int(d.get("iteration_number", 0)),
            tool_calls=int(d.get("tool_calls", 0)),
            findings=d.get("findings", []),
            evidence_comparison=comp,
            adjudication=str(d.get("adjudication", "")),
            adjudication_result=d.get("adjudication_result", {}),
            steps=d.get("steps", []),
            timestamp=d.get("timestamp"),
        )


class InvestigatorBudget(BaseModel):
    model_config = ConfigDict(extra="allow")

    max_iterations: int = Field(default=5, ge=1, le=20)
    max_tool_calls_per_iteration: int = Field(default=10, ge=1, le=50)
    max_total_tool_calls: int = Field(default=50, ge=10, le=200)
    max_duration_seconds: float | None = Field(default=600.0, ge=1.0, le=3600.0)


class InvestigatorState(BaseModel):
    model_config = ConfigDict(extra="allow")

    scan_id: SafeStr
    target: SafeStr = ""
    status: str = "pending"  # pending | running | completed | failed | stopped
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    plan: ValidationPlan | None = None
    iterations: list[IterationResult] = Field(default_factory=list)
    stop_reason: str | None = None
    error: str | None = None
    budget: InvestigatorBudget = Field(default_factory=InvestigatorBudget)
    total_tool_calls: int = 0
    started_at: str = ""
    finished_at: str | None = None

    def elapsed_seconds(self) -> float:
        """Return elapsed time in seconds, never negative."""
        end = self.finished_at or datetime.now(UTC).isoformat()
        try:
            end_ts = datetime.fromisoformat(end).timestamp()
            start_ts = datetime.fromisoformat(self.started_at).timestamp()
            return max(0.0, end_ts - start_ts)
        except Exception:
            return 0.0

    def is_blocked(self) -> bool:
        """Return True when the investigation has reached a terminal state."""
        return self.status in ("completed", "partial", "failed", "stopped")

    @classmethod
    def from_dict(cls, d: dict[str, Any] | Any) -> "InvestigatorState":
        if isinstance(d, cls):
            return d
        budget = d.get("budget")
        if not isinstance(budget, dict):
            budget = {}
        plan = d.get("plan")
        if isinstance(plan, dict):
            plan = ValidationPlan.from_dict(plan)
        elif plan is None:
            plan = None
        hypotheses = d.get("hypotheses", [])
        if not isinstance(hypotheses, list):
            hypotheses = []
        iterations = d.get("iterations", [])
        if not isinstance(iterations, list):
            iterations = []
        return cls(
            scan_id=str(d.get("scan_id", "")),
            target=str(d.get("target", "")),
            status=str(d.get("status", "pending")),
            hypotheses=[Hypothesis.from_dict(h) for h in hypotheses],
            plan=plan,
            iterations=[IterationResult.from_dict(i) for i in iterations],
            stop_reason=d.get("stop_reason"),
            error=d.get("error"),
            budget=InvestigatorBudget(**budget),
            total_tool_calls=int(d.get("total_tool_calls", 0)),
            started_at=str(d.get("started_at", "")),
            finished_at=d.get("finished_at"),
        )
