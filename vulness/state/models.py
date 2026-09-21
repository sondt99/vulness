"""Typed mirrors of the SQLite tables. Rows in, models out."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

TaskKind = Literal[
    "recon", "hunt", "validate", "gapfill", "feedback", "trace", "judge", "fix", "dedup"
]
TaskStatus = Literal["queued", "leased", "done", "failed", "shallow", "abandoned"]
TaskOrigin = Literal[
    "seed", "gapfill", "sibling_fork", "feedback", "trace", "requeue_shallow", "requeue_error"
]
ExitReason = Literal["ok", "api_error_text", "timeout", "empty", "schema_invalid", "crash", "budget"]
Verdict = Literal["candidate", "confirmed", "rejected", "needs_validation", "duplicate"]
CellStatus = Literal["planned", "assigned", "covered", "thin", "deferred", "out_of_scope"]


def now() -> str:
    return datetime.now(UTC).isoformat()


def _loads(v: Any, default: Any) -> Any:
    if v is None or v == "":
        return default
    if isinstance(v, (dict, list)):
        return v
    try:
        return json.loads(v)
    except (json.JSONDecodeError, TypeError):
        return default


class Run(BaseModel):
    run_id: str
    started_at: str = Field(default_factory=now)
    ended_at: str | None = None
    status: str = "planned"
    incomplete_reason: str | None = None
    profile: str = "standard"
    budget_tasks: int | None = None
    model_hunt: str
    model_verify: str
    config_json: dict = Field(default_factory=dict)


class Repo(BaseModel):
    repo_id: str
    name: str
    path: str
    git_remote: str | None = None
    head_sha: str | None = None
    dirty: bool = False
    lang_mix_json: dict = Field(default_factory=dict)
    enabled: bool = True
    budget_tasks: int | None = None


class Task(BaseModel):
    task_id: str
    run_id: str
    repo_id: str
    stage: str
    kind: TaskKind
    cell_id: str | None = None
    parent_task_id: str | None = None
    origin: TaskOrigin = "seed"
    finding_id: str | None = None
    priority: int = 100
    prompt: str
    seed_json: dict = Field(default_factory=dict)
    status: TaskStatus = "queued"
    attempt: int = 0
    lease_until: str | None = None
    worker: str | None = None
    started_at: str | None = None
    ended_at: str | None = None
    duration_s: float | None = None
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    exit_reason: ExitReason | None = None
    result_json: dict = Field(default_factory=dict)

    @classmethod
    def from_row(cls, row: Any) -> Task:
        d = dict(row)
        d["seed_json"] = _loads(d.get("seed_json"), {})
        d["result_json"] = _loads(d.get("result_json"), {})
        return cls(**d)


class Cell(BaseModel):
    """One (area x attack-class) coverage unit. The grid Gapfill walks."""

    run_id: str
    repo_id: str
    cell_id: str
    area: str
    attack_class: str
    paths_json: list[str] = Field(default_factory=list)
    rationale: str | None = None
    priority: int = 100
    status: CellStatus = "planned"
    hunter_tasks: int = 0
    findings_count: int = 0
    last_touched: str | None = None

    @classmethod
    def from_row(cls, row: Any) -> Cell:
        d = dict(row)
        d["paths_json"] = _loads(d.get("paths_json"), [])
        return cls(**d)


class ThreatModel(BaseModel):
    """Required before a hunter may file. No attacker, no boundary -> no finding."""

    attacker: str
    boundary: str
    broken_assumption: str
    affected_principal: str | None = None

    def is_complete(self) -> bool:
        return all(
            len((getattr(self, f) or "").strip()) >= 8
            for f in ("attacker", "boundary", "broken_assumption")
        )


class Finding(BaseModel):
    finding_id: str
    run_id: str
    repo_id: str
    task_id: str
    fingerprint: str
    title: str
    area: str | None = None
    attack_class: str | None = None
    cell_id: str | None = None
    threat_model_json: dict = Field(default_factory=dict)
    trace_json: list = Field(default_factory=list)
    evidence_json: dict = Field(default_factory=dict)
    poc_json: dict = Field(default_factory=dict)
    severity_json: dict = Field(default_factory=dict)
    remediation_json: dict = Field(default_factory=dict)
    verdict: Verdict = "candidate"
    duplicate_of: str | None = None
    created_at: str = Field(default_factory=now)
    updated_at: str | None = None

    @classmethod
    def from_row(cls, row: Any) -> Finding:
        d = dict(row)
        for k, default in (
            ("threat_model_json", {}),
            ("trace_json", []),
            ("evidence_json", {}),
            ("poc_json", {}),
            ("severity_json", {}),
            ("remediation_json", {}),
        ):
            d[k] = _loads(d.get(k), default)
        return cls(**d)

    def threat_model(self) -> ThreatModel | None:
        try:
            return ThreatModel(**self.threat_model_json)
        except Exception:
            return None

    def severity(self) -> str:
        return str(self.severity_json.get("overall_severity", "unrated"))


class Validation(BaseModel):
    validation_id: str
    finding_id: str
    task_id: str | None = None
    validator: Literal["mechanical", "adversarial", "sandbox", "judge", "dedup"]
    model: str
    verdict: Literal["upheld", "disproved", "needs_validation", "error"]
    reason: str
    detail_json: dict = Field(default_factory=dict)
    created_at: str = Field(default_factory=now)


class Wish(BaseModel):
    wish_id: str
    run_id: str
    repo_id: str
    task_id: str | None = None
    kind: str
    resource: str
    context_json: dict = Field(default_factory=dict)
    status: str = "open"
    created_at: str = Field(default_factory=now)
    resolved_at: str | None = None
    requeued_task_id: str | None = None
