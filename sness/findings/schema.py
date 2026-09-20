"""The findings contract, plus the two gates every candidate must survive.

Shape follows Cloudflare's released `report-schema.json` (verdict/trace/evidence/severity/
confidence), with one addition that is non-negotiable here: `threat_model`. A hunter must
name the attacker and the boundary crossed *before* it is allowed to file anything. That
single requirement is what separates a vulnerability from a code smell.

Two gates, in order:
  1. candidate_gate()  -- structural. Did the agent actually say something falsifiable?
  2. mechanical_check() -- deterministic, written in plain code and NOT another model.
     Do the cited files and lines physically exist? Models hallucinate line numbers; a
     model asked to check another model's line numbers hallucinates agreement.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Severity = Literal["informational", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
TraceKind = Literal["entrypoint", "propagation", "sink"]


class TraceStep(BaseModel):
    kind: TraceKind
    file: str
    line: int = Field(ge=1)
    scope: str = ""
    description: str = ""


class Evidence(BaseModel):
    file: str
    line: int = Field(ge=1)
    description: str = ""


class ThreatModelBlock(BaseModel):
    """Who attacks, what boundary they cross, which assumption breaks."""

    attacker: str
    boundary: str
    broken_assumption: str
    affected_principal: str = ""


class SeverityBlock(BaseModel):
    likelihood: Severity = "low"
    impact: Severity = "low"
    overall_severity: Severity = "low"
    reason: str = ""


class PoC(BaseModel):
    """A PoC is a test that runs against the ORIGINAL, UNTOUCHED source.

    `command` is executed inside the sandbox with the target mounted read-only. If the
    target tree changes during the run, the finding is void -- the agent edited the code
    to make its own exploit land.
    """

    strategy: str = ""
    command: list[str] = Field(default_factory=list)
    test_file_name: str = ""
    test_source: str = ""
    expected_observation: str = ""


class HunterFinding(BaseModel):
    """What a hunter emits. One root cause, one record."""

    title: str
    description: str = ""
    root_cause: str = ""
    intended_behavior: str = ""
    threat_model: ThreatModelBlock
    trace: list[TraceStep] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    conditions: list[str] = Field(default_factory=list)
    poc: PoC | None = None
    severity: SeverityBlock = Field(default_factory=SeverityBlock)
    confidence: Confidence = "low"
    remediation: str = ""
    attack_class: str = ""
    area: str = ""

    @field_validator("title")
    @classmethod
    def _title_is_specific(cls, v: str) -> str:
        if len(v.strip()) < 12:
            raise ValueError("title too vague to deduplicate")
        return v.strip()

    def primary_location(self) -> tuple[str, str]:
        """The sink is the bug's home. Fall back to first trace step, then first evidence."""
        for step in self.trace:
            if step.kind == "sink":
                return step.file, step.scope or ""
        if self.trace:
            return self.trace[0].file, self.trace[0].scope or ""
        if self.evidence:
            return self.evidence[0].file, ""
        return "", ""


class MechanicalReport(BaseModel):
    ok: bool
    missing_files: list[str] = Field(default_factory=list)
    out_of_range_lines: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def reason(self) -> str:
        bits = []
        if self.missing_files:
            bits.append(f"cited files do not exist: {', '.join(self.missing_files[:5])}")
        if self.out_of_range_lines:
            bits.append(f"line numbers past end of file: {', '.join(self.out_of_range_lines[:5])}")
        bits.extend(self.notes)
        return "; ".join(bits) or "ok"


def candidate_gate(f: HunterFinding) -> tuple[bool, str]:
    """Structural gate. Cheap, runs before any model spends tokens validating."""
    tm = f.threat_model
    for field_name in ("attacker", "boundary", "broken_assumption"):
        if len((getattr(tm, field_name) or "").strip()) < 8:
            return False, f"threat model incomplete: {field_name} is missing or a stub"
    if not f.trace:
        return False, "no trace: a finding must point at code, not describe a concern"
    if not f.evidence:
        return False, "no evidence"
    if not any(s.kind == "sink" for s in f.trace):
        return False, "trace has no sink: nothing shows where the boundary is actually crossed"
    return True, "ok"


def mechanical_check(f: HunterFinding, repo_path: Path) -> MechanicalReport:
    """Deterministic verification. Plain code on purpose -- see module docstring."""
    missing: list[str] = []
    bad_lines: list[str] = []
    notes: list[str] = []
    line_cache: dict[str, int] = {}

    def count_lines(rel: str) -> int | None:
        if rel in line_cache:
            return line_cache[rel]
        p = (repo_path / rel).resolve()
        try:
            # Containment check: a trace may not cite files outside the repo under review.
            p.relative_to(repo_path.resolve())
        except ValueError:
            notes.append(f"path escapes repo: {rel}")
            return None
        if not p.is_file():
            return None
        try:
            n = sum(1 for _ in p.open("rb"))
        except OSError:
            return None
        line_cache[rel] = n
        return n

    for label, items in (("trace", f.trace), ("evidence", f.evidence)):
        for item in items:
            rel = item.file.lstrip("/")
            n = count_lines(rel)
            if n is None:
                if rel not in missing:
                    missing.append(rel)
                continue
            if item.line > n:
                bad_lines.append(f"{rel}:{item.line} (file has {n} lines, cited in {label})")

    return MechanicalReport(
        ok=not missing and not bad_lines,
        missing_files=missing,
        out_of_range_lines=bad_lines,
        notes=notes,
    )
