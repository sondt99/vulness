"""Adversarial validation, on the other model.

Two independent mechanisms keep this honest:

1. **This module never files a finding.** There is no call to `db.file_finding` here and
   there must never be one. A validator that can file becomes a second hunter, and a
   hunter that can validate approves its own work.
2. **It runs on a different model.** The hunt is Claude; validation is GLM. Forcing model B
   to judge model A's output means the finding is evaluated by a different set of weights
   and training data, not by the same biases that produced it.
"""

from __future__ import annotations

import json
import time

from sness.agents.context_budget import ContextBudget, Section
from sness.agents.roles.context import RoleContext, TaskOutcome
from sness.prompts import preamble, render
from sness.state.db import new_id
from sness.state.models import Task, Validation

_VERDICT_MAP = {
    "upheld": "confirmed",
    "disproved": "rejected",
    "needs_validation": "needs_validation",
}


def _finding_block(ctx: RoleContext, finding_id: str) -> str:
    f = ctx.db.get_finding(finding_id)
    if f is None:
        return "(finding missing)"
    return json.dumps(
        {
            "title": f.title,
            "attack_class": f.attack_class,
            "area": f.area,
            "threat_model": f.threat_model_json,
            "trace": f.trace_json,
            "evidence": f.evidence_json,
            "severity": f.severity_json,
            "remediation": f.remediation_json,
            "proposed_poc": f.poc_json,
        },
        indent=2,
    )[:14000]


def _mechanical_block(ctx: RoleContext, finding_id: str) -> str:
    """Everything already established before a model was asked to judge.

    The sandbox line matters most: a PoC that executed against read-only source is the
    hardest evidence the harness produces, and withholding it would have the validator
    re-argue from source what was already demonstrated.
    """
    lines: list[str] = []
    for v in ctx.db.validations_for(finding_id):
        if v.validator == "mechanical":
            lines.append(f"- Deterministic file/line check: **{v.verdict}** - {v.reason}")
        elif v.validator == "sandbox":
            detail = v.detail_json or {}
            lines.append(
                f"- Sandboxed PoC: **{detail.get('verdict', v.verdict)}** - {v.reason}"
                + (f"\n  - stdout: `{str(detail.get('stdout', ''))[-400:]}`" if detail.get("stdout") else "")
            )
    return "\n".join(lines) or "- Deterministic file/line check: not run."


async def run_validate(ctx: RoleContext, task: Task) -> TaskOutcome:
    if not task.finding_id:
        return TaskOutcome(status="failed", exit_reason="schema_invalid")

    repo = ctx.repo_path(task.repo_id)
    started = time.monotonic()

    # A finding with a long trace plus sandbox output can be large; budget it rather than
    # trusting the earlier hard character cap to be the right number on every model.
    budget = ContextBudget(
        ctx.settings.verify.model, occupancy=ctx.settings.budget.context_occupancy
    )
    instruction = render(
        "validator",
        repo_name=task.repo_id,
        repo_path=str(repo),
        finding_block="{FINDING}",
        mechanical_block=_mechanical_block(ctx, task.finding_id),
    )
    head, _, tail = instruction.partition("{FINDING}")
    prompt, fit = budget.fit(
        [
            Section("head", head, priority=0),
            Section("finding", _finding_block(ctx, task.finding_id), priority=1, floor_chars=2000),
            Section("tail", tail, priority=0),
        ],
        separator="",
    )
    if fit.trimmed or fit.dropped:
        ctx.db.event(
            "context.trimmed",
            run_id=task.run_id,
            task_id=task.task_id,
            finding_id=task.finding_id,
            detail=fit.summary(),
        )

    result = await ctx.verify_agent.run(
        prompt,
        system=preamble(),
        cwd=repo,
        timeout_s=ctx.settings.verify.timeout_s,
        schema={"verdict": "upheld|disproved|needs_validation", "reason": "str"},
    )
    duration = time.monotonic() - started

    if not result.ok:
        # A validator that failed to run has NOT cleared anything. The finding stays a
        # candidate and the task is retried -- never silently promoted.
        ctx.db.event(
            "validate.failed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="error",
            finding_id=task.finding_id,
            classification=result.classification,
            error=result.error,
        )
        return TaskOutcome(
            status="failed",
            exit_reason=result.classification,
            duration_s=duration,
            tokens_in=result.tokens_in,
            tokens_out=result.tokens_out,
            cost_usd=result.cost_usd,
        )

    payload = result.extract_json() or {}
    raw_verdict = str(payload.get("verdict", "")).strip().lower()
    reason = str(payload.get("reason", "")).strip() or "(no reason given)"

    if raw_verdict not in _VERDICT_MAP:
        ctx.db.event(
            "validate.unparseable",
            run_id=task.run_id,
            task_id=task.task_id,
            level="warn",
            finding_id=task.finding_id,
            got=raw_verdict[:80],
        )
        return TaskOutcome(status="failed", exit_reason="schema_invalid", duration_s=duration)

    ctx.db.record_validation(
        Validation(
            validation_id=new_id("v"),
            finding_id=task.finding_id,
            task_id=task.task_id,
            validator="adversarial",
            model=ctx.verify_agent.model or ctx.settings.verify.model,
            verdict=raw_verdict,  # type: ignore[arg-type]
            reason=reason,
            detail_json={
                "checks": payload.get("checks", []),
                "corrected_severity": payload.get("corrected_severity"),
                "missing_fact": payload.get("missing_fact"),
            },
        )
    )
    ctx.db.set_verdict(task.finding_id, _VERDICT_MAP[raw_verdict])

    return TaskOutcome(
        status="done",
        exit_reason="ok",
        duration_s=duration,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost_usd=result.cost_usd,
        detail={"verdict": raw_verdict, "reason": reason[:400]},
    )
