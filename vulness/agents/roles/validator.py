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
from pathlib import Path

from vulness.agents.context_budget import ContextBudget, Section
from vulness.agents.roles.context import RoleContext, TaskOutcome
from vulness.prompts import preamble, render
from vulness.state.db import new_id
from vulness.state.models import Task, Validation

_VERDICT_MAP = {
    "upheld": "confirmed",
    "disproved": "rejected",
    "needs_validation": "needs_validation",
}


# Enough context to judge a claim without being able to open the file yourself.
_SNIPPET_BEFORE = 12
_SNIPPET_AFTER = 12
# A validator that is handed more source than it can answer about runs out of tokens
# mid-sentence and returns nothing, which is strictly worse than being handed less.
_MAX_SOURCE_CHARS = 14_000
_MAX_LOCATIONS = 12


def _source_block(ctx: RoleContext, finding_id: str, repo: Path) -> str:
    """Embed the cited source, because the validator cannot go and read it.

    The hunt runs on a CLI agent with a filesystem. Validation runs on an API model with
    none. Asking it to "read the cited code" produced exactly what you would expect once
    findings got large enough to need it: the model emitted a tool call it has no runtime
    for and stopped mid-sentence, and every validation of that finding failed as
    schema_invalid. Observed on real code, not in theory. So the harness does the reading.
    """
    f = ctx.db.get_finding(finding_id)
    if f is None:
        return "(finding missing)"

    wanted: dict[str, set[int]] = {}
    for item in list(f.trace_json) + list((f.evidence_json or {}).get("items") or []):
        if isinstance(item, dict) and item.get("file") and item.get("line"):
            wanted.setdefault(str(item["file"]).lstrip("/"), set()).add(int(item["line"]))

    # Keep the sink's own file first: it is the one location the verdict actually turns on.
    sink_files = {
        str(s.get("file", "")).lstrip("/")
        for s in f.trace_json
        if isinstance(s, dict) and s.get("kind") == "sink"
    }
    ordered = sorted(wanted.items(), key=lambda kv: (kv[0] not in sink_files, kv[0]))[
        :_MAX_LOCATIONS
    ]

    out: list[str] = []
    budget = _MAX_SOURCE_CHARS
    for rel, lines in ordered:
        if budget <= 0:
            out.append("_Further cited locations omitted to keep the answer within budget._")
            break
        path = (repo / rel).resolve()
        try:
            path.relative_to(repo.resolve())
            text = path.read_text(errors="replace").splitlines()
        except (OSError, ValueError):
            out.append(f"### {rel}\n\n_could not be read; treat any claim about it as unproven._")
            continue
        # Merge overlapping windows so one function does not appear three times.
        spans: list[tuple[int, int]] = []
        for ln in sorted(lines):
            lo, hi = max(1, ln - _SNIPPET_BEFORE), min(len(text), ln + _SNIPPET_AFTER)
            if spans and lo <= spans[-1][1] + 1:
                spans[-1] = (spans[-1][0], max(spans[-1][1], hi))
            else:
                spans.append((lo, hi))
        for lo, hi in spans:
            body = "\n".join(f"{i:>5} | {text[i - 1]}" for i in range(lo, hi + 1))
            block = f"### {rel} lines {lo}-{hi}\n\n```\n{body}\n```"
            budget -= len(block)
            out.append(block)
            if budget <= 0:
                break
    return "\n\n".join(out) or "_No citable source locations._"


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
    source = _source_block(ctx, task.finding_id, repo)
    prompt, fit = budget.fit(
        [
            Section("head", head, priority=0),
            Section("finding", _finding_block(ctx, task.finding_id), priority=2, floor_chars=1500),
            # The source outranks the claim: a validator with the claim but not the code
            # can only agree with it.
            Section(
                "source",
                "## The cited source\n\n" + source,
                priority=1,
                floor_chars=2000,
            ),
            Section("tail", tail, priority=0),
        ],
        separator="\n\n",
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
