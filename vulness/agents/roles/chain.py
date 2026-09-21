"""Compose confirmed findings into exploit chains.

Every other stage treats a finding as one root cause crossing one boundary. That is the
right unit for writing a fix and the wrong unit for judging impact: three mediums that
compose into unauthenticated code execution are not a medium problem, and nobody triaging
them individually will ever see it.

This runs on the hunting model rather than the verifying one. Composing an attack is
generative work: it asks what an attacker could build out of parts, which is a different
task from checking whether a claim about a line of code is true.

It draws on confirmed findings across **every** run of the repository, not just this one.
Chains are exactly the thing a single run is least likely to see, because the two halves
are often found weeks apart by hunters working different cells.
"""

from __future__ import annotations

import json
import time

from vulness.agents.context_budget import ContextBudget, Section
from vulness.agents.roles.context import RoleContext, TaskOutcome
from vulness.prompts import preamble, render
from vulness.state.db import new_id
from vulness.state.models import Task

# Below this there is nothing to compose, and paying a model to confirm that is waste.
MIN_FINDINGS = 2
# Chains are pairwise-ish reasoning, so the prompt grows fast. The most severe findings
# are the ones worth composing anyway.
MAX_FINDINGS = 18

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}


def _findings_block(ctx: RoleContext, repo_id: str) -> tuple[str, dict[str, str]]:
    """Render confirmed findings for composition, most severe first.

    Returns the text and a map of finding_id -> title, so a chain that cites an id which
    was never shown can be rejected without asking a model whether it made it up.
    """
    confirmed = [
        f
        for f in ctx.db.query(
            "SELECT * FROM findings WHERE repo_id=? AND verdict='confirmed'", (repo_id,)
        )
    ]
    from vulness.state.models import Finding

    items = [Finding.from_row(r) for r in confirmed]
    items.sort(key=lambda f: _SEVERITY_RANK.get(f.severity(), 5))
    items = items[:MAX_FINDINGS]

    known = {f.finding_id: f.title for f in items}
    blocks = []
    for f in items:
        tm = f.threat_model_json or {}
        sink = next(
            (s for s in f.trace_json if isinstance(s, dict) and s.get("kind") == "sink"), {}
        )
        blocks.append(
            json.dumps(
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "severity": f.severity(),
                    "area": f.area,
                    "attack_class": f.attack_class,
                    "attacker": tm.get("attacker"),
                    "boundary_crossed": tm.get("boundary"),
                    "broken_assumption": tm.get("broken_assumption"),
                    "sink": f"{sink.get('file', '?')}:{sink.get('line', '?')}",
                },
                indent=2,
            )
        )
    return "\n\n".join(blocks), known


async def run_chain(ctx: RoleContext, task: Task) -> TaskOutcome:
    repo = ctx.repo_path(task.repo_id)
    started = time.monotonic()

    block, known = _findings_block(ctx, task.repo_id)
    if len(known) < MIN_FINDINGS:
        ctx.db.event(
            "chain.skipped",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            confirmed=len(known),
        )
        return TaskOutcome(
            status="done",
            exit_reason="ok",
            duration_s=time.monotonic() - started,
            detail={"skipped": f"only {len(known)} confirmed finding(s); nothing to compose"},
        )

    budget = ContextBudget(ctx.settings.hunt.model, occupancy=ctx.settings.budget.context_occupancy)
    instruction = render(
        "chain",
        repo_name=task.repo_id,
        repo_path=str(repo),
        findings_block="{FINDINGS}",
    )
    head, _, tail = instruction.partition("{FINDINGS}")
    prompt, _fit = budget.fit(
        [
            Section("head", head, priority=0),
            Section("findings", block, priority=1, floor_chars=3000),
            Section("tail", tail, priority=0),
        ],
        separator="\n\n",
    )

    result = await ctx.hunt_agent.run(
        prompt,
        system=preamble(),
        cwd=repo,
        timeout_s=ctx.settings.hunt.timeout_s,
        schema={"chains": "list", "rejected_pairs": "list"},
    )
    duration = time.monotonic() - started

    if not result.ok:
        ctx.db.event(
            "chain.failed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="error",
            classification=result.classification,
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
    filed = 0
    for raw in payload.get("chains") or []:
        if not isinstance(raw, dict):
            continue
        steps = [s for s in (raw.get("steps") or []) if isinstance(s, str)]

        # Deterministic gate, before anything is believed: a chain must be built out of
        # findings that were actually shown, in at least two steps. A model composing an
        # attack is the one place in this pipeline most likely to reach for a step that
        # would make the story work, and a hallucinated finding_id is free to invent.
        unknown = [s for s in steps if s not in known]
        if len(steps) < 2 or unknown:
            ctx.db.event(
                "chain.rejected",
                run_id=task.run_id,
                repo_id=task.repo_id,
                task_id=task.task_id,
                level="warn",
                reason="fabricated step" if unknown else "fewer than two steps",
                unknown_ids=unknown[:4],
                title=str(raw.get("title", ""))[:120],
            )
            continue
        if len(set(steps)) != len(steps):
            continue  # a finding cannot chain to itself

        ctx.db.file_chain(
            new_id("ch"),
            task.run_id,
            task.repo_id,
            title=str(raw.get("title", ""))[:300] or "untitled chain",
            narrative=str(raw.get("narrative", "")),
            steps=steps,
            preconditions=str(raw.get("preconditions", "")),
            terminal_impact=str(raw.get("terminal_impact", "")),
            severity=str(raw.get("severity", "medium")),
        )
        filed += 1

    ctx.db.event(
        "chain.complete",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        considered=len(known),
        filed=filed,
        rejected_pairs=len(payload.get("rejected_pairs") or []),
    )
    return TaskOutcome(
        status="done",
        exit_reason="ok",
        duration_s=duration,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost_usd=result.cost_usd,
        detail={"chains_filed": filed, "findings_considered": len(known)},
    )
