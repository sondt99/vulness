"""Feedback: turn this run's rejections into sharper prompts, while the run is still going.

    The Feedback agent learns from validation failures and instantly rewrites queued
    prompts to make future tasks sharper.
        -- Cloudflare, "Build your own vulnerability harness"

The load-bearing word is *instantly*. A post-run quality report is a document nobody reads;
rewriting the prompts of tasks that have not been leased yet changes the output of the very
run that produced the rejections. That is why this stage reaches into the `tasks` table
directly instead of handing advice back to the scheduler -- by the time a run ends there is
nothing left to sharpen.

Three rules keep it safe to run repeatedly:

- **It never files a finding.** There is no `db.file_finding` call here and there must
  never be one. Feedback reads the harness's own verdicts; a stage that both judges the
  hunters and files alongside them is grading its own homework.
- **The rewrite is idempotent.** Every addendum is prefixed with a sentinel marker and any
  task already carrying it is skipped, so a second pass sharpens the prompts that are still
  plain rather than stacking guidance until the hunt has no context left for the hunt.
- **It costs nothing when there is nothing to learn.** No rejections means no model call.
  A task spent confirming that hunters are doing fine is a hunt that never happened.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

from sness.agents.context_budget import ContextBudget, Section, occupancy_fraction, peak_occupancy
from sness.agents.roles.context import RoleContext, TaskOutcome
from sness.prompts import preamble, render
from sness.state.models import Task

# Fences the appended guidance. Present in the prompt text itself -- not in a side table --
# because the prompt column is the only thing that survives a crash and a restart, and the
# check has to work against a row the current process never wrote.
MARKER = "<!-- sness:feedback-addendum -->"

# Hard ceiling on what gets appended. A hunter's window is the scarce resource the whole
# harness is built around; guidance that displaces the architecture map is a net loss even
# when it is correct.
MAX_ADDENDUM_CHARS = 2500

# How many rejection records reach the prompt verbatim. The clustered digest above them
# carries the signal; the raw sample is there so the model can see real wording.
_MAX_RAW_REJECTIONS = 40
_MAX_MODES = 8

_REJECTION_SQL = """
SELECT v.validator, v.reason, f.finding_id, f.title, f.attack_class, f.area, f.repo_id
FROM validations v
JOIN findings f ON f.finding_id = v.finding_id
WHERE f.run_id = ? AND v.verdict = 'disproved' AND v.validator IN ('mechanical', 'adversarial')
ORDER BY v.created_at
"""

# Candidates killed before a validator ever saw them. These never reach the validations
# table, so a feedback stage that read only verdicts would miss the cheapest lesson there
# is: findings that were malformed rather than wrong.
_GATE_EVENT_SQL = """
SELECT kind, payload_json FROM events
WHERE run_id = ? AND kind IN ('finding.gated', 'finding.unparseable')
ORDER BY event_id
"""

# Normalisation for clustering. Paths first: the path pattern would otherwise swallow the
# digits it needs to see, and "line 84 does not exist in api/views.py" has to collapse onto
# "line # does not exist in <path>" for the count to mean anything.
_PATHISH = re.compile(r"[\w@-]*[./\\][\w./\\@-]+")
_DIGITS = re.compile(r"\d+")
_WHITESPACE = re.compile(r"\s+")


@dataclass(slots=True)
class _Rejection:
    """One way the harness told a hunter it was wrong."""

    source: str  # mechanical | adversarial | gate | unparseable
    reason: str
    title: str
    attack_class: str
    repo_id: str


def _collect(ctx: RoleContext, run_id: str) -> list[_Rejection]:
    """Every rejection this run has produced, from both places they land."""
    out: list[_Rejection] = []
    for row in ctx.db.query(_REJECTION_SQL, (run_id,)):
        out.append(
            _Rejection(
                source=str(row["validator"]),
                reason=str(row["reason"] or "").strip(),
                title=str(row["title"] or ""),
                attack_class=str(row["attack_class"] or ""),
                repo_id=str(row["repo_id"] or ""),
            )
        )
    for row in ctx.db.query(_GATE_EVENT_SQL, (run_id,)):
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        kind = str(row["kind"])
        out.append(
            _Rejection(
                source="gate" if kind == "finding.gated" else "unparseable",
                reason=str(payload.get("reason") or payload.get("error") or "").strip(),
                title=str(payload.get("title") or ""),
                attack_class="",
                repo_id="",
            )
        )
    return [r for r in out if r.reason]


def _signature(reason: str) -> str:
    """Collapse one rejection reason to the shape of the mistake behind it."""
    s = _PATHISH.sub("<path>", reason.strip().lower())
    s = _DIGITS.sub("#", s)
    return _WHITESPACE.sub(" ", s)[:140]


def _failure_modes(rejections: list[_Rejection]) -> list[dict[str, Any]]:
    """Group rejections by what they are really saying, ranked by how often it happened.

    Deterministic clustering before the model runs, not instead of it. A count is the one
    thing a model cannot get right by reading a sample, and "12 findings died on bad line
    numbers" is a far stronger instruction to write against than twelve separate anecdotes.
    """
    groups: dict[tuple[str, str], list[_Rejection]] = {}
    for r in rejections:
        groups.setdefault((r.source, _signature(r.reason)), []).append(r)
    ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    return [
        {
            "source": source,
            "count": len(members),
            "pattern": signature,
            "examples": [m.reason[:300] for m in members[:2]],
            "titles": [m.title[:120] for m in members[:2] if m.title],
        }
        for (source, signature), members in ranked[:_MAX_MODES]
    ]


def _modes_block(modes: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for m in modes:
        lines.append(f"- **{m['count']}x** via `{m['source']}` - {m['pattern']}")
        lines.extend(f"    - example: {ex}" for ex in m["examples"])
    return "\n".join(lines) or "_(no reasons recorded)_"


def _rejections_block(rejections: list[_Rejection]) -> str:
    sample = [
        {
            "source": r.source,
            "repo": r.repo_id,
            "attack_class": r.attack_class,
            "title": r.title[:160],
            "reason": r.reason[:600],
        }
        for r in rejections[-_MAX_RAW_REJECTIONS:]
    ]
    return "```json\n" + json.dumps(sample, indent=2) + "\n```"


def _rewrite_queued(ctx: RoleContext, run_id: str, addendum: str) -> tuple[int, int]:
    """Append the addendum to every hunt still waiting. Returns (rewritten, skipped).

    Run-scoped rather than repo-scoped on purpose: what these rejections describe is how
    the hunt *model* fails -- fabricated line numbers, threat models that name a role
    instead of a principal -- and those habits do not stop at a repository boundary.
    """
    block = f"\n\n{MARKER}\n## Corrective guidance from this run's rejections\n\n{addendum}\n"
    rewritten = skipped = 0
    for queued in ctx.db.iter_tasks(run_id, status="queued"):
        if queued.kind not in ("hunt", "gapfill"):
            continue
        if MARKER in queued.prompt:
            skipped += 1
            continue
        # `status='queued'` is repeated in the UPDATE, not just the read: workers lease
        # tasks concurrently with this loop, and rewriting a prompt that is already in
        # flight changes nothing except the audit trail's honesty about what ran.
        cursor = ctx.db.execute(
            "UPDATE tasks SET prompt = prompt || ? WHERE task_id = ? AND status = 'queued'",
            (block, queued.task_id),
        )
        if cursor.rowcount:
            rewritten += 1
        else:
            skipped += 1
    return rewritten, skipped


async def run_feedback(ctx: RoleContext, task: Task) -> TaskOutcome:
    started = time.monotonic()
    rejections = _collect(ctx, task.run_id)

    # Nothing has been rejected yet, so there is nothing to learn and no prompt to sharpen.
    # Spending a model call to discover that is the one mistake this stage cannot afford.
    if not rejections:
        ctx.db.event(
            "feedback.noop",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            reason="no rejections recorded for this run",
        )
        return TaskOutcome(
            status="done",
            exit_reason="ok",
            duration_s=time.monotonic() - started,
            detail={"rejections_analysed": 0, "tasks_rewritten": 0, "addendum": ""},
        )

    modes = _failure_modes(rejections)
    instruction = render(
        "feedback",
        run_id=task.run_id,
        rejection_count=len(rejections),
        max_chars=MAX_ADDENDUM_CHARS,
        modes_block="{MODES}",
        rejections_block="{REJECTIONS}",
    )

    # The clustered digest outranks the raw dump: it is where the counts live, and counts
    # are what turn an anecdote into an instruction. The raw sample exists only so the
    # model can hear the harness's actual wording, so it is the first thing shed.
    budget = ContextBudget(ctx.settings.hunt.model, occupancy=ctx.settings.budget.context_occupancy)
    head, _, rest = instruction.partition("{MODES}")
    mid, _, foot = rest.partition("{REJECTIONS}")
    prompt, fit = budget.fit(
        [
            Section("instruction_head", head, priority=0),
            Section("modes", _modes_block(modes), priority=1, floor_chars=800),
            Section("instruction_mid", mid, priority=0),
            Section("rejections", _rejections_block(rejections), priority=2, floor_chars=600),
            Section("instruction_tail", foot, priority=0),
        ],
        separator="",
    )
    if fit.trimmed or fit.dropped or fit.over_budget:
        ctx.db.event(
            "context.trimmed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn" if fit.over_budget else "info",
            detail=fit.summary(),
        )

    result = await ctx.hunt_agent.run(
        prompt,
        system=preamble(),
        cwd=ctx.repo_paths.get(task.repo_id),
        timeout_s=ctx.settings.hunt.timeout_s,
        schema={"failure_modes": "list", "addendum": "str"},
    )
    duration = time.monotonic() - started

    if not result.ok:
        ctx.db.event(
            "feedback.failed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="error",
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

    peak = peak_occupancy(result.raw_events)
    frac = occupancy_fraction(peak, ctx.settings.hunt.model)
    if frac > ctx.settings.budget.context_occupancy:
        ctx.db.event(
            "context.exceeded",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            peak_tokens=peak,
            occupancy=round(frac, 3),
            target=ctx.settings.budget.context_occupancy,
        )

    payload = result.extract_json() or {}
    addendum = str(payload.get("addendum") or "").strip()[:MAX_ADDENDUM_CHARS]
    if not addendum:
        # The call succeeded and said nothing usable. `schema_invalid` is retryable, which
        # is what we want: the rejections are still sitting there and a second attempt is
        # cheap relative to leaving the rest of the run hunting the same way.
        ctx.db.event(
            "feedback.unparseable",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            keys=sorted(payload)[:10],
        )
        return TaskOutcome(
            status="failed",
            exit_reason="schema_invalid",
            duration_s=duration,
            tokens_in=result.tokens_in,
            tokens_out=result.tokens_out,
            cost_usd=result.cost_usd,
        )

    rewritten, skipped = _rewrite_queued(ctx, task.run_id, addendum)
    model_modes = [m for m in (payload.get("failure_modes") or []) if isinstance(m, dict)]

    ctx.db.event(
        "feedback.complete",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        rejections=len(rejections),
        rewritten=rewritten,
        skipped=skipped,
        modes=[str(m.get("mode", ""))[:120] for m in model_modes[:_MAX_MODES]],
    )
    return TaskOutcome(
        status="done",
        exit_reason="ok",
        duration_s=duration,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost_usd=result.cost_usd,
        detail={
            "rejections_analysed": len(rejections),
            "tasks_rewritten": rewritten,
            "addendum": addendum,
            "tasks_skipped": skipped,
            "clustered_modes": modes,
            "model_failure_modes": model_modes[:_MAX_MODES],
            "peak_context_tokens": peak,
            "context_occupancy": round(frac, 3),
            "context_fit": fit.summary(),
        },
    )
