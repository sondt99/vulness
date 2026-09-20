"""The producer-consumer loop.

Stages are not a pipeline. Once recon lands, hunting, validation, sibling forks and gapfill
all contend for the same worker pool, and completed work enqueues more work. The loop ends
when the queue drains and gapfill has nothing left to add.

Everything that matters is in SQLite before it is in memory, so the loop is restartable:
kill the process mid-run, start it again, and it reclaims expired leases and re-derives
outstanding validation work from the findings table rather than from anything it remembered.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
import traceback
from collections.abc import Awaitable, Callable

from sness.agents.classify import is_retryable
from sness.agents.roles import (
    RoleContext,
    TaskOutcome,
    run_dedup,
    run_feedback,
    run_fixer,
    run_hunt,
    run_judge,
    run_recon,
    run_trace,
    run_validate,
)
from sness.coverage.cells import thin_cells
from sness.orchestrator.budget import Budget
from sness.state.db import new_id
from sness.state.models import Task

MAX_ATTEMPTS = 3
_LEASE_SECONDS = 3600

# Every TaskKind must appear here. A declared kind with no handler is worse than a missing
# stage: tasks for it are enqueued, fail as schema_invalid, and the pipeline reports a
# stage that exists in the vocabulary and never runs. test_pipeline.py asserts parity.
_HANDLERS: dict[str, Callable[[RoleContext, Task], Awaitable[TaskOutcome]]] = {
    "recon": run_recon,
    "hunt": run_hunt,
    "gapfill": run_hunt,
    "validate": run_validate,
    "feedback": run_feedback,
    "trace": run_trace,
    "judge": run_judge,
    "fix": run_fixer,
    "dedup": run_dedup,
}


def _retry_depth(task: Task) -> int:
    """How many times this task has already been re-filed, across the whole chain."""
    return int((task.seed_json or {}).get("retry_depth", 0))


class Scheduler:
    def __init__(
        self,
        ctx: RoleContext,
        run_id: str,
        *,
        gapfill_passes: int = 1,
        triage: bool = True,
        fix: bool = False,
    ) -> None:
        self.ctx = ctx
        self.db = ctx.db
        self.run_id = run_id
        self.gapfill_passes = gapfill_passes
        self.triage = triage
        self.fix = fix
        self._gapfill_done = 0
        self._triage_done = False
        self._feedback_done = 0
        self._stop = asyncio.Event()
        b = ctx.settings.budget
        self.budget = Budget(
            self.db,
            run_id,
            per_repo=b.tasks_per_repo,
            validator_reserve=b.validator_reserve_fraction,
        )

    # ---------- seeding ----------

    def seed_recon(self, repo_id: str) -> Task:
        return self.db.enqueue(
            Task(
                task_id=new_id("t"),
                run_id=self.run_id,
                repo_id=repo_id,
                stage="recon",
                kind="recon",
                priority=0,  # nothing useful happens before the map exists
                prompt="(rendered at dispatch)",
                origin="seed",
            )
        )

    def seed_hunts(self, repo_id: str) -> int:
        """One hunt per planned cell."""
        n = 0
        for cell in self.db.cells(self.run_id, repo_id, status="planned"):
            self.db.enqueue(
                Task(
                    task_id=new_id("t"),
                    run_id=self.run_id,
                    repo_id=repo_id,
                    stage="hunt",
                    kind="hunt",
                    cell_id=cell.cell_id,
                    priority=cell.priority + 100,  # after recon, before nothing
                    prompt="(rendered at dispatch)",
                    seed_json={
                        "attack_class": cell.attack_class,
                        "area": cell.area,
                        "paths": cell.paths_json,
                    },
                    origin="seed",
                )
            )
            cell.status = "assigned"
            self.db.upsert_cell(cell)
            n += 1
        return n

    def enqueue_pending_validations(self, repo_id: str) -> int:
        """Derive validation work from the findings table, not from memory.

        A candidate with no validate task is outstanding work regardless of what happened
        to the process that filed it -- which is what makes a mid-run crash survivable.
        """
        existing = {
            t.finding_id for t in self.db.iter_tasks(self.run_id, kind="validate") if t.finding_id
        }
        n = 0
        for f in self.db.findings(self.run_id, verdict="candidate", repo_id=repo_id):
            if f.finding_id in existing:
                continue
            self.db.enqueue(
                Task(
                    task_id=new_id("t"),
                    run_id=self.run_id,
                    repo_id=repo_id,
                    stage="validate",
                    kind="validate",
                    finding_id=f.finding_id,
                    cell_id=f.cell_id,
                    priority=50,  # validate eagerly: it is what makes findings real
                    prompt="(rendered at dispatch)",
                    origin="seed",
                )
            )
            n += 1
        return n

    # ---------- the loop ----------

    async def run(self, repo_ids: list[str]) -> None:
        for repo_id in repo_ids:
            if self.db.stage_status(self.run_id, repo_id, "recon") != "done":
                self.seed_recon(repo_id)
            else:
                # Resuming a run that already has a map: go straight back to work.
                self.seed_hunts(repo_id)
                self.enqueue_pending_validations(repo_id)

        n = self.ctx.settings.budget.max_concurrent_agents
        workers = [asyncio.create_task(self._worker(f"w{i}", repo_ids)) for i in range(n)]
        try:
            await asyncio.gather(*workers)
        finally:
            for w in workers:
                if not w.done():
                    w.cancel()
                    with contextlib.suppress(asyncio.CancelledError):
                        await w

    async def _worker(self, worker_id: str, repo_ids: list[str]) -> None:
        idle_rounds = 0
        while not self._stop.is_set():
            task = self.db.lease(self.run_id, worker_id, lease_s=_LEASE_SECONDS)

            if task is None:
                # Queue is empty. Before declaring victory, let gapfill look for thin cells.
                if self.db.pending_count(self.run_id) == 0:
                    if self._run_gapfill(repo_ids):
                        idle_rounds = 0
                        continue
                    if self._run_triage(repo_ids):
                        idle_rounds = 0
                        continue
                    idle_rounds += 1
                    if idle_rounds >= 2:
                        self._stop.set()
                        return
                await asyncio.sleep(0.4)
                continue

            idle_rounds = 0
            decision = self.budget.can_dispatch(task.repo_id, task.kind)
            if not decision.allowed:
                self.db.complete_task(
                    task.task_id, status="abandoned", exit_reason="budget", result={"why": decision.reason}
                )
                self.db.event(
                    "task.budget_hold",
                    run_id=self.run_id,
                    repo_id=task.repo_id,
                    task_id=task.task_id,
                    level="warn",
                    reason=decision.reason,
                )
                continue

            await self._dispatch(task)

    async def _dispatch(self, task: Task) -> None:
        started = time.monotonic()
        try:
            handler = _HANDLERS.get(task.kind)
            if handler is None:
                self.db.event(
                    "task.unroutable",
                    run_id=self.run_id,
                    task_id=task.task_id,
                    level="error",
                    kind=task.kind,
                )
                outcome = TaskOutcome(status="failed", exit_reason="schema_invalid")
            else:
                outcome = await handler(self.ctx, task)
        except Exception as e:  # a role bug must not take the whole run down
            # Keep the traceback. An exception string alone names the symptom and not the
            # line, and these are caught across every stage, so there is no other record.
            self.db.event(
                "task.exception",
                run_id=self.run_id,
                repo_id=task.repo_id,
                task_id=task.task_id,
                level="error",
                kind=task.kind,
                error=f"{type(e).__name__}: {e}"[:300],
                traceback=traceback.format_exc()[-2000:],
            )
            outcome = TaskOutcome(
                status="failed", exit_reason="crash", duration_s=time.monotonic() - started
            )

        self.db.complete_task(
            task.task_id,
            status=outcome.status,
            exit_reason=outcome.exit_reason,
            duration_s=outcome.duration_s,
            tokens_in=outcome.tokens_in,
            tokens_out=outcome.tokens_out,
            cost_usd=outcome.cost_usd,
            result=outcome.detail,
        )
        self._post(task, outcome)

    # ---------- what completion produces ----------

    def _post(self, task: Task, outcome: TaskOutcome) -> None:
        # A transient backend failure is not a result. Requeue it; do not bank the silence.
        if outcome.status == "failed" and is_retryable(outcome.exit_reason):  # type: ignore[arg-type]
            if _retry_depth(task) < MAX_ATTEMPTS:
                self.db.requeue(task, "requeue_error")
            else:
                self.db.event(
                    "task.exhausted",
                    run_id=self.run_id,
                    task_id=task.task_id,
                    level="error",
                    kind=task.kind,
                    attempts=_retry_depth(task),
                    exit_reason=outcome.exit_reason,
                )
            return

        if outcome.status == "shallow" and _retry_depth(task) < MAX_ATTEMPTS:
            self.db.requeue(task, "requeue_shallow")
            return

        if task.kind == "recon" and outcome.status == "done":
            self.db.set_stage(self.run_id, task.repo_id, "recon", "done")
            self.seed_hunts(task.repo_id)
            return

        if task.kind in ("hunt", "gapfill") and outcome.status == "done":
            self._maybe_enqueue_feedback(task.repo_id)
            # Sibling forking: a lead becomes a fresh task with a clean context window,
            # instead of the current hunter wandering off its own cell.
            for lead in outcome.leads[:4]:
                self.db.enqueue(
                    Task(
                        task_id=new_id("t"),
                        run_id=self.run_id,
                        repo_id=task.repo_id,
                        stage="hunt",
                        kind="hunt",
                        cell_id=task.cell_id,
                        parent_task_id=task.task_id,
                        origin="sibling_fork",
                        priority=max(0, task.priority - 5),
                        prompt="(rendered at dispatch)",
                        seed_json={
                            "attack_class": lead.get("attack_class") or task.seed_json.get("attack_class"),
                            "area": task.seed_json.get("area", "root"),
                            "paths": [lead.get("where")] if lead.get("where") else task.seed_json.get("paths", ["."]),
                            "lead": f"{lead.get('where', '?')}: {lead.get('why', '')}",
                        },
                    )
                )
            if outcome.findings_filed:
                self.enqueue_pending_validations(task.repo_id)

    # Below this many rejections there is nothing to generalise from, and a Feedback pass
    # would spend a task to tell hunters what one unlucky agent did once.
    _FEEDBACK_MIN_REJECTIONS = 4
    _FEEDBACK_MAX_PASSES = 2

    def _maybe_enqueue_feedback(self, repo_id: str) -> None:
        """Rewrite queued prompts from what validation has been rejecting.

        Only useful while work is still queued: the stage edits pending tasks, so firing it
        after the queue drains changes nothing.
        """
        if self._feedback_done >= self._FEEDBACK_MAX_PASSES:
            return
        row = self.db.one(
            "SELECT COUNT(*) c FROM validations v JOIN findings f ON f.finding_id=v.finding_id"
            " WHERE f.run_id=? AND v.verdict='disproved'",
            (self.run_id,),
        )
        rejections = int(row["c"]) if row else 0
        if rejections < self._FEEDBACK_MIN_REJECTIONS * (self._feedback_done + 1):
            return
        queued = self.db.one(
            "SELECT COUNT(*) c FROM tasks WHERE run_id=? AND status='queued'"
            " AND kind IN ('hunt','gapfill')",
            (self.run_id,),
        )
        if not queued or int(queued["c"]) == 0:
            return
        self._feedback_done += 1
        self.db.enqueue(
            Task(
                task_id=new_id("t"),
                run_id=self.run_id,
                repo_id=repo_id,
                stage="feedback",
                kind="feedback",
                origin="feedback",
                priority=10,  # ahead of hunts: it exists to improve the ones still waiting
                prompt="(rendered at dispatch)",
            )
        )

    def _run_triage(self, repo_ids: list[str]) -> bool:
        """VVS: dedup, then judge each confirmed finding, then optionally propose fixes.

        Runs once, after discovery has drained. Triage on a partial finding set would
        dedup against records that do not exist yet and judge findings the hunt has not
        finished producing.
        """
        if not self.triage or self._triage_done:
            return False
        self._triage_done = True
        added = 0

        for repo_id in repo_ids:
            confirmed = self.db.findings(self.run_id, verdict="confirmed", repo_id=repo_id)
            if len(confirmed) > 1:
                self.db.enqueue(
                    Task(
                        task_id=new_id("t"),
                        run_id=self.run_id,
                        repo_id=repo_id,
                        stage="dedup",
                        kind="dedup",
                        origin="seed",
                        priority=20,
                        prompt="(rendered at dispatch)",
                    )
                )
                added += 1

            for f in confirmed:
                self.db.enqueue(
                    Task(
                        task_id=new_id("t"),
                        run_id=self.run_id,
                        repo_id=repo_id,
                        stage="judge",
                        kind="judge",
                        finding_id=f.finding_id,
                        origin="seed",
                        priority=30,
                        prompt="(rendered at dispatch)",
                    )
                )
                added += 1
                if self.fix:
                    self.db.enqueue(
                        Task(
                            task_id=new_id("t"),
                            run_id=self.run_id,
                            repo_id=repo_id,
                            stage="fix",
                            kind="fix",
                            finding_id=f.finding_id,
                            origin="seed",
                            priority=40,
                            prompt="(rendered at dispatch)",
                        )
                    )
                    added += 1

        # Cross-repo tracing is meaningless below two repos, and trace itself short-circuits
        # without spending a model call, so gating here is belt and braces.
        if len(repo_ids) > 1:
            for repo_id in repo_ids:
                self.db.enqueue(
                    Task(
                        task_id=new_id("t"),
                        run_id=self.run_id,
                        repo_id=repo_id,
                        stage="trace",
                        kind="trace",
                        origin="seed",
                        priority=25,
                        prompt="(rendered at dispatch)",
                    )
                )
                added += 1

        if added:
            self.db.event("triage.started", run_id=self.run_id, tasks=added, fix_enabled=self.fix)
        return added > 0

    def _run_gapfill(self, repo_ids: list[str]) -> bool:
        """Enqueue hunts for cells that were never reached. Returns True if it added work.

        Gapfill is the cost-to-coverage lever: a second pass costs a fraction of the first
        because it only revisits cells the grid says are thin.
        """
        if self._gapfill_done >= self.gapfill_passes:
            return False
        self._gapfill_done += 1
        added = 0
        for repo_id in repo_ids:
            # Any candidate still unvalidated outranks new hunting.
            added += self.enqueue_pending_validations(repo_id)
            for cell in thin_cells(self.db.cells(self.run_id, repo_id)):
                if not self.budget.can_dispatch(repo_id, "hunt").allowed:
                    break
                self.db.enqueue(
                    Task(
                        task_id=new_id("t"),
                        run_id=self.run_id,
                        repo_id=repo_id,
                        stage="gapfill",
                        kind="gapfill",
                        cell_id=cell.cell_id,
                        origin="gapfill",
                        priority=cell.priority + 200,
                        prompt="(rendered at dispatch)",
                        seed_json={
                            "attack_class": cell.attack_class,
                            "area": cell.area,
                            "paths": cell.paths_json,
                        },
                    )
                )
                added += 1
        if added:
            self.db.event("gapfill.pass", run_id=self.run_id, added=added, pass_no=self._gapfill_done)
        return added > 0
