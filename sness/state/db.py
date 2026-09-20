"""SQLite state. Every stage reads and writes here; nothing important lives in a context window.

Single-process orchestrator, so a re-entrant lock around the connection is sufficient and
far simpler than a pool. Writes are sub-millisecond; the bottleneck is always the model.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sness.state.models import Cell, Finding, Run, Task, Validation, Wish, now

SCHEMA = Path(__file__).with_name("schema.sql")
SCHEMA_VERSION = 1


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _dumps(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, default=str)


class Database:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, timeout=30.0)
        self._conn.row_factory = sqlite3.Row
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript(SCHEMA.read_text())
            self._conn.execute(
                "INSERT OR IGNORE INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,)
            )
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---------- primitives ----------

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # ---------- events (append-only audit trail) ----------

    def event(
        self,
        kind: str,
        /,
        *,
        run_id: str | None = None,
        repo_id: str | None = None,
        task_id: str | None = None,
        level: str = "info",
        **payload: Any,
    ) -> None:
        """Append an audit record.

        `kind` is positional-only (PEP 570) on purpose: callers routinely log a payload
        field of their own called "kind" (a task kind, a wish kind), and without the `/`
        that collides with this parameter and raises TypeError on the first event written.
        """
        self.execute(
            "INSERT INTO events(ts, run_id, repo_id, task_id, level, kind, payload_json)"
            " VALUES (?,?,?,?,?,?,?)",
            (now(), run_id, repo_id, task_id, level, kind, _dumps(payload)),
        )

    # ---------- runs ----------

    def create_run(self, run: Run) -> Run:
        self.execute(
            "INSERT INTO runs(run_id, started_at, status, profile, budget_tasks,"
            " model_hunt, model_verify, config_json) VALUES (?,?,?,?,?,?,?,?)",
            (
                run.run_id,
                run.started_at,
                run.status,
                run.profile,
                run.budget_tasks,
                run.model_hunt,
                run.model_verify,
                _dumps(run.config_json),
            ),
        )
        self.event("run.created", run_id=run.run_id, profile=run.profile)
        return run

    def finish_run(self, run_id: str, status: str, reason: str | None = None) -> None:
        self.execute(
            "UPDATE runs SET status=?, ended_at=?, incomplete_reason=? WHERE run_id=?",
            (status, now(), reason, run_id),
        )
        self.event("run.finished", run_id=run_id, status=status, reason=reason)

    def latest_run(self) -> sqlite3.Row | None:
        return self.one("SELECT * FROM runs ORDER BY started_at DESC LIMIT 1")

    # ---------- repos ----------

    def upsert_repo(self, repo_id: str, name: str, path: str, **kw: Any) -> str:
        self.execute(
            "INSERT INTO repos(repo_id, name, path, git_remote, head_sha, dirty, lang_mix_json,"
            " enabled, budget_tasks) VALUES (?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(repo_id) DO UPDATE SET name=excluded.name, path=excluded.path,"
            " head_sha=excluded.head_sha, dirty=excluded.dirty, lang_mix_json=excluded.lang_mix_json",
            (
                repo_id,
                name,
                path,
                kw.get("git_remote"),
                kw.get("head_sha"),
                int(kw.get("dirty", False)),
                _dumps(kw.get("lang_mix", {})),
                int(kw.get("enabled", True)),
                kw.get("budget_tasks"),
            ),
        )
        return repo_id

    # ---------- stages ----------

    def set_stage(self, run_id: str, repo_id: str, stage: str, status: str, error: str | None = None) -> None:
        ts = now()
        self.execute(
            "INSERT INTO stages(run_id, repo_id, stage, status, attempt, started_at, ended_at, error)"
            " VALUES (?,?,?,?,1,?,?,?)"
            " ON CONFLICT(run_id, repo_id, stage) DO UPDATE SET status=excluded.status,"
            " attempt=stages.attempt+1, ended_at=excluded.ended_at, error=excluded.error",
            (
                run_id,
                repo_id,
                stage,
                status,
                ts,
                ts if status in ("done", "failed", "skipped") else None,
                error,
            ),
        )

    def stage_status(self, run_id: str, repo_id: str, stage: str) -> str | None:
        row = self.one(
            "SELECT status FROM stages WHERE run_id=? AND repo_id=? AND stage=?",
            (run_id, repo_id, stage),
        )
        return row["status"] if row else None

    # ---------- tasks ----------

    def enqueue(self, task: Task) -> Task:
        self.execute(
            "INSERT INTO tasks(task_id, run_id, repo_id, stage, kind, cell_id, parent_task_id,"
            " origin, finding_id, priority, prompt, seed_json, status, attempt)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                task.task_id,
                task.run_id,
                task.repo_id,
                task.stage,
                task.kind,
                task.cell_id,
                task.parent_task_id,
                task.origin,
                task.finding_id,
                task.priority,
                task.prompt,
                _dumps(task.seed_json),
                task.status,
                task.attempt,
            ),
        )
        self.event(
            "task.enqueued",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            kind=task.kind,
            origin=task.origin,
            cell_id=task.cell_id,
        )
        return task

    def lease(self, run_id: str, worker: str, lease_s: int = 3600, kinds: list[str] | None = None) -> Task | None:
        """Atomically claim the highest-priority queued task, or reclaim an expired lease."""
        with self._lock:
            clause = ""
            params: list[Any] = [run_id, now()]
            if kinds:
                clause = f" AND kind IN ({','.join('?' * len(kinds))})"
                params.extend(kinds)
            row = self._conn.execute(
                "SELECT * FROM tasks WHERE run_id=? AND (status='queued'"
                " OR (status='leased' AND lease_until IS NOT NULL AND lease_until < ?))"
                + clause
                + " ORDER BY priority ASC, task_id ASC LIMIT 1",
                tuple(params),
            ).fetchone()
            if row is None:
                return None
            until = (datetime.now(UTC) + timedelta(seconds=lease_s)).isoformat()
            self._conn.execute(
                "UPDATE tasks SET status='leased', worker=?, lease_until=?, started_at=?,"
                " attempt=attempt+1 WHERE task_id=?",
                (worker, until, now(), row["task_id"]),
            )
            self._conn.commit()
            return Task.from_row(
                self._conn.execute("SELECT * FROM tasks WHERE task_id=?", (row["task_id"],)).fetchone()
            )

    def complete_task(
        self,
        task_id: str,
        *,
        status: str,
        exit_reason: str,
        duration_s: float = 0.0,
        tokens_in: int = 0,
        tokens_out: int = 0,
        cost_usd: float = 0.0,
        result: dict | None = None,
    ) -> None:
        self.execute(
            "UPDATE tasks SET status=?, exit_reason=?, ended_at=?, duration_s=?, tokens_in=?,"
            " tokens_out=?, cost_usd=?, result_json=?, lease_until=NULL WHERE task_id=?",
            (
                status,
                exit_reason,
                now(),
                duration_s,
                tokens_in,
                tokens_out,
                cost_usd,
                _dumps(result or {}),
                task_id,
            ),
        )

    def requeue(self, task: Task, origin: str, *, priority_boost: int = -10) -> Task:
        """Re-file a task under a fresh id so the original attempt stays auditable.

        The retry depth travels in seed_json rather than in `attempt`, because `attempt`
        counts leases of one row and is reset by the new id. Without this, a task that
        fails identically every time is requeued forever: observed live as nine
        consecutive validations of the same finding, each one paid for.
        """
        seed = dict(task.seed_json or {})
        seed["retry_depth"] = int(seed.get("retry_depth", 0)) + 1
        clone = task.model_copy(
            update={
                "task_id": new_id("t"),
                "status": "queued",
                "origin": origin,
                "attempt": 0,
                "seed_json": seed,
                "parent_task_id": task.task_id,
                "priority": max(0, task.priority + priority_boost),
                "lease_until": None,
                "worker": None,
                "exit_reason": None,
            }
        )
        return self.enqueue(clone)

    def pending_count(self, run_id: str) -> int:
        row = self.one(
            "SELECT COUNT(*) c FROM tasks WHERE run_id=? AND status IN ('queued','leased')",
            (run_id,),
        )
        return int(row["c"]) if row else 0

    def spent_tasks(self, run_id: str, repo_id: str | None = None) -> int:
        sql = "SELECT COUNT(*) c FROM tasks WHERE run_id=? AND status NOT IN ('queued','abandoned')"
        params: tuple = (run_id,)
        if repo_id:
            sql += " AND repo_id=?"
            params += (repo_id,)
        row = self.one(sql, params)
        return int(row["c"]) if row else 0

    def iter_tasks(self, run_id: str, **filters: Any) -> Iterator[Task]:
        sql = "SELECT * FROM tasks WHERE run_id=?"
        params: tuple = (run_id,)
        for k, v in filters.items():
            sql += f" AND {k}=?"
            params += (v,)
        for row in self.query(sql + " ORDER BY task_id", params):
            yield Task.from_row(row)

    # ---------- cells ----------

    def upsert_cell(self, cell: Cell) -> None:
        self.execute(
            "INSERT INTO cells(run_id, repo_id, cell_id, area, attack_class, paths_json,"
            " rationale, priority, status, hunter_tasks, findings_count, last_touched)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(run_id, repo_id, cell_id) DO UPDATE SET status=excluded.status,"
            " hunter_tasks=excluded.hunter_tasks, findings_count=excluded.findings_count,"
            " last_touched=excluded.last_touched, priority=excluded.priority",
            (
                cell.run_id,
                cell.repo_id,
                cell.cell_id,
                cell.area,
                cell.attack_class,
                _dumps(cell.paths_json),
                cell.rationale,
                cell.priority,
                cell.status,
                cell.hunter_tasks,
                cell.findings_count,
                cell.last_touched or now(),
            ),
        )

    def cells(self, run_id: str, repo_id: str | None = None, status: str | None = None) -> list[Cell]:
        sql = "SELECT * FROM cells WHERE run_id=?"
        params: tuple = (run_id,)
        if repo_id:
            sql += " AND repo_id=?"
            params += (repo_id,)
        if status:
            sql += " AND status=?"
            params += (status,)
        return [Cell.from_row(r) for r in self.query(sql + " ORDER BY priority, cell_id", params)]

    def touch_cell(self, run_id: str, repo_id: str, cell_id: str, *, findings: int = 0, status: str | None = None) -> None:
        sets = "hunter_tasks=hunter_tasks+1, findings_count=findings_count+?, last_touched=?"
        params: tuple = (findings, now())
        if status:
            sets += ", status=?"
            params += (status,)
        self.execute(
            f"UPDATE cells SET {sets} WHERE run_id=? AND repo_id=? AND cell_id=?",
            params + (run_id, repo_id, cell_id),
        )

    # ---------- findings ----------

    def file_finding(self, f: Finding) -> Finding:
        self.execute(
            "INSERT INTO findings(finding_id, run_id, repo_id, task_id, fingerprint, title, area,"
            " attack_class, cell_id, threat_model_json, trace_json, evidence_json, poc_json,"
            " severity_json, remediation_json, verdict, duplicate_of, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                f.finding_id,
                f.run_id,
                f.repo_id,
                f.task_id,
                f.fingerprint,
                f.title,
                f.area,
                f.attack_class,
                f.cell_id,
                _dumps(f.threat_model_json),
                _dumps(f.trace_json),
                _dumps(f.evidence_json),
                _dumps(f.poc_json),
                _dumps(f.severity_json),
                _dumps(f.remediation_json),
                f.verdict,
                f.duplicate_of,
                f.created_at,
            ),
        )
        self.event(
            "finding.filed",
            run_id=f.run_id,
            repo_id=f.repo_id,
            task_id=f.task_id,
            finding_id=f.finding_id,
            title=f.title,
            fingerprint=f.fingerprint,
        )
        return f

    def set_verdict(self, finding_id: str, verdict: str, duplicate_of: str | None = None) -> None:
        self.execute(
            "UPDATE findings SET verdict=?, duplicate_of=?, updated_at=? WHERE finding_id=?",
            (verdict, duplicate_of, now(), finding_id),
        )
        self.event("finding.verdict", finding_id=finding_id, verdict=verdict)

    def findings(self, run_id: str, verdict: str | None = None, repo_id: str | None = None) -> list[Finding]:
        sql = "SELECT * FROM findings WHERE run_id=?"
        params: tuple = (run_id,)
        if verdict:
            sql += " AND verdict=?"
            params += (verdict,)
        if repo_id:
            sql += " AND repo_id=?"
            params += (repo_id,)
        return [Finding.from_row(r) for r in self.query(sql + " ORDER BY created_at", params)]

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self.one("SELECT * FROM findings WHERE finding_id=?", (finding_id,))
        return Finding.from_row(row) if row else None

    def find_by_sink(self, run_id: str, repo_id: str, file: str, line: int) -> Finding | None:
        """Cheapest possible dedup: two findings whose sink is the same line are one bug.

        Deterministic and run before any model is paid to reason about similarity --
        Cloudflare's advice is to skip a dedicated dedup agent until actually drowning in
        noise, but an exact-location collapse costs nothing and caught 4 of 7 duplicates
        in the first calibration run.
        """
        for f in self.findings(run_id, repo_id=repo_id):
            for step in f.trace_json:
                if (
                    isinstance(step, dict)
                    and step.get("kind") == "sink"
                    and str(step.get("file", "")).lstrip("/") == file.lstrip("/")
                    and int(step.get("line", -1) or -1) == line
                ):
                    return f
        return None

    def find_by_fingerprint(self, run_id: str, fingerprint: str) -> Finding | None:
        row = self.one(
            "SELECT * FROM findings WHERE run_id=? AND fingerprint=? LIMIT 1", (run_id, fingerprint)
        )
        return Finding.from_row(row) if row else None

    # ---------- validations ----------

    def record_validation(self, v: Validation) -> Validation:
        self.execute(
            "INSERT INTO validations(validation_id, finding_id, task_id, validator, model, verdict,"
            " reason, detail_json, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                v.validation_id,
                v.finding_id,
                v.task_id,
                v.validator,
                v.model,
                v.verdict,
                v.reason,
                _dumps(v.detail_json),
                v.created_at,
            ),
        )
        self.event(
            "validation.recorded",
            finding_id=v.finding_id,
            validator=v.validator,
            verdict=v.verdict,
            model=v.model,
        )
        return v

    def validations_for(self, finding_id: str) -> list[Validation]:
        rows = self.query(
            "SELECT * FROM validations WHERE finding_id=? ORDER BY created_at", (finding_id,)
        )
        out = []
        for r in rows:
            d = dict(r)
            d["detail_json"] = json.loads(d["detail_json"] or "{}")
            out.append(Validation(**d))
        return out

    # ---------- wishlist ----------

    def wish(self, w: Wish) -> Wish:
        self.execute(
            "INSERT INTO wishlist(wish_id, run_id, repo_id, task_id, kind, resource, context_json,"
            " status, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                w.wish_id,
                w.run_id,
                w.repo_id,
                w.task_id,
                w.kind,
                w.resource,
                _dumps(w.context_json),
                w.status,
                w.created_at,
            ),
        )
        self.event("wishlist.written", run_id=w.run_id, task_id=w.task_id, kind=w.kind, resource=w.resource)
        return w

    def open_wishes(self, run_id: str | None = None) -> list[Wish]:
        sql = "SELECT * FROM wishlist WHERE status='open'"
        params: tuple = ()
        if run_id:
            sql += " AND run_id=?"
            params = (run_id,)
        out = []
        for r in self.query(sql + " ORDER BY created_at DESC", params):
            d = dict(r)
            d["context_json"] = json.loads(d["context_json"] or "{}")
            out.append(Wish(**d))
        return out
