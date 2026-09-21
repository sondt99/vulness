"""The wishlist is a two-way channel, and these tests cover the return half.

Cloudflare's design is explicit that an agent records what it could not do *plus enough
context to re-run that exact task* once a human provides the dependency. Writing the wish
was already implemented. Resolving one is where the expensive mistakes live: drop the
requeue and the gap the agent wrote about is never examined again, double it and a paid
hunt runs twice for one wish.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest
from rich.console import Console

from vulness import cli
from vulness.state.db import Database, new_id
from vulness.state.models import Run, Task, Wish


@dataclass
class Harness:
    db: Database
    run_id: str
    task: Task
    wish: Wish


@pytest.fixture
def h(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    """A finished hunt, and the wish it wrote because it could not finish the job."""
    db = Database(tmp_path / "state.db")
    db.create_run(Run(run_id="r", status="running", model_hunt="m", model_verify="n"))
    db.upsert_repo("repo", name="repo", path=str(tmp_path))

    task = db.enqueue(
        Task(
            task_id=new_id("t"),
            run_id="r",
            repo_id="repo",
            stage="hunt",
            kind="hunt",
            cell_id="c1",
            prompt="hunt the auth area for injection",
            seed_json={"area": "auth"},
        )
    )
    db.complete_task(task.task_id, status="done", exit_reason="ok")
    wish = db.wish(
        Wish(
            wish_id=new_id("w"),
            run_id="r",
            repo_id="repo",
            task_id=task.task_id,
            kind="build_env",
            resource="a staging database loaded with the production schema",
            context_json={"why": "the SQL sink is unreachable without one"},
        )
    )

    monkeypatch.setattr(cli, "_load", lambda config: (None, db))
    # A fixed wide console: rich wraps to the terminal width, and an assertion about a
    # command string is otherwise testing the line-breaking rather than the output.
    monkeypatch.setattr(cli, "console", Console(width=200, no_color=True))
    return Harness(db=db, run_id="r", task=task, wish=wish)


def _queued(db: Database) -> list[Task]:
    return list(db.iter_tasks("r", status="queued"))


def test_listing_shows_the_wish_id_and_the_task_that_asked(
    h: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    """A wish nobody can address is just a log line. Acting on one needs both ids."""
    assert cli.app(["wishlist"]) == 0
    out = capsys.readouterr().out
    assert h.wish.wish_id in out
    assert h.task.task_id in out


def test_resolve_requeues_exactly_one_task_and_links_it(h: Harness) -> None:
    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 0

    queued = _queued(h.db)
    assert len(queued) == 1
    new = queued[0]
    assert new.task_id != h.task.task_id
    assert new.parent_task_id == h.task.task_id, "the original attempt stays auditable"
    assert (new.kind, new.prompt, new.cell_id) == (h.task.kind, h.task.prompt, h.task.cell_id)

    resolved = h.db.get_wish(h.wish.wish_id)
    assert resolved is not None
    assert resolved.status == "provided"
    assert resolved.resolved_at
    assert resolved.requeued_task_id == new.task_id


def test_the_requeued_task_can_actually_be_leased(h: Harness) -> None:
    """Guards the borrowed origin. `TaskOrigin` is a closed literal that `Task.from_row`
    validates on every lease, so a requeue labelled with anything outside it writes a row
    that raises the moment the scheduler reaches for it. A wish resolved into a task
    nothing can run is worse than a wish left open, because it reads as done."""
    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 0

    leased = h.db.lease("r", worker="test")
    assert leased is not None
    assert leased.seed_json["wish_id"] == h.wish.wish_id, "provenance the origin cannot carry"


def test_double_resolve_is_refused(h: Harness) -> None:
    """The failure this refusal prevents is a second paid run of the same hunt."""
    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 0
    first = _queued(h.db)

    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 1

    assert [t.task_id for t in _queued(h.db)] == [t.task_id for t in first]
    resolved = h.db.get_wish(h.wish.wish_id)
    assert resolved is not None
    assert resolved.requeued_task_id == first[0].task_id


def test_dismiss_enqueues_nothing(h: Harness) -> None:
    assert cli.app(["wishlist", "dismiss", h.wish.wish_id]) == 0

    assert _queued(h.db) == []
    resolved = h.db.get_wish(h.wish.wish_id)
    assert resolved is not None
    assert resolved.status == "wontfix"
    assert resolved.requeued_task_id is None
    assert resolved.resolved_at


def test_a_dismissed_wish_cannot_be_resolved_afterwards(h: Harness) -> None:
    assert cli.app(["wishlist", "dismiss", h.wish.wish_id]) == 0
    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 1
    assert _queued(h.db) == []


@pytest.mark.parametrize("action", ["resolve", "dismiss"])
def test_unknown_wish_id_is_reported_not_raised(h: Harness, action: str) -> None:
    assert cli.app(["wishlist", action, "w_not_a_real_id"]) == 1
    assert _queued(h.db) == []


@pytest.mark.parametrize("how", ["deleted", "never_recorded"])
def test_a_wish_whose_task_is_gone_still_resolves_cleanly(h: Harness, how: str) -> None:
    """Runs get pruned and older wishes predate task_id being recorded. Refusing to close
    those would leave rows nobody can ever clear off the list."""
    if how == "deleted":
        h.db.execute("DELETE FROM tasks WHERE task_id=?", (h.task.task_id,))
    else:
        h.db.execute("UPDATE wishlist SET task_id=NULL WHERE wish_id=?", (h.wish.wish_id,))

    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 0

    assert _queued(h.db) == []
    resolved = h.db.get_wish(h.wish.wish_id)
    assert resolved is not None
    assert resolved.status == "provided"
    assert resolved.requeued_task_id is None


def test_resolving_into_a_finished_run_names_the_resume_command(
    h: Harness, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing leases a queued task once its run is closed, so a bare "re-enqueued" line
    would be a success message for work that never happens."""
    h.db.finish_run("r", "complete")

    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 0
    out = capsys.readouterr().out
    assert f"vulness run --resume {h.run_id}" in out


def test_a_running_run_gets_no_resume_advice(h: Harness, capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 0
    assert "--resume" not in capsys.readouterr().out


def test_resolving_closes_the_wish_off_the_open_list(h: Harness) -> None:
    assert [w.wish_id for w in h.db.open_wishes()] == [h.wish.wish_id]
    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 0
    assert h.db.open_wishes() == []


def test_resolution_is_written_to_the_audit_trail(h: Harness) -> None:
    assert cli.app(["wishlist", "resolve", h.wish.wish_id]) == 0

    row = h.db.one("SELECT payload_json FROM events WHERE kind='wish.resolved'")
    assert row is not None
    payload = json.loads(row["payload_json"])
    assert payload["wish_id"] == h.wish.wish_id
    assert payload["status"] == "provided"
    assert payload["requeued_task_id"] == _queued(h.db)[0].task_id
