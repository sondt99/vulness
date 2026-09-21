"""Scaling behaviour.

Every constant here was set by measuring a real run and finding the default absurd, not by
picking a round number.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sness.coverage.cells import MAX_CELLS, MIN_CELLS, Area, build_grid, grid_size_for
from sness.orchestrator.budget import Budget
from sness.orchestrator.scheduler import FORK_SHARE_CAP, MAX_FORKS_PER_HUNT, Scheduler
from sness.state.db import Database, new_id
from sness.state.models import Run, Task


def test_grid_scales_with_target_size() -> None:
    """Regression: a flat cap of 80 gave a 102-line fixture the same grid as a large
    service. Six of those 80 cells were ever reached."""
    tiny = grid_size_for(3)
    mid = grid_size_for(120)
    large = grid_size_for(600)
    assert tiny == MIN_CELLS
    assert tiny < mid < large <= MAX_CELLS


def test_grid_growth_is_sublinear() -> None:
    """Areas grow far more slowly than files. Linear growth produced 144 cells for a
    120-file project, which is a budget nobody would choose to spend."""
    assert grid_size_for(1200) < 10 * grid_size_for(120)


def test_grid_is_bounded_at_both_ends() -> None:
    assert grid_size_for(0) == MIN_CELLS
    assert grid_size_for(10_000_000) == MAX_CELLS


def test_build_grid_respects_the_derived_size() -> None:
    areas = [Area(name=f"a{i}", paths=[f"a{i}"], files=2, langs={".py": 2}) for i in range(6)]
    cells = build_grid("r", "repo", areas)
    assert len(cells) <= grid_size_for(sum(a.files for a in areas))


def test_fork_share_cap_matches_the_published_range() -> None:
    """Cloudflare measures ~9% of fleet tasks, up to about a fifth by model. Uncapped,
    this harness reached 33%: a third of the run chasing tangents while planned cells
    went unhunted."""
    assert 0.05 <= FORK_SHARE_CAP <= 0.20
    assert MAX_FORKS_PER_HUNT <= 4


@pytest.mark.parametrize(
    ("forks", "total", "expect_allowed"),
    [(0, 10, True), (1, 100, True), (30, 100, False), (20, 100, False)],
)
def test_fork_allowance_closes_once_forks_take_their_share(
    forks: int, total: int, expect_allowed: bool
) -> None:
    db = Database(Path(tempfile.mkdtemp()) / "t.db")
    db.create_run(Run(run_id="r", model_hunt="m", model_verify="n"))
    db.upsert_repo("repo", name="repo", path="/tmp")
    for i in range(total):
        db.enqueue(
            Task(
                task_id=new_id("t"), run_id="r", repo_id="repo", stage="hunt", kind="hunt",
                prompt="x", origin="sibling_fork" if i < forks else "seed",
            )
        )
    sched = Scheduler.__new__(Scheduler)
    sched.db = db
    sched.run_id = "r"
    assert (sched._fork_allowance() > 0) is expect_allowed


def test_triage_is_exempt_from_the_hunt_budget() -> None:
    """Regression: 102 of 132 tasks were budget-abandoned during discovery and triage
    never ran, so confirmed findings were never judged."""
    db = Database(Path(tempfile.mkdtemp()) / "t.db")
    db.create_run(Run(run_id="r", model_hunt="m", model_verify="n"))
    db.upsert_repo("repo", name="repo", path="/tmp")
    b = Budget(db, "r", per_repo=0, validator_reserve=0.3)  # budget fully spent
    assert not b.can_dispatch("repo", "hunt").allowed
    for kind in ("validate", "judge", "dedup", "fix", "trace", "feedback"):
        assert b.can_dispatch("repo", kind).allowed, f"{kind} must survive budget exhaustion"
