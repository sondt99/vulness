"""Cross-run memory: what makes run 20 better than run 1 rather than a repeat of it.

Everything else in the harness is keyed by run_id, which is correct for a single audit and
wrong for a repository you come back to. These three behaviours are what change that.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from vulness.coverage.cells import thin_cells
from vulness.findings import HunterFinding, compute_fingerprint
from vulness.state.db import Database, new_id
from vulness.state.models import Cell, Finding, Run, now


@pytest.fixture
def db() -> Database:
    d = Database(Path(tempfile.mkdtemp()) / "t.db")
    d.create_run(Run(run_id="r1", model_hunt="m", model_verify="n"))
    d.create_run(Run(run_id="r2", model_hunt="m", model_verify="n"))
    d.upsert_repo("repo", name="repo", path="/tmp", head_sha="sha1")
    return d


# ---------------- the map ----------------


def test_map_is_reused_for_the_same_commit(db: Database) -> None:
    """Three reconnaissance passes over a large repository is the second most expensive
    thing the harness does, and the answer does not change until the code does."""
    db.save_map("repo", "sha1", "r1", architecture="A" * 40, areas=[{"name": "api"}], classes=[])
    got = db.prior_map("repo", "sha1")
    assert got and got["from_run"] == "r1"
    assert got["areas"] == [{"name": "api"}]


def test_map_is_not_reused_after_the_code_changes(db: Database) -> None:
    """A map of code that has since changed is worse than no map: a hunter trusts it and
    looks in the wrong place."""
    db.save_map("repo", "sha1", "r1", architecture="A", areas=[], classes=[])
    assert db.prior_map("repo", "sha2") is None


def test_map_lookup_tolerates_a_repo_with_no_git(db: Database) -> None:
    assert db.prior_map("repo", None) is None


# ---------------- findings ----------------


def _file(db: Database, run_id: str, fingerprint: str, verdict: str = "confirmed") -> Finding:
    return db.file_finding(
        Finding(
            finding_id=new_id("f"), run_id=run_id, repo_id="repo", task_id="t",
            fingerprint=fingerprint, title="A specific and repeatable title",
            threat_model_json={"attacker": "a", "boundary": "b", "broken_assumption": "c"},
            verdict=verdict, created_at=now(),
        )
    )


def test_a_later_run_recognises_a_bug_an_earlier_run_filed(db: Database) -> None:
    """The stable fingerprint existed for this from the start; the lookup was scoped to a
    single run, so re-running a repository re-filed everything under fresh ids."""
    first = _file(db, "r1", "fp_abc")
    found = db.find_prior_finding("repo", "fp_abc", exclude_run="r2")
    assert found and found.finding_id == first.finding_id


def test_prior_lookup_excludes_the_current_run(db: Database) -> None:
    """Same-run duplicates are a different mechanism; this one must only see history."""
    _file(db, "r2", "fp_only_now")
    assert db.find_prior_finding("repo", "fp_only_now", exclude_run="r2") is None


def test_prior_lookup_is_scoped_to_the_repository(db: Database) -> None:
    _file(db, "r1", "fp_abc")
    assert db.find_prior_finding("other-repo", "fp_abc") is None


def test_fingerprint_survives_a_rerun_of_the_same_bug() -> None:
    """Cross-run recognition is only as good as the key it is built on."""
    raw = dict(
        title="Unauthenticated SQL injection in the export handler",
        threat_model={"attacker": "remote client", "boundary": "HTTP to SQL", "broken_assumption": "id is numeric"},
        trace=[{"kind": "sink", "file": "api/reports.py", "line": 20, "scope": "export"}],
        evidence=[{"file": "api/reports.py", "line": 20, "description": "interpolation"}],
        attack_class="injection",
    )
    # Same bug, different run, line drifted because someone added imports above it.
    moved = {**raw, "trace": [{"kind": "sink", "file": "api/reports.py", "line": 38, "scope": "export"}]}
    assert compute_fingerprint(HunterFinding(**raw), "repo") == compute_fingerprint(
        HunterFinding(**moved), "repo"  # type: ignore[arg-type]
    )


# ---------------- coverage ----------------


def test_coverage_accumulates_across_runs(db: Database) -> None:
    db.record_coverage("repo", "api::injection", head_sha="sha1", run_id="r1", findings=2)
    db.record_coverage("repo", "api::injection", head_sha="sha1", run_id="r2", findings=1)
    cov = db.prior_coverage("repo")["api::injection"]
    assert cov["hunts"] == 2 and cov["findings"] == 3


def test_gapfill_prefers_cells_nobody_has_ever_hunted() -> None:
    """Without history every run rediscovers the same gaps in the same order, and the
    twentieth run explores exactly what the first one did."""
    cells = [
        Cell(run_id="r", repo_id="repo", cell_id=f"c{i}", area="a", attack_class="x")
        for i in range(4)
    ]
    order = [c.cell_id for c in thin_cells(cells, prior={"c0": {"hunts": 5}, "c1": {"hunts": 1}})]
    assert order[:2] == ["c2", "c3"], order
    assert order.index("c1") < order.index("c0"), "least-hunted first among the seen"
