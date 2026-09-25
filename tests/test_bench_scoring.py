"""Scoring a run against ground truth.

`RESEARCH.md` §4: two fixtures with a handful of planted defects "cannot measure precision
or recall", and nothing in the project tried to. These tests pin down the arithmetic, and
above all the three judgement calls a scorer has to get right or it flatters whoever wrote
it: what a near-miss line is, what an unlabelled finding means, and what a decoy costs.
"""

from __future__ import annotations

import json
from pathlib import Path

from vulness.bench import Corpus, load_corpora, render_scorecard, score_repo
from vulness.bench.corpus import LINE_TOLERANCE
from vulness.state.db import Database, new_id
from vulness.state.models import Finding

GROUND_TRUTH = Path(__file__).resolve().parent / "ground_truth"


def _corpus(**kw) -> Corpus:
    base = {
        "repo": "target",
        "path": "tests/fixtures/vulnshop",
        "labels": [
            {
                "id": "sqli",
                "kind": "true_positive",
                "file": "api/reports.py",
                "line": 20,
                "line_end": 21,
                "cwe": "CWE-89",
                "note": "n",
            },
            {
                "id": "decoy-mac",
                "kind": "decoy",
                "file": "api/auth.py",
                "line": 9,
                "line_end": 24,
                "note": "n",
            },
        ],
        "chains": [],
    }
    base.update(kw)
    return Corpus(**base)


def _file(db: Database, file: str, line: int, *, verdict: str = "confirmed", title: str = "") -> Finding:
    f = Finding(
        finding_id=new_id("f"),
        run_id="r",
        repo_id="target",
        task_id="t0",
        fingerprint=new_id("fp"),
        title=title or f"finding at {file}:{line} with a long enough title",
        trace_json=[{"kind": "sink", "file": file, "line": line}],
    )
    db.file_finding(f)
    db.set_verdict(f.finding_id, verdict)
    db.execute("INSERT OR IGNORE INTO tasks(task_id, run_id, repo_id, stage, kind, status, prompt)"
               " VALUES (?,?,?,?,?,?,?)", (new_id("t"), "r", "target", "hunt", "hunt", "done", ""))
    return f


# ------------------------------------------------------------------ matching


def test_a_finding_on_the_labelled_line_is_a_hit(db: Database) -> None:
    _file(db, "api/reports.py", 20)
    s = score_repo(db, "r", _corpus())
    assert s.tiers["confirmed"].recall == 1.0
    assert s.tiers["confirmed"].precision == 1.0


def test_a_near_miss_inside_the_tolerance_still_counts(db: Database) -> None:
    """A hunter that cites the line above the sink has found the bug. Scoring that as a
    miss measures citation style, not detection."""
    _file(db, "api/reports.py", 20 + LINE_TOLERANCE)
    assert score_repo(db, "r", _corpus()).tiers["confirmed"].recall == 1.0


def test_a_finding_far_from_any_label_is_not_a_hit(db: Database) -> None:
    _file(db, "api/reports.py", 20 + LINE_TOLERANCE + 5)
    tier = score_repo(db, "r", _corpus()).tiers["confirmed"]
    assert tier.recall == 0.0
    assert len(tier.unlabelled) == 1


def test_the_right_file_with_no_line_is_not_a_hit(db: Database) -> None:
    """Weak evidence must not inflate recall."""
    f = Finding(
        finding_id=new_id("f"), run_id="r", repo_id="target", task_id="t0",
        fingerprint="fp1", title="a finding with no line number at all",
        trace_json=[{"kind": "sink", "file": "api/reports.py"}],
    )
    db.file_finding(f)
    db.set_verdict(f.finding_id, "confirmed")
    assert score_repo(db, "r", _corpus()).tiers["confirmed"].recall == 0.0


def test_a_decoy_hit_is_a_false_positive_not_a_miss(db: Database) -> None:
    _file(db, "api/auth.py", 22)
    tier = score_repo(db, "r", _corpus()).tiers["confirmed"]
    assert len(tier.decoys) == 1
    assert tier.precision == 0.0
    assert tier.recall == 0.0


def test_a_positive_label_wins_a_tie_with_an_overlapping_decoy() -> None:
    """vulnshop's login bypass and its sound token MAC sit a dozen lines apart in one file.
    The wider decoy span must not swallow the narrower real defect."""
    corpus = _corpus(labels=[
        {"id": "wide-decoy", "kind": "decoy", "file": "a.py", "line": 1, "line_end": 40, "note": "n"},
        {"id": "real", "kind": "true_positive", "file": "a.py", "line": 20, "note": "n"},
    ])
    assert corpus.match("a.py", 20).id == "real"
    assert corpus.match("a.py", 2).id == "wide-decoy"


def test_a_label_is_only_counted_once_however_many_findings_hit_it(db: Database) -> None:
    """Recall is over defects, precision over findings. Three reports of one bug is one
    bug found and three chances to be wrong."""
    for _ in range(3):
        _file(db, "api/reports.py", 20)
    tier = score_repo(db, "r", _corpus()).tiers["confirmed"]
    assert tier.recall == 1.0
    assert len(tier.hits) == 3


def test_duplicates_are_not_scored(db: Database) -> None:
    """Counting a finding that dedup folded away would make deduplication look like a
    precision loss."""
    _file(db, "api/reports.py", 20)
    _file(db, "api/reports.py", 20, verdict="duplicate")
    assert len(score_repo(db, "r", _corpus()).tiers["raw"].hits) == 1


def test_a_trace_matching_at_the_entrypoint_still_counts(db: Database) -> None:
    """The label sits on one end of a trace the hunter walked correctly."""
    f = Finding(
        finding_id=new_id("f"), run_id="r", repo_id="target", task_id="t0",
        fingerprint="fp2", title="traced from the route into the query",
        trace_json=[
            {"kind": "entrypoint", "file": "api/reports.py", "line": 20},
            {"kind": "sink", "file": "db/other.py", "line": 400},
        ],
    )
    db.file_finding(f)
    db.set_verdict(f.finding_id, "confirmed")
    assert score_repo(db, "r", _corpus()).tiers["confirmed"].recall == 1.0


# ------------------------------------------------------------ world and tiers


def test_closed_world_counts_an_unlabelled_finding_against_precision(db: Database) -> None:
    _file(db, "api/reports.py", 20)
    _file(db, "somewhere/else.py", 5)
    tier = score_repo(db, "r", _corpus()).tiers["confirmed"]
    assert tier.scored == 2
    assert tier.precision == 0.5


def test_open_world_leaves_an_unlabelled_finding_out_of_the_denominator(db: Database) -> None:
    """On a real project with one known CVE, a finding nobody labelled may be a real bug.
    Scoring it as wrong would punish the harness for working."""
    _file(db, "api/reports.py", 20)
    _file(db, "somewhere/else.py", 5)
    s = score_repo(db, "r", _corpus(closed_world=False))
    tier = s.tiers["confirmed"]
    assert tier.scored == 1
    assert tier.precision == 1.0
    assert len(tier.unlabelled) == 1


def test_tiers_widen_by_verdict(db: Database) -> None:
    """The evidence ceiling holds findings at needs_validation, so precision at `confirmed`
    alone would report an empty run as a perfect one."""
    _file(db, "api/reports.py", 20, verdict="needs_validation")
    s = score_repo(db, "r", _corpus())
    assert s.tiers["confirmed"].recall == 0.0
    assert s.tiers["reported"].recall == 1.0
    assert s.tiers["raw"].recall == 1.0


def test_missed_lists_what_nothing_reached(db: Database) -> None:
    s = score_repo(db, "r", _corpus())
    assert [x.id for x in s.missed] == ["sqli"]


# ----------------------------------------------------------------- the chain


def test_a_chain_scores_only_when_every_step_is_covered(db: Database) -> None:
    corpus = _corpus(
        labels=[
            {"id": "leak", "kind": "true_positive", "file": "app/profile.py", "line": 26, "note": "n"},
            {"id": "exec", "kind": "true_positive", "file": "app/admin.py", "line": 26, "note": "n"},
        ],
        chains=[{"id": "login-to-rce", "steps": ["leak", "exec"], "note": "n"}],
    )
    a = _file(db, "app/profile.py", 26)
    b = _file(db, "app/admin.py", 26)

    assert score_repo(db, "r", corpus).chains[0].found is False, "no chain filed yet"

    db.execute(
        "INSERT INTO chains(chain_id, run_id, repo_id, title, narrative, steps_json,"
        " severity, verdict, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        ("c1", "r", "target", "login to rce", "n", json.dumps([a.finding_id, b.finding_id]),
         "critical", "confirmed", "2026-01-01"),
    )
    scored = score_repo(db, "r", corpus).chains[0]
    assert scored.found and scored.matched_by == "c1"


def test_a_chain_missing_a_step_does_not_score(db: Database) -> None:
    corpus = _corpus(
        labels=[
            {"id": "leak", "kind": "true_positive", "file": "app/profile.py", "line": 26, "note": "n"},
            {"id": "exec", "kind": "true_positive", "file": "app/admin.py", "line": 26, "note": "n"},
        ],
        chains=[{"id": "login-to-rce", "steps": ["leak", "exec"], "note": "n"}],
    )
    a = _file(db, "app/profile.py", 26)
    db.execute(
        "INSERT INTO chains(chain_id, run_id, repo_id, title, narrative, steps_json,"
        " severity, verdict, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        ("c1", "r", "target", "half a chain", "n", json.dumps([a.finding_id]),
         "medium", "confirmed", "2026-01-01"),
    )
    assert score_repo(db, "r", corpus).chains[0].found is False


# ------------------------------------------------------------ the real corpus


def test_the_shipped_corpora_load_and_describe_the_fixtures() -> None:
    corpora = load_corpora(GROUND_TRUTH)
    assert set(corpora) == {"vulnshop", "chainshop", "vulnshop-client"}
    assert len(corpora["vulnshop"].positives) == 3
    assert len(corpora["vulnshop"].decoys) == 1
    assert corpora["chainshop"].chains[0].steps == [
        "chainshop-key-disclosure",
        "chainshop-authorised-command-exec",
    ]


def test_an_empty_run_scores_zero_rather_than_crashing(db: Database) -> None:
    db.execute("INSERT INTO tasks(task_id, run_id, repo_id, stage, kind, status, prompt)"
               " VALUES (?,?,?,?,?,?,?)", ("t1", "r", "target", "hunt", "hunt", "done", ""))
    s = score_repo(db, "r", _corpus())
    assert s.tiers["raw"].recall == 0.0
    assert s.tiers["raw"].precision is None, "no findings means precision is undefined, not zero"
    assert "Missed entirely" in render_scorecard([s])


def test_the_scorecard_renders_every_tier(db: Database) -> None:
    _file(db, "api/reports.py", 20)
    _file(db, "api/auth.py", 22)
    text = render_scorecard([score_repo(db, "r", _corpus())])
    for tier in ("confirmed", "reported", "raw"):
        assert tier in text
    assert "decoy-mac" in text
