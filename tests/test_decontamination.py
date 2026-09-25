"""The calibration targets must not contain their own answer key.

A hunter runs with `cwd` set to the target repository and Read, Grep and Glob in its tool
allowlist. Everything inside that directory is readable by the model being measured. The
fixtures used to ship a README at their root with a ground-truth table naming the file and
line of every planted defect, its severity, and which function was a decoy that must produce
no finding. `api/auth.py` announced itself as a decoy in its own module docstring.

Nothing excluded any of it: `_UNINTERESTING_SUFFIXES` in `coverage/scope.py` drops `.md`
from the changed-file list of a `--since` run, which has no bearing on what a tool may open.

So "a healthy run finds 1, 2 and 3 and says nothing about 4" measured nothing. These tests
keep the separation that makes it a measurement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GROUND_TRUTH = ROOT / "tests" / "ground_truth"
FIXTURES = ROOT / "tests" / "fixtures"

# Phrases that grade the code they sit next to. A real repository does not tell a reader
# which of its lines are safe, and neither may a target that is standing in for one.
_TELLS = (
    "decoy",
    "false positive",
    "not vulnerable",
    "is actually fine",
    "planted",
    "ground-truth",
    "answer key",
    "true positive",
)


def _corpora() -> list[dict]:
    return [json.loads(p.read_text()) for p in sorted(GROUND_TRUTH.glob("*.json"))]


def _fixture_files() -> list[Path]:
    return [
        p
        for p in FIXTURES.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"
    ]


def test_ground_truth_lives_outside_every_target_tree() -> None:
    for corpus in _corpora():
        target = (ROOT / corpus["path"]).resolve()
        assert GROUND_TRUTH.resolve().relative_to(ROOT) not in target.parents
        assert not str(GROUND_TRUTH.resolve()).startswith(str(target) + "/")


def test_no_label_text_appears_inside_any_fixture() -> None:
    """The decisive check: a note or a label id turning up in the tree means the answer key
    has leaked back in."""
    needles: list[str] = []
    for corpus in _corpora():
        for label in corpus["labels"]:
            needles.append(label["id"])
            needles.append(label["note"])
            if label.get("cwe"):
                needles.append(label["cwe"])
        for chain in corpus["chains"]:
            needles.append(chain["id"])
            needles.append(chain["note"])

    leaked: list[str] = []
    for path in _fixture_files():
        text = path.read_text(errors="replace")
        leaked += [
            f"{path.relative_to(ROOT)}: {n[:60]!r}" for n in needles if n and n in text
        ]
    assert not leaked, "ground truth leaked into the audited tree:\n" + "\n".join(leaked)


def test_no_fixture_file_grades_its_own_code() -> None:
    leaked: list[str] = []
    for path in _fixture_files():
        low = path.read_text(errors="replace").lower()
        leaked += [f"{path.relative_to(ROOT)}: {tell!r}" for tell in _TELLS if tell in low]
    assert not leaked, "a fixture tells the model how to grade it:\n" + "\n".join(leaked)


@pytest.mark.parametrize("corpus", _corpora(), ids=lambda c: c["repo"])
def test_every_label_still_points_at_real_code(corpus: dict) -> None:
    """Labels rot silently when a fixture is edited. A benchmark whose ground truth has
    drifted off the line it describes reports a miss and blames the harness."""
    target = ROOT / corpus["path"]
    for label in corpus["labels"]:
        path = target / label["file"]
        assert path.exists(), f"{label['id']} points at a missing file"
        lines = path.read_text().splitlines()
        assert 1 <= label["line"] <= len(lines), f"{label['id']} line out of range"
        end = label.get("line_end", label["line"])
        assert label["line"] <= end <= len(lines), f"{label['id']} line_end out of range"


@pytest.mark.parametrize("corpus", _corpora(), ids=lambda c: c["repo"])
def test_chain_steps_resolve_to_labels(corpus: dict) -> None:
    ids = {label["id"] for label in corpus["labels"]}
    for chain in corpus["chains"]:
        assert len(chain["steps"]) >= 2, "a chain of one is a finding"
        for step in chain["steps"]:
            assert step in ids, f"{chain['id']} references unknown label {step}"


def test_every_fixture_has_a_corpus() -> None:
    """A target with no ground truth cannot be scored, so it must not be quietly added."""
    described = {(ROOT / c["path"]).name for c in _corpora()}
    on_disk = {p.name for p in FIXTURES.iterdir() if p.is_dir() and p.name != "__pycache__"}
    assert on_disk == described, f"undescribed fixtures: {sorted(on_disk - described)}"
