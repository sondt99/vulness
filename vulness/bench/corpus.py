"""Labelled targets, loaded from outside the trees they describe.

A corpus is the only thing that turns run output into a measurement. Everything here is
deliberately dumb data: the harness must not be able to influence what it is scored against,
so nothing in this module reads a run, a finding, or the database.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

# How far a cited line may sit from the labelled span and still count. A hunter that points
# at the `if` guarding a sink rather than the sink has found the bug; a benchmark that says
# otherwise is measuring citation style.
LINE_TOLERANCE = 3


class Label(BaseModel):
    """One thing a run is expected to conclude about a target."""

    id: str
    kind: str = "true_positive"  # true_positive | decoy
    file: str
    line: int
    line_end: int | None = None
    cwe: str | None = None
    attack_class: str | None = None
    severity: str | None = None
    note: str = ""

    @property
    def span(self) -> tuple[int, int]:
        end = self.line_end or self.line
        return self.line - LINE_TOLERANCE, end + LINE_TOLERANCE

    def covers(self, file: str, line: int | None) -> bool:
        """Whether a citation lands on this label.

        Path only when there is no line: a finding that names the right file but no line is
        weak evidence, and treating it as a hit inflates recall. Callers decide; this
        reports the match.
        """
        if _norm(file) != _norm(self.file):
            return False
        if line is None:
            return False
        lo, hi = self.span
        return lo <= line <= hi


class Chain(BaseModel):
    id: str
    steps: list[str]
    severity: str | None = None
    terminal_impact: str = ""
    note: str = ""


class Corpus(BaseModel):
    repo: str
    path: str
    labels: list[Label] = Field(default_factory=list)
    chains: list[Chain] = Field(default_factory=list)
    # Whether every defect in this target is labelled. True for a purpose-built fixture,
    # false for a real project where one CVE is known and the rest of the code is unknown.
    # It decides the one question a scorer cannot answer on its own: is a finding that
    # matches no label a false positive, or a bug nobody wrote down?
    closed_world: bool = True

    @property
    def positives(self) -> list[Label]:
        return [x for x in self.labels if x.kind == "true_positive"]

    @property
    def decoys(self) -> list[Label]:
        return [x for x in self.labels if x.kind == "decoy"]

    def match(self, file: str, line: int | None) -> Label | None:
        """The tightest label covering a citation, positives before decoys.

        Tightest because a decoy can legitimately overlap a real defect in the same file:
        vulnshop's login bypass and its sound token MAC live in `api/auth.py` a dozen lines
        apart, and the wider span must not swallow the narrower one.
        """
        hits = [x for x in self.labels if x.covers(file, line)]
        if not hits:
            return None
        return min(hits, key=lambda x: (x.kind != "true_positive", x.span[1] - x.span[0]))


def _norm(path: str) -> str:
    return path.strip().lstrip("./").lstrip("/")


def load_corpora(directory: Path) -> dict[str, Corpus]:
    """Every corpus in a directory, keyed by repo id.

    A file may hold one corpus or a list of them. The hand-written fixture corpora are one
    file each because they are read and edited by people; an imported benchmark is a bundle,
    because SecBench.js alone is several hundred targets and that many files is a directory
    nobody can look at.
    """
    out: dict[str, Corpus] = {}
    for path in sorted(directory.glob("*.json")):
        data = json.loads(path.read_text())
        for item in data if isinstance(data, list) else [data]:
            corpus = Corpus(**item)
            out[corpus.repo] = corpus
    return out


def dump_corpora(corpora: list[Corpus], out: Path) -> int:
    """Write a bundle. Sorted and indented so a regenerated corpus diffs line by line."""
    payload = [c.model_dump(exclude_none=False) for c in sorted(corpora, key=lambda c: c.repo)]
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return len(payload)
