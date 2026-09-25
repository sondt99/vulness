"""Score a run against a labelled corpus.

`RESEARCH.md` §4 named the gap this closes: two fixtures with a handful of planted defects
"cannot measure precision or recall", and the harness had no code that tried. Every number
the project could previously quote about itself was a count of what it did, never a
proportion of what was there to find.

Three properties this deliberately has:

- **Thresholds, not a number.** Precision at `confirmed` alone says nothing useful while the
  evidence ceiling is holding findings at `needs_validation`. The scorer reports every tier
  so the validator's effect on the funnel is visible rather than hidden inside one ratio.
- **Closed world is a corpus property, not an assumption.** On a purpose-built fixture a
  finding matching no label is a false positive. On a real project with one known CVE it is
  an unknown, and counting it as a miss would punish a harness for finding a real bug.
- **No model anywhere.** Matching is file and line arithmetic. A scorer that asks a model
  whether a finding matches a label has the grading problem the harness itself is about.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from vulness.bench.corpus import Corpus, Label
from vulness.state.db import Database
from vulness.state.models import Finding

# Reported verdicts, widening. `duplicate` is never scored: it was folded into another
# finding, and counting both would make deduplication look like a precision loss.
TIERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("confirmed", ("confirmed",)),
    ("reported", ("confirmed", "needs_validation")),
    ("raw", ("confirmed", "needs_validation", "candidate", "rejected")),
)


@dataclass
class Match:
    finding_id: str
    title: str
    verdict: str
    file: str
    line: int | None
    label: Label | None
    outcome: str  # hit | decoy | unlabelled


@dataclass
class Tier:
    name: str
    closed_world: bool
    positives: int
    hits: list[Match] = field(default_factory=list)
    decoys: list[Match] = field(default_factory=list)
    unlabelled: list[Match] = field(default_factory=list)

    @property
    def found(self) -> set[str]:
        return {m.label.id for m in self.hits if m.label}

    @property
    def scored(self) -> int:
        """Findings in the precision denominator.

        In an open world an unlabelled finding is not evidence either way, so it leaves the
        denominator entirely and is reported on its own line. Folding it in would have a
        harness that found a genuine unlabelled bug score worse than one that found nothing.
        """
        n = len(self.hits) + len(self.decoys)
        return n + len(self.unlabelled) if self.closed_world else n

    @property
    def precision(self) -> float | None:
        return len(self.hits) / self.scored if self.scored else None

    @property
    def recall(self) -> float | None:
        return len(self.found) / self.positives if self.positives else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p and r else None


@dataclass
class ChainScore:
    chain_id: str
    found: bool
    matched_by: str | None = None


@dataclass
class RepoScore:
    repo: str
    corpus: Corpus
    tiers: dict[str, Tier]
    chains: list[ChainScore] = field(default_factory=list)

    @property
    def missed(self) -> list[Label]:
        """Labelled defects no finding reached at the widest tier: the true blind spots."""
        seen = self.tiers[TIERS[-1][0]].found
        return [x for x in self.corpus.positives if x.id not in seen]


def _citations(finding: Finding) -> list[tuple[str, int | None]]:
    """Every location a finding points at, sink first.

    Sink first because that is the bug's home and the label is anchored there. The rest are
    tried before declaring a miss: a hunter whose trace runs entrypoint to sink has found
    the defect even when the label sits on the other end of its own trace.
    """
    sinks: list[tuple[str, int | None]] = []
    rest: list[tuple[str, int | None]] = []
    for step in finding.trace_json or []:
        if not isinstance(step, dict) or not step.get("file"):
            continue
        line = step.get("line")
        pair = (str(step["file"]), int(line) if line else None)
        (sinks if step.get("kind") == "sink" else rest).append(pair)
    for item in (finding.evidence_json or {}).get("items") or []:
        if isinstance(item, dict) and item.get("file"):
            line = item.get("line")
            rest.append((str(item["file"]), int(line) if line else None))
    return sinks + rest


def _classify(finding: Finding, corpus: Corpus) -> Match:
    cites = _citations(finding)
    for file, line in cites:
        label = corpus.match(file, line)
        if label is not None:
            return Match(
                finding_id=finding.finding_id,
                title=finding.title,
                verdict=finding.verdict,
                file=file,
                line=line,
                label=label,
                outcome="hit" if label.kind == "true_positive" else "decoy",
            )
    file, line = cites[0] if cites else ("", None)
    return Match(
        finding_id=finding.finding_id,
        title=finding.title,
        verdict=finding.verdict,
        file=file,
        line=line,
        label=None,
        outcome="unlabelled",
    )


def score_repo(db: Database, run_id: str, corpus: Corpus) -> RepoScore:
    findings = [
        f for f in db.findings(run_id, repo_id=corpus.repo) if f.verdict != "duplicate"
    ]
    matches = [(f, _classify(f, corpus)) for f in findings]

    tiers: dict[str, Tier] = {}
    for name, verdicts in TIERS:
        tier = Tier(name=name, closed_world=corpus.closed_world, positives=len(corpus.positives))
        for finding, match in matches:
            if finding.verdict not in verdicts:
                continue
            getattr(tier, {"hit": "hits", "decoy": "decoys", "unlabelled": "unlabelled"}[match.outcome]).append(match)
        tiers[name] = tier

    by_id = {f.finding_id: m for f, m in matches}
    chains = []
    for want in corpus.chains:
        hit = None
        for produced in db.chains(run_id=run_id, repo_id=corpus.repo):
            covered: set[str] = set()
            for step in produced.get("steps") or []:
                match = by_id.get(step)
                if match and match.label:
                    covered.add(match.label.id)
            if set(want.steps) <= covered:
                hit = produced["chain_id"]
                break
        chains.append(ChainScore(chain_id=want.id, found=hit is not None, matched_by=hit))

    return RepoScore(repo=corpus.repo, corpus=corpus, tiers=tiers, chains=chains)


def score_run(db: Database, run_id: str, corpora: dict[str, Corpus]) -> list[RepoScore]:
    """Only repositories the run actually touched, so an unused corpus is not a zero."""
    touched = {r["repo_id"] for r in db.query("SELECT DISTINCT repo_id FROM tasks WHERE run_id=?", (run_id,))}
    return [score_repo(db, run_id, c) for repo, c in corpora.items() if repo in touched]
