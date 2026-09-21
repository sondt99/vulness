"""VVS dedup: deterministic candidate clusters first, a model only for the hard call.

    Deterministic inverted indexes on files/functions/trust-boundaries/rare tokens generate
    a candidate list, then an agent judges whether findings collapse onto one fix.
        -- Cloudflare, "Build your own vulnerability harness"

The split is the whole design. Similarity is cheap and mechanical: two findings that share a
sink file, an enclosing scope, a trust boundary or an unusual word are *candidates*, and
plain Python can say so for free across the whole run. Whether they collapse onto **one
fix** is a judgement about root cause that no index can make -- so that, and only that, costs
a GLM call. If no cluster has more than one member, this stage never calls a model at all.

This is the second of two dedup passes, and the harder one. `hunter.py` already collapses
two findings whose sink is the same file and line, at file time, for nothing
(`db.find_by_sink`). What survives that is the expensive case: **one root cause reached
through different sinks** -- a missing authorisation check that shows up in three handlers,
a validator that three call sites each fail to apply. Those share no line number, so only the
boundary/entrypoint/rare-token indexes and a model reading the pair will ever connect them.

Two decisions are deliberately kept away from the model:

* **Which member survives.** The canonical is the highest-severity, best-evidenced record,
  chosen by `_rank` -- not by whichever id the model happened to list first.
* **Which ids are real.** Only ids present in the cluster it was shown are accepted. A
  hallucinated id would otherwise mark an unrelated finding as a duplicate of nothing, and
  duplicates disappear from the report.

Collapses are durable, and a collapsed finding is no longer clusterable, so a retry after a
mid-stage failure resumes rather than repeats.
"""

from __future__ import annotations

import re
import time
from collections import Counter, defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import combinations

from vulness.agents.context_budget import ContextBudget, Section
from vulness.agents.roles.context import RoleContext, TaskOutcome
from vulness.prompts import preamble, render
from vulness.state.db import new_id
from vulness.state.models import Finding, Task, Validation

# Rejected findings are not worth merging, and a duplicate has already collapsed. Excluding
# them is what makes a retry resume instead of re-proposing the same merges.
_NOT_CLUSTERABLE = frozenset({"rejected", "duplicate"})

_SEVERITY_RANK: dict[str, int] = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}

# How much each shared index term argues that two findings are one bug. An identical
# fingerprint is root-cause identity by construction (see findings/fingerprint.py) and clears
# the threshold alone; attack class alone is nearly meaningless and never does.
_WEIGHTS: dict[str, int] = {
    "fingerprint": 5,
    "scope": 3,
    "sink_file": 2,
    "entrypoint": 2,
    "boundary": 1,
    "attack_class": 1,
    "token": 1,
}
# Only rare tokens accumulate; everything else counts once however many times it matches.
_CAPS: dict[str, int] = {"token": 3}
_EDGE_SCORE = 3

# Families exempt from the "a term half the run shares is not discriminating" rule. A
# fingerprint is identity, not similarity: twenty findings carrying one is twenty views of
# one defect, and suppressing that bucket would hide the very case it exists to catch.
_UNCAPPED = frozenset({"fingerprint"})

# A cluster is a prompt. Eight findings is already a long one, and a model shown thirty
# records will agree that they are all related -- agreeableness scales with list length.
# Oversized components are sliced by rank, which is a real limitation: a weak duplicate of a
# strong finding can land in a different slice and survive. Better than one unreadable call.
_MAX_CLUSTER = 8
_MAX_CLUSTER_CHARS = 18_000
_MEMBER_CHARS = 1_400

_TOKEN = re.compile(r"[a-z0-9]+")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")

# Connective tissue plus the words every security title contains. A token shared by two
# findings is only evidence if it is a word that had no reason to appear twice.
_STOPWORDS = frozenset(
    {
        "the",
        "a",
        "an",
        "and",
        "or",
        "of",
        "to",
        "in",
        "on",
        "for",
        "via",
        "with",
        "by",
        "at",
        "is",
        "are",
        "from",
        "into",
        "not",
        "no",
        "any",
        "all",
        "can",
        "may",
        "when",
        "allows",
        "allowing",
        "without",
        "missing",
        "unvalidated",
        "unsanitized",
        "arbitrary",
        "user",
        "users",
        "input",
        "data",
        "value",
        "values",
        "request",
        "response",
        "error",
        "vulnerability",
        "vulnerable",
        "issue",
        "bug",
        "flaw",
        "attack",
        "attacker",
        "remote",
        "code",
        "file",
        "files",
        "path",
        "paths",
        "check",
        "checks",
        "validation",
        "handler",
        "function",
        "method",
        "class",
        "module",
        "api",
        "endpoint",
        "leads",
        "leading",
        "results",
        "resulting",
        "due",
        "lack",
        "improper",
        "insecure",
        "unsafe",
    }
)


@dataclass(frozen=True)
class Cluster:
    """A candidate group the indexes produced, plus why they were grouped.

    Membership is a hint for the model. `canonical` is not: it is decided here, so that a
    merge can never demote the better-evidenced record to a footnote.
    """

    members: tuple[Finding, ...]
    signals: tuple[str, ...]

    @property
    def canonical(self) -> Finding:
        return min(self.members, key=_rank)

    def by_id(self) -> dict[str, Finding]:
        return {f.finding_id: f for f in self.members}


def _rank(f: Finding) -> tuple[int, int, int, str, str]:
    """Sort key for `min`: the strongest record first.

    Severity, then how much evidence carries it, then how completely the path is traced.
    Creation order breaks ties so the choice is stable across runs and across processes --
    a canonical that moves between passes produces a different report from the same data.
    """
    evidence = (f.evidence_json or {}).get("items")
    return (
        -_SEVERITY_RANK.get(str(f.severity_json.get("overall_severity", "")).lower(), 0),
        -(len(evidence) if isinstance(evidence, list) else 0),
        -len(f.trace_json or []),
        f.created_at,
        f.finding_id,
    )


def _norm(text: str) -> str:
    return _NON_ALNUM.sub("-", (text or "").strip().lower()).strip("-")


def _rare_cutoff(n: int) -> int:
    """Document frequency at which a title token stops being distinctive.

    Flat 2 for small runs -- in a corpus of five, a word in two findings is notable. It grows
    slowly and stops at 4: in a run of eighty findings, a word appearing in eight is a house
    term, not a coincidence.
    """
    return max(2, min(4, n // 10))


def _terms(f: Finding) -> dict[str, set[str]]:
    """Index terms for one finding, by family.

    `sink_file` and `scope` are `findings.fingerprint.dedup_key` inverted; that helper is not
    called directly because it takes a `HunterFinding` and this stage works from stored rows.
    """
    out: dict[str, set[str]] = {family: set() for family in _WEIGHTS}
    out["fingerprint"].add(f.fingerprint)
    if f.attack_class:
        out["attack_class"].add(_norm(f.attack_class))

    steps = [s for s in (f.trace_json or []) if isinstance(s, dict)]
    for step in steps:
        file = _norm(str(step.get("file", "")).lstrip("/"))
        if not file:
            continue
        kind = str(step.get("kind", ""))
        scope = _norm(str(step.get("scope", "")))
        if kind == "sink":
            out["sink_file"].add(file)
            if scope:
                # Scoped to the file: a bare `__init__` or `handle` matching across unrelated
                # modules is a naming convention, not a shared root cause.
                out["scope"].add(f"{file}::{scope}")
        elif kind == "entrypoint":
            out["entrypoint"].add(file)
    if not out["sink_file"] and steps:
        out["sink_file"].add(_norm(str(steps[0].get("file", "")).lstrip("/")))

    boundary = _norm(str((f.threat_model_json or {}).get("boundary", "")))[:80]
    if boundary:
        out["boundary"].add(boundary)

    out["token"] = {
        tok
        for tok in _TOKEN.findall((f.title or "").lower())
        if len(tok) > 3 and tok not in _STOPWORDS
    }
    return out


def build_clusters(findings: Sequence[Finding]) -> list[Cluster]:
    """Deterministic candidate clusters. Pure function: no model, no network, no database.

    Inverted indexes over each family produce co-occurrence; co-occurrence is weighted into a
    pair score; pairs above the threshold become edges; connected components become clusters.
    Only components with more than one member come back, so an empty result means the model
    is never called.
    """
    eligible = [f for f in findings if f.verdict not in _NOT_CLUSTERABLE]
    if len(eligible) < 2:
        return []

    terms = [_terms(f) for f in eligible]
    df = Counter(tok for t in terms for tok in t["token"])
    cutoff = _rare_cutoff(len(eligible))
    for t in terms:
        t["token"] = {tok for tok in t["token"] if df[tok] <= cutoff}

    index: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, t in enumerate(terms):
        for family, values in t.items():
            for value in values:
                if value:
                    index[(family, value)].append(i)

    # A term half the run shares is not evidence of anything; it would fuse the whole corpus
    # into one component and hand the model an unanswerable question.
    bucket_cap = max(3, len(eligible) // 2)
    hits: dict[tuple[int, int], Counter] = defaultdict(Counter)
    labels: dict[tuple[int, int], set[str]] = defaultdict(set)
    for (family, value), members in index.items():
        if len(members) < 2 or (len(members) > bucket_cap and family not in _UNCAPPED):
            continue
        for a, b in combinations(sorted(members), 2):
            hits[(a, b)][family] += 1
            labels[(a, b)].add(f"{family}:{value}"[:100])

    adjacency: dict[int, set[int]] = defaultdict(set)
    edges: dict[tuple[int, int], int] = {}
    for pair, families in hits.items():
        score = sum(
            min(count, _CAPS.get(family, 1)) * _WEIGHTS[family]
            for family, count in families.items()
        )
        if score >= _EDGE_SCORE:
            edges[pair] = score
            adjacency[pair[0]].add(pair[1])
            adjacency[pair[1]].add(pair[0])

    clusters: list[Cluster] = []
    seen: set[int] = set()
    for start in sorted(adjacency):
        if start in seen:
            continue
        component: list[int] = []
        queue = deque([start])
        seen.add(start)
        while queue:
            node = queue.popleft()
            component.append(node)
            for neighbour in sorted(adjacency[node]):
                if neighbour not in seen:
                    seen.add(neighbour)
                    queue.append(neighbour)
        if len(component) < 2:
            continue

        ordered = sorted(component, key=lambda i: _rank(eligible[i]))
        for chunk in (ordered[i : i + _MAX_CLUSTER] for i in range(0, len(ordered), _MAX_CLUSTER)):
            if len(chunk) < 2:
                continue
            inside = set(chunk)
            signals = sorted(
                {
                    label
                    for pair in edges
                    if pair[0] in inside and pair[1] in inside
                    for label in labels[pair]
                }
            )
            clusters.append(
                Cluster(
                    members=tuple(eligible[i] for i in chunk),
                    signals=tuple(signals[:12]),
                )
            )

    clusters.sort(key=lambda c: _rank(c.canonical))
    return clusters


def _member_block(f: Finding) -> str:
    trace = [s for s in (f.trace_json or []) if isinstance(s, dict)]
    sink = next((s for s in trace if s.get("kind") == "sink"), None)
    entry = next((s for s in trace if s.get("kind") == "entrypoint"), None)
    tm = f.threat_model_json or {}

    def where(step: dict | None) -> str:
        if not step:
            return "not stated"
        scope = step.get("scope") or "?"
        return f"`{step.get('file', '?')}:{step.get('line', '?')}` in `{scope}`"

    lines = [
        f"### `{f.finding_id}` - {f.title}",
        f"- severity: {f.severity()} · attack class: {f.attack_class or '?'} · area: {f.area or '?'}",
        f"- entrypoint: {where(entry)}",
        f"- sink: {where(sink)}",
        f"- boundary crossed: {tm.get('boundary', '?')}",
        f"- assumption broken: {tm.get('broken_assumption', '?')}",
        f"- remediation the hunter proposed: {(f.remediation_json or {}).get('strategy', '?')}",
    ]
    return "\n".join(lines)[:_MEMBER_CHARS]


def _cluster_block(cluster: Cluster) -> str:
    body = "\n\n".join(_member_block(f) for f in cluster.members)[:_MAX_CLUSTER_CHARS]
    signals = ", ".join(f"`{s}`" for s in cluster.signals) or "none recorded"
    return f"{len(cluster.members)} findings. The index grouped them on: {signals}.\n\n{body}"


async def run_dedup(ctx: RoleContext, task: Task) -> TaskOutcome:
    """Collapse findings that share one fix, across the whole run for one repository."""
    started = time.monotonic()
    # Scoped to the repo on purpose: the "same" bug in two codebases is two fixes, in two
    # review queues, and merging them would delete one of them from the report.
    findings = ctx.db.findings(task.run_id, repo_id=task.repo_id)
    clusters = build_clusters(findings)

    if not clusters:
        # The deterministic half found nothing worth asking about. No model call, no cost.
        ctx.db.event(
            "dedup.complete",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            considered=len(findings),
            clusters=0,
            collapsed=0,
        )
        return TaskOutcome(
            status="done",
            exit_reason="ok",
            duration_s=time.monotonic() - started,
            detail={"clusters": 0, "collapsed": 0, "considered": len(findings)},
        )

    budget = ContextBudget(
        ctx.settings.verify.model, occupancy=ctx.settings.budget.context_occupancy
    )
    collapsed: set[str] = set()
    tokens_in = tokens_out = 0
    cost = 0.0

    for cluster in clusters:
        instruction = render(
            "dedup",
            repo_name=task.repo_id,
            repo_path=str(ctx.repo_path(task.repo_id)),
            cluster_block="{CLUSTER}",
        )
        head, sep, tail = instruction.partition("{CLUSTER}")
        if not sep:
            raise KeyError("prompts/dedup.md is missing the {CLUSTER} slot")
        prompt, fit = budget.fit(
            [
                Section("instruction_head", head, priority=0),
                Section("cluster", _cluster_block(cluster), priority=1, floor_chars=2000),
                Section("instruction_tail", tail, priority=0),
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
                stage="dedup",
                detail=fit.summary(),
            )

        result = await ctx.verify_agent.run(
            prompt,
            system=preamble(),
            cwd=ctx.repo_path(task.repo_id),
            timeout_s=ctx.settings.verify.timeout_s,
            schema={"groups": "list", "distinct": "list"},
        )
        tokens_in += result.tokens_in
        tokens_out += result.tokens_out
        cost += result.cost_usd

        if not result.ok:
            # Merges already applied are durable and their members drop out of the next
            # clustering pass, so a requeue resumes where this stopped.
            ctx.db.event(
                "dedup.failed",
                run_id=task.run_id,
                repo_id=task.repo_id,
                task_id=task.task_id,
                level="error",
                classification=result.classification,
                collapsed_so_far=len(collapsed),
                error=result.error,
            )
            return TaskOutcome(
                status="failed",
                exit_reason=result.classification,
                duration_s=time.monotonic() - started,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                cost_usd=cost,
                detail={"clusters": len(clusters), "collapsed": len(collapsed)},
            )

        payload = result.extract_json() or {}
        collapsed |= _apply_groups(ctx, task, cluster, payload, already=collapsed)

    ctx.db.event(
        "dedup.complete",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        considered=len(findings),
        clusters=len(clusters),
        collapsed=len(collapsed),
    )
    return TaskOutcome(
        status="done",
        exit_reason="ok",
        duration_s=time.monotonic() - started,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=cost,
        detail={"clusters": len(clusters), "collapsed": len(collapsed)},
    )


def _apply_groups(
    ctx: RoleContext, task: Task, cluster: Cluster, payload: dict, *, already: set[str]
) -> set[str]:
    """Merge the groups the model returned. Returns the ids newly marked duplicate."""
    by_id = cluster.by_id()
    done: set[str] = set()

    for group in payload.get("groups") or []:
        if not isinstance(group, dict):
            continue
        # Only ids from the cluster the model was shown. An id it invented would otherwise
        # mark an unrelated finding as a duplicate of nothing, and duplicates leave the report.
        ids: list[str] = []
        for raw in group.get("finding_ids") or []:
            fid = str(raw)
            if fid in by_id and fid not in already and fid not in done and fid not in ids:
                ids.append(fid)
        if len(ids) < 2:
            ctx.db.event(
                "dedup.bad_group",
                run_id=task.run_id,
                repo_id=task.repo_id,
                task_id=task.task_id,
                level="warn",
                got=str(group.get("finding_ids"))[:200],
                usable=len(ids),
            )
            continue

        members = [by_id[i] for i in ids]
        canonical = min(members, key=_rank)
        one_fix = str(group.get("one_fix") or "").strip()
        reason = str(group.get("reason") or "").strip() or "(no reason given)"
        model = ctx.verify_agent.model or ctx.settings.verify.model

        for dup in members:
            if dup.finding_id == canonical.finding_id:
                continue
            ctx.db.set_verdict(dup.finding_id, "duplicate", duplicate_of=canonical.finding_id)
            # "upheld", not "disproved": a duplicate is a real bug that has been merged, and
            # recording it as disproved would tell the report the defect is not there.
            ctx.db.record_validation(
                Validation(
                    validation_id=new_id("v"),
                    finding_id=dup.finding_id,
                    task_id=task.task_id,
                    validator="dedup",
                    model=model,
                    verdict="upheld",
                    reason=f"collapses onto {canonical.finding_id}: {reason}",
                    detail_json={
                        "duplicate_of": canonical.finding_id,
                        "one_fix": one_fix,
                        "root_cause": group.get("root_cause", ""),
                        "cluster": ids,
                        "signals": list(cluster.signals),
                    },
                )
            )
            done.add(dup.finding_id)

        absorbed = [i for i in ids if i != canonical.finding_id]
        ctx.db.record_validation(
            Validation(
                validation_id=new_id("v"),
                finding_id=canonical.finding_id,
                task_id=task.task_id,
                validator="dedup",
                model=model,
                verdict="upheld",
                reason=f"canonical for {len(absorbed)} merged finding(s): {', '.join(absorbed)}. "
                f"One fix: {one_fix or reason}",
                detail_json={
                    "absorbed": absorbed,
                    "one_fix": one_fix,
                    "signals": list(cluster.signals),
                },
            )
        )
        ctx.db.event(
            "dedup.collapsed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            canonical=canonical.finding_id,
            duplicates=absorbed,
            one_fix=one_fix[:200],
        )

    for row in payload.get("distinct") or []:
        if isinstance(row, dict) and str(row.get("finding_id")) in by_id:
            ctx.db.event(
                "dedup.kept",
                run_id=task.run_id,
                repo_id=task.repo_id,
                task_id=task.task_id,
                finding_id=str(row.get("finding_id")),
                why=str(row.get("why_separate", ""))[:200],
            )
    return done


__all__ = ["Cluster", "build_clusters", "run_dedup"]
