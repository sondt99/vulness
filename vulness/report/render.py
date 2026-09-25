"""Reporting. No model runs here.

Rendering is deterministic on purpose: by this point every judgement has already been made
and recorded, and asking a model to summarise its own findings is a chance for the prose
and the data to disagree. The report is a view over the database, nothing more.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import Any

from vulness.state.db import Database
from vulness.state.models import Finding, now

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "unrated": 5}

# Any run of three or more backticks, which is what ends a fenced block early.
_FENCE = re.compile(r"`{3,}")


def _md(text: Any, limit: int = 2000) -> str:
    """Model-authored text, made safe to interpolate into a line of Markdown.

    Every string here was written by a model reading a repository this harness does not
    trust, so it is attacker-influenced in the same sense the source is. The schema enforces
    a 12-character minimum on a title and nothing about its content. A finding titled with a
    newline and a `## ` restructures the report; one containing a fence ends the PoC block
    early and spills the rest as prose.

    Not HTML escaping: the output is Markdown read by people and diffed in git, so the aim
    is that model text cannot change the document's structure, not that it renders inertly.
    """
    flat = " ".join(str(text or "").split())
    return _FENCE.sub("``", flat)[:limit] or "-"


def _fenced(text: Any, limit: int = 600) -> str:
    """Body for a fenced block. Newlines survive; fences do not."""
    return _FENCE.sub("``", str(text or "")).strip()[-limit:]


def run_stats(db: Database, run_id: str) -> dict[str, Any]:
    tasks = list(db.iter_tasks(run_id))
    findings = db.findings(run_id)
    cells = db.cells(run_id)

    by_verdict = Counter(f.verdict for f in findings)
    by_status = Counter(t.status for t in tasks)
    by_exit = Counter(t.exit_reason for t in tasks if t.exit_reason)
    by_origin = Counter(t.origin for t in tasks)

    covered = sum(1 for c in cells if c.hunter_tasks > 0)

    # PoC execution and context pressure are run-health signals, not finding attributes:
    # they say whether the harness was able to do its job, which the coverage number alone
    # cannot express.
    poc_counts: Counter[str] = Counter()
    for f in findings:
        for v in db.validations_for(f.finding_id):
            if v.validator == "sandbox":
                poc_counts[str((v.detail_json or {}).get("verdict", v.verdict))] += 1
    peaks = [
        int(t.result_json.get("peak_context_tokens", 0))
        for t in tasks
        if isinstance(t.result_json, dict) and t.result_json.get("peak_context_tokens")
    ]
    return {
        "poc": dict(poc_counts),
        "context_peak_tokens": max(peaks) if peaks else 0,
        "context_peak_occupancy": round(max(peaks) / 200_000, 3) if peaks else 0.0,
        "context_overruns": len(
            db.query(
                "SELECT 1 FROM events WHERE run_id=? AND kind='context.exceeded'", (run_id,)
            )
        ),
        "tasks": len(tasks),
        "tasks_by_status": dict(by_status),
        "tasks_by_exit": dict(by_exit),
        "tasks_by_origin": dict(by_origin),
        "findings": len(findings),
        "by_verdict": dict(by_verdict),
        "cells_total": len(cells),
        "cells_covered": covered,
        "coverage_pct": round(100.0 * covered / len(cells), 1) if cells else 0.0,
        "cost_usd": round(sum(t.cost_usd for t in tasks), 4),
        # Only the hunt backend reports a price; GLM usage is deliberately left unpriced
        # (see agents/glm.py). Summing the two into one figure reads as the run's cost and
        # is not, so the renderer says which tasks the number actually covers.
        "priced_tasks": sum(1 for t in tasks if t.cost_usd),
        "unpriced_tasks": sum(1 for t in tasks if not t.cost_usd and (t.tokens_in or t.tokens_out)),
        "tokens_in": sum(t.tokens_in for t in tasks),
        "tokens_out": sum(t.tokens_out for t in tasks),
        "wall_time_s": round(sum(t.duration_s or 0.0 for t in tasks), 1),
    }


def _sev(f: Finding) -> int:
    return _SEVERITY_ORDER.get(f.severity(), 5)


def _finding_section(db: Database, f: Finding) -> str:
    tm = f.threat_model_json or {}
    lines = [
        f"### {_md(f.title, 200)}",
        "",
        f"`{f.fingerprint}` · **{f.severity()}** · {_md(f.attack_class or 'unclassified', 60)}"
        f" · area `{_md(f.area or '?', 60)}`",
        "",
        "**Threat model**",
        "",
        f"- Attacker: {_md(tm.get('attacker'), 400)}",
        f"- Boundary crossed: {_md(tm.get('boundary'), 400)}",
        f"- Broken assumption: {_md(tm.get('broken_assumption'), 400)}",
        "",
    ]
    if f.trace_json:
        lines += ["**Trace**", ""]
        for step in f.trace_json:
            if isinstance(step, dict):
                lines.append(
                    f"- `{_md(step.get('kind', '?'), 40)}` -"
                    f" `{_md(step.get('file', '?'), 300)}:{_md(step.get('line', '?'), 20)}`"
                    f" in `{_md(step.get('scope', '?'), 120)}` - {_md(step.get('description'), 500)}"
                )
        lines.append("")
    if items := (f.evidence_json or {}).get("items"):
        lines += ["**Evidence**", ""]
        for e in items:
            if isinstance(e, dict):
                lines.append(
                    f"- `{_md(e.get('file', '?'), 300)}:{_md(e.get('line', '?'), 20)}`"
                    f" - {_md(e.get('description'), 500)}"
                )
        lines.append("")

    for v in db.validations_for(f.finding_id):
        icon = {"upheld": "✔", "disproved": "✘", "needs_validation": "?"}.get(v.verdict, "·")
        lines.append(f"> {icon} **{v.validator}** ({_md(v.model, 60)}): {_md(v.reason, 1200)}")
        # A PoC that executed is the hardest evidence in the report; show what it printed.
        if v.validator == "sandbox" and (out := _fenced((v.detail_json or {}).get("stdout"))):
            lines += ["", "```", out, "```"]
    lines.append("")

    if strategy := (f.remediation_json or {}).get("strategy"):
        lines += ["**Remediation**", "", str(strategy), ""]
    return "\n".join(lines)


def render_report(db: Database, run_id: str) -> str:
    stats = run_stats(db, run_id)
    findings = db.findings(run_id)
    confirmed = sorted([f for f in findings if f.verdict == "confirmed"], key=_sev)
    needs = [f for f in findings if f.verdict == "needs_validation"]
    rejected = [f for f in findings if f.verdict == "rejected"]

    run = db.one("SELECT * FROM runs WHERE run_id=?", (run_id,))
    out: list[str] = [
        f"# vulness report - `{run_id}`",
        "",
        f"_generated {now()}_",
        "",
        f"- Hunt model: `{run['model_hunt'] if run else '?'}`",
        f"- Verify model: `{run['model_verify'] if run else '?'}` (independent of the hunter)",
        f"- Profile: `{run['profile'] if run else '?'}` · status: `{run['status'] if run else '?'}`",
        "",
        "## Summary",
        "",
        "| confirmed | needs validation | rejected | candidates open |",
        "|---|---|---|---|",
        f"| **{len(confirmed)}** | {len(needs)} | {len(rejected)} |"
        f" {stats['by_verdict'].get('candidate', 0)} |",
        "",
        f"Coverage: **{stats['cells_covered']}/{stats['cells_total']} cells "
        f"({stats['coverage_pct']}%)** · {stats['tasks']} agent tasks · "
        f"{stats['tokens_in'] + stats['tokens_out']:,} tokens · ${stats['cost_usd']}"
        + (
            f" (hunt backend only; {stats['unpriced_tasks']} validation tasks are unpriced)"
            if stats["unpriced_tasks"]
            else ""
        ),
        "",
    ]

    if stats["poc"]:
        verified = stats["poc"].get("verified", 0)
        out += [
            f"Proofs of concept executed in sandbox: **{verified} verified**, "
            f"{stats['poc'].get('refuted', 0)} refuted, "
            f"{stats['poc'].get('tainted', 0)} voided for touching the source, "
            f"{stats['poc'].get('skipped', 0)} source-only.",
            "",
        ]
    if stats["context_peak_tokens"]:
        warn = " ⚠️" if stats["context_overruns"] else ""
        out += [
            f"Peak agent context: {stats['context_peak_tokens']:,} tokens "
            f"({stats['context_peak_occupancy']:.0%} of window){warn}"
            + (
                f" - {stats['context_overruns']} task(s) exceeded the target; their cells "
                "were too broad and should be split."
                if stats["context_overruns"]
                else ""
            ),
            "",
        ]

    # Never let a report imply a clean sweep. Failed tasks are coverage gaps, not silence.
    failed = stats["tasks_by_status"].get("failed", 0)
    abandoned = stats["tasks_by_status"].get("abandoned", 0)
    if failed or abandoned:
        out += [
            f"> **Coverage is incomplete.** {failed} task(s) failed and {abandoned} were dropped "
            f"for budget. Exit reasons: `{stats['tasks_by_exit']}`. Cells those tasks owned were "
            "not examined - this report does not claim they are clean.",
            "",
        ]

    if confirmed:
        out += ["## Confirmed findings", ""]
        out += [_finding_section(db, f) for f in confirmed]
    else:
        out += [
            "## Confirmed findings",
            "",
            "_None._ No candidate survived independent validation on the second model. "
            "That is a statement about this run's coverage, not a clean bill of health.",
            "",
        ]

    if needs:
        out += ["## Needs validation", "", "_Blocked on a fact outside this repository._", ""]
        for f in needs:
            missing = ""
            for v in db.validations_for(f.finding_id):
                if v.detail_json.get("missing_fact"):
                    missing = str(v.detail_json["missing_fact"])
            out.append(
                f"- **{_md(f.title, 200)}** -"
                f" {_md(missing or 'missing external fact not specified', 600)}"
            )
        out.append("")

    if rejected:
        out += ["## Rejected", "", f"{len(rejected)} candidate(s) were disproved:", ""]
        for f in rejected:
            why = next(
                (v.reason for v in db.validations_for(f.finding_id) if v.verdict == "disproved"),
                "no reason recorded",
            )
            out.append(f"- ~~{_md(f.title, 200)}~~ - {_md(why, 600)}")
        out.append("")

    if chains := [c for c in db.chains(run_id=run_id) if c["verdict"] != "rejected"]:
        # Steps are resolved per repo, not per run: a chain routinely joins a primitive
        # recorded weeks ago to a finding confirmed today, and a run-scoped lookup renders
        # the older half as "(unknown)".
        by_title = {
            r["finding_id"]: r["title"]
            for r in db.query(
                "SELECT finding_id, title FROM findings WHERE repo_id IN"
                " (SELECT DISTINCT repo_id FROM findings WHERE run_id=?)",
                (run_id,),
            )
        }
        out += [
            "## Exploit chains",
            "",
            "_Confirmed findings that compose. Severity here is the impact of the whole "
            "chain, which is why it can exceed any single step._",
            "",
        ]
        for c in sorted(chains, key=lambda x: _SEVERITY_ORDER.get(x["severity"], 5)):
            out += [
                f"### {_md(c['title'], 200)}",
                "",
                f"**{_md(c['severity'], 40)}** - {_md(c['terminal_impact'], 300)}",
                "",
            ]
            if c["preconditions"]:
                out += [f"Attacker starts with: {_md(c['preconditions'], 600)}", ""]
            for i, fid in enumerate(c["steps"], 1):
                out.append(f"{i}. {_md(by_title.get(fid, fid), 200)}")
            out += ["", _md(c["narrative"], 3000), ""]

    if wishes := db.open_wishes(run_id):
        out += [
            "## Wishlist",
            "",
            "_Agents asked for these and could not proceed without them:_",
            "",
        ]
        out += [
            f"- **{_md(w.kind, 40)}** - {_md(w.resource, 300)}"
            f" ({_md(w.context_json.get('why'), 400)})"
            for w in wishes
        ]
        out.append("")

    out += ["## Run statistics", "", "```json", json.dumps(stats, indent=2), "```", ""]
    return "\n".join(out)
