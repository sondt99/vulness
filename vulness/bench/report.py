"""Render a scorecard. No model, same as the run report."""

from __future__ import annotations

from vulness.bench.score import TIERS, RepoScore


def _pct(v: float | None) -> str:
    return "n/a" if v is None else f"{100 * v:.0f}%"


def render_scorecard(scores: list[RepoScore]) -> str:
    if not scores:
        return "No scored repository in this run. Nothing in the corpus was audited.\n"

    out = ["# Benchmark scorecard", ""]
    for name, _ in TIERS:
        tiers = [s.tiers[name] for s in scores]
        positives = sum(t.positives for t in tiers)
        found = sum(len(t.found) for t in tiers)
        hits = sum(len(t.hits) for t in tiers)
        decoys = sum(len(t.decoys) for t in tiers)
        unlabelled = sum(len(t.unlabelled) for t in tiers)
        scored = sum(t.scored for t in tiers)
        precision = hits / scored if scored else None
        recall = found / positives if positives else None
        out.append(
            f"- **{name}**: recall {_pct(recall)} ({found}/{positives}), "
            f"precision {_pct(precision)} ({hits}/{scored}), "
            f"decoys hit {decoys}, unlabelled {unlabelled}"
        )
    out += ["", "Tiers widen by verdict: `confirmed`, then plus `needs_validation`, then every",
            "candidate the hunters filed. Reading them together separates what the hunters",
            "found from what the validator was willing to let through.", ""]

    for s in scores:
        out += [f"## {s.repo}", ""]
        world = "closed" if s.corpus.closed_world else "open"
        out += [
            f"{len(s.corpus.positives)} labelled defect(s), {len(s.corpus.decoys)} decoy(s), "
            f"{world} world.",
            "",
            "| tier | recall | precision | hits | decoys | unlabelled |",
            "|---|---|---|---|---|---|",
        ]
        for name, _ in TIERS:
            t = s.tiers[name]
            out.append(
                f"| {name} | {_pct(t.recall)} ({len(t.found)}/{t.positives}) | "
                f"{_pct(t.precision)} | {len(t.hits)} | {len(t.decoys)} | {len(t.unlabelled)} |"
            )
        out.append("")

        if s.missed:
            out += ["**Missed entirely:**", ""]
            out += [f"- `{x.id}` {x.file}:{x.line} - {x.note}" for x in s.missed]
            out.append("")

        widest = s.tiers[TIERS[-1][0]]
        if widest.decoys:
            out += ["**Decoys flagged (each one a false positive):**", ""]
            out += [
                f"- `{m.label.id if m.label else '?'}` from {m.file}:{m.line} - {m.title}"
                for m in widest.decoys
            ]
            out.append("")
        if widest.unlabelled:
            note = (
                "counted as false positives: this target is exhaustively labelled"
                if s.corpus.closed_world
                else "not scored either way: this target is only partly labelled"
            )
            out += [f"**Unlabelled findings** ({note}):", ""]
            out += [f"- {m.file}:{m.line} - {m.title}" for m in widest.unlabelled]
            out.append("")

        if s.corpus.chains:
            out += ["**Chains:**", ""]
            for c in s.chains:
                mark = "found" if c.found else "**missed**"
                out.append(f"- `{c.chain_id}`: {mark}")
            out.append("")

    return "\n".join(out)
