"""vulness command line.

    vulness doctor              check the machine can actually run a hunt
    vulness run <repo>          recon -> hunt -> validate -> report
    vulness status              where the last run got to
    vulness findings            what it found, and what killed the rest
    vulness wishlist            what the agents asked for and did not get
    vulness wishlist resolve    grant one and re-run the task that asked for it
    vulness wishlist dismiss    close one without granting it
    vulness report              render REPORT.md from the database

argparse rather than a CLI framework, deliberately: typer 0.12.x breaks against
click >= 8.2 (`make_metavar()` lost its ctx argument), and a harness that runs unattended
for hours should not be able to die at argument-parsing time because a transitive
dependency moved. stdlib has no such release.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from vulness.config import Settings
from vulness.state.db import Database, new_id
from vulness.state.models import Run, Wish

console = Console()


def _load(config: str | None) -> tuple[Settings, Database]:
    settings = Settings.load(Path(config) if config else None)
    return settings, Database(settings.db_path)


def _repo_id(path: Path) -> str:
    return path.resolve().name


# ---------------------------------------------------------------- doctor


def cmd_doctor(args: argparse.Namespace) -> int:
    """Verify both models and the sandbox before spending a run on a broken toolchain."""
    settings = Settings.load(Path(args.config) if args.config else None)
    rows: list[tuple[str, bool, str]] = []

    async def checks() -> None:
        from vulness.agents.claude_cli import ClaudeCodeAgent
        from vulness.agents.glm import GLMAgent

        hunt = ClaudeCodeAgent(settings.hunt)
        ok, detail = await hunt.health()
        rows.append((f"hunt model ({settings.hunt.model} via claude CLI)", ok, detail))

        verify = GLMAgent(settings.verify)
        ok, detail = await verify.health()
        rows.append((f"verify model ({settings.verify.model})", ok, detail))
        await verify.aclose()

        if settings.sandbox.backend == "docker":
            from vulness.sandbox.docker import DockerSandbox

            ok, detail = await DockerSandbox(settings.sandbox).doctor()
            rows.append(("sandbox (docker)", ok, detail))
        else:
            rows.append(("sandbox", False, f"backend={settings.sandbox.backend} not verified"))

        skill = settings.resolved_skill_dir()
        rows.append(
            (
                "attack-class playbooks",
                skill is not None,
                str(skill) if skill else "security-audit-skill not found (hunts lose companions)",
            )
        )

    asyncio.run(checks())

    table = Table(title="vulness doctor")
    table.add_column("check")
    table.add_column("ok", justify="center")
    table.add_column("detail", overflow="fold")
    for name, ok, detail in rows:
        table.add_row(name, "[green]yes[/]" if ok else "[red]NO[/]", detail)
    console.print(table)

    if not all(ok for _, ok, _ in rows[:2]):
        console.print(
            "\n[red]Both models must work.[/] The hunt needs the `claude` CLI logged in; "
            "validation needs [bold]GLM_API_KEY[/] exported."
        )
        return 1
    if not rows[2][1]:
        console.print(
            "\n[yellow]Sandbox unavailable.[/] Hunts will still run, but PoCs cannot be "
            "executed - findings stay source-only."
        )
    return 0


# ---------------------------------------------------------------- run


def cmd_run(args: argparse.Namespace) -> int:
    """Audit a repository end to end."""
    settings, db = _load(args.config)
    # Targets come from the command line, or from fleet.yaml when none are named. The
    # budget is per repo, so adding a repo adds its own allowance rather than diluting
    # everyone else's: cross-repo tracing is only meaningful once there are several.
    raw_targets = [Path(r) for r in (args.repo or [])]
    if not raw_targets:
        raw_targets = [rc.path for rc in settings.repos if rc.enabled]
    if not raw_targets:
        console.print("[red]no targets.[/] Name a repository, or list repos: in fleet.yaml")
        return 1
    if args.budget:
        settings.budget.tasks_per_repo = args.budget

    repos: dict[str, Path] = {}
    for raw in raw_targets:
        repo = raw.resolve()
        if not repo.is_dir():
            console.print(f"[red]not a directory:[/] {repo}")
            return 1
        repo_id = _repo_id(repo)
        if repo_id in repos:
            console.print(f"[red]duplicate repo name:[/] {repo_id}. Names must be unique.")
            return 1
        repos[repo_id] = repo
        db.upsert_repo(
            repo_id,
            name=repo_id,
            path=str(repo),
            git_remote=_git(repo, "config", "--get", "remote.origin.url"),
            head_sha=_git(repo, "rev-parse", "HEAD"),
            dirty=bool(_git(repo, "status", "--porcelain")),
        )
    repo = next(iter(repos.values()))
    repo_id = next(iter(repos))
    head = _git(repo, "rev-parse", "HEAD")

    if args.resume:
        run_id = args.resume
        if db.one("SELECT 1 FROM runs WHERE run_id=?", (run_id,)) is None:
            console.print(f"[red]no such run:[/] {run_id}")
            return 1
        console.print(f"[cyan]resuming[/] {run_id}")
    else:
        run_id = new_id("run")
        db.create_run(
            Run(
                run_id=run_id,
                status="running",
                profile=settings.profile,
                budget_tasks=settings.budget.tasks_per_repo,
                model_hunt=settings.hunt.model,
                model_verify=settings.verify.model,
                config_json={"repo": str(repo), "head": head},
            )
        )
        if len(repos) == 1:
            console.print(f"[green]run[/] {run_id} - {repo_id} @ {(head or 'no-git')[:8]}")
        else:
            console.print(
                f"[green]run[/] {run_id} - {len(repos)} repos: {', '.join(repos)}"
            )

    scopes: dict[str, list[str]] = {}
    if args.since:
        from vulness.coverage.scope import changed_since

        for rid, rpath in repos.items():
            sc = changed_since(rpath, args.since)
            if sc.error:
                console.print(f"[red]{rid}: {sc.summary()}[/]")
                return 1
            scopes[rid] = sc.changed
            console.print(f"  {rid}: {sc.summary()}")
        if not any(scopes.values()):
            console.print(
                f"[yellow]nothing changed since {args.since}.[/] No work to do."
            )
            db.finish_run(run_id, "complete")
            return 0

    asyncio.run(
        _execute(
            settings, db, run_id, repos, args.gapfill,
            triage=not args.no_triage, fix=args.fix, scopes=scopes,
        )
    )

    from vulness.report import render_report, run_stats

    # Close the run BEFORE rendering: the report reads run status from the database, and
    # a finished run that describes itself as "running" is a lie told by ordering.
    db.finish_run(run_id, "complete")

    stats = run_stats(db, run_id)
    out = settings.work_dir / run_id / "REPORT.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(db, run_id))
    console.print(
        f"\n[bold]{stats['by_verdict'].get('confirmed', 0)} confirmed[/] - "
        f"{stats['by_verdict'].get('rejected', 0)} rejected - "
        f"{stats['cells_covered']}/{stats['cells_total']} cells - "
        f"{stats['tasks']} tasks - ${stats['cost_usd']}"
    )
    console.print(f"report: {out}")
    return 0


async def _execute(
    settings: Settings,
    db: Database,
    run_id: str,
    repos: dict[str, Path],
    gapfill: int,
    *,
    triage: bool = True,
    fix: bool = False,
    scopes: dict[str, list[str]] | None = None,
) -> None:
    from vulness.agents.claude_cli import ClaudeCodeAgent
    from vulness.agents.glm import GLMAgent
    from vulness.agents.roles import RoleContext
    from vulness.orchestrator import Scheduler

    hunt = ClaudeCodeAgent(settings.hunt, max_concurrent=settings.budget.max_concurrent_agents)
    verify = GLMAgent(settings.verify)
    sandbox = None
    if settings.sandbox.backend == "docker":
        from vulness.sandbox.docker import DockerSandbox

        candidate = DockerSandbox(
            settings.sandbox, max_concurrent=settings.budget.max_concurrent_sandboxes
        )
        ok, detail = await candidate.doctor()
        if ok:
            sandbox = candidate
        else:
            db.event("sandbox.unavailable", run_id=run_id, level="warn", detail=detail)
            console.print(f"[yellow]sandbox unavailable:[/] {detail} - source-only findings")

    # Digest the tree once, before any agent touches it. Every PoC is checked against this
    # baseline, so "the source was untouched" covers the whole run rather than just the
    # seconds around the PoC -- an agent that edited the repo during its hunt cannot pass.
    baselines: dict[str, dict[str, str]] = {}
    if sandbox is not None:
        from vulness.sandbox.policy import SourceIntegrity

        for rid, rpath in repos.items():
            baselines[rid] = await asyncio.to_thread(SourceIntegrity.snapshot, rpath)
            db.event("source.baseline", run_id=run_id, repo_id=rid, files=len(baselines[rid]))

    ctx = RoleContext(
        db=db,
        settings=settings,
        hunt_agent=hunt,
        verify_agent=verify,
        repo_paths=dict(repos),
        sandbox=sandbox,
        repo_baselines=baselines,
    )
    try:
        await Scheduler(
            ctx, run_id, gapfill_passes=gapfill, triage=triage, fix=fix, scopes=scopes
        ).run(list(repos))
    finally:
        await verify.aclose()


# ---------------------------------------------------------------- inspection


def cmd_status(args: argparse.Namespace) -> int:
    """Summarise the most recent run."""
    settings, db = _load(args.config)
    row = db.latest_run()
    if row is None:
        console.print("no runs yet")
        return 0

    from vulness.report import run_stats

    stats = run_stats(db, row["run_id"])
    console.print(f"[bold]{row['run_id']}[/] · {row['status']} · started {row['started_at']}")
    console.print(f"hunt={row['model_hunt']}  verify={row['model_verify']}\n")

    t = Table(show_header=True)
    t.add_column("metric")
    t.add_column("value", justify="right")
    for k in ("tasks", "findings", "cells_total", "cells_covered", "coverage_pct", "cost_usd"):
        t.add_row(k, str(stats[k]))
    console.print(t)
    console.print(f"\nverdicts: {stats['by_verdict']}")
    console.print(f"task status: {stats['tasks_by_status']}")
    if stats["tasks_by_exit"]:
        console.print(f"exit reasons: {stats['tasks_by_exit']}")
    return 0


def cmd_findings(args: argparse.Namespace) -> int:
    """List findings from a run."""
    settings, db = _load(args.config)
    rid = args.run or (db.latest_run() or {})["run_id"]
    items = db.findings(rid, verdict=args.verdict)

    if args.json:
        print(json.dumps([f.model_dump() for f in items], indent=2, default=str))
        return 0

    if not items:
        console.print("no findings")
        return 0
    t = Table(title=f"findings · {rid}")
    t.add_column("verdict")
    t.add_column("sev")
    t.add_column("class")
    t.add_column("title", overflow="fold")
    colour = {
        "confirmed": "red",
        "rejected": "dim",
        "candidate": "yellow",
        "needs_validation": "cyan",
    }
    for f in items:
        c = colour.get(f.verdict, "white")
        t.add_row(f"[{c}]{f.verdict}[/]", f.severity(), f.attack_class or "-", f.title)
    console.print(t)
    return 0


# The wishlist is a two-way channel, and the return half needs an origin for the task it
# re-files. `TaskOrigin` has no member for it and `Task.from_row` validates that literal on
# every lease, so an invented label would write a row the scheduler can never pick up.
# "feedback" is the existing origin for work re-filed because information came back into
# the system; the wish id rides in seed_json so the real provenance survives the borrowing.
_WISH_ORIGIN = "feedback"


def cmd_chains(args: argparse.Namespace) -> int:
    """Confirmed findings that compose into something worse than any one of them."""
    settings, db = _load(args.config)
    rid = args.run or (db.latest_run() or {})["run_id"]
    items = [c for c in db.chains(run_id=rid) if c["verdict"] != "rejected"]
    if not items:
        console.print("no chains")
        return 0
    # Per repo, not per run: a chain routinely joins an older primitive to a new finding.
    findings = {
        r["finding_id"]: r["title"]
        for r in db.query(
            "SELECT finding_id, title FROM findings WHERE repo_id IN"
            " (SELECT DISTINCT repo_id FROM findings WHERE run_id=?)",
            (rid,),
        )
    }
    for c in items:
        console.print(f"\n[bold]{c['title']}[/]  [red]{c['severity']}[/]")
        console.print(f"  ends in: {c['terminal_impact']}")
        for i, fid in enumerate(c["steps"], 1):
            console.print(f"  {i}. {findings.get(fid, fid)}")
    return 0


def cmd_wishlist(args: argparse.Namespace) -> int:
    """What the agents asked for. This is how they talk back to you."""
    settings, db = _load(args.config)
    items = db.open_wishes()
    if not items:
        console.print("wishlist empty")
        return 0
    t = Table(title="open wishes")
    t.add_column("wish_id")
    t.add_column("kind")
    t.add_column("resource", overflow="fold")
    t.add_column("why", overflow="fold")
    t.add_column("asked by", overflow="fold")
    for w in items:
        t.add_row(
            w.wish_id,
            w.kind,
            w.resource,
            str(w.context_json.get("why", "")),
            w.task_id or "(task gone)",
        )
    console.print(t)
    console.print(
        "\n[dim]vulness wishlist resolve <wish_id>[/] grants one and re-runs the task that "
        "asked\n[dim]vulness wishlist dismiss <wish_id>[/] closes one without granting it"
    )
    return 0


def _open_wish(db: Database, wish_id: str) -> Wish | None:
    """Fetch a wish that can still be acted on, explaining any refusal."""
    wish = db.get_wish(wish_id)
    if wish is None:
        console.print(f"[red]no such wish:[/] {wish_id}. `vulness wishlist` lists the open ones.")
        return None
    if wish.status != "open":
        detail = f"[yellow]{wish_id} is already {wish.status}[/] ({wish.resolved_at})"
        if wish.requeued_task_id:
            detail += f", re-enqueued as {wish.requeued_task_id}"
        console.print(f"{detail}. Resolving it again would queue that work a second time.")
        return None
    return wish


def _warn_if_run_closed(db: Database, run_id: str) -> None:
    """A queued task in a finished run is never leased: nothing is left to pick it up."""
    row = db.one("SELECT status FROM runs WHERE run_id=?", (run_id,))
    if row is None:
        console.print(
            f"[yellow]run {run_id} is no longer in the database.[/] The task is queued under "
            "a run nothing can resume, so it will not be picked up."
        )
        return
    if str(row["status"]) == "running":
        return
    console.print(
        f"[yellow]run {run_id} is {row['status']}.[/] Re-enqueuing into a finished run does "
        f"nothing on its own. Pick it up with:\n  vulness run --resume {run_id}"
    )


def cmd_wishlist_resolve(args: argparse.Namespace) -> int:
    """Grant a wish and re-run the exact task that asked for it.

    Marking a wish provided without re-filing that task is the failure this command exists
    to prevent: the dependency arrives, and the gap the agent wrote about stays unexamined
    because nothing ever asks again.
    """
    settings, db = _load(args.config)
    wish = _open_wish(db, args.wish_id)
    if wish is None:
        return 1

    original = db.get_task(wish.task_id) if wish.task_id else None
    if original is None:
        db.resolve_wish(wish.wish_id, status="provided", requeued_task_id=None)
        console.print(f"[green]provided[/] {wish.wish_id} - {wish.resource}")
        console.print(
            "[yellow]the task that asked for it is gone[/], so nothing was re-enqueued: "
            "the wish status is all that changed."
        )
        return 0

    requeued = db.requeue(original, _WISH_ORIGIN, seed_extra={"wish_id": wish.wish_id})
    db.resolve_wish(wish.wish_id, status="provided", requeued_task_id=requeued.task_id)
    console.print(f"[green]provided[/] {wish.wish_id} - {wish.resource}")
    console.print(
        f"re-enqueued {original.kind} task {original.task_id} as [bold]{requeued.task_id}[/]"
    )
    _warn_if_run_closed(db, wish.run_id)
    return 0


def cmd_wishlist_dismiss(args: argparse.Namespace) -> int:
    """Close a wish nobody is going to grant. Enqueues nothing."""
    settings, db = _load(args.config)
    wish = _open_wish(db, args.wish_id)
    if wish is None:
        return 1
    db.resolve_wish(wish.wish_id, status="wontfix", requeued_task_id=None)
    console.print(f"[dim]wontfix[/] {wish.wish_id} - {wish.resource}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Render REPORT.md from stored records. Deterministic: no model runs."""
    settings, db = _load(args.config)
    rid = args.run or (db.latest_run() or {})["run_id"]
    from vulness.report import render_report

    text = render_report(db, rid)
    if args.out:
        Path(args.out).write_text(text)
        console.print(f"wrote {args.out}")
    else:
        print(text)
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    """Score a run against labelled targets. Deterministic: no model runs.

    Exit status is the point of the `--min-recall` and `--max-decoys` gates: a benchmark
    nothing can fail is a dashboard. CI can hold a floor without anyone reading the table.
    """
    settings, db = _load(args.config)
    rid = args.run or (db.latest_run() or {})["run_id"]
    from vulness.bench import load_corpora, render_scorecard, score_run

    corpus_dir = Path(args.corpus)
    if not corpus_dir.is_dir():
        console.print(f"[red]no corpus directory at {corpus_dir}[/red]")
        return 2
    corpora = load_corpora(corpus_dir)
    if not corpora:
        console.print(f"[red]no *.json corpora in {corpus_dir}[/red]")
        return 2

    scores = score_run(db, rid, corpora)
    text = render_scorecard(scores)
    if args.out:
        Path(args.out).write_text(text)
        console.print(f"wrote {args.out}")
    else:
        print(text)

    if not scores:
        return 0
    tier = args.tier
    recalls = [r for r in (s.tiers[tier].recall for s in scores) if r is not None]
    recall = sum(recalls) / len(recalls) if recalls else 0.0
    decoys = sum(len(s.tiers[tier].decoys) for s in scores)
    failed = []
    if args.min_recall is not None and recall < args.min_recall:
        failed.append(f"recall {recall:.0%} at tier {tier} is below the {args.min_recall:.0%} floor")
    if args.max_decoys is not None and decoys > args.max_decoys:
        failed.append(f"{decoys} decoy(s) flagged at tier {tier}, limit {args.max_decoys}")
    for line in failed:
        console.print(f"[red]{line}[/red]")
    return 1 if failed else 0


def cmd_corpus_secbench(args: argparse.Namespace) -> int:
    """Build a corpus bundle from SecBench.js sink_locations_*.txt files."""
    from vulness.bench import dump_corpora, from_secbench_js

    src = Path(args.sinks)
    files = {p.stem.removeprefix("sink_locations_"): p for p in sorted(src.glob("*.txt"))}
    if not files:
        console.print(f"[red]no sink_locations_*.txt under {src}[/red]")
        return 2
    corpora = from_secbench_js(files)
    n = dump_corpora(corpora, Path(args.out))
    labels = sum(len(c.labels) for c in corpora)
    console.print(f"wrote {args.out}: {n} target(s), {labels} label(s)")
    return 0


def cmd_corpus_vul4j(args: argparse.Namespace) -> int:
    """Build a corpus bundle from the Vul4J dataset CSV plus its fix-commit patches."""
    from vulness.bench import dump_corpora, from_vul4j

    csv_path, patches = Path(args.csv), Path(args.patches)
    if not csv_path.exists():
        console.print(f"[red]no dataset csv at {csv_path}[/red]")
        return 2
    if not patches.is_dir():
        console.print(
            f"[red]no patch directory at {patches}. Fetch <commit>.patch for each"
            " human_patch url into <vul_id>.patch first.[/red]"
        )
        return 2
    corpora = from_vul4j(csv_path, patches)
    if not corpora:
        console.print("[red]no entry had a patch on disk; nothing to write[/red]")
        return 2
    n = dump_corpora(corpora, Path(args.out))
    labels = sum(len(c.labels) for c in corpora)
    console.print(f"wrote {args.out}: {n} target(s), {labels} label(s)")
    return 0


def _git(repo: Path, *args: str) -> str | None:
    import subprocess

    try:
        r = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=10
        )
        return r.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


# ---------------------------------------------------------------- argument parsing


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulness", description="Autonomous vulnerability-discovery harness."
    )
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser) -> argparse.ArgumentParser:
        sp.add_argument("-c", "--config", help="path to fleet.yaml")
        return sp

    common(sub.add_parser("doctor", help="check both models and the sandbox")).set_defaults(
        fn=cmd_doctor
    )

    r = common(sub.add_parser("run", help="audit a repository end to end"))
    r.add_argument(
        "repo",
        nargs="*",
        help="repositories to audit. Omit to use the repos listed in fleet.yaml. "
        "Two or more enables cross-repo tracing.",
    )
    r.add_argument("-b", "--budget", type=int, help="max agent tasks for this repo")
    r.add_argument("-g", "--gapfill", type=int, default=1, help="gapfill passes")
    r.add_argument("--resume", help="continue an existing run_id")
    r.add_argument(
        "--since",
        metavar="REF",
        help="audit only what changed since this git ref (branch, tag or commit). "
        "Reports partial coverage: unchanged code is not examined.",
    )
    r.add_argument("--no-triage", action="store_true", help="skip VVS dedup/judge")
    r.add_argument("--fix", action="store_true", help="propose patches for confirmed findings")
    r.set_defaults(fn=cmd_run)

    common(sub.add_parser("status", help="summarise the most recent run")).set_defaults(
        fn=cmd_status
    )

    f = common(sub.add_parser("findings", help="list findings"))
    f.add_argument("-v", "--verdict", help="confirmed|rejected|candidate|needs_validation")
    f.add_argument("--run", help="run_id (default: latest)")
    f.add_argument("--json", action="store_true")
    f.set_defaults(fn=cmd_findings)

    ch = common(sub.add_parser("chains", help="findings that compose into a worse attack"))
    ch.add_argument("--run", help="run_id (default: latest)")
    ch.set_defaults(fn=cmd_chains)

    w = common(sub.add_parser("wishlist", help="what the agents asked for"))
    w.set_defaults(fn=cmd_wishlist)
    # Bare `vulness wishlist` is still the listing, so the action word stays optional.
    w_sub = w.add_subparsers(dest="wish_action")

    def wish_action(name: str, help_text: str) -> argparse.ArgumentParser:
        sp = w_sub.add_parser(name, help=help_text)
        sp.add_argument("wish_id", help="id shown by `vulness wishlist`")
        # SUPPRESS rather than a None default: argparse copies a subparser's whole namespace
        # over its parent's, so a plain default would erase a --config given before the
        # action word.
        sp.add_argument("-c", "--config", default=argparse.SUPPRESS, help="path to fleet.yaml")
        return sp

    wish_action("resolve", "grant it and re-run the task that asked").set_defaults(
        fn=cmd_wishlist_resolve
    )
    wish_action("dismiss", "close it without granting it; enqueues nothing").set_defaults(
        fn=cmd_wishlist_dismiss
    )

    b = common(sub.add_parser("bench", help="score a run against labelled targets"))
    b.add_argument("--run", help="run id (default: most recent)")
    b.add_argument("--corpus", default="tests/ground_truth", help="directory of corpus JSON")
    b.add_argument("-o", "--out", help="write the scorecard to a file")
    b.add_argument(
        "--tier",
        default="reported",
        choices=("confirmed", "reported", "raw"),
        help="which verdict tier the gates below apply to",
    )
    b.add_argument("--min-recall", type=float, help="fail below this recall, 0.0 to 1.0")
    b.add_argument("--max-decoys", type=int, help="fail above this many decoys flagged")
    b.set_defaults(fn=cmd_bench)

    cp = sub.add_parser("corpus", help="build a scoring corpus from a published benchmark")
    cp_sub = cp.add_subparsers(dest="corpus_command", required=True)
    sb = cp_sub.add_parser("secbench", help="SecBench.js sink locations")
    sb.add_argument("--sinks", required=True, help="directory of sink_locations_*.txt")
    sb.add_argument("-o", "--out", required=True, help="corpus bundle to write")
    sb.set_defaults(fn=cmd_corpus_secbench)
    vj = cp_sub.add_parser("vul4j", help="Vul4J dataset csv plus fix-commit patches")
    vj.add_argument("--csv", required=True, help="vul4j_dataset.csv")
    vj.add_argument("--patches", required=True, help="directory of <vul_id>.patch")
    vj.add_argument("-o", "--out", required=True, help="corpus bundle to write")
    vj.set_defaults(fn=cmd_corpus_vul4j)

    rp = common(sub.add_parser("report", help="render REPORT.md"))
    rp.add_argument("--run", help="run_id (default: latest)")
    rp.add_argument("-o", "--out", help="write to this path instead of stdout")
    rp.set_defaults(fn=cmd_report)

    return p


def app(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.fn(args) or 0)


def main() -> None:
    sys.exit(app())


if __name__ == "__main__":
    main()
