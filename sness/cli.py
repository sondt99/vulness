"""s-ness command line.

    sness doctor              check the machine can actually run a hunt
    sness run <repo>          recon -> hunt -> validate -> report
    sness status              where the last run got to
    sness findings            what it found, and what killed the rest
    sness wishlist            what the agents asked for and did not get
    sness report              render REPORT.md from the database

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

from sness.config import Settings
from sness.state.db import Database, new_id
from sness.state.models import Run

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
        from sness.agents.claude_cli import ClaudeCodeAgent
        from sness.agents.glm import GLMAgent

        hunt = ClaudeCodeAgent(settings.hunt)
        ok, detail = await hunt.health()
        rows.append((f"hunt model ({settings.hunt.model} via claude CLI)", ok, detail))

        verify = GLMAgent(settings.verify)
        ok, detail = await verify.health()
        rows.append((f"verify model ({settings.verify.model})", ok, detail))
        await verify.aclose()

        if settings.sandbox.backend == "docker":
            from sness.sandbox.docker import DockerSandbox

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

    table = Table(title="s-ness doctor")
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
            "executed \u2014 findings stay source-only."
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
            console.print(f"[green]run[/] {run_id} \u00b7 {repo_id} @ {(head or 'no-git')[:8]}")
        else:
            console.print(
                f"[green]run[/] {run_id} \u00b7 {len(repos)} repos: {', '.join(repos)}"
            )

    asyncio.run(
        _execute(
            settings, db, run_id, repos, args.gapfill,
            triage=not args.no_triage, fix=args.fix,
        )
    )

    from sness.report import render_report, run_stats

    # Close the run BEFORE rendering: the report reads run status from the database, and
    # a finished run that describes itself as "running" is a lie told by ordering.
    db.finish_run(run_id, "complete")

    stats = run_stats(db, run_id)
    out = settings.work_dir / run_id / "REPORT.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_report(db, run_id))
    console.print(
        f"\n[bold]{stats['by_verdict'].get('confirmed', 0)} confirmed[/] \u00b7 "
        f"{stats['by_verdict'].get('rejected', 0)} rejected \u00b7 "
        f"{stats['cells_covered']}/{stats['cells_total']} cells \u00b7 "
        f"{stats['tasks']} tasks \u00b7 ${stats['cost_usd']}"
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
) -> None:
    from sness.agents.claude_cli import ClaudeCodeAgent
    from sness.agents.glm import GLMAgent
    from sness.agents.roles import RoleContext
    from sness.orchestrator import Scheduler

    hunt = ClaudeCodeAgent(settings.hunt)
    verify = GLMAgent(settings.verify)
    sandbox = None
    if settings.sandbox.backend == "docker":
        from sness.sandbox.docker import DockerSandbox

        candidate = DockerSandbox(settings.sandbox)
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
        from sness.sandbox.policy import SourceIntegrity

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
            ctx, run_id, gapfill_passes=gapfill, triage=triage, fix=fix
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

    from sness.report import run_stats

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


def cmd_wishlist(args: argparse.Namespace) -> int:
    """What the agents asked for. This is how they talk back to you."""
    settings, db = _load(args.config)
    items = db.open_wishes()
    if not items:
        console.print("wishlist empty")
        return 0
    t = Table(title="open wishes")
    t.add_column("kind")
    t.add_column("resource", overflow="fold")
    t.add_column("why", overflow="fold")
    for w in items:
        t.add_row(w.kind, w.resource, str(w.context_json.get("why", "")))
    console.print(t)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Render REPORT.md from stored records. Deterministic: no model runs."""
    settings, db = _load(args.config)
    rid = args.run or (db.latest_run() or {})["run_id"]
    from sness.report import render_report

    text = render_report(db, rid)
    if args.out:
        Path(args.out).write_text(text)
        console.print(f"wrote {args.out}")
    else:
        print(text)
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
        prog="sness", description="Autonomous vulnerability-discovery harness."
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

    common(sub.add_parser("wishlist", help="what the agents asked for")).set_defaults(
        fn=cmd_wishlist
    )

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
