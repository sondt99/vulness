"""Trace: walk the cross-repo dependency graph and hunt at the seams.

    Trace walks the cross-repo dependency graph and spawns fresh hunt tasks in consumer
    repos to catch systemic flaws at component boundaries.
        -- Cloudflare, "Build your own vulnerability harness"

A defect inside a library is a library bug. The same defect reached through an export a
dozen services call is a fleet incident, and no single-repo hunt can see the difference --
the hunter that found it was never shown the caller. This stage is the only place in the
harness that holds two repositories in view at once.

The blog is equally explicit that it is worth nothing below a threshold: *skip cross-repo
tracing entirely until you have more than one repository that matters*. So the first thing
this module does is count repositories and leave without spending a model call.

The graph itself is built deterministically, from manifests, before anything is asked of a
model. Manifests are the one place where a dependency is *declared* rather than inferred,
and an edge a parser found is an edge that exists; letting a model guess the topology would
put hallucinated repositories into the work queue. The model is asked exactly one question
that a parser cannot answer: does the consumer actually reach the defective code path.

Like every stage but Hunt, **this module never files a finding.** There is no
`db.file_finding` call here and there must never be one.
"""

from __future__ import annotations

import json
import re
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from vulness.agents.context_budget import ContextBudget, Section, occupancy_fraction, peak_occupancy
from vulness.agents.roles.context import RoleContext, TaskOutcome
from vulness.prompts import preamble, render
from vulness.state.db import new_id
from vulness.state.models import Cell, Finding, Task

# One trace task may not flood the queue. Consumer hunts compete with the source repo's own
# coverage for the same per-repo budget, and a speculative boundary hunt is worth less than
# a planned cell that has not been reached yet.
MAX_HUNTS = 6

# Manifests worth reading. Anything else either does not declare dependencies by name
# (Makefiles, lockfiles keyed by hash) or restates one of these.
_MANIFEST_GLOBS = ("pyproject.toml", "requirements*.txt", "package.json", "go.mod", "Cargo.toml")

# Directories whose manifests describe somebody else's code, not this repository's.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "dist",
        "node_modules",
        "site-packages",
        "target",
        "vendor",
        "venv",
    }
)

# PEP 508 and friends: the name is everything up to the first separator, and no ecosystem
# lets a package name start with one. Matching the head is enough for every manifest here.
_REQ_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_GO_MAJOR = re.compile(r"^v\d+$")
_PUNCT = re.compile(r"[_.\s]+")
_KEBAB = re.compile(r"[^a-z0-9]+")

_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


# --------------------------------------------------------------------------- manifests


def _read(path: Path) -> str:
    """Never let an unreadable manifest end the stage. A missing edge beats a dead task."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _req_name(spec: str) -> str:
    match = _REQ_NAME.match(spec)
    return match.group(1) if match else ""


def _parse_pyproject(path: Path) -> tuple[set[str], set[str]]:
    """Returns (names this project publishes under, names it declares)."""
    try:
        data = tomllib.loads(_read(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return set(), set()
    own: set[str] = set()
    deps: set[str] = set()
    raw_project = data.get("project")
    project: dict[str, Any] = raw_project if isinstance(raw_project, dict) else {}
    if isinstance(project.get("name"), str):
        own.add(project["name"])
    for spec in project.get("dependencies") or []:
        if isinstance(spec, str) and (name := _req_name(spec)):
            deps.add(name)
    for group in (project.get("optional-dependencies") or {}).values():
        for spec in group if isinstance(group, list) else []:
            if isinstance(spec, str) and (name := _req_name(spec)):
                deps.add(name)
    # PEP 735 dependency groups live at the top level, outside [project].
    for group in (data.get("dependency-groups") or {}).values():
        for spec in group if isinstance(group, list) else []:
            if isinstance(spec, str) and (name := _req_name(spec)):
                deps.add(name)

    poetry = ((data.get("tool") or {}).get("poetry")) or {}
    if isinstance(poetry, dict):
        if isinstance(poetry.get("name"), str):
            own.add(poetry["name"])
        blocks = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
        blocks += [
            g.get("dependencies")
            for g in (poetry.get("group") or {}).values()
            if isinstance(g, dict)
        ]
        for block in blocks:
            if isinstance(block, dict):
                deps.update(str(k) for k in block if str(k).lower() != "python")
    return own, deps


def _parse_requirements(path: Path) -> set[str]:
    deps: set[str] = set()
    for raw in _read(path).splitlines():
        line = raw.split("#", 1)[0].strip()
        # `-r other.txt`, `-e .`, `--index-url ...`: directives, not dependencies.
        if not line or line.startswith("-"):
            continue
        # A bare URL or local path installs something whose name is not written down here.
        if "://" in line and "@" not in line:
            continue
        if name := _req_name(line):
            deps.add(name)
    return deps


def _parse_package_json(path: Path) -> tuple[set[str], set[str]]:
    try:
        data = json.loads(_read(path) or "{}")
    except json.JSONDecodeError:
        return set(), set()
    if not isinstance(data, dict):
        return set(), set()
    own = {data["name"]} if isinstance(data.get("name"), str) else set()
    deps: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = data.get(key)
        if isinstance(block, dict):
            deps.update(str(k) for k in block)
    return own, deps


def _parse_go_mod(path: Path) -> tuple[set[str], set[str]]:
    own: set[str] = set()
    deps: set[str] = set()
    in_require = False
    for raw in _read(path).splitlines():
        line = raw.split("//", 1)[0].strip()
        if not line:
            continue
        if line.startswith("module "):
            own.add(line.split(None, 1)[1].strip())
            continue
        if line.startswith("require"):
            rest = line[len("require") :].strip()
            if rest.startswith("("):
                in_require = True
                rest = rest[1:].strip()
            if rest:
                deps.add(rest.split()[0])
            continue
        if in_require:
            # `replace` and `exclude` blocks never open one, so anything reached here is a
            # require entry: `module/path v1.2.3`.
            if line.startswith(")"):
                in_require = False
                continue
            deps.add(line.split()[0])
    return own, deps


def _parse_cargo(path: Path) -> tuple[set[str], set[str]]:
    try:
        data = tomllib.loads(_read(path))
    except (tomllib.TOMLDecodeError, ValueError):
        return set(), set()
    own: set[str] = set()
    package = data.get("package")
    if isinstance(package, dict) and isinstance(package.get("name"), str):
        own.add(package["name"])
    deps: set[str] = set()
    blocks: list[Any] = [
        data.get(k) for k in ("dependencies", "dev-dependencies", "build-dependencies")
    ]
    workspace = data.get("workspace")
    if isinstance(workspace, dict):
        blocks.append(workspace.get("dependencies"))
    # Platform-gated dependencies are still dependencies: [target.'cfg(unix)'.dependencies].
    for target in (data.get("target") or {}).values():
        if isinstance(target, dict):
            blocks += [
                target.get(k) for k in ("dependencies", "dev-dependencies", "build-dependencies")
            ]
    for block in blocks:
        if isinstance(block, dict):
            deps.update(str(k) for k in block)
    return own, deps


def _manifest_files(repo: Path) -> list[Path]:
    """Repo root plus one level of subdirectories.

    Deeper than that, a manifest is a vendored copy or a test fixture far more often than a
    real declaration, and an `rglob` that wanders into `node_modules` costs more wall-clock
    than the entire rest of the stage.
    """
    roots = [repo]
    try:
        roots += [
            d
            for d in repo.iterdir()
            if d.is_dir() and d.name not in _SKIP_DIRS and not d.name.startswith(".")
        ]
    except OSError:
        return []
    found: list[Path] = []
    for root in roots:
        for pattern in _MANIFEST_GLOBS:
            try:
                found.extend(sorted(p for p in root.glob(pattern) if p.is_file()))
            except OSError:
                continue
    return found


def _aliases(raw: str) -> set[str]:
    """Every spelling one component might be named by, normalised for comparison.

    Ecosystems disagree about punctuation and namespacing: PyPI folds `_` and `.` onto `-`,
    npm scopes as `@org/pkg`, Go uses a full module path with a `/v2` major suffix. One
    repository is plausibly all of those at once, so edges are matched by intersecting
    alias sets rather than by comparing strings.
    """
    s = raw.strip().lower().rstrip("/")
    if not s:
        return set()
    out = {s}
    if s.startswith("@") and "/" in s:
        out.add(s.split("/", 1)[1])
    if "/" in s:
        parts = [p for p in s.split("/") if p]
        while parts and _GO_MAJOR.match(parts[-1]):
            parts.pop()
        if parts:
            out.add(parts[-1])
    # Two characters is not a name, it is a coincidence waiting to match every manifest.
    return {a for a in (_PUNCT.sub("-", x).strip("-") for x in out) if len(a) >= 3}


@dataclass(slots=True)
class _RepoManifest:
    """What one repository declares about itself and about what it pulls in."""

    repo_id: str
    name: str
    path: Path | None
    reachable: bool  # present in ctx.repo_paths, so a hunt can actually be dispatched there
    publishes: set[str] = field(default_factory=set)  # aliases others would depend on it by
    deps: set[str] = field(default_factory=set)  # declared dependency names, verbatim
    dep_aliases: set[str] = field(default_factory=set)
    manifests: list[str] = field(default_factory=list)


def _scan(repo_id: str, name: str, path: Path | None, *, reachable: bool) -> _RepoManifest:
    manifest = _RepoManifest(repo_id=repo_id, name=name, path=path, reachable=reachable)
    # The identity the graph starts from, before any manifest is read: a repository with no
    # manifest at all can still be depended upon by name.
    manifest.publishes |= _aliases(repo_id) | _aliases(name)
    if path is None or not path.is_dir():
        return manifest
    manifest.publishes |= _aliases(path.name)

    for file in _manifest_files(path):
        filename = file.name
        if filename == "pyproject.toml":
            own, deps = _parse_pyproject(file)
        elif filename.startswith("requirements") and filename.endswith(".txt"):
            own, deps = set(), _parse_requirements(file)
        elif filename == "package.json":
            own, deps = _parse_package_json(file)
        elif filename == "go.mod":
            own, deps = _parse_go_mod(file)
        elif filename == "Cargo.toml":
            own, deps = _parse_cargo(file)
        else:
            continue
        if not own and not deps:
            continue
        for declared in own:
            manifest.publishes |= _aliases(declared)
        manifest.deps |= deps
        manifest.manifests.append(
            filename if file.parent == path else f"{file.parent.name}/{filename}"
        )
    for dep in manifest.deps:
        manifest.dep_aliases |= _aliases(dep)
    return manifest


def _known_repos(ctx: RoleContext) -> list[tuple[str, str, Path | None, bool]]:
    """Every repository this run could reason about: (repo_id, name, path, reachable).

    `repo_paths` is authoritative -- it is what `ctx.repo_path()` resolves and therefore
    the only place a hunt can be dispatched -- but the `repos` table carries the human name
    a manifest is far more likely to spell, so both feed the graph.
    """
    rows: dict[str, tuple[str, str, Path | None, bool]] = {}
    for row in ctx.db.query("SELECT repo_id, name, path FROM repos"):
        repo_id = str(row["repo_id"])
        recorded = str(row["path"] or "")
        rows[repo_id] = (
            repo_id,
            str(row["name"] or repo_id),
            Path(recorded) if recorded else None,
            False,
        )
    for repo_id, path in ctx.repo_paths.items():
        name = rows[repo_id][1] if repo_id in rows else path.name
        rows[repo_id] = (repo_id, name, path, True)
    # Keyed on repo_id explicitly: a bare tuple sort would compare a `Path` against `None`
    # for any two repos that ever shared an id, and stage order must not depend on that.
    return sorted(rows.values(), key=lambda r: r[0])


# ------------------------------------------------------------------------- prompt blocks


def _dependency_block(target: _RepoManifest, upstream: list[_RepoManifest]) -> str:
    lines = [
        f"- manifests read: {', '.join(target.manifests) or '(none found)'}",
        f"- declared dependencies: {len(target.deps)}",
        f"- names this repository publishes under: {', '.join(sorted(target.publishes)) or '(none)'}",
    ]
    if upstream:
        lines.append("- dependencies that are themselves repositories in this run:")
        lines += [f"    - `{m.repo_id}` ({m.name})" for m in upstream]
    return "\n".join(lines)


def _consumer_block(target: _RepoManifest, consumers: list[_RepoManifest]) -> str:
    lines: list[str] = []
    for m in consumers:
        matched = sorted(target.publishes & m.dep_aliases)
        lines.append(
            f"- `{m.repo_id}` ({m.name}) declares it as {', '.join(f'`{x}`' for x in matched)}"
            f" in {', '.join(m.manifests) or '(name match only)'}"
        )
    return "\n".join(lines) or "_(none)_"


def _findings_block(findings: list[Finding]) -> str:
    items = [
        {
            "finding_id": f.finding_id,
            "title": f.title,
            "attack_class": f.attack_class,
            "area": f.area,
            "severity": f.severity_json.get("overall_severity"),
            "threat_model": f.threat_model_json,
            # The trace is what says where the defect physically lives; the rest of the
            # record is argument the model was told not to reopen.
            "trace": f.trace_json,
            "remediation": f.remediation_json.get("strategy"),
        }
        for f in findings
    ]
    return "```json\n" + json.dumps(items, indent=2) + "\n```"


# ------------------------------------------------------------------------------ seeding


def _kebab(value: str, fallback: str) -> str:
    cleaned = _KEBAB.sub("-", str(value).lower()).strip("-")[:60]
    return cleaned or fallback


def _overlaps(a: str, b: str) -> bool:
    a, b = a.strip("./"), b.strip("./")
    return bool(a) and bool(b) and (a == b or a.startswith(f"{b}/") or b.startswith(f"{a}/"))


def _match_cell(
    ctx: RoleContext, run_id: str, repo_id: str, attack_class: str, paths: list[str]
) -> Cell | None:
    """Land the spawned hunt on a real coverage cell where one already exists.

    Without this the consumer hunt is invisible to the grid: it files findings nobody
    counts, and Gapfill keeps re-hunting a cell that Trace already covered.
    """
    candidates = [c for c in ctx.db.cells(run_id, repo_id) if c.attack_class == attack_class]
    for cell in candidates:
        if any(_overlaps(p, cp) for p in paths for cp in cell.paths_json):
            return cell
    return candidates[0] if candidates else None


def _build_hunt(
    *,
    run_id: str,
    repo_id: str,
    parent_task_id: str,
    priority: int,
    cell_id: str | None,
    seed: dict[str, Any],
) -> Task:
    """Construct the consumer-repo hunt, keeping its provenance honest.

    `docs/PLAN.md` lists `trace` among the task origins, but the `TaskOrigin` literal in
    `state/models.py` has not caught up, and a run must not die over a label. Ask for the
    true origin; fall back to `sibling_fork` -- also "a task another agent's discovery
    spawned" -- only if the enum rejects it. `seed_json` records the real provenance either
    way, so the audit trail survives the schema lagging behind the pipeline.
    """
    fields: dict[str, Any] = {
        "task_id": new_id("t"),
        "run_id": run_id,
        "repo_id": repo_id,
        "stage": "hunt",
        "kind": "hunt",
        "cell_id": cell_id,
        "parent_task_id": parent_task_id,
        "priority": priority,
        "prompt": "(rendered at dispatch)",
        "seed_json": seed,
    }
    try:
        return Task(origin="trace", **fields)  # type: ignore[arg-type]
    except ValidationError:
        return Task(origin="sibling_fork", **fields)


def _already_seeded(ctx: RoleContext, run_id: str) -> set[tuple[str, str]]:
    """(consumer repo, origin finding) pairs Trace has already spawned a hunt for."""
    seen: set[tuple[str, str]] = set()
    for t in ctx.db.iter_tasks(run_id, kind="hunt"):
        if origin_finding := str(t.seed_json.get("origin_finding_id") or ""):
            seen.add((t.repo_id, origin_finding))
    return seen


# --------------------------------------------------------------------------------- role


async def run_trace(ctx: RoleContext, task: Task) -> TaskOutcome:
    started = time.monotonic()
    known = _known_repos(ctx)

    # The threshold the blog is explicit about. One repository has no component boundary to
    # cross, so there is no question for a model to answer and no hunt to spawn.
    if len(known) < 2:
        note = f"cross-repo tracing needs more than one repo; this run knows of {len(known)}"
        ctx.db.event(
            "trace.skipped",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            reason=note,
            repos=[r[0] for r in known],
        )
        return TaskOutcome(
            status="done",
            exit_reason="ok",
            duration_s=time.monotonic() - started,
            detail={
                "dependencies_found": 0,
                "consumer_repos": [],
                "hunts_enqueued": 0,
                "note": note,
            },
        )

    manifests = {
        repo_id: _scan(repo_id, name, path, reachable=reachable)
        for repo_id, name, path, reachable in known
    }
    target = manifests.get(task.repo_id) or _scan(
        task.repo_id, task.repo_id, ctx.repo_paths.get(task.repo_id), reachable=True
    )
    others = [m for m in manifests.values() if m.repo_id != target.repo_id]

    # Two directions, and only one of them is this task's job. Repositories the target
    # pulls in are context; repositories that pull the target in are where its confirmed
    # defects travel to, so those are the ones that get hunted.
    upstream = [m for m in others if m.publishes & target.dep_aliases]
    consumers = [m for m in others if target.publishes & m.dep_aliases]
    reachable_consumers = [m for m in consumers if m.reachable]
    confirmed = ctx.db.findings(task.run_id, verdict="confirmed", repo_id=task.repo_id)

    base_detail: dict[str, Any] = {
        "dependencies_found": len(target.deps),
        "consumer_repos": [m.repo_id for m in consumers],
        "hunts_enqueued": 0,
        "upstream_repos": [m.repo_id for m in upstream],
        "manifests_read": target.manifests,
    }

    # Same discipline as the single-repo guard: with nobody downstream, or nothing confirmed
    # to push downstream, the model has no decision to make and the task would buy silence.
    if not reachable_consumers or not confirmed:
        note = (
            "no consumer repo in this run declares a dependency on it"
            if not reachable_consumers
            else "no confirmed findings to propagate yet"
        )
        ctx.db.event(
            "trace.skipped",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            reason=note,
            dependencies=len(target.deps),
            consumers=[m.repo_id for m in consumers],
        )
        return TaskOutcome(
            status="done",
            exit_reason="ok",
            duration_s=time.monotonic() - started,
            detail={**base_detail, "note": note},
        )

    instruction = render(
        "trace",
        repo_name=target.name,
        repo_path=str(target.path or ctx.repo_paths.get(task.repo_id, Path("."))),
        dependency_block=_dependency_block(target, upstream),
        consumer_block="{CONSUMERS}",
        findings_block="{FINDINGS}",
    )
    # The consumer list is the answer key -- a propagation naming a repo that is not on it
    # is discarded downstream -- so it outranks the findings dump, which can be trimmed to
    # its most recent entries and still leave the model something real to reason about.
    budget = ContextBudget(ctx.settings.hunt.model, occupancy=ctx.settings.budget.context_occupancy)
    head, _, rest = instruction.partition("{CONSUMERS}")
    mid, _, foot = rest.partition("{FINDINGS}")
    prompt, fit = budget.fit(
        [
            Section("instruction_head", head, priority=0),
            Section(
                "consumers",
                _consumer_block(target, reachable_consumers),
                priority=1,
                floor_chars=400,
            ),
            Section("instruction_mid", mid, priority=0),
            Section("findings", _findings_block(confirmed), priority=2, floor_chars=2000),
            Section("instruction_tail", foot, priority=0),
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
            detail=fit.summary(),
        )

    result = await ctx.hunt_agent.run(
        prompt,
        system=preamble(),
        cwd=ctx.repo_paths.get(task.repo_id),
        timeout_s=ctx.settings.hunt.timeout_s,
        schema={"export_surface": "list", "propagations": "list"},
    )
    duration = time.monotonic() - started

    if not result.ok:
        ctx.db.event(
            "trace.failed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="error",
            classification=result.classification,
            error=result.error,
        )
        return TaskOutcome(
            status="failed",
            exit_reason=result.classification,
            duration_s=duration,
            tokens_in=result.tokens_in,
            tokens_out=result.tokens_out,
            cost_usd=result.cost_usd,
        )

    peak = peak_occupancy(result.raw_events)
    frac = occupancy_fraction(peak, ctx.settings.hunt.model)
    if frac > ctx.settings.budget.context_occupancy:
        ctx.db.event(
            "context.exceeded",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            peak_tokens=peak,
            occupancy=round(frac, 3),
            target=ctx.settings.budget.context_occupancy,
        )

    payload = result.extract_json() or {}
    exports = [e for e in (payload.get("export_surface") or []) if isinstance(e, dict)]
    enqueued = _seed_consumer_hunts(
        ctx,
        task,
        payload=payload,
        confirmed={f.finding_id: f for f in confirmed},
        consumers={m.repo_id: m for m in reachable_consumers},
    )

    ctx.db.event(
        "trace.complete",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        dependencies=len(target.deps),
        consumers=[m.repo_id for m in consumers],
        exports=len(exports),
        enqueued=enqueued,
    )
    return TaskOutcome(
        status="done",
        exit_reason="ok",
        duration_s=duration,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost_usd=result.cost_usd,
        detail={
            **base_detail,
            "hunts_enqueued": enqueued,
            "export_surface": exports[:20],
            "notes": str(payload.get("notes", ""))[:600],
            "peak_context_tokens": peak,
            "context_occupancy": round(frac, 3),
            "context_fit": fit.summary(),
        },
    )


def _seed_consumer_hunts(
    ctx: RoleContext,
    task: Task,
    *,
    payload: dict[str, Any],
    confirmed: dict[str, Finding],
    consumers: dict[str, _RepoManifest],
) -> int:
    """Turn accepted propagations into hunts, dropping everything unverifiable.

    Each claim is checked against the harness's own facts before it costs a task: the
    finding must be one we showed the model, the consumer must be a repository we can
    actually dispatch into, and the suggested paths must exist on disk. A hunt seeded with
    an invented path burns a whole task discovering the path is invented.
    """
    raw = [p for p in (payload.get("propagations") or []) if isinstance(p, dict)]
    accepted = [p for p in raw if p.get("reaches_consumer") is True]
    accepted.sort(key=lambda p: _CONFIDENCE_RANK.get(str(p.get("confidence", "")).lower(), 3))

    seeded = _already_seeded(ctx, task.run_id)
    enqueued = 0
    for prop in accepted:
        if enqueued >= MAX_HUNTS:
            break
        finding = confirmed.get(str(prop.get("finding_id", "")))
        consumer = consumers.get(str(prop.get("consumer_repo", "")))
        if finding is None or consumer is None:
            ctx.db.event(
                "trace.propagation_rejected",
                run_id=task.run_id,
                repo_id=task.repo_id,
                task_id=task.task_id,
                level="warn",
                reason="unknown finding or consumer repo",
                finding_id=str(prop.get("finding_id", ""))[:40],
                consumer_repo=str(prop.get("consumer_repo", ""))[:60],
            )
            continue
        key = (consumer.repo_id, finding.finding_id)
        if key in seeded:
            continue

        consumer_root = ctx.repo_paths[consumer.repo_id]
        paths = [
            p
            for p in (prop.get("where_to_look") or [])
            if isinstance(p, str) and p.strip() and (consumer_root / p.strip().lstrip("/")).exists()
        ] or ["."]
        attack_class = _kebab(
            str(prop.get("attack_class") or ""), finding.attack_class or "logic-and-state"
        )
        cell = _match_cell(ctx, task.run_id, consumer.repo_id, attack_class, paths)
        lead = (
            f"{finding.title} was confirmed in `{task.repo_id}`, which this repository "
            f"depends on. {str(prop.get('lead') or prop.get('why') or '').strip()}"
        )[:1200]

        ctx.db.enqueue(
            _build_hunt(
                run_id=task.run_id,
                repo_id=consumer.repo_id,
                parent_task_id=task.task_id,
                # Ahead of ordinary seeded hunts: a boundary flaw with a known root cause
                # is the highest-prior lead the harness ever produces.
                priority=max(0, task.priority - 10),
                cell_id=cell.cell_id if cell else None,
                seed={
                    "attack_class": attack_class,
                    "area": cell.area if cell else "cross-repo-boundary",
                    "paths": cell.paths_json if cell else paths,
                    "lead": lead,
                    "origin_finding_id": finding.finding_id,
                    "origin_repo_id": task.repo_id,
                    "origin_stage": "trace",
                    "confidence": str(prop.get("confidence", ""))[:20],
                },
            )
        )
        seeded.add(key)
        enqueued += 1
    return enqueued
