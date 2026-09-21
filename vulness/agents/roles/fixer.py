"""VVS fixing: propose a patch, and prove the regression test flips.

    Generates patches, runs regression tests; blocks on fail->pass flip ... never merges
    without human review.
        -- Cloudflare, "Build your own vulnerability harness"

Two invariants define this stage, and they pull in the same direction.

**The harness never writes to the target.** Every artefact -- the diff, the test, the
proposal -- lands under `work_dir/<run>/<repo>/fixes/<finding>/`. The patched tree that the
test runs against is a throwaway copy in that directory, never the repository under audit.
`_out_dir` refuses to proceed if a misconfigured `work_dir` would put the two in the same
place, because a harness that edits its target has destroyed the only thing that made its
findings believable.

**A patch is not cleared until the test flips.** The test must FAIL against the untouched
source and PASS against the patched copy. One half alone is worthless: a test that passes
before the patch proves nothing about the bug, and a test that fails after it proves nothing
about the fix. Anything short of both halves comes back `flip_verified: false`, and the blog's
warning is why that matters --

    Left to patch freely, a model will happily fix a security bug while quietly breaking an
    unrelated feature.

-- so the output is a **proposal for a human reviewer**, never an applied change. Nothing in
this module has a code path that writes into the repository, and nothing should acquire one.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path

from vulness.agents.context_budget import ContextBudget, Section
from vulness.agents.roles.context import RoleContext, TaskOutcome
from vulness.prompts import preamble, render
from vulness.sandbox.policy import SCRATCH_MOUNT, TARGET_MOUNT, SandboxLimits
from vulness.state.db import new_id
from vulness.state.models import Finding, Task, Validation

# A patch for a finding nobody is going to read is a wasted GLM call.
_NOT_FIXABLE = frozenset({"rejected", "duplicate"})

_SINK_FILE_CHARS = 32_000  # the file being patched: the model needs real context lines
_OTHER_FILE_CHARS = 8_000  # everything else is orientation, not diff material
_MAX_SOURCE_CHARS = 52_000
_MAX_FILE_BYTES = 2_000_000
_LOG_TAIL = 2_000

# Skipped when copying the tree to patch: `.git` doubles the copy for nothing (the working
# tree is what gets tested), and caches are regenerated. Dependencies are deliberately NOT
# skipped -- a regression test that needs them must still find them.
_COPY_IGNORE = shutil.ignore_patterns(
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox"
)

# Model-authored diffs drift: fuzzy context, miscounted @@ headers, `a/` prefixes present or
# not. `--recount` fixes the counts, and trying -p1 then -p0 covers both prefix habits. If
# none of these apply the patch, the patch does not apply -- that is a real answer, not a
# reason to hand-edit it into place.
_APPLIERS: tuple[tuple[str, ...], ...] = (
    ("git", "apply", "--recount", "--whitespace=nowarn", "-p1"),
    ("git", "apply", "--recount", "--whitespace=nowarn", "-p0"),
    ("patch", "-p1", "--batch", "--forward", "--no-backup-if-mismatch", "-i"),
    ("patch", "-p0", "--batch", "--forward", "--no-backup-if-mismatch", "-i"),
)
_APPLY_TIMEOUT_S = 60.0


@dataclass
class _Flip:
    """Whether the regression test actually flipped, and the evidence either way."""

    verified: bool = False
    reason: str = "not attempted"
    pre_exit: int | None = None
    post_exit: int | None = None
    applier: str = ""
    logs: dict[str, str] = field(default_factory=dict)

    def as_detail(self) -> dict:
        return {
            "flip_verified": self.verified,
            "reason": self.reason,
            "unpatched_exit": self.pre_exit,
            "patched_exit": self.post_exit,
            "applied_with": self.applier,
            "logs": self.logs,
        }


def _read(root: Path, rel: str) -> str | None:
    """Read a repo-relative file, refusing anything that escapes the tree under audit."""
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        return None
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(errors="replace")
    except OSError:
        return None


def _safe_name(name: str, default: str) -> str:
    """The filename comes from the model, so it is untrusted input to a path join."""
    base = Path(name or default).name
    return base if base and base not in (".", "..") else default


def _sink_file(f: Finding) -> str:
    """The file the patch most likely belongs in: the sink, else the first cited location."""
    steps = [s for s in f.trace_json if isinstance(s, dict) and s.get("file")]
    for step in steps:
        if step.get("kind") == "sink":
            return str(step["file"]).lstrip("/")
    if steps:
        return str(steps[0]["file"]).lstrip("/")
    items = [e for e in (f.evidence_json or {}).get("items", []) if isinstance(e, dict)]
    return str(items[0].get("file", "")).lstrip("/") if items else ""


def _cited_files(f: Finding) -> list[str]:
    """Every distinct file the finding touches, sink first: the patch goes in one of these."""
    order: list[str] = []
    sink = _sink_file(f)
    if sink:
        order.append(sink)
    rows = [s for s in f.trace_json if isinstance(s, dict)]
    rows += [e for e in (f.evidence_json or {}).get("items", []) if isinstance(e, dict)]
    for row in rows:
        rel = str(row.get("file", "")).lstrip("/")
        if rel and rel not in order:
            order.append(rel)
    return order


def _source_block(repo: Path, f: Finding) -> str:
    """Line-numbered source for the cited files.

    Numbered because a unified diff needs true line numbers and the model has no filesystem
    to count with; the prompt is explicit that the `NNN| ` prefix is display only. The sink
    file gets the large budget -- it is the one the hunks land in.
    """
    root = repo.resolve()
    chunks: list[str] = []
    spent = 0
    for i, rel in enumerate(_cited_files(f)):
        text = _read(root, rel)
        if text is None:
            chunks.append(f"### `{rel}`\n\n_Not readable at judgement time; it may have moved._")
            continue
        lines = text.splitlines()
        limit = _SINK_FILE_CHARS if i == 0 else _OTHER_FILE_CHARS
        body = "\n".join(f"{n:>5}| {line}" for n, line in enumerate(lines, 1))
        truncated = len(body) > limit
        body = body[:limit]
        note = f" - {len(lines)} lines" + (", truncated for context budget" if truncated else "")
        chunk = f"### `{rel}`{note}\n\n```\n{body}\n```"
        if spent + len(chunk) > _MAX_SOURCE_CHARS:
            chunks.append(f"_{len(_cited_files(f)) - i} further cited file(s) omitted._")
            break
        spent += len(chunk)
        chunks.append(chunk)
    return "\n\n".join(chunks) or "_The finding cites no readable file._"


def _finding_block(f: Finding) -> str:
    return json.dumps(
        {
            "finding_id": f.finding_id,
            "title": f.title,
            "attack_class": f.attack_class,
            "threat_model": f.threat_model_json,
            "trace": f.trace_json,
            "evidence": f.evidence_json,
            "severity": f.severity_json,
            "remediation": f.remediation_json,
            "proposed_poc": f.poc_json,
        },
        indent=2,
    )[:14000]


def _out_dir(ctx: RoleContext, task: Task, repo: Path) -> Path:
    """Where the proposal is written. Refuses to be anywhere inside the target.

    This is the enforcement point for the read-only rule. `work_dir` is operator-configured
    and defaults to a relative path, so a run started from inside the repository under audit
    would otherwise write the patch, the test and a whole second copy of the tree into the
    code being audited -- and every integrity check downstream would be right to reject the
    run afterwards.
    """
    out = (
        ctx.settings.work_dir / task.run_id / task.repo_id / "fixes" / (task.finding_id or "x")
    ).resolve()
    try:
        out.relative_to(repo.resolve())
    except ValueError:
        return out
    raise ValueError(
        f"work_dir {ctx.settings.work_dir} resolves inside the target repository {repo}; "
        "the harness must never write into a tree it audits"
    )


async def _apply_patch(tree: Path, patch_path: Path) -> tuple[bool, str, str]:
    """Apply the diff to a throwaway copy. Returns (applied, applier, detail).

    `tree` is always a copy under `work_dir` -- see `_out_dir`. Nothing here may be pointed
    at the repository under audit.
    """
    attempts: list[str] = []
    for argv in _APPLIERS:
        if shutil.which(argv[0]) is None:
            continue
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                str(patch_path),
                cwd=str(tree),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(proc.communicate(), timeout=_APPLY_TIMEOUT_S)
        except (OSError, TimeoutError) as exc:
            attempts.append(f"{' '.join(argv)}: {type(exc).__name__}")
            continue
        if proc.returncode == 0:
            return True, " ".join(argv), ""
        detail = (err or out).decode(errors="replace").strip()
        attempts.append(f"{' '.join(argv)}: exit {proc.returncode} {detail[:200]}")
    if not attempts:
        return False, "", "neither `git` nor `patch` is available to apply the diff"
    return False, "", "; ".join(attempts)[:800]


async def _verify_flip(
    ctx: RoleContext,
    task: Task,
    repo: Path,
    out_dir: Path,
    patch_path: Path,
    test_name: str,
    test_source: str,
    command: list[str],
) -> _Flip:
    """Run the test unpatched (expect FAIL), then patched (expect PASS).

    The unpatched run goes through `run_poc`, so it also proves the test did not edit the
    target to manufacture its own failure. The patched run targets a copy, and hashing that
    copy proves the test did not edit its way to a pass either.
    """
    if ctx.sandbox is None:
        return _Flip(reason="no sandbox available; the patch is unproven")
    if not command:
        return _Flip(reason="model supplied no argv test_command; the flip cannot be run")
    if not test_source.strip():
        return _Flip(reason="model supplied no test source; there is nothing to flip")

    limits = SandboxLimits.from_config(ctx.settings.sandbox)
    flip = _Flip()

    unpatched_scratch = out_dir / "unpatched"
    unpatched_scratch.mkdir(parents=True, exist_ok=True)
    (unpatched_scratch / test_name).write_text(test_source)
    try:
        pre, unchanged, changed = await ctx.sandbox.run_poc(
            command,
            target=repo,
            scratch=unpatched_scratch,
            limits=limits,
            baseline=ctx.repo_baselines.get(task.repo_id),
        )
    except Exception as e:  # a sandbox fault must not lose the proposal
        return _Flip(reason=f"sandbox raised on the unpatched run: {type(e).__name__}: {e}"[:300])

    flip.pre_exit = pre.exit_code
    flip.logs["unpatched"] = (
        f"{pre.summary()}\n{pre.stdout[-_LOG_TAIL:]}\n{pre.stderr[-_LOG_TAIL:]}"
    )
    if not unchanged:
        return _Flip(
            reason=f"the test modified the target during the unpatched run ({', '.join(changed[:5])})",
            pre_exit=pre.exit_code,
            logs=flip.logs,
        )
    if not pre.ok:
        flip.reason = f"the unpatched run never completed: {pre.summary()}"
        return flip
    if pre.exited_clean:
        flip.reason = "the test passes against unpatched source, so it does not test the bug"
        return flip

    patched_tree = out_dir / "patched-tree"
    patched_scratch = out_dir / "patched"
    patched_scratch.mkdir(parents=True, exist_ok=True)
    (patched_scratch / test_name).write_text(test_source)
    try:
        # Copying a tree is seconds of blocking I/O; on the orchestrator's event loop that
        # stalls every other worker's timeout clock.
        await asyncio.to_thread(shutil.rmtree, patched_tree, True)
        await asyncio.to_thread(
            shutil.copytree, repo, patched_tree, symlinks=True, ignore=_COPY_IGNORE
        )
        applied, applier, detail = await _apply_patch(patched_tree, patch_path)
        flip.applier = applier
        if not applied:
            flip.reason = f"the patch does not apply cleanly: {detail}"
            flip.logs["apply"] = detail
            return flip
        post, post_unchanged, post_changed = await ctx.sandbox.run_poc(
            command, target=patched_tree, scratch=patched_scratch, limits=limits
        )
    except Exception as e:
        return _Flip(
            reason=f"sandbox raised on the patched run: {type(e).__name__}: {e}"[:300],
            pre_exit=flip.pre_exit,
            logs=flip.logs,
        )
    finally:
        # One copy of the target per finding fills a disk fast. The diff, the test and the
        # logs are the evidence worth keeping; the copy is reproducible from them.
        await asyncio.to_thread(shutil.rmtree, patched_tree, True)

    flip.post_exit = post.exit_code
    flip.logs["patched"] = (
        f"{post.summary()}\n{post.stdout[-_LOG_TAIL:]}\n{post.stderr[-_LOG_TAIL:]}"
    )
    if not post_unchanged:
        flip.reason = f"the test modified the patched tree ({', '.join(post_changed[:5])})"
        return flip
    if not post.ok:
        flip.reason = f"the patched run never completed: {post.summary()}"
        return flip
    if not post.exited_clean:
        flip.reason = f"the test still fails after the patch (exit {post.exit_code})"
        return flip

    flip.verified = True
    flip.reason = (
        f"fail->pass flip demonstrated: exit {flip.pre_exit} unpatched, 0 patched, "
        f"applied with `{applier}`"
    )
    return flip


async def run_fixer(ctx: RoleContext, task: Task) -> TaskOutcome:
    """Propose the smallest patch for one confirmed finding. Never applies it to the target."""
    if not task.finding_id:
        return TaskOutcome(status="failed", exit_reason="schema_invalid")
    finding = ctx.db.get_finding(task.finding_id)
    if finding is None:
        ctx.db.event(
            "fixer.missing_finding",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            finding_id=task.finding_id,
        )
        return TaskOutcome(status="failed", exit_reason="schema_invalid")
    if finding.verdict in _NOT_FIXABLE:
        ctx.db.event(
            "fixer.skipped",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            finding_id=finding.finding_id,
            verdict=finding.verdict,
        )
        return TaskOutcome(status="done", exit_reason="ok", detail={"skipped": finding.verdict})

    repo = ctx.repo_path(task.repo_id)
    started = time.monotonic()
    try:
        out_dir = _out_dir(ctx, task, repo)
    except ValueError as e:
        ctx.db.event(
            "fixer.unsafe_work_dir",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="error",
            finding_id=finding.finding_id,
            error=str(e),
        )
        # Misconfiguration, not weather: retrying writes into the target just as fast.
        return TaskOutcome(status="failed", exit_reason="crash", detail={"error": str(e)})

    instruction = render(
        "fixer",
        repo_name=task.repo_id,
        repo_path=str(repo),
        target_mount=TARGET_MOUNT,
        scratch_mount=SCRATCH_MOUNT,
        finding_block="{FINDING}",
        source_block="{SOURCE}",
    )
    head, sep_f, tail = instruction.partition("{FINDING}")
    mid, sep_s, foot = tail.partition("{SOURCE}")
    if not sep_f or not sep_s:
        raise KeyError("prompts/fixer.md is missing the {FINDING} or {SOURCE} slot")

    budget = ContextBudget(
        ctx.settings.hunt.model, occupancy=ctx.settings.budget.context_occupancy
    )
    prompt, fit = budget.fit(
        [
            Section("instruction_head", head, priority=0),
            Section("finding", _finding_block(finding), priority=2, floor_chars=3000),
            Section("instruction_mid", mid, priority=0),
            # Trimmed last of the two: a patch written without the real lines around the
            # defect is a patch that will not apply.
            Section("source", _source_block(repo, finding), priority=1, floor_chars=4000),
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
            stage="fixer",
            detail=fit.summary(),
        )

    result = await ctx.hunt_agent.run(
        prompt,
        system=preamble(),
        cwd=repo,
        timeout_s=ctx.settings.hunt.timeout_s,
        schema={
            "invariant": "str",
            "decision_point": "str",
            "patch": "unified diff as a single string",
            "patch_rationale": "str",
            "test_file_name": "str",
            "test_source": "str",
            "test_command": "list of argv strings",
            "blast_radius": "list",
            "review_notes": "str",
        },
    )
    duration = time.monotonic() - started

    if not result.ok:
        ctx.db.event(
            "fixer.failed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="error",
            finding_id=finding.finding_id,
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

    payload = result.extract_json() or {}
    patch = str(payload.get("patch") or "")
    if not patch.strip():
        ctx.db.event(
            "fixer.unparseable",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            finding_id=finding.finding_id,
            got=str(payload)[:120],
        )
        return TaskOutcome(status="failed", exit_reason="schema_invalid", duration_s=duration)

    test_name = _safe_name(str(payload.get("test_file_name") or ""), "test_regression.py")
    test_source = str(payload.get("test_source") or "")
    raw_command = payload.get("test_command")
    # policy.as_argv refuses a bare string on purpose; honour that here so the failure is a
    # sentence in the proposal rather than a BAD_REQUEST from the sandbox.
    command = (
        [str(part) for part in raw_command] if isinstance(raw_command, list) and raw_command else []
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    patch_path = out_dir / "patch.diff"
    # A diff without a trailing newline is rejected by `patch` and warned about by `git apply`.
    patch_path.write_text(patch if patch.endswith("\n") else patch + "\n")
    test_path = out_dir / test_name
    if test_source:
        test_path.write_text(test_source)

    flip = await _verify_flip(ctx, task, repo, out_dir, patch_path, test_name, test_source, command)

    proposal = {
        "status": "PROPOSAL - NOT APPLIED. Requires human review before it goes anywhere near "
        "the repository.",
        "finding_id": finding.finding_id,
        "title": finding.title,
        "repo_id": task.repo_id,
        "model": result.model or ctx.settings.hunt.model,
        "invariant": payload.get("invariant", ""),
        "decision_point": payload.get("decision_point", ""),
        "patch_rationale": payload.get("patch_rationale", ""),
        "expected_before": payload.get("expected_before", ""),
        "expected_after": payload.get("expected_after", ""),
        "blast_radius": payload.get("blast_radius", []),
        "review_notes": payload.get("review_notes", ""),
        "patch_path": str(patch_path),
        "test_path": str(test_path) if test_source else None,
        "test_command": command,
        "flip": flip.as_detail(),
    }
    (out_dir / "proposal.json").write_text(json.dumps(proposal, indent=2, default=str))

    # `judge` is reused deliberately: models.Validation restricts validator to a fixed set and
    # none of them is "fixer". A patch proposal is a judgement about the finding, recorded
    # alongside the reachability call, and inventing a sixth label would fail the Literal.
    ctx.db.record_validation(
        Validation(
            validation_id=new_id("v"),
            finding_id=finding.finding_id,
            task_id=task.task_id,
            validator="judge",
            model=ctx.hunt_agent.model or ctx.settings.hunt.model,
            # An unverified patch is not a disproof of anything -- it is an open question for
            # the reviewer, which is exactly what needs_validation means.
            verdict="upheld" if flip.verified else "needs_validation",
            reason=f"patch proposal ({'flip verified' if flip.verified else 'unverified'}): "
            f"{flip.reason}",
            detail_json={
                "kind": "patch_proposal",
                "human_review_required": True,
                "patch_path": str(patch_path),
                "test_path": str(test_path) if test_source else None,
                "invariant": payload.get("invariant", ""),
                "blast_radius": payload.get("blast_radius", []),
                **flip.as_detail(),
            },
        )
    )
    # Deliberately no set_verdict: a proposed fix says nothing about whether the bug is real,
    # and a fixer that could move verdicts would be grading the hunt it is patching.

    ctx.db.event(
        "fixer.complete",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        finding_id=finding.finding_id,
        flip_verified=flip.verified,
        patch_path=str(patch_path),
    )
    return TaskOutcome(
        status="done",
        exit_reason="ok",
        duration_s=duration,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost_usd=result.cost_usd,
        detail={
            "patch_path": str(patch_path),
            "test_path": str(test_path) if test_source else None,
            "flip_verified": flip.verified,
            "flip_reason": flip.reason,
            "human_review_required": True,
            "context_fit": fit.summary(),
        },
    )
