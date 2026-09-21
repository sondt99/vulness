"""VVS judgement: is the bug in something that actually runs?

    Validates production reachability ... searches wiki/Jira/git/config for applicability
    ... filters "exploitable now" from "latent".
        -- Cloudflare, "Build your own vulnerability harness"

Adversarial validation answers "is this defect real in the source". That is a different
question from "can anyone reach it", and conflating the two is how a report ends up leading
with a command injection in a file that no shipped code path calls. This stage asks the
second question, on the same model that asked the first -- GLM, not the hunter -- and it is
the last thing standing between a finding and a human's attention.

Two rules give the stage its shape:

**It never files a finding.** Like the validator, there is no `db.file_finding` here and
there must never be one. A judge that can file is a hunter with extra context.

**Absent evidence is not evidence of absence.** A repository with no Dockerfile has not told
us the code is unreachable; it has told us nothing. That case is `needs_deployment_fact`, a
question routed to a human, and never a rejection. The deterministic half of this module
exists to make that distinction honest: it reports which classes of deployment artefact it
looked for and did not find, so the model is reasoning about a stated absence instead of
inventing one.

The model gets no filesystem (see `GLMAgent.run`), so every fact it judges on is packed into
the prompt here: the current bytes at each cited line, a drift check against the hunt, the
deployment artefacts that exist, and what the earlier checks already concluded.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path
from typing import Literal

from vulness.agents.context_budget import ContextBudget, Section
from vulness.agents.roles.context import RoleContext, TaskOutcome
from vulness.prompts import preamble, render
from vulness.state.db import new_id
from vulness.state.models import Finding, Task, Validation

ValidationVerdict = Literal["upheld", "disproved", "needs_validation", "error"]

# classification -> (what goes in the validations table, what the finding's verdict becomes).
# `None` means leave the finding alone, and that is load-bearing: `set_verdict` rewrites the
# `duplicate_of` column on every call, so a redundant "still confirmed" write would silently
# unlink a finding that dedup had already merged.
_JUDGEMENT: dict[str, tuple[ValidationVerdict, str | None]] = {
    "exploitable_now": ("upheld", None),
    "latent": ("upheld", None),
    "not_reachable": ("disproved", "rejected"),
    "needs_deployment_fact": ("needs_validation", "needs_validation"),
}

# A rejected finding has no reachability left to establish; a duplicate is judged through its
# canonical. Both are a wasted GLM call and, worse, a destructive one -- see above.
_NOT_JUDGEABLE = frozenset({"rejected", "duplicate"})

_WINDOW = 6  # lines of context either side of a cited line
_MAX_LOCATIONS = 12
_MAX_FILE_BYTES = 2_000_000
_PER_CATEGORY = 3  # deployment artefacts sampled per kind: breadth beats depth here
_DEPLOY_EXCERPT = 1400

# Machine-generated or vendored trees. A Dockerfile inside `node_modules` describes somebody
# else's deployment, and walking these costs more than the whole judgement.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        "vendor",
        "third_party",
    }
)

# What "deployment context in the repo" means, concretely. The model is told which of these
# were searched for and came back empty, so it can distinguish "this is not deployed" from
# "this repository does not say how it is deployed".
_DEPLOYMENT_KINDS: tuple[str, ...] = (
    "container build",
    "compose topology",
    "kubernetes manifest",
    "CI pipeline",
    "terraform",
    "example environment",
    "process supervisor",
    "deployment config",
)

_CONFIG_PREFIXES = (
    "config/",
    "configs/",
    "deploy/",
    "deployment/",
    "deployments/",
    "k8s/",
    "kubernetes/",
    "charts/",
    "helm/",
    "manifests/",
    "infra/",
    "infrastructure/",
)


@dataclass(frozen=True)
class _Slot:
    """One trimmable block in the rendered prompt, and how readily it may be shed."""

    marker: str
    name: str
    priority: int
    floor_chars: int


# Order must match the placeholder order in prompts/judge.md. Deployment evidence is shed
# first because the prompt already tells the model how to reason about its absence -- a
# trimmed block degrades the answer toward `needs_deployment_fact`, which is the safe
# direction. The claim itself is trimmed last: without it there is nothing to judge.
_SLOTS: tuple[_Slot, ...] = (
    _Slot("{FINDING}", "finding", 1, 4000),
    _Slot("{VALIDATIONS}", "validations", 3, 300),
    _Slot("{SOURCE}", "source", 2, 1500),
    _Slot("{DEPLOYMENT}", "deployment", 4, 800),
)


def _read(root: Path, rel: str) -> str | None:
    """Read a repo-relative file, refusing anything that escapes the tree under audit."""
    path = (root / rel).resolve()
    try:
        path.relative_to(root)
    except ValueError:
        # A trace that cites /etc/passwd is a finding about the hunter, not about the repo.
        return None
    if not path.is_file():
        return None
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return None
        return path.read_text(errors="replace")
    except OSError:
        return None


def _locations(f: Finding) -> list[tuple[str, int, str, str]]:
    """Every (file, line, kind, description) the finding points at, in narrative order."""
    out: list[tuple[str, int, str, str]] = []
    seen: set[tuple[str, int]] = set()
    steps = [s for s in f.trace_json if isinstance(s, dict)]
    items = [e for e in (f.evidence_json or {}).get("items", []) if isinstance(e, dict)]
    for default_kind, rows in (("trace", steps), ("evidence", items)):
        for row in rows:
            file = str(row.get("file", "")).lstrip("/")
            try:
                line = int(row.get("line") or 0)
            except (TypeError, ValueError):
                continue
            if not file or line < 1 or (file, line) in seen:
                continue
            seen.add((file, line))
            out.append(
                (
                    file,
                    line,
                    str(row.get("kind") or default_kind),
                    str(row.get("description") or ""),
                )
            )
    return out


def _source_block(repo: Path, f: Finding) -> str:
    """The current bytes at each cited line, plus a deterministic drift check.

    The hunt may have been hours ago. Whether the cited lines still exist is plain code's
    job, not the model's: a model asked whether a line number is stale will agree with
    whichever answer the prompt leans toward.
    """
    locs = _locations(f)
    if not locs:
        return (
            "**Drift check:** the finding cites no file or line at all. Every reachability "
            "claim in it is unsourced."
        )

    root = repo.resolve()
    chunks: list[str] = []
    alive = 0
    for file, line, kind, description in locs[:_MAX_LOCATIONS]:
        header = f"### `{file}:{line}` - {kind}" + (f"\n\n_{description}_" if description else "")
        text = _read(root, file)
        if text is None:
            chunks.append(f"{header}\n\n_File is gone, unreadable, or outside the repository._")
            continue
        lines = text.splitlines()
        if line > len(lines):
            chunks.append(
                f"{header}\n\n_File is now {len(lines)} lines; the cited line is past the end._"
            )
            continue
        alive += 1
        lo = max(1, line - _WINDOW)
        hi = min(len(lines), line + _WINDOW)
        body = "\n".join(
            f"{n:>5}{'>' if n == line else '|'} {lines[n - 1]}" for n in range(lo, hi + 1)
        )
        chunks.append(f"{header}\n\n```\n{body}\n```")

    shown = len(locs[:_MAX_LOCATIONS])
    drift = (
        f"**Drift check:** {alive} of {shown} cited location(s) still exist at the quoted line"
        f"{f' (of {len(locs)} cited in total)' if len(locs) > shown else ''}. "
    )
    drift += (
        "The source has moved since the hunt; treat anything below marked gone as a claim "
        "about code that no longer exists."
        if alive < shown
        else "The tree has not moved under this finding."
    )
    return drift + "\n\n" + "\n\n".join(chunks)


def _deployment_category(rel: str, name: str) -> str | None:
    """Classify one repo-relative path as deployment evidence, or not evidence at all."""
    low = name.lower()
    if low in ("dockerfile", "containerfile") or low.startswith("dockerfile."):
        return "container build"
    if low.endswith(".dockerfile"):
        return "container build"
    if fnmatch(low, "docker-compose*.y*ml") or fnmatch(low, "compose*.y*ml"):
        return "compose topology"
    if (
        rel.startswith((".github/workflows/", ".circleci/", ".buildkite/"))
        or low in (".gitlab-ci.yml", "jenkinsfile", "azure-pipelines.yml", ".travis.yml")
        or fnmatch(low, "*.gitlab-ci.yml")
    ):
        return "CI pipeline"
    if low.endswith((".tf", ".tfvars")):
        return "terraform"
    # `.env.example` documents the knobs; a bare `.env` is live secrets and is never read --
    # this harness must not vacuum credentials into a third-party API prompt.
    if low.startswith(".env.") and not low.endswith((".key", ".pem")):
        return "example environment"
    if low == "procfile" or low.endswith((".service", ".nomad")) or low == "supervisord.conf":
        return "process supervisor"
    if rel.startswith(_CONFIG_PREFIXES):
        return "deployment config"
    return None


def _looks_like_k8s(path: Path) -> bool:
    try:
        with path.open("r", errors="replace") as fh:
            head = fh.read(2048)
    except OSError:
        return False
    return "apiVersion:" in head and "kind:" in head


def _deployment_block(repo: Path) -> str:
    """Deployment artefacts that exist in the repo, and an explicit list of those that do not.

    The second half is the point. "No manifests found" is a fact the model must be handed;
    left to infer it, a model reads silence as confirmation of whatever it already believes.
    """
    root = repo.resolve()
    found: dict[str, list[Path]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS)
        here = Path(dirpath)
        for name in sorted(filenames):
            path = here / name
            rel = path.relative_to(root).as_posix()
            category = _deployment_category(rel, name)
            if category is None and name.lower().endswith((".yaml", ".yml")):
                category = "kubernetes manifest" if _looks_like_k8s(path) else None
            if category is None:
                continue
            bucket = found.setdefault(category, [])
            if len(bucket) < _PER_CATEGORY:
                bucket.append(path)

    missing = [k for k in _DEPLOYMENT_KINDS if k not in found]
    if not found:
        return (
            "**Nothing found.** Searched this repository for: "
            + ", ".join(_DEPLOYMENT_KINDS)
            + ". None are present. This tells you how this repository is packaged, not how the "
            "code is deployed - absence here can only produce `needs_deployment_fact`."
        )

    lines: list[str] = []
    for category in _DEPLOYMENT_KINDS:
        for path in found.get(category, []):
            rel = path.relative_to(root).as_posix()
            text = _read(root, rel) or ""
            lines.append(f"### `{rel}` - {category}\n\n```\n{text[:_DEPLOY_EXCERPT].rstrip()}\n```")
    if missing:
        lines.append(
            "**Searched for and not present:** "
            + ", ".join(missing)
            + ". Their absence is not evidence that the code is undeployed."
        )
    return "\n\n".join(lines)


def _finding_block(f: Finding) -> str:
    return json.dumps(
        {
            "finding_id": f.finding_id,
            "title": f.title,
            "attack_class": f.attack_class,
            "area": f.area,
            "threat_model": f.threat_model_json,
            "trace": f.trace_json,
            "evidence": f.evidence_json,
            "severity": f.severity_json,
            "remediation": f.remediation_json,
        },
        indent=2,
    )[:14000]


def _validations_block(ctx: RoleContext, finding_id: str) -> str:
    rows = ctx.db.validations_for(finding_id)
    if not rows:
        return "_Nothing ran before this stage. The claim is unverified source reading._"
    return "\n".join(
        f"- **{v.validator}** ({v.model}): `{v.verdict}` - {v.reason[:400]}" for v in rows
    )


def _assemble(instruction: str, blocks: dict[str, str]) -> list[Section]:
    """Split the rendered template on its block markers into priced sections."""
    sections: list[Section] = []
    rest = instruction
    for i, slot in enumerate(_SLOTS):
        head, sep, rest = rest.partition(slot.marker)
        if not sep:
            # The template and this table disagree. Failing here beats shipping a prompt
            # with a block silently missing, which reads to the model as "no evidence".
            raise KeyError(f"prompts/judge.md is missing the {slot.marker} slot")
        sections.append(Section(f"instruction_{i}", head, priority=0))
        sections.append(Section(slot.name, blocks[slot.name], slot.priority, slot.floor_chars))
    sections.append(Section("instruction_tail", rest, priority=0))
    return sections


async def run_judge(ctx: RoleContext, task: Task) -> TaskOutcome:
    """Classify one confirmed finding's production reachability. Files nothing, ever."""
    if not task.finding_id:
        return TaskOutcome(status="failed", exit_reason="schema_invalid")
    finding = ctx.db.get_finding(task.finding_id)
    if finding is None:
        ctx.db.event(
            "judge.missing_finding",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            finding_id=task.finding_id,
        )
        return TaskOutcome(status="failed", exit_reason="schema_invalid")

    if finding.verdict in _NOT_JUDGEABLE:
        ctx.db.event(
            "judge.skipped",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            finding_id=finding.finding_id,
            verdict=finding.verdict,
        )
        return TaskOutcome(status="done", exit_reason="ok", detail={"skipped": finding.verdict})

    repo = ctx.repo_path(task.repo_id)
    started = time.monotonic()

    instruction = render(
        "judge",
        repo_name=task.repo_id,
        repo_path=str(repo),
        finding_block="{FINDING}",
        validations_block="{VALIDATIONS}",
        source_block="{SOURCE}",
        deployment_block="{DEPLOYMENT}",
    )
    blocks = {
        "finding": _finding_block(finding),
        "validations": _validations_block(ctx, finding.finding_id),
        "source": _source_block(repo, finding),
        "deployment": _deployment_block(repo),
    }
    budget = ContextBudget(
        ctx.settings.verify.model, occupancy=ctx.settings.budget.context_occupancy
    )
    prompt, fit = budget.fit(_assemble(instruction, blocks), separator="")
    if fit.trimmed or fit.dropped or fit.over_budget:
        ctx.db.event(
            "context.trimmed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn" if fit.over_budget else "info",
            stage="judge",
            detail=fit.summary(),
        )

    result = await ctx.verify_agent.run(
        prompt,
        system=preamble(),
        cwd=repo,
        timeout_s=ctx.settings.verify.timeout_s,
        schema={
            "classification": "exploitable_now|latent|not_reachable|needs_deployment_fact",
            "reason": "str",
            "exposure": "object",
            "preconditions": "list",
            "missing_fact": "str",
        },
    )
    duration = time.monotonic() - started

    if not result.ok:
        # A judgement that did not run has not cleared or condemned anything. The finding
        # keeps the verdict validation gave it and the task is retried.
        ctx.db.event(
            "judge.failed",
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
    verdict_key = str(payload.get("classification", "")).strip().lower()
    reason = str(payload.get("reason", "")).strip() or "(no reason given)"

    if verdict_key not in _JUDGEMENT:
        ctx.db.event(
            "judge.unparseable",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            finding_id=finding.finding_id,
            got=verdict_key[:80],
        )
        return TaskOutcome(status="failed", exit_reason="schema_invalid", duration_s=duration)

    validation_verdict, new_finding_verdict = _JUDGEMENT[verdict_key]
    exposure = payload.get("exposure") if isinstance(payload.get("exposure"), dict) else {}
    missing_fact = str(payload.get("missing_fact") or "").strip()

    ctx.db.record_validation(
        Validation(
            validation_id=new_id("v"),
            finding_id=finding.finding_id,
            task_id=task.task_id,
            validator="judge",
            model=ctx.verify_agent.model or ctx.settings.verify.model,
            verdict=validation_verdict,
            reason=f"{verdict_key}: {reason}",
            detail_json={
                "classification": verdict_key,
                "exposure": exposure,
                "deployment_evidence": payload.get("deployment_evidence", []),
                "preconditions": payload.get("preconditions", []),
                # The report renders this verbatim for anything left needing validation, so
                # it must survive as its own key rather than only inside the prose reason.
                "missing_fact": missing_fact or None,
            },
        )
    )
    if new_finding_verdict is not None:
        ctx.db.set_verdict(finding.finding_id, new_finding_verdict)

    ctx.db.event(
        "judge.complete",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        finding_id=finding.finding_id,
        classification=verdict_key,
        verdict=new_finding_verdict or finding.verdict,
    )
    return TaskOutcome(
        status="done",
        exit_reason="ok",
        duration_s=duration,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost_usd=result.cost_usd,
        detail={
            "classification": verdict_key,
            "reason": reason[:400],
            "missing_fact": missing_fact or None,
            "context_fit": fit.summary(),
        },
    )
