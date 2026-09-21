"""Recon: write the threat model instead of receiving one.

This is the highest-leverage stage in the harness. Cloudflare reported that feeding
hunters proper recon context dropped their validation rejection rate from 40% to 11% and
raised high-integrity findings from 35% to 58% -- a bigger quality swing than any prompt
tuning. The reason is the repo-specific attack classes: a hunt driven by a generic
taxonomy finds generic bugs.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from vulness.agents.base import AgentResult
from vulness.agents.context_budget import ContextBudget, Section
from vulness.agents.roles.context import RoleContext, TaskOutcome
from vulness.coverage.cells import BUILTIN_ATTACK_CLASSES, Area, build_grid, discover_areas
from vulness.coverage.scope import scope_areas
from vulness.prompts import preamble, render
from vulness.state.models import Task, now

# Three passes with different questions, run concurrently. The blog runs three recon
# agents in parallel for a reason that is easy to miss: a single agent asked to do all of
# this spends its window on whichever part it hit first, and the repo-specific attack
# classes -- the highest-value output -- are what get squeezed out. Separate windows mean
# none of the three can starve the others.
_FOCUS: dict[str, str] = {
    "surface": (
        "## Your focus: attack surface\n\n"
        "Concentrate on what an outsider can reach. Enumerate every entry point: HTTP routes"
        " and handlers, CLI arguments, message/queue consumers, IPC and socket endpoints,"
        " file and format parsers, deserialization, scheduled jobs, webhooks. For each, say"
        " who can reach it and with what level of authentication. Populate"
        " `trust_boundaries` thoroughly; keep `areas` coarse."
    ),
    "structure": (
        "## Your focus: structure and data flow\n\n"
        "Concentrate on how the software is organised and where data travels. Identify the"
        " coherent subsystems worth hunting independently, following the repo's own"
        " structure. Trace how untrusted input reaches storage, queries, the filesystem,"
        " and other services. Populate `areas` thoroughly and precisely, with real paths;"
        " keep `trust_boundaries` brief."
    ),
    "classes": (
        "## Your focus: repo-specific attack classes\n\n"
        "This is the highest-value output of reconnaissance, so spend your whole budget"
        " here. The standard taxonomy describes software in general; your job is to name"
        " the weaknesses THIS codebase specifically invites, given its idioms, its"
        " abstractions, and the mistakes its structure makes easy. Propose at least three"
        " classes the standard list does not cover, each with a concrete hunting"
        " methodology for this repo. Populate `repo_specific_attack_classes` thoroughly;"
        " keep the other fields short."
    ),
}


def _lang_summary(repo: Path) -> str:
    counts: dict[str, int] = {}
    skip = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", "target"}
    for f in repo.rglob("*"):
        if f.is_file() and not any(p in skip for p in f.parts) and f.suffix:
            counts[f.suffix.lower()] = counts.get(f.suffix.lower(), 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:8]
    return ", ".join(f"{ext} x{n}" for ext, n in top) or "(none detected)"


async def _recon_pass(ctx: RoleContext, task: Task, repo: Path, focus: str) -> AgentResult:
    """One reconnaissance perspective, in its own context window."""
    budget = ContextBudget(ctx.settings.hunt.model, occupancy=ctx.settings.budget.context_occupancy)
    body, _fit = budget.fit(
        [
            Section(
                "instruction",
                render(
                    "recon",
                    repo_name=task.repo_id,
                    repo_path=str(repo),
                    lang_summary=_lang_summary(repo),
                    builtin_classes=", ".join(BUILTIN_ATTACK_CLASSES),
                    max_turns=ctx.settings.hunt.max_turns,
                    focus_block=_FOCUS[focus],
                ),
                priority=0,
            )
        ],
        separator="",
    )
    return await ctx.hunt_agent.run(
        body,
        system=preamble(),
        cwd=repo,
        timeout_s=ctx.settings.hunt.timeout_s,
        schema={"architecture": "str", "areas": "list", "repo_specific_attack_classes": "list"},
    )


def _merge_payloads(results: list[AgentResult]) -> dict:
    """Fold three perspectives into one map, keeping the best answer for each field.

    Union rather than overwrite: each pass was told to go deep on one field and shallow on
    the rest, so the longest non-empty answer per field is the one that was actually
    researched. Attack classes are unioned by name because disagreement between passes is
    signal -- a class only one of them saw is still a class worth hunting.
    """
    merged: dict = {
        "architecture": "",
        "trust_boundaries": [],
        "areas": [],
        "repo_specific_attack_classes": [],
        "highest_value_targets": [],
    }
    seen_classes: set[str] = set()
    seen_areas: set[str] = set()

    for r in results:
        payload = r.extract_json() or {}
        if len(str(payload.get("architecture", ""))) > len(merged["architecture"]):
            merged["architecture"] = str(payload.get("architecture", ""))
        for b in payload.get("trust_boundaries") or []:
            if isinstance(b, dict):
                merged["trust_boundaries"].append(b)
        for a in payload.get("areas") or []:
            if isinstance(a, dict) and (name := str(a.get("name", ""))) and name not in seen_areas:
                seen_areas.add(name)
                merged["areas"].append(a)
        for c in payload.get("repo_specific_attack_classes") or []:
            if isinstance(c, dict) and (name := str(c.get("name", ""))) and name not in seen_classes:
                seen_classes.add(name)
                merged["repo_specific_attack_classes"].append(c)
        for h in payload.get("highest_value_targets") or []:
            merged["highest_value_targets"].append(h)
    return merged


async def run_recon(ctx: RoleContext, task: Task) -> TaskOutcome:
    repo = ctx.repo_path(task.repo_id)
    started = time.monotonic()

    results = await asyncio.gather(
        *(_recon_pass(ctx, task, repo, focus) for focus in _FOCUS),
        return_exceptions=True,
    )
    good = [r for r in results if isinstance(r, AgentResult) and r.ok]
    duration = time.monotonic() - started
    tokens_in = sum(r.tokens_in for r in results if isinstance(r, AgentResult))
    tokens_out = sum(r.tokens_out for r in results if isinstance(r, AgentResult))
    cost = sum(r.cost_usd for r in results if isinstance(r, AgentResult))

    # One surviving pass still yields a usable map; zero means the repo was never read and
    # hunting it would be hunting blind.
    if not good:
        reasons = [
            r.classification if isinstance(r, AgentResult) else type(r).__name__ for r in results
        ]
        ctx.db.event(
            "recon.failed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="error",
            passes=reasons,
        )
        first = next((r for r in results if isinstance(r, AgentResult)), None)
        return TaskOutcome(
            status="failed",
            exit_reason=first.classification if first else "crash",
            duration_s=duration,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd=cost,
        )

    if len(good) < len(_FOCUS):
        ctx.db.event(
            "recon.partial",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            survived=len(good),
            of=len(_FOCUS),
        )

    payload = _merge_payloads(good)
    changed = list((task.seed_json or {}).get("changed_files") or [])
    areas = _scoped_areas(changed, repo) if changed else _areas_from_payload(payload, repo)
    extra_classes = [
        str(c.get("name", "")).strip()
        for c in payload.get("repo_specific_attack_classes", [])
        if isinstance(c, dict) and c.get("name")
    ]

    cells = build_grid(
        task.run_id, task.repo_id, areas, extra_classes=extra_classes, repo=repo
    )
    for cell in cells:
        ctx.db.upsert_cell(cell)

    # architecture.md is the shared context every later hunter reads a slice of.
    arch_path = ctx.settings.work_dir / task.run_id / task.repo_id / "architecture.md"
    arch_path.parent.mkdir(parents=True, exist_ok=True)
    arch_path.write_text(_render_architecture(payload, task.repo_id))

    ctx.db.event(
        "recon.complete",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        passes=len(good),
        scoped=bool(changed),
        areas=len(areas),
        cells=len(cells),
        repo_specific_classes=extra_classes,
    )

    return TaskOutcome(
        status="done",
        exit_reason="ok",
        duration_s=duration,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=cost,
        detail={
            "passes_survived": len(good),
            "areas": len(areas),
            "cells": len(cells),
            "repo_specific_attack_classes": extra_classes,
            "architecture_path": str(arch_path),
        },
    )


def _scoped_areas(changed: list[str], repo: Path) -> list[Area]:
    """Areas built only from files that changed, for a `--since` run.

    Recon's own view is ignored here on purpose: it maps the whole repository, and using it
    would re-seed cells over untouched code, which is exactly the spend a scoped run exists
    to avoid.
    """
    areas: list[Area] = []
    for name, files in scope_areas(changed):
        langs: dict[str, int] = {}
        for rel in files:
            suffix = Path(rel).suffix.lower()
            if suffix:
                langs[suffix] = langs.get(suffix, 0) + 1
        areas.append(Area(name=name, paths=files, files=len(files), langs=langs))
    return areas


def _areas_from_payload(payload: dict, repo: Path) -> list[Area]:
    """Trust recon's areas, but never let a bad parse leave the grid empty.

    A run with no cells silently hunts nothing, which is the most expensive possible
    failure: it looks exactly like a clean codebase.
    """
    raw = payload.get("areas") or []
    areas: list[Area] = []
    for a in raw:
        if not isinstance(a, dict) or not a.get("name"):
            continue
        paths = [p for p in (a.get("paths") or []) if isinstance(p, str)]
        valid = [p for p in paths if (repo / p).exists()]
        if not valid:
            continue
        langs: dict[str, int] = {}
        files = 0
        for p in valid:
            target = repo / p
            candidates = [target] if target.is_file() else list(target.rglob("*"))
            for f in candidates:
                if f.is_file() and f.suffix:
                    langs[f.suffix.lower()] = langs.get(f.suffix.lower(), 0) + 1
                    files += 1
        areas.append(Area(name=str(a["name"]), paths=valid, files=files, langs=langs))

    return areas or discover_areas(repo)


def _render_architecture(payload: dict, repo_id: str) -> str:
    lines = [f"# Architecture - {repo_id}", "", f"_generated {now()}_", ""]
    if arch := payload.get("architecture"):
        lines += ["## Overview", "", str(arch), ""]
    if tb := payload.get("trust_boundaries"):
        lines += ["## Trust boundaries", ""]
        for b in tb:
            if isinstance(b, dict):
                lines.append(
                    f"- **{b.get('name', '?')}** - {b.get('low_trust_side', '?')} sends "
                    f"{b.get('crosses', '?')}; control: {b.get('control', '?')}"
                )
        lines.append("")
    if cls := payload.get("repo_specific_attack_classes"):
        lines += ["## Repo-specific attack classes", ""]
        for c in cls:
            if isinstance(c, dict):
                lines.append(f"### {c.get('name', '?')}")
                lines.append(f"{c.get('why_this_repo', '')}")
                lines.append(f"{c.get('methodology', '')}")
                lines.append("")
    if hv := payload.get("highest_value_targets"):
        lines += ["## Highest-value targets", ""] + [f"- {t}" for t in hv] + [""]
    lines += ["## Raw", "", "```json", json.dumps(payload, indent=2)[:12000], "```"]
    return "\n".join(lines)
