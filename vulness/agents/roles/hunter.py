"""Hunt: attack one (area x attack-class) cell.

Two behaviours here are worth reading closely.

**Sibling forking.** When a hunter trips over something promising outside its scope, it
does not chase it - it records a lead, and the scheduler forks a fresh task seeded with it.
That keeps the current hunt on-task while the lead still gets hunted, by an agent with a
clean context window instead of a half-consumed one.

**The gate runs before the model.** A candidate passes a structural gate and a
deterministic file/line check -- plain code, no model -- before any validator is paid to
think about it. Hallucinated line numbers get killed for free.
"""

from __future__ import annotations

import time
from pathlib import Path

from vulness.agents.context_budget import ContextBudget, Section, occupancy_fraction, peak_occupancy
from vulness.agents.roles.context import RoleContext, TaskOutcome
from vulness.agents.roles.feedback import MARKER as FEEDBACK_MARKER
from vulness.coverage.cells import companion_for
from vulness.findings import HunterFinding, candidate_gate, compute_fingerprint, mechanical_check
from vulness.findings.poc import POC_TO_VALIDATION, execute_poc
from vulness.prompts import preamble, render
from vulness.state.db import new_id
from vulness.state.models import Finding, Task, Validation, Wish, now

# A hunt that returns this fast almost certainly hit a broken toolchain, not a clean repo.
_SHALLOW_SECONDS = 25.0


def _architecture_block(ctx: RoleContext, task: Task) -> str:
    path = ctx.settings.work_dir / task.run_id / task.repo_id / "architecture.md"
    if not path.is_file():
        return "_No reconnaissance output available; rely on the source._"
    text = path.read_text()
    # Hunters get the map, not the whole territory -- context is the scarce resource.
    return "## Architecture (from reconnaissance)\n\n" + text[:6000]


async def run_hunt(ctx: RoleContext, task: Task) -> TaskOutcome:
    repo = ctx.repo_path(task.repo_id)
    started = time.monotonic()
    seed = task.seed_json or {}
    attack_class = seed.get("attack_class") or "logic-and-state"
    area = seed.get("area") or "root"
    paths = seed.get("paths") or ["."]

    companion = companion_for(attack_class, ctx.skill_dir())
    instruction = render(
        "hunter",
        repo_name=task.repo_id,
        repo_path=str(repo),
        attack_class=attack_class,
        area=area,
        paths=", ".join(paths),
        architecture_block="{ARCHITECTURE}",
        companion_block="{COMPANION}",
    )
    lead = seed.get("lead")

    # Assemble under an explicit token budget rather than concatenating and hoping. The
    # instruction and its output contract are priority 0 and never trimmed; the map and the
    # playbook are shed first, because a hunter can read the source but cannot recover a
    # mangled output schema.
    budget = ContextBudget(ctx.settings.hunt.model, occupancy=ctx.settings.budget.context_occupancy)
    head, sep, tail = instruction.partition("{ARCHITECTURE}")
    mid, _, foot = tail.partition("{COMPANION}")
    sections = [
        Section("instruction_head", head, priority=0),
        Section("architecture", _architecture_block(ctx, task), priority=3, floor_chars=1500),
        Section("instruction_mid", mid, priority=0),
        Section(
            "companion",
            companion or "_No companion playbook for this class; use the taxonomy._",
            priority=2,
            floor_chars=3000,
        ),
        Section("instruction_tail", foot, priority=0),
    ]
    # The Feedback stage rewrites queued task prompts in place. Hunts are re-rendered from
    # the template at dispatch, so without this splice that rewriting would reach nothing
    # and the stage would silently do no work.
    if FEEDBACK_MARKER in (task.prompt or ""):
        addendum = task.prompt.split(FEEDBACK_MARKER, 1)[1]
        if addendum.strip():
            sections.append(
                Section("feedback", addendum.strip(), priority=1, floor_chars=400)
            )
    if lead:
        sections.append(
            Section(
                "lead",
                f"## Seed from a sibling hunter\n\nAnother hunter flagged this and could not "
                f"pursue it: {lead}\nStart there.\n",
                priority=1,
                floor_chars=200,
            )
        )
    prompt, fit = budget.fit(sections, separator="")
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
        cwd=repo,
        timeout_s=ctx.settings.hunt.timeout_s,
        schema={"findings": "list", "out_of_scope_leads": "list", "wishlist": "list"},
    )
    duration = time.monotonic() - started

    if not result.ok:
        ctx.db.event(
            "hunt.failed",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="error",
            classification=result.classification,
            cell_id=task.cell_id,
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

    # Estimation got us into the window; this is the measurement of how full it actually
    # got. Forty turns of reading source dwarfs any prompt we assembled.
    peak = peak_occupancy(result.raw_events)
    frac = occupancy_fraction(peak, ctx.settings.hunt.model)
    if frac > ctx.settings.budget.context_occupancy:
        ctx.db.event(
            "context.exceeded",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            cell_id=task.cell_id,
            peak_tokens=peak,
            occupancy=round(frac, 3),
            target=ctx.settings.budget.context_occupancy,
        )

    payload = result.extract_json() or {}
    raw_findings = payload.get("findings") or []
    leads = [x for x in (payload.get("out_of_scope_leads") or []) if isinstance(x, dict)]
    wishes = [x for x in (payload.get("wishlist") or []) if isinstance(x, dict)]

    filed = 0
    for raw in raw_findings:
        if isinstance(raw, dict) and await _process_candidate(
            ctx, task, repo, raw, area, attack_class
        ):
            filed += 1

    for w in wishes:
        ctx.db.wish(
            Wish(
                wish_id=new_id("w"),
                run_id=task.run_id,
                repo_id=task.repo_id,
                task_id=task.task_id,
                kind=str(w.get("kind", "tool"))[:40],
                resource=str(w.get("resource", ""))[:500],
                context_json={"why": w.get("why", ""), "cell": task.cell_id},
            )
        )

    if task.cell_id:
        ctx.db.touch_cell(
            task.run_id,
            task.repo_id,
            task.cell_id,
            findings=filed,
            status="covered" if filed else "thin",
        )

    # Shallow detection: zero findings AND zero leads AND suspiciously fast is the signature
    # of a crashed dependency, not a clean cell. Requeue rather than bank a false all-clear.
    if filed == 0 and not leads and duration < _SHALLOW_SECONDS:
        ctx.db.event(
            "hunt.shallow",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            duration_s=round(duration, 1),
            cell_id=task.cell_id,
        )
        return TaskOutcome(
            status="shallow",
            exit_reason="ok",
            leads=leads,
            duration_s=duration,
            tokens_in=result.tokens_in,
            tokens_out=result.tokens_out,
            cost_usd=result.cost_usd,
        )

    ctx.db.event(
        "hunt.complete",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        cell_id=task.cell_id,
        candidates=len(raw_findings),
        filed=filed,
        leads=len(leads),
    )
    return TaskOutcome(
        status="done",
        exit_reason="ok",
        findings_filed=filed,
        leads=leads,
        wishes=wishes,
        duration_s=duration,
        tokens_in=result.tokens_in,
        tokens_out=result.tokens_out,
        cost_usd=result.cost_usd,
        detail={
            "coverage_note": payload.get("coverage_note", ""),
            "peak_context_tokens": peak,
            "context_occupancy": round(frac, 3),
            "context_fit": fit.summary(),
        },
    )


async def _process_candidate(
    ctx: RoleContext, task: Task, repo: Path, raw: dict, area: str, attack_class: str
) -> bool:
    """Parse -> gate -> mechanical check -> file -> RUN THE PoC.

    Returns True if it became a live candidate worth a validator's time.
    """
    raw.setdefault("attack_class", attack_class)
    raw.setdefault("area", area)
    try:
        hf = HunterFinding(**raw)
    except Exception as e:
        ctx.db.event(
            "finding.unparseable",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            error=str(e)[:400],
            title=str(raw.get("title", ""))[:120],
        )
        return False

    passed, reason = candidate_gate(hf)
    if not passed:
        ctx.db.event(
            "finding.gated",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            level="warn",
            reason=reason,
            title=hf.title[:120],
        )
        return False

    fingerprint = compute_fingerprint(hf, task.repo_id)
    existing = ctx.db.find_by_fingerprint(task.run_id, fingerprint)
    if existing is None:
        # Same defect seen through a different attack class lands on the same sink line.
        sink = next((s for s in hf.trace if s.kind == "sink"), None)
        if sink is not None:
            existing = ctx.db.find_by_sink(task.run_id, task.repo_id, sink.file, sink.line)
    if existing is not None:
        ctx.db.event(
            "finding.duplicate",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            fingerprint=fingerprint,
            of=existing.finding_id,
            title=hf.title[:120],
        )
        return False

    mech = mechanical_check(hf, repo)
    finding = Finding(
        finding_id=new_id("f"),
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        fingerprint=fingerprint,
        title=hf.title,
        area=hf.area or area,
        attack_class=hf.attack_class or attack_class,
        cell_id=task.cell_id,
        threat_model_json=hf.threat_model.model_dump(),
        trace_json=[s.model_dump() for s in hf.trace],
        evidence_json={"items": [e.model_dump() for e in hf.evidence]},
        poc_json=hf.poc.model_dump() if hf.poc else {},
        severity_json=hf.severity.model_dump(),
        remediation_json={"strategy": hf.remediation},
        verdict="candidate" if mech.ok else "rejected",
        created_at=now(),
    )
    ctx.db.file_finding(finding)

    # The mechanical verdict is recorded either way: the Feedback stage learns from
    # rejections, and "the model invented line numbers" is the most actionable signal there is.
    ctx.db.record_validation(
        Validation(
            validation_id=new_id("v"),
            finding_id=finding.finding_id,
            task_id=task.task_id,
            validator="mechanical",
            model="deterministic",
            verdict="upheld" if mech.ok else "disproved",
            reason=mech.reason(),
            detail_json=mech.model_dump(),
        )
    )
    if not mech.ok:
        return False

    # Run the proof. Source inspection established the path; this establishes the behaviour.
    outcome = await execute_poc(
        ctx,
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        finding_id=finding.finding_id,
        poc=hf.poc,
        repo=repo,
    )
    ctx.db.record_validation(
        Validation(
            validation_id=new_id("v"),
            finding_id=finding.finding_id,
            task_id=task.task_id,
            validator="sandbox",
            model="docker",
            verdict=POC_TO_VALIDATION[outcome.verdict],
            reason=outcome.reason,
            detail_json=outcome.as_detail(),
        )
    )
    ctx.db.event(
        "poc.executed",
        run_id=task.run_id,
        repo_id=task.repo_id,
        task_id=task.task_id,
        finding_id=finding.finding_id,
        verdict=outcome.verdict,
        exit_code=outcome.exit_code,
    )

    if outcome.voids_finding:
        # The agent edited the target to make its exploit land. Not a caveat -- a rejection.
        ctx.db.set_verdict(finding.finding_id, "rejected")
        return False

    return True
