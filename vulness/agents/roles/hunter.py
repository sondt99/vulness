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
from vulness.findings import (
    HunterFinding,
    LatentPrimitive,
    candidate_gate,
    compute_fingerprint,
    mechanical_check,
    primitive_fingerprint,
)
from vulness.findings.poc import POC_TO_VALIDATION, execute_poc
from vulness.prompts import preamble, render
from vulness.sandbox.shim import (
    invocation_count,
    probe_imports,
    shim_instructions,
    write_shim,
)
from vulness.state.db import new_id
from vulness.state.models import Finding, Task, Validation, Wish, now

# A hunt that returns this fast almost certainly hit a broken toolchain, not a clean repo.
_SHALLOW_SECONDS = 25.0


def _history_block(ctx: RoleContext, task: Task, area: str) -> str:
    """What previous runs of this repository already proved.

    Reconnaissance describes the code as written. This describes the code as it has
    actually failed, which is different information and only exists after the first run.
    Weakness clusters: a subsystem that mishandled one trust boundary usually mishandles
    others, and a hunter that knows this area already yielded an auth bypass reads the
    code beside it differently.

    Deliberately not a list of bugs to re-report. The fingerprint check already refuses
    duplicates, so the value here is the pattern, not the record.
    """
    digest = ctx.db.weakness_digest(task.repo_id)
    if not digest:
        return ""
    here = [d for d in digest if d["area"] == area]
    lines = [
        "## What earlier runs proved about this repository",
        "",
        "These are confirmed, already filed, and must NOT be reported again. They are here",
        "because the mistakes a codebase makes tend to repeat: look for the same reasoning",
        "applied elsewhere, and for the weaknesses that sit next to a known one.",
        "",
    ]
    for d in digest[:8]:
        mark = " **(your area)**" if d["area"] == area else ""
        lines.append(f"- `{d['severity']}` {d['attack_class']} in {d['area']}{mark}: {d['title']}")
    if here:
        lines += [
            "",
            f"This area has already broken {len(here)} time(s). Treat its assumptions as "
            "suspect rather than as established.",
        ]
    return "\n".join(lines)


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

    # Give the hunter the sandbox during the hunt, not only at proof time. Until this
    # existed the sandbox ran a PoC after a finding was already filed, which is the wrong
    # end of the process: the hunter had committed to a theory it had no way to test.
    shim_block = ""
    extra_tools: list[str] = []
    shim_path: Path | None = None
    if ctx.sandbox is not None and ctx.settings.sandbox.hunter_shell:
        work = ctx.settings.work_dir / task.run_id / task.repo_id / "exec" / task.task_id
        cfg = ctx.settings.sandbox
        if image := ctx.sandbox_image_for(task.repo_id):
            cfg = cfg.model_copy(update={"image": image})
        shim = write_shim(
            work / "vulness-exec", target=repo, scratch=work / "scratch", cfg=cfg
        )
        usable, detail = probe_imports(shim, (seed.get("import_hint") or None))
        if usable:
            shim_block = shim_instructions(shim)
            extra_tools = [f"Bash({shim}:*)"]
            shim_path = shim
        else:
            # Do not offer a sandbox that cannot run the target: the hunter will inspect
            # it, conclude it is useless, and move on without telling anyone. Make the gap
            # visible instead, which is exactly what the wishlist is for.
            shim_block = (
                "_A sandbox exists but cannot run this target "
                f"(`{detail}`), so reason from source and record what you could not test._"
            )
            ctx.db.wish(
                Wish(
                    wish_id=new_id("w"),
                    run_id=task.run_id,
                    repo_id=task.repo_id,
                    task_id=task.task_id,
                    kind="build_env",
                    resource=f"container image that can import {task.repo_id}",
                    context_json={
                        "probe_error": detail,
                        "current_image": cfg.image,
                        "fix": "set sandbox_image for this repo in fleet.yaml",
                    },
                )
            )

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
        sandbox_block="{SANDBOX}",
        history_block="{HISTORY}",
    )
    lead = seed.get("lead")

    # Assemble under an explicit token budget rather than concatenating and hoping. The
    # instruction and its output contract are priority 0 and never trimmed; the map and the
    # playbook are shed first, because a hunter can read the source but cannot recover a
    # mangled output schema.
    budget = ContextBudget(ctx.settings.hunt.model, occupancy=ctx.settings.budget.context_occupancy)
    head, _, tail = instruction.partition("{ARCHITECTURE}")
    mid, _, rest = tail.partition("{COMPANION}")
    companion_tail, _, after_sandbox = rest.partition("{SANDBOX}")
    sandbox_tail, _, foot = after_sandbox.partition("{HISTORY}")
    # The sandbox block sits inline, before the output contract rather than appended after
    # it. Placed last it read as an appendix and hunters invoked it zero times across a
    # whole run; the capability existed and went unused because of where it was printed.
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
        Section("instruction_companion_tail", companion_tail, priority=0),
        # Priority 0: an agent told it can run code, whose instructions for doing so were
        # trimmed away, will invent an invocation and report its failure as a finding.
        Section("sandbox", shim_block or "_No sandbox available; reason from source only._",
                priority=0),
        Section("instruction_sandbox_tail", sandbox_tail, priority=0),
        # Trimmed before the playbook: on a first run it is empty anyway, and on later runs
        # a truncated history still carries its most severe entries, which are listed first.
        Section("history", _history_block(ctx, task, area), priority=4, floor_chars=600),
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
        schema={
            "findings": "list",
            "latent_primitives": "list",
            "out_of_scope_leads": "list",
            "wishlist": "list",
        },
        allowed_tools=(ctx.settings.hunt.allowed_tools + extra_tools) or None,
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

    sandbox_calls = invocation_count(shim_path) if shim_path else 0
    if shim_path is not None:
        ctx.db.event(
            "hunt.sandbox_usage",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            cell_id=task.cell_id,
            invocations=sandbox_calls,
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

    # Latent primitives are chain material, not vulnerabilities. Stored with their own
    # verdict so no report ever presents them as findings, and so the composer can see the
    # step that is never independently exploitable and therefore never gets filed.
    latent = 0
    for raw in payload.get("latent_primitives") or []:
        if not isinstance(raw, dict):
            continue
        try:
            lp = LatentPrimitive(**raw)
        except Exception:
            continue
        fp = primitive_fingerprint(task.repo_id, lp.file, lp.scope, lp.title)
        if ctx.db.find_prior_finding(task.repo_id, fp) or ctx.db.find_by_fingerprint(
            task.run_id, fp
        ):
            continue
        ctx.db.file_finding(
            Finding(
                finding_id=new_id("lp"),
                run_id=task.run_id,
                repo_id=task.repo_id,
                task_id=task.task_id,
                fingerprint=fp,
                title=lp.title,
                area=area,
                attack_class=attack_class,
                cell_id=task.cell_id,
                threat_model_json={
                    "attacker": "whoever defeats the gate below",
                    "boundary": lp.capability,
                    "broken_assumption": f"currently gated by: {lp.gated_by}",
                },
                trace_json=[
                    {"kind": "sink", "file": lp.file, "line": lp.line, "scope": lp.scope,
                     "description": lp.capability}
                ],
                evidence_json={"items": [{"file": lp.file, "line": lp.line,
                                          "description": lp.gated_by}]},
                remediation_json={"strategy": lp.gate_falls_if},
                verdict="latent",
                created_at=now(),
            )
        )
        latent += 1
    if latent:
        ctx.db.event(
            "primitive.recorded",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            count=latent,
            cell_id=task.cell_id,
        )

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
        row = ctx.db.one("SELECT head_sha FROM repos WHERE repo_id=?", (task.repo_id,))
        ctx.db.record_coverage(
            task.repo_id,
            task.cell_id,
            head_sha=row["head_sha"] if row else None,
            run_id=task.run_id,
            findings=filed,
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
            "sandbox_invocations": sandbox_calls,
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

    # Did an earlier run of this repository already file this exact root cause? The stable
    # fingerprint existed for this from the start, but the lookup was scoped to one run, so
    # re-running a repository re-filed everything it had already found under fresh ids.
    if prior := ctx.db.find_prior_finding(task.repo_id, fingerprint, exclude_run=task.run_id):
        ctx.db.event(
            "finding.known",
            run_id=task.run_id,
            repo_id=task.repo_id,
            task_id=task.task_id,
            fingerprint=fingerprint,
            first_seen_run=prior.run_id,
            prior_verdict=prior.verdict,
            title=hf.title[:120],
        )
        # A prior rejection stands until the code changes. Re-hunting the same disproved
        # claim every run is how a harness spends its budget arguing with itself.
        if prior.verdict == "rejected":
            return False

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
