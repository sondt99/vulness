"""What the validator is allowed to conclude, and from what.

`EVALUATION.md` §4 recorded 22 upheld, 15 needs_validation and 0 disproved across 37
validations, with every one of ten PoCs refuted. Two separate defects produced that: the
validator could not reach the code it needed to reject anything, and nothing stopped it
upholding a claim whose only attempt at demonstration had failed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import ScriptedAgent, make_ctx, make_finding, record_sandbox, validate_task

from vulness.agents.roles.validator import _evidence_ceiling, _poc_verdict, run_validate
from vulness.state.db import Database


def test_a_refuted_poc_caps_an_upheld_verdict() -> None:
    verdict, capped = _evidence_ceiling("upheld", "refuted")
    assert verdict == "needs_validation"
    assert capped and "did not reproduce" in capped


def test_a_verified_poc_leaves_upheld_alone() -> None:
    assert _evidence_ceiling("upheld", "verified") == ("upheld", None)


def test_a_source_only_finding_can_still_be_upheld() -> None:
    """No PoC ran, so there is no dynamic evidence to contradict. Capping here would make
    every finding in a repo the sandbox cannot build permanently unprovable."""
    assert _evidence_ceiling("upheld", None) == ("upheld", None)
    assert _evidence_ceiling("upheld", "skipped") == ("upheld", None)


def test_the_ceiling_never_blocks_a_rejection() -> None:
    """It is a ceiling, not a floor. The validator killing a finding outright is the
    outcome this harness is short of; nothing here may stand in its way."""
    assert _evidence_ceiling("disproved", "refuted") == ("disproved", None)
    assert _evidence_ceiling("disproved", "verified") == ("disproved", None)


def test_poc_verdict_reads_the_sandbox_row(db: Database, repo: Path) -> None:
    ctx = make_ctx(db, repo)
    f = make_finding(db)
    assert _poc_verdict(ctx, f.finding_id) is None
    record_sandbox(db, f.finding_id, "refuted")
    assert _poc_verdict(ctx, f.finding_id) == "refuted"


@pytest.mark.asyncio
async def test_a_refuted_poc_is_not_confirmed_end_to_end(db: Database, repo: Path) -> None:
    """The whole point, exercised through run_validate: all four confirmed findings on this
    box had a refuted PoC and were promoted anyway."""
    agent = ScriptedAgent({"verdict": "upheld", "reason": "the sink is unescaped"})
    ctx = make_ctx(db, repo, verify=agent)
    f = make_finding(db)
    record_sandbox(db, f.finding_id, "refuted")

    outcome = await run_validate(ctx, validate_task(f.finding_id))

    assert outcome.status == "done"
    assert outcome.detail["verdict"] == "needs_validation"
    assert db.get_finding(f.finding_id).verdict == "needs_validation"
    recorded = [v for v in db.validations_for(f.finding_id) if v.validator == "adversarial"]
    assert len(recorded) == 1
    assert recorded[0].verdict == "needs_validation"
    # The model's own answer survives in the record: the cap is visible, not a rewrite.
    assert recorded[0].detail_json["model_verdict"] == "upheld"
    assert recorded[0].detail_json["capped"]


@pytest.mark.asyncio
async def test_a_verified_poc_still_confirms(db: Database, repo: Path) -> None:
    agent = ScriptedAgent({"verdict": "upheld", "reason": "the sink is unescaped"})
    ctx = make_ctx(db, repo, verify=agent)
    f = make_finding(db)
    record_sandbox(db, f.finding_id, "verified")

    await run_validate(ctx, validate_task(f.finding_id))

    assert db.get_finding(f.finding_id).verdict == "confirmed"
