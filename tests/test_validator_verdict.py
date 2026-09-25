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

from vulness.agents.base import AgentResult
from vulness.agents.roles.validator import (
    _MAX_REASK_LOCATIONS,
    _evidence_ceiling,
    _poc_verdict,
    _quote,
    _requested_locations,
    run_validate,
)
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


# ---------------------------------------------------------------- the re-ask


def test_requested_locations_reads_the_structured_field() -> None:
    got = _requested_locations({"missing_locations": [{"file": "api/auth.py", "line": 2}]})
    assert got == [("api/auth.py", {2})]


def test_requested_locations_falls_back_to_prose() -> None:
    """The prompt asked for 'the exact missing location' long before there was a field for
    it. A model that answers in prose must not cost the round."""
    got = _requested_locations({"missing_fact": "need the caller at api/auth.py:29 to decide"})
    assert got == [("api/auth.py", {29})]


def test_requested_locations_is_bounded() -> None:
    payload = {"missing_locations": [{"file": f"a/f{i}.py", "line": i + 1} for i in range(40)]}
    assert len(_requested_locations(payload)) == _MAX_REASK_LOCATIONS


def test_requested_locations_ignores_junk() -> None:
    assert _requested_locations({}) == []
    assert _requested_locations({"missing_locations": ["not a dict", {}, {"line": 3}]}) == []


def test_quote_refuses_a_path_outside_the_repository(repo: Path) -> None:
    """These paths come from a model, so containment is the control and not an assertion."""
    out = _quote(repo, [("../../../etc/passwd", {1})], char_budget=4000)
    assert "root:" not in out
    assert "could not be read" in out


@pytest.mark.asyncio
async def test_needs_validation_triggers_one_reask_and_can_end_in_a_rejection(
    db: Database, repo: Path
) -> None:
    """The whole point of the fix. 0 of 37 validations were `disproved` because the check
    that kills a finding, 'is there a control the hunter missed', needs code that was never
    quoted, and needs_validation was terminal."""
    agent = ScriptedAgent(
        {
            "verdict": "needs_validation",
            "reason": "cannot see the caller",
            "missing_locations": [{"file": "api/auth.py", "line": 2}],
        },
        {"verdict": "disproved", "reason": "api/auth.py:2 already checks the token"},
    )
    ctx = make_ctx(db, repo, verify=agent)
    f = make_finding(db)

    outcome = await run_validate(ctx, validate_task(f.finding_id))

    assert agent.calls == 2, "the validator must be asked again with the code it named"
    assert outcome.detail["verdict"] == "disproved"
    assert outcome.detail["rounds"] == 2
    assert db.get_finding(f.finding_id).verdict == "rejected"
    # The second prompt carries the code, the first does not.
    assert "compare_digest" not in agent.prompts[0]
    assert "compare_digest" in agent.prompts[1]


@pytest.mark.asyncio
async def test_the_reask_happens_at_most_once(db: Database, repo: Path) -> None:
    """A model that still cannot decide with the code it chose itself is telling you the
    answer is not in this repository. Asking a third time just spends money."""
    ask = {
        "verdict": "needs_validation",
        "reason": "still not enough",
        "missing_locations": [{"file": "api/auth.py", "line": 2}],
    }
    agent = ScriptedAgent(ask, ask, ask)
    ctx = make_ctx(db, repo, verify=agent)
    f = make_finding(db)

    await run_validate(ctx, validate_task(f.finding_id))

    assert agent.calls == 2
    assert db.get_finding(f.finding_id).verdict == "needs_validation"


@pytest.mark.asyncio
async def test_no_named_location_means_no_second_call(db: Database, repo: Path) -> None:
    """needs_validation for a fact that lives outside the repository is a real answer, not
    a request. There is nothing to fetch, so nothing is spent."""
    agent = ScriptedAgent(
        {"verdict": "needs_validation", "reason": "depends on the reverse proxy config"}
    )
    ctx = make_ctx(db, repo, verify=agent)
    f = make_finding(db)

    await run_validate(ctx, validate_task(f.finding_id))

    assert agent.calls == 1


@pytest.mark.asyncio
async def test_an_upheld_first_round_is_never_reasked(db: Database, repo: Path) -> None:
    agent = ScriptedAgent({"verdict": "upheld", "reason": "the sink is unescaped"})
    ctx = make_ctx(db, repo, verify=agent)
    f = make_finding(db)

    await run_validate(ctx, validate_task(f.finding_id))

    assert agent.calls == 1
    assert db.get_finding(f.finding_id).verdict == "confirmed"


@pytest.mark.asyncio
async def test_a_failed_second_round_keeps_the_first_verdict(db: Database, repo: Path) -> None:
    """A transient backend failure on the re-ask must not lose the answer already given."""
    agent = ScriptedAgent(
        {
            "verdict": "needs_validation",
            "reason": "cannot see the caller",
            "missing_locations": [{"file": "api/auth.py", "line": 2}],
        },
        AgentResult(classification="api_error_text", text="upstream error", model="scripted-1"),
    )
    ctx = make_ctx(db, repo, verify=agent)
    f = make_finding(db)

    outcome = await run_validate(ctx, validate_task(f.finding_id))

    assert agent.calls == 2
    assert outcome.status == "done"
    assert outcome.detail["verdict"] == "needs_validation"
    assert outcome.detail["rounds"] == 1
