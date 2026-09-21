"""Pipeline completeness.

The failure this guards against is specific and was real: a stage name existed in the
TaskKind vocabulary, nothing routed it, and tasks for it would have been enqueued, failed
as `schema_invalid`, and reported as a stage that exists and never runs.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
VULNESS = ROOT / "vulness"


def _declared_kinds() -> set[str]:
    src = (VULNESS / "state/models.py").read_text()
    block = re.search(r"TaskKind = Literal\[(.*?)\]", src, re.S)
    assert block, "TaskKind literal not found"
    return set(re.findall(r'"(\w+)"', block.group(1)))


def _routed_kinds() -> set[str]:
    src = (VULNESS / "orchestrator/scheduler.py").read_text()
    block = re.search(r"_HANDLERS: dict\[.*?\] = \{(.*?)\n\}", src, re.S)
    assert block, "_HANDLERS table not found"
    return set(re.findall(r'"(\w+)":', block.group(1)))


def test_every_declared_task_kind_has_a_handler() -> None:
    declared, routed = _declared_kinds(), _routed_kinds()
    assert not (declared - routed), f"kinds with no handler: {sorted(declared - routed)}"


def test_no_handler_for_an_undeclared_kind() -> None:
    declared, routed = _declared_kinds(), _routed_kinds()
    assert not (routed - declared), f"handlers for unknown kinds: {sorted(routed - declared)}"


def test_all_eight_discovery_stages_plus_triage_exist() -> None:
    """The blog's VDH has 8 stages and VVS has 3 jobs. Report needs no model, so it is a
    renderer rather than a role."""
    for module in (
        "recon", "hunter", "validator", "feedback", "trace", "judge", "fixer", "dedup",
    ):
        assert (VULNESS / f"agents/roles/{module}.py").is_file(), f"missing role: {module}"
    assert (VULNESS / "report/render.py").is_file()
    assert (VULNESS / "coverage/cells.py").is_file(), "gapfill lives in the coverage grid"


@pytest.mark.parametrize(
    "role", ["validator", "recon", "feedback", "trace", "judge", "fixer", "dedup"]
)
def test_only_the_hunter_files_findings(role: str) -> None:
    """Write isolation, extended to every stage added since. Findings originate in exactly
    one place; everything else records verdicts."""
    tree = ast.parse((VULNESS / f"agents/roles/{role}.py").read_text())
    called = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "file_finding" not in called, f"{role}.py must not file findings"


def test_every_role_has_a_prompt_template() -> None:
    for role, template in (
        ("recon", "recon"), ("hunter", "hunter"), ("validator", "validator"),
        ("feedback", "feedback"), ("trace", "trace"), ("judge", "judge"),
        ("fixer", "fixer"), ("dedup", "dedup"),
    ):
        assert (VULNESS / f"prompts/{template}.md").is_file(), f"{role} has no prompt template"


def test_fixer_never_writes_to_the_target_repo() -> None:
    """A patch is a proposal for human review. The harness is read-only against targets."""
    src = (VULNESS / "agents/roles/fixer.py").read_text()
    assert "work_dir" in src, "fixer must write patches under work_dir"


def test_chain_stage_exists_and_is_routed() -> None:
    """Every other stage treats a finding as one root cause crossing one boundary. Chains
    are the only place impact is judged across findings."""
    assert (VULNESS / "agents/roles/chain.py").is_file()
    assert (VULNESS / "prompts/chain.md").is_file()
    assert "chain" in _routed_kinds()


def test_chain_stage_does_not_file_findings() -> None:
    """It composes what is already confirmed; it may not invent new records."""
    tree = ast.parse((VULNESS / "agents/roles/chain.py").read_text())
    called = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "file_finding" not in called
    assert "file_chain" in called


def test_latent_primitives_are_never_reported_as_vulnerabilities() -> None:
    """A gated capability is not a finding. The report must surface confirmed,
    needs_validation and rejected records only, or the harness is filing checklist
    observations as vulnerabilities."""
    src = (VULNESS / "report/render.py").read_text()
    assert 'f.verdict == "confirmed"' in src
    assert '"latent"' not in src, "the report must not have a section for latent primitives"


def test_chain_stage_sees_latent_primitives() -> None:
    """The step that turns a leak into code execution is never independently exploitable,
    so it never becomes a finding. A composer reading only confirmed findings is blind to
    exactly the half of a chain that makes it a chain."""
    src = (VULNESS / "agents/roles/chain.py").read_text()
    assert "'confirmed','latent'" in src or '"confirmed","latent"' in src
