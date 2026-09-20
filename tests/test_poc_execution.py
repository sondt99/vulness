"""PoC execution: the step that turns an argument into evidence.

The property under test is the one the blog is emphatic about -- a PoC must run against
the ORIGINAL, UNTOUCHED codebase, or the agent has simply proved a bug in code it wrote
itself moments earlier.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from sness.findings.poc import POC_TO_VALIDATION, PocOutcome, execute_poc
from sness.findings.schema import PoC

SNESS = Path(__file__).resolve().parents[1] / "sness"


def test_run_poc_has_a_live_call_path() -> None:
    """Regression: the sandbox was fully built, passed its self-test, and was never
    called by anything. PoCs were collected, stored, shown to the validator as text --
    and never executed."""
    tree = ast.parse((SNESS / "findings/poc.py").read_text())
    called = {
        n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "run_poc" in called, "poc.py must actually invoke the sandbox"

    hunter = ast.parse((SNESS / "agents/roles/hunter.py").read_text())
    hunter_calls = {
        n.func.id for n in ast.walk(hunter) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert "execute_poc" in hunter_calls, "the hunt path must reach PoC execution"


def test_tainted_source_voids_the_finding() -> None:
    o = PocOutcome("tainted", "tree changed", exit_code=0, changed_files=["vuln.c"])
    assert o.voids_finding, "a PoC that edited the target is a rejection, not a caveat"
    assert POC_TO_VALIDATION["tainted"] == "disproved"


def test_exit_zero_does_not_rescue_a_tainted_run() -> None:
    """The clean exit code is exactly what makes this dangerous: it looks like success."""
    assert PocOutcome("tainted", "x", exit_code=0).voids_finding


def test_refuted_is_not_disproved() -> None:
    """A PoC that failed to reproduce is a statement about the PoC. The adversarial
    validator still judges the finding on its source evidence."""
    assert POC_TO_VALIDATION["refuted"] == "needs_validation"
    assert not PocOutcome("refuted", "x").voids_finding


@pytest.mark.asyncio
async def test_no_sandbox_skips_instead_of_failing(tmp_path: Path) -> None:
    """A missing sandbox must degrade to source-only findings, never lose them."""

    class Ctx:
        sandbox = None
        repo_baselines: dict = {}

        class settings:  # noqa: N801
            work_dir = tmp_path

    out = await execute_poc(
        Ctx(),  # type: ignore[arg-type]
        run_id="r",
        repo_id="repo",
        task_id="t",
        finding_id="f",
        poc=PoC(command=["python3", "poc.py"]),
        repo=tmp_path,
    )
    assert out.verdict == "skipped"
    assert not out.voids_finding


@pytest.mark.asyncio
async def test_missing_poc_skips(tmp_path: Path) -> None:
    class Ctx:
        sandbox = object()
        repo_baselines: dict = {}

        class settings:  # noqa: N801
            work_dir = tmp_path

    out = await execute_poc(
        Ctx(),  # type: ignore[arg-type]
        run_id="r", repo_id="repo", task_id="t", finding_id="f", poc=None, repo=tmp_path,
    )
    assert out.verdict == "skipped"
