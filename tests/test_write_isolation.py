"""The single most important invariant in the harness: a validator cannot file findings.

Enforced with the AST rather than a substring search, because the validator module
legitimately *discusses* `file_finding` in its docstring. A grep-based check fails on
prose; an AST check only sees calls.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

VULNESS = Path(__file__).resolve().parents[1] / "vulness"

# Functions that mutate the findings table. A validator may call none of them.
FORBIDDEN_FOR_VALIDATORS = {"file_finding"}


def _called_attributes(path: Path) -> set[str]:
    """Every `x.y(...)` attribute name actually invoked in the module."""
    tree = ast.parse(path.read_text())
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            names.add(node.func.attr)
    return names


def test_validator_role_cannot_file_findings() -> None:
    called = _called_attributes(VULNESS / "agents/roles/validator.py")
    leaked = called & FORBIDDEN_FOR_VALIDATORS
    assert not leaked, (
        f"validator.py calls {leaked}: a validator that can file findings becomes a second "
        "hunter, and the adversarial check collapses"
    )


def test_validator_records_to_validations_table() -> None:
    """It must still write its verdict somewhere -- just not into findings."""
    called = _called_attributes(VULNESS / "agents/roles/validator.py")
    assert "record_validation" in called
    assert "set_verdict" in called


def test_hunter_is_the_only_role_that_files() -> None:
    hunter = _called_attributes(VULNESS / "agents/roles/hunter.py")
    assert "file_finding" in hunter, "the hunt role is the one place findings originate"

    recon = _called_attributes(VULNESS / "agents/roles/recon.py")
    assert "file_finding" not in recon, "recon maps the target; it does not file bugs"


@pytest.mark.parametrize("role", ["validator", "recon"])
def test_non_hunting_roles_never_touch_findings_table(role: str) -> None:
    called = _called_attributes(VULNESS / f"agents/roles/{role}.py")
    assert "file_finding" not in called
