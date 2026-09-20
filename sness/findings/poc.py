"""Execute a hunter's proof of concept against untouched source.

    Every confirmed finding ships with a PoC written as a test that runs against the
    original, untouched codebase. This prevents the agent from editing the source files
    to force an exploit to land.
        -- Cloudflare, "Build your own vulnerability harness"

Reading source tells you what code says; running it tells you what the code does. This is
the step that separates a finding from a well-argued hypothesis, and it is the one the
blog credits with the biggest single jump in quality.

Outcomes and what each one means:

- ``verified``  -- the PoC ran in an isolated container against read-only source and
  demonstrated the claimed effect. The strongest evidence the harness can produce.
- ``refuted``   -- the PoC ran and did **not** reproduce. This does not reject the finding
  on its own: a weak PoC is a statement about the PoC. It is recorded and handed to the
  adversarial validator as evidence.
- ``tainted``   -- the source tree changed. The finding is **void**, whatever the exit
  code. The agent proved a bug in code it wrote itself.
- ``skipped``   -- no PoC supplied, or no sandbox available. The finding stays source-only.
- ``error``     -- the sandbox could not carry out the run.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal

from sness.findings.schema import PoC

if TYPE_CHECKING:
    from sness.agents.roles.context import RoleContext

PocVerdict = Literal["verified", "refuted", "tainted", "skipped", "error"]
ValidationVerdict = Literal["upheld", "disproved", "needs_validation", "error"]

# How a sandbox outcome lands in the validations table. `refuted` is deliberately NOT
# `disproved`: a PoC that failed to reproduce is a statement about the PoC, and the
# adversarial validator still gets to judge the finding on the source.
POC_TO_VALIDATION: dict[PocVerdict, ValidationVerdict] = {
    "verified": "upheld",
    "tainted": "disproved",
    "refuted": "needs_validation",
    "skipped": "needs_validation",
    "error": "error",
}

# A PoC is a focused test, not a build. Anything longer is a hung process or a fixture
# that wanted the network, and both are better reported than waited on.
_POC_TIMEOUT_S = 120


@dataclass
class PocOutcome:
    verdict: PocVerdict
    reason: str
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    changed_files: list[str] | None = None
    duration_s: float = 0.0

    @property
    def voids_finding(self) -> bool:
        return self.verdict == "tainted"

    def as_detail(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "exit_code": self.exit_code,
            "stdout": self.stdout[-2000:],
            "stderr": self.stderr[-2000:],
            "changed_files": self.changed_files or [],
            "duration_s": round(self.duration_s, 2),
        }


def _safe_test_name(name: str) -> str:
    """The filename comes from the model, so it is untrusted input to a path join."""
    base = Path(name or "poc.py").name
    return base if base and base not in (".", "..") else "poc.py"


async def execute_poc(
    ctx: RoleContext,
    *,
    run_id: str,
    repo_id: str,
    task_id: str,
    finding_id: str,
    poc: PoC | None,
    repo: Path,
) -> PocOutcome:
    """Materialise the PoC in a scratch dir and run it with the target mounted read-only."""
    if poc is None or not poc.command:
        return PocOutcome("skipped", "hunter supplied no runnable PoC")
    if ctx.sandbox is None:
        return PocOutcome("skipped", "no sandbox available; finding is source-only")

    from sness.sandbox.policy import SandboxLimits

    scratch = ctx.settings.work_dir / run_id / repo_id / "poc" / finding_id
    scratch.mkdir(parents=True, exist_ok=True)

    if poc.test_source:
        (scratch / _safe_test_name(poc.test_file_name)).write_text(poc.test_source)

    limits = SandboxLimits.from_config(ctx.settings.sandbox)
    limits.timeout_s = min(limits.timeout_s or _POC_TIMEOUT_S, _POC_TIMEOUT_S)

    try:
        result, source_unchanged, changed = await ctx.sandbox.run_poc(
            list(poc.command),
            target=repo,
            scratch=scratch,
            limits=limits,
            baseline=ctx.repo_baselines.get(repo_id),
        )
    except Exception as e:  # a sandbox fault must not lose the finding
        return PocOutcome("error", f"sandbox raised {type(e).__name__}: {e}"[:300])

    if not source_unchanged:
        return PocOutcome(
            "tainted",
            f"source tree changed during the run ({len(changed)} file(s)): "
            f"{', '.join(changed[:5])}. The PoC proved a bug in code the agent wrote.",
            exit_code=result.exit_code,
            changed_files=changed,
            duration_s=result.duration_s,
        )

    if result.violation:
        return PocOutcome(
            "error",
            f"sandbox violation: {result.summary()}",
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_s=result.duration_s,
        )

    cmd = " ".join(shlex.quote(c) for c in poc.command)
    if result.exited_clean:
        return PocOutcome(
            "verified",
            f"PoC `{cmd}` reproduced the claimed effect against read-only source "
            f"(expected: {poc.expected_observation or 'not stated'})",
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_s=result.duration_s,
        )

    return PocOutcome(
        "refuted",
        f"PoC `{cmd}` ran but exited {result.exit_code} without demonstrating the effect",
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
        duration_s=result.duration_s,
    )
