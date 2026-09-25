"""Shared fixtures: a database, a repo on disk, and an agent that answers from a script.

Roles were previously only testable by running them against a live model, which meant they
were not tested at all. Everything here exists so a role's control flow, and above all its
verdict arithmetic, can be asserted without spending a token.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from vulness.agents.base import Agent, AgentResult
from vulness.agents.roles.context import RoleContext
from vulness.config import Settings
from vulness.state.db import Database, new_id
from vulness.state.models import Finding, Run, Task, Validation


class ScriptedAgent(Agent):
    """Returns queued replies in order, and records what it was asked.

    A list rather than a single reply because the point of several roles is what they do on
    the second call: the validator re-asks, and a test that cannot distinguish round one
    from round two cannot prove it happened.
    """

    name = "scripted"

    def __init__(self, *replies: dict[str, Any] | AgentResult, model: str = "scripted-1") -> None:
        self.model = model
        self.queued = list(replies)
        self.prompts: list[str] = []

    async def run(
        self,
        prompt: str,
        *,
        system: str | None = None,
        cwd: Path | None = None,
        timeout_s: int | None = None,
        schema: dict[str, Any] | None = None,
        allowed_tools: list[str] | None = None,
    ) -> AgentResult:
        self.prompts.append(prompt)
        if not self.queued:
            return AgentResult(classification="empty", text="", model=self.model)
        reply = self.queued.pop(0)
        if isinstance(reply, AgentResult):
            return reply
        return AgentResult(payload=reply, text="", model=self.model)

    @property
    def calls(self) -> int:
        return len(self.prompts)


@pytest.fixture
def db(tmp_path: Path) -> Database:
    d = Database(tmp_path / "vulness.db")
    d.create_run(Run(run_id="r", model_hunt="hunt-1", model_verify="verify-1"))
    return d


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A minimal target with one citable line, so _source_block has something to quote."""
    root = tmp_path / "target"
    (root / "api").mkdir(parents=True)
    (root / "api" / "reports.py").write_text(
        "\n".join(f"# line {i}" for i in range(1, 20))
        + '\ndef get(report_id):\n    return db.execute("SELECT * FROM r WHERE id = \'%s\'" % report_id)\n'
    )
    (root / "api" / "auth.py").write_text("def check(tok):\n    return hmac.compare_digest(tok, want)\n")
    return root


def make_ctx(
    db: Database, repo: Path, *, verify: Agent | None = None, hunt: Agent | None = None
) -> RoleContext:
    db.upsert_repo("target", name="target", path=str(repo))
    return RoleContext(
        db=db,
        settings=Settings(),
        hunt_agent=hunt or ScriptedAgent(),
        verify_agent=verify or ScriptedAgent(),
        repo_paths={"target": repo},
    )


def make_finding(db: Database, *, file: str = "api/reports.py", line: int = 21) -> Finding:
    f = Finding(
        finding_id=new_id("f"),
        run_id="r",
        repo_id="target",
        task_id="t0",
        fingerprint="fp_test",
        title="SQL injection in the report lookup",
        area="api",
        attack_class="injection",
        threat_model_json={
            "attacker": "unauthenticated caller",
            "boundary": "HTTP route to database",
            "broken_assumption": "report_id is an integer",
        },
        trace_json=[{"kind": "sink", "file": file, "line": line, "note": "string formatted into SQL"}],
        evidence_json={"items": []},
    )
    return db.file_finding(f)


def validate_task(finding_id: str) -> Task:
    return Task(
        task_id=new_id("t"),
        run_id="r",
        repo_id="target",
        stage="validate",
        kind="validate",
        finding_id=finding_id,
        prompt="",
    )


def record_sandbox(db: Database, finding_id: str, verdict: str) -> None:
    """Whatever the PoC run concluded, in the shape the sandbox layer writes it."""
    db.record_validation(
        Validation(
            validation_id=new_id("v"),
            finding_id=finding_id,
            validator="sandbox",
            model="docker",
            verdict="needs_validation" if verdict != "verified" else "upheld",
            reason=f"PoC {verdict}",
            detail_json={"verdict": verdict, "exit_code": 1 if verdict == "refuted" else 0},
        )
    )
