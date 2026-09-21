"""Shared plumbing for roles.

`RoleContext` is deliberately the only way a role reaches the database or a model. That
makes the write-isolation rule auditable in one place: see `validator_agent` vs
`hunter_agent`, and note that no validator code path is ever handed `db.file_finding`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from vulness.agents.base import Agent
from vulness.config import Settings
from vulness.state.db import Database

if TYPE_CHECKING:
    from vulness.sandbox.docker import DockerSandbox


@dataclass
class TaskOutcome:
    """What the scheduler needs to know after a role finishes."""

    status: str  # done | failed | shallow
    exit_reason: str
    findings_filed: int = 0
    leads: list[dict] = field(default_factory=list)
    wishes: list[dict] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0


@dataclass
class RoleContext:
    db: Database
    settings: Settings
    hunt_agent: Agent  # Claude Code, subscription auth
    verify_agent: Agent  # GLM, API key -- deliberately a different model
    repo_paths: dict[str, Path] = field(default_factory=dict)
    sandbox: DockerSandbox | None = None
    # Digest of each repo taken at ingest. Passed to every PoC run so integrity covers the
    # whole run: snapshotting just before a PoC only proves the tree was stable across it,
    # and an agent that edited source earlier in its turn would still pass that check.
    repo_baselines: dict[str, dict[str, str]] = field(default_factory=dict)

    def repo_path(self, repo_id: str) -> Path:
        try:
            return self.repo_paths[repo_id]
        except KeyError as e:
            raise KeyError(f"unknown repo_id {repo_id!r}") from e

    def skill_dir(self) -> Path | None:
        return self.settings.resolved_skill_dir()
