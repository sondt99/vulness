"""Configuration. Two models: Claude Code (subscription CLI) hunts, GLM (API) verifies."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

Profile = Literal["quick", "standard", "deep"]


def load_dotenv(path: Path = Path(".env")) -> list[str]:
    """Put unprefixed keys from a .env file into the process environment.

    `env_prefix="VULNESS_"` below means pydantic-settings reads .env looking only for
    VULNESS_* names, and VerifyBackend.api_key() reads os.environ directly. So GLM_API_KEY
    written to .env, which is where .env.example and the README both tell you to put it,
    reached nothing: `doctor` reported "GLM_API_KEY not set" with the key sitting in the
    file beside it, and every run that did validate was one where the operator happened to
    have exported it by hand.

    An already-exported value always wins, so a shell can still override the file. Returns
    the names set, never the values: these are credentials and nothing may log them.
    """
    if not path.exists():
        return []
    applied: list[str] = []
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip().removeprefix("export ").strip(), value.strip().strip("\"'")
        if key and value and key not in os.environ:
            os.environ[key] = value
            applied.append(key)
    return applied


class HuntBackend(BaseModel):
    """Claude Code CLI, driven headless. Subscription auth -- no API key is read or sent."""

    cli: str = "claude"
    model: str = "sonnet"
    permission_mode: str = "acceptEdits"
    max_turns: int = 60
    timeout_s: int = 1800
    # Read-only by default. The hunter reasons over source; execution goes to the sandbox.
    allowed_tools: list[str] = Field(
        default_factory=lambda: ["Read", "Grep", "Glob", "Bash(rg:*)", "Bash(git log:*)"]
    )
    disallowed_tools: list[str] = Field(default_factory=lambda: ["Write", "Edit", "WebFetch"])
    # Refuse the target repository's own agent configuration. Measured on a probe target
    # carrying a CLAUDE.md, a .claude/settings.json hook and a .mcp.json: with the previous
    # invocation the hook and the MCP server both executed, and the CLAUDE.md reached the
    # model's context. See agents/claude_cli.py. Off only to reproduce that, never in a run.
    isolate_target: bool = True


class VerifyBackend(BaseModel):
    """GLM over an OpenAI-compatible endpoint. Different weights, different blind spots."""

    # GLM Coding Plan uses a dedicated endpoint. The general /api/paas/v4 path returns
    # "Insufficient balance" on a Coding Plan key -- verified against this account.
    base_url: str = "https://api.z.ai/api/coding/paas/v4"
    model: str = "glm-5.3"
    api_key_env: str = "GLM_API_KEY"
    timeout_s: int = 300
    # GLM-5.3 is a reasoning model: reasoning_content consumed 49 of 53 completion tokens
    # on a trivial prompt. Too small a budget returns finish_reason="length" with EMPTY
    # content -- a 200 OK that means failure. Give validation real headroom.
    # Raised after the first real repository run: 8 of 13 validations came back
    # `subtype=length`, meaning GLM spent the whole budget in reasoning_content and was cut
    # off before it emitted any JSON. Fixture findings were small enough to hide this.
    max_tokens: int = 32768
    temperature: float = 0.2
    max_retries: int = 4

    def api_key(self) -> str | None:
        for env in (self.api_key_env, "ZHIPU_API_KEY", "ZAI_API_KEY"):
            if v := os.environ.get(env):
                return v.strip()
        return None


class SandboxConfig(BaseModel):
    # "bwrap" was advertised here with no bwrap.py behind it. Selecting it left sandbox=None
    # and degraded every finding in the run to source-only behind a console warning, which is
    # the exact failure docker.py says doctor exists to prevent. It comes back when the
    # backend does, not before.
    backend: Literal["docker", "none"] = "docker"
    # Let hunters run code during the hunt, not only at proof time. Measured across three
    # targets including a Go repository with a working toolchain: hunters invoked it zero
    # times. Claude hunts by reading. The capability stays because it should pay off on
    # parsers and binaries, but it is off by default rather than costing a container probe
    # per hunt for a tool nothing reaches for.
    hunter_shell: bool = False
    image: str = "python:3.12-slim"
    cpus: float = 1.0
    memory: str = "2g"
    pids_limit: int = 256
    timeout_s: int = 120
    tmpfs_size: str = "256m"


class BudgetConfig(BaseModel):
    """One cell ~ one hunter. One candidate ~ 1-2 validators. Reserve before you hunt."""

    tasks_per_repo: int = 80
    max_concurrent_agents: int = 10
    max_concurrent_sandboxes: int = 4
    validator_reserve_fraction: float = 0.30
    # Share of a model's context window one agent task may occupy. The blog treats staying
    # under a quarter as the thing that stops a model cannibalising its own memory.
    context_occupancy: float = 0.25


class RepoConfig(BaseModel):
    name: str
    path: Path
    enabled: bool = True
    budget_tasks: int | None = None
    scope_paths: list[str] = Field(default_factory=list)
    # A sandbox whose image cannot import the target is a sandbox nobody uses. Measured:
    # hunters offered python:3.12-slim against a Flask app invoked it zero times across a
    # whole run, correctly, because `import flask` fails there. Point this at an image that
    # has the target's runtime dependencies installed.
    sandbox_image: str | None = None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNESS_", env_file=".env", extra="ignore")

    db_path: Path = Path("./.vulness/vulness.db")
    work_dir: Path = Path("./.vulness/work")
    skill_dir: Path | None = None  # cloudflare security-audit-skill checkout

    profile: Profile = "standard"
    hunt: HuntBackend = Field(default_factory=HuntBackend)
    verify: VerifyBackend = Field(default_factory=VerifyBackend)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    budget: BudgetConfig = Field(default_factory=BudgetConfig)
    repos: list[RepoConfig] = Field(default_factory=list)

    @classmethod
    def load(cls, path: Path | None = None) -> Settings:
        """Layer fleet.yaml under environment variables."""
        load_dotenv()
        data: dict = {}
        candidate = path or Path("fleet.yaml")
        if candidate.exists():
            data = yaml.safe_load(candidate.read_text()) or {}
        return cls(**data)

    def resolved_skill_dir(self) -> Path | None:
        if self.skill_dir and self.skill_dir.exists():
            return self.skill_dir
        for guess in (
            Path.home() / "Github/Research/security-audit-skill/skills/security-audit",
            Path("../security-audit-skill/skills/security-audit"),
        ):
            if guess.exists():
                return guess.resolve()
        return None
