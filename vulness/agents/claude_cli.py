"""Claude Code CLI backend -- the hunter half of the two-model design.

This drives the `claude` binary headless (`-p`) rather than the Anthropic API, for one reason:
it runs on the operator's *subscription*, so a fleet sweep costs a flat monthly fee instead of
per-token API billing. That property is fragile -- the CLI silently prefers ANTHROPIC_API_KEY
when it is present -- so this module scrubs the environment before every launch rather than
trusting the shell to be clean.

The hunter reasons over source with read-only tools; anything that needs to *execute* goes to
the sandbox. GLM (vulness.agents.glm) then re-reads what this backend claims to have found.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from vulness.agents.base import Agent, AgentResult
from vulness.agents.classify import classify
from vulness.config import HuntBackend

# Inherited variables that would move this run off the subscription and onto metered billing.
# vulness launches thousands of hunts; one stray export is the difference between a flat fee and
# a five-figure invoice, and the CLI gives no warning when it switches. Strip, never trust.
_BILLING_ENV_BLOCKLIST = frozenset(
    {
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
    }
)

_READ_CHUNK = 1 << 16
# A single JSONL line is an event, not a file. Past this the stream is garbage; drop it rather
# than let an unterminated flood grow the buffer without bound.
_MAX_PENDING_BYTES = 64 << 20
_MAX_STDERR_BYTES = 64 << 10
_KILL_GRACE_S = 5.0
_HEALTH_TIMEOUT_S = 15.0


class _JsonlCollector:
    """Incremental JSONL parser for `--output-format stream-json`.

    Parsing as bytes arrive (not once at exit) is what makes a timed-out hunt still worth
    reading: the events collected before the kill are the only record of what the agent saw.
    """

    def __init__(self) -> None:
        self.events: list[dict] = []
        self.terminal: dict[str, Any] | None = None
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> None:
        self._buf.extend(chunk)
        while (newline := self._buf.find(b"\n")) >= 0:
            line = bytes(self._buf[:newline])
            del self._buf[: newline + 1]
            self._consume(line)
        if len(self._buf) > _MAX_PENDING_BYTES:
            self._buf.clear()

    def finish(self) -> None:
        """Flush a final line that the process emitted without a trailing newline."""
        if self._buf:
            self._consume(bytes(self._buf))
            self._buf.clear()

    def _consume(self, raw: bytes) -> None:
        line = raw.strip()
        if not line:
            return
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Truncated tail, or a stray non-JSON write into stdout. One bad line must never
            # cost us the whole transcript.
            return
        if not isinstance(event, dict):
            return
        self.events.append(event)
        if event.get("type") == "result":
            self.terminal = event


async def _pump(stream: asyncio.StreamReader | None, sink: Callable[[bytes], None]) -> None:
    """Drain a pipe in fixed chunks.

    Deliberately not readline(): a stream-json line carrying a large tool result overruns
    StreamReader's line limit, and readline() raises there instead of yielding the event.
    """
    if stream is None:
        return
    while chunk := await stream.read(_READ_CHUNK):
        sink(chunk)


def _append_capped(buf: bytearray, chunk: bytes) -> None:
    if len(buf) < _MAX_STDERR_BYTES:
        buf.extend(chunk[: _MAX_STDERR_BYTES - len(buf)])


async def _kill_process_group(proc: asyncio.subprocess.Process) -> None:
    """Kill the group, not the process.

    The CLI forks tool subprocesses (rg, git, node). proc.kill() reaps the parent and leaves
    those holding the pipe open, so the orchestrator hangs on a run it already gave up on.
    Safe only because every process here is launched with start_new_session=True.
    """
    if proc.returncode is not None:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            await asyncio.wait_for(proc.wait(), _KILL_GRACE_S)
            return
        except TimeoutError:
            continue


def _subscription_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in _BILLING_ENV_BLOCKLIST}


def _json_directive(schema: dict[str, Any]) -> str:
    rendered = json.dumps(schema, indent=2, ensure_ascii=False)
    return (
        "\n\nWhen you are finished, end your reply with exactly one fenced ```json block and "
        "write nothing after it. That block must hold a single JSON object matching this "
        f"schema:\n```json\n{rendered}\n```"
    )


def _assistant_text(events: list[dict]) -> str:
    """Concatenate assistant text blocks -- the fallback when no terminal event arrived."""
    parts: list[str] = []
    for event in events:
        if event.get("type") != "assistant":
            continue
        message = event.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str):
            if content:
                parts.append(content)
            continue
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "text":
                continue
            text = block.get("text")
            if isinstance(text, str) and text:
                parts.append(text)
    return "\n".join(parts)


def _resolved_model(events: list[dict], fallback: str) -> str:
    """Config carries an alias ("sonnet"); the transcript carries the snapshot actually served.

    Record the snapshot: a finding is only reproducible against the weights that produced it.
    """
    for event in reversed(events):
        message = event.get("message")
        if isinstance(message, dict):
            model = message.get("model")
            if isinstance(model, str) and model:
                return model
    return fallback


def _as_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _usage_tokens(terminal: dict[str, Any] | None) -> tuple[int, int]:
    """Cache reads and cache writes are real input tokens.

    With prompt caching the CLI reports input_tokens in the single digits while tens of
    thousands of cached tokens do the work; counting only that field makes budget accounting
    useless, so fold the cache fields back in.
    """
    if not terminal:
        return 0, 0
    usage = terminal.get("usage")
    if not isinstance(usage, dict):
        return 0, 0
    tokens_in = (
        _as_int(usage.get("input_tokens"))
        + _as_int(usage.get("cache_creation_input_tokens"))
        + _as_int(usage.get("cache_read_input_tokens"))
    )
    return tokens_in, _as_int(usage.get("output_tokens"))


class ClaudeCodeAgent(Agent):
    """One headless `claude -p` run per task, on subscription auth."""

    name = "claude-code"

    def __init__(self, cfg: HuntBackend | None = None) -> None:
        self.cfg = cfg or HuntBackend()
        self.model = self.cfg.model

    def _argv(
        self,
        prompt: str,
        *,
        system: str | None,
        cwd: Path | None,
        allowed_tools: list[str] | None,
    ) -> list[str]:
        argv = [
            self.cfg.cli,
            "-p",
            prompt,
            # stream-json rather than plain text, and it is not about streaming: the terminal
            # event carries is_error/subtype. A transient backend failure is delivered as prose
            # inside a 200 OK with exit status 0, and that flag is the only machine-readable
            # signal that separates "found nothing" from "never actually ran".
            "--output-format",
            "stream-json",
            # The CLI refuses stream-json in print mode without it.
            "--verbose",
            "--model",
            self.cfg.model,
            "--permission-mode",
            self.cfg.permission_mode,
            "--max-turns",
            str(self.cfg.max_turns),
        ]
        if system:
            # Append, never replace: the built-in prompt is what makes the tool loop work.
            argv += ["--append-system-prompt", system]
        if cwd is not None:
            # cwd already scopes the session, but a repo reached through a symlink (git
            # worktrees, /tmp) resolves elsewhere and tool calls get denied on the real path.
            argv += ["--add-dir", str(Path(cwd).resolve())]
        tools = allowed_tools if allowed_tools is not None else self.cfg.allowed_tools
        # Variadic flags: these must stay last, and each stops at the next `--` token.
        if tools:
            argv += ["--allowedTools", *tools]
        if self.cfg.disallowed_tools:
            argv += ["--disallowedTools", *self.cfg.disallowed_tools]
        return argv

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
        if schema is not None:
            prompt = prompt + _json_directive(schema)
        argv = self._argv(prompt, system=system, cwd=cwd, allowed_tools=allowed_tools)
        budget = float(timeout_s if timeout_s is not None else self.cfg.timeout_s)
        started = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd is not None else None,
                env=_subscription_env(),
                # Own process group, so the kill path can never signal the orchestrator.
                start_new_session=True,
            )
        except OSError as exc:
            # Missing binary or unusable cwd. The ABC forbids raising; classify it instead so
            # the scheduler records a crash rather than losing the task.
            return AgentResult(
                classification="crash",
                model=self.cfg.model,
                duration_s=time.monotonic() - started,
                error=f"cannot launch {self.cfg.cli!r}: {exc}",
            )

        collector = _JsonlCollector()
        stderr_buf = bytearray()
        timed_out = False

        async def _consume() -> int:
            await asyncio.gather(
                _pump(proc.stdout, collector.feed),
                _pump(proc.stderr, lambda chunk: _append_capped(stderr_buf, chunk)),
            )
            return await proc.wait()

        task = asyncio.ensure_future(_consume())
        exit_code: int | None
        try:
            exit_code = await asyncio.wait_for(task, budget)
        except TimeoutError:
            timed_out = True
            exit_code = None
            await _kill_process_group(proc)
        finally:
            collector.finish()

        duration = time.monotonic() - started
        terminal = collector.terminal
        # The terminal event's own text is authoritative; assistant blocks are the salvage path
        # for a run that died before emitting one.
        text = ""
        if terminal is not None and isinstance(terminal.get("result"), str):
            text = terminal["result"]
        if not text.strip():
            text = _assistant_text(collector.events)

        stderr_text = bytes(stderr_buf).decode("utf-8", "replace").strip()
        if exit_code not in (None, 0) and not text.strip() and stderr_text:
            # classify()'s crash branch quotes `text`; an empty quote hides the real cause
            # (revoked auth, rejected flag), which is exactly what stderr holds here.
            text = stderr_text

        result = AgentResult(
            text=text,
            duration_s=duration,
            model=_resolved_model(collector.events, self.cfg.model),
            raw_events=collector.events,
        )
        result.tokens_in, result.tokens_out = _usage_tokens(terminal)
        if terminal is not None:
            cost = terminal.get("total_cost_usd")
            if isinstance(cost, int | float):
                result.cost_usd = float(cost)

        payload = result.extract_json() if schema is not None else None
        classification, reason = classify(
            text=text,
            exit_code=exit_code,
            timed_out=timed_out,
            terminal_event=terminal,
            expects_json=schema is not None,
            payload=payload,
        )
        result.classification = classification
        result.payload = payload
        result.error = reason
        if timed_out and not result.error:
            result.error = f"exceeded {budget:.0f}s"
        return result

    async def health(self) -> tuple[bool, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.cfg.cli,
                "--version",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=_subscription_env(),
                start_new_session=True,
            )
        except OSError as exc:
            return False, f"{self.cfg.cli!r} not executable: {exc}"
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), _HEALTH_TIMEOUT_S)
        except TimeoutError:
            await _kill_process_group(proc)
            return False, f"{self.cfg.cli} --version timed out"
        version = out.decode("utf-8", "replace").strip()
        if proc.returncode != 0:
            return False, f"{self.cfg.cli} --version exit {proc.returncode}: {version[:200]}"
        return True, version or "unknown version"
