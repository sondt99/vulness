"""The target repository is untrusted input, including its agent configuration.

Claude Code loads CLAUDE.md, .claude/settings.json (which can define hooks) and .mcp.json
from the directory it runs in, and the hunt runs with cwd set to the repository it is
auditing. Measured on a probe target carrying all three:

| surface                  | before            | with isolation |
|--------------------------|-------------------|----------------|
| .claude/settings.json    | hook executed     | blocked        |
| .mcp.json                | server executed   | blocked        |
| CLAUDE.md                | reached context   | not in context |

Tool permissions do not contain any of it: hooks and MCP servers are a different mechanism
from tools, so allowedTools and disallowedTools have no bearing on them. `RESEARCH.md` §8
collects the live record of this exact class, including GHSA-ph6w-f82w-28w6 against Claude
Code itself.
"""

from __future__ import annotations

from vulness.agents.claude_cli import ClaudeCodeAgent
from vulness.config import HuntBackend

TOOLS = ["Read", "Grep", "Glob", "Bash(rg:*)", "Bash(git log:*)"]


def _argv(**kw) -> list[str]:
    agent = ClaudeCodeAgent(HuntBackend(**kw))
    return agent._argv("prompt", system=None, cwd=None, allowed_tools=TOOLS)


def test_isolation_is_on_by_default() -> None:
    assert HuntBackend().isolate_target is True


def test_the_hunt_refuses_target_settings_and_mcp() -> None:
    argv = _argv()
    assert "--restricted" in argv, "target .claude/settings.json hooks execute without it"
    assert "--strict-mcp-config" in argv, "target .mcp.json servers execute without it"


def test_restricted_mode_still_gets_the_tools_it_was_given() -> None:
    """--restricted removes the code-running tools unless --tools names them, and
    --allowedTools is not that flag. With Bash(rg:*) allowed but Bash absent from --tools,
    the model reported no Bash tool in the session."""
    argv = _argv()
    names = argv[argv.index("--tools") + 1].split(",")
    assert set(names) == {"Bash", "Glob", "Grep", "Read"}
    assert "(" not in argv[argv.index("--tools") + 1], "--tools takes bare names"


def test_allowedtools_still_constrains_which_bash_invocations_run() -> None:
    """--tools re-admits the tool; --allowedTools is what keeps it to rg and git log."""
    argv = _argv()
    allowed = argv[argv.index("--allowedTools") + 1 :]
    assert "Bash(rg:*)" in allowed and "Bash(git log:*)" in allowed


def test_isolation_never_uses_bare() -> None:
    """--bare looks like the answer and is not: it never reads OAuth or the keychain, so it
    breaks the subscription auth this backend is built on and demands an API key instead."""
    assert "--bare" not in _argv()


def test_isolation_can_be_turned_off_only_deliberately() -> None:
    argv = _argv(isolate_target=False)
    assert "--restricted" not in argv and "--strict-mcp-config" not in argv


def test_no_tools_means_no_tools_flag() -> None:
    agent = ClaudeCodeAgent(HuntBackend())
    argv = agent._argv("p", system=None, cwd=None, allowed_tools=[])
    assert "--tools" not in argv, "an empty --tools would read as a value-less flag"
