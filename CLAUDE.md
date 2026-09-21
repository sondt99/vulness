# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

vulness is an autonomous vulnerability discovery harness. Claude Code hunts, GLM validates.
State lives in SQLite so agents can be stateless and disposable. The design follows
Cloudflare's published VDH/VVS architecture.

Read `docs/PLAN.md` for the architecture and `README.md` for usage before making changes.

## Verification is not optional

```bash
ruff check vulness/ tests/ && pyright vulness/ && pytest -q
```

Run all three before reporting any task complete. File writes succeed even when the code
is wrong; these commands are the only evidence that it is not. If a check fails, fix it
rather than describing it.

## Invariants with tests behind them

Do not break these. Each has a test that will fail, and each exists because the
alternative produced unusable output.

- Only `agents/roles/hunter.py` calls `db.file_finding`. Every other role records a
  verdict through `db.record_validation`.
- The harness never writes to a target repository. Patches go to `work_dir`.
- A PoC that changed the target tree voids its finding, whatever its exit code.
- Every `TaskKind` in `state/models.py` has an entry in `_HANDLERS` in
  `orchestrator/scheduler.py`.
- `db.event()` takes its kind positionally, PEP 570. Callers pass their own `kind` field
  in the payload, and without the `/` that collides and raises at the first event written.

## Things that will surprise you

- **`--max-turns` is hidden in `claude --help` but still accepted.** Do not remove it.
- **GLM 5.3 is a reasoning model.** `reasoning_content` consumes most of the output
  budget. Too small a `max_tokens` returns `finish_reason="length"` with empty content,
  which is a 200 response that means failure.
- **The GLM Coding Plan uses a different base URL.** `api/coding/paas/v4`, not
  `api/paas/v4`. The general endpoint returns "insufficient balance" on a Coding Plan key.
- **`bwrap` and `unshare` do not work on Ubuntu 24.04** by default:
  `kernel.apparmor_restrict_unprivileged_userns=1`. Docker is the sandbox. See
  `docs/PLAN.md`.
- **Typer 0.12 is incompatible with click 8.2 and later.** The CLI uses argparse
  deliberately. Do not reintroduce a CLI framework.
- **`schema_invalid` is retryable, `crash` is not.** A stochastic model returning prose
  instead of JSON is transient. A missing binary is not.

## Style

- Python 3.12, `from __future__ import annotations`, full type hints, 100 columns.
- Comments explain why, never what. Delete any comment that restates its code.
- No em dashes anywhere in this project. Use a colon, a comma, or a hyphen.
- `vulness/agents/roles/hunter.py` is the reference for voice and structure.

## Never commit

`.env`, `.vulness/`, or `fleet.yaml`. All three are git ignored. Findings are unpatched
vulnerability reports; treat run artifacts as sensitive.
