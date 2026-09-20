# Contributing

## The short version

```bash
git clone https://github.com/sondt99/s-ness && cd s-ness
pip install -e ".[dev]"
cp .env.example .env          # add your GLM key
cp fleet.example.yaml fleet.yaml
sness doctor                  # must pass before anything else
```

Then, before every push:

```bash
ruff check sness/ tests/
pyright sness/
pytest -q
```

All three must be clean. There is no "fix it in review" here: the harness runs unattended
for hours, and a type error at hour four costs a whole run.

## What this project wants most

**Accuracy reports.** A false positive or a missed bug, reduced to a synthetic example, is
worth more than a feature. Most of the regression suite came from exactly that: measuring
the harness against a target with known ground truth and fixing what the measurement
exposed. Use the accuracy issue template.

**Prompt improvements.** The prompts in `sness/prompts/` are the product. They are
Markdown on purpose so they can be tuned without touching Python. If you improve one,
say which failure mode you were targeting and what changed in the results.

## Rules that are not negotiable

These are invariants, not style preferences. Each one has a test that fails if you break
it, and each one exists because the alternative produced garbage.

1. **Only the hunt role files findings.** Every other stage records a verdict.
   `tests/test_pipeline.py` enforces this with an AST check. A validator that can file
   becomes a second hunter, and then nothing is checking anything.
2. **The harness never writes to a target repository.** Patches go to the work directory
   as proposals.
3. **A PoC runs against untouched source.** If the tree changed, the finding is void
   regardless of exit code.
4. **A finding requires a stated threat model.** Attacker, boundary, broken assumption.
   No exceptions, no "probably exploitable".
5. **Every declared `TaskKind` has a handler.** A stage in the vocabulary with no route is
   a stage that silently never runs.
6. **No live probing.** Ever. See SECURITY.md.

## Adding a pipeline stage

1. Add the kind to `TaskKind` in `sness/state/models.py`.
2. Write `sness/agents/roles/<name>.py` exposing
   `async def run_<name>(ctx: RoleContext, task: Task) -> TaskOutcome`.
3. Write `sness/prompts/<name>.md`. Literal braces in the JSON contract must be doubled,
   because `render()` uses `str.format`.
4. Register it in `_HANDLERS` in `sness/orchestrator/scheduler.py` and in
   `sness/agents/roles/__init__.py`.
5. Decide where it gets enqueued. A stage nothing schedules is dead code with a test.

`tests/test_pipeline.py` will tell you if you missed step 4.

## Style

- Python 3.12, `from __future__ import annotations`, full type hints, 100 columns.
- Comments explain **why**, never what. If a comment restates the code, delete it.
  The ones worth writing describe a failure you are preventing.
- No em dashes anywhere in the project. Use a colon, a comma, or a hyphen.
- Match the voice of `sness/agents/roles/hunter.py`. It is the reference implementation.

## Agent backends

A backend implements `Agent` from `sness/agents/base.py`. Two rules:

- **Never raise for a model side failure.** Classify it through
  `sness.agents.classify.classify` and return an `AgentResult`. A transient API error that
  arrives as text in a 200 response must not look like a clean empty run.
- **Never read `ANTHROPIC_API_KEY`.** The hunt backend runs on a Claude Code subscription
  and scrubs billing variables from the subprocess environment on purpose.
