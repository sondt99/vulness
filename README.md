# vulness

An autonomous vulnerability-discovery harness. Two models, one database.

**Claude Code hunts** (your subscription, via `claude -p` - no API key).
**GLM-5.3 validates** (Z.AI Coding Plan). Different weights, different blind spots, so
neither model grades its own homework.

Modeled on the architecture Cloudflare described in
[Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness/),
and seeded with the prompts from their released
[security-audit skill](https://github.com/cloudflare/security-audit-skill).

## Why a harness and not just a prompt

Point any frontier model at a repo and it finds bugs for about an hour. Then the context
window fills, it starts forgetting what it found, and it confidently validates its own
false positives. A harness fixes that structurally:

| Failure | Answer in vulness |
|---|---|
| Context exhaustion | All state in SQLite. Agents are stateless, disposable, and stay under ~25% of their window. |
| Self-grading | The validator **cannot file findings** - enforced by an AST test, not a prompt. |
| One model's blind spots | Hunt on Claude, validate on GLM. |
| "It reviewed the code" ≠ "it found a bug" | Threat model required before filing; PoCs run against read-only source in a sandbox. |
| A 5-hour run dies at hour 4 | Crash costs the in-flight task only. `--resume` picks up the rest. |

## Install

```bash
pip install -e .
export GLM_API_KEY=...          # Z.AI Coding Plan key
claude --version                # must be logged in (subscription, not an API key)
vulness doctor                    # verifies both models + the sandbox before you spend a run
```

`doctor` is not decorative. It starts a container and asserts the network is actually
unreachable and the target mount is actually read-only, because a sandbox that silently
fails to start turns the whole harness into a very expensive `grep`.

## Use

```bash
vulness run /path/to/repo              # recon -> hunt -> validate -> report
vulness run /path/to/repo -b 40 -g 2   # bigger budget, two gapfill passes
vulness status                         # where the last run got to
vulness findings -v confirmed          # what survived validation
vulness findings -v rejected           # what the validator killed, and why
vulness wishlist                       # what agents asked for and did not get
vulness report -o REPORT.md
```

## How a run works

```
recon ──▶ hunt ──▶ validate ──▶ report
  │        │ ▲         │
  │        │ └── sibling forks (leads outside the current cell)
  │        │ ▲
  │        │ └── gapfill (cells the grid says are thin)
  └────────┴── all of it contending for one worker pool
```

1. **Recon** maps the repo and *writes its own threat model* - including attack classes
   specific to this codebase. On the calibration target it invented
   `partial-sanitization-bypass`, which is precisely the bug that was there.
2. **Hunt** attacks one `(area × attack-class)` cell. It must state attacker, boundary and
   broken assumption before it may file anything.
3. **Gates** run before any validator is paid: a structural check, then a deterministic
   file/line check written in plain Python - models hallucinate line numbers, and a model
   asked to check another model's line numbers hallucinates agreement.
4. **Validate** hands the finding to GLM with one instruction: *disprove this*.
5. **Report** is pure rendering. No model, so the prose and the data cannot disagree.

## Testing

Three levels, cheapest first.

**1. Suite and static gates.** No models, no network, no cost. Run these before every push.

```bash
pytest -q                     # 39 tests, under a second
ruff check vulness/ tests/
pyright vulness/
```

What they actually guard: that only the hunt role can file findings, that every declared
stage has a handler, that the context budget converges, and a regression for each bug a
live run has exposed.

**2. Environment self-test.** Touches both models and starts a container. Effectively free.

```bash
vulness doctor
```

Four checks, and it refuses to dispatch execution tasks if the sandbox fails, because a
sandbox that silently does not start turns the harness into a very expensive grep.

**3. Calibration against known ground truth.** Costs tokens. This is the only test that
measures whether the harness is any good.

```bash
vulness run tests/fixtures/vulnshop -b 42 --gapfill 1
vulness findings -v confirmed
```

`tests/fixtures/vulnshop/README.md` lists the planted defects, including one decoy that
must NOT be reported. A healthy run finds three real bugs and stays silent about the
decoy. If it reports the decoy, that is a false positive worth an issue.

## Calibration

Measured against a target with known ground truth (2 planted bugs + 1 crypto decoy):

- Found the unauthenticated SQL injection, the `../` path traversal, and an auth bypass
  the author had written by accident.
- Did **not** flag the planted `hmac.compare_digest` decoy.
- Two defects this surfaced in vulness itself - attack class splitting one bug into three
  identities, and `schema_invalid` being treated as fatal - are now regression tests.

## Measured behaviour

Two-repo fleet run against the calibration fixtures, after the scaling work:

| | Cloudflare | vulness |
|---|---|---|
| Repos | 128 | 2 |
| Workers | 50-200 | 6 |
| Coverage | grid driven to a clean pass | 11/14 cells (79%) |
| Sibling-fork rate | ~9%, up to ~20% by model | 19% |
| Peak agent context | under 25% of window | 28% |
| Stages exercised live | all | recon, hunt, validate, judge, trace, dedup |

Grid size scales with the target: 3 files gives 6 cells, ~600 files gives 81. A flat cap
previously gave a 102 line fixture the same 80 cell grid as a large service, and 6 of
those cells were ever reached.

## Status

Working: recon, hunt, validate, coverage grid, gapfill, sibling forking, shallow-run
detection, budget reserve, wishlist, Docker sandbox, report, resume.

Not built yet, deliberately: cross-repo tracing and a dedicated dedup agent. Cloudflare's
advice is to skip both until you have more than one repo that matters and are actually
drowning in noise. See `docs/PLAN.md`.
