[![ci](https://github.com/sondt99/vulness/actions/workflows/ci.yml/badge.svg)](https://github.com/sondt99/vulness/actions/workflows/ci.yml)

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
| "It reviewed the code" ≠ "it found a bug" | Threat model required before filing; PoCs run against read-only source in a sandbox, and a PoC that did not reproduce caps the verdict at `needs_validation`. |
| A validator that only ever agrees | When it says the deciding code was not quoted, the harness fetches exactly those lines and asks once more. |
| The target's own agent config | The hunt runs `--restricted --strict-mcp-config`: no CLAUDE.md, no hooks, no MCP from the repository being audited. |
| A 5-hour run dies at hour 4 | Crash costs the in-flight task only. `--resume` picks up the rest, reclaiming stranded leases. |

## Install

```bash
pip install -e .
echo 'GLM_API_KEY=...' > .env   # Z.AI Coding Plan key, or export it; the shell wins
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
vulness bench                          # score the last run against ground truth
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
4. **Validate** hands the finding to GLM with one instruction: *disprove this*. If GLM
   answers that the deciding code was never quoted, the harness reads exactly the lines it
   named and asks once more, then stops. One round, because a model that still cannot
   decide with the code it chose itself is saying the answer is not in this repository.
5. **Report** is pure rendering. No model, so the prose and the data cannot disagree.

## Testing

Three levels, cheapest first.

**1. Suite and static gates.** No models, no network, no cost. Run these before every push.

```bash
pytest -q                     # 159 tests, a few seconds
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

**3. Scoring against ground truth.** Costs tokens. This is the only test that measures
whether the harness is any good.

```bash
vulness run tests/fixtures/vulnshop -b 42 --gapfill 1
vulness bench --min-recall 0.6 --max-decoys 0
```

`vulness bench` matches findings to labels by file and line and prints precision, recall
and decoys flagged at three verdict tiers. `--min-recall` and `--max-decoys` make it exit
non-zero, because a benchmark nothing can fail is a dashboard.

Ground truth lives in `tests/ground_truth/*.json`, deliberately outside the trees it
describes. It used to sit in a README at the root of each fixture, which put the answer key
inside the directory the hunter reads: a table naming the file and line of every defect,
its severity, and which function was a decoy. `tests/test_decontamination.py` now fails if
any of it reappears there.

`benchmarks/` holds corpora imported from published datasets, 692 targets and 1,055 labels
from SecBench.js and Vul4J. `vulness corpus --help` regenerates them. Scoring a run against
those still needs the targets checked out and buildable, which is the remaining work.

## Status

Working: recon, hunt, validate with one re-ask round, coverage grid, gapfill, sibling
forking, shallow-run detection, budget reserve, wishlist, Docker sandbox, cross-repo trace,
dedup, judge, chain composition, fixer, report, resume, scoring.

Not yet measured honestly. Every run recorded on this box predates the decontamination
above, so whatever recall it shows was read with the answer key sitting in the tree.
`vulness bench` scores those runs at 100% recall on vulnshop and 50% on chainshop, and
neither number means anything until a run happens against the fixtures as they now stand.

`docs/EVALUATION.md` is the honest assessment, including what is built but not
demonstrated. `docs/RESEARCH.md` is the outside comparison. `docs/PLAN.md` is the
architecture.
