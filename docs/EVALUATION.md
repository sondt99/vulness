# vulness - Architecture Evaluation

Assessed 2026-09-22, revised 2026-09-26. The assessment below is kept as written; §0
records what has since changed and what the revision found that the first pass missed.

Assessed against Cloudflare's
[Build your own vulnerability harness](https://blog.cloudflare.com/build-your-own-vulnerability-harness/)
and the current research literature. See `RESEARCH.md` for the literature.

Method: full read of `vulness/` (10,127 LOC), the prompt corpus, and the test suite, plus a
read-only query of `.vulness/vulness.db` covering the 5 runs recorded on this box. Every
claim below cites either a `file:line` or a row in that database. Claims that could not be
verified from code or data are marked as such.

---

## 0. Revision, 2026-09-26

Ten of the fourteen prioritized fixes in §7 have landed, and the revision turned up three
things the first pass did not.

**The calibration target shipped its own answer key.** `tests/fixtures/vulnshop/README.md`
carried a ground-truth table naming the file and line of every planted defect, its severity,
and which function was a decoy that must produce no finding. `api/auth.py` announced itself
as a decoy in its own module docstring. The hunt runs with `cwd` set to the target and
`Read`, `Grep` and `Glob` allowed, so all of it was readable by the model being measured.
Every run recorded in §2 was scored with the answers in the tree. Ground truth now lives in
`tests/ground_truth/*.json` and `tests/test_decontamination.py` fails if it comes back.

**§3.1 is confirmed, and its suggested fix was wrong.** A probe target carrying a
`CLAUDE.md`, a `.claude/settings.json` hook and a `.mcp.json` was audited with the previous
invocation: the hook executed, the MCP server executed, and the CLAUDE.md reached the
model's context. Not inferred from the help text, observed. But `--bare`, which §3.1
recommended, never reads OAuth or the keychain, so it would have broken the subscription
auth this backend is built on. The isolation that works is
`--restricted --strict-mcp-config`, plus `--tools` to re-admit the tools `--restricted`
removes, because `--allowedTools` is not that flag.

**The documented way to supply the GLM key never worked.** `Settings` declares
`env_prefix="VULNESS_"` with `env_file=".env"`, so pydantic-settings read that file looking
only for `VULNESS_*` names while `VerifyBackend.api_key()` read `os.environ` directly.
`GLM_API_KEY` in `.env`, which `.env.example` and the README both instruct, reached nothing.
Every run that validated was one where the operator had exported it by hand.

There is now a scorer. `vulness bench` reports precision, recall and decoys flagged at three
verdict tiers, gated by `--min-recall` and `--max-decoys`, and `benchmarks/` holds 692
targets and 1,055 labels imported from SecBench.js and Vul4J against the seven the project
had. What it has not done is score a run made since the decontamination, so every number in
§2 and §5 still stands unrevised.

---

## Summary

The architecture is a faithful reimplementation of the VDH/VVS design and improves on it in
three places: validation runs on a genuinely different vendor's model, the deterministic
gates run before a validator is paid, and cross-run memory persists what a repository has
already proved about itself.

The engineering is sound. The problem is that almost nothing is demonstrated. The central
claim, that a second model adversarially disproves the first, has never once occurred. Four
of ten stages have never executed. The mechanism the sandbox documentation calls "the clause
the whole harness rests on" has no test. Four configuration knobs do nothing.

The gap is between "built" and "shown to work", not between "built" and "correct".

---

## 1. Fidelity to the Cloudflare architecture

| Cloudflare element | vulness | Assessment |
|---|---|---|
| VDH/VVS two-model split | Claude hunts, GLM validates | Better than planned. `PLAN.md` specified Model A for validation; the code uses a different vendor entirely. |
| Validator cannot file findings | AST test over `validator.py` | Enforced, but as a lint rather than a capability boundary. See §3.8. |
| Validator can reject | One re-ask round on the code it names | Added 2026-09-26, unexercised. §4 explains why it was arithmetically impossible before. |
| PoC on untouched source | Baseline SHA-256, `tainted` verdict | Correct mechanism (`findings/poc.py:126-132`), zero test coverage (§3.9). |
| Sandbox | `--read-only --cap-drop=ALL --security-opt=no-new-privileges --network=none`, `:ro` mount | Stronger than the blog describes. `doctor` actively tries to reach 1.1.1.1 and write `/target`, and fails if either succeeds (`sandbox/docker.py:170-174`). |
| Stateless agents, SQLite state | WAL, keyed by run and repo | Correct. Only `recon` ever writes a `stages` row, so that table oversells its generality. |
| Context under 25% of window | Measured post hoc, logged | Measured, never enforced (§3.5). |
| Coverage grid, gapfill | Grid built; gapfill bounded by a pass quota | Diverges. The blog runs gapfill "until it stops producing findings"; this stops after `gapfill_passes` (default 1). |
| Feedback loop | Implemented, gated on rejections | Structurally unreachable (§4). |
| Wishlist | 13 entries recorded | Correct, and matches the blog's "main way the agents talk back to us". |
| Response classification | `agents/classify.py` | Correct, and the subtlest lesson in the blog: a 200 OK carrying error prose is classified, not trusted. |

Beyond the blog: `agents/roles/chain.py` composes confirmed findings and latent primitives
into exploit chains. This has no counterpart in the reference architecture and is the right
instinct; Cloudflare's later work and the primitive-composition literature both point the
same way (`RESEARCH.md` §6). One real chain has been filed against the `chainshop` fixture.

---

## 2. What the run database shows

Five runs, two fixture repositories, 90 tasks, $7.73, 10.2M input and 353k output tokens.

| Measure | Observed | Note |
|---|---|---|
| Adversarial validations | 22 `upheld`, 15 `needs_validation`, **0 `disproved`** | The schema allows `disproved` (`state/models.py:192`). It has never been written. |
| Hunt tasks | 25 done, **34 abandoned**, 5 leased, 2 shallow | All 34 abandoned on `task.budget_hold` (§3.2). |
| Findings | 10 total: 4 confirmed, 1 duplicate, 5 needs_validation | |
| Coverage | 8 of 54 cells covered (15%) | 14 thin, 32 assigned. |
| Attack classes hunted | `injection`, `access-control`, `resource-and-file-handling` | 3 of 10 builtin classes, corrected 2026-09-26. No crypto cell was ever created. |
| PoC outcomes | **10 of 10 refuted**, 0 verified, 0 tainted | Corrected 2026-09-26: every PoC that has ever run failed to reproduce, and every one was upheld anyway (§4). |
| Context breaches | 10 `context.exceeded` at 27.2% and 28.1% | Target 25%. |
| Stages never executed | `gapfill`, `feedback`, `trace`, `fix` | `trace` and `fix` are correctly gated, not broken. See §5. |
| Real repositories audited | 0 | Only `tests/fixtures/vulnshop` and `chainshop`. |

Two consequences worth stating plainly.

**The decoy result is vacuous.** `README.md` reports that the harness "did not flag the
planted `hmac.compare_digest` decoy". No crypto cell was ever created, so the decoy's attack
class was never hunted. The harness did not resist a false positive; it never looked.
Relatedly, `crypto-and-secrets` and `logic-and-state` have no entry in `COMPANION_MAP`
(`coverage/cells.py:38-52`), so `_companion()` returns `None` for them silently.

**One run is stuck.** `run_4b0d855da2e0` sits at `status='running'` with 5 hunt tasks still
`leased`. That is a live instance of the resume defect in §3.4.

---

## 3. Verified defects

Each entry is reproduced from code or data, not inferred.

### 3.1 The hunt subprocess trusts the repository it is auditing  [FIXED 2026-09-26]

`agents/roles/hunter.py:223` runs `claude -p` with `cwd` set to the target repository. Claude
Code loads `CLAUDE.md`, `.claude/settings.json` (which can define hooks) and `.mcp.json` from
that directory. `agents/claude_cli.py:236-259` passes no `--bare`, no `--settings` override
and no MCP isolation, and nothing anywhere strips repository-local agent configuration.

Hooks and MCP servers are a different mechanism from tool permissions, so the
`allowedTools`/`disallowedTools` policy does not contain them. `SECURITY.md` already names
target source as untrusted input. This is the most serious issue in the evaluation: a
vulnerability harness that executes attacker-controlled agent configuration from its target.

The installed CLI (2.1.258) offers `--bare`, documented as "skip hooks, LSP, plugin".

### 3.2 The validator reserve blocks hunting with nothing to validate  [FIXED 2026-09-26]

`orchestrator/budget.py:44-50`:

```python
reserve = int(self.per_repo * self.validator_reserve)
unvalidated = len(self.db.findings(self.run_id, verdict="candidate", repo_id=repo_id))
needed = max(reserve, unvalidated)
if remaining <= needed:
    return BudgetDecision(False, f"holding {remaining} tasks in reserve to validate {unvalidated} open candidates")
```

The 30% floor applies even when `unvalidated` is 0, which is the recorded reason on all 34
abandoned hunts: `holding 3 tasks in reserve to validate 0 open candidates`. The last 30% of
every repository's budget can never be spent on hunting.

This class of bug has been hit before. `orchestrator/scheduler.py:396-407` records that "102
of 132 tasks were budget-abandoned during discovery and triage never ran at all". That fix
exempted triage from the budget; it did not fix the floor.

### 3.3 Docker sandbox concurrency is unbounded  [FIXED 2026-09-26]

`config.py:78` declares `max_concurrent_sandboxes` (default 4) and `fleet.example.yaml:7`
sets it to 3. Neither value is read anywhere else, and there are no semaphores in `vulness/`.
PoC execution runs inline inside a hunt task, so the real ceiling is `max_concurrent_agents`
(default 10). Tuning the documented knob does nothing.

### 3.4 Orphaned leases stall a resume, and a crashed recon corrupts coverage  [HALF FIXED]

Leases are reclaimed at startup as of 2026-09-26. The `seed_recon` duplicate guard is not
written, so the coverage-reset half of this entry stands.

Nothing reclaims leases at startup. `pending_count()` counts `leased` as pending
(`state/db.py:309-314`), and the worker loop only reaches gapfill, triage or shutdown when
`pending_count() == 0` (`orchestrator/scheduler.py:198-217`). A resume after a crash with
tasks in flight therefore busy-polls until the leases expire at `_LEASE_SECONDS = 3600`.

Recon is worse. `seed_recon()` re-enqueues whenever the stage is not `done`, with no check
for an outstanding attempt (`orchestrator/scheduler.py:104-117`). When both the orphan and
the replacement complete, `upsert_cell` does `SET status=excluded.status` (`state/db.py:345-347`)
and `build_grid()` always stamps `planned` (`coverage/cells.py:268`), so cells that reached
`covered` are reset and re-hunted. Hunt tasks do not have this problem because `seed_hunts()`
flips the cell to `assigned` at enqueue time.

### 3.5 The context ceiling is measured, never enforced

`agents/context_budget.py` computes the budget as `int(window * occupancy) - 22000`. When
trimming cannot fit the required sections, `FitReport.over_budget` is set and the prompt is
dispatched anyway with the log level raised to `warn` (`agents/roles/hunter.py:210-218`).
`peak_occupancy` is only computed after the subprocess exits, so nothing can act on it
mid-task. Token estimation is `len(text) / 3.0`, a character proxy rather than a tokenizer.

### 3.6 Latent-primitive fingerprints are unstable across processes  [FIXED 2026-09-26]

`agents/roles/hunter.py:306`:

```python
fp = f"lp_{abs(hash((task.repo_id, lp.file, lp.scope, lp.title))) & 0xFFFFFFFFFFFF:012x}"
```

`hash()` on strings is `PYTHONHASHSEED`-randomized. The same tuple produced 73486012744111
and 57328230013814 in two processes. The cross-run lookup on the next line is therefore inert
for latent primitives, so the same primitive re-files on every run. This defeats the stated
purpose of the artifact, which `agents/roles/chain.py:12-14` describes as bridging halves "found weeks
apart". `findings/fingerprint.py:33-50` gets this right with SHA-256.

### 3.7 Gapfill is bounded by a pass quota, not by coverage  [HALF FIXED]

Gapfill now backfills once the pool is half idle rather than waiting for a fully drained
queue, and excludes cells that already have a task scheduled. The pass quota itself stands.

`orchestrator/scheduler.py:506`: `if self._gapfill_done >= self.gapfill_passes: return False`,
default 1. `thin_cells()` can still be reporting virgin cells and gapfill will decline to act.
The blog treats gapfill as the cost-to-coverage lever run iteratively to a clean pass.

### 3.8 Write isolation is a lint, not a capability boundary

`PLAN.md` specifies enforcement "in the task router, not in the prompt: a validator task is
dispatched with a tool policy that has no `file_finding` tool bound at all". The
implementation hands `validator.py` the same `Database` object the hunter holds. Enforcement
is `tests/test_write_isolation.py`, an AST scan. That is a real control and it would catch a
regression in CI, but it is not the boundary the plan describes.

### 3.9 The taint check and the sandbox have no tests

`sandbox/policy.py:22` calls the source-integrity check "the clause the whole harness rests
on". There are zero references to `SourceIntegrity` or `DockerSandbox` anywhere in `tests/`.
The two tests that sound like coverage assert properties of the `PocOutcome` dataclass and the
`POC_TO_VALIDATION` mapping; neither builds a tree, mutates it, and asserts the diff fires.
CI explicitly declines to run `doctor` or `run`.

Two related gaps. `SourceIntegrity.snapshot` skips a directory allowlist including
`node_modules`, `__pycache__` and `.git` (`sandbox/policy.py:152-169`); the docstring concedes
a mutation hidden there "goes unseen". And `vulness doctor` returns 0 when the sandbox is
broken (`cli.py:93-104`), so its exit code cannot gate CI on PoC verification being available.

### 3.10 `bwrap` is a phantom backend  [FIXED 2026-09-26]

`config.py:58` advertises `Literal["docker", "bwrap", "none"]`. There is no `bwrap.py` in
`vulness/sandbox/`. Selecting it leaves `sandbox = None` and degrades every finding in the run
to source-only behind a console warning, which is the exact failure mode
`sandbox/docker.py:110-114` says `doctor` exists to prevent.

### 3.11 The report renderer interpolates model text unescaped  [FIXED 2026-09-26]

`report/render.py` is genuinely model-free, but it formats model-authored strings into
Markdown with bare f-strings: titles (`report/render.py:77`), threat-model fields (`report/render.py:83`),
validator reasons (`report/render.py:106`) and raw PoC stdout inside a fenced block
(`report/render.py:108-109`). The schema enforces only a 12-character minimum on titles. Text
influenced by an untrusted target can break the report's structure.

---

## 4. Root cause: the validator cannot reject

This is the finding that matters most, because it is structural rather than a tuning problem.

`prompts/validator.md:29-47` asks GLM to attack a finding five ways: does the quoted code say
what is claimed, is there a control the hunter missed, is the attacker real, is the result
real, is it self-impact. The harness gives GLM:

- 12 lines either side of at most 12 cited locations (`agents/roles/validator.py:33-38`)
- no filesystem and no tools at all (`agents/glm.py:229-232`, `del cwd, allowed_tools`)

Only the first check is answerable from that. The prompt concedes it: "This is the check you
are best placed to make, because you can see the code and the claim side by side." Checks 2
through 5 need code that was not quoted, and the prompt routes exactly that case to
`needs_validation`: "If deciding this needs code that was not quoted, that is
`needs_validation`."

So every adversarial check exits as `needs_validation` and every quote-accuracy check exits as
`upheld`. **22 upheld, 15 needs_validation, 0 disproved is the arithmetically expected output
of this design.** No prompt sharpening changes it.

`needs_validation` is terminal. Nothing re-fetches the named missing fact; the value appears
only in CLI colouring and report rendering.

The validator is also overriding the dynamic evidence. Every finding's chain reads:

```
mechanical:upheld, sandbox:needs_validation, adversarial:upheld, judge:upheld
```

The sandbox reports that the PoC did not demonstrate the effect, that result is packed into
the validator's prompt (`agents/roles/validator.py:120-137`), and GLM upholds regardless. The
one layer with ground truth is outvoted by the layer with the least context.

**The fix is already half-built.** The prompt asks for the exact missing location. Feed it
back through the same deterministic reader that builds `_source_block`, re-ask once, cap the
loop at one or two rounds. That closes the context gap without granting GLM filesystem access,
so the cross-model independence the design exists for survives.

*Built 2026-09-26, exactly as described, and not yet exercised against a live model.* The
sandbox override is closed separately: an `upheld` verdict on a finding whose PoC was
refuted is capped at `needs_validation`, with the model's own answer kept alongside the cap.

---

## 5. Unmet exit criteria

`PLAN.md` sets its own acceptance tests. Three have not been met, which matters more than any
external comparison.

| Milestone | Exit criterion | Status |
|---|---|---|
| M1 | "the Validator demonstrably rejects a planted false positive" | **Not met.** 0 `disproved` in 37 validations. |
| M2 | "a source-mutating PoC is auto-rejected" | **Not exercised.** No `tainted` verdict has ever been recorded, and no test covers the mechanism. |
| M3 | "Gapfill drives cell coverage to a clean pass" | **Not met.** Gapfill has never run; coverage is 15%. |
| M4 | "two models disagree on >=1 finding and the disagreement is surfaced" | **Not met.** The two models have never disagreed. |

`gapfill` is genuinely misconfigured (§3.7). `trace`, `feedback` and `fix` are correctly
gated rather than broken: `trace` needs more than one repository and every run was
single-repo, `fix` needs `--fix` which was never passed, and `feedback` needs four `disproved`
validations, which §4 explains can never arrive.

---

## 6. What is strong

Worth recording so it is not lost in the defect list.

- **Deterministic gates before a model is paid.** `candidate_gate()` rejects stub threat
  models and traces with no sink; `mechanical_check()` verifies that cited files and lines
  exist and are inside the repo. A finding rejected mechanically is never selected for
  validation, so the saving is structural rather than advisory (`findings/schema.py:146-203`).
- **The sandbox.** Read-only rootfs, dropped capabilities, no new privileges, pinned
  memory and swap, PID cap, tmpfs, `--init` to reap orphans, environment built from an
  allowlist rather than inherited. `doctor` verifies isolation by trying to violate it.
- **Cross-run memory.** `repo_maps`, `coverage_history`, `weakness_digest` and SHA-256
  fingerprint lookup, all covered by `tests/test_cross_run.py`.
- **Path containment is applied consistently.** Every place a model-cited path is read back,
  containment is re-checked: `findings/schema.py:171-177`, `agents/roles/validator.py:75-79`, `agents/roles/judge.py:145-151`,
  `agents/roles/fixer.py:97-102`. Model-supplied filenames are reduced to `Path(name).name`.
- **Secret discipline.** Billing environment stripped before each CLI launch
  (`agents/claude_cli.py:31-39`); sandbox environment built from a positive allowlist; the judge
  reads `.env.example` and refuses `.env` (`agents/roles/judge.py:257-260`).
- **Regressions are documented with numbers at the point of fix.** Sibling forking capped at
  20% because uncapped it reached 33%; `peak_occupancy` skips the cumulative terminal event
  because it raised 19 false alerts; grid sizing counts the real tree because summing per-area
  counts sized a 707-file repository at 29 cells instead of 94.
- **No shell anywhere.** Every subprocess uses `create_subprocess_exec` with an argv list.
  `sandbox/policy.py:340-357` refuses a bare string command.

---

## 7. Prioritized fixes

| # | Fix | Status |
|---|---|---|
| 1 | Isolate the hunt subprocess from target-controlled agent config | **done**, as `--restricted --strict-mcp-config --tools`, not `--bare`. See §0. |
| 2 | Re-fetch on `needs_validation` and re-ask once, so the validator can reject | **done**, unexercised against a live model |
| 3 | Stop upholding findings whose PoC did not demonstrate the effect | **done**, as a verdict ceiling that never blocks a rejection |
| 4 | Reclaim orphaned leases at startup; guard `seed_recon` against duplicates | **half**: leases reclaimed, recon guard outstanding |
| 5 | Reserve floor must collapse to `unvalidated` when nothing is open | **done** |
| 6 | SHA-256 instead of `hash()` for latent-primitive fingerprints | **done** |
| 7 | Wire `max_concurrent_sandboxes`, or delete it | **done**, both it and `max_concurrent_agents` |
| 8 | Make gapfill converge instead of running a fixed number of passes | **half**: backfills at half-idle, pass quota stands |
| 9 | Tests for `SourceIntegrity` and `DockerSandbox`; one integration test per role with a mock agent | **partial**: `tests/conftest.py` gives roles a scripted agent and the validator has one; the sandbox and taint check still have none |
| 10 | Remove `bwrap` from the backend Literal, or fail loudly when selected | **done**, removed |
| 11 | Escape model-authored text in the renderer | **done** |
| 12 | Companions for `crypto-and-secrets` and `logic-and-state` | **done**, mapped to the closest real coverage |
| 13 | Adopt a real benchmark; report precision and recall | **done**: `vulness bench`, plus 692 imported targets in `benchmarks/` |
| 14 | Inject static-analysis output into hunter prompts as context, never as a tool | outstanding |

New since, and not on the original list:

| Fix | Status |
|---|---|
| Take the ground truth out of the tree the harness audits | **done**, §0 |
| Make the `.env` the docs point at reach the client that reads it | **done**, §0 |
| `doctor --require-sandbox`, so CI can gate on PoC execution | **done** |

What remains is 4 and 8's second halves, 9's sandbox tests, 14, and the thing none of them
substitute for: a run against the fixtures as they now stand.

---

## 8. Documentation that no longer matches the code  [FIXED 2026-09-26]

`README.md` was stale in four material ways, all four now corrected: the test count, the
claim that cross-repo trace and the dedup agent were "not built yet, deliberately" while
`trace.py` is 747 lines and `dedup.py` is 605, the 11-of-14-cells coverage figure against a
database showing 8 of 54, and the absence of `chain`, `fixer`, `feedback` and `hunter` by
name. It also still pointed readers at the fixture README as where ground truth lives, which
is the file §0 emptied.

`PLAN.md` has been updated alongside this document. Its milestone structure is left intact as
a historical record; only the claims that misdescribe the current system were corrected.
