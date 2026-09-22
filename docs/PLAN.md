# vulness - Build Plan

**An autonomous vulnerability-discovery harness.**
Modeled on Cloudflare's VDH/VVS architecture ([blog](https://blog.cloudflare.com/build-your-own-vulnerability-harness/)), adapted to this machine and to the `security-audit-skill` prompt corpus already cloned next door.

Status: all ten stages in this plan are implemented. Built is not the same as demonstrated.
`EVALUATION.md` records what has actually run, which of the milestone exit criteria below are
still unmet, and the verified defect list. `RESEARCH.md` holds the outside comparison.
`README.md` covers usage.

---

## 1. The thesis

An LLM is a stateless compute engine that is good at attacking ~200 lines of code and bad at remembering anything. Every architectural decision below follows from that one sentence:

| Failure mode | Structural answer |
|---|---|
| Context fills → model cannibalizes its own memory | Externalize **all** state to SQLite. Each agent task stays under ~25% of its window. |
| Agent grades its own homework → validates everything | A **Validator that cannot file findings**. Its only job is disproof. |
| One model's blind spots | **Two different models.** Discovery on `claude`, triage on `glm-5.3`. Different vendors, so no shared weights. |
| "It reviewed the code" ≠ "it found a bug" | **PoC as a test that runs against untouched source**, in a sandbox. |
| 5-hour run dies at hour 4 | Persistence *before* parallelism. Crash costs the in-flight task only. |

Cloudflare's own minimal-harness advice, which this plan takes literally:

> A real but minimal harness consists of just Recon, Hunt, and Validate stages kept in a database, alongside a separate Validator that can't file its own findings. You should skip cross-repo tracing entirely until you have more than one repository that matters. Skip a dedicated Deduplication agent until you are actively drowning in noise.

So M1 is Recon + Hunt + Validate + DB + Report. Everything else is earned.

---

## 2. What I verified on this box

Measured, not assumed - these numbers drive the design.

| Capability | Result | Consequence for vulness |
|---|---|---|
| `claude` CLI | 2.1.258, `-p --output-format stream-json`, `--allowedTools`, `--permission-mode`, `--append-system-prompt`, `--add-dir`, `--mcp-config`, `--agents` | **Model A** - discovery backend |
| `codex` CLI | 0.154.0, `exec --json --output-schema <FILE>` | Evaluated as Model B, never adopted. Superseded by GLM below. |
| GLM-5.3 | Z.AI Coding Plan, OpenAI-compatible, `api/coding/paas/v4` | **Model B** - triage backend. Reasoning model, so `max_tokens` must be generous |
| `bwrap` / `unshare` | ❌ **BLOCKED** - `kernel.apparmor_restrict_unprivileged_userns = 1` (Ubuntu default). `bwrap: setting up uid map: Permission denied` | Cannot be the default sandbox |
| `docker` | ✅ 29.8.1 / overlayfs. Verified `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit --memory --cpus --tmpfs` → confirmed **NO_NET** | **Default sandbox** |
| `semgrep` | installed | Use as a *cell seeder*, never as an agent tool (see §7) |
| Python | 3.12.3, `anthropic` 0.122, `pydantic` 2.12, `mcp` 1.23, `fastmcp` 3.2 | stdlib `sqlite3`; pydantic for the findings contract |
| Hardware | 22 cores / 62 GB | ~10 concurrent agents, ~4 concurrent sandbox containers |
| `sqlite3` CLI | missing | Python `sqlite3` only; ship `vulness db` for inspection |

**This is exactly the gotcha Cloudflare warned about**, in a different costume - they hit `seccomp=unconfined`/`apparmor=unconfined` for nested Docker; here AppArmor kills unprivileged user namespaces outright. Docker-first is not a preference, it's the only thing that works today.

Optional later speedup (one-time, needs root, ~100× faster startup than a container for cheap checks):

```bash
# /etc/apparmor.d/bwrap
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
# sudo apparmor_parser -r /etc/apparmor.d/bwrap
```

Treat `bwrap` as an opt-in fast path behind the same `SandboxPolicy` interface. Never make it required.

---

## 3. Architecture

Two engines, two models, one database.

```
                    ┌──────────────── DISCOVERY (Model A: claude) ─────────────────┐
                    │                                                              │
   repo ──▶ RECON ──▶ HUNT ──▶ VALIDATE ──▶ [confirmed candidates]                 │
            (×3 ∥)    │  ▲         │                                               │
                      │  │         ▼                                               │
                      │  │     (reject)                                            │
                      │  │         │                                               │
                      │  └─── FEEDBACK ◀─┘   rewrites queued prompts                │
                      │  ▲                                                          │
                      │  └─── GAPFILL ◀──── thin (area × attack-class) cells        │
                      │  ▲                                                          │
                      │  └─── TRACE   ◀──── cross-repo dependency graph  [M5]       │
                    └──────────────────────────┬───────────────────────────────────┘
                                               │  SQLite (run_id, repo, stage)
                    ┌──────────────────────────▼───────── TRIAGE (Model B: glm) ────┐
                    │   DEDUP ──▶ JUDGE (reachable in prod?) ──▶ FIX (fail→pass)    │
                    └──────────────────────────┬───────────────────────────────────┘
                                               ▼
                                     REPORT (no model) ──▶ human review gate ──▶ PR
```

**Stages 4-8 are not sequential.** Gapfill, Feedback and Trace run as a continuous producer-consumer loop *while* Hunt is still draining - they enqueue new hunt tasks against the same worker pool.

### Stage contracts

| Stage | Model | Input | Output | Can file findings? |
|---|---|---|---|---|
| **Recon** | A ×3 ∥ | repo tree | `architecture.md`, trust boundaries, **repo-specific attack classes**, seeded coverage cells | no |
| **Hunt** | A | one cell + recon context | candidate findings + PoC | **yes** |
| **Validate** | **B** | one candidate + quoted source | verdict + reason | **no - disproof only** |
| **Gapfill** | A | cell coverage stats | new hunt tasks | no |
| **Feedback** | A | validation rejections | rewritten queued prompts | no |
| **Trace** [M5] | A | dep graph | hunt tasks in consumer repos | no |
| **Dedup** | B | finding clusters | merge decisions | no |
| **Judge** | B | confirmed finding | exploitable-now vs latent | no |
| **Fix** | B | confirmed finding | patch + regression test | no |
| **Report** | - | DB | Markdown/JSON | no |

The Validator's write-isolation is the single most important rule in the system.

As built, it is enforced by an AST test (`tests/test_write_isolation.py`) rather than by the
task router: `validator.py` receives the same `Database` handle the hunter holds. That test
fails CI if a `file_finding` call ever appears, which is a real control, but it is a lint and
not a capability boundary. Binding the tool policy at dispatch remains the stronger design.

---

## 4. State model

One SQLite DB, WAL mode, keyed `(run_id, repo_id, stage)`. Findings stream in as they happen.

```sql
CREATE TABLE runs (
  run_id TEXT PRIMARY KEY, started_at TEXT, ended_at TEXT,
  status TEXT,                       -- planned|running|complete|incomplete|failed
  profile TEXT,                      -- quick|standard|deep
  budget_tasks INTEGER, config_json TEXT,
  model_discovery TEXT, model_triage TEXT
);

CREATE TABLE repos (
  repo_id TEXT PRIMARY KEY, name TEXT, path TEXT, git_remote TEXT,
  head_sha TEXT, dirty INTEGER, lang_mix_json TEXT, enabled INTEGER,
  budget_tasks INTEGER              -- per-repo cap, NOT per-run
);

CREATE TABLE stages (
  run_id TEXT, repo_id TEXT, stage TEXT, status TEXT,
  attempt INTEGER, started_at TEXT, ended_at TEXT, error TEXT,
  PRIMARY KEY (run_id, repo_id, stage)
);

CREATE TABLE tasks (
  task_id TEXT PRIMARY KEY, run_id TEXT, repo_id TEXT, stage TEXT,
  kind TEXT,                         -- recon|hunt|validate|gapfill|feedback|trace|dedup|judge|fix
  cell_id TEXT, parent_task_id TEXT,
  origin TEXT,                       -- seed|gapfill|sibling_fork|feedback|trace|requeue_shallow
  prompt TEXT, seed_json TEXT,
  status TEXT,                       -- queued|leased|running|done|failed|shallow|abandoned
  attempt INTEGER, lease_until TEXT, worker TEXT,
  started_at TEXT, ended_at TEXT,
  tokens_in INTEGER, tokens_out INTEGER, cost_usd REAL,
  exit_reason TEXT                   -- ok|api_error_text|timeout|schema_invalid|budget|crash
);

CREATE TABLE cells (                 -- the (area × attack-class) coverage grid
  run_id TEXT, repo_id TEXT, cell_id TEXT,
  area TEXT, attack_class TEXT, priority INTEGER,
  status TEXT,                       -- planned|assigned|covered|thin|deferred|out_of_scope
  hunter_tasks INTEGER, findings_count INTEGER, last_touched TEXT,
  PRIMARY KEY (run_id, repo_id, cell_id)
);

CREATE TABLE findings (
  finding_id TEXT PRIMARY KEY, run_id TEXT, repo_id TEXT, task_id TEXT,
  fingerprint TEXT,                  -- stable across runs → reopens prior records
  title TEXT, area TEXT, attack_class TEXT,
  threat_model_json TEXT,            -- attacker, boundary, broken assumption  (REQUIRED)
  trace_json TEXT, evidence_json TEXT, poc_json TEXT,
  severity_json TEXT, remediation_json TEXT,
  verdict TEXT,                      -- candidate|confirmed|rejected|needs_validation|duplicate
  duplicate_of TEXT, created_at TEXT
);
CREATE INDEX idx_findings_fp ON findings(fingerprint);

CREATE TABLE validations (
  validation_id TEXT PRIMARY KEY, finding_id TEXT, validator TEXT,
  model TEXT, verdict TEXT, reason TEXT, mechanical_json TEXT, created_at TEXT
);

CREATE TABLE wishlist (
  wish_id TEXT PRIMARY KEY, run_id TEXT, repo_id TEXT, task_id TEXT,
  kind TEXT,                         -- build_env|poc_validator|vm|prod_config|credential|tool
  resource TEXT, context_json TEXT,
  status TEXT,                       -- open|provided|wontfix
  resolved_at TEXT, requeued_task_id TEXT
);

CREATE TABLE events (                -- append-only audit trail
  event_id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
  run_id TEXT, repo_id TEXT, task_id TEXT, level TEXT, kind TEXT, payload_json TEXT
);
```

Two properties this buys:
- **Resume.** Any stage can retry or be pulled into a later run without redoing work. Kill the process at hour 4, restart, lose one task.
- **Countable spend.** One cell ≈ one hunter assignment; one candidate ≈ 1-2 validator assignments. Budget is enforceable *before* dispatch.

---

## 5. Repository layout

```
vulness/
├── pyproject.toml                   # setuptools, py>=3.12, console_script: vulness
├── README.md
├── fleet.yaml                       # repos, budgets, profiles
├── docs/
│   ├── PLAN.md                      # this file
│   ├── ARCHITECTURE.md
│   └── SANDBOX.md                   # the AppArmor story, container profile
├── vulness/
│   ├── cli.py                       # vulness run|resume|status|findings|wishlist|report|db
│   ├── config.py                    # pydantic-settings
│   ├── state/
│   │   ├── schema.sql
│   │   ├── db.py                    # WAL, migrations, lease/heartbeat
│   │   └── models.py                # pydantic mirrors of every table
│   ├── orchestrator/
│   │   ├── scheduler.py             # producer-consumer, priority queue, requeue
│   │   ├── worker.py                # asyncio pool, lease renewal, crash recovery
│   │   └── budget.py                # per-repo cap + reserve-before-hunt
│   ├── agents/
│   │   ├── base.py                  # Agent protocol -> AgentResult
│   │   ├── claude_cli.py            # claude -p --output-format stream-json
│   │   ├── glm.py                   # GLM over an OpenAI-compatible endpoint
│   │   ├── classify.py              # ★ response classifier - see §7
│   │   └── roles/                   # recon, hunter, validator, gapfill, feedback,
│   │                                #   trace, dedup, judge, fixer, chain
│   ├── prompts/                     # seeded from security-audit-skill
│   ├── sandbox/
│   │   ├── policy.py                # limits, env allowlist, artifact promotion
│   │   ├── docker.py                # default backend  (verified)
│   │   └── bwrap.py                 # opt-in fast path (needs AppArmor profile)
│   ├── coverage/cells.py            # grid build, thinness scoring
│   ├── findings/
│   │   ├── schema.py                # pydantic ← report-schema.json
│   │   ├── fingerprint.py           # stable cross-run key
│   │   └── dedup.py                 # deterministic inverted index (pre-agent)
│   ├── wishlist.py
│   └── report/render.py
└── tests/
```

---

## 6. Prompt layer - do not write these from scratch

`~/Github/Research/security-audit-skill` is Cloudflare's released seed skill, and the blog is explicit that the prompts *are* the product:

> The real value lives in the prompts themselves, and our prompts continue to carry the initial skill's attacker scenarios, bug classes, and anti-pattern detections nearly unchanged.

What to lift, verbatim where possible:

| Source file | Becomes |
|---|---|
| `SKILL.md` - candidate gate, severity anchors, anti-patterns, execution safety | The shared system preamble for every role |
| `HUNTING.md` - required hunter prompt, structured hunter result, coverage-critic waves | `roles/hunter.py` prompt + result contract |
| `RECONNAISSANCE.md` - coverage units, architecture summary | `roles/recon.py` + initial cell seeding |
| `ATTACK-CLASSES.md` + 10 domain companions (web/auth, memory-safety, resource-exhaustion, client-side, desktop/IPC, supply-chain, data-isolation, protocols/RPC, AI/LLM, cloud/deploy) | The attack-class axis of the coverage grid; loaded **selectively** per cell to protect context |
| `report-schema.json` | `findings/schema.py` (pydantic); GLM is held to the same contract by prompt plus a parse-or-retry classification |
| `validate-findings.cjs`, `validate-coverage-ledger.cjs` | The mechanical (non-model) validation pass - shell out to `node`, don't reimplement |

Selective companion loading is what keeps each agent under 25% context. A hunter working a `memory-safety × parser` cell must never see the cloud-deployment companion.

**Recon must be allowed to invent repo-specific attack classes** beyond the built-in list. That dynamic threat model is what dropped Cloudflare's validation rejection rate from 40% → 11% and raised high-integrity findings from 35% → 58%.

---

## 7. The five things that will actually bite

Baked into the design, each traceable to a specific failure.

**1. API errors that look like success.**
> Sometimes a transient API error comes back as text in the (200 OK) response stream instead of throwing a code exception. To the orchestrator, this looks exactly like a task that finished cleanly.

`agents/classify.py` is mandatory, not a nicety. Every agent result is classified before it is trusted: exit code, stream-json terminal event, *and* a content-pattern check for apology/error prose. A task that produced no structured result is `exit_reason='api_error_text'` and requeues - it is never logged as a clean empty run.

**2. Shallow runs.**
> If a hunt finished suspiciously fast and fails to spawn sub-hunts or gap tasks, it usually indicates a crashed dependency rather than a clean codebase.

Any hunter finishing with zero findings **and** zero sibling forks **and** anomalously low duration/tokens → `status='shallow'` → immediate requeue. Cheap, and it catches broken toolchains that would otherwise read as "this repo is clean."

**3. The self-grading validator.**
> If a Hunter is allowed to grade its own homework, it will confidently validate everything it outputs.

Enforced by tool binding at dispatch, as above. Validator verdicts go to `validations`, never to `findings`.

**4. PoC theatre.**
> Every confirmed finding ships with a PoC written as a test that runs against the original, untouched codebase. This prevents the agent from editing the source files to force an exploit to land.

Mechanism: hash the target tree before the PoC runs, mount it **read-only** into the container, give the agent a writable `scratch/` only, re-hash after. Any source mutation invalidates the finding outright.

**5. Sandbox that silently fails to start.**
Already hit - see §2. `vulness doctor` runs the sandbox self-test (spawn container, assert no network, assert read-only target, assert rlimits) on every startup and refuses to dispatch execution tasks if it fails. A harness that silently stops executing code degrades into a very expensive grep.

---

## 8. Milestones

Each milestone ends with a working binary and a verification gate. No milestone is "done" until `pytest` and the type-check pass.

### M0 - Spine (no models)
`pyproject.toml`, SQLite schema + migrations, task queue with leases, asyncio worker pool, event log, `vulness db`/`status`. Agent backend is a **stub adapter** that replays canned JSON.
*Exit:* a 200-task fake run completes, is killed mid-flight, and resumes losing exactly one task.
*Status:* **partially met.** Resume re-derives work from the database rather than memory, but
leases are never reclaimed at startup, so a crash with tasks in flight stalls the resume until
they expire. `EVALUATION.md` §3.4.

### M1 - Minimal real harness ← *the Cloudflare minimum*
Recon (×3 ∥) → Hunt → Validate → Report, one repo, `claude` backend, prompts ported from the skill, findings validated against `report-schema.json` via `validate-findings.cjs`.
*Exit:* full run on a deliberately-vulnerable target produces ≥1 confirmed finding with a stated threat model, and the Validator demonstrably rejects a planted false positive.
*Status:* **unmet.** The first half holds. The Validator has never rejected anything.

### M2 - Sandbox + PoC contract
`sandbox/docker.py` with the verified profile, `vulness doctor`, read-only target + hash verification, artifact promotion into `artifacts/`.
*Exit:* a PoC executes in-container with no network, proves a boundary violation, and a source-mutating PoC is auto-rejected.
*Status:* **half met.** Isolation is verified by `doctor` on a live container. The auto-reject
clause has never fired and has no test. `EVALUATION.md` §3.9.

### M3 - Coverage loop
`(area × attack-class)` grid, Gapfill, Feedback (queued-prompt rewriting), shallow detection, sibling forking, per-repo budget gate.
*Exit:* Gapfill drives cell coverage to a clean pass; iteration 2 costs ≈ half of iteration 1 and still surfaces new findings.
*Status:* **unmet.** Gapfill has never run. It is bounded by a pass quota rather than by the
coverage signal it computes, so a clean pass is not something the loop pursues.

### M4 - Triage on the second model
GLM backend, deterministic inverted-index dedup, then agent dedup, Judge (exploitable-now vs latent), stable cross-run fingerprints.
*Exit:* two models disagree on ≥1 finding and the disagreement is surfaced, not silently resolved.
*Status:* **unmet.** 37 validations, zero `disproved`. See `EVALUATION.md` §4 for why this is
structural rather than a tuning problem.

### M5 - Fleet
Multi-repo `fleet.yaml`, cross-repo Trace, Wishlist review UI, Fixer with the **fail→pass gate** and a mandatory human PR review.
*Exit:* a patch is generated, its regression test flips fail→pass, and it lands as a PR that no automation can merge.
*Status:* **not exercised.** Trace needs more than one repo in a run, Fixer needs `--fix`.
Both are implemented and correctly gated; neither has run.

> Skip M4's dedup agent until you are actually drowning in noise, and skip M5's Trace until a second repo matters. Building them early is how this becomes a framework instead of a bug-finder.

---

## 9. Budget model on this box

Cloudflare runs 50-200 workers; 22 cores here means the binding constraint is **API spend and rate limits, not CPU** - agents are network-bound, containers are not.

- Agent concurrency: **8-12**. Sandbox container concurrency: **4** (1 CPU / 2 GB each).
- Per-repo cap in *tasks*, never per-run. A 30k-LOC repo: seed ~40-60 cells, ~1 hunter each, ~1.5 validators per surviving candidate.
- First run ≈ 60-100 agent tasks ≈ **1.5-3 h wall clock** at 10 concurrency. Gapfill iteration 2 ≈ half that.
- Almost all spend goes to Hunt. Gapfill is therefore the cost-to-coverage lever - the dial to turn when you want more coverage per dollar.
- Reserve validator budget *before* dispatching hunters. A run that hunts until broke and cannot validate produces nothing usable.

---

## 10. Scope and safety posture

vulness audits **source you own or are authorized to audit**. Inherited directly from the skill's `execution_policy: sandboxed-source-and-local-only`:

- Static analysis establishes the path; sandboxed local execution resolves behavior.
- **No live probing** - no deployed endpoints, shared infrastructure, production identities, or third-party services. Ever.
- Target code runs only with no network, read-only source, dropped capabilities, and explicit CPU/memory/PID/wall-clock limits.
- Stop at the minimum effect that proves the boundary violation. No persistence, no post-exploitation.
- If the decisive fact lives outside the repo (proxy config, identity policy, deployment topology), it is `needs_validation` with the exact missing fact - never a guess.
- Fixes are proposed, never auto-merged. The human review gate is the compliance trail.

---

## 11. Decisions, as resolved

These were open when the plan was written. Recording the answers so the plan reads as history
rather than as pending work.

1. **First target repo.** `tests/fixtures/vulnshop` and `chainshop`, both deliberately
   vulnerable and both shipped in-tree. This is enough to exercise the pipeline and not enough
   to measure precision or recall: see `RESEARCH.md` §4 for benchmarks that would.
2. **Model split.** `claude` hunts, `glm-5.3` triages. GLM rather than `codex`, because a
   different vendor shares no weights with the hunter. Validation moved to Model B as well,
   which is stricter than this plan originally specified.
3. **Fleet scope.** Multi-repo, via `fleet.yaml`. Trace is gated on a run holding more than
   one repository.
4. **Sandbox tier.** Docker only. `bwrap` is still blocked by the AppArmor default on this
   box and no `bwrap.py` was written, so the `"bwrap"` option in `SandboxConfig.backend` is a
   phantom that degrades silently when selected. `EVALUATION.md` §3.10.
