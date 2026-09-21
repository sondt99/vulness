-- vulness state. One DB per fleet. Keyed (run_id, repo_id, stage).
-- Persistence before parallelism: a crash costs the in-flight task and nothing else.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 10000;

CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY);

CREATE TABLE IF NOT EXISTS runs (
    run_id           TEXT PRIMARY KEY,
    started_at       TEXT NOT NULL,
    ended_at         TEXT,
    status           TEXT NOT NULL DEFAULT 'planned',   -- planned|running|complete|incomplete|failed
    incomplete_reason TEXT,
    profile          TEXT NOT NULL DEFAULT 'standard',  -- quick|standard|deep
    budget_tasks     INTEGER,
    model_hunt       TEXT NOT NULL,
    model_verify     TEXT NOT NULL,
    config_json      TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS repos (
    repo_id       TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    path          TEXT NOT NULL,
    git_remote    TEXT,
    head_sha      TEXT,
    dirty         INTEGER NOT NULL DEFAULT 0,
    lang_mix_json TEXT NOT NULL DEFAULT '{}',
    enabled       INTEGER NOT NULL DEFAULT 1,
    budget_tasks  INTEGER
);

CREATE TABLE IF NOT EXISTS stages (
    run_id     TEXT NOT NULL,
    repo_id    TEXT NOT NULL,
    stage      TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'planned',   -- planned|running|done|failed|skipped
    attempt    INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    ended_at   TEXT,
    error      TEXT,
    PRIMARY KEY (run_id, repo_id, stage)
);

-- The work queue. Every unit of model compute is a row here.
CREATE TABLE IF NOT EXISTS tasks (
    task_id        TEXT PRIMARY KEY,
    run_id         TEXT NOT NULL,
    repo_id        TEXT NOT NULL,
    stage          TEXT NOT NULL,
    kind           TEXT NOT NULL,      -- recon|hunt|validate|gapfill|feedback|judge|dedup
    cell_id        TEXT,
    parent_task_id TEXT,
    origin         TEXT NOT NULL DEFAULT 'seed',
                   -- seed|gapfill|sibling_fork|feedback|requeue_shallow|requeue_error
    finding_id     TEXT,               -- set for validate/judge tasks
    priority       INTEGER NOT NULL DEFAULT 100,
    prompt         TEXT NOT NULL,
    seed_json      TEXT NOT NULL DEFAULT '{}',
    status         TEXT NOT NULL DEFAULT 'queued',
                   -- queued|leased|done|failed|shallow|abandoned
    attempt        INTEGER NOT NULL DEFAULT 0,
    lease_until    TEXT,
    worker         TEXT,
    started_at     TEXT,
    ended_at       TEXT,
    duration_s     REAL,
    tokens_in      INTEGER NOT NULL DEFAULT 0,
    tokens_out     INTEGER NOT NULL DEFAULT 0,
    cost_usd       REAL NOT NULL DEFAULT 0.0,
    exit_reason    TEXT,               -- ok|api_error_text|timeout|empty|schema_invalid|crash|budget
    result_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_tasks_queue  ON tasks(run_id, status, priority, task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_repo   ON tasks(run_id, repo_id, kind);
CREATE INDEX IF NOT EXISTS idx_tasks_parent ON tasks(parent_task_id);

-- Coverage grid: one row per (area x attack-class) cell.
CREATE TABLE IF NOT EXISTS cells (
    run_id        TEXT NOT NULL,
    repo_id       TEXT NOT NULL,
    cell_id       TEXT NOT NULL,
    area          TEXT NOT NULL,
    attack_class  TEXT NOT NULL,
    paths_json    TEXT NOT NULL DEFAULT '[]',
    rationale     TEXT,
    priority      INTEGER NOT NULL DEFAULT 100,
    status        TEXT NOT NULL DEFAULT 'planned',
                  -- planned|assigned|covered|thin|deferred|out_of_scope
    hunter_tasks  INTEGER NOT NULL DEFAULT 0,
    findings_count INTEGER NOT NULL DEFAULT 0,
    last_touched  TEXT,
    PRIMARY KEY (run_id, repo_id, cell_id)
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id        TEXT PRIMARY KEY,
    run_id            TEXT NOT NULL,
    repo_id           TEXT NOT NULL,
    task_id           TEXT NOT NULL,
    fingerprint       TEXT NOT NULL,
    title             TEXT NOT NULL,
    area              TEXT,
    attack_class      TEXT,
    cell_id           TEXT,
    threat_model_json TEXT NOT NULL,   -- attacker/boundary/assumption -- REQUIRED, gate enforced
    trace_json        TEXT NOT NULL DEFAULT '[]',
    evidence_json     TEXT NOT NULL DEFAULT '{}',
    poc_json          TEXT NOT NULL DEFAULT '{}',
    severity_json     TEXT NOT NULL DEFAULT '{}',
    remediation_json  TEXT NOT NULL DEFAULT '{}',
    verdict           TEXT NOT NULL DEFAULT 'candidate',
                      -- candidate|confirmed|rejected|needs_validation|duplicate
    duplicate_of      TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_fp   ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_run  ON findings(run_id, verdict);

-- Validator output lands here and NEVER in findings. A validator cannot file.
CREATE TABLE IF NOT EXISTS validations (
    validation_id   TEXT PRIMARY KEY,
    finding_id      TEXT NOT NULL,
    task_id         TEXT,
    validator       TEXT NOT NULL,     -- mechanical|adversarial|judge
    model           TEXT NOT NULL,
    verdict         TEXT NOT NULL,     -- upheld|disproved|needs_validation|error
    reason          TEXT NOT NULL,
    detail_json     TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL,
    FOREIGN KEY (finding_id) REFERENCES findings(finding_id)
);
CREATE INDEX IF NOT EXISTS idx_validations_finding ON validations(finding_id);

-- How agents talk back to us when they need something they do not have.
CREATE TABLE IF NOT EXISTS wishlist (
    wish_id          TEXT PRIMARY KEY,
    run_id           TEXT NOT NULL,
    repo_id          TEXT NOT NULL,
    task_id          TEXT,
    kind             TEXT NOT NULL,    -- build_env|poc_validator|vm|prod_config|tool|credential
    resource         TEXT NOT NULL,
    context_json     TEXT NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'open',   -- open|provided|wontfix
    created_at       TEXT NOT NULL,
    resolved_at      TEXT,
    requeued_task_id TEXT
);

CREATE TABLE IF NOT EXISTS events (
    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    run_id       TEXT,
    repo_id      TEXT,
    task_id      TEXT,
    level        TEXT NOT NULL DEFAULT 'info',
    kind         TEXT NOT NULL,
    payload_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, event_id);

-- Cross-run memory. Everything above is keyed by run_id, which makes each run start blind:
-- recon re-derives a map that has not changed, the same bug is filed again under a new id,
-- and coverage restarts at zero. These two tables are what let run 20 be better than run 1
-- instead of merely being run 1 again.

CREATE TABLE IF NOT EXISTS repo_maps (
    repo_id      TEXT NOT NULL,
    head_sha     TEXT NOT NULL,
    run_id       TEXT NOT NULL,          -- the run that paid for it
    architecture TEXT NOT NULL,
    areas_json   TEXT NOT NULL DEFAULT '[]',
    classes_json TEXT NOT NULL DEFAULT '[]',
    created_at   TEXT NOT NULL,
    PRIMARY KEY (repo_id, head_sha)
);

-- Cell coverage accumulated over every run of a repo, so Gapfill can tell "never hunted by
-- anyone" from "hunted last week and clean". Keyed without run_id on purpose.
CREATE TABLE IF NOT EXISTS coverage_history (
    repo_id      TEXT NOT NULL,
    cell_id      TEXT NOT NULL,
    head_sha     TEXT,
    hunts        INTEGER NOT NULL DEFAULT 0,
    findings     INTEGER NOT NULL DEFAULT 0,
    last_run_id  TEXT,
    last_hunted  TEXT,
    PRIMARY KEY (repo_id, cell_id)
);
CREATE INDEX IF NOT EXISTS idx_cov_repo ON coverage_history(repo_id);
