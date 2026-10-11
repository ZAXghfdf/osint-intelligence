-- OSINT INTELLIGENCE — full relational schema (SQLite dialect; PostgreSQL-compatible names)
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS roles (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS permissions (
    id          INTEGER PRIMARY KEY,
    code        TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS role_permissions (
    role_id       INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT,
    full_name     TEXT,
    password_hash TEXT NOT NULL,
    role_id       INTEGER NOT NULL REFERENCES roles(id),
    is_active     INTEGER NOT NULL DEFAULT 1,
    must_change_pw INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    ip         TEXT,
    user_agent TEXT
);

CREATE TABLE IF NOT EXISTS sources (
    id             INTEGER PRIMARY KEY,
    key            TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL,
    category       TEXT NOT NULL,
    description    TEXT,
    official_url   TEXT,
    input_types    TEXT NOT NULL DEFAULT '[]',   -- JSON array of indicator types
    requires_key   INTEGER NOT NULL DEFAULT 0,
    env_key        TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1,
    status         TEXT NOT NULL DEFAULT 'unconfigured', -- ok|unconfigured|error|disabled
    rate_limit     TEXT,
    last_success_at TEXT,
    last_error     TEXT,
    request_count  INTEGER NOT NULL DEFAULT 0,
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS searches (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    title         TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'running', -- running|completed|failed|cancelled|partial
    scope         TEXT NOT NULL DEFAULT 'both',    -- external|internal|both
    input_summary TEXT,
    result_count  INTEGER NOT NULL DEFAULT 0,
    needs_review  INTEGER NOT NULL DEFAULT 0,
    notes         TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    completed_at  TEXT
);

CREATE TABLE IF NOT EXISTS search_queries (
    id               INTEGER PRIMARY KEY,
    search_id        INTEGER NOT NULL REFERENCES searches(id) ON DELETE CASCADE,
    indicator_type   TEXT NOT NULL,
    value            TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    valid            INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS source_runs (
    id           INTEGER PRIMARY KEY,
    search_id    INTEGER NOT NULL REFERENCES searches(id) ON DELETE CASCADE,
    source_id    INTEGER REFERENCES sources(id),
    source_key   TEXT NOT NULL,
    status       TEXT NOT NULL,   -- ok|error|skipped|unconfigured|timeout
    started_at   TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at  TEXT,
    result_count INTEGER NOT NULL DEFAULT 0,
    duration_ms  INTEGER,
    error        TEXT
);

CREATE TABLE IF NOT EXISTS entities (
    id               INTEGER PRIMARY KEY,
    entity_type      TEXT NOT NULL,   -- person|username|email|domain|ip|url|file|organization|service|indicator
    value            TEXT NOT NULL,
    normalized_value TEXT NOT NULL,
    display_name     TEXT,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (entity_type, normalized_value)
);

CREATE TABLE IF NOT EXISTS entity_identifiers (
    id                  INTEGER PRIMARY KEY,
    entity_id           INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    id_type             TEXT NOT NULL,
    value               TEXT NOT NULL,
    normalized_value    TEXT NOT NULL,
    source              TEXT,
    confidence          TEXT,
    verification_status TEXT,
    first_seen_at       TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY,
    search_id           INTEGER REFERENCES searches(id) ON DELETE CASCADE,
    source_id           INTEGER REFERENCES sources(id),
    source_run_id       INTEGER REFERENCES source_runs(id) ON DELETE SET NULL,
    dataset_id          INTEGER REFERENCES datasets(id) ON DELETE SET NULL,
    entity_id           INTEGER REFERENCES entities(id) ON DELETE SET NULL,
    entity_type         TEXT NOT NULL,
    title               TEXT,
    description         TEXT,
    value               TEXT NOT NULL,
    url                 TEXT,
    source_name         TEXT,
    confidence          TEXT NOT NULL DEFAULT 'unverified', -- direct|probable|weak|unverified
    verification_status TEXT NOT NULL DEFAULT 'unverified', -- verified|unverified|rejected
    collected_at        TEXT NOT NULL DEFAULT (datetime('now')),
    raw_json            TEXT,
    notes               TEXT,
    is_demo             INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_findings_search ON findings(search_id);
CREATE INDEX IF NOT EXISTS idx_findings_entity ON findings(entity_id);

CREATE TABLE IF NOT EXISTS entity_relationships (
    id                  INTEGER PRIMARY KEY,
    from_entity_id      INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    to_entity_id        INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    rel_type            TEXT NOT NULL,
    source              TEXT,
    evidence_url        TEXT,
    confidence          TEXT NOT NULL DEFAULT 'unverified',
    verification_status TEXT NOT NULL DEFAULT 'unverified',
    reason              TEXT,
    search_id           INTEGER REFERENCES searches(id) ON DELETE SET NULL,
    first_seen_at       TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at        TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (from_entity_id, to_entity_id, rel_type)
);
CREATE INDEX IF NOT EXISTS idx_rel_from ON entity_relationships(from_entity_id);
CREATE INDEX IF NOT EXISTS idx_rel_to ON entity_relationships(to_entity_id);

CREATE TABLE IF NOT EXISTS datasets (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    description  TEXT,
    source_name  TEXT,
    source_url   TEXT,
    purpose      TEXT,
    license      TEXT,
    acquired_at  TEXT,
    status       TEXT NOT NULL DEFAULT 'active', -- active|quarantined|archived
    record_count INTEGER NOT NULL DEFAULT 0,
    created_by   INTEGER REFERENCES users(id),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (name)
);

CREATE TABLE IF NOT EXISTS dataset_versions (
    id           INTEGER PRIMARY KEY,
    dataset_id   INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    version      INTEGER NOT NULL,
    note         TEXT,
    record_count INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (dataset_id, version)
);

CREATE TABLE IF NOT EXISTS dataset_import_jobs (
    id             INTEGER PRIMARY KEY,
    dataset_id     INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    version_id     INTEGER REFERENCES dataset_versions(id) ON DELETE SET NULL,
    filename       TEXT NOT NULL,
    file_type      TEXT,
    size_bytes     INTEGER,
    stored_path    TEXT,
    status         TEXT NOT NULL DEFAULT 'pending', -- pending|previewed|imported|failed|reverted
    mapping_json   TEXT,
    total_rows     INTEGER NOT NULL DEFAULT 0,
    imported_rows  INTEGER NOT NULL DEFAULT 0,
    duplicate_rows INTEGER NOT NULL DEFAULT 0,
    rejected_rows  INTEGER NOT NULL DEFAULT 0,
    error          TEXT,
    report_json    TEXT,
    created_by     INTEGER REFERENCES users(id),
    created_at     TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at    TEXT
);

CREATE TABLE IF NOT EXISTS dataset_fields (
    id          INTEGER PRIMARY KEY,
    dataset_id  INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    field_name  TEXT NOT NULL,
    mapped_type TEXT,
    sample_value TEXT
);

CREATE TABLE IF NOT EXISTS dataset_records (
    id               INTEGER PRIMARY KEY,
    dataset_id       INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    job_id           INTEGER REFERENCES dataset_import_jobs(id) ON DELETE SET NULL,
    version_id       INTEGER REFERENCES dataset_versions(id) ON DELETE SET NULL,
    record_json      TEXT NOT NULL,
    indicator_type   TEXT,
    indicator_value  TEXT,
    normalized_value TEXT,
    dedupe_hash      TEXT NOT NULL,
    created_at       TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (dataset_id, dedupe_hash)
);
CREATE INDEX IF NOT EXISTS idx_dsrec_indicator ON dataset_records(indicator_type, normalized_value);
CREATE INDEX IF NOT EXISTS idx_dsrec_dataset ON dataset_records(dataset_id);

CREATE TABLE IF NOT EXISTS dataset_sources (
    id          INTEGER PRIMARY KEY,
    dataset_id  INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    source_name TEXT,
    source_url  TEXT,
    license     TEXT,
    acquired_at TEXT
);

CREATE TABLE IF NOT EXISTS dataset_access_permissions (
    id         INTEGER PRIMARY KEY,
    dataset_id INTEGER NOT NULL REFERENCES datasets(id) ON DELETE CASCADE,
    role_id    INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    can_read   INTEGER NOT NULL DEFAULT 0,
    can_write  INTEGER NOT NULL DEFAULT 0,
    can_delete INTEGER NOT NULL DEFAULT 0,
    UNIQUE (dataset_id, role_id)
);

CREATE TABLE IF NOT EXISTS reports (
    id          INTEGER PRIMARY KEY,
    search_id   INTEGER REFERENCES searches(id) ON DELETE SET NULL,
    user_id     INTEGER REFERENCES users(id),
    title       TEXT NOT NULL,
    format      TEXT NOT NULL,
    file_path   TEXT,
    meta_json   TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER REFERENCES users(id),
    action      TEXT NOT NULL,
    entity_type TEXT,
    entity_id   TEXT,
    details_json TEXT,
    ip          TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

CREATE TABLE IF NOT EXISTS application_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ---------- Cybersecurity Tools Hub ----------
CREATE TABLE IF NOT EXISTS tools (
    id             INTEGER PRIMARY KEY,
    slug           TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL,
    category       TEXT NOT NULL,
    description    TEXT,
    repo_url       TEXT,
    docs_url       TEXT,
    license        TEXT,
    os_support     TEXT,
    requires       TEXT,
    installed      INTEGER NOT NULL DEFAULT 0,
    install_status TEXT NOT NULL DEFAULT 'not_installed', -- installed|not_installed|needs_setup|incompatible|failed
    version        TEXT,
    enabled        INTEGER NOT NULL DEFAULT 1,
    allowed_options TEXT DEFAULT '[]',
    last_checked_at TEXT,
    notes          TEXT,
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tool_tasks (
    id           INTEGER PRIMARY KEY,
    tool_id      INTEGER REFERENCES tools(id),
    user_id      INTEGER REFERENCES users(id),
    search_id    INTEGER REFERENCES searches(id) ON DELETE SET NULL,
    task_type    TEXT,
    target       TEXT,
    options_json TEXT,
    command      TEXT,
    status       TEXT NOT NULL DEFAULT 'queued', -- queued|running|success|failed|cancelled|rejected
    started_at   TEXT,
    finished_at  TEXT,
    exit_code    INTEGER,
    stdout       TEXT,
    stderr       TEXT,
    timeout_s    INTEGER,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tool_results (
    id                  INTEGER PRIMARY KEY,
    task_id             INTEGER REFERENCES tool_tasks(id) ON DELETE CASCADE,
    tool_id             INTEGER REFERENCES tools(id),
    result_type         TEXT,
    title               TEXT,
    description         TEXT,
    severity            TEXT,
    source_tool         TEXT,
    source_reference    TEXT,
    collected_at        TEXT NOT NULL DEFAULT (datetime('now')),
    raw_output_ref      TEXT,
    parsed_json         TEXT,
    verification_status TEXT NOT NULL DEFAULT 'unverified'
);

CREATE TABLE IF NOT EXISTS github_projects (
    id              INTEGER PRIMARY KEY,
    repo_full_name  TEXT NOT NULL UNIQUE,
    name            TEXT,
    description     TEXT,
    url             TEXT,
    language        TEXT,
    license         TEXT,
    stars           INTEGER DEFAULT 0,
    pushed_at       TEXT,
    category        TEXT,
    status          TEXT NOT NULL DEFAULT 'discovered', -- discovered|pending_review|accepted|ready|installed|rejected|incompatible
    review_decision TEXT,
    review_reason   TEXT,
    archived        INTEGER DEFAULT 0,
    added_by        INTEGER REFERENCES users(id),
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS knowledge_docs (
    id         INTEGER PRIMARY KEY,
    kind       TEXT,        -- tool|source|dataset|reference
    title      TEXT,
    url        TEXT,
    license    TEXT,
    meta_json  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
