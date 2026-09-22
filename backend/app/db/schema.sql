PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    base_url TEXT NOT NULL,
    model_name TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT 'EXTERNAL_SUPPORT',
    target_mode TEXT NOT NULL DEFAULT 'INSTRUMENTED', -- 'INSTRUMENTED' | 'BLACK_BOX'
    capabilities_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS policies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    policy_json TEXT NOT NULL,
    taxonomy TEXT NOT NULL DEFAULT 'OWASP',
    taxonomy_version TEXT NOT NULL DEFAULT '2025',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id) ON DELETE CASCADE,
    status TEXT DEFAULT 'QUEUED',  -- QUEUED | RUNNING | COMPLETED | FAILED | CANCELLED
    scan_mode TEXT DEFAULT 'INSTRUMENTED',  -- INSTRUMENTED | BLACK_BOX
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    overall_score INTEGER,
    risk_grade TEXT,
    mitigation_enabled BOOLEAN DEFAULT FALSE,
    -- Canonical result summary (single source of truth)
    objectives_tested INTEGER DEFAULT 0,
    confirmed_count INTEGER DEFAULT 0,
    likely_count INTEGER DEFAULT 0,
    inconclusive_count INTEGER DEFAULT 0,
    pass_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    not_applicable_count INTEGER DEFAULT 0,
    policy_coverage REAL DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_objectives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
    family TEXT NOT NULL,                 -- 'injection' | 'leakage' | 'agency'
    policy_rule_id TEXT NOT NULL,         -- e.g. 'POL-BOLA-001'
    objective TEXT NOT NULL,
    status TEXT DEFAULT 'pending',        -- pending | RUNNING | COMPLETED | NOT_APPLICABLE | ERROR
    final_verdict TEXT,                   -- CONFIRMED | LIKELY | INCONCLUSIVE | PASS | ERROR | NOT_APPLICABLE
    attack_outcome TEXT,                  -- BLOCKED | COMPLIED | PARTIAL | INCONCLUSIVE | ERROR
    evidence_status TEXT,                 -- SUFFICIENT | PARTIAL | INSUFFICIENT | NOT_AVAILABLE
    severity TEXT NOT NULL,
    owasp_category TEXT NOT NULL,
    taxonomy_version TEXT DEFAULT '2025',
    application_security_class TEXT,      -- e.g. 'BOLA/IDOR'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS attack_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    objective_id INTEGER REFERENCES attack_objectives(id) ON DELETE CASCADE,
    -- Provenance chain
    scan_id INTEGER,
    target_id INTEGER,
    session_id TEXT,                      -- Unique per-objective session identifier
    turn_number INTEGER NOT NULL,
    strategy TEXT NOT NULL,
    prompt_text TEXT NOT NULL,
    response_text TEXT,
    stance_tag TEXT,
    stance_reason TEXT,
    stance_confidence REAL,
    next_strategy TEXT,
    -- Observation → decision log
    observation_json TEXT,               -- JSON: {previous_strategy, attack_outcome, decision, reason, ...}
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS execution_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attempt_id INTEGER REFERENCES attack_attempts(id) ON DELETE CASCADE,
    -- Provenance
    scan_id INTEGER,
    target_id INTEGER,
    session_id TEXT,
    event_type TEXT NOT NULL,            -- 'tool_call' | 'rag_retrieval' | 'memory_access' | 'output_filter_triggered' | 'authz_document_blocked'
    event_data TEXT NOT NULL,            -- JSON
    source TEXT NOT NULL DEFAULT 'target',  -- ALWAYS 'target' — scanner never produces events
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
    objective_id INTEGER REFERENCES attack_objectives(id) ON DELETE CASCADE,
    finding_id TEXT UNIQUE NOT NULL,
    owasp_category TEXT NOT NULL,
    taxonomy_version TEXT DEFAULT '2025',
    application_security_class TEXT,
    -- Three-dimensional result
    status TEXT NOT NULL,                -- Security verdict: CONFIRMED | LIKELY | INCONCLUSIVE | PASS
    attack_outcome TEXT,                 -- BLOCKED | COMPLIED | PARTIAL | INCONCLUSIVE | ERROR
    evidence_status TEXT,                -- SUFFICIENT | PARTIAL | INSUFFICIENT | NOT_AVAILABLE
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    remediation TEXT NOT NULL,
    -- Regression replay support
    exploit_sequence_json TEXT,          -- JSON: saved attack sequence for replay
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER NOT NULL UNIQUE REFERENCES targets(id) ON DELETE CASCADE,
    scan_id INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    baseline_json TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
