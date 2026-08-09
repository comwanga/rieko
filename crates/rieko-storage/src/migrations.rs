use rusqlite::Connection;

use crate::storage::StorageError;

/// Schema version the current binary understands and writes.
///
/// Bump this and add an entry to [`MIGRATIONS`] when the schema changes. A
/// database already at this version is opened as-is (idempotent); one *newer*
/// than this is rejected as unsupported so an old binary refuses to touch a
/// database it can no longer interpret.
pub const CURRENT_SCHEMA_VERSION: i64 = 10;

/// One ordered, transactional upgrade step.
pub struct Migration {
    /// Schema version this step produces.
    pub version: i64,
    /// SQL applied inside a single transaction.
    pub sql: &'static str,
}

/// The ordered migration history. Steps must appear in ascending `version`
/// order. Do not edit or reorder past steps: a step only runs once and its
/// effect is sticky in upgraded databases.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: V1_SCHEMA,
    },
    Migration {
        version: 2,
        sql: V2_FINDING_METADATA,
    },
    Migration {
        version: 3,
        sql: V3_AUDIT_TRANSITIONS,
    },
    Migration {
        version: 4,
        sql: V4_OPERATIONAL_STATE,
    },
    Migration {
        version: 5,
        sql: V5_RECOMMENDATION_RATIONALE,
    },
    Migration {
        version: 6,
        sql: V6_CLEANUP_STATE,
    },
    Migration {
        version: 7,
        sql: V7_SNAPSHOT_SPENDABLE,
    },
    Migration {
        version: 8,
        sql: V8_SIMULATION_V2,
    },
    Migration {
        version: 9,
        sql: V9_FINDING_PROVENANCE,
    },
    Migration {
        version: 10,
        sql: V10_SIMULATION_INTEGRITY,
    },
];

const V1_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS findings (
    id          TEXT PRIMARY KEY,
    detector    TEXT NOT NULL,
    severity    INTEGER NOT NULL,
    node_id     TEXT,
    channel_id  TEXT,
    evidence    TEXT NOT NULL,
    explanation TEXT,
    ts          TEXT NOT NULL,
    last_seen   TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings (ts DESC);
CREATE INDEX IF NOT EXISTS idx_findings_channel ON findings (channel_id);

CREATE TABLE IF NOT EXISTS recommendations (
    finding_id   TEXT NOT NULL,
    action_id    TEXT PRIMARY KEY,
    action_type  TEXT NOT NULL,
    stage        TEXT NOT NULL,
    target       TEXT,
    params       TEXT NOT NULL,
    summary      TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit (
    id          TEXT PRIMARY KEY,
    action_id   TEXT NOT NULL,
    action_type TEXT NOT NULL,
    stage       TEXT NOT NULL,
    actor       TEXT NOT NULL,
    details     TEXT NOT NULL,
    ts          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit (ts DESC);

CREATE TABLE IF NOT EXISTS channel_snapshots (
    channel_id        TEXT NOT NULL,
    ts                TEXT NOT NULL,
    local_ratio       REAL NOT NULL,
    local_balance_msat INTEGER,
    remote_balance_msat INTEGER,
    capacity_msat     INTEGER,
    status_int        INTEGER NOT NULL,
    PRIMARY KEY (channel_id, ts)
);
CREATE INDEX IF NOT EXISTS idx_snapshots_channel_ts
    ON channel_snapshots (channel_id, ts DESC);

CREATE TABLE IF NOT EXISTS simulations (
    id          TEXT PRIMARY KEY,
    action_id   TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    action_type TEXT NOT NULL,
    projection  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_simulations_action
    ON simulations (action_id);
CREATE INDEX IF NOT EXISTS idx_simulations_ts
    ON simulations (created_at DESC);

CREATE TABLE IF NOT EXISTS alert_state (
    dedup_key      TEXT PRIMARY KEY,
    last_sent_at   TEXT,
    last_severity  INTEGER,
    last_status    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS operational_state (
    id                      TEXT PRIMARY KEY,
    source                  TEXT NOT NULL,
    source_connected        INTEGER,
    last_ingestion_attempt  TEXT,
    last_ingestion_success  TEXT,
    last_cycle_attempt      TEXT,
    last_cycle_success      TEXT,
    last_persist_success    TEXT,
    source_data_at          TEXT,
    llm                     TEXT NOT NULL,
    alert_sink              TEXT NOT NULL
);
"#;

/// v2: add traceability and lifecycle metadata to findings. Existed in v1 when
/// `first_seen`/`last_seen` were stored, and later replaced with the pair
/// `first_seen_at`/`last_seen_at` plus detector + schema versions. New
/// databases get the full columns via `V1_SCHEMA` above; this migration adds
/// them to databases created on the older schema.
const V2_FINDING_METADATA: &str = r#"
ALTER TABLE findings ADD COLUMN last_seen_at TEXT;
ALTER TABLE findings ADD COLUMN first_seen_at TEXT;
ALTER TABLE findings ADD COLUMN detector_version TEXT NOT NULL DEFAULT '1';
ALTER TABLE findings ADD COLUMN schema_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE findings ADD COLUMN lifecycle TEXT NOT NULL DEFAULT 'active';
UPDATE findings SET last_seen_at = COALESCE(last_seen_at, ts) WHERE last_seen_at IS NULL;
UPDATE findings SET first_seen_at = COALESCE(first_seen_at, ts) WHERE first_seen_at IS NULL;
"#;

/// v3: audit transitions (RIEKO-AUDIT-007). Add the `previous_stage` column so
/// every audit entry records the transition that actually occurred, and make
/// the audit table append-only: normal `UPDATE`/`DELETE` is denied by triggers
/// so the application API is the only way rows are written. This is a truthful
/// guarantee — a local administrator with raw filesystem access can still
/// modify the database; cryptographic tamper evidence is not implemented.
const V3_AUDIT_TRANSITIONS: &str = r#"
ALTER TABLE audit ADD COLUMN previous_stage TEXT;

CREATE TRIGGER IF NOT EXISTS audit_append_only_update
BEFORE UPDATE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit rows are append-only');
END;

CREATE TRIGGER IF NOT EXISTS audit_append_only_delete
BEFORE DELETE ON audit
BEGIN
    SELECT RAISE(ABORT, 'audit rows are append-only');
END;
"#;

/// v4: self-observability (RIEKO-AUDIT-008). A small, constant-size record of
/// operational state (ingestion/cycle attempts, source, LLM and alert-sink
/// capability) so `/status` reflects real operation without scanning data.
const V4_OPERATIONAL_STATE: &str = r#"
CREATE TABLE IF NOT EXISTS operational_state (
    id                      TEXT PRIMARY KEY,
    source                  TEXT NOT NULL,
    source_connected        INTEGER,
    last_ingestion_attempt  TEXT,
    last_ingestion_success  TEXT,
    last_cycle_attempt      TEXT,
    last_cycle_success      TEXT,
    last_persist_success    TEXT,
    source_data_at          TEXT,
    llm                     TEXT NOT NULL,
    alert_sink              TEXT NOT NULL
);
"#;

/// v5: conservative, evidence-backed recommendations (RIEKO-AUDIT-010). Add
/// the structured rationale (JSON), so the deterministic reasoning that
/// justifies each recommendation persists with it. Fresh and upgraded databases
/// both reach it via this step.
const V5_RECOMMENDATION_RATIONALE: &str = r#"
ALTER TABLE recommendations ADD COLUMN rationale TEXT NOT NULL DEFAULT '{}';
"#;

/// v6: retention cleanup observability (RIEKO-AUDIT-016). Record cleanup
/// component state and last attempt/success so `/status` and the `status`
/// command report whether the bounded-retention pass is healthy.
const V6_CLEANUP_STATE: &str = r#"
ALTER TABLE operational_state ADD COLUMN cleanup TEXT NOT NULL DEFAULT 'not_configured';
ALTER TABLE operational_state ADD COLUMN last_cleanup_attempt TEXT;
ALTER TABLE operational_state ADD COLUMN last_cleanup_success TEXT;
"#;

/// v7: spendable liquidity columns on channel_snapshots (RIEKO-AUDIT-011 /
/// Phase 7.1). Effective outbound/inbound capacity after subtracting channel
/// reserves, so the drift detector and simulation can reason about funds
/// actually available to move.
const V7_SNAPSHOT_SPENDABLE: &str = r#"
CREATE TABLE IF NOT EXISTS channel_snapshots (
    channel_id        TEXT NOT NULL,
    ts                TEXT NOT NULL,
    local_ratio       REAL NOT NULL,
    local_balance_msat INTEGER,
    remote_balance_msat INTEGER,
    capacity_msat     INTEGER,
    status_int        INTEGER NOT NULL,
    PRIMARY KEY (channel_id, ts)
);
ALTER TABLE channel_snapshots ADD COLUMN spendable_outbound_msat INTEGER NOT NULL DEFAULT 0;
ALTER TABLE channel_snapshots ADD COLUMN spendable_inbound_msat INTEGER NOT NULL DEFAULT 0;
"#;

/// v8: v2 simulation fields (ADR-0005). Adds lifecycle, provenance, and
/// deterministic-identity columns to the simulations table. Existing rows
/// get sensible defaults (status=completed, model_id='legacy').
const V8_SIMULATION_V2: &str = r#"
ALTER TABLE simulations ADD COLUMN status TEXT NOT NULL DEFAULT 'completed';
ALTER TABLE simulations ADD COLUMN model_id TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE simulations ADD COLUMN model_version TEXT NOT NULL DEFAULT '0';
ALTER TABLE simulations ADD COLUMN input_hash TEXT NOT NULL DEFAULT '';
ALTER TABLE simulations ADD COLUMN confidence TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE simulations ADD COLUMN assumptions TEXT NOT NULL DEFAULT '[]';
ALTER TABLE simulations ADD COLUMN warnings TEXT NOT NULL DEFAULT '[]';
ALTER TABLE simulations ADD COLUMN explanation TEXT NOT NULL DEFAULT '';
"#;

/// v9: optional evidence provenance and the reconciliation lookup path. Legacy
/// rows remain NULL because their origin cannot be reconstructed truthfully.
const V9_FINDING_PROVENANCE: &str = r#"
ALTER TABLE findings ADD COLUMN provenance TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_scope_lifecycle
    ON findings (detector, node_id, lifecycle);
"#;

/// v10: immutable, replayable v2 simulation inputs and a lifecycle event log.
/// Existing rows remain readable but carry NULL canonical input because source
/// state cannot be reconstructed after the fact.
const V10_SIMULATION_INTEGRITY: &str = r#"
CREATE TABLE IF NOT EXISTS channel_snapshots (
    channel_id TEXT NOT NULL, ts TEXT NOT NULL, local_ratio REAL NOT NULL,
    local_balance_msat INTEGER, remote_balance_msat INTEGER, capacity_msat INTEGER,
    status_int INTEGER NOT NULL, spendable_outbound_msat INTEGER NOT NULL DEFAULT 0,
    spendable_inbound_msat INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (channel_id, ts)
);
ALTER TABLE channel_snapshots RENAME TO channel_snapshots_v9;
CREATE TABLE channel_snapshots (
    node_id TEXT,
    channel_id TEXT NOT NULL,
    ts TEXT NOT NULL,
    local_ratio REAL NOT NULL,
    local_balance_msat INTEGER,
    remote_balance_msat INTEGER,
    capacity_msat INTEGER,
    status_int INTEGER NOT NULL,
    spendable_outbound_msat INTEGER NOT NULL DEFAULT 0,
    spendable_inbound_msat INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (node_id, channel_id, ts)
);
INSERT INTO channel_snapshots
    (node_id, channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat,
     capacity_msat, status_int, spendable_outbound_msat, spendable_inbound_msat)
SELECT NULL, channel_id, ts, local_ratio, local_balance_msat, remote_balance_msat,
       capacity_msat, status_int, spendable_outbound_msat, spendable_inbound_msat
FROM channel_snapshots_v9;
DROP TABLE channel_snapshots_v9;
CREATE INDEX idx_snapshots_channel_ts
    ON channel_snapshots (channel_id, ts DESC);
CREATE INDEX idx_snapshots_node_channel_ts
    ON channel_snapshots (node_id, channel_id, ts DESC);

ALTER TABLE simulations ADD COLUMN canonical_input TEXT;
ALTER TABLE simulations ADD COLUMN source_observed_at TEXT;
ALTER TABLE simulations ADD COLUMN requested_at TEXT;
ALTER TABLE simulations ADD COLUMN completed_at TEXT;
ALTER TABLE simulations ADD COLUMN error_code TEXT;
UPDATE simulations SET requested_at = created_at WHERE requested_at IS NULL;
UPDATE simulations SET completed_at = created_at
    WHERE completed_at IS NULL AND status IN ('completed', 'stale');

CREATE UNIQUE INDEX IF NOT EXISTS idx_simulations_input_hash_unique
    ON simulations (input_hash)
    WHERE input_hash <> '' AND canonical_input IS NOT NULL AND projection <> 'null';

CREATE TABLE simulation_events (
    id              TEXT PRIMARY KEY,
    simulation_id   TEXT NOT NULL,
    status          TEXT NOT NULL,
    error_code      TEXT,
    ts              TEXT NOT NULL,
    FOREIGN KEY (simulation_id) REFERENCES simulations(id)
);
CREATE INDEX idx_simulation_events_simulation_ts
    ON simulation_events (simulation_id, ts);
CREATE TRIGGER simulation_events_append_only_update
BEFORE UPDATE ON simulation_events
BEGIN
    SELECT RAISE(ABORT, 'simulation events are append-only');
END;
CREATE TRIGGER simulation_events_append_only_delete
BEFORE DELETE ON simulation_events
BEGIN
    SELECT RAISE(ABORT, 'simulation events are append-only');
END;
"#;

/// Read the persisted schema version (`PRAGMA user_version`).
pub fn schema_version(conn: &Connection) -> Result<i64, StorageError> {
    let v: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(|e| StorageError::Backend(format!("reading schema version: {e}")))?;
    Ok(v)
}

/// Bring `conn` to the current schema. Idempotent once at the latest version.
///
/// * fresh database: `user_version` is 0, so every step runs.
/// * an older database: only the steps newer than its version run.
/// * a database already at [`CURRENT_SCHEMA_VERSION`]: no-op.
/// * a database newer than [`CURRENT_SCHEMA_VERSION`]: rejected, because an
///   older binary must not read (and risk writing to) a schema it doesn't
///   understand.
///
/// Each step runs in its own transaction, so a failing step rolls back fully
/// and `user_version` cannot advance past it.
pub fn migrate(conn: &mut Connection) -> Result<(), StorageError> {
    // Fast path: an already current database needs no migration, so a reader
    // opg a database concurrent with a live writer must not take a write lock.
    let current = schema_version(conn)?;
    if current == CURRENT_SCHEMA_VERSION {
        return Ok(());
    }
    // A database newer than this binary is always rejected, without needing a
    // lock: an older binary must not write to a schema it doesn't understand.
    if current > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::Unsupported(format!(
            "database schema version {current} is newer than the supported \
             version {CURRENT_SCHEMA_VERSION}; upgrade rieo before opening it"
        )));
    }
    // Migrations pending. Take an immediate write lock and re-read the version
    // inside the transaction: two connections racing to open a fresh database
    // would otherwise both run the same non-idempotent steps.
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| StorageError::Backend(format!("starting migration: {e}")))?;
    let current = schema_version(&tx)?;
    for step in MIGRATIONS.iter().filter(|s| s.version > current) {
        apply(&tx, step)?;
    }
    tx.commit()
        .map_err(|e| StorageError::Backend(format!("committing migration: {e}")))
        .map(|_| ())
}

fn apply(tx: &rusqlite::Transaction, step: &Migration) -> Result<(), StorageError> {
    tx.execute_batch(step.sql).map_err(|e| {
        StorageError::Backend(format!("migration to v{} failed: {e}", step.version))
    })?;
    tx.pragma_update(None, "user_version", step.version)
        .map_err(|e| StorageError::Backend(format!("recording schema version: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn bare_conn() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    fn has_table(conn: &Connection, name: &str) -> bool {
        let mut stmt = conn
            .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1")
            .unwrap();
        stmt.exists([name]).unwrap()
    }

    #[test]
    fn empty_db_reaches_current_schema() {
        let mut conn = bare_conn();
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        for table in [
            "findings",
            "recommendations",
            "audit",
            "channel_snapshots",
            "simulations",
            "simulation_events",
            "alert_state",
            "operational_state",
        ] {
            assert!(has_table(&conn, table), "missing table {table}");
        }
    }

    #[test]
    fn current_schema_reopened_is_idempotent() {
        let mut conn = bare_conn();
        migrate(&mut conn).unwrap();
        // Applying migrations again is a no-op that must not error or bump higher.
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn previous_schema_migrates_with_data_preserved() {
        // An "older" supported schema: all tables except `alert_state`, version 0.
        let mut conn = bare_conn();
        conn.execute_batch(
            "CREATE TABLE findings (
                id TEXT PRIMARY KEY, detector TEXT NOT NULL, severity INTEGER NOT NULL,
                node_id TEXT, channel_id TEXT, evidence TEXT NOT NULL,
                explanation TEXT, ts TEXT NOT NULL, last_seen TEXT
            );",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO findings (id, detector, severity, evidence, ts)
             VALUES ('f1', 'channel_liquidity', 1, '[]', '2020-01-01')",
            [],
        )
        .unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 0);

        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        // The newest table is created…
        assert!(has_table(&conn, "alert_state"));
        // …and the existing data is preserved.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM findings", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn v9_adds_nullable_provenance_and_scope_lifecycle_index() {
        let mut conn = bare_conn();
        conn.execute_batch(
            "CREATE TABLE findings (
                id TEXT PRIMARY KEY, detector TEXT NOT NULL, detector_version TEXT NOT NULL,
                schema_version INTEGER NOT NULL, severity INTEGER NOT NULL, node_id TEXT,
                channel_id TEXT, evidence TEXT NOT NULL, explanation TEXT, ts TEXT NOT NULL,
                first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, lifecycle TEXT NOT NULL
             );
             INSERT INTO findings VALUES
                ('legacy', 'detector', '1', 1, 0, NULL, NULL, '[]', NULL,
                 '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z',
                 '2020-01-01T00:00:00Z', 'active');
             CREATE TABLE simulations (
                id TEXT PRIMARY KEY, action_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                action_type TEXT NOT NULL, projection TEXT NOT NULL, created_at TEXT NOT NULL,
                status TEXT NOT NULL, model_id TEXT NOT NULL, model_version TEXT NOT NULL,
                input_hash TEXT NOT NULL, confidence TEXT NOT NULL, assumptions TEXT NOT NULL,
                warnings TEXT NOT NULL, explanation TEXT NOT NULL
             );
             PRAGMA user_version = 8;",
        )
        .unwrap();

        migrate(&mut conn).unwrap();
        let provenance: Option<String> = conn
            .query_row(
                "SELECT provenance FROM findings WHERE id = 'legacy'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(provenance, None, "legacy provenance must remain unknown");
        let index_exists: bool = conn
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'index' AND name = 'idx_findings_scope_lifecycle'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(index_exists);
    }

    #[test]
    fn v10_preserves_legacy_simulation_and_adds_integrity_metadata() {
        let mut conn = bare_conn();
        conn.execute_batch(
            "CREATE TABLE simulations (
                id TEXT PRIMARY KEY, action_id TEXT NOT NULL, finding_id TEXT NOT NULL,
                action_type TEXT NOT NULL, projection TEXT NOT NULL, created_at TEXT NOT NULL,
                status TEXT NOT NULL, model_id TEXT NOT NULL, model_version TEXT NOT NULL,
                input_hash TEXT NOT NULL, confidence TEXT NOT NULL, assumptions TEXT NOT NULL,
                warnings TEXT NOT NULL, explanation TEXT NOT NULL
             );
             INSERT INTO simulations VALUES
                ('legacy', 'a1', 'f1', 'rebalance_channel', '{}',
                 '2020-01-01T00:00:00Z', 'completed', 'legacy', '0', 'old-hash',
                 'unknown', '[]', '[]', ''),
                ('legacy-duplicate', 'a1', 'f1', 'rebalance_channel', '{}',
                 '2020-01-01T00:01:00Z', 'completed', 'legacy', '0', 'old-hash',
                 'unknown', '[]', '[]', '');
             PRAGMA user_version = 9;",
        )
        .unwrap();

        migrate(&mut conn).unwrap();

        let (canonical_input, requested_at, completed_at): (
            Option<String>,
            String,
            Option<String>,
        ) = conn
            .query_row(
                "SELECT canonical_input, requested_at, completed_at
                 FROM simulations WHERE id = 'legacy'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(canonical_input, None);
        assert_eq!(requested_at, "2020-01-01T00:00:00Z");
        assert_eq!(completed_at.as_deref(), Some("2020-01-01T00:00:00Z"));
        assert!(has_table(&conn, "simulation_events"));
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM simulations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 2, "historical duplicate hashes must be preserved");
        assert_eq!(schema_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn newer_unsupported_schema_is_rejected() {
        let mut conn = bare_conn();
        conn.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION + 1)
            .unwrap();
        let err = migrate(&mut conn).unwrap_err();
        assert!(
            matches!(err, StorageError::Unsupported(_)),
            "expected Unsupported, got {err:?}"
        );
    }

    #[test]
    fn failing_migration_rolls_back_and_does_not_advance_version() {
        let mut conn = bare_conn();
        assert_eq!(schema_version(&conn).unwrap(), 0);
        // A syntax error inside one step must roll back the whole transaction
        // and leave the schema version untouched.
        use rusqlite::TransactionBehavior;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let step = Migration {
            version: 99,
            sql: "CREATE TABLE ok (id INT); CREATE TABLE broken (",
        };
        let err = apply(&tx, &step).unwrap_err();
        assert!(matches!(err, StorageError::Backend(_)));
        drop(tx);
        // The valid statement was rolled back with the failed transaction.
        assert!(!has_table(&conn, "ok"));
        assert_eq!(schema_version(&conn).unwrap(), 0);
    }

    #[test]
    fn partially_initialized_db_is_handled() {
        // A database where a migration began but crashed partway: the version
        // was never recorded (SQLite is atomic) and some tables exist. Opening
        // it again must re-run the pending step and finish cleanly.
        let mut conn = bare_conn();
        conn.execute_batch(
            "CREATE TABLE findings (
                id TEXT PRIMARY KEY, detector TEXT NOT NULL, severity INTEGER NOT NULL,
                node_id TEXT, channel_id TEXT, evidence TEXT NOT NULL,
                explanation TEXT, ts TEXT NOT NULL, last_seen TEXT
            );",
        )
        .unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 0);

        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), CURRENT_SCHEMA_VERSION);
        assert!(has_table(&conn, "alert_state"));
    }
}
