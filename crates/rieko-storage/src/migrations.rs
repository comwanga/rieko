use rusqlite::Connection;

use crate::storage::StorageError;

/// Schema version the current binary understands and writes.
///
/// Bump this and add an entry to [`MIGRATIONS`] when the schema changes. A
/// database already at this version is opened as-is (idempotent); one *newer*
/// than this is rejected as unsupported so an old binary refuses to touch a
/// database it can no longer interpret.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

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
pub const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: V1_SCHEMA,
}];

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
    let current = schema_version(conn)?;
    if current > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::Unsupported(format!(
            "database schema version {current} is newer than the supported \
             version {CURRENT_SCHEMA_VERSION}; upgrade rieo before opening it"
        )));
    }

    for step in MIGRATIONS.iter().filter(|s| s.version > current) {
        apply(conn, step)?;
    }
    Ok(())
}

fn apply(conn: &mut Connection, step: &Migration) -> Result<(), StorageError> {
    let tx = conn
        .transaction()
        .map_err(|e| StorageError::Backend(format!("starting migration: {e}")))?;
    tx.execute_batch(step.sql).map_err(|e| {
        StorageError::Backend(format!("migration to v{} failed: {e}", step.version))
    })?;
    tx.pragma_update(None, "user_version", step.version)
        .map_err(|e| StorageError::Backend(format!("recording schema version: {e}")))?;
    tx.commit()
        .map_err(|e| StorageError::Backend(format!("committing migration: {e}")))
        .map(|_| ())
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
            "alert_state",
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
        // One valid statement followed by a deliberate syntax error.
        let step = Migration {
            version: 99,
            sql: "CREATE TABLE ok (id INT); CREATE TABLE broken (",
        };
        let err = apply(&mut conn, &step).unwrap_err();
        assert!(matches!(err, StorageError::Backend(_)));
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
