//! Gap 10: versioned, checksummed, transactional schema migrations.
//!
//! Replaces "re-run one idempotent SCHEMA_SQL blob at every start" (which cannot
//! detect an edited schema, a downgrade, or a half-applied change) with an
//! ordered migration list recorded in `schema_migrations`.
//!
//! Requires Postgres (same conventions as `db_pool_concurrency.rs`):
//! `CIPHERSETTLE_TEST_DB_URL`, `CIPHERSETTLE_TEST_DB_REQUIRED=1` makes an
//! unreachable DB a failure, and each test leaves
//! `<CARGO_TARGET_TMPDIR>/migrations.<test>.outcome` = `started` | `skipped: ..` | `ran`.
//! Each test works in its OWN Postgres schema so tests never see each other's tables.

#[path = "../src/migrations.rs"]
#[allow(dead_code)]
mod migrations;

use migrations::{migrate_with, MigrateError, Migration, MIGRATIONS};
use std::time::Duration;

fn record_outcome(test: &str, outcome: &str) {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(dir.join(format!("migrations.{test}.outcome")), outcome);
}

fn db_required() -> bool {
    matches!(std::env::var("CIPHERSETTLE_TEST_DB_REQUIRED"), Ok(v) if !v.is_empty() && v != "0")
}

fn test_db_url() -> String {
    std::env::var("CIPHERSETTLE_TEST_DB_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/ciphersettle_test".to_string())
}

/// One isolated schema per test; every connection it hands out has that
/// schema as its search_path. Dropped (CASCADE) at the end.
struct Sandbox {
    url: String,
    schema: String,
}

impl Sandbox {
    async fn connect(&self) -> tokio_postgres::Client {
        let mut cfg: tokio_postgres::Config = self.url.parse().expect("url");
        cfg.options(format!("-c search_path={}", self.schema));
        let (client, conn) = cfg.connect(tokio_postgres::NoTls).await.expect("connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        client
    }
    async fn drop_schema(&self) {
        let (c, conn) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .expect("connect");
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let _ = c
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {} CASCADE", self.schema))
            .await;
    }
}

async fn sandbox(test: &str) -> Option<Sandbox> {
    record_outcome(test, "started");
    let url = test_db_url();
    let r = tokio::time::timeout(
        Duration::from_secs(3),
        tokio_postgres::connect(&url, tokio_postgres::NoTls),
    )
    .await;
    let Ok(Ok((c, conn))) = r else {
        if db_required() {
            panic!("DB_REQUIRED_BUT_UNREACHABLE: {test} needs Postgres at {url}");
        }
        record_outcome(test, &format!("skipped: no reachable Postgres at {url}"));
        eprintln!("skipping {test}: no reachable Postgres at {url}");
        return None;
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let schema = format!(
        "mig_{}_{}",
        test.replace(|ch: char| !ch.is_alphanumeric(), "_"),
        nanos % 1_000_000_000_000
    );
    c.batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create schema");
    Some(Sandbox { url, schema })
}

async fn versions(c: &tokio_postgres::Client) -> Vec<i32> {
    c.query(
        "SELECT version FROM schema_migrations ORDER BY version",
        &[],
    )
    .await
    .expect("read schema_migrations")
    .iter()
    .map(|r| r.get(0))
    .collect()
}

async fn table_exists(c: &tokio_postgres::Client, name: &str) -> bool {
    c.query_one(
        "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1)",
        &[&name],
    )
    .await
    .map(|r| r.get(0))
    .unwrap_or(false)
}

const V2_OK: Migration = Migration {
    version: 2,
    name: "test_add_table",
    sql: "CREATE TABLE mig_probe (id INT PRIMARY KEY);",
};

fn with_v2() -> Vec<Migration> {
    let mut v = MIGRATIONS.to_vec();
    v.push(V2_OK);
    v
}

#[test]
fn m0_builtin_list_is_well_formed() {
    assert!(!MIGRATIONS.is_empty());
    for (i, m) in MIGRATIONS.iter().enumerate() {
        assert_eq!(
            m.version,
            i as i32 + 1,
            "versions must be 1..n with no gaps"
        );
        assert!(!m.name.is_empty() && !m.sql.trim().is_empty());
    }
    let mut names: Vec<_> = MIGRATIONS.iter().map(|m| m.name).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), MIGRATIONS.len(), "names must be unique");
}

#[tokio::test]
async fn m1_fresh_database_gets_every_table_and_a_recorded_checksum() {
    const T: &str = "m1_fresh";
    let Some(sb) = sandbox(T).await else { return };
    let mut c = sb.connect().await;
    let applied = migrate_with(&mut c, MIGRATIONS).await.expect("migrate");
    assert_eq!(applied, vec![1]);
    assert_eq!(versions(&c).await, vec![1]);
    for t in [
        "nullifiers",
        "invoices",
        "regulators",
        "derive_call_times",
        "crypto_meta",
        "audit_outbox",
        "audit_failures",
    ] {
        assert!(table_exists(&c, t).await, "missing table {t}");
    }
    let row = c
        .query_one(
            "SELECT checksum, name FROM schema_migrations WHERE version = 1",
            &[],
        )
        .await
        .unwrap();
    let checksum: String = row.get(0);
    assert_eq!(checksum, migrations::checksum(MIGRATIONS[0].sql));
    assert_eq!(checksum.len(), 64);
    sb.drop_schema().await;
    record_outcome(T, "ran");
}

#[tokio::test]
async fn m2_rerun_is_a_noop() {
    const T: &str = "m2_rerun";
    let Some(sb) = sandbox(T).await else { return };
    let mut c = sb.connect().await;
    migrate_with(&mut c, MIGRATIONS).await.expect("first");
    let again = migrate_with(&mut c, MIGRATIONS).await.expect("second");
    assert!(
        again.is_empty(),
        "nothing should be applied twice: {again:?}"
    );
    assert_eq!(versions(&c).await, vec![1]);
    // A later migration is applied exactly once.
    let v2 = migrate_with(&mut c, &with_v2()).await.expect("v2");
    assert_eq!(v2, vec![2]);
    assert!(table_exists(&c, "mig_probe").await);
    assert!(migrate_with(&mut c, &with_v2())
        .await
        .expect("v2 again")
        .is_empty());
    sb.drop_schema().await;
    record_outcome(T, "ran");
}

#[tokio::test]
async fn m3_legacy_database_without_a_migrations_table_is_adopted_without_data_loss() {
    const T: &str = "m3_legacy";
    let Some(sb) = sandbox(T).await else { return };
    let mut c = sb.connect().await;
    // Exactly what every pre-Gap-10 deployment looks like: the old blob ran,
    // data exists, there is no schema_migrations table.
    c.batch_execute(MIGRATIONS[0].sql)
        .await
        .expect("legacy schema");
    c.execute(
        "INSERT INTO invoices (invoice_id, issuer, status, created_at_ms) VALUES ('legacy-1', 'issuer', 'active', 1)",
        &[],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO nullifiers (nullifier_hash) VALUES ('legacy-null')",
        &[],
    )
    .await
    .unwrap();
    assert!(!table_exists(&c, "schema_migrations").await);

    migrate_with(&mut c, MIGRATIONS).await.expect("adopt");
    assert_eq!(versions(&c).await, vec![1]);
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM invoices WHERE invoice_id = 'legacy-1'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let k: i64 = c
        .query_one("SELECT count(*) FROM nullifiers", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!((n, k), (1, 1), "legacy rows must survive adoption");
    sb.drop_schema().await;
    record_outcome(T, "ran");
}

#[tokio::test]
async fn m4_database_newer_than_this_binary_is_refused_and_left_untouched() {
    const T: &str = "m4_newer";
    let Some(sb) = sandbox(T).await else { return };
    let mut c = sb.connect().await;
    migrate_with(&mut c, &with_v2()).await.expect("up to v2");
    // An OLDER binary (knows only v1) must refuse to start against a v2 database.
    let err = migrate_with(&mut c, MIGRATIONS)
        .await
        .expect_err("must refuse");
    assert!(
        matches!(
            err,
            MigrateError::DatabaseNewerThanBinary {
                db_version: 2,
                binary_version: 1
            }
        ),
        "got {err:?}"
    );
    assert_eq!(
        versions(&c).await,
        vec![1, 2],
        "refusal must not modify anything"
    );
    sb.drop_schema().await;
    record_outcome(T, "ran");
}

#[tokio::test]
async fn m5_an_edited_already_applied_migration_is_refused() {
    const T: &str = "m5_checksum";
    let Some(sb) = sandbox(T).await else { return };
    let mut c = sb.connect().await;
    migrate_with(&mut c, MIGRATIONS).await.expect("apply");
    let tampered = [Migration {
        version: 1,
        name: MIGRATIONS[0].name,
        sql: "CREATE TABLE IF NOT EXISTS nullifiers (nullifier_hash TEXT PRIMARY KEY, extra TEXT);",
    }];
    let err = migrate_with(&mut c, &tampered)
        .await
        .expect_err("must refuse");
    assert!(
        matches!(err, MigrateError::ChecksumMismatch { version: 1, .. }),
        "got {err:?}"
    );
    sb.drop_schema().await;
    record_outcome(T, "ran");
}

#[tokio::test]
async fn m6_concurrent_migrators_apply_each_migration_exactly_once() {
    const T: &str = "m6_concurrent";
    let Some(sb) = sandbox(T).await else { return };
    let list = with_v2();
    let mut handles = Vec::new();
    for _ in 0..6 {
        let mut c = sb.connect().await;
        let list = list.clone();
        handles.push(tokio::spawn(
            async move { migrate_with(&mut c, &list).await },
        ));
    }
    let mut applied_total = 0usize;
    for h in handles {
        let r = h.await.expect("join").expect("every migrator must succeed");
        applied_total += r.len();
    }
    assert_eq!(
        applied_total, 2,
        "versions 1 and 2 are applied once in total across 6 racers"
    );
    let c = sb.connect().await;
    assert_eq!(versions(&c).await, vec![1, 2]);
    sb.drop_schema().await;
    record_outcome(T, "ran");
}

#[tokio::test]
async fn m7_a_failing_migration_rolls_back_completely() {
    const T: &str = "m7_rollback";
    let Some(sb) = sandbox(T).await else { return };
    let mut c = sb.connect().await;
    migrate_with(&mut c, MIGRATIONS).await.expect("v1");
    let mut list = MIGRATIONS.to_vec();
    list.push(Migration {
        version: 2,
        name: "half_applied",
        sql: "CREATE TABLE mig_half (id INT); SELECT 1/0;",
    });
    let err = migrate_with(&mut c, &list).await.expect_err("must fail");
    assert!(matches!(err, MigrateError::Db(_)), "got {err:?}");
    assert_eq!(
        versions(&c).await,
        vec![1],
        "failed version must not be recorded"
    );
    assert!(
        !table_exists(&c, "mig_half").await,
        "partial DDL must be rolled back"
    );
    sb.drop_schema().await;
    record_outcome(T, "ran");
}
