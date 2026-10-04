//! Integration test for audit finding A10.
//!
//! The old implementation held one `tokio_postgres::Client` behind a
//! `tokio::sync::Mutex`, so a second in-flight request's `.lock().await`
//! would block for as long as the first request's guard was held --
//! meaning two requests could never genuinely be "in the database" at the
//! same time, no matter how many CPU cores or how much Postgres capacity
//! was available. This test proves the replacement `deadpool-postgres`
//! pool doesn't have that property: it can hand out more than one live
//! connection at once.
//!
//! Requires a reachable Postgres. Set `CIPHERSETTLE_TEST_DB_URL` to point
//! at one (defaults to `postgres://postgres:postgres@localhost/ciphersettle_test`,
//! matching the sandbox setup used during development). If no Postgres is
//! reachable, the test prints a message and skips rather than failing --
//! the same pattern a CI job would use with `services: postgres:` (see the
//! CI workflow), where the database is always present, versus a local
//! `cargo test` run where it might not be.
//!
//! ## Telling a real pass from a skip (TASK-008 / DISC-5)
//!
//! `cargo test` reports a skipped test as plain `ok`, identical to a real
//! pass, unless run with `--nocapture`. Two mechanisms make the difference
//! observable without that flag:
//!
//! * `CIPHERSETTLE_TEST_DB_REQUIRED=1` (intended for CI, where Postgres is
//!   always present): an unreachable database makes the test FAIL with a
//!   message containing `DB_REQUIRED_BUT_UNREACHABLE` instead of skipping.
//!   Any value other than empty or `0` enables it.
//! * Every run writes one file per test,
//!   `<CARGO_TARGET_TMPDIR>/db_pool_concurrency.<test>.outcome`, whose
//!   content is `started` (test began, did not finish -- e.g. it
//!   panicked), `skipped: ...` (no Postgres), or `ran` (all assertions
//!   passed against a live database). Each run overwrites the file, so a
//!   stale `ran` from an earlier run cannot survive a new run.
//!
//! Default behaviour with no Postgres and no env var is unchanged: the
//! test skips and the run stays green.

use std::time::Duration;

/// Records what this test actually did, overwriting any earlier run's file.
/// Best-effort by design: failing to write the marker must never fail a test.
fn record_outcome(test: &str, outcome: &str) {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let _ = std::fs::create_dir_all(dir);
    let _ = std::fs::write(
        dir.join(format!("db_pool_concurrency.{test}.outcome")),
        outcome,
    );
}

fn db_required() -> bool {
    match std::env::var("CIPHERSETTLE_TEST_DB_REQUIRED") {
        Ok(v) => !v.is_empty() && v != "0",
        Err(_) => false,
    }
}

/// Called when no Postgres is reachable: fail loudly if the environment
/// says a database is mandatory, otherwise record and skip as before.
fn skip_or_fail(test: &str, url: &str) {
    if db_required() {
        record_outcome(test, "started");
        panic!("DB_REQUIRED_BUT_UNREACHABLE: {test} needs Postgres at {url} (CIPHERSETTLE_TEST_DB_REQUIRED is set)");
    }
    record_outcome(test, &format!("skipped: no reachable Postgres at {url}"));
    eprintln!("skipping: no reachable Postgres at {url} (set CIPHERSETTLE_TEST_DB_URL)");
}

fn test_db_url() -> String {
    std::env::var("CIPHERSETTLE_TEST_DB_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost/ciphersettle_test".to_string())
}

fn build_pool(url: &str, max_size: usize) -> deadpool_postgres::Pool {
    let pg_config: tokio_postgres::Config = url.parse().expect("test DB URL must parse");
    let manager = deadpool_postgres::Manager::from_config(
        pg_config,
        tokio_postgres::NoTls,
        deadpool_postgres::ManagerConfig {
            recycling_method: deadpool_postgres::RecyclingMethod::Fast,
        },
    );
    deadpool_postgres::Pool::builder(manager)
        .max_size(max_size)
        .build()
        .expect("failed to build pool")
}

#[tokio::test]
async fn pool_hands_out_multiple_simultaneous_connections() {
    const NAME: &str = "pool_hands_out_multiple_simultaneous_connections";
    record_outcome(NAME, "started");
    let url = test_db_url();
    let pool = build_pool(&url, 5);

    // Sanity-check connectivity first; skip (not fail) the assertion below
    // if there's no reachable Postgres in this environment.
    let probe = tokio::time::timeout(Duration::from_secs(2), pool.get()).await;
    let Ok(Ok(_probe_client)) = probe else {
        skip_or_fail(NAME, &url);
        return;
    };
    drop(_probe_client);

    // Check out 5 connections and HOLD all of them open simultaneously.
    // Under the old Mutex<Client> design this is structurally impossible:
    // there was only ever one client, and a second `.lock().await` would
    // wait for the first guard to be dropped. Here, all 5 checkouts must
    // succeed concurrently, well within a generous timeout, with none of
    // them waiting on any of the others to finish.
    let mut held = Vec::new();
    for i in 0..5 {
        let client = tokio::time::timeout(Duration::from_secs(3), pool.get())
            .await
            .unwrap_or_else(|_| panic!("checkout {i} timed out waiting on another checkout -- pool is still effectively serialized"))
            .expect("checkout failed");
        // Prove the connection is actually live and independently usable,
        // not just an object -- run a trivial query on each one while all
        // the others are still held open.
        let row = client
            .query_one("SELECT 1", &[])
            .await
            .expect("query failed on held connection");
        let value: i32 = row.get(0);
        assert_eq!(value, 1);
        held.push(client);
    }
    assert_eq!(
        held.len(),
        5,
        "expected all 5 simultaneous checkouts to succeed"
    );
    record_outcome(NAME, "ran");
    // All 5 dropped together at end of scope -- fine, that's cleanup, not
    // part of what's being proven.
}

#[tokio::test]
async fn db_helpers_work_unchanged_against_a_pooled_client() {
    const NAME: &str = "db_helpers_work_unchanged_against_a_pooled_client";
    record_outcome(NAME, "started");
    // Audit finding A10's fix intentionally left `db.rs`'s function
    // signatures (`&Client` / `&mut Client`) untouched -- deadpool's
    // pooled `Object` derefs to `tokio_postgres::Client`, so every
    // existing query helper should work against a pooled connection with
    // no changes. This is a smoke test of that assumption, exercising the
    // one function that needs `&mut` (a transaction).
    let url = test_db_url();
    let pool = build_pool(&url, 2);

    let probe = tokio::time::timeout(Duration::from_secs(2), pool.get()).await;
    if probe.is_err() || probe.as_ref().unwrap().is_err() {
        skip_or_fail(NAME, &url);
        return;
    }

    let mut client = pool.get().await.expect("checkout failed");
    quorum_service_db_test_support::init_and_register(&mut client).await;
    record_outcome(NAME, "ran");
}

// `db.rs` is a private module of the `quorum_service` binary crate, not a
// library, so it isn't directly importable from an external integration
// test (`tests/*.rs` compiles against the crate as an external user, the
// same as any downstream caller would see it). Rather than restructure
// the crate into lib+bin just for this test, this thin support module
// re-implements the couple of schema/insert statements needed to prove
// pooled clients behave like direct clients for real queries -- it is
// deliberately NOT a copy of `db.rs`'s business logic (nullifier/uniqueness
// checks, etc.), only enough SQL to prove connectivity and transactions
// work the same way against a pooled client as they did against the old
// single client.
mod quorum_service_db_test_support {
    pub async fn init_and_register(client: &mut tokio_postgres::Client) {
        client
            .batch_execute(
                "CREATE TABLE IF NOT EXISTS pool_smoke_test (id TEXT PRIMARY KEY, val TEXT NOT NULL)",
            )
            .await
            .expect("schema init failed");

        let id = format!("smoke-{}", uuid_like());
        let tx = client
            .transaction()
            .await
            .expect("failed to start transaction (mut client)");
        tx.execute("DELETE FROM pool_smoke_test WHERE id = $1", &[&id])
            .await
            .expect("delete failed");
        tx.execute(
            "INSERT INTO pool_smoke_test (id, val) VALUES ($1, $2)",
            &[&id, &"ok"],
        )
        .await
        .expect("insert failed");
        tx.commit().await.expect("commit failed");

        let row = client
            .query_one("SELECT val FROM pool_smoke_test WHERE id = $1", &[&id])
            .await
            .expect("select failed");
        let val: String = row.get(0);
        assert_eq!(val, "ok");
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        format!(
            "{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
}
