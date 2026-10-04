#!/usr/bin/env bash
# Gap 10: rehearse backup -> restore of the Postgres tier and PROVE the restored
# database is identical, instead of assuming it. Needs: a Postgres superuser URL
# (default below), pg_dump/pg_restore/psql, and a built quorum_service binary.
#
#   usage: ci/backup_restore_rehearsal.sh [OUTDIR=rehearsal_out]
#
# Steps (each EXECUTED and checked; exit 1 on the first failure):
#   R1 create a source DB through the REAL migrator (`quorum_service migrate`)
#   R2 load representative rows (invoices, nullifiers, outbox, audit_failures...)
#   R3 pg_dump (custom format)            -> record backup size + seconds
#   R4 pg_restore into a NEW empty DB     -> record restore seconds (the RTO sample)
#   R5 compare, table by table, row count AND an order-independent content digest
#   R6 the restored DB is accepted by the migrator as already current (no re-apply)
#   R7 NEGATIVE: damage one restored row; the comparison MUST report a mismatch
#      (proves R5 can fail).
# Does NOT cover: node key-share/audit-log files (separate backup, see
# agent_memory/DESIGN_NOTE_gap1_share_persistence.md), PITR/WAL archiving,
# restores across Postgres major versions, or a restore performed by anyone but
# the author. Those remain open under Gap 10.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-rehearsal_out}"; mkdir -p "$OUT"
ADMIN="${REHEARSAL_ADMIN_URL:-postgres://postgres:ciphersettle_dev@127.0.0.1:5432/postgres}"
BASE="${ADMIN%/*}"
BIN="${CARGO_TARGET_DIR:-target}/debug/quorum_service"
[ -x "$BIN" ] || { echo "FAIL: build quorum_service first ($BIN)"; exit 1; }
SRC="rehearsal_src_$$"; DST="rehearsal_dst_$$"
cleanup() {
  local rc=$?
  psql "$ADMIN" -qc "DROP DATABASE IF EXISTS $SRC" -c "DROP DATABASE IF EXISTS $DST" >/dev/null 2>&1 \
    || echo "WARN: could not drop scratch databases $SRC / $DST" >&2
  exit $rc
}
trap cleanup EXIT
q() { psql "$BASE/$1" -v ON_ERROR_STOP=1 -qAt -c "$2"; }
now() { date +%s.%N; }
log() { echo "$@" | tee -a "$OUT/rehearsal.txt"; }
: > "$OUT/rehearsal.txt"

psql "$ADMIN" -qc "CREATE DATABASE $SRC"
"$BIN" migrate "$BASE/$SRC" >/dev/null
ver=$(q $SRC "select max(version) from schema_migrations")
[ -n "$ver" ] || { echo "R1 FAIL: no schema_migrations version"; exit 1; }
log "R1 ok: source schema built by the real migrator, schema version $ver"

q $SRC "
INSERT INTO invoices (invoice_id, issuer, bank, ciphertext, status, created_at_ms, commitment_bytes, merkle_leaf_index)
  SELECT 'inv-'||g, 'issuer-'||(g%7), CASE WHEN g%3=0 THEN 'bank-1' END, decode(md5(g::text),'hex'),
         CASE WHEN g%5=0 THEN 'settled' ELSE 'active' END, 1700000000000+g, decode(md5('c'||g),'hex'), g-1
  FROM generate_series(1,2000) g;
INSERT INTO nullifiers SELECT 'null-'||g FROM generate_series(1,2000) g;
INSERT INTO regulators VALUES ('reg-1'),('reg-2');
INSERT INTO derive_call_times SELECT 'c-'||(g%5), 1700000000000+g FROM generate_series(1,500) g;
INSERT INTO crypto_meta VALUES ('crypto_epoch','blstrs-rfc9380-v1');
INSERT INTO audit_outbox (invoice_id, actor, action, timestamp_unix_ms, status, created_at_ms)
  SELECT 'inv-'||g,'issuer','invoice_registered',1700000000000+g, CASE WHEN g%10=0 THEN 'pending' ELSE 'done' END, 1700000000000+g
  FROM generate_series(1,2000) g;
INSERT INTO audit_failures (at_ms, invoice_id, actor, action, error) VALUES (1,'inv-1','a','key_derived','probe');
" >/dev/null
log "R2 ok: loaded rows (2000 invoices/nullifiers/outbox + small tables)"

t0=$(now); pg_dump -Fc -f "$OUT/backup.dump" "$BASE/$SRC"; t1=$(now)
log "R3 ok: pg_dump -Fc $(stat -c %s "$OUT/backup.dump") bytes in $(printf '%.2f' "$(echo "$t1 - $t0" | bc)") s"

psql "$ADMIN" -qc "CREATE DATABASE $DST"
t0=$(now); pg_restore --no-owner --exit-on-error -d "$BASE/$DST" "$OUT/backup.dump"; t1=$(now)
log "R4 ok: pg_restore into an empty database in $(printf '%.2f' "$(echo "$t1 - $t0" | bc)") s (sample RTO for this data size, same host)"

tables=$(q $SRC "select string_agg(tablename, ' ' order by tablename) from pg_tables where schemaname='public'")
digest() { # db table -> "count digest"; digest is order-independent (sorted row texts)
  q "$1" "select count(*) || ' ' || coalesce(md5(string_agg(t::text, '|' order by t::text)),'-') from $2 t"; }
mismatch=0
for t in $tables; do
  a=$(digest $SRC $t); b=$(digest $DST $t)
  if [ "$a" = "$b" ]; then echo "  ok:   $t ($a)" >> "$OUT/rehearsal.txt"; else echo "  FAIL: $t src=[$a] dst=[$b]" | tee -a "$OUT/rehearsal.txt"; mismatch=1; fi
done
[ $mismatch -eq 0 ] || { log "R5 FAIL: restored data differs"; exit 1; }
log "R5 ok: every table matches (row count + content digest): $tables"

applied=$("$BIN" migrate "$BASE/$DST")
case "$applied" in *"[]"*) log "R6 ok: migrator treats the restored DB as current ($applied)";; *) log "R6 FAIL: $applied"; exit 1;; esac

q $DST "delete from invoices where invoice_id='inv-7'" >/dev/null
if [ "$(digest $SRC invoices)" = "$(digest $DST invoices)" ]; then log "R7 FAIL: comparison did not notice a deleted row"; exit 1; fi
log "R7 ok: negative check, a single deleted row IS detected by the comparison"
log "RESULT: backup/restore rehearsal passed (Postgres tier only)"
