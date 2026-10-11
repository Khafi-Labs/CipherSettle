#!/usr/bin/env bash
# F-27: a second, TLS-enabled Postgres cluster for the live database-TLS test.
# Idempotent. Test-only credentials and a throwaway CA; NEVER reuse anywhere real.
#   cluster `ssltest` on port 5433, password auth over TLS only (hostssl),
#   CA at $OUT/ca.der (DER), server cert valid for localhost and 127.0.0.1 only.
# Prints the two environment variables the test reads.
set -euo pipefail
OUT="${1:-/tmp/ciphersettle_ssl}"
SUDO=""; AS_PG="runuser -u postgres --"
[ "$(id -u)" = 0 ] || { SUDO="sudo"; AS_PG="sudo -u postgres"; }   # cluster management needs root (GitHub runners: passwordless sudo)
PORT=5433
mkdir -p "$OUT"
if [ ! -f "$OUT/ca.der" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=ciphersettle-test-ca" \
    -keyout "$OUT/ca.key" -out "$OUT/ca.pem" 2>/dev/null
  openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout "$OUT/server.key" \
    -out "$OUT/server.csr" 2>/dev/null
  printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > "$OUT/san.ext"
  openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" \
    -CAcreateserial -days 30 -extfile "$OUT/san.ext" -out "$OUT/server.pem" 2>/dev/null
  openssl x509 -in "$OUT/ca.pem" -outform DER -out "$OUT/ca.der"
  # A second, unrelated CA for the "wrong CA is refused" case.
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=other-ca" \
    -keyout "$OUT/other.key" -out "$OUT/other.pem" 2>/dev/null
  openssl x509 -in "$OUT/other.pem" -outform DER -out "$OUT/other_ca.der"
fi
chmod 644 "$OUT"/*.pem "$OUT"/*.der
if ! pg_lsclusters | awk '{print $2}' | grep -qx ssltest; then
  $SUDO pg_createcluster 16 ssltest -p "$PORT" >/dev/null
  D=/etc/postgresql/16/ssltest
  $SUDO install -o postgres -g postgres -m 600 "$OUT/server.key" "$D/server.key"
  $SUDO install -o postgres -g postgres -m 644 "$OUT/server.pem" "$D/server.pem"
  {
    echo "ssl = on"
    echo "ssl_cert_file = '$D/server.pem'"
    echo "ssl_key_file = '$D/server.key'"
    echo "listen_addresses = '127.0.0.1'"
  } | $SUDO tee -a "$D/postgresql.conf" >/dev/null
  printf 'local all postgres peer\nhostssl all all 127.0.0.1/32 scram-sha-256\n' | $SUDO tee "$D/pg_hba.conf" >/dev/null
fi
pg_lsclusters | awk '$2=="ssltest" && $4=="online"{f=1} END{exit !f}' || $SUDO pg_ctlcluster 16 ssltest start
for _ in $(seq 1 30); do pg_isready -h 127.0.0.1 -p "$PORT" >/dev/null 2>&1 && break; sleep 1; done
$AS_PG psql -p "$PORT" -qc "ALTER USER postgres PASSWORD 'ciphersettle_dev'" postgres >/dev/null
echo "export CIPHERSETTLE_SSL_DB_PORT=$PORT"
echo "export CIPHERSETTLE_SSL_DB_DIR=$OUT"
