#!/usr/bin/env bash
# Gap 10: static policy for the container build (runs without Docker or network).
#   usage: ci/check_dockerfile.sh [Dockerfile=Dockerfile] [.dockerignore=.dockerignore]
# Checks (each violation prints FAIL and the script exits 1):
#   D1 every FROM names an explicit tag or digest, never `latest`/untagged
#   D2 the FINAL stage sets a non-root numeric or `nonroot` USER
#   D3 ENTRYPOINT is in exec form (JSON array), no shell CMD/ENTRYPOINT
#   D4 no ADD of remote URLs; no COPY of *.json/*.pem/*.key/*.der config or key material
#   D5 .dockerignore excludes .git, target, and key/config material
#   D6 the final stage is not a builder image (no `rust:` / `cargo` toolchain at runtime)
# This does NOT prove the image builds, boots or is free of CVEs: that needs a
# Docker daemon and registry access (CI job `container-image`, not yet run).
set -uo pipefail
DF="${1:-Dockerfile}"; DI="${2:-.dockerignore}"; bad=0
fail() { echo "FAIL: $*"; bad=1; }
[ -f "$DF" ] || { echo "FAIL: $DF missing"; exit 1; }
while read -r line; do
  img=$(awk '{print $2}' <<<"$line"); [ "$img" = "scratch" ] && continue
  case "$img" in *@sha256:*) ;; *:latest|*:) fail "D1 untagged/latest base: $img";; *:*) ;; *) fail "D1 base image without tag: $img";; esac
done < <(grep -iE '^FROM ' "$DF" | sed 's/ AS .*//I')
last_from_line=$(grep -niE '^FROM ' "$DF" | tail -1 | cut -d: -f1)
final=$(tail -n +"$last_from_line" "$DF")
user=$(grep -iE '^USER ' <<<"$final" | tail -1 | awk '{print $2}')
case "$user" in ""|root|0|0:*|root:*) fail "D2 final stage USER is '${user:-unset}' (must be non-root)";; esac
grep -qiE '^ENTRYPOINT \[' <<<"$final" || fail "D3 final stage lacks exec-form ENTRYPOINT"
grep -iE '^(CMD|ENTRYPOINT) ' <<<"$final" | grep -vE '\[' >/dev/null && fail "D3 shell-form CMD/ENTRYPOINT"
grep -iE '^ADD +https?://' "$DF" >/dev/null && fail "D4 ADD of a remote URL"
grep -iE '^COPY .*\.(json|pem|key|der)( |$)' "$DF" | grep -v -- '--from=' >/dev/null && fail "D4 COPY of config/key material into the image"
final_from=$(grep -iE '^FROM ' <<<"$final" | head -1 | awk '{print $2}')
case "$final_from" in rust:*|*/rust:*) fail "D6 final stage is a toolchain image: $final_from";; esac
if [ -f "$DI" ]; then
  for pat in '.git' 'target' '*.pem' '*.key' '*.der'; do
    grep -qxF "$pat" "$DI" || fail "D5 .dockerignore lacks '$pat'"
  done
else fail "D5 $DI missing"; fi
[ $bad -eq 0 ] && echo "dockerfile policy: ok ($DF)"; exit $bad
