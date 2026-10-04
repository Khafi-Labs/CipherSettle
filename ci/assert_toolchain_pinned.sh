#!/usr/bin/env bash
# Gap 6/7: fail unless the ACTIVE rustc is the one pinned in rust-toolchain.toml.
# A green run on a different compiler (e.g. a distro 1.91 vs the pinned 1.97) is
# NOT evidence about the pinned build; this makes that mismatch a hard failure.
set -euo pipefail
cd "$(dirname "$0")/.."
pin=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)
[ -n "$pin" ] || { echo "FAIL: no channel in rust-toolchain.toml" >&2; exit 1; }
active=$(rustc --version)
case "$pin" in
  [0-9]*.[0-9]*.[0-9]*) want="rustc $pin " ;;
  [0-9]*.[0-9]*)        want="rustc $pin." ;;
  *) echo "FAIL: pinned channel '$pin' is not a numeric version" >&2; exit 1 ;;
esac
echo "pinned channel: $pin; active: $active"
case "$active" in
  "$want"*) echo "ok: active toolchain matches the pin" ;;
  *) echo "FAIL: active toolchain does not match the pinned channel $pin" >&2; exit 1 ;;
esac
