#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

SERVER_BIN="$1"
CLIENT_BIN="$2"
TEST_CONFIG_DIR="$3"

export XDG_CONFIG_HOME="$TEST_CONFIG_DIR"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$TMP_IN" "$TMP_OUT"
}
trap cleanup EXIT

# Start server
"$SERVER_BIN" &
SERVER_PID=$!
sleep 2

# Prepare binary payload with NULs
TMP_IN=$(mktemp)
head -c 1024 /dev/urandom > "$TMP_IN"

# Write binary to clipboard (current client treats data as C-strings, likely truncates at first NUL)
cat "$TMP_IN" | "$CLIENT_BIN" write 127.0.0.1 || true
sleep 0.5

# Read back
TMP_OUT=$(mktemp)
"$CLIENT_BIN" read 127.0.0.1 > "$TMP_OUT" || true

# Compare
if cmp -s "$TMP_IN" "$TMP_OUT"; then
  echo "Unexpected PASS: binary roundtrip matched"
  exit 0
else
  echo "Expected FAIL: binary differs (client/server treat payload as string)" >&2
  # Return failure so Meson can mark should_fail
  exit 1
fi