#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

SERVER_BIN="$1"
CLIENT_BIN="$2"
TEST_CONFIG_DIR="$3"

export XDG_CONFIG_HOME="$TEST_CONFIG_DIR"

# Test configuration
TEST_IP="127.0.0.2"
TEST_PORT="15457"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -f "$TMP_IN" "$TMP_OUT"
}
trap cleanup EXIT

# Start server
"$SERVER_BIN" -b $TEST_IP -p $TEST_PORT &
SERVER_PID=$!
sleep 2

# Prepare binary payload with NULs
TMP_IN=$(mktemp)
head -c 1024 /dev/urandom > "$TMP_IN"

# Start blocking read (subscribe mode) before write; will capture first generation update
TMP_OUT=$(mktemp)
timeout 5 "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read_blocked > "$TMP_OUT" &
SYNC_PID=$!
sleep 1

# Write binary to clipboard (current client treats data as C-strings, likely truncates at first NUL)
cat "$TMP_IN" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write || true
sleep 1

# Wait for sync read to finish (or timeout)
wait $SYNC_PID 2>/dev/null || true

# Compare (now should match exactly with protobuf protocol)
if cmp -s "$TMP_IN" "$TMP_OUT"; then
  echo "PASS: binary roundtrip matched (subscribe)"
  exit 0
else
  echo "FAIL: binary differs after roundtrip" >&2
  hexdump -C "$TMP_IN" | head -n 5 >&2
  hexdump -C "$TMP_OUT" | head -n 5 >&2
  exit 1
fi