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
  rm -f "$EXACT" "$READ_AFTER_EXACT" "$OVERSIZE" "$READ_AFTER_OVERSIZE"
}
trap cleanup EXIT

MAX="32K" # smaller limit for test
LIMIT_BYTES=$((32 * 1024))

echo "Starting server with max size $MAX (policy=drop)"
"$SERVER_BIN" -b $TEST_IP -p $TEST_PORT --max-size "$MAX" --oversize-policy drop &
SERVER_PID=$!
sleep 2

# Generate payload exactly at limit
EXACT=$(mktemp)
READ_AFTER_EXACT=$(mktemp)
head -c "$LIMIT_BYTES" /dev/urandom > "$EXACT"

echo "Writing exact-limit payload ($LIMIT_BYTES bytes)"
cat "$EXACT" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write
sleep 1

"$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read > "$READ_AFTER_EXACT"

if ! cmp -s "$EXACT" "$READ_AFTER_EXACT"; then
  echo "FAIL: Exact-limit payload mismatch" >&2
  exit 1
fi
echo "PASS: Exact-limit payload stored"

# Oversize payload (limit + 500 bytes)
OVERSIZE=$(mktemp)
READ_AFTER_OVERSIZE=$(mktemp)
head -c $((LIMIT_BYTES + 500)) /dev/urandom > "$OVERSIZE"
OVERSIZE_SIZE=$(stat -c %s "$OVERSIZE")
echo "Writing oversize payload ($OVERSIZE_SIZE bytes > $LIMIT_BYTES) expecting drop"

set +e
cat "$OVERSIZE" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write >/dev/null 2>&1
WRITE_RC=$?
set -e
sleep 1

if [[ "$WRITE_RC" -ne 0 ]]; then
  echo "FAIL: Oversize write failed (should succeed under drop policy)" >&2
  exit 1
fi

"$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read > "$READ_AFTER_OVERSIZE"

READ_SIZE=$(stat -c %s "$READ_AFTER_OVERSIZE")
if [[ "$READ_SIZE" -ne "$LIMIT_BYTES" ]]; then
  echo "FAIL: Clipboard size changed after drop (size=$READ_SIZE)" >&2
  exit 1
fi

if cmp -s "$EXACT" "$READ_AFTER_OVERSIZE"; then
  echo "PASS: Drop policy preserved original clipboard"
else
  echo "FAIL: Clipboard content changed under drop policy" >&2
  exit 1
fi

echo "All drop policy tests passed"
exit 0
