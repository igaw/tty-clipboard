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

MAX="64K" # limit for this test

echo "Starting server with max size $MAX"
"$SERVER_BIN" -b $TEST_IP -p $TEST_PORT --max-size "$MAX" &
SERVER_PID=$!
sleep 2

# Generate payload exactly at limit (64 * 1024 bytes)
EXACT=$(mktemp)
READ_AFTER_EXACT=$(mktemp)
head -c $((64 * 1024)) /dev/urandom > "$EXACT"

echo "Writing exact-limit payload ($(stat -c %s "$EXACT") bytes)"
cat "$EXACT" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write
sleep 1

"$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read > "$READ_AFTER_EXACT"

SIZE_EXACT=$(stat -c %s "$EXACT")
SIZE_READ_EXACT=$(stat -c %s "$READ_AFTER_EXACT")

if [[ "$SIZE_EXACT" -ne 65536 ]]; then
  echo "FAIL: Generated exact-limit size unexpected ($SIZE_EXACT)" >&2
  exit 1
fi

if [[ "$SIZE_READ_EXACT" -ne "$SIZE_EXACT" ]]; then
  echo "FAIL: Read size ($SIZE_READ_EXACT) differs from written ($SIZE_EXACT)" >&2
  exit 1
fi

if cmp -s "$EXACT" "$READ_AFTER_EXACT"; then
  echo "PASS: Exact-limit write roundtrip succeeded"
else
  echo "FAIL: Exact-limit payload content mismatch" >&2
  exit 1
fi

# Generate oversize payload (limit + 1000 bytes)
OVERSIZE=$(mktemp)
READ_AFTER_OVERSIZE=$(mktemp)
head -c $((64 * 1024 + 1000)) /dev/urandom > "$OVERSIZE"
SIZE_OVERSIZE=$(stat -c %s "$OVERSIZE")
echo "Attempting oversize write ($SIZE_OVERSIZE bytes > 65536)"
set +e
cat "$OVERSIZE" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write >/dev/null 2>&1
WRITE_RC=$?
set -e
sleep 1

"$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read > "$READ_AFTER_OVERSIZE"
SIZE_READ_OVERSIZE=$(stat -c %s "$READ_AFTER_OVERSIZE")

if [[ "$SIZE_READ_OVERSIZE" -ne 65536 ]]; then
  echo "FAIL: Oversize write incorrectly changed clipboard size to $SIZE_READ_OVERSIZE" >&2
  exit 1
fi

if [[ "$WRITE_RC" -eq 0 ]]; then
  echo "FAIL: Oversize write exited with success status (expected failure)" >&2
  exit 1
fi

if cmp -s "$EXACT" "$READ_AFTER_OVERSIZE"; then
  echo "PASS: Oversize write rejected; clipboard unchanged"
else
  echo "FAIL: Clipboard content changed after oversize write" >&2
  exit 1
fi

echo "All max-size limit checks passed"
exit 0
