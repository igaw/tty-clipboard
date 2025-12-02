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

# Start server in protobuf mode
"$SERVER_BIN" --protobuf &
SERVER_PID=$!
sleep 2

echo "Test 1: Protobuf write"
TMP_IN=$(mktemp)
echo "Hello protobuf world" > "$TMP_IN"

cat "$TMP_IN" | "$CLIENT_BIN" --protobuf write 127.0.0.1
sleep 1
echo "✓ Protobuf write succeeded"

echo "Test 2: Protobuf read"
TMP_OUT=$(mktemp)
"$CLIENT_BIN" --protobuf read 127.0.0.1 > "$TMP_OUT"

if cmp -s "$TMP_IN" "$TMP_OUT"; then
  echo "✓ Protobuf read matched"
else
  echo "FAIL: Protobuf read mismatch" >&2
  exit 1
fi

echo "Test 3: Protobuf write_read (bidirectional)"
TMP_IN2=$(mktemp)
TMP_OUT2=$(mktemp)
echo "Bidirectional test data" > "$TMP_IN2"

cat "$TMP_IN2" | "$CLIENT_BIN" --protobuf write_read 127.0.0.1 > "$TMP_OUT2"

if cmp -s "$TMP_IN2" "$TMP_OUT2"; then
  echo "✓ Protobuf write_read roundtrip succeeded"
else
  echo "FAIL: Protobuf write_read mismatch" >&2
  exit 1
fi

echo "Test 4: Binary data with protobuf"
TMP_BIN=$(mktemp)
TMP_BIN_OUT=$(mktemp)
head -c 2048 /dev/urandom > "$TMP_BIN"

cat "$TMP_BIN" | "$CLIENT_BIN" --protobuf write 127.0.0.1
sleep 1
"$CLIENT_BIN" --protobuf read 127.0.0.1 > "$TMP_BIN_OUT"

if cmp -s "$TMP_BIN" "$TMP_BIN_OUT"; then
  echo "✓ Binary protobuf roundtrip succeeded"
else
  echo "FAIL: Binary protobuf mismatch" >&2
  exit 1
fi

rm -f "$TMP_IN2" "$TMP_OUT2" "$TMP_BIN" "$TMP_BIN_OUT"

echo "All protobuf tests passed"
exit 0
