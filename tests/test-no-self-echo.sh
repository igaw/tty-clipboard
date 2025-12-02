#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Test that a subscriber never receives its own writes (fuzz test)
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
  [[ -n "${SUB_PID:-}" ]] && kill "$SUB_PID" 2>/dev/null || true
  rm -f "$SUBOUT"
}
trap cleanup EXIT

# Start server in protobuf mode
"$SERVER_BIN" --protobuf &
SERVER_PID=$!
sleep 2

echo "Test: Client never receives its own writes"

SUBOUT=$(mktemp)

# Simple test: write_subscribe should not see its own write
echo "=== Testing write_subscribe self-echo prevention ==="
echo "my_marker_$$" > /tmp/write_$$

timeout 10 cat /tmp/write_$$ | "$CLIENT_BIN" --protobuf write_subscribe 127.0.0.1 > "$SUBOUT" 2>/dev/null &
SUB_PID=$!
rm /tmp/write_$$

sleep 1

# Write some messages from other connections
for i in {1..100}; do
  echo "external_$i" | "$CLIENT_BIN" --protobuf write 127.0.0.1 2>/dev/null
done

sleep 1

kill -TERM "$SUB_PID" 2>/dev/null || true
sleep 0.5
kill -KILL "$SUB_PID" 2>/dev/null || true
wait "$SUB_PID" 2>/dev/null || true
SUB_PID=""

echo "Subscriber received $(wc -l < "$SUBOUT") lines"

# Verify subscriber never received its own marker
if grep -q "my_marker_$$" "$SUBOUT"; then
  echo "FAIL: Subscriber received its own write!" >&2
  echo "Subscriber output:" >&2
  cat "$SUBOUT" >&2
  exit 1
fi

# Verify subscriber received external messages
external_count=$(grep -c "external_" "$SUBOUT" || true)
if [ "$external_count" -ne 100 ]; then
  echo "FAIL: Subscriber received $external_count external messages (expected 100)" >&2
  echo "Subscriber output:" >&2
  cat "$SUBOUT" >&2
  exit 1
fi

echo "✓ Subscriber received $external_count external messages"
echo "✓ Subscriber never received its own write"
echo "Self-echo prevention test passed"
exit 0
