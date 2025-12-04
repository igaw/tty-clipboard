#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Test that updates are properly synchronized across multiple clients
# Verifies that a fresh subscriber sees updates correctly
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
  [[ -n "${SUB_PID:-}" ]] && kill "$SUB_PID" 2>/dev/null || true
  rm -f "$SUBOUT"
}
trap cleanup EXIT

# Start server
"$SERVER_BIN" -b $TEST_IP -p $TEST_PORT &
SERVER_PID=$!
sleep 2

echo "Test: Verify UUID-based deduplication works"

SUBOUT=$(mktemp)

# Test: Start read_blocked subscriber, then write from another client
# The subscriber should see the write (it's from a different connection/UUID)
echo "=== Testing subscriber receives external writes ==="

# Start subscriber in background (read_blocked waits for updates)
timeout 10 "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read_blocked > "$SUBOUT" 2>/dev/null &
SUB_PID=$!

sleep 1

# Write test marker from a separate connection
echo "test_marker_$$" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write 2>/dev/null

sleep 1

# Write some additional messages 
for i in {1..10}; do
  echo "external_$i" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write 2>/dev/null
done

sleep 1

kill -TERM "$SUB_PID" 2>/dev/null || true
sleep 0.5
kill -KILL "$SUB_PID" 2>/dev/null || true
wait "$SUB_PID" 2>/dev/null || true
SUB_PID=""

echo "Subscriber received $(wc -l < "$SUBOUT") lines"

# Verify subscriber received the marker (it's from a different client)
if ! grep -q "test_marker_$$" "$SUBOUT"; then
  echo "FAIL: Subscriber did not receive marker from other client!" >&2
  echo "Subscriber output:" >&2
  cat "$SUBOUT" >&2
  exit 1
fi

# Verify subscriber received external messages
external_count=$(grep -c "external_" "$SUBOUT" || true)
if [ "$external_count" -ne 10 ]; then
  echo "FAIL: Subscriber received $external_count external messages (expected 10)" >&2
  echo "Subscriber output:" >&2
  cat "$SUBOUT" >&2
  exit 1
fi

echo "✓ Subscriber received test_marker_$$"
echo "✓ Subscriber received $external_count external messages"
echo "Update synchronization test passed"
exit 0
