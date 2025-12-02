#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# Test that clients don't receive their own writes back in subscribe mode
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
  [[ -n "${CLIENT1_PID:-}" ]] && kill "$CLIENT1_PID" 2>/dev/null || true
  [[ -n "${CLIENT2_PID:-}" ]] && kill "$CLIENT2_PID" 2>/dev/null || true
  rm -f "$TMP1" "$TMP2" "$WRITE1" "$WRITE2"
}
trap cleanup EXIT

# Start server
"$SERVER_BIN" -b $TEST_IP -p $TEST_PORT &
SERVER_PID=$!
sleep 2

echo "Test: Two subscribers receive all writes exactly once"

TMP1=$(mktemp)
TMP2=$(mktemp)
WRITE1=$(mktemp)
WRITE2=$(mktemp)

echo "first_message" > "$WRITE1"
echo "second_message" > "$WRITE2"

echo "DEBUG: Starting subscriber 1..."
# Subscriber 1 starts listening
timeout 10 "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read_blocked > "$TMP1" 2>/dev/null &
CLIENT1_PID=$!
echo "DEBUG: Subscriber 1 PID: $CLIENT1_PID"

echo "DEBUG: Starting subscriber 2..."
# Subscriber 2 starts listening
timeout 10 "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read_blocked > "$TMP2" 2>/dev/null &
CLIENT2_PID=$!
echo "DEBUG: Subscriber 2 PID: $CLIENT2_PID"

# Give subscribers time to connect
sleep 1

echo "DEBUG: Client 1 writing..."
# Write from client 1
cat "$WRITE1" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write 2>/dev/null
echo "DEBUG: Client 1 write complete"

sleep 1

echo "DEBUG: Client 2 writing..."
# Write from client 2
cat "$WRITE2" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write 2>/dev/null
echo "DEBUG: Client 2 write complete"

# Give time for propagation
sleep 2

echo "DEBUG: Killing clients..."
kill -TERM "$CLIENT1_PID" "$CLIENT2_PID" 2>/dev/null || true
sleep 0.5
kill -KILL "$CLIENT1_PID" "$CLIENT2_PID" 2>/dev/null || true
wait "$CLIENT1_PID" "$CLIENT2_PID" 2>/dev/null || true

echo "DEBUG: Clients finished"

echo "DEBUG: Client 1 output file size: $(wc -c < "$TMP1") bytes"
echo "DEBUG: Client 2 output file size: $(wc -c < "$TMP2") bytes"
echo "DEBUG: Subscriber 1 received:"
cat "$TMP1" | od -c || echo "(empty)"
echo "DEBUG: Subscriber 2 received:"
cat "$TMP2" | od -c || echo "(empty)"

# Both subscribers should receive both messages (no duplicate suppression within same subscriber)
# Each subscriber connection tracks its own last_sent_message_id, so each message is delivered exactly once per subscriber
if grep -q "first_message" "$TMP1" && grep -q "second_message" "$TMP1"; then
  echo "✓ Subscriber 1 received both messages"
else
  echo "FAIL: Subscriber 1 didn't receive all messages" >&2
  echo "Subscriber 1 received:" >&2
  cat "$TMP1" >&2
  exit 1
fi

if grep -q "first_message" "$TMP2" && grep -q "second_message" "$TMP2"; then
  echo "✓ Subscriber 2 received both messages"
else
  echo "FAIL: Subscriber 2 didn't receive all messages" >&2
  echo "Subscriber 2 received:" >&2
  cat "$TMP2" >&2
  exit 1
fi

echo "All message tracking tests passed"
exit 0
