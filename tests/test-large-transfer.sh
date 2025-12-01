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
  rm -f "$SRC" "$DST"
}
trap cleanup EXIT

# Start server
"$SERVER_BIN" &
SERVER_PID=$!
sleep 2

# Generate 4MB random payload
SRC=$(mktemp)
DST=$(mktemp)
head -c $((4 * 1024 * 1024)) /dev/urandom > "$SRC"

# Write payload
cat "$SRC" | "$CLIENT_BIN" write 127.0.0.1
sleep 1

# Read back using normal read
"$CLIENT_BIN" read 127.0.0.1 > "$DST"

ORIG_SIZE=$(stat -c %s "$SRC")
READ_SIZE=$(stat -c %s "$DST")

echo "Original size: $ORIG_SIZE bytes"
echo "Read size:     $READ_SIZE bytes"

if cmp -s "$SRC" "$DST"; then
  echo "PASS: Large payload roundtrip succeeded"
  exit 0
else
  echo "FAIL: Large payload mismatch" >&2
  if [[ "$ORIG_SIZE" -ne "$READ_SIZE" ]]; then
    echo "Size difference: wrote $ORIG_SIZE, read $READ_SIZE (ratio $((READ_SIZE*100/ORIG_SIZE))%)" >&2
  else
    echo "Sizes equal ($ORIG_SIZE) but content differs" >&2
  fi
  echo "First 64 bytes (written):" >&2
  hexdump -C "$SRC" | head -n 5 >&2
  echo "First 64 bytes (read):" >&2
  hexdump -C "$DST" | head -n 5 >&2
  echo "Diff sample (first 10 differing byte offsets):" >&2
  cmp -l "$SRC" "$DST" | head -n 10 >&2 || true
  exit 1
fi
