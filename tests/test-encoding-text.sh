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
}
trap cleanup EXIT

# Start server
"$SERVER_BIN" -b $TEST_IP -p $TEST_PORT &
SERVER_PID=$!
sleep 2

pass_case() {
  local label="$1" payload="$2"
  printf "%s" "$payload" | "$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT write
  sleep 0.5
  local out
  out=$("$CLIENT_BIN" -s $TEST_IP -p $TEST_PORT read)
  if [[ "$out" != "$payload" ]]; then
    echo "FAIL ($label): expected '$payload' got '$out'" >&2
    exit 1
  else
    echo "PASS ($label)"
  fi
}

echo "ASCII test"
pass_case "ascii" "The quick brown fox jumps over 13 lazy dogs! @#%&*()[]{};:,.?/~"

echo "UTF-8 test"
pass_case "utf8-simple" "こんにちは世界"
pass_case "utf8-emoji" "😀👍🏽 café naïve coöperate résumé äöü ß 中文测试"

# Control characters (no NUL): include tabs and newlines removed (client strips trailing newline), so avoid newline
pass_case "control-chars" $'col1\tcol2\tcol3\t✓'

echo "All encoding text tests passed"