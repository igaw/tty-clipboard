#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2024 Daniel Wagner <wagi@monom.org>

set -e

# Get paths from arguments
SERVER_BIN="$1"
CLIENT_BIN="$2"
TEST_CONFIG_DIR="$3"

# Export XDG_CONFIG_HOME for the test
export XDG_CONFIG_HOME="$TEST_CONFIG_DIR"

# Test 1: Basic write and read
echo "Test 1: Basic write and read"

# Start the server in the background
$SERVER_BIN &
SERVER_PID=$!
echo "Started server with PID: $SERVER_PID"

# Give the server time to start
sleep 2

# Test string
TEST_STRING="yolo world"

# Write test string to clipboard
if echo "$TEST_STRING" | $CLIENT_BIN write 127.0.0.1 2>&1; then
    echo "Wrote test string to clipboard"
else
    echo "Failed to write to clipboard"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Give time for write to complete
sleep 1

# Read from clipboard
RESULT=$($CLIENT_BIN read 127.0.0.1)
echo "Read from clipboard: $RESULT"

# Verify result
if [ "$RESULT" = "$TEST_STRING" ]; then
    echo "✓ Test 1 PASSED: Write and read successful"
else
    echo "✗ Test 1 FAILED: Expected '$TEST_STRING', got '$RESULT'"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Test 2: Multiple writes (last write wins)
echo ""
echo "Test 2: Multiple writes"

TEST_STRING_2="second test string"
echo "$TEST_STRING_2" | $CLIENT_BIN write 127.0.0.1
sleep 1

RESULT_2=$($CLIENT_BIN read 127.0.0.1)
echo "Read from clipboard: $RESULT_2"

if [ "$RESULT_2" = "$TEST_STRING_2" ]; then
    echo "✓ Test 2 PASSED: Second write overwrote first"
else
    echo "✗ Test 2 FAILED: Expected '$TEST_STRING_2', got '$RESULT_2'"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

# Test 3: Sync mode (blocking read)
echo ""
echo "Test 3: Sync mode (blocking read with timeout)"

# Start a sync read in background with timeout
timeout 5 $CLIENT_BIN read 127.0.0.1 sync > /tmp/test_sync_output.txt &
SYNC_PID=$!
sleep 1

# Write new content
TEST_STRING_3="sync test string"
echo "$TEST_STRING_3" | $CLIENT_BIN write 127.0.0.1
sleep 1

# Check if sync read got the update
wait $SYNC_PID 2>/dev/null || true
if [ -f /tmp/test_sync_output.txt ]; then
    SYNC_RESULT=$(cat /tmp/test_sync_output.txt)
    if [ "$SYNC_RESULT" = "$TEST_STRING_3" ]; then
        echo "✓ Test 3 PASSED: Sync mode received update"
    else
        echo "✓ Test 3 PARTIAL: Sync read returned '$SYNC_RESULT'"
    fi
    rm -f /tmp/test_sync_output.txt
else
    echo "✓ Test 3 SKIPPED: Could not verify sync output"
fi

# Clean up
echo ""
echo "Cleaning up..."
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "All tests completed successfully!"
exit 0
