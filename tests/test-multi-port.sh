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

# Test configuration
TEST_IP="127.0.0.2"
PORT1="15457"
PORT2="15458"
PORT3="15459"

echo "=========================================="
echo "Multi-Port Client Tests"
echo "=========================================="

# Start three servers on different ports
echo "Starting three servers on ports $PORT1, $PORT2, $PORT3..."

$SERVER_BIN -b $TEST_IP -p $PORT1 &
SERVER_PID1=$!
echo "Started server 1 with PID: $SERVER_PID1 on port $PORT1"

$SERVER_BIN -b $TEST_IP -p $PORT2 &
SERVER_PID2=$!
echo "Started server 2 with PID: $SERVER_PID2 on port $PORT2"

$SERVER_BIN -b $TEST_IP -p $PORT3 &
SERVER_PID3=$!
echo "Started server 3 with PID: $SERVER_PID3 on port $PORT3"

# Give the servers time to start
sleep 3

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up servers..."
    kill $SERVER_PID1 $SERVER_PID2 $SERVER_PID3 2>/dev/null || true
    wait $SERVER_PID1 $SERVER_PID2 $SERVER_PID3 2>/dev/null || true
}

trap cleanup EXIT

# Test 1: Write to multiple ports simultaneously
echo ""
echo "Test 1: Write to multiple ports simultaneously"
TEST_STRING_1="multi-port test data"

if echo "$TEST_STRING_1" | $CLIENT_BIN -s $TEST_IP -p "$PORT1,$PORT2,$PORT3" write 2>&1; then
    echo "✓ Write command completed"
else
    echo "✗ Test 1 FAILED: Write command failed"
    exit 1
fi

sleep 1

# Verify data was written to all three servers
RESULT1=$($CLIENT_BIN -s $TEST_IP -p $PORT1 read)
RESULT2=$($CLIENT_BIN -s $TEST_IP -p $PORT2 read)
RESULT3=$($CLIENT_BIN -s $TEST_IP -p $PORT3 read)

if [ "$RESULT1" = "$TEST_STRING_1" ] && [ "$RESULT2" = "$TEST_STRING_1" ] && [ "$RESULT3" = "$TEST_STRING_1" ]; then
    echo "✓ Test 1 PASSED: Data written to all three servers"
    echo "  Server 1: $RESULT1"
    echo "  Server 2: $RESULT2"
    echo "  Server 3: $RESULT3"
else
    echo "✗ Test 1 FAILED: Data mismatch"
    echo "  Expected: '$TEST_STRING_1'"
    echo "  Server 1: '$RESULT1'"
    echo "  Server 2: '$RESULT2'"
    echo "  Server 3: '$RESULT3'"
    exit 1
fi

# Test 2: Read from multiple ports (returns first available)
echo ""
echo "Test 2: Read from multiple ports"

# Write different data to each server
echo "first" | $CLIENT_BIN -s $TEST_IP -p $PORT1 write
sleep 0.5
echo "second" | $CLIENT_BIN -s $TEST_IP -p $PORT2 write
sleep 0.5
echo "third" | $CLIENT_BIN -s $TEST_IP -p $PORT3 write
sleep 1

# Read from all three ports - should get one of them
MULTI_READ=$($CLIENT_BIN -s $TEST_IP -p "$PORT1,$PORT2,$PORT3" read)

if [ "$MULTI_READ" = "first" ] || [ "$MULTI_READ" = "second" ] || [ "$MULTI_READ" = "third" ]; then
    echo "✓ Test 2 PASSED: Multi-port read returned data: '$MULTI_READ'"
else
    echo "✗ Test 2 FAILED: Unexpected result: '$MULTI_READ'"
    exit 1
fi

# Test 3: Subscribe to multiple ports (read_blocked)
echo ""
echo "Test 3: Subscribe to multiple ports with blocking read"

# Start blocking read in background
timeout 10 $CLIENT_BIN -s $TEST_IP -p "$PORT1,$PORT2,$PORT3" read_blocked > /tmp/test_multi_blocked.txt 2>&1 &
BLOCKED_PID=$!
sleep 2

# Write to the second server only
TEST_STRING_3="update from server 2"
echo "$TEST_STRING_3" | $CLIENT_BIN -s $TEST_IP -p $PORT2 write
sleep 2

# Gracefully terminate the blocked read
kill -TERM $BLOCKED_PID 2>/dev/null || true
wait $BLOCKED_PID 2>/dev/null || true
sleep 1

# Check if the blocked read received the update
if [ -f /tmp/test_multi_blocked.txt ]; then
    BLOCKED_RESULT=$(head -n 1 /tmp/test_multi_blocked.txt)
    if [ "$BLOCKED_RESULT" = "$TEST_STRING_3" ]; then
        echo "✓ Test 3 PASSED: Blocking read received update from any port"
        echo "  Received: $BLOCKED_RESULT"
    else
        echo "✗ Test 3 FAILED: Expected '$TEST_STRING_3', got '$BLOCKED_RESULT'"
        rm -f /tmp/test_multi_blocked.txt
        exit 1
    fi
    rm -f /tmp/test_multi_blocked.txt
else
    echo "✗ Test 3 FAILED: No output captured"
    exit 1
fi

# Give servers time to clean up SSL connections after client termination
echo "Waiting for servers to clean up connections..."
sleep 3

# Restart servers to ensure clean state after blocking read test
echo "Restarting servers for clean state..."
kill $SERVER_PID1 $SERVER_PID2 $SERVER_PID3 2>/dev/null || true
wait $SERVER_PID1 $SERVER_PID2 $SERVER_PID3 2>/dev/null || true
sleep 1

$SERVER_BIN -b $TEST_IP -p $PORT1 &
SERVER_PID1=$!
$SERVER_BIN -b $TEST_IP -p $PORT2 &
SERVER_PID2=$!
$SERVER_BIN -b $TEST_IP -p $PORT3 &
SERVER_PID3=$!
sleep 2
echo "Servers restarted: PID1=$SERVER_PID1, PID2=$SERVER_PID2, PID3=$SERVER_PID3"

# Test 4: Port list with single port (backward compatibility)
echo ""
echo "Test 4: Single port in comma format (backward compatibility)"

# Check server status
echo "Checking server status..."
for pid in $SERVER_PID1 $SERVER_PID2 $SERVER_PID3; do
    if kill -0 $pid 2>/dev/null; then
        echo "  PID $pid is running"
    else
        echo "  PID $pid is NOT running"
    fi
done

# Check if ports are listening
echo "Checking listening ports..."
ss -tlnp 2>/dev/null | grep -E ":(15457|15458|15459)" || echo "No servers listening on test ports"

# Verify servers are still running, restart if needed
if ! kill -0 $SERVER_PID1 2>/dev/null; then
    echo "⚠ Server 1 stopped, restarting..."
    $SERVER_BIN -b $TEST_IP -p $PORT1 &
    SERVER_PID1=$!
    sleep 2
fi
if ! kill -0 $SERVER_PID2 2>/dev/null; then
    echo "⚠ Server 2 stopped, restarting..."
    $SERVER_BIN -b $TEST_IP -p $PORT2 &
    SERVER_PID2=$!
    sleep 2
fi
if ! kill -0 $SERVER_PID3 2>/dev/null; then
    echo "⚠ Server 3 stopped, restarting..."
    $SERVER_BIN -b $TEST_IP -p $PORT3 &
    SERVER_PID3=$!
    sleep 2
fi

TEST_STRING_4="single port test"

echo "Attempting write to PORT1 ($PORT1)..."
if echo "$TEST_STRING_4" | $CLIENT_BIN -s $TEST_IP -p "$PORT1" write 2>&1; then
    echo "✓ Write succeeded"
else
    WRITE_EXIT=$?
    echo "✗ Write failed with exit code: $WRITE_EXIT"
    exit 1
fi
sleep 2  # Give server more time to process the write

# Check if server is still running after write
echo "Checking server status after write..."
if kill -0 $SERVER_PID1 2>/dev/null; then
    echo "  Server 1 still running"
else
    echo "  ✗ Server 1 CRASHED after write!"
    exit 1
fi

echo "Attempting read from PORT1 ($PORT1)..."
set +e  # Temporarily disable exit on error to capture exit code
SINGLE_RESULT=$($CLIENT_BIN -s $TEST_IP -p "$PORT1" read 2>&1)
READ_EXIT=$?
set -e  # Re-enable exit on error

if [ $READ_EXIT -ne 0 ]; then
    echo "✗ Read failed with exit code: $READ_EXIT"
    echo "Read output: $SINGLE_RESULT"
    exit 1
fi

if [ "$SINGLE_RESULT" = "$TEST_STRING_4" ]; then
    echo "✓ Test 4 PASSED: Single port works as before"
else
    echo "✗ Test 4 FAILED: Expected '$TEST_STRING_4', got '$SINGLE_RESULT'"
    exit 1
fi

# Test 5: Write to subset of ports
echo ""
echo "Test 5: Write to subset of ports"
TEST_STRING_5="subset test"

echo "$TEST_STRING_5" | $CLIENT_BIN -s $TEST_IP -p "$PORT1,$PORT3" write
sleep 1

SUBSET_RESULT1=$($CLIENT_BIN -s $TEST_IP -p $PORT1 read)
SUBSET_RESULT3=$($CLIENT_BIN -s $TEST_IP -p $PORT3 read)

if [ "$SUBSET_RESULT1" = "$TEST_STRING_5" ] && [ "$SUBSET_RESULT3" = "$TEST_STRING_5" ]; then
    echo "✓ Test 5 PASSED: Write to subset succeeded"
    echo "  Port $PORT1: $SUBSET_RESULT1"
    echo "  Port $PORT3: $SUBSET_RESULT3"
else
    echo "✗ Test 5 FAILED: Subset write failed"
    exit 1
fi

echo ""
echo "=========================================="
echo "All multi-port tests completed successfully!"
echo "=========================================="
exit 0
