#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only

# Test the clipboard bridge with mock plugin
# Simple test to verify bridge can start and handle basic operations

set -e

SERVER_BIN="$1"
CLIENT_BIN="$2"
BRIDGE_BIN="$3"
TEST_CONFIG_DIR="$4"

if [[ -z "$SERVER_BIN" || -z "$CLIENT_BIN" || -z "$BRIDGE_BIN" || -z "$TEST_CONFIG_DIR" ]]; then
    echo "Usage: $0 <server_bin> <client_bin> <bridge_bin> <test_config_dir>"
    exit 1
fi

# Export XDG_CONFIG_HOME for the test
export XDG_CONFIG_HOME="$TEST_CONFIG_DIR"

# Enable TLS debug output if MBEDTLS_DEBUG is set
if [[ -n "$MBEDTLS_DEBUG" ]]; then
    echo "TLS debugging enabled"
fi

# Test configuration - use separate IPs for local and remote servers
LOCAL_SERVER_IP="127.0.0.2"
REMOTE_SERVER_IP="127.0.0.3"
LOCAL_SERVER_PORT=9457
REMOTE_SERVER_PORT=9458
TEST_TMP_DIR="$TEST_CONFIG_DIR/test-logs"
mkdir -p "$TEST_TMP_DIR"

cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
    sleep 0.5
}
trap cleanup EXIT

echo "Test: Bridge with mock plugin"
echo ""

# Prepare TLS debug log arguments if MBEDTLS_DEBUG is set
REMOTE_TLS_ARGS=()
LOCAL_TLS_ARGS=()
BRIDGE_TLS_ARGS=()
if [[ -n "$MBEDTLS_DEBUG" ]]; then
    REMOTE_TLS_ARGS=(--tls-debug-log "$TEST_TMP_DIR/remote_server_tls.log")
    LOCAL_TLS_ARGS=(--tls-debug-log "$TEST_TMP_DIR/local_server_tls.log")
    BRIDGE_TLS_ARGS=(--tls-debug-log "$TEST_TMP_DIR/bridge_tls.log")
fi

# Start remote server on 127.0.0.3
"$SERVER_BIN" -v -b "$REMOTE_SERVER_IP" -p "$REMOTE_SERVER_PORT" "${REMOTE_TLS_ARGS[@]}" \
    > "$TEST_TMP_DIR/remote_server.log" 2>&1 &
REMOTE_PID=$!
sleep 1

# Start local server on 127.0.0.2
"$SERVER_BIN" -v -b "$LOCAL_SERVER_IP" -p "$LOCAL_SERVER_PORT" "${LOCAL_TLS_ARGS[@]}" \
    > "$TEST_TMP_DIR/local_server.log" 2>&1 &
LOCAL_PID=$!
sleep 1


# Start bridge with mock plugin
# Bridge connects from local (127.0.0.2) to remote (127.0.0.3)
"$BRIDGE_BIN" -v --plugin mock --server "$LOCAL_SERVER_IP:$LOCAL_SERVER_PORT,$REMOTE_SERVER_IP:$REMOTE_SERVER_PORT" \
    "${BRIDGE_TLS_ARGS[@]}" > "$TEST_TMP_DIR/bridge.log" 2>&1 &
BRIDGE_PID=$!

# Wait for bridge to connect (retry up to 10 seconds)
RETRY=0
MAX_RETRY=10
while (( RETRY < MAX_RETRY )); do
    sleep 1
    if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
        echo "FAILED: Bridge failed to start"
        cat "$TEST_TMP_DIR/bridge.log"
        exit 1
    fi
    # Check for connection errors
    if grep -q "Failed to connect\|Failed to initialize" "$TEST_TMP_DIR/bridge.log"; then
        echo "FAILED: Bridge failed to connect to server"
        echo "Logs are available in: $TEST_TMP_DIR"
        echo "=== Bridge log ==="
        cat "$TEST_TMP_DIR/bridge.log"
        exit 1
    fi
    # Check for successful connection
    if grep -q "Connected to server" "$TEST_TMP_DIR/bridge.log"; then
        echo "PASSED: Bridge started and connected successfully"
        break
    fi
    (( RETRY++ ))
done
if (( RETRY == MAX_RETRY )); then
    echo "FAILED: Bridge did not connect within timeout"
    cat "$TEST_TMP_DIR/bridge.log"
    exit 1
fi

# Check for SSL errors in bridge log (these are fatal)
if grep -q "SSL handshake failed" "$TEST_TMP_DIR/bridge.log"; then
    echo "FAILED: Bridge SSL handshake error"
    echo "Logs are available in: $TEST_TMP_DIR"
    echo "=== Bridge log ==="
    cat "$TEST_TMP_DIR/bridge.log"
    if [[ -n "$MBEDTLS_DEBUG" ]]; then
        echo "=== Remote server log ==="
        cat "$TEST_TMP_DIR/remote_server.log"
        echo "=== Local server log ==="
        cat "$TEST_TMP_DIR/local_server.log"
        echo "=== TLS debug logs ==="
        for logfile in "$TEST_TMP_DIR"/*_tls.log; do
            if [[ -f "$logfile" ]]; then
                echo "--- $logfile ---"
                cat "$logfile"
            fi
        done
    fi
    exit 1
fi

# Test 1: Basic write/read on local server
echo -n "test1" | "$CLIENT_BIN" -s "$LOCAL_SERVER_IP" -p "$LOCAL_SERVER_PORT" write 2>/dev/null
sleep 0.2
RESULT=$("$CLIENT_BIN" -s "$LOCAL_SERVER_IP" -p "$LOCAL_SERVER_PORT" read 2>/dev/null)
if [[ "$RESULT" == "test1" ]]; then
    echo "PASSED: Test 1 - local server write/read"
else
    echo "FAILED: Test 1 - got '$RESULT'"
    exit 1
fi

# Test 2: Write to local server, verify remote server sees it
LOCAL_TO_REMOTE="local_to_remote_test_data"
echo -n "$LOCAL_TO_REMOTE" | "$CLIENT_BIN" -s "$LOCAL_SERVER_IP" -p "$LOCAL_SERVER_PORT" write 2>/dev/null
sleep 0.5  # Give bridge time to sync

REMOTE_RESULT=$("$CLIENT_BIN" -s "$REMOTE_SERVER_IP" -p "$REMOTE_SERVER_PORT" read 2>/dev/null)
if [[ "$REMOTE_RESULT" == "$LOCAL_TO_REMOTE" ]]; then
    echo "PASSED: Test 2 - local write visible on remote"
else
    echo "FAILED: Test 2 - remote server got '$REMOTE_RESULT', expected '$LOCAL_TO_REMOTE'"
    exit 1
fi

# Test 3: Write to remote server, verify local server sees it
REMOTE_TO_LOCAL="remote_to_local_test_data"
echo -n "$REMOTE_TO_LOCAL" | "$CLIENT_BIN" -s "$REMOTE_SERVER_IP" -p "$REMOTE_SERVER_PORT" write 2>/dev/null
sleep 0.5  # Give bridge time to sync

LOCAL_RESULT=$("$CLIENT_BIN" -s "$LOCAL_SERVER_IP" -p "$LOCAL_SERVER_PORT" read 2>/dev/null)
if [[ "$LOCAL_RESULT" == "$REMOTE_TO_LOCAL" ]]; then
    echo "PASSED: Test 3 - remote write visible on local"
else
    echo "FAILED: Test 3 - local server got '$LOCAL_RESULT', expected '$REMOTE_TO_LOCAL'"
    exit 1
fi

# Test 4: Signal to trigger mock plugin (local clipboard change)
kill -USR1 "$BRIDGE_PID" 2>/dev/null || true
sleep 0.5

# The mock plugin's local change should propagate to remote server
MOCK_RESULT=$("$CLIENT_BIN" -s "$REMOTE_SERVER_IP" -p "$REMOTE_SERVER_PORT" read 2>/dev/null)
if [[ "$MOCK_RESULT" == local_clipboard_change_* ]]; then
    echo "PASSED: Test 4 - mock plugin local change propagated to remote"
else
    echo "FAILED: Test 4 - remote server got '$MOCK_RESULT', expected 'local_clipboard_change_*'"
    exit 1
fi

# Check bridge is still running
if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo "FAILED: Bridge crashed after SIGUSR1 test"
    exit 1
fi

# Test 5: Binary data (avoid null bytes as they corrupt shell variable expansion)
# Use a different binary sequence that doesn't include null bytes
BINARY=$(printf '\x01\x02\x03\xFF\xFE\xFD')
echo -n "$BINARY" | "$CLIENT_BIN" -s "$LOCAL_SERVER_IP" -p "$LOCAL_SERVER_PORT" write 2>/dev/null
sleep 0.5

# Verify bridge is still running after binary test
if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo "FAILED: Test 5 - Bridge crashed during binary data test"
    cat "$TEST_TMP_DIR/bridge.log"
    exit 1
fi

# Read back from local server
"$CLIENT_BIN" -s "$LOCAL_SERVER_IP" -p "$LOCAL_SERVER_PORT" read 2>/dev/null > "$TEST_TMP_DIR/binary_result_local.bin"
LOCAL_BINARY_SIZE=$(stat -f%z "$TEST_TMP_DIR/binary_result_local.bin" 2>/dev/null || stat -c%s "$TEST_TMP_DIR/binary_result_local.bin" 2>/dev/null || echo 0)
BINARY_SIZE=${#BINARY}

if [[ "$LOCAL_BINARY_SIZE" -eq "$BINARY_SIZE" ]]; then
    echo "PASSED: Test 5a - binary data on local server ($LOCAL_BINARY_SIZE bytes)"
else
    echo "FAILED: Test 5a - binary data size mismatch on local (expected $BINARY_SIZE, got $LOCAL_BINARY_SIZE)"
    exit 1
fi

# Verify binary data also synced to remote server
"$CLIENT_BIN" -s "$REMOTE_SERVER_IP" -p "$REMOTE_SERVER_PORT" read 2>/dev/null > "$TEST_TMP_DIR/binary_result_remote.bin"
REMOTE_BINARY_SIZE=$(stat -f%z "$TEST_TMP_DIR/binary_result_remote.bin" 2>/dev/null || stat -c%s "$TEST_TMP_DIR/binary_result_remote.bin" 2>/dev/null || echo 0)

if [[ "$REMOTE_BINARY_SIZE" -eq "$BINARY_SIZE" ]]; then
    echo "PASSED: Test 5b - binary data synced to remote server ($REMOTE_BINARY_SIZE bytes)"
else
    echo "FAILED: Test 5b - binary data size mismatch on remote (expected $BINARY_SIZE, got $REMOTE_BINARY_SIZE)"
    exit 1
fi

# Final check: verify bridge is still running
if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo "FAILED: Bridge crashed after tests"
    cat "$TEST_TMP_DIR/bridge.log"
    exit 1
fi

echo ""
echo "All tests passed"
exit 0
