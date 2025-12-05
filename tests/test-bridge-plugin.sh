#!/bin/bash
# Simplified test: verify bridge can send data to server via local clipboard changes

SERVER_BIN="$1"
CLIENT_BIN="$2"
BRIDGE_BIN="$3"
TEST_CONFIG_DIR="$4"

if [[ -z "$SERVER_BIN" || -z "$CLIENT_BIN" || -z "$BRIDGE_BIN" || -z "$TEST_CONFIG_DIR" ]]; then
    echo "Usage: $0 <server_bin> <client_bin> <bridge_bin> <test_config_dir>"
    exit 1
fi

export XDG_CONFIG_HOME="$TEST_CONFIG_DIR"
TEST_TMP_DIR="$TEST_CONFIG_DIR/test-logs-plugin"
mkdir -p "$TEST_TMP_DIR"

cleanup() {
    jobs -p | xargs -r kill 2>/dev/null || true
    sleep 0.5
}
trap cleanup EXIT

echo "Test: Bridge Plugin Communication"
echo ""

# Start single server
"$SERVER_BIN" -b 127.0.0.1 -p 8888 \
    > "$TEST_TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!
sleep 1

# Start bridge with mock plugin
"$BRIDGE_BIN" --plugin mock --server 127.0.0.1:8888 -v -d \
    > "$TEST_TMP_DIR/bridge.log" 2>&1 &
BRIDGE_PID=$!
sleep 3

# Verify bridge started
if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo "FAILED: Bridge failed to start"
    cat "$TEST_TMP_DIR/bridge.log"
    exit 1
fi
echo "PASSED: Bridge started successfully"

# Check for connection errors in bridge log
if grep -q "Failed to connect\|Failed to initialize" "$TEST_TMP_DIR/bridge.log"; then
    echo "FAILED: Bridge failed to connect to server"
    echo "=== Bridge log ==="
    cat "$TEST_TMP_DIR/bridge.log"
    exit 1
fi

# Test 1: Trigger mock plugin via SIGUSR1 to generate local change
echo "Triggering mock plugin via SIGUSR1 to send data to server..."
kill -USR1 "$BRIDGE_PID" 2>/dev/null || true
sleep 1

# Verify bridge is still running
if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then
    echo "FAILED: Bridge crashed after SIGUSR1"
    cat "$TEST_TMP_DIR/bridge.log"
    exit 1
fi
echo "PASSED: Bridge still running after SIGUSR1"

# Read from server to see if mock plugin change was forwarded
RESULT=$("$CLIENT_BIN" -s 127.0.0.1 -p 8888 read 2>/dev/null)
if [[ "$RESULT" == local_clipboard_change_* ]]; then
    echo "PASSED: Mock plugin change received by server"
    echo "  Received: '$RESULT'"
else
    echo "FAILED: Expected local_clipboard_change_*, got '$RESULT'"
    echo "Bridge log:"
    cat "$TEST_TMP_DIR/bridge.log"
    exit 1
fi

echo ""
echo "All tests passed"
exit 0
