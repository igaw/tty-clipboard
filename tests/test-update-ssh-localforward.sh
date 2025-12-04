#!/usr/bin/env bash
set -euo pipefail

# Usage: test_update_ssh_localforward.sh <build_dir> <update_script>
if [ $# -ne 2 ]; then
    echo "Usage: $0 <build_dir> <update_script>"
    exit 1
fi

BUILD_DIR="$1"
SCRIPT="$2"

if [ ! -f "$SCRIPT" ]; then
    echo "Error: script '$SCRIPT' does not exist"
    exit 1
fi

mkdir -p "$BUILD_DIR"

# Paths inside build dir
TEST_CONFIG="$BUILD_DIR/test_ssh_config"
KNOWN_GOOD="$BUILD_DIR/known_good_ssh_config"

test_passed=0
test_failed=0

# Test 1: Add LocalForward to existing host without LocalForward
echo "=== Test 1: Add LocalForward to existing host ==="
cat > "$TEST_CONFIG" <<'EOF'
Host foo.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet

Host lucisinferno
    HostName lucisinferno.dreamland.dk

Host bar.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet
EOF

cat > "$KNOWN_GOOD" <<'EOF'
Host foo.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet

Host lucisinferno
    HostName lucisinferno.dreamland.dk
    LocalForward 127.0.0.1:5457 127.0.0.1:5457
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m

Host bar.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet
EOF

python3 "$SCRIPT" lucisinferno "127.0.0.1:5457 127.0.0.1:5457" --config "$TEST_CONFIG"

if diff -u "$KNOWN_GOOD" "$TEST_CONFIG"; then
    echo "✓ Test 1 passed"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 1 failed"
    test_failed=$((test_failed + 1))
fi

# Test 2: Update existing LocalForward entry
echo ""
echo "=== Test 2: Update existing LocalForward entry ==="
cat > "$TEST_CONFIG" <<'EOF'
Host foo.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet

Host lucisinferno
    HostName lucisinferno.dreamland.dk
    LocalForward 127.0.0.1:9999 127.0.0.1:9999

Host bar.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet
EOF

cat > "$KNOWN_GOOD" <<'EOF'
Host foo.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet

Host lucisinferno
    HostName lucisinferno.dreamland.dk
    LocalForward 127.0.0.1:5457 127.0.0.1:5457
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m

Host bar.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet
EOF

python3 "$SCRIPT" lucisinferno "127.0.0.1:5457 127.0.0.1:5457" --config "$TEST_CONFIG"

if diff -u "$KNOWN_GOOD" "$TEST_CONFIG"; then
    echo "✓ Test 2 passed"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 2 failed"
    test_failed=$((test_failed + 1))
fi

# Test 3: Create new host entry when hostname doesn't exist
echo ""
echo "=== Test 3: Create new host entry when hostname doesn't exist ==="
cat > "$TEST_CONFIG" <<'EOF'
Host foo.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet

Host bar.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet
EOF

cat > "$KNOWN_GOOD" <<'EOF'
Host foo.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet

Host bar.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet

Host newhost
    LocalForward 127.0.0.1:5457 127.0.0.1:5457
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m
EOF

python3 "$SCRIPT" newhost "127.0.0.1:5457 127.0.0.1:5457" --config "$TEST_CONFIG"

if diff -u "$KNOWN_GOOD" "$TEST_CONFIG"; then
    echo "✓ Test 3 passed"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 3 failed"
    test_failed=$((test_failed + 1))
fi

# Test 4: Detect port for host with existing LocalForward
echo ""
echo "=== Test 4: Detect port for host with existing LocalForward ==="
cat > "$TEST_CONFIG" <<'EOF'
Host server1
    HostName server1.example.com
    LocalForward 127.0.0.1:5457 127.0.0.1:5457

Host server2
    HostName server2.example.com
    LocalForward 127.0.0.1:5458 127.0.0.1:5457

Host server3
    HostName server3.example.com
EOF

RESULT=$(python3 "$SCRIPT" server2 --detect-port --config "$TEST_CONFIG")
if [ "$RESULT" = "server2:5458" ]; then
    echo "✓ Test 4 passed (detected existing port)"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 4 failed (expected 'server2:5458', got '$RESULT')"
    test_failed=$((test_failed + 1))
fi

# Test 5: Detect next available port for new host
echo ""
echo "=== Test 5: Detect next available port for new host ==="
# server3 has no LocalForward, so should get next available port (5459)
RESULT=$(python3 "$SCRIPT" server3 --detect-port --config "$TEST_CONFIG")
if [ "$RESULT" = "server3:5459" ]; then
    echo "✓ Test 5 passed (detected next available port)"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 5 failed (expected 'server3:5459', got '$RESULT')"
    test_failed=$((test_failed + 1))
fi

# Test 6: Detect port for completely new host with no config
echo ""
echo "=== Test 6: Detect port for new host when config is empty ==="
cat > "$TEST_CONFIG" <<'EOF'
EOF

RESULT=$(python3 "$SCRIPT" newserver --detect-port --config "$TEST_CONFIG")
if [ "$RESULT" = "newserver:5457" ]; then
    echo "✓ Test 6 passed (detected default port)"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 6 failed (expected 'newserver:5457', got '$RESULT')"
    test_failed=$((test_failed + 1))
fi

# Test 7: Detect port skips gaps in port sequence
echo ""
echo "=== Test 7: Detect port with gaps in sequence ==="
cat > "$TEST_CONFIG" <<'EOF'
Host server1
    LocalForward 127.0.0.1:5457 127.0.0.1:5457

Host server2
    LocalForward 127.0.0.1:5459 127.0.0.1:5457

Host server3
    HostName server3.example.com
EOF

# Should detect 5458 (the gap between 5457 and 5459)
RESULT=$(python3 "$SCRIPT" server3 --detect-port --config "$TEST_CONFIG")
if [ "$RESULT" = "server3:5458" ]; then
    echo "✓ Test 7 passed (detected port filling gap)"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 7 failed (expected 'server3:5458', got '$RESULT')"
    test_failed=$((test_failed + 1))
fi

# Test 11: List all ports across hosts
echo ""
echo "=== Test 11: List all ports across hosts ==="
cat > "$TEST_CONFIG" <<'EOF'
Host a
    LocalForward 127.0.0.1:5459 127.0.0.1:5457

Host b
    LocalForward 127.0.0.1:5457 127.0.0.1:5457

Host c
    LocalForward 127.0.0.1:5458 127.0.0.1:5457

Host d
    HostName d.example.com
EOF

PORT_LIST=$(python3 "$SCRIPT" ignored --list-all-ports --config "$TEST_CONFIG")
if [ "$PORT_LIST" = "5457,5458,5459" ]; then
    echo "✓ Test 11 passed (sorted, de-duplicated list)"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 11 failed (expected '5457,5458,5459', got '$PORT_LIST')"
    test_failed=$((test_failed + 1))
fi

# Test 12: List all ports on empty config
echo ""
echo "=== Test 12: List all ports on empty config ==="
cat > "$TEST_CONFIG" <<'EOF'
EOF

PORT_LIST=$(python3 "$SCRIPT" ignored --list-all-ports --config "$TEST_CONFIG")
if [ -z "$PORT_LIST" ]; then
    echo "✓ Test 12 passed (empty list on empty config)"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 12 failed (expected empty, got '$PORT_LIST')"
    test_failed=$((test_failed + 1))
fi

# Test 8: Configure multiple hosts (one LocalForward per host)
echo ""
echo "=== Test 8: Configure multiple hosts (one LocalForward per host) ==="
cat > "$TEST_CONFIG" <<'EOF'
Host server1
    HostName server1.example.com

Host server2
    HostName server2.example.com

Host server3
    HostName server3.example.com
EOF

cat > "$KNOWN_GOOD" <<'EOF'
Host server1
    HostName server1.example.com
    LocalForward 127.0.0.1:5457 127.0.0.1:5457
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m

Host server2
    HostName server2.example.com
    LocalForward 127.0.0.1:5458 127.0.0.1:5457
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m

Host server3
    HostName server3.example.com
    LocalForward 127.0.0.1:5459 127.0.0.1:5457
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m
EOF

python3 "$SCRIPT" server1 "127.0.0.1:5457 127.0.0.1:5457" --config "$TEST_CONFIG"
python3 "$SCRIPT" server2 "127.0.0.1:5458 127.0.0.1:5457" --config "$TEST_CONFIG"
python3 "$SCRIPT" server3 "127.0.0.1:5459 127.0.0.1:5457" --config "$TEST_CONFIG"

if diff -u "$KNOWN_GOOD" "$TEST_CONFIG"; then
    echo "✓ Test 8 passed"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 8 failed"
    test_failed=$((test_failed + 1))
fi

# Test 9: Replace multiple LocalForward lines with a single one
echo ""
echo "=== Test 9: Replace multiple LocalForward lines with single ==="
cat > "$TEST_CONFIG" <<'EOF'
Host multi
    HostName multi.example.com
    LocalForward 127.0.0.1:6000 127.0.0.1:6000
    LocalForward 127.0.0.1:6001 127.0.0.1:6001
EOF

cat > "$KNOWN_GOOD" <<'EOF'
Host multi
    HostName multi.example.com
    LocalForward 127.0.0.1:5457 127.0.0.1:5457
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m
EOF

python3 "$SCRIPT" multi "127.0.0.1:5457 127.0.0.1:5457" --config "$TEST_CONFIG"

if diff -u "$KNOWN_GOOD" "$TEST_CONFIG"; then
    echo "✓ Test 9 passed"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 9 failed"
    test_failed=$((test_failed + 1))
fi

# Test 10: Reject pipe-separated multi-forward value
echo ""
echo "=== Test 10: Reject multi-forward value ==="
cat > "$TEST_CONFIG" <<'EOF'
Host single
    HostName single.example.com
EOF

python3 "$SCRIPT" single "127.0.0.1:5457 127.0.0.1:5457|127.0.0.1:5458 127.0.0.1:5458" --config "$TEST_CONFIG" && STATUS=$? || STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "✓ Test 10 passed (multi-forward rejected)"
    test_passed=$((test_passed + 1))
else
    echo "✗ Test 10 failed (multi-forward accepted, should reject)"
    test_failed=$((test_failed + 1))
fi

# Summary
echo ""
echo "==================================="
echo "Test Results: $test_passed passed, $test_failed failed"
echo "==================================="

if [ $test_failed -eq 0 ]; then
    exit 0
else
    exit 1
fi

