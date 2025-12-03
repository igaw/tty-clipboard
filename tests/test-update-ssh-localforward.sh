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

