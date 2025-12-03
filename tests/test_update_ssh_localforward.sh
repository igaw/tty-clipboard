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

# Cleanup previous test files
rm -f "$TEST_CONFIG" "$KNOWN_GOOD"

# Step 1: create dummy SSH config
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

# Step 2: create expected known-good config after update
cat > "$KNOWN_GOOD" <<'EOF'
Host foo.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet

Host lucisinferno
    HostName lucisinferno.dreamland.dk
    LocalForward 127.0.0.1:5457 127.0.0.1:5457

Host bar.name.com
    IdentityFile ~/.ssh/id_ed25519
    AddressFamily inet
EOF

# Step 3: run the update script
python3 "$SCRIPT" lucisinferno "127.0.0.1:5457 127.0.0.1:5457" --config "$TEST_CONFIG"

# Step 4: compare result
if diff -u "$KNOWN_GOOD" "$TEST_CONFIG"; then
    echo "Test passed: LocalForward correctly added/updated"
    exit 0
else
    echo "Test failed: Config does not match expected"
    exit 1
fi

