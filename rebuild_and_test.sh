#!/bin/bash
set -e

echo "=== Rebuilding..."
cd /workspaces/tty-clipboard
meson compile -C .build --force-rebuild-all 2>&1 | tail -20

echo ""
echo "=== Checking binary timestamp..."
stat .build/src/tty-cb-bridge | grep Modify

echo ""
echo "=== Running test..."
meson test -C .build bridge-mock 2>&1 | tail -50

echo ""
echo "=== Test complete ==="
