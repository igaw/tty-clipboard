#!/bin/bash
set -e

cd /workspaces/tty-clipboard

echo "=== Starting full rebuild and test ==="
echo ""
echo "Step 1: Compiling..."
meson compile -C .build

echo ""
echo "Step 2: Checking binary timestamps..."
ls -lh .build/src/tty-cb-bridge

echo ""
echo "Step 3: Running bridge-mock test..."
MBEDTLS_DEBUG=1 meson test -C .build bridge-mock

echo ""
echo "=== Test complete ==="
