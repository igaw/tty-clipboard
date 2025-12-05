#!/bin/bash

# Test script to build the C clipboard bridges

set -e

cd "$(dirname "$0")"

echo "Building tty-clipboard with C bridges..."
echo "=========================================="

# Build with meson
meson compile -C builddir

echo ""
echo "Build completed successfully!"
echo ""
echo "Generated executables:"
ls -lh builddir/src/tty-cb-*-bridge 2>/dev/null || echo "  (executables will be created after build)"

echo ""
echo "To test the Wayland bridge:"
echo "  builddir/src/tty-cb-wayland-bridge --help"
echo "  builddir/src/tty-cb-wayland-bridge -d --plugin wayland --server localhost"

echo ""
echo "To test the Klipper bridge:"
echo "  builddir/src/tty-cb-klipper-bridge --help"
echo "  builddir/src/tty-cb-klipper-bridge -d --plugin klipper --server localhost"
