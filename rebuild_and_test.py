#!/usr/bin/env python3
import subprocess
import sys
import os

os.chdir('/workspaces/tty-clipboard')

# Step 1: Rebuild
print("=" * 50)
print("STEP 1: Rebuilding project")
print("=" * 50)
result = subprocess.run(['meson', 'compile', '-C', '.build'], 
                       capture_output=False)
if result.returncode != 0:
    print("ERROR: Build failed!")
    sys.exit(1)

# Step 2: Check binary
print("\n" + "=" * 50)
print("STEP 2: Checking binary")
print("=" * 50)
result = subprocess.run(['ls', '-lh', '.build/src/tty-cb-bridge'],
                       capture_output=False)

# Step 3: Run test
print("\n" + "=" * 50)
print("STEP 3: Running bridge-mock test")
print("=" * 50)
os.environ['MBEDTLS_DEBUG'] = '1'
result = subprocess.run(['meson', 'test', '-C', '.build', 'bridge-mock'],
                       capture_output=False)

print("\n" + "=" * 50)
print(f"Test result: {'PASSED' if result.returncode == 0 else 'FAILED'}")
print("=" * 50)

sys.exit(result.returncode)
