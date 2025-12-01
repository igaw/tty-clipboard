# TTY Clipboard Tests

## Overview

This directory contains integration tests for the tty-clipboard project.

## Test Structure

- `setup-test-certs.sh` - Creates test SSL certificates in a temporary directory
- `test-basic.sh` - Main test script that performs integration testing
- `meson.build` - Meson configuration for running tests

## Running Tests

### With Meson

```bash
# Setup build directory (first time)
meson setup builddir

# Run all tests
meson test -C builddir

# Run with verbose output
meson test -C builddir --verbose

# Run specific test
meson test -C builddir basic-clipboard-test
```

### Manual Testing

You can also run the test script directly (after building):

```bash
# Build the project first
meson compile -C builddir

# Run the test script
./tests/test-basic.sh builddir/tty-cb-server builddir/tty-cb-client builddir/tests/test-config
```

## Test Cases

### Test 1: Basic Write and Read
- Starts the server
- Writes a test string to the clipboard via the client
- Reads it back and verifies the content matches

### Test 2: Multiple Writes
- Writes a second string to the clipboard
- Verifies that the new content overwrites the old content

### Test 3: Sync Mode (Blocking Read)
- Tests the synchronous/blocking read functionality
- Verifies that a blocking read receives updates when new content is written

## Test Certificates

Tests use automatically generated SSL certificates with simple passwords (not keyring-based) stored in the build directory under `tests/test-config/tty-clipboard/`.

These certificates are:
- Self-signed for testing purposes only
- Generated fresh for each test run
- Not suitable for production use
