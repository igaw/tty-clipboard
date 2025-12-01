# CLI Usage

## tty-cb-client

```bash
Usage: tty-cb-client [OPTIONS] <read|write> <server_ip>

A secure clipboard client for TTY environments.

Commands:
  read             Read clipboard content from server
  write            Write stdin content to server clipboard

Options:
  -s, --sync       Use synchronous/blocking read mode
  -h, --help       Display this help message
  -v, --version    Display version information

Examples:
  tty-cb-client write 192.168.1.100          # Write stdin to clipboard
  tty-cb-client read 192.168.1.100           # Read clipboard to stdout
  tty-cb-client read 192.168.1.100 --sync    # Read with sync mode
```

## tty-cb-server

```bash
Usage: tty-cb-server [OPTIONS]

A secure clipboard server for TTY environments.

Options:
  -h, --help       Display this help message
  -v, --version    Display version information
  -d, --daemon     Run in daemon mode (background)

Ports:
  5457              Read port (non-blocking)
  5458              Write port
  5459              Read port (blocking/sync)

The server listens on all interfaces (0.0.0.0) by default.
Client authentication is required via mutual TLS.
```

## Quick Start

1. Start the server:
```bash
tty-cb-server
# or in background:
tty-cb-server --daemon
```

2. Write to clipboard:
```bash
echo "Hello World" | tty-cb-client write localhost
```

3. Read from clipboard:
```bash
tty-cb-client read localhost
```

4. Use sync mode for blocking reads:
```bash
# This will wait until new data is written
tty-cb-client read localhost --sync
```
