# CLI Usage

## tty-cb-client

```bash
Usage: tty-cb-client [OPTIONS] <read|write[|write_read]> <server_ip>

A secure clipboard client for TTY environments.

Commands:
  read             Read clipboard content from server
  write            Write stdin content to server clipboard

Options:
  -s, --sync       Use synchronous/blocking read mode
  -h, --help       Display this help message
  -v, --version    Display version information
  --protobuf       Use protobuf-c bidirectional protocol (enables write_read)

Examples:
  tty-cb-client write 192.168.1.100          # Write stdin to clipboard
  tty-cb-client read 192.168.1.100           # Read clipboard to stdout
  tty-cb-client read 192.168.1.100 --sync    # Read with sync mode
  tty-cb-client --protobuf write_read 192.168.1.100 < data.bin  # Write then read back over one connection
```

## tty-cb-server

```bash
Usage: tty-cb-server [OPTIONS]

A secure clipboard server for TTY environments.

Options:
  -h, --help                     Display this help message
  -v, --version                  Display version information
  -d, --daemon                   Run in daemon mode (background)
  -m, --max-size N[K|M|G]        Set maximum clipboard size (0=unlimited)
  -p, --oversize-policy MODE     Action when write exceeds max-size:
                                 reject (close connection, client fails)
                                 drop   (discard payload, client succeeds)
  --protobuf                     Enable protobuf-c bidirectional protocol mode

Port:
  5457                          Single port for all operations

Protocol:
  Client connects, sends one command string (read, write, read_blocked) then
  transmits or receives an 8-byte big-endian length prefix + raw payload.

Oversize Handling:
  max-size limits stored clipboard expansion. If exceeded:
    reject: server issues TLS shutdown early; client write fails.
    drop: server streams/discards payload without storing; clipboard unchanged.

Write Acknowledgement:
  After a write payload is sent, server returns 1 status byte:
    0 = success, clipboard updated
    1 = failure (oversize rejection or internal error)
  Clients exit non-zero on failure.

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
