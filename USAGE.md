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

### Automated Setup

The easiest way to get started is using the setup script:

```bash
# Build the project (dynamic build)
meson setup .build
ninja -C .build

# Set up client locally and server remotely
./scripts/setup.sh <remote-hostname>
```

This will:
- Generate TLS certificates (stored in `~/.config/tty-clipboard/`)
- Install client to `~/.local/bin/tty-cb-client` locally
- Deploy server and client to the remote host
- Create a systemd service on the remote host
- Configure SSH with automatic port forwarding

After setup, simply SSH to your remote host and the clipboard will work automatically!

**Note:** Dynamic builds assume both local and remote hosts have compatible versions of mbedTLS and protobuf-c installed. For maximum portability, use a static build instead.

### Static Build (Portable)

For portable binaries that work across different distributions without requiring runtime dependencies:

```bash
# Build static binaries (all dependencies bundled)
meson setup .build -Dstatic=true --force-fallback-for=mbedtls,libprotobuf-c
ninja -C .build

# Install using the static binaries
./scripts/setup.sh <remote-hostname>
```

Static builds are ideal when:
- Local and remote hosts run different Linux distributions or versions
- Target systems don't have mbedTLS or protobuf-c installed
- You want a single binary that works everywhere

The `--force-fallback-for` option ensures mbedTLS and libprotobuf-c are built from source as subprojects, creating truly portable binaries. Without this flag, the build will use system static libraries if available (which may not be portable).

### Manual Setup

If you prefer manual setup:

1. Generate certificates:
```bash
./scripts/create-certs.sh
```

2. Start the server:
```bash
tty-cb-server
# or in background:
tty-cb-server --daemon
```

3. Configure SSH port forwarding in `~/.ssh/config`:
```
Host myserver
    HostName myserver.example.com
    LocalForward 127.0.0.1:5457 127.0.0.1:5457
    ControlMaster auto
    ControlPath ~/.ssh/sockets/%r@%h:%p
    ControlPersist 10m
```

### Usage Examples

1. Write to clipboard:
```bash
echo "Hello World" | tty-cb-client write localhost
```

2. Read from clipboard:
```bash
tty-cb-client read localhost
```

3. Use sync mode for blocking reads:
```bash
# This will wait until new data is written
tty-cb-client read localhost --sync
```

## tmux Integration

Integrate tty-clipboard with tmux for seamless copy/paste between your local machine and remote sessions.

Add these bindings to your `~/.tmux.conf`:

```tmux
# Copy selection to tty-clipboard
bind-key -T copy-mode-vi y send-keys -X copy-pipe-and-cancel "tty-cb-client write localhost"
bind-key -T copy-mode-vi MouseDragEnd1Pane send-keys -X copy-pipe-and-cancel "tty-cb-client write localhost"

# Paste from tty-clipboard
bind p run-shell 'tty-cb-client read localhost | tmux load-buffer - && tmux paste-buffer'
```

After adding these, reload your tmux config:
```bash
tmux source-file ~/.tmux.conf
```

**Usage:**
- In tmux copy mode (`Prefix + [`), select text and press `y` to copy to tty-clipboard
- Mouse selection also copies to tty-clipboard automatically
- Press `Prefix + p` to paste from tty-clipboard

**Note:** If you already use `Prefix + p` for something else, rebind window navigation first:
```tmux
# Free up p by moving next/previous window to n/m
bind n select-window -t :+
bind m select-window -t :-
```

This allows seamless clipboard sharing between:
- Local terminal → remote tmux session
- Remote tmux session → local terminal
- Multiple remote sessions via the same clipboard server

## tig Integration

Integrate tty-clipboard with [tig](https://jonas.github.io/tig/) (text-mode interface for Git) to quickly copy commit information.

Add these bindings to your `~/.tigrc`:

```
# Copy commit message to clipboard
bind main C @sh -c "git log --format=%B -n 1 %(commit) | tty-cb-client write localhost"

# Copy commit hash to clipboard
bind generic I @sh -c "echo -n %(commit) | tty-cb-client write localhost"

# Copy short hash with subject to clipboard
bind generic O @sh -c "git show -s --pretty='format:%h (\"%s\")' --abbrev=12 %(commit) | tty-cb-client write localhost"
```

**Usage in tig:**
- `Shift+C` - Copy the full commit message of the selected commit
- `Shift+I` - Copy the commit hash (SHA) to clipboard
- `Shift+O` - Copy short hash with subject line (e.g., `abc123456789 ("Fix bug")`)

These bindings work in any tig view where commits are displayed (main, log, diff, etc.).

## Doom Emacs Integration

Integrate tty-clipboard with Doom Emacs to sync the kill-ring (Emacs clipboard) with your system clipboard.

Add this configuration to your `~/.doom.d/config.el`:

```elisp
;; tty-clipboard integration for Doom Emacs
(defun tty-clipboard-copy (text)
  "Copy TEXT to tty-clipboard."
  (let ((process-connection-type nil))
    (let ((proc (start-process "tty-cb-copy" nil
                               "tty-cb-client" "write")))
      (process-send-string proc text)
      (process-send-eof proc))))

(defun tty-clipboard-paste ()
  "Paste from tty-clipboard."
  (with-temp-buffer
    (call-process "tty-cb-client" nil t nil "read")
    (buffer-string)))

;; Hook into Emacs clipboard functions
(setq interprogram-cut-function #'tty-clipboard-copy)
(setq interprogram-paste-function #'tty-clipboard-paste)
```

After adding this configuration, reload your Doom config:
```
SPC h r r  (or M-x doom/reload)
```

**Usage:**
- Copy in Emacs (`y` in evil mode, `M-w` in Emacs mode) → automatically sent to tty-clipboard
- Paste in Emacs (`p` in evil mode, `C-y` in Emacs mode) → pulls from tty-clipboard
- Works bidirectionally with tmux, tig, and other integrated tools

**Note:** This integrates with Emacs' kill-ring, so all standard Emacs copy/paste operations will use tty-clipboard automatically. For Doom Emacs specifically, this works seamlessly with evil-mode yanking and pasting.
