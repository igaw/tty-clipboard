# CLI Usage

## tty-cb-client

```bash
Usage: tty-cb-client [OPTIONS] <command>

A secure clipboard client for TTY environments.

Commands:
  read             Read clipboard content from server
  write            Write stdin content to server clipboard
  read_blocked     Subscribe to clipboard updates (blocking)

Options:
  -h, --help       Display this help message
  -V, --version    Display version information
  -v, --verbose    Enable verbose logging (repeat for more detail)
  -s, --server IP  Server IP address (default: 127.0.0.1)
  -p, --port PORTS Server port(s), comma-separated (default: 5457)

Examples:
  tty-cb-client write 192.168.1.100          # Write stdin to clipboard
  tty-cb-client read 192.168.1.100           # Read clipboard to stdout
  tty-cb-client read_blocked 192.168.1.100   # Monitor clipboard for updates
  tty-cb-client -p 5457,5458 write 192.168.1.100  # Write to multiple ports
```

## tty-cb-server

```bash
Usage: tty-cb-server [OPTIONS]

A secure clipboard server for TTY environments.

Options:
  -h, --help                     Display this help message
  -V, --version                  Display version information
  -v, --verbose                  Enable verbose logging
  -b, --bind IP                  Bind to specific IP address (default: 127.0.0.1)
  -p, --port PORT                Listen on port (default: 5457)
  -m, --max-size N[K|M|G]        Set maximum clipboard size (0=unlimited)
  -R, --oversize-policy MODE     Action when write exceeds max-size:
                                 reject (close connection, client fails)
                                 drop   (discard payload, client succeeds)

Port:
  5457 (default)                Single port for all operations

Client Roles:
  - write: Write stdin to clipboard, exit
  - read: Read clipboard to stdout once, exit
  - read_blocked: Subscribe to clipboard updates (blocking)

Authentication:
  Client authentication is required via mutual TLS.

The server listens on the specified address and port, supports multiple concurrent clients,
and maintains clipboard state with optional size limits.
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

## Wayland Desktop Integration

For bidirectional clipboard sync between Wayland desktop environments (GNOME, KDE, Sway, etc.) and tty-clipboard:

```bash
# Start the bridge (syncs clipboard changes in both directions)
./scripts/wayland-bridge.sh

# Connect to remote server
./scripts/wayland-bridge.sh 192.168.1.100

# Monitor multiple remote servers simultaneously
./scripts/wayland-bridge.sh localhost 5457,5458,5459

# Stop the bridge
./scripts/wayland-bridge.sh --stop
```

The bridge runs two background processes:
- **Wayland → TTY**: Watches Wayland clipboard with `wl-paste -w`, writes changes to tty-clipboard
- **TTY → Wayland**: Watches tty-clipboard with `read_blocked`, writes changes to Wayland clipboard

**Multi-port support:**
When multiple ports are specified (comma-separated), the bridge:
- Monitors all ports for clipboard updates from any remote server
- Writes to all ports when the Wayland clipboard changes
- Enables seamless clipboard sync across multiple remote hosts

**Requirements:**
- `wl-clipboard` package (provides `wl-copy` and `wl-paste` commands)
- `tty-cb-client` installed

**Use cases:**
- Copy from Firefox/Chrome → automatically available in terminal applications
- Copy in tmux/vim → automatically available in GUI applications  
- Seamless clipboard sync between desktop and multiple remote servers via tty-clipboard

**Running as a systemd service:**

The bridge is designed to run as a systemd user service for automatic startup:

```bash
# Install the script to user's local bin
cp scripts/wayland-bridge.sh ~/.local/bin/
chmod +x ~/.local/bin/wayland-bridge.sh

# Create systemd user service
mkdir -p ~/.config/systemd/user

cat > ~/.config/systemd/user/tty-clipboard-bridge.service << 'EOF'
[Unit]
Description=Wayland Clipboard Bridge for tty-clipboard
Documentation=https://github.com/igaw/tty-clipboard
After=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/wayland-bridge.sh localhost 5457,5458,5459
ExecStop=%h/.local/bin/wayland-bridge.sh --stop
Restart=on-failure
RestartSec=5
Environment="WAYLAND_DISPLAY=wayland-0"

[Install]
WantedBy=default.target
EOF

# Enable and start the service
systemctl --user daemon-reload
systemctl --user enable --now tty-clipboard-bridge.service

# Check status
systemctl --user status tty-clipboard-bridge.service
```

**Note:** Update the ExecStart line with your specific ports (e.g., `5457,5458,5459`
for three remote servers).
systemctl --user status tty-clipboard-bridge.service
```

**Auto-populating bridge ports from SSH config:**

If you've configured multiple hosts with one LocalForward each, you can auto-populate
the bridge's port list from your `~/.ssh/config` using the helper script:

```bash
# List all local ports used in LocalForward entries (sorted, unique)
python3 scripts/update-ssh-localforward.py ignored --list-all-ports --config ~/.ssh/config
# Example output:
# 5457,5458,5459

# Use that output to create the service dynamically
PORTS=$(python3 scripts/update-ssh-localforward.py ignored --list-all-ports --config ~/.ssh/config)
cat > ~/.config/systemd/user/tty-clipboard-bridge.service << EOF
[Unit]
Description=Wayland Clipboard Bridge for tty-clipboard
After=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/wayland-bridge.sh localhost ${PORTS}
ExecStop=%h/.local/bin/wayland-bridge.sh --stop
Restart=on-failure
RestartSec=5
Environment="WAYLAND_DISPLAY=wayland-0"

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now tty-clipboard-bridge.service
```

You can also override the ports explicitly in `setup.sh` with:

```bash
./scripts/setup.sh myserver.example.com -w --bridge-ports 5457,5458,5459
```

**Managing the service:**

```bash
# View logs
journalctl --user -u tty-clipboard-bridge.service -f

# Stop the service
systemctl --user stop tty-clipboard-bridge.service

# Restart the service
systemctl --user restart tty-clipboard-bridge.service

# Disable auto-start
systemctl --user disable tty-clipboard-bridge.service
```

