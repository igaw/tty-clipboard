#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

# Script to set up tty-clipboard: install client locally and server on remote host

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] <hostname> [build_dir]

Set up tty-clipboard by installing the client locally and server on a remote host.

Arguments:
    hostname        SSH hostname or user@hostname of the remote host
    build_dir       Path to the build directory containing the binaries (default: .build)

Options:
    -p, --port PORT Local port for SSH LocalForward (default: auto-detect)
    -h, --help      Show this help message

This script will:
  1. Check if certificates exist locally, generate them if needed
  2. Install client binary to local ~/.local/bin
  3. Copy certificates to the remote host
  4. Copy server and client binaries to remote ~/.local/bin
  5. Create a systemd user service to start the server on login
  6. Update local ~/.ssh/config with LocalForward (if hostname entry exists)

Example:
    $0 myserver.example.com
    $0 myserver.example.com ./builddir
    $0 -p 5458 server2.com          # Use specific local port
    $0 --port 5459 user@server3.com

Note: By default, ports are auto-detected. If a host already has a LocalForward
      configured, that port is reused. Otherwise, the next available port starting
      from 5457 is assigned. Use -p to override and specify a custom port.

EOF
}

# Parse arguments
if [[ $# -lt 1 ]]; then
    echo "Error: Missing required arguments"
    show_usage
    exit 1
fi

LOCAL_PORT=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            LOCAL_PORT="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -*)
            echo "Error: Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

REMOTE_HOST="$1"
BUILD_DIR="${2:-.build}"  # Default to .build if not specified

if [ ! -d "$BUILD_DIR" ]; then
    echo "Error: Build directory '$BUILD_DIR' does not exist"
    exit 1
fi

# Check for binaries
SERVER_BIN="$BUILD_DIR/src/tty-cb-server"
CLIENT_BIN="$BUILD_DIR/src/tty-cb-client"

if [ ! -f "$SERVER_BIN" ]; then
    echo "Error: Server binary not found at $SERVER_BIN"
    exit 1
fi

if [ ! -f "$CLIENT_BIN" ]; then
    echo "Error: Client binary not found at $CLIENT_BIN"
    exit 1
fi

# Local certificate paths
LOCAL_CFG_BASE=${XDG_CONFIG_HOME:-"$HOME/.config"}/tty-clipboard
LOCAL_CERT_DIR="$LOCAL_CFG_BASE/certs"
LOCAL_KEY_DIR="$LOCAL_CFG_BASE/keys"

# Check if certificates exist locally, create if needed
if [ ! -f "$LOCAL_CERT_DIR/ca.crt" ] || [ ! -f "$LOCAL_CERT_DIR/server.crt" ] || \
   [ ! -f "$LOCAL_CERT_DIR/client.crt" ] || [ ! -f "$LOCAL_KEY_DIR/ca.key" ] || \
   [ ! -f "$LOCAL_KEY_DIR/server.key" ] || [ ! -f "$LOCAL_KEY_DIR/client.key" ]; then
    echo "Certificates not found locally. Generating..."
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    "$SCRIPT_DIR/create-certs.sh"
fi

echo "Using local certificates from: $LOCAL_CFG_BASE"

# Install client locally
echo ""
echo "Installing client locally..."
mkdir -p "$HOME/.local/bin"
cp "$CLIENT_BIN" "$HOME/.local/bin/tty-cb-client"
chmod 755 "$HOME/.local/bin/tty-cb-client"
echo "✓ Client installed to ~/.local/bin/tty-cb-client"

# Remote paths (will be expanded on remote host)
REMOTE_BIN_DIR="\$HOME/.local/bin"
REMOTE_CONFIG_DIR="\$HOME/.config"
REMOTE_CERT_DIR="\$HOME/.config/tty-clipboard/certs"
REMOTE_KEY_DIR="\$HOME/.config/tty-clipboard/keys"

echo ""
echo "Installing tty-clipboard server on $REMOTE_HOST..."
echo ""

# Get remote home directory (to avoid ~ expansion issues with scp)
echo "Querying remote home directory..."
REMOTE_HOME=$(ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" 'echo $HOME' 2>/dev/null)
if [ -z "$REMOTE_HOME" ]; then
    echo "Error: Could not determine remote home directory"
    exit 1
fi
echo "Remote home directory: $REMOTE_HOME"

# Create remote directories
echo "Creating remote directories..."
ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "mkdir -p $REMOTE_HOME/.local/bin $REMOTE_HOME/.config/tty-clipboard/certs $REMOTE_HOME/.config/tty-clipboard/keys" 2>/dev/null

# Copy certificates to remote host
echo "Copying certificates to remote host..."
scp -o "ExitOnForwardFailure=no" "$LOCAL_CERT_DIR"/ca.crt "$LOCAL_CERT_DIR"/server.crt "$LOCAL_CERT_DIR"/client.crt \
    "$REMOTE_HOST:$REMOTE_HOME/.config/tty-clipboard/certs/"

scp -o "ExitOnForwardFailure=no" "$LOCAL_KEY_DIR"/ca.key "$LOCAL_KEY_DIR"/server.key "$LOCAL_KEY_DIR"/client.key \
    "$REMOTE_HOST:$REMOTE_HOME/.config/tty-clipboard/keys/"

# Set appropriate permissions on remote files
echo "Setting certificate permissions..."
ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "chmod 644 $REMOTE_HOME/.config/tty-clipboard/certs/*.crt && chmod 600 $REMOTE_HOME/.config/tty-clipboard/keys/*.key" 2>/dev/null

# Stop the service if it exists (so binaries can be updated)
echo "Checking for existing service..."
if ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "systemctl --user is-enabled --quiet tty-clipboard.service" 2>/dev/null; then
    echo "Stopping existing service..."
    ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "systemctl --user stop tty-clipboard.service" 2>/dev/null
fi

# Copy binaries to remote host
echo "Copying binaries to remote host..."
scp -o "ExitOnForwardFailure=no" "$SERVER_BIN" "$CLIENT_BIN" "$REMOTE_HOST:$REMOTE_HOME/.local/bin/"
ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "chmod 755 $REMOTE_HOME/.local/bin/tty-cb-server $REMOTE_HOME/.local/bin/tty-cb-client" 2>/dev/null

# Create systemd user service
echo "Creating systemd user service..."
ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "mkdir -p ~/.config/systemd/user" 2>/dev/null

# Generate the service file content
SERVICE_CONTENT='[Unit]
Description=TTY Clipboard Server
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/tty-cb-server
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
'

# Write service file to remote host
ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "cat > ~/.config/systemd/user/tty-clipboard.service" 2>/dev/null << EOF
$SERVICE_CONTENT
EOF

# Enable and start the service
echo "Enabling and starting the service..."
ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "systemctl --user daemon-reload && \
                     systemctl --user enable tty-clipboard.service && \
                     systemctl --user restart tty-clipboard.service" 2>/dev/null

# Check service status
echo ""
echo "Checking service status..."
# Give the service a moment to start
sleep 1
if ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "systemctl --user is-active --quiet tty-clipboard.service" 2>/dev/null; then
    echo "✓ Service is running"
    ssh -o "ExitOnForwardFailure=no" "$REMOTE_HOST" "systemctl --user status tty-clipboard.service --no-pager -l" 2>/dev/null
else
    echo "✗ Service failed to start"
    echo "Check logs with: ssh $REMOTE_HOST 'journalctl --user -u tty-clipboard.service'"
    exit 1
fi

# Update SSH config with LocalForward
echo ""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSH_CONFIG="${HOME}/.ssh/config"

# Create .ssh/sockets directory for ControlMaster
mkdir -p "${HOME}/.ssh/sockets"
chmod 700 "${HOME}/.ssh/sockets"

# Extract just the hostname part (without user@) for SSH config lookup
HOSTNAME_ONLY="${REMOTE_HOST##*@}"

# Auto-detect port if not specified
if [ -z "$LOCAL_PORT" ]; then
    echo "Auto-detecting local port for '$HOSTNAME_ONLY'..."
    PORT_RESULT=$(python3 "$SCRIPT_DIR/update-ssh-localforward.py" "$HOSTNAME_ONLY" --detect-port)
    LOCAL_PORT=$(echo "$PORT_RESULT" | cut -d: -f2)
    echo "Using local port: $LOCAL_PORT"
else
    echo "Using specified local port: $LOCAL_PORT"
fi

echo "Updating SSH config with LocalForward..."

if [ -f "$SSH_CONFIG" ] && grep -q "^Host.*\b${HOSTNAME_ONLY}\b" "$SSH_CONFIG"; then
    echo "Found SSH config entry for '$HOSTNAME_ONLY', adding LocalForward and ControlMaster..."
    python3 "$SCRIPT_DIR/update-ssh-localforward.py" "$HOSTNAME_ONLY" "127.0.0.1:${LOCAL_PORT} 127.0.0.1:5457"
    echo "✓ SSH config updated"
else
    echo "⚠ No SSH config entry found for '$HOSTNAME_ONLY'"
    echo ""
    echo "To enable automatic port forwarding, add this to your ~/.ssh/config:"
    echo ""
    echo "Host $HOSTNAME_ONLY"
    echo "    HostName $HOSTNAME_ONLY"
    echo "    LocalForward 127.0.0.1:${LOCAL_PORT} 127.0.0.1:5457"
    echo "    ControlMaster auto"
    echo "    ControlPath ~/.ssh/sockets/%r@%h:%p"
    echo "    ControlPersist 10m"
    echo ""
    echo "Or connect manually with port forwarding:"
    echo "    ssh -L 127.0.0.1:${LOCAL_PORT}:127.0.0.1:5457 $REMOTE_HOST"
fi

echo ""
echo "=========================================="
echo "Setup complete!"
echo "=========================================="
echo ""
echo "Local client installed: ~/.local/bin/tty-cb-client"
echo "Local port forward: 127.0.0.1:${LOCAL_PORT} -> ${REMOTE_HOST}:5457"
echo "Server installed on: $REMOTE_HOST"
echo "  Binaries location: ~/.local/bin/"
echo "  Certificates location: ~/.config/tty-clipboard/"
echo "  Service: tty-clipboard.service (systemd user service)"
echo ""
echo "To use the clipboard:"
echo "  1. Connect with SSH (port forwarding will be automatic if configured above)"
echo "  2. Use tty-cb-client with localhost:${LOCAL_PORT}:"
echo "     echo 'hello' | tty-cb-client write localhost"
echo "     tty-cb-client read localhost"
echo ""
echo "Note: When connecting to this server, use localhost:${LOCAL_PORT} for tty-cb-client."
echo "      Each remote server should use a different local port (5457, 5458, 5459, etc.)"
echo "     tty-cb-client read"
echo ""
echo "Useful commands:"
echo "  Check status:    ssh $REMOTE_HOST 'systemctl --user status tty-clipboard.service'"
echo "  View logs:       ssh $REMOTE_HOST 'journalctl --user -u tty-clipboard.service -f'"
echo "  Stop service:    ssh $REMOTE_HOST 'systemctl --user stop tty-clipboard.service'"
echo "  Start service:   ssh $REMOTE_HOST 'systemctl --user start tty-clipboard.service'"
echo ""
