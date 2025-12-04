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
    -p, --port PORT      Local port for SSH LocalForward (default: auto-detect)
    --bridge-ports LIST  Comma-separated port list for clipboard bridge (overrides auto-detect)
    -w, --wayland-bridge Install and configure Wayland clipboard bridge service
    -k, --klipper-bridge Install and configure KDE Klipper clipboard bridge service
    --auto-bridge        Auto-detect and install appropriate clipboard bridge
    -h, --help           Show this help message

This script will:
  1. Check if certificates exist locally, generate them if needed
  2. Install client binary to local ~/.local/bin
  3. Copy certificates to the remote host
  4. Copy server and client binaries to remote ~/.local/bin
  5. Create a systemd user service to start the server on login
  6. Update local ~/.ssh/config with LocalForward (if hostname entry exists)
  7. Optionally install clipboard bridge systemd service (-w, -k, or --auto-bridge flags)

Example:
    $0 myserver.example.com
    $0 myserver.example.com ./builddir
    $0 -p 5458 server2.com               # Use specific local port
    $0 -w myserver.example.com           # Install Wayland bridge
    $0 -k myserver.example.com           # Install Klipper bridge
    $0 --auto-bridge myserver.example.com # Auto-detect and install appropriate bridge

Note: By default, ports are auto-detected. If a host already has a LocalForward
      configured, that port is reused. Otherwise, the next available port starting
      from 5457 is assigned. Use -p to override and specify a custom port.
      
      With --auto-bridge, the script will detect whether Wayland or KDE Klipper is
      available and install the appropriate clipboard bridge automatically.
      
      For multi-server clipboard sync, run this script once for each server:
        $0 -p 5457 server1.com
        $0 -p 5458 server2.com
        $0 -p 5459 server3.com
      Then use: tty-cb-client -p 5457,5458,5459 read

EOF
}

# Parse arguments
if [[ $# -lt 1 ]]; then
    echo "Error: Missing required arguments"
    show_usage
    exit 1
fi

LOCAL_PORT=""
BRIDGE_PORTS_OVERRIDE=""
INSTALL_WAYLAND_BRIDGE=false
BRIDGE_TYPE=""  # Will be set to 'wayland' or 'klipper' based on detection

# Function to detect desktop environment and determine clipboard bridge type
detect_clipboard_bridge() {
    # Check for KDE Plasma / Klipper
    if [ -n "${KDE_FULL_SESSION:-}" ] || [ -n "${KDE_SESSION_VERSION:-}" ] || [ -n "${KDEDIR:-}" ]; then
        # KDE Plasma is running, check if Klipper D-Bus service is available
        if command -v qdbus-qt6 &>/dev/null || command -v qdbus-qt5 &>/dev/null; then
            BRIDGE_TYPE="klipper"
            return 0
        fi
    fi
    
    # Check for Wayland
    if [ -n "${WAYLAND_DISPLAY:-}" ]; then
        # Check if wl-clipboard is available
        if command -v wl-copy &>/dev/null && command -v wl-paste &>/dev/null; then
            BRIDGE_TYPE="wayland"
            return 0
        fi
    fi
    
    # Check XDG_SESSION_TYPE
    if [ "${XDG_SESSION_TYPE:-}" = "wayland" ]; then
        if command -v wl-copy &>/dev/null && command -v wl-paste &>/dev/null; then
            BRIDGE_TYPE="wayland"
            return 0
        fi
    elif [ "${XDG_SESSION_TYPE:-}" = "x11" ] || [ "${XDG_SESSION_TYPE:-}" = "kde" ]; then
        if command -v qdbus-qt6 &>/dev/null || command -v qdbus-qt5 &>/dev/null; then
            BRIDGE_TYPE="klipper"
            return 0
        fi
    fi
    
    # No suitable bridge detected
    BRIDGE_TYPE=""
    return 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--port)
            LOCAL_PORT="$2"
            shift 2
            ;;
        --bridge-ports)
            BRIDGE_PORTS_OVERRIDE="$2"
            shift 2
            ;;
        -w|--wayland-bridge)
            INSTALL_WAYLAND_BRIDGE=true
            BRIDGE_TYPE="wayland"
            shift
            ;;
        -k|--klipper-bridge)
            INSTALL_WAYLAND_BRIDGE=true
            BRIDGE_TYPE="klipper"
            shift
            ;;
        --auto-bridge)
            # Auto-detect the appropriate bridge (default behavior)
            INSTALL_WAYLAND_BRIDGE=true
            shift
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

# Function to check if ~/.local/bin is in PATH
check_local_bin_in_path() {
    if [[ ":$PATH:" == *":$HOME/.local/bin:"* ]]; then
        return 0  # Found in PATH
    else
        return 1  # Not in PATH
    fi
}

# Function to print PATH setup instructions
print_path_setup_instructions() {
    echo ""
    echo "=========================================="
    echo "⚠ Warning: ~/.local/bin is not in your PATH"
    echo "=========================================="
    echo ""
    echo "To use tty-cb-client directly, add ~/.local/bin to your PATH."
    echo ""
    
    # Detect shell
    CURRENT_SHELL=$(basename "$SHELL")
    
    if [[ "$CURRENT_SHELL" == "bash" ]]; then
        echo "For Bash, add this line to ~/.bashrc:"
        echo ""
        echo '    export PATH="$HOME/.local/bin:$PATH"'
        echo ""
        echo "Then reload with:"
        echo "    source ~/.bashrc"
        echo ""
    elif [[ "$CURRENT_SHELL" == "zsh" ]]; then
        echo "For Zsh, add this line to ~/.zshrc:"
        echo ""
        echo '    export PATH="$HOME/.local/bin:$PATH"'
        echo ""
        echo "Then reload with:"
        echo "    source ~/.zshrc"
        echo ""
    else
        echo "For other shells, add this line to your shell configuration file:"
        echo ""
        echo '    export PATH="$HOME/.local/bin:$PATH"'
        echo ""
    fi
    
    echo "Or use the full path for now:"
    echo "    ~/.local/bin/tty-cb-client"
    echo ""
}

# Install client locally
echo ""
echo "Installing client locally..."

# Stop the Wayland bridge service if it's running (to avoid "Text file busy" error)
BRIDGE_SERVICE_WAS_RUNNING=false
if systemctl --user is-active --quiet tty-clipboard-bridge.service 2>/dev/null; then
    echo "Stopping tty-clipboard-bridge service..."
    systemctl --user stop tty-clipboard-bridge.service 2>/dev/null || true
    BRIDGE_SERVICE_WAS_RUNNING=true
    # Give it a moment to fully stop
    sleep 1
fi

mkdir -p "$HOME/.local/bin"
cp "$CLIENT_BIN" "$HOME/.local/bin/tty-cb-client"
chmod 755 "$HOME/.local/bin/tty-cb-client"
echo "✓ Client installed to ~/.local/bin/tty-cb-client"

# Restart the bridge service if it was running
if [ "$BRIDGE_SERVICE_WAS_RUNNING" = true ]; then
    echo "Restarting tty-clipboard-bridge service..."
    systemctl --user start tty-clipboard-bridge.service 2>/dev/null || true
fi

# Check if ~/.local/bin is in PATH
if ! check_local_bin_in_path; then
    print_path_setup_instructions
fi

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

# Install clipboard bridge if requested
if [ "$INSTALL_WAYLAND_BRIDGE" = true ]; then
    # Auto-detect bridge type if not explicitly specified
    if [ -z "$BRIDGE_TYPE" ]; then
        echo "Detecting available clipboard bridge..."
        if detect_clipboard_bridge; then
            echo "✓ Detected: $BRIDGE_TYPE"
        else
            echo "⚠ Warning: No suitable clipboard bridge detected"
            echo "   - For Wayland: install wl-clipboard"
            echo "   - For KDE Plasma: install qdbus-qt5 or qdbus-qt6"
            INSTALL_WAYLAND_BRIDGE=false
        fi
    fi
fi

# Install Wayland bridge if requested
if [ "$INSTALL_WAYLAND_BRIDGE" = true ] && [ "$BRIDGE_TYPE" = "wayland" ]; then
    echo "=========================================="
    echo "Installing Wayland clipboard bridge..."
    echo "=========================================="
    echo ""
    
    # Check if wl-clipboard is installed
    if ! command -v wl-copy &> /dev/null || ! command -v wl-paste &> /dev/null; then
        echo "⚠ Warning: wl-clipboard not found. Please install it:"
        echo "  Debian/Ubuntu: sudo apt install wl-clipboard"
        echo "  Fedora:        sudo dnf install wl-clipboard"
        echo "  Arch:          sudo pacman -S wl-clipboard"
        echo ""
    fi
    
    # Copy wayland-bridge.sh script
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp "$SCRIPT_DIR/wayland-bridge.sh" "$HOME/.local/bin/"
    chmod +x "$HOME/.local/bin/wayland-bridge.sh"
    echo "✓ Wayland bridge script installed to ~/.local/bin/wayland-bridge.sh"
    
    # Create systemd user service for Wayland bridge
    mkdir -p "$HOME/.config/systemd/user"
    
    # Discover all configured local ports from SSH config to enable multi-server bridge
    # If user provided explicit list, use it; otherwise detect from SSH config
    if [ -n "$BRIDGE_PORTS_OVERRIDE" ]; then
        ALL_PORTS="$BRIDGE_PORTS_OVERRIDE"
    else
        ALL_PORTS=$(python3 "$SCRIPT_DIR/update-ssh-localforward.py" ignored --list-all-ports --config "$SSH_CONFIG" 2>/dev/null || true)
    fi
    if [ -z "$ALL_PORTS" ]; then
        # Fallback to the single port provided/auto-detected
        ALL_PORTS="$LOCAL_PORT"
    fi

    cat > "$HOME/.config/systemd/user/tty-cb-bridge.service" << BRIDGEEOF
[Unit]
Description=Wayland Clipboard Bridge for tty-clipboard
Documentation=https://github.com/igaw/tty-clipboard
After=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/wayland-bridge.sh localhost ${ALL_PORTS}
Restart=on-failure
RestartSec=5
Environment="WAYLAND_DISPLAY=wayland-0"
Environment="HOME=%h"

[Install]
WantedBy=default.target
BRIDGEEOF
    
    if [ -n "$BRIDGE_PORTS_OVERRIDE" ]; then
        echo "✓ Wayland bridge configured for overridden ports: ${ALL_PORTS}"
    else
        echo "✓ Wayland bridge configured for ports: ${ALL_PORTS}"
    fi
    
    echo "✓ Systemd service created: tty-cb-bridge.service"
    
    # Enable and start the service
    systemctl --user daemon-reload
    systemctl --user enable tty-cb-bridge.service
    systemctl --user start tty-cb-bridge.service
    
    echo "✓ Wayland bridge service enabled and started"
    echo ""
    echo "Wayland bridge setup complete!"
    echo "  Script: ~/.local/bin/wayland-bridge.sh"
    echo "  Service: tty-cb-bridge.service"
    echo ""
    echo "The bridge syncs clipboard bidirectionally:"
    echo "  • Copy in GUI apps → available in terminal"
    echo "  • Copy in terminal → available in GUI apps"
    echo ""
    echo "Manage the service:"
    echo "  Status:  systemctl --user status tty-cb-bridge.service"
    echo "  Logs:    journalctl --user -u tty-cb-bridge.service -f"
    echo "  Stop:    systemctl --user stop tty-cb-bridge.service"
    echo "  Restart: systemctl --user restart tty-cb-bridge.service"
    echo ""
    echo "Enable debug logging (to troubleshoot clipboard sync issues):"
    echo "  1. Edit: ~/.config/systemd/user/tty-cb-bridge.service"
    echo "  2. Change ExecStart line to: ExecStart=%h/.local/bin/wayland-bridge.sh -d localhost ${ALL_PORTS}"
    echo "  3. Reload: systemctl --user daemon-reload"
    echo "  4. Restart: systemctl --user restart tty-cb-bridge.service"
    echo "  5. View logs: journalctl --user -u tty-cb-bridge.service -f"
    echo ""
fi

# Install Klipper bridge if requested
if [ "$INSTALL_WAYLAND_BRIDGE" = true ] && [ "$BRIDGE_TYPE" = "klipper" ]; then
    echo "=========================================="
    echo "Installing KDE Klipper clipboard bridge..."
    echo "=========================================="
    echo ""
    
    # Check if qdbus is installed
    if ! command -v qdbus-qt6 &> /dev/null && ! command -v qdbus-qt5 &> /dev/null; then
        echo "⚠ Warning: qdbus-qt5 or qdbus-qt6 not found. Please install Qt development tools:"
        echo "  Debian/Ubuntu: sudo apt install qt6-tools or qt5-qmake"
        echo "  Fedora:        sudo dnf install qt6-qtbase or qt5-qtbase"
        echo "  Arch:          sudo pacman -S qt6-base or qt5-base"
        echo ""
    fi
    
    # Check if dbus-monitor is installed
    if ! command -v dbus-monitor &> /dev/null; then
        echo "⚠ Warning: dbus-monitor not found. Please install dbus package:"
        echo "  Debian/Ubuntu: sudo apt install dbus"
        echo "  Fedora:        sudo dnf install dbus"
        echo "  Arch:          sudo pacman -S dbus"
        echo ""
    fi
    
    # Copy klipper-bridge.sh script
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp "$SCRIPT_DIR/klipper-bridge.sh" "$HOME/.local/bin/"
    chmod +x "$HOME/.local/bin/klipper-bridge.sh"
    echo "✓ Klipper bridge script installed to ~/.local/bin/klipper-bridge.sh"
    
    # Create systemd user service for Klipper bridge
    mkdir -p "$HOME/.config/systemd/user"
    
    # Discover all configured local ports from SSH config to enable multi-server bridge
    # If user provided explicit list, use it; otherwise detect from SSH config
    if [ -n "$BRIDGE_PORTS_OVERRIDE" ]; then
        ALL_PORTS="$BRIDGE_PORTS_OVERRIDE"
    else
        ALL_PORTS=$(python3 "$SCRIPT_DIR/update-ssh-localforward.py" ignored --list-all-ports --config "$SSH_CONFIG" 2>/dev/null || true)
    fi
    if [ -z "$ALL_PORTS" ]; then
        # Fallback to the single port provided/auto-detected
        ALL_PORTS="$LOCAL_PORT"
    fi

    cat > "$HOME/.config/systemd/user/tty-cb-bridge.service" << BRIDGEEOF
[Unit]
Description=KDE Klipper Clipboard Bridge for tty-clipboard
Documentation=https://github.com/igaw/tty-clipboard
After=graphical-session.target

[Service]
Type=simple
ExecStart=%h/.local/bin/klipper-bridge.sh localhost ${ALL_PORTS}
Restart=on-failure
RestartSec=5
Environment="HOME=%h"

[Install]
WantedBy=default.target
BRIDGEEOF
    
    if [ -n "$BRIDGE_PORTS_OVERRIDE" ]; then
        echo "✓ Klipper bridge configured for overridden ports: ${ALL_PORTS}"
    else
        echo "✓ Klipper bridge configured for ports: ${ALL_PORTS}"
    fi
    
    echo "✓ Systemd service created: tty-cb-bridge.service"
    
    # Enable and start the service
    systemctl --user daemon-reload
    systemctl --user enable tty-cb-bridge.service
    systemctl --user start tty-cb-bridge.service
    
    echo "✓ Klipper bridge service enabled and started"
    echo ""
    echo "Klipper bridge setup complete!"
    echo "  Script: ~/.local/bin/klipper-bridge.sh"
    echo "  Service: tty-cb-bridge.service"
    echo ""
    echo "The bridge syncs clipboard bidirectionally:"
    echo "  • Copy in GUI apps → available in terminal"
    echo "  • Copy in terminal → available in GUI apps"
    echo ""
    echo "Manage the service:"
    echo "  Status:  systemctl --user status tty-cb-bridge.service"
    echo "  Logs:    journalctl --user -u tty-cb-bridge.service -f"
    echo "  Stop:    systemctl --user stop tty-cb-bridge.service"
    echo "  Restart: systemctl --user restart tty-cb-bridge.service"
    echo ""
    echo "Enable debug logging (to troubleshoot clipboard sync issues):"
    echo "  1. Edit: ~/.config/systemd/user/tty-cb-bridge.service"
    echo "  2. Change ExecStart line to: ExecStart=%h/.local/bin/klipper-bridge.sh -d localhost ${ALL_PORTS}"
    echo "  3. Reload: systemctl --user daemon-reload"
    echo "  4. Restart: systemctl --user restart tty-cb-bridge.service"
    echo "  5. View logs: journalctl --user -u tty-cb-bridge.service -f"
    echo ""
fi

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
