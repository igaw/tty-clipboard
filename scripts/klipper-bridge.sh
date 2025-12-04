#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

# Bridge between KDE Klipper clipboard and tty-clipboard server
# Syncs clipboard content bidirectionally using Klipper D-Bus interface

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [server_address] [ports]

Bridge between KDE Klipper clipboard and tty-clipboard server.
Runs two background processes:
  1. Watch Klipper clipboard and write changes to tty-clipboard
  2. Watch tty-clipboard and write changes to Klipper clipboard

Arguments:
    server_address    Address of tty-clipboard server (default: localhost)
    ports             Comma-separated port list (default: 5457)

Options:
    -h, --help       Show this help message
    -s, --stop       Stop existing bridge processes
    -v, --verbose    Enable verbose output
    -d, --debug      Enable debug logging (shows clipboard operations)

Requirements:
    - KDE Plasma (Klipper)
    - qdbus-qt6 (Qt6 development tools)
    - dbus-monitor (part of dbus package)
    - tty-cb-client

Example:
    $0                              # Start bridge with localhost:5457
    $0 localhost 5457,5458,5459     # Monitor multiple ports
    $0 localhost 5457               # Explicit single port
    $0 192.168.1.100 5458           # Bridge to remote server
    $0 --stop                       # Stop all bridge processes

Multi-port usage:
    When multiple ports are specified, the bridge monitors all ports for
    clipboard updates and writes to all ports when the Klipper clipboard changes.

EOF
}

VERBOSE=false
DEBUG=false
STOP=false
SERVER="localhost"
PORTS="5457"

# Debug logging function
debug_log() {
    if [ "$DEBUG" = true ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >&2
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_usage
            exit 0
            ;;
        -s|--stop)
            STOP=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -*)
            echo "Error: Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            if [ -z "${SERVER_SET:-}" ]; then
                SERVER="$1"
                SERVER_SET=1
            else
                PORTS="$1"
            fi
            shift
            ;;
    esac
done

# Ensure ~/.local/bin is in PATH (needed when run from systemd)
# systemd may not set HOME, so we need to handle that
if [ -z "${HOME:-}" ]; then
    HOME=$(getent passwd "$(whoami)" | cut -d: -f6)
    export HOME
fi
export PATH="${HOME}/.local/bin:${PATH}"

# Also try adding to PATH using direct expansion in case HOME isn't fully resolved
LOCAL_BIN_DIR="${HOME}/.local/bin"
if [ -d "$LOCAL_BIN_DIR" ]; then
    export PATH="$LOCAL_BIN_DIR:${PATH}"
fi

# Use Qt6 qdbus
QDBUS="qdbus-qt6"

# Check dependencies
if ! command -v "$QDBUS" &> /dev/null; then
    echo "Error: qdbus-qt6 not found. Please install Qt6 development tools."
    echo "  Debian/Ubuntu: sudo apt install qt6-tools"
    echo "  Fedora:        sudo dnf install qt6-qtbase"
    echo "  Arch:          sudo pacman -S qt6-base"
    exit 1
fi

if ! command -v dbus-monitor &> /dev/null; then
    echo "Error: dbus-monitor not found. Please install dbus package."
    exit 1
fi

if ! command -v tty-cb-client &> /dev/null; then
    # If still not found, try using absolute path
    if [ ! -f "$LOCAL_BIN_DIR/tty-cb-client" ]; then
        echo "Error: tty-cb-client not found at $LOCAL_BIN_DIR/tty-cb-client. Please install tty-clipboard."
        exit 1
    fi
    # Create an alias to use the absolute path
    tty-cb-client() {
        "$LOCAL_BIN_DIR/tty-cb-client" "$@"
    }
    export -f tty-cb-client
fi

# Verify Klipper is running
if ! $QDBUS org.kde.klipper /klipper org.freedesktop.DBus.Introspectable.Introspect &>/dev/null; then
    echo "Error: Klipper D-Bus service not found. Is KDE Plasma running?"
    exit 1
fi

# PID file locations
PIDFILE_KLIPPER_TO_TTY="/tmp/tty-clipboard-bridge-klipper-to-tty-${USER}.pid"
PIDFILE_TTY_TO_KLIPPER="/tmp/tty-clipboard-bridge-tty-to-klipper-${USER}.pid"

# Function to stop existing bridge processes
stop_bridge() {
    local stopped=false
    
    if [ -f "$PIDFILE_KLIPPER_TO_TTY" ]; then
        PID=$(cat "$PIDFILE_KLIPPER_TO_TTY")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            echo "Stopped Klipper→TTY bridge (PID: $PID)"
            stopped=true
        fi
        rm -f "$PIDFILE_KLIPPER_TO_TTY"
    fi
    
    if [ -f "$PIDFILE_TTY_TO_KLIPPER" ]; then
        PID=$(cat "$PIDFILE_TTY_TO_KLIPPER")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            echo "Stopped TTY→Klipper bridge (PID: $PID)"
            stopped=true
        fi
        rm -f "$PIDFILE_TTY_TO_KLIPPER"
    fi
    
    if [ "$stopped" = false ]; then
        echo "No bridge processes running"
    fi
}

# Handle --stop flag
if [ "$STOP" = true ]; then
    stop_bridge
    exit 0  # Always exit with success when stopping
fi

# Clean up stale PID files (don't try to stop processes, they may be from previous runs)
rm -f "$PIDFILE_KLIPPER_TO_TTY" "$PIDFILE_TTY_TO_KLIPPER"

# Klipper → TTY: Monitor Klipper clipboard signal and write to tty-clipboard
if [ "$VERBOSE" = true ]; then
    echo "Starting Klipper→TTY bridge..."
fi

debug_log "Starting Klipper→TTY bridge process (using clipboardHistoryUpdated signal)"

(
    # Monitor Klipper clipboard changes via D-Bus signal
    $QDBUS --system-bus --print-reply \
        org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus.ListNames 2>/dev/null | grep -q "org.kde.klipper" || {
        debug_log "Error: Klipper not found on session bus"
    }
    
    # Use dbus-monitor to watch for clipboardHistoryUpdated signal
    dbus-monitor --session "type='signal',interface='org.kde.klipper.klipper',member='clipboardHistoryUpdated'" | while read -r line; do
        # When we get a signal, fetch the current clipboard content
        if echo "$line" | grep -q "member=clipboardHistoryUpdated"; then
            current_content=$($QDBUS org.kde.klipper /klipper org.kde.klipper.klipper.getClipboardContents 2>/dev/null || echo "")
            
            if [ -n "$current_content" ]; then
                if [ "$DEBUG" = true ]; then
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Klipper clipboard changed (signal), sending to tty-clipboard ($SERVER:$PORTS)" >&2
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Content length: ${#current_content} bytes" >&2
                    if [ ${#current_content} -lt 200 ]; then
                        echo "[$(date +'%Y-%m-%d %H:%M:%S')] Content preview: $current_content" >&2
                    fi
                fi
                
                # Send to tty-clipboard
                if [ "$DEBUG" = true ]; then
                    echo "$current_content" | tty-cb-client -p "$PORTS" write "$SERVER" 2>&1 | while read -r tty_line; do
                        echo "[$(date +'%Y-%m-%d %H:%M:%S')] tty-cb-client: $tty_line" >&2
                    done
                else
                    echo "$current_content" | tty-cb-client -p "$PORTS" write "$SERVER" 2>/dev/null
                fi
            fi
        fi
    done
) &
KLIPPER_TO_TTY_PID=$!
echo $KLIPPER_TO_TTY_PID > "$PIDFILE_KLIPPER_TO_TTY"

debug_log "Klipper→TTY bridge started with PID: $KLIPPER_TO_TTY_PID (signal-based)"

# TTY → Klipper: Watch tty-clipboard and write to Klipper clipboard
if [ "$VERBOSE" = true ]; then
    echo "Starting TTY→Klipper bridge..."
fi

debug_log "Starting TTY→Klipper bridge process"

(
    while true; do
        if [ "$DEBUG" = true ]; then
            debug_log "Waiting for clipboard updates from tty-clipboard ($SERVER:$PORTS)..."
            tty-cb-client -vv -p "$PORTS" read_blocked "$SERVER" 2>&1 | while IFS= read -r line; do
                # Check if this is a debug line with metadata
                if echo "$line" | grep -q "Data from host:"; then
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $line" >&2
                elif echo "$line" | grep -q "Received"; then
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $line" >&2
                else
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Received from tty-clipboard: $line" >&2
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Writing to Klipper clipboard..." >&2
                    $QDBUS org.kde.klipper /klipper org.kde.klipper.klipper.setClipboardContents "$line" 2>&1 | while read -r klipper_line; do
                        echo "[$(date +'%Y-%m-%d %H:%M:%S')] setClipboardContents: $klipper_line" >&2
                    done
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Written to Klipper clipboard" >&2
                fi
            done
        else
            tty-cb-client -p "$PORTS" read_blocked "$SERVER" 2>/dev/null | while IFS= read -r line; do
                $QDBUS org.kde.klipper /klipper org.kde.klipper.klipper.setClipboardContents "$line" 2>/dev/null
            done
        fi
        sleep 1
    done
) &
TTY_TO_KLIPPER_PID=$!
echo $TTY_TO_KLIPPER_PID > "$PIDFILE_TTY_TO_KLIPPER"

debug_log "TTY→Klipper bridge started with PID: $TTY_TO_KLIPPER_PID"

if [ "$VERBOSE" = true ] || [ "$DEBUG" = true ]; then
    echo "=========================================="
    echo "Klipper ↔ TTY Clipboard Bridge Started"
    echo "=========================================="
    echo "Server: $SERVER"
    echo "Ports: $PORTS"
    echo "Klipper→TTY PID: $KLIPPER_TO_TTY_PID"
    echo "TTY→Klipper PID: $TTY_TO_KLIPPER_PID"
    if [ "$DEBUG" = true ]; then
        echo "Debug mode: ENABLED"
        echo "Logs will show clipboard operations"
    fi
    echo ""
    echo "To stop the bridge:"
    echo "    $0 --stop"
    echo ""
fi

debug_log "Bridge initialization complete"
debug_log "Waiting for clipboard events..."

# Cleanup handler - kill process group to ensure all subprocesses are terminated
cleanup() {
    debug_log "Shutting down bridge..."
    # Kill child processes and their subprocesses
    if [ -n "${KLIPPER_TO_TTY_PID:-}" ]; then
        kill -TERM -$KLIPPER_TO_TTY_PID 2>/dev/null || true
    fi
    if [ -n "${TTY_TO_KLIPPER_PID:-}" ]; then
        kill -TERM -$TTY_TO_KLIPPER_PID 2>/dev/null || true
    fi
    # Give them a moment to terminate gracefully
    sleep 0.2
    # Force kill if still running
    if [ -n "${KLIPPER_TO_TTY_PID:-}" ]; then
        kill -KILL -$KLIPPER_TO_TTY_PID 2>/dev/null || true
    fi
    if [ -n "${TTY_TO_KLIPPER_PID:-}" ]; then
        kill -KILL -$TTY_TO_KLIPPER_PID 2>/dev/null || true
    fi
    debug_log "Bridge stopped"
    exit 0
}

trap 'cleanup' INT TERM EXIT

# Keep the main script running by waiting for the child processes
# If either exits, the main script will also exit (and systemd will restart it)
wait $KLIPPER_TO_TTY_PID $TTY_TO_KLIPPER_PID || true
