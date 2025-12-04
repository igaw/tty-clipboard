#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

# Bridge between Wayland clipboard and tty-clipboard server
# Syncs clipboard content bidirectionally

show_usage() {
    cat << EOF
Usage: $0 [OPTIONS] [server_address] [ports]

Bridge between Wayland clipboard (wl-clipboard) and tty-clipboard server.
Runs two background processes:
  1. Watch Wayland clipboard and write changes to tty-clipboard
  2. Watch tty-clipboard and write changes to Wayland clipboard

Arguments:
    server_address    Address of tty-clipboard server (default: localhost)
    ports             Comma-separated port list (default: 5457)

Options:
    -h, --help       Show this help message
    -s, --stop       Stop existing bridge processes
    -v, --verbose    Enable verbose output

Requirements:
    - wl-clipboard (wl-copy, wl-paste)
    - tty-cb-client

Example:
    $0                              # Start bridge with localhost:5457
    $0 localhost 5457,5458,5459     # Monitor multiple ports
    $0 localhost 5457               # Explicit single port
    $0 192.168.1.100 5458           # Bridge to remote server
    $0 --stop                       # Stop all bridge processes

Multi-port usage:
    When multiple ports are specified, the bridge monitors all ports for
    clipboard updates and writes to all ports when the Wayland clipboard changes.

EOF
}

VERBOSE=false
STOP=false
SERVER="localhost"
PORTS="5457"

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

# Check dependencies
if ! command -v wl-copy &> /dev/null; then
    echo "Error: wl-copy not found. Please install wl-clipboard."
    exit 1
fi

if ! command -v wl-paste &> /dev/null; then
    echo "Error: wl-paste not found. Please install wl-clipboard."
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

# PID file locations
PIDFILE_WAYLAND_TO_TTY="/tmp/tty-clipboard-bridge-wayland-to-tty-${USER}.pid"
PIDFILE_TTY_TO_WAYLAND="/tmp/tty-clipboard-bridge-tty-to-wayland-${USER}.pid"

# Function to stop existing bridge processes
stop_bridge() {
    local stopped=false
    
    if [ -f "$PIDFILE_WAYLAND_TO_TTY" ]; then
        PID=$(cat "$PIDFILE_WAYLAND_TO_TTY")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            echo "Stopped Wayland→TTY bridge (PID: $PID)"
            stopped=true
        fi
        rm -f "$PIDFILE_WAYLAND_TO_TTY"
    fi
    
    if [ -f "$PIDFILE_TTY_TO_WAYLAND" ]; then
        PID=$(cat "$PIDFILE_TTY_TO_WAYLAND")
        if kill -0 "$PID" 2>/dev/null; then
            kill "$PID" 2>/dev/null || true
            echo "Stopped TTY→Wayland bridge (PID: $PID)"
            stopped=true
        fi
        rm -f "$PIDFILE_TTY_TO_WAYLAND"
    fi
    
    if [ "$stopped" = false ]; then
        echo "No bridge processes running"
    fi
}

# Handle --stop flag
if [ "$STOP" = true ]; then
    stop_bridge
    exit 0
fi

# Stop any existing bridge processes
stop_bridge

# Wayland → TTY: Watch Wayland clipboard and write to tty-clipboard
if [ "$VERBOSE" = true ]; then
    echo "Starting Wayland→TTY bridge..."
fi

(
    while true; do
        wl-paste -w tty-cb-client -p "$PORTS" write "$SERVER" 2>/dev/null || sleep 1
    done
) &
WAYLAND_TO_TTY_PID=$!
echo $WAYLAND_TO_TTY_PID > "$PIDFILE_WAYLAND_TO_TTY"

# TTY → Wayland: Watch tty-clipboard and write to Wayland clipboard
if [ "$VERBOSE" = true ]; then
    echo "Starting TTY→Wayland bridge..."
fi

(
    while true; do
        tty-cb-client -p "$PORTS" read_blocked "$SERVER" 2>/dev/null | while IFS= read -r line; do
            echo "$line" | wl-copy 2>/dev/null
        done
        sleep 1
    done
) &
TTY_TO_WAYLAND_PID=$!
echo $TTY_TO_WAYLAND_PID > "$PIDFILE_TTY_TO_WAYLAND"

if [ "$VERBOSE" = true ]; then
    echo "=========================================="
    echo "Wayland ↔ TTY Clipboard Bridge Started"
    echo "=========================================="
    echo "Server: $SERVER"
    echo "Ports: $PORTS"
    echo "Wayland→TTY PID: $WAYLAND_TO_TTY_PID"
    echo "TTY→Wayland PID: $TTY_TO_WAYLAND_PID"
    echo ""
    echo "To stop the bridge:"
    echo "    $0 --stop"
    echo ""
fi

# Cleanup handler
trap 'stop_bridge; exit 0' INT TERM EXIT

# Keep script running and wait for child processes
# If either process dies, restart it
while true; do
    # Check if Wayland→TTY process is still running
    if ! kill -0 $WAYLAND_TO_TTY_PID 2>/dev/null; then
        echo "Wayland→TTY bridge died, restarting..."
        (
            while true; do
                wl-paste -w tty-cb-client -p "$PORTS" write "$SERVER" 2>/dev/null || sleep 1
            done
        ) &
        WAYLAND_TO_TTY_PID=$!
        echo $WAYLAND_TO_TTY_PID > "$PIDFILE_WAYLAND_TO_TTY"
    fi
    
    # Check if TTY→Wayland process is still running
    if ! kill -0 $TTY_TO_WAYLAND_PID 2>/dev/null; then
        echo "TTY→Wayland bridge died, restarting..."
        (
            while true; do
                tty-cb-client -p "$PORTS" read_blocked "$SERVER" 2>/dev/null | while IFS= read -r line; do
                    echo "$line" | wl-copy 2>/dev/null
                done
                sleep 1
            done
        ) &
        TTY_TO_WAYLAND_PID=$!
        echo $TTY_TO_WAYLAND_PID > "$PIDFILE_TTY_TO_WAYLAND"
    fi
    
    # Sleep a bit before checking again
    sleep 2
done
