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
    -d, --debug      Enable debug logging (shows clipboard operations)

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
    exit 0  # Always exit with success when stopping
fi

# Clean up stale PID files (don't try to stop processes, they may be from previous runs)
rm -f "$PIDFILE_WAYLAND_TO_TTY" "$PIDFILE_TTY_TO_WAYLAND"

# Wayland → TTY: Watch Wayland clipboard and write to tty-clipboard
if [ "$VERBOSE" = true ]; then
    echo "Starting Wayland→TTY bridge..."
fi

debug_log "Starting Wayland→TTY bridge process"

(
    last_content=""
    while true; do
        # Get current clipboard content
        current_content=$(wl-paste 2>/dev/null || echo "")
        
        # Check if content has changed
        if [ "$current_content" != "$last_content" ] && [ -n "$current_content" ]; then
            if [ "$DEBUG" = true ]; then
                echo "[$(date +'%Y-%m-%d %H:%M:%S')] Wayland clipboard changed, sending to tty-clipboard ($SERVER:$PORTS)" >&2
                echo "[$(date +'%Y-%m-%d %H:%M:%S')] Content length: ${#current_content} bytes" >&2
                if [ ${#current_content} -lt 200 ]; then
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Content preview: $current_content" >&2
                fi
            fi
            
            # Send to tty-clipboard
            if [ "$DEBUG" = true ]; then
                echo "$current_content" | tty-cb-client -p "$PORTS" write "$SERVER" 2>&1 | while read -r line; do
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] tty-cb-client: $line" >&2
                done
            else
                echo "$current_content" | tty-cb-client -p "$PORTS" write "$SERVER" 2>/dev/null
            fi
            
            last_content="$current_content"
        fi
        
        # Poll every 0.5 seconds
        sleep 0.5
    done
) &
WAYLAND_TO_TTY_PID=$!
echo $WAYLAND_TO_TTY_PID > "$PIDFILE_WAYLAND_TO_TTY"

debug_log "Wayland→TTY bridge started with PID: $WAYLAND_TO_TTY_PID (polling mode)"

# TTY → Wayland: Watch tty-clipboard and write to Wayland clipboard
if [ "$VERBOSE" = true ]; then
    echo "Starting TTY→Wayland bridge..."
fi

debug_log "Starting TTY→Wayland bridge process"

(
    while true; do
        if [ "$DEBUG" = true ]; then
            debug_log "Waiting for clipboard updates from tty-clipboard ($SERVER:$PORTS)..."
            tty-cb-client -vv -p "$PORTS" read_blocked "$SERVER" 2>&1 | while IFS= read -r line; do
                # Check if this is a log line (starts with [INFO], [DEBUG], [ERROR], etc.)
                if echo "$line" | grep -qE '^\[(INFO|DEBUG|ERROR|WARN)\]'; then
                    # This is a log message from tty-cb-client, just echo to stderr
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $line" >&2
                else
                    # This is actual clipboard content
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Received clipboard data: $line" >&2
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Writing to Wayland clipboard..." >&2
                    echo "$line" | wl-copy 2>&1 | while read -r wl_line; do
                        echo "[$(date +'%Y-%m-%d %H:%M:%S')] wl-copy: $wl_line" >&2
                    done
                    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Written to Wayland clipboard" >&2
                fi
            done
        else
            tty-cb-client -p "$PORTS" read_blocked "$SERVER" 2>/dev/null | while IFS= read -r line; do
                echo "$line" | wl-copy 2>/dev/null
            done
        fi
        sleep 1
    done
) &
TTY_TO_WAYLAND_PID=$!
echo $TTY_TO_WAYLAND_PID > "$PIDFILE_TTY_TO_WAYLAND"

debug_log "TTY→Wayland bridge started with PID: $TTY_TO_WAYLAND_PID"

if [ "$VERBOSE" = true ] || [ "$DEBUG" = true ]; then
    echo "=========================================="
    echo "Wayland ↔ TTY Clipboard Bridge Started"
    echo "=========================================="
    echo "Server: $SERVER"
    echo "Ports: $PORTS"
    echo "Wayland→TTY PID: $WAYLAND_TO_TTY_PID"
    echo "TTY→Wayland PID: $TTY_TO_WAYLAND_PID"
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

# Cleanup handler - kill all child processes
cleanup() {
    debug_log "Shutting down bridge..."
    # Kill child processes and all their descendants
    if [ -n "${WAYLAND_TO_TTY_PID:-}" ]; then
        # Kill the main process
        kill -TERM "$WAYLAND_TO_TTY_PID" 2>/dev/null || true
        # Kill all descendants using pkill
        pkill -TERM -P "$WAYLAND_TO_TTY_PID" 2>/dev/null || true
    fi
    if [ -n "${TTY_TO_WAYLAND_PID:-}" ]; then
        # Kill the main process
        kill -TERM "$TTY_TO_WAYLAND_PID" 2>/dev/null || true
        # Kill all descendants using pkill
        pkill -TERM -P "$TTY_TO_WAYLAND_PID" 2>/dev/null || true
    fi
    # Give them a moment to terminate gracefully
    sleep 0.3
    # Force kill if still running
    if [ -n "${WAYLAND_TO_TTY_PID:-}" ]; then
        kill -KILL "$WAYLAND_TO_TTY_PID" 2>/dev/null || true
        pkill -KILL -P "$WAYLAND_TO_TTY_PID" 2>/dev/null || true
    fi
    if [ -n "${TTY_TO_WAYLAND_PID:-}" ]; then
        kill -KILL "$TTY_TO_WAYLAND_PID" 2>/dev/null || true
        pkill -KILL -P "$TTY_TO_WAYLAND_PID" 2>/dev/null || true
    fi
    # Clean up PID files
    rm -f "$PIDFILE_WAYLAND_TO_TTY" "$PIDFILE_TTY_TO_WAYLAND" 2>/dev/null || true
    debug_log "Bridge stopped"
    exit 0
}

trap 'cleanup' INT TERM EXIT

# Keep the main script running by waiting for the child processes
# If either exits, the main script will also exit (and systemd will restart it)
wait $WAYLAND_TO_TTY_PID $TTY_TO_WAYLAND_PID || true
