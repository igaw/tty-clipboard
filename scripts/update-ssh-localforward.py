#!/usr/bin/env python3
import argparse
from pathlib import Path
import sys
import re

def detect_port_for_host(config_path, host):
    """
    Detect the port to use for a given host.
    Returns (host, port) tuple.
    
    If host already has LocalForward configured, return that port.
    Otherwise, find the next available port starting from 5457.
    """
    if not config_path.exists():
        return (host, 5457)
    
    lines = config_path.read_text().splitlines()
    used_ports = set()
    host_port = None
    current_host = None
    
    for line in lines:
        stripped = line.strip()
        
        # Detect Host line
        if stripped.lower().startswith("host "):
            parts = stripped.split(maxsplit=1)
            if len(parts) > 1:
                current_host = parts[1]
        
        # Detect LocalForward line
        if stripped.lower().startswith("localforward"):
            # Parse: LocalForward 127.0.0.1:5457 127.0.0.1:5457
            # or: LocalForward [127.0.0.1]:5457 127.0.0.1:5457
            match = re.search(r'127\.0\.0\.1[:\]](\d+)', stripped)
            if match:
                port = int(match.group(1))
                used_ports.add(port)
                
                # If this is our target host, remember its port
                if current_host == host:
                    host_port = port
    
    # If host already has a port, return it
    if host_port is not None:
        return (host, host_port)
    
    # Find next available port starting from 5457
    next_port = 5457
    while next_port in used_ports:
        next_port += 1
    
    return (host, next_port)

def main():
    parser = argparse.ArgumentParser(
        description="Add or update LocalForward for a Host entry in SSH config"
    )
    parser.add_argument("host", help="Host alias in SSH config")
    parser.add_argument(
        "localforward",
        nargs='?',
        help='LocalForward value (e.g. "127.0.0.1:5457 127.0.0.1:5457"). Not required with --detect-port'
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path.home() / ".ssh" / "config",
        help="Path to SSH config file (default: ~/.ssh/config)"
    )
    parser.add_argument(
        "--detect-port",
        action="store_true",
        help="Detect and print the port to use for this host (existing or next available)"
    )
    args = parser.parse_args()

    host = args.host
    config_path = args.config
    
    # Handle port detection mode
    if args.detect_port:
        detected_host, detected_port = detect_port_for_host(config_path, host)
        print(f"{detected_host}:{detected_port}")
        return

    # Normal update mode - localforward is required
    if not args.localforward:
        parser.error("localforward argument is required when not using --detect-port")
    
    forward_value = args.localforward

    config_path.parent.mkdir(parents=True, exist_ok=True)
    if not config_path.exists():
        config_path.touch(mode=0o600)

    lines = config_path.read_text().splitlines()
    new_lines = []
    localforward_updated = False
    i = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Detect host line
        if stripped.lower().startswith("host ") and stripped.split()[1] == host:
            new_lines.append(line)
            i += 1

            # Collect all lines of this host block
            host_block_lines = []
            indent = "    "  # default 4 spaces
            while i < len(lines):
                subline = lines[i]
                sub_stripped = subline.strip()
                if sub_stripped.lower().startswith("host "):
                    break
                # Detect indentation from first indented line
                if sub_stripped and subline.startswith((" ", "\t")) and indent == "    ":
                    # Calculate actual indentation
                    indent = subline[:len(subline) - len(subline.lstrip())]
                host_block_lines.append(subline)
                i += 1

            # Check if LocalForward, ControlMaster, ControlPath, ControlPersist exist
            lf_found = False
            cm_found = False
            cp_found = False
            cpers_found = False
            
            for idx, subline in enumerate(host_block_lines):
                stripped_lower = subline.strip().lower()
                if stripped_lower.startswith("localforward"):
                    host_block_lines[idx] = indent + "LocalForward " + forward_value
                    lf_found = True
                elif stripped_lower.startswith("controlmaster"):
                    cm_found = True
                elif stripped_lower.startswith("controlpath"):
                    cp_found = True
                elif stripped_lower.startswith("controlpersist"):
                    cpers_found = True

            # Insert missing options after last non-blank line
            insert_idx = len(host_block_lines)
            for rev_idx in reversed(range(len(host_block_lines))):
                if host_block_lines[rev_idx].strip() != "":
                    insert_idx = rev_idx + 1
                    break
            
            options_to_add = []
            if not lf_found:
                options_to_add.append(indent + "LocalForward " + forward_value)
            if not cm_found:
                options_to_add.append(indent + "ControlMaster auto")
            if not cp_found:
                options_to_add.append(indent + "ControlPath ~/.ssh/sockets/%r@%h:%p")
            if not cpers_found:
                options_to_add.append(indent + "ControlPersist 10m")
            
            for option in options_to_add:
                host_block_lines.insert(insert_idx, option)
                insert_idx += 1

            new_lines.extend(host_block_lines)
            localforward_updated = True
            continue

        else:
            new_lines.append(line)
            i += 1

    # If host did not exist, append it at the end without extra blank lines
    if not localforward_updated:
        if len(new_lines) > 0 and new_lines[-1].strip() != "":
            new_lines.append("")  # separate from previous block
        new_lines.append(f"Host {host}")
        new_lines.append(f"    LocalForward {forward_value}")
        new_lines.append("    ControlMaster auto")
        new_lines.append("    ControlPath ~/.ssh/sockets/%r@%h:%p")
        new_lines.append("    ControlPersist 10m")

    # Write back preserving all spacing
    config_path.write_text("\n".join(new_lines) + "\n")
    print(f"Host '{host}' updated: LocalForward and ControlMaster configured in {config_path}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
