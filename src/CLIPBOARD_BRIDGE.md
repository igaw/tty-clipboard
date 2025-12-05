# C-Based Clipboard Bridges

This directory contains C implementations of clipboard bridges that connect local clipboard managers (Wayland, Klipper) to the tty-clipboard server with full metadata forwarding.

## Architecture

The bridges use a **plugin-based architecture**:

- **plugin.h**: Defines the plugin interface that clipboard plugins must implement
- **wayland-plugin.c**: Plugin for Wayland clipboard (uses `wl-paste`/`wl-copy`)
- **klipper-plugin.c**: Plugin for KDE Klipper clipboard (uses D-Bus API)
- **clipboard-bridge.c**: Core bridge implementation that manages bidirectional synchronization

## Key Features

### 1. Metadata Forwarding
Every clipboard operation includes:
- **hostname**: The host that originally wrote the data
- **timestamp**: Unix timestamp of the write operation
- **write_uuid**: Unique identifier for tracking operations

This allows tracing clipboard data across multiple systems.

### 2. Feedback Loop Prevention
The bridge prevents infinite loops when clipboard data is synced bidirectionally:

```
User copies on Wayland → Wayland→TTY bridge writes to server
                      ↓
                   Server receives and broadcasts
                      ↓
                   TTY→Wayland bridge receives data
                      ↓
                   Metadata matching prevents re-writing same data
```

The bridge compares:
- Content (raw bytes)
- Metadata (hostname, timestamp, UUID)

Only writes new data if it differs from what was just written in the opposite direction.

### 3. Protocol Compliance
Bridges forward complete protobuf messages with all metadata intact:

```protobuf
message WriteRequest {
  bytes data = 1;
  string hostname = 4;
  int64 timestamp = 5;
  bytes write_uuid = 3;
}

message DataFrame {
  bytes data = 1;
  string hostname = 4;
  int64 timestamp = 5;
  bytes write_uuid = 3;
}
```

## Building

The bridges are compiled with the main project:

```bash
meson compile -C builddir
```

Two executables are generated:
- `tty-cb-wayland-bridge`: Wayland ↔ TTY bridge
- `tty-cb-klipper-bridge`: Klipper ↔ TTY bridge

## Usage

### Wayland Bridge

```bash
tty-cb-wayland-bridge --plugin wayland --server <host> [--ports 5457,5458] [-d]
```

Example:
```bash
tty-cb-wayland-bridge --plugin wayland --server 192.168.1.100 --ports 5457,5458 -d
```

### Klipper Bridge

```bash
tty-cb-klipper-bridge --plugin klipper --server <host> [--ports 5457,5458] [-d]
```

Example:
```bash
tty-cb-klipper-bridge --plugin klipper --server localhost --ports 5457,5458 -d
```

### Options

- `-p, --plugin <name>`: Clipboard plugin (`wayland`, `klipper`)
- `-s, --server <host>`: Server hostname or IP address
- `-P, --ports PORT1,PORT2`: Server ports (default: 5457,5458)
- `-c, --ca-cert <path>`: Path to CA certificate for TLS
- `-v, --verbose`: Enable verbose logging
- `-d, --debug`: Enable debug logging
- `-h, --help`: Show help message

## Plugin Interface

Plugins must implement the `plugin_interface_t` structure:

```c
typedef struct {
    const char *name;
    const char *version;
    
    plugin_handle_t (*init)(void);
    clipboard_data_t* (*read)(plugin_handle_t handle);
    int (*write)(plugin_handle_t handle, const clipboard_data_t *data);
    void (*free_clipboard_data)(clipboard_data_t *data);
    void (*cleanup)(plugin_handle_t handle);
} plugin_interface_t;
```

### Implementing a New Plugin

1. Create `<name>-plugin.c` implementing the interface
2. Export `const plugin_interface_t <name>_plugin`
3. Add to `meson.build`:
   ```meson
   <name>_bridge_sources = bridge_common_sources + ['clipboard-bridge.c', '<name>-plugin.c']
   <name>_bridge = executable('tty-cb-<name>-bridge', <name>_bridge_sources, ...)
   ```

## Metadata Flow Example

```
Host A (adalid):
  User copies "Hello World"
  ↓
  tty-cb-client write to server
  {data: "Hello World", hostname: "adalid", timestamp: 1704067200, write_uuid: <uuid>}
  ↓
  tty-cb-server receives and stores
  ↓
  tty-cb-server broadcasts to all subscribers
  ↓
Host B:
  tty-cb-wayland-bridge receives
  {data: "Hello World", hostname: "adalid", timestamp: 1704067200, write_uuid: <uuid>}
  ↓
  Metadata is preserved when writing to Wayland clipboard
  ↓
  User can verify origin: "Data from host: adalid, timestamp: 2024-01-01 00:00:00"
```

## Thread Model

The bridge runs two concurrent threads:

1. **Local→Server**: Monitors local clipboard for changes, sends to server
   - Polls every 1 second
   - Skips if content matches what was just received from server
   
2. **Server→Local**: Listens for clipboard updates from server, writes locally
   - Blocks on `read_blocked` waiting for server updates
   - Skips if content matches what was just sent to server

Both threads access shared state (`last_local_data`, `last_remote_data`) protected by `data_mutex`.

## Advantages over Bash Bridges

- **Type Safety**: Protobuf and C types prevent parsing errors
- **Performance**: Native compilation, no shell subprocess overhead
- **Metadata Handling**: Native protobuf support for all fields
- **Maintainability**: Plugin architecture for easy extensibility
- **Resource Usage**: Lower memory and CPU footprint

## Troubleshooting

### Bridge won't start
- Verify server is running: `tty-cb-server -p 5457 -p 5458`
- Check connectivity: `ping <server_host>`
- Verify certificates if using TLS

### Data not syncing
- Enable debug mode: `-d` flag
- Check bridge logs for errors
- Ensure Wayland/Klipper tools are available (`wl-paste`, `qdbus`)

### Feedback loops
- Metadata matching should prevent infinite loops
- If occurring, check debug output for "Skipping echo" messages

## Future Enhancements

- [ ] X11 clipboard plugin (XClip/XSel)
- [ ] macOS pasteboard plugin
- [ ] Regex-based content filtering
- [ ] Hot-reload plugins without restart
- [ ] Clipboard history management
- [ ] Compression for large data transfers
