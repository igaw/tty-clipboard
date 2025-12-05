# TTY Clipboard Bridge Architecture

## Overview

The clipboard bridge system provides bidirectional synchronization of clipboard content between local clipboard managers (Wayland, Klipper, etc.) and a remote tty-clipboard server, with full preservation of metadata (hostname, timestamp, write UUID).

## System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                        Remote System (SSH)                       │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │         tty-clipboard Server (C)                         │   │
│  │  ┌──────────────┐           ┌──────────────┐           │   │
│  │  │ Port 5457    │           │ Port 5458    │           │   │
│  │  │ (Clipboard)  │           │ (Bridge)     │           │   │
│  │  └──────────────┘           └──────────────┘           │   │
│  │          ▲                          ▲                  │   │
│  │          │ WriteRequest             │                  │   │
│  │          │ DataFrame                │                  │   │
│  └──────────────────────────────────────────────────────────┘   │
│          ▲          ▲          ▲          ▲                     │
└──────────┼──────────┼──────────┼──────────┼─────────────────────┘
           │          │          │          │
     SSL/TLS          │          │          │
     Connection       │          │          │
           │          │          │          │
┌──────────▼──────────▼──────────▼──────────▼─────────────────────┐
│                      Local System                               │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │    C Bridge (tty-cb-wayland-bridge / klipper-bridge)    │  │
│  │                                                          │  │
│  │  ┌────────────────────────────────────────────────────┐ │  │
│  │  │          Plugin Interface                          │ │  │
│  │  │  ┌──────────────┐           ┌──────────────┐      │ │  │
│  │  │  │ Wayland      │           │ Klipper      │      │ │  │
│  │  │  │ Plugin       │           │ Plugin       │      │ │  │
│  │  │  │ (wl-paste)   │           │ (D-Bus)      │      │ │  │
│  │  │  └──────────────┘           └──────────────┘      │ │  │
│  │  └────────────────────────────────────────────────────┘ │  │
│  │                        ▲                                 │  │
│  │                        │ Metadata                        │  │
│  │                        │ (hostname, timestamp, UUID)     │  │
│  └────────────────────────┼─────────────────────────────────┘  │
│                          │                                      │
│         ┌────────────────┴─────────────────┐                   │
│         │                                  │                   │
│    ┌────▼────────┐              ┌─────────▼────┐               │
│    │   Wayland   │              │   Klipper    │               │
│    │ Clipboard   │              │  Clipboard   │               │
│    └─────────────┘              └──────────────┘               │
│         ▲                              ▲                        │
│         │                              │                        │
│    ┌────┴──────────────┬───────────────┴────┐                 │
│    │                   │                    │                 │
│  Copy/Paste         Copy/Paste         User Interaction       │
└────────────────────────────────────────────────────────────────┘
```

## Protocol Flow with Metadata

### 1. Local Clipboard → Server

```
Wayland/Klipper User Action
        │
        ▼
   Plugin reads
   clipboard content
        │
        ▼
  Bridge adds metadata:
  - hostname (from gethostname())
  - timestamp (from time())
  - write_uuid (generated)
        │
        ▼
  WriteRequest protobuf:
  {
    data: [clipboard bytes],
    hostname: "adalid",
    timestamp: 1704067200,
    write_uuid: [16-byte UUID]
  }
        │
        ▼
  TLS connection to server
        │
        ▼
  Server receives and stores
```

### 2. Server → Local Clipboard

```
Server broadcasts
to all subscribers
        │
        ▼
  DataFrame protobuf:
  {
    data: [clipboard bytes],
    hostname: "adalid",
    timestamp: 1704067200,
    write_uuid: [16-byte UUID],
    message_id: 42
  }
        │
        ▼
  Bridge receives
  over TLS
        │
        ▼
  Bridge checks:
  "Is this the same data
   we just sent?"
        │
   YES ───► Skip write
        │   (feedback loop prevention)
        │
   NO  ───► Compare with
             last received data
             │
        ▼
   NEW DATA ──► Plugin writes
                to local clipboard
                (with metadata
                 available via API)
```

## Feedback Loop Prevention

### The Problem

```
Without feedback loop prevention:

User copies on Wayland
        │
        ▼
Bridge sends to server
        │
        ▼
Server broadcasts
        │
        ▼
Bridge receives same data
        │
        ▼
Bridge writes back to Wayland
        │
        ▼
Wayland clipboard change event
        │
        ▼
Bridge detects change
        │
        ▼
Bridge sends to server (again!)
        │
        ▼
INFINITE LOOP!
```

### The Solution

Each bridge stores metadata of the last write it made in each direction:

```c
clipboard_data_t *last_local_data;   // Last data we wrote to local clipboard
clipboard_data_t *last_remote_data;  // Last data we sent to remote server
```

Before writing, the bridge checks:

```c
if (clipboard_data_equal(received_data, last_local_data)) {
    // This is the same data we just wrote
    // Skip to prevent feedback loop
    continue;
}
```

**Metadata-Based Comparison:**
- Compare raw bytes (full content)
- Compare hostname (origin)
- Compare timestamp (when it was written)
- Compare UUID (unique ID)

All four must match to consider it "the same write".

## Metadata Preservation

### In Client → Server

```c
WriteRequest wr = TTYCB__WRITE_REQUEST__INIT;
wr.data.data = clipboard_bytes;
wr.data.len = size;
wr.hostname = local_hostname;  // "adalid"
wr.timestamp = time(NULL);     // Unix timestamp
wr.write_uuid.data = uuid;     // Generated UUID
wr.write_uuid.len = 16;
```

### In Server → Subscribers

```c
DataFrame df = TTYCB__DATA_FRAME__INIT;
df.data.data = clipboard_bytes;
df.data.len = size;
df.hostname = request->hostname;  // Forwarded from WriteRequest
df.timestamp = request->timestamp;
df.write_uuid.data = request->write_uuid.data;
df.write_uuid.len = request->write_uuid.len;
```

### Debug Output with Metadata

```bash
$ tty-cb-client -vv read localhost
[DEBUG] Data from host: adalid, timestamp: 2024-01-01 00:00:00 UTC, size: 11 bytes
Hello World
```

## Plugin Architecture Benefits

### 1. Extensibility
Adding support for new clipboard managers (X11, macOS) requires only implementing the plugin interface:

```c
const plugin_interface_t x11_plugin = {
    .name = "x11",
    .init = x11_init,
    .read = x11_read,
    .write = x11_write,
    ...
};
```

### 2. Clean Separation
- Core bridge logic: `clipboard-bridge.c` (600 lines)
- Clipboard-specific code: Plugin files (100 lines each)
- No bash shell escaping issues
- No subprocess management complexity

### 3. Type Safety
- Protocol Buffers for message definition
- C type system prevents buffer overflows
- Compile-time checking

### 4. Performance
- Native compilation (no interpreter overhead)
- Efficient protobuf serialization
- Minimal memory allocation

## Thread Model

The bridge runs exactly two threads:

```
┌──────────────────────────────────────────────────────┐
│  Main Thread                                         │
│  - Parses arguments                                  │
│  - Initializes plugins and TLS                       │
│  - Creates worker threads                            │
│  - Waits for thread completion                       │
│  - Handles cleanup on signal                         │
└──────────────────────────────────────────────────────┘
         ▲                              ▲
         │                              │
         │ Start                        │ Join
         │                              │
┌────────┴──────────────┬───────────────┴──────────┐
│                       │                          │
│ ┌────────────────────▼────────────────┐          │
│ │  Local→Server Thread                │          │
│ │  - Poll local clipboard every 1s    │          │
│ │  - Detect changes                   │          │
│ │  - Send WriteRequest to server      │          │
│ │  - Check feedback loop prevention   │          │
│ └─────────────────────────────────────┘          │
│                                                   │
│                 data_mutex                        │
│                     ▲                             │
│                     │ Protect                     │
│                     │ last_local_data            │
│                     │ last_remote_data           │
│                     │                             │
│ ┌────────────────────▼────────────────┐          │
│ │  Server→Local Thread                │          │
│ │  - Call read_blocked() on server    │          │
│ │  - Wait for DataFrame               │          │
│ │  - Extract metadata                 │          │
│ │  - Write to local clipboard         │          │
│ │  - Check feedback loop prevention   │          │
│ └─────────────────────────────────────┘          │
└───────────────────────────────────────────────────┘
```

## Data Structures

### Metadata Structure

```c
typedef struct clipboard_metadata {
    char hostname[256];           // Origin hostname
    int64_t timestamp;            // Unix timestamp
    unsigned char write_uuid[16]; // Unique write identifier
} clipboard_metadata_t;
```

### Clipboard Data

```c
typedef struct clipboard_data {
    unsigned char *data;          // Raw clipboard bytes
    size_t size;                  // Size in bytes
    clipboard_metadata_t metadata;
} clipboard_data_t;
```

### Bridge Context

```c
typedef struct {
    const plugin_interface_t *plugin;
    plugin_handle_t plugin_handle;
    char server_host[256];
    uint16_t server_ports[2];
    char local_hostname[256];
    bridge_tls_ctx_t tls;
    volatile sig_atomic_t running;
    clipboard_data_t *last_local_data;
    clipboard_data_t *last_remote_data;
    pthread_mutex_t data_mutex;
} bridge_ctx_t;
```

## Security Considerations

1. **TLS/SSL**: All communication with server is encrypted
2. **Certificate Verification**: Optional CA certificate validation
3. **No Authentication**: Bridge uses server's existing security model
4. **Metadata Visibility**: Hostname/timestamp visible in debug output (by design)
5. **UUID Randomness**: Uses system entropy for write UUID generation

## Performance Characteristics

### Memory Usage
- Per clipboard operation: ~50KB (variable with content size)
- Typical resident set: 2-5MB
- Stack allocation: Minimal (heap for dynamic data)

### CPU Usage
- Idle: <1% CPU (sleeping on I/O)
- On clipboard change: Brief spike (~5-10ms processing)
- Network roundtrip: ~100-500ms (depends on latency)

### Latency
- Local→Server: ~100-200ms (including network + server processing)
- Server→Local: ~100-200ms (blocking wait reduces unnecessary polling)

## Comparison with Bash Bridges

| Aspect | Bash Bridge | C Bridge |
|--------|------------|----------|
| **Startup Time** | ~100ms | ~5ms |
| **Memory** | 10-20MB | 2-5MB |
| **Data Handling** | String-based | Binary-safe |
| **Metadata** | State files | Native structs |
| **Loop Prevention** | File-based tracking | In-memory matching |
| **Extensibility** | Script modifications | Plugin interface |
| **Type Safety** | None | Full C type safety |
| **Shell Dependency** | High | None |
| **Debugging** | Log files | Structured logging |

## Future Enhancements

1. **Dynamic Plugin Loading**: Load plugins from `.so` files at runtime
2. **Content Filtering**: Regex-based include/exclude patterns
3. **Compression**: DEFLATE compression for large transfers
4. **History Management**: Keep clipboard history with metadata
5. **X11 Support**: XClip/XSel plugin for traditional X servers
6. **macOS Support**: NSPasteboard plugin for macOS
7. **Network Resilience**: Automatic reconnection with exponential backoff
8. **Performance Monitoring**: Built-in metrics collection

## References

- **Protobuf Definition**: `proto/clipboard.proto`
- **Plugin Header**: `src/plugin.h`
- **Bridge Implementation**: `src/clipboard-bridge.c`
- **Wayland Plugin**: `src/wayland-plugin.c`
- **Klipper Plugin**: `src/klipper-plugin.c`
- **Build Configuration**: `src/meson.build`
