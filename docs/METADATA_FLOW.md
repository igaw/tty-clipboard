# Metadata Flow in TTY Clipboard System

## Overview

This document explains how metadata (hostname, timestamp, UUID) flows through the entire tty-clipboard system from a user copying text to another user reading it on a remote system.

## Complete Data Flow Example

### Scenario
- **Host A**: `adalid` (Linux desktop with Wayland)
- **Host B**: `remote-server` (SSH server running tty-clipboard)
- **Host C**: `other-desktop` (SSH from another location)

### Step-by-Step Flow

#### 1. User Copies on Host A (adalid)

```
[Host A: adalid]

User copies "Hello World" in Firefox
        ↓
Wayland clipboard manager updates
        ↓
tty-cb-wayland-bridge detects change
(running on adalid, listening to Wayland)
        ↓
wayland-plugin::read() executes:
    $ wl-paste
    Returns: "Hello World" (11 bytes)
        ↓
Bridge creates clipboard_data_t:
    {
        data: "Hello World",
        size: 11,
        metadata: {
            hostname: "adalid",  // From gethostname()
            timestamp: 1704067200,  // From time()
            write_uuid: {0x12, 0x34, 0x56, ...}  // Generated
        }
    }
```

#### 2. Bridge Sends to Server (adalid → remote-server)

```
Bridge creates WriteRequest:
    {
        data: [11 bytes of "Hello World"],
        hostname: "adalid",
        timestamp: 1704067200,
        write_uuid: {0x12, 0x34, 0x56, ...}
    }
        ↓
Protobuf serialization:
    ttycb__write_request__pack(wr, buffer)
        ↓
Add 8-byte length prefix (big-endian):
    uint64_t len = htobe64(packed_size)
        ↓
Send over TLS to server:PORT 5457
    SSL_write(socket, length_prefix, 8)
    SSL_write(socket, buffer, packed_size)
```

#### 3. Server Receives Write (remote-server)

```
[Host B: remote-server]

tty-cb-server running on PORT 5457
        ↓
Receives WriteRequest with metadata:
    hostname: "adalid"
    timestamp: 1704067200
    write_uuid: {0x12, 0x34, 0x56, ...}
        ↓
Server stores in shared buffer:
    shared_buffer = "Hello World"
    shared_length = 11
    shared_hostname = "adalid"
    shared_timestamp = 1704067200
    shared_write_uuid = {0x12, 0x34, 0x56, ...}
    shared_message_id = 1
        ↓
Server broadcasts to all connected clients:
    - Any clients on PORT 5458 (bridge ports)
    - Any clients on PORT 5457 (direct clients)
```

#### 4. Bridge on Host A Receives Response (adalid)

```
[Host A: adalid - feedback loop prevention]

Server→Local thread on adalid bridge
receives broadcast:
    DataFrame {
        data: "Hello World",
        hostname: "adalid",
        timestamp: 1704067200,
        write_uuid: {0x12, 0x34, 0x56, ...},
        message_id: 1
    }
        ↓
Bridge compares with last_local_data
(data we sent)
        ↓
clipboard_data_equal():
    - Content matches ✓
    - hostname matches ✓
    - timestamp matches ✓
    - UUID matches ✓
        ↓
DECISION: Skip write (this is our echo)
        ↓
LOG: [DEBUG] Skipping echo: data matches last local write
        ↓
No write to wayland-plugin (prevents feedback loop)
```

#### 5. Client on Host C Receives Data (other-desktop)

```
[Host C: other-desktop]

User runs:
    $ ssh -N -L 5457:localhost:5457 remote-server
    (Tunnels remote clipboard to local port 5457)
        ↓
Another user on Host C runs:
    $ tty-cb-client read localhost
        ↓
Client opens connection to localhost:5457
        ↓
Server sends DataFrame with full metadata:
    {
        data: "Hello World",
        hostname: "adalid",
        timestamp: 1704067200,
        write_uuid: {0x12, 0x34, 0x56, ...},
        message_id: 1
    }
        ↓
Client unpacks protobuf
        ↓
WITH -vv flag, shows:
    [DEBUG] Data from host: adalid
    [DEBUG] Timestamp: 2024-01-01 00:00:00 UTC
    [DEBUG] UUID: 12345678-...
    [DEBUG] Message ID: 1
    Hello World
        ↓
WITHOUT -vv flag, shows:
    Hello World
        ↓
User on Host C can see clipboard came from "adalid"!
```

## Metadata Use Cases

### Use Case 1: Multi-Host Debugging

**Scenario**: Multiple developers sharing clipboard server, want to know who changed it.

```
Alice on "alice-laptop":
  $ echo "Fix: use malloc instead of alloca" | \
    tty-cb-client write server.example.com
    
Bob on "bob-desktop" reads:
  $ tty-cb-client -vv read server.example.com
  [DEBUG] Data from host: alice-laptop, timestamp: 2024-01-01 12:34:56
  Fix: use malloc instead of alloca
  
  → Bob knows Alice just sent this
  → Bob can follow up: "Alice, I saw your fix"
```

### Use Case 2: Audit Trail

**Scenario**: Security-sensitive data needs clipboard history.

```
Bridge logs with timestamps:
  2024-01-01 12:00:00 Write from alice-laptop
  2024-01-01 12:15:00 Write from bob-desktop  
  2024-01-01 12:30:00 Read by alice-laptop
  2024-01-01 13:00:00 Write from alice-laptop
  
→ Complete audit trail of who accessed clipboard
→ Can match timestamps with terminal logs
```

### Use Case 3: Duplicate Detection

**Scenario**: Prevent infinite sync loops between mirrors.

```
Bridge A→Bridge B flow:
  Metadata: {hostname: "primary", timestamp: 1234567890}
  
Bridge B receives from Mirror C:
  Metadata: {hostname: "primary", timestamp: 1234567890}
  
→ SAME? Check all 4 fields:
   - Content ✓
   - hostname ✓  
   - timestamp ✓
   - UUID ✓
  
→ YES: Skip write → No loop!
```

## Protocol Implementation

### Protobuf Message Definition

```protobuf
message WriteRequest {
  bytes data = 1;              // Raw clipboard content
  uint64 client_id = 2;        // Client identifier
  bytes write_uuid = 3;        // Unique operation ID
  string hostname = 4;         // Origin hostname
  int64 timestamp = 5;         // Unix timestamp
}

message DataFrame {
  bytes data = 1;              // Raw clipboard content
  uint64 message_id = 2;       // Server-assigned message ID
  bytes write_uuid = 3;        // Original write UUID
  string hostname = 4;         // Origin hostname
  int64 timestamp = 5;         // Original timestamp
}
```

### Wire Protocol

```
WriteRequest message:

┌─────────────────────────────────────────────┐
│ 8-byte length (big-endian uint64)          │ Header
├─────────────────────────────────────────────┤
│ Protobuf packed WriteRequest                │
│ ┌───────────────────────────────────────┐  │
│ │ Field 1: data                        │  │
│ │   [11 bytes: "Hello World"]          │  │
│ ├───────────────────────────────────────┤  │
│ │ Field 3: write_uuid                  │  │
│ │   [16 bytes: unique UUID]            │  │
│ ├───────────────────────────────────────┤  │
│ │ Field 4: hostname                    │  │
│ │   [string: "adalid"]                 │  │
│ ├───────────────────────────────────────┤  │
│ │ Field 5: timestamp                   │  │
│ │   [int64: 1704067200]                │  │
│ └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

## Metadata Preservation Chain

### At Each Step

1. **Client Write**
   ```c
   wr.hostname = local_hostname;  // From gethostname()
   wr.timestamp = time(NULL);     // Current Unix time
   wr.write_uuid = generated_uuid;
   ```

2. **Server Receipt**
   ```c
   strcpy(shared_hostname, write_req->hostname);      // Preserve
   shared_timestamp = write_req->timestamp;           // Preserve
   memcpy(shared_write_uuid, write_req->write_uuid);  // Preserve
   ```

3. **Server Broadcast**
   ```c
   df.hostname = shared_hostname;          // Pass through
   df.timestamp = shared_timestamp;        // Pass through
   memcpy(df.write_uuid, shared_write_uuid);  // Pass through
   ```

4. **Bridge Receipt**
   ```c
   clipboard_data_t cdata;
   strncpy(cdata.metadata.hostname, frame->hostname);
   cdata.metadata.timestamp = frame->timestamp;
   memcpy(cdata.metadata.write_uuid, frame->write_uuid);
   ```

5. **Client Display**
   ```c
   if (debug_mode) {
       printf("Data from host: %s\n", metadata.hostname);
       printf("Timestamp: %ld\n", metadata.timestamp);
   }
   ```

## Memory Layout of Metadata

### On Stack (Fast Access)

```c
clipboard_metadata_t metadata = {
    // Offset 0: hostname[256]
    .hostname = "adalid",          // Variable length string
    
    // Offset 256: timestamp (int64_t)
    .timestamp = 1704067200,       // 8 bytes, signed
    
    // Offset 264: write_uuid[16]
    .write_uuid = {0x12, 0x34...}, // Exactly 16 bytes
};
// Total size: 256 + 8 + 16 = 280 bytes
```

### Protobuf Serialization

```
Field 4 (hostname) as string:
  - Varint: field_number << 3 | wire_type
  - Length-delimited: string length
  - Data: UTF-8 bytes

Field 5 (timestamp) as int64:
  - Varint: 0x28 (field 5, zigzag)
  - Varint encoded: integer value
```

## Error Handling

### Missing Metadata

```c
// Graceful degradation
if (!frame->hostname || strlen(frame->hostname) == 0) {
    strcpy(metadata.hostname, "unknown");
}

if (frame->timestamp == 0) {
    metadata.timestamp = time(NULL);  // Use current time
}

if (frame->write_uuid.len != UUID_SIZE) {
    memset(metadata.write_uuid, 0, UUID_SIZE);  // Zero UUID
}
```

### Metadata Comparison Edge Cases

```c
// Exact equality required for loop prevention
bool data_equal = (a->size == b->size) &&
                  (memcmp(a->data, b->data, a->size) == 0) &&
                  (strcmp(a->metadata.hostname, b->metadata.hostname) == 0) &&
                  (a->metadata.timestamp == b->metadata.timestamp) &&
                  (memcmp(a->metadata.write_uuid, b->metadata.write_uuid, 16) == 0);

// If ANY field differs → write the data
// This prevents false positives in loop detection
```

## Performance Impact

### CPU Cost

```
Per clipboard sync operation:

1. gethostname()      ~1μs
2. time()             ~1μs  
3. UUID generation    ~5μs (system entropy)
4. Protobuf pack      ~10μs (depends on size)
5. Metadata compare   ~1μs (fixed 280 bytes)

Total metadata overhead: ~20μs per operation
(Negligible compared to network latency ~100ms)
```

### Network Impact

```
WriteRequest size:
  - Field 1 (data):     variable
  - Field 3 (UUID):     ~20 bytes (protobuf encoded)
  - Field 4 (hostname): ~15 bytes (protobuf encoded)
  - Field 5 (timestamp): ~10 bytes (protobuf encoded)

Metadata overhead: ~45 bytes per message
(Negligible for typical clipboard operations >100 bytes)
```

## Debugging Metadata

### Enable Debug Output

```bash
# Show all metadata in debug mode
$ tty-cb-client -vv read localhost

# Shows:
# [DEBUG] Data from host: adalid
# [DEBUG] Timestamp: 2024-01-01 00:00:00 UTC
# [DEBUG] UUID: 12345678-9abc-def0-1234-567890abcdef
```

### Bridge Logs with Metadata

```bash
# Start bridge with debug
$ tty-cb-wayland-bridge --plugin wayland --server localhost -d

# Logs:
# [DEBUG] Received 11 bytes from server (from adalid)
# [DEBUG] Sending 11 bytes to server
# [DEBUG] Skipping echo: data matches last remote write
```

### Manual Inspection

```bash
# Write with specific content
$ echo "Test $(date)" | tty-cb-client write localhost

# Read back with metadata
$ tty-cb-client -vv read localhost

# Both hostname and timestamp show origin
```

## Metadata Lifecycle Diagram

```
┌─────────────────────────────────────────────────────┐
│                                                      │
│  User copies on Host A (hostname="adalid")           │
│       │                                              │
│       ▼                                              │
│  gethostname() → metadata.hostname = "adalid"        │
│  time() → metadata.timestamp = 1704067200           │
│  gen_uuid() → metadata.write_uuid = [16 bytes]       │
│       │                                              │
│       ▼                                              │
│  WriteRequest with metadata                          │
│       │                                              │
│       ▼                                              │
│  Bridge saves as last_remote_data:                   │
│  └─ metadata preserved in memory                     │
│       │                                              │
│       ▼                                              │
│  Server receives and stores in shared_*:             │
│  ├─ shared_hostname = "adalid"                       │
│  ├─ shared_timestamp = 1704067200                    │
│  └─ shared_write_uuid = [16 bytes]                   │
│       │                                              │
│       ▼                                              │
│  Server broadcasts DataFrame to all clients:         │
│  ├─ data: clipboard content                          │
│  ├─ hostname: "adalid" (preserved)                   │
│  ├─ timestamp: 1704067200 (preserved)                │
│  └─ write_uuid: [16 bytes] (preserved)               │
│       │                                              │
│  ┌────┴────────────────────────┐                     │
│  │                             │                     │
│  ▼                             ▼                     │
│ Bridge A          Bridge B (another host)           │
│ (adalid)          (other-desktop)                    │
│  │                 │                                │
│  ▼                 ▼                                │
│ Compare           Extract metadata                  │
│ with              for display                       │
│ last_local_data                                     │
│  │                 │                                │
│  ▼                 ▼                                │
│ MATCH ──────►      Shows:                           │
│ Skip write         "From: adalid"                    │
│ (loop prevent)     "Time: 2024-01-01..."             │
│                                                      │
│           ▼                                          │
│           Metadata available to remote user!         │
│                                                      │
└─────────────────────────────────────────────────────┘
```

## Conclusion

The metadata system enables:

1. **Traceability**: Know where clipboard data originated
2. **Deduplication**: Prevent infinite sync loops
3. **Audit Trail**: Complete history of clipboard operations
4. **User Awareness**: Context about clipboard changes
5. **System Debugging**: Identify connectivity and flow issues

All with negligible performance impact (~20μs overhead, ~45 bytes network cost).
