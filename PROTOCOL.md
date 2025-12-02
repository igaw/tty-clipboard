# tty-clipboard Wire Protocol

This document describes the on-the-wire framing between `tty-cb-client` and `tty-cb-server` over a mutually authenticated TLS (OpenSSL) connection.

## Transport Layer
- **Security:** TLS with mutual (client + server) X.509 certificate authentication.
- **Port:** Single TCP port (`SERVER_PORT`, default 5457) for all operations.
- **Reliability:** Stream (TCP); protocol adds minimal framing for message delineation.

## High-Level Flow
1. TCP connect
2. TLS handshake (mutual auth) – connection aborted on certificate failure
3. Client sends a single ASCII command line: `read`, `write`, or `read_blocked` followed by `\n`.
4. Server dispatches handler based on command.
5. Handler-specific message exchange (described below).
6. Connection ends (server side initiates graceful shutdown after response or client may close after consuming data). For `read_blocked`, connection persists sending multiple updates until terminated by signal or disconnect.

## Commands
| Command        | Direction | Purpose                                  |
|----------------|-----------|------------------------------------------|
| `write`        | C → S     | Upload clipboard content                 |
| `read`         | C → S     | Fetch current clipboard content          |
| `read_blocked` | C → S     | Stream updates whenever clipboard changes|

Maximum command length accepted: `CMD_MAX_LEN` (currently 32 bytes). Unknown commands are ignored and connection closed.
- **Status Byte (Write Acknowledgement):** 1 byte following a write payload:
  - `0x00`: Success (clipboard updated)
  - `0x01`: Failure (oversize rejection, memory allocation error, or discard policy triggered)

## Message Framing Per Operation
### WRITE
```
Client → Server:
+----------------+----------------------+--------------+-----------------+
| Length Prefix  | Payload (raw bytes)  | (no trailing | (any binary)    |
| 8 bytes BE     | N bytes              | sentinel)    |                 |
+----------------+----------------------+--------------+-----------------+

Server → Client:
+-------------+
| Status Byte |
| 0x00 or 0x01|
+-------------+
```
Notes:
- Server reads prefix, then the exact number of payload bytes.
- Oversize handling depends on policy (see below).
- No further data are sent after the status byte for this command.

### READ
```
Client → Server:
(command line already sent)

Server → Client:
+----------------+----------------------+ 
| Length Prefix  | Payload (raw bytes)  |
| 8 bytes BE     | N bytes (may be 0)   |
+----------------+----------------------+ 
```
If length is `0`, no payload bytes follow.

### READ_BLOCKED
Initial response identical to a single READ; followed by zero or more update frames whenever the clipboard changes:
```
Server → Client (repeats):
+----------------+----------------------+ 
| Length Prefix  | Payload (raw bytes)  |
| 8 bytes BE     | N bytes (may be 0)   |
+----------------+----------------------+ 
```
Termination conditions:
- Client disconnects
- Server receives termination signal (SIGINT) and broadcasts shutdown

## Oversize Policy
Configured via `--max-size <limit>` and `--oversize-policy <reject|drop>`.
- **max-size = 0:** Unlimited.
- **reject:** Server discards incoming payload bytes, then sends status `0x01` (clipboard unchanged). Client exits non-zero.
- **drop:** Server discards incoming payload bytes, sends status `0x00` ONLY if discard succeeded? (Implementation currently sends `0x00` for successful discard, `0x01` if discard failed). Client treats it as success; clipboard unchanged.

### Discard Procedure
For oversize payloads the server:
1. Reads and ignores payload in fixed chunks (64 KiB).
2. After all bytes consumed (or failure), sends status byte.
3. Returns to normal shutdown logic.

## Error Handling
Server-sent failure for write (`status = 0x01`) occurs for:
- Oversize with reject policy
- Allocation failure for temporary buffer
- Failure while discarding oversize data (I/O error) even under drop policy
- Failure reading the declared payload

Reads (`read` / `read_blocked`) do not have a status byte; failure modes cause connection closure. Client should treat unexpected EOF before full prefix/payload as error.

## Endianness
- Length prefix is big-endian (`htobe64` / `be64toh`). Cross-platform safe.

## Concurrency & Ordering
- Server uses a generation counter (`gen`) incremented after successful write storage.
- `read_blocked` waits until `gen` changes and then emits a new frame.
- Frames are atomic at the TLS record/application level: client must always read exactly 8 bytes for prefix before reading payload.

## Empty Payloads
- Length prefix `0` is allowed (clipboard empty). For writes: accepted and clipboard becomes empty, status `0x00`.

## Client Responsibilities
- Send command line terminated by `\n`.
- For writes: after sending prefix + payload, read 1 status byte. Non-zero → exit failure.
- For read_blocked: loop reading frames until connection closes; ignore zero-length frames.

## Security Considerations
- Mutual TLS prevents unauthenticated use.
- Max size + oversize policy mitigate memory DoS.
- Dropping oversize still consumes network bandwidth; `reject` conserves some server-side CPU after initial discard.

## Extensibility
Potential reserved future additions:
- Multi-byte status block (e.g., reason codes, server metrics)
- Compression flag (bitmap preceding length prefix)
- Streaming chunk framing (multiple payload segments per write)

Backwards compatibility strategy:
- Any extension should use a capability negotiation command or reserve high bits in status byte (e.g., `0x80` set indicates extended status follows).

## Example Hex Transcript
Write 5 bytes `hello` (ASCII):
```
Client→Server: "write\n"
Client→Server: 00 00 00 00 00 00 00 05 68 65 6c 6c 6f
Server→Client: 00
```
Read after write:
```
Client→Server: "read\n"
Server→Client: 00 00 00 00 00 00 00 05 68 65 6c 6c 6f
```
Oversize reject (limit 4, payload 5):
```
Client→Server: "write\n"
Client→Server: 00 00 00 00 00 00 00 05 68 65 6c 6c 6f
Server discards 5 bytes
Server→Client: 01
```
Client exits failure.

## Versioning
Protocol changes should increment software version (`VERSION` macro) and update this document. Consider adding a `--protocol-version` option for scripting.

---
Generated: 2025-12-01
