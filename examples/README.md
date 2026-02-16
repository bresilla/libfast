# RunQUIC Examples

This directory contains example applications demonstrating how to use the RunQUIC library.

## Building Examples

Build all examples:
```bash
zig build
```

## SSH/QUIC Mode Examples

### SSH Echo Server

Minimal server that accepts SSH/QUIC connections and echoes data back.

```bash
zig build run-ssh-server
```

Features:
- SSH key exchange mode
- Obfuscation keyword authentication
- Stream handling
- Connection lifecycle management

### SSH Echo Client

Connects to SSH/QUIC server and sends test messages.

```bash
zig build run-ssh-client
```

## TLS/QUIC Mode Examples

### TLS Echo Server

Minimal server using standard TLS 1.3 handshake.

```bash
zig build run-tls-server
```

Features:
- TLS 1.3 mode
- Certificate-based authentication
- Compatible with HTTP/3 applications

### TLS Echo Client

Connects to TLS/QUIC server using standard TLS handshake.

```bash
zig build run-tls-client
```

## Implementation Status

**Note:** These examples demonstrate the intended API structure. Full connection handling is still in development.

**Implemented:**
- Configuration API (SSH and TLS modes)
- Connection initialization
- Event queue and types

**Not Yet Implemented (TODO):**
- Connection establishment (connect/accept methods are stubs)
- Stream operations (openStream is stub)
- Data transmission (streamWrite/streamRead are stubs)
- Event polling (poll method is stub)

## API Usage Patterns

### SSH Mode

```zig
const runquic = @import("runquic");

// Create SSH mode configuration
const config = runquic.QuicConfig.sshClient(
    "server.example.com",
    "obfuscation-keyword"
);

// Initialize connection
var conn = try runquic.QuicConnection.init(allocator, config);
defer conn.deinit();

// Connect to server
try conn.connect("192.0.2.1:4433");

// Open a stream
var stream = try conn.openStream();

// Send data
try stream.write("Hello, QUIC!");

// Receive data
var buf: [4096]u8 = undefined;
const n = try stream.read(&buf);
```

### TLS Mode

```zig
const runquic = @import("runquic");

// Create TLS mode configuration
const config = runquic.QuicConfig.tlsClient("server.example.com");

// Same connection API as SSH mode
var conn = try runquic.QuicConnection.init(allocator, config);
defer conn.deinit();

// The crypto layer is abstracted - stream I/O is identical
try conn.connect("192.0.2.1:443");
var stream = try conn.openStream();
try stream.write("GET / HTTP/3.0\r\n\r\n");
```

## Next Steps

To see the full implementation plan, refer to:
- `PLAN.md` - Complete implementation roadmap
- `lib/api/` - Public API implementation
- `lib/core/` - Core QUIC protocol
- `lib/crypto/` - SSH and TLS crypto modes
