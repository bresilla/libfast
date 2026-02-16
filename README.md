# RunQUIC

A standalone Zig QUIC transport library supporting both SSH key exchange and TLS 1.3 modes.

## Overview

RunQUIC provides a complete QUIC transport implementation (RFC 9000, 9002) with dual crypto modes:

- **SSH Key Exchange Mode** - For SSH applications (experimental spec)
- **TLS 1.3 Mode** - For HTTP/3 and standard QUIC applications (RFC 9001)

## Features

**Core QUIC Protocol**
- Connection management
- Stream multiplexing (bidirectional and unidirectional)
- Packet encoding/decoding
- Frame handling

**SSH/QUIC Crypto Mode**
- Obfuscated envelope (AEAD-AES-256-GCM)
- SSH key exchange (curve25519-sha256)
- Secret derivation (SSH K,H → QUIC secrets)
- No TLS overhead for SSH applications

**Standard TLS/QUIC**
- TLS 1.3 handshake
- Cipher suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305)
- Compatible with HTTP/3 applications

**Reliability & Performance**
- Flow control (stream and connection level)
- Loss detection (RFC 9002)
- RTT estimation
- Congestion control (NewReno)

## Quick Start

### Installation

Add RunQUIC as a dependency in your `build.zig`:

```zig
const runquic = b.dependency("runquic", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("runquic", runquic.module("runquic"));
```

### Usage Example (SSH Mode)

```zig
const std = @import("std");
const runquic = @import("runquic");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Configure SSH mode
    const config = runquic.QuicConfig.sshClient(
        "server.example.com",
        "obfuscation-keyword"
    );

    // Create connection
    var conn = try runquic.QuicConnection.init(allocator, config);
    defer conn.deinit();

    // Connect and use streams
    try conn.connect("192.0.2.1:4433");
    var stream = try conn.openStream();
    try stream.write("Hello, QUIC!");
}
```

### Usage Example (TLS Mode)

```zig
// Configure TLS mode
const config = runquic.QuicConfig.tlsClient("server.example.com");

// Same API - just different crypto mode
var conn = try runquic.QuicConnection.init(allocator, config);
// ... rest is identical
```

## Project Structure

```
lib/
├── runquic.zig              # Main entry point, public API
├── core/                    # Core QUIC protocol
│   ├── types.zig
│   ├── connection.zig
│   ├── stream.zig
│   ├── packet.zig
│   ├── frame.zig
│   ├── transport_params.zig
│   ├── flow_control.zig
│   ├── loss_detection.zig
│   └── congestion.zig
├── crypto/                  # Cryptographic layer
│   ├── crypto.zig          # Crypto abstraction
│   ├── aead.zig
│   ├── keys.zig
│   ├── header_protection.zig
│   ├── ssh/                # SSH key exchange mode
│   │   ├── obfuscation.zig
│   │   ├── init.zig
│   │   ├── reply.zig
│   │   ├── cancel.zig
│   │   ├── kex_methods.zig
│   │   └── secret_derivation.zig
│   └── tls/                # TLS 1.3 mode
│       ├── handshake.zig
│       ├── key_schedule.zig
│       └── tls_context.zig
├── api/                    # Public API
│   ├── config.zig
│   ├── types.zig
│   ├── connection.zig
│   └── stream.zig
├── transport/              # Transport layer
│   └── udp.zig
└── utils/                  # Utilities
    ├── varint.zig
    ├── buffer.zig
    └── time.zig
```

## Building

Build the library:
```bash
zig build
```

Run tests:
```bash
zig build test
```

Run examples:
```bash
zig build run-ssh-server
zig build run-ssh-client
zig build run-tls-server
zig build run-tls-client
```

## Testing

200+ unit tests covering:
- Core protocol (packets, frames, streams)
- SSH crypto (obfuscation, key exchange)
- TLS crypto (handshake, key schedule)
- Flow control and congestion control
- Loss detection and RTT estimation

```bash
zig build test --summary all
```

## Implementation Status

### Completed (Phase 1-8)
- Core QUIC types and constants
- Packet encoding/decoding
- Frame handling
- Variable-length integers
- UDP transport
- Connection state machine
- Stream management
- Transport parameters
- SSH obfuscation and key exchange
- TLS 1.3 handshake structures
- Common crypto layer (AEAD, keys, header protection)
- Flow control (stream and connection level)
- Loss detection (RFC 9002)
- Congestion control (NewReno)
- Public API design and implementation
- Connection establishment (connect/accept)
- Stream I/O (read/write operations)
- Integration layer (public API to internal components)
- Example applications
- Documentation

### Future Enhancements
- Path validation and migration
- Full integration testing
- Performance optimization
- Interoperability testing
- TLS certificate validation
- Out-of-order packet buffering

## Dependencies

RunQUIC uses only Zig's standard library:
- `std.crypto` - All cryptographic operations
- `std.net` - UDP sockets
- `std.mem` - Memory management
- `std.time` - Timers

No external dependencies required!

## Design Philosophy

1. **Library-First Approach** - RunQUIC is a transport library, not a full protocol implementation
   - QUIC transport and crypto
   - SSH protocol (implemented by applications like syslink)
   - HTTP/3 semantics (implemented by HTTP/3 applications)

2. **Dual Crypto Modes** - Support both SSH and TLS without code duplication
   - Unified connection/stream API
   - Mode-specific crypto layers
   - Same reliability mechanisms

3. **Clean Public API** - Easy to use, hard to misuse
   - `QuicConnection` and `QuicStream` handles
   - Configuration-driven setup
   - Clear error handling

## Documentation

- [PLAN.md](PLAN.md) - Complete implementation roadmap
- [TEST_COVERAGE.md](TEST_COVERAGE.md) - Test coverage report
- [examples/README.md](examples/README.md) - Example applications
- [ssh_quic_spec.md](ssh_quic_spec.md) - SSH/QUIC specification

## References

### QUIC Standards
- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) - QUIC Transport
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001) - Using TLS to Secure QUIC
- [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002) - Loss Detection and Congestion Control

### SSH Standards
- [RFC 4251-4254](https://www.rfc-editor.org/rfc/rfc4251) - SSH Protocol
- [RFC 8731](https://www.rfc-editor.org/rfc/rfc8731) - Curve25519-SHA256

### Implementation References
- [quiche](https://github.com/cloudflare/quiche) - Cloudflare's Rust QUIC
- [ngtcp2](https://github.com/ngtcp2/ngtcp2) - C QUIC implementation

## License

[License information to be added]

## Version

Current version: **0.3.0**

- Core QUIC protocol implemented and tested
- SSH and TLS crypto modes functional
- Flow control and reliability complete
- Public API implemented and stable
- Integration layer complete
- 200 unit tests passing
- Examples and documentation complete
