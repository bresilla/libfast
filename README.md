# libfast

QUIC transport engine in Zig with dual security modes.

## Overview

`libfast` runs the same QUIC transport API with two handshake/security paths:

- **QUIC-over-TLS** for standards-aligned QUIC workflows.
- **QUIC-over-SSH** for SSH-style key exchange and host-key trust workflows.

Core transport behavior (streams, loss recovery, congestion, flow control) stays the same across both modes.

## Core Capabilities

- Connection lifecycle and stream multiplexing
- Packet/frame encode/decode
- Flow control and NewReno congestion control
- Loss detection and RTT tracking
- TLS and SSH security mode integration under one API

## Build and Test

```bash
make build
make test
make test-dual-mode
```

## Docs

- See `docs/` for package documentation and notes.
- If `docs/` is currently sparse, it is the canonical place for upcoming docs.

## Acknowledgments

- See `ACKNOWLEDGMENTS.md`.

## Version

- Current package version: `0.0.14`
