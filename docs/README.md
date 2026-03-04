# libfast Documentation

## What this package does

`libfast` is a QUIC transport engine with a unified API that supports two security modes:

- QUIC-over-TLS
- QUIC-over-SSH

The key design value is that stream/connection behavior stays the same while the security path is selected by configuration.

## Core responsibilities

- QUIC packet and frame processing
- connection lifecycle/state transitions
- stream multiplexing
- flow control
- loss detection and RTT tracking
- congestion control (NewReno)
- transport integration with TLS and SSH security paths

## Security mode model

### QUIC-over-TLS

Use when you need standard QUIC/TLS behavior.

- standard QUIC security model
- suitable for HTTP/3-style deployments
- certificate-driven trust model

### QUIC-over-SSH

Use when you need SSH-style key exchange/trust behavior.

- SSH-style KEX and host-key semantics
- suited to SSH-like remote access workflows
- known-host/fingerprint-oriented trust model

Both modes share identical stream and transport semantics.

## Public API usage pattern

Typical flow:

1. Build a `QuicConfig` for TLS or SSH mode.
2. Initialize `QuicConnection`.
3. Connect/accept.
4. Run `poll()` loop.
5. Consume events and perform stream I/O.

Mode-specific choice happens at config creation time; the runtime API remains uniform.

## Build and test

```bash
make build
make test
make test-dual-mode
```

## Testing strategy

- unit tests for packet/frame/stream/core behavior
- dual-mode regression checks across TLS and SSH paths
- parity/interoperability checks and vectors where applicable

## Version

- `0.0.14`
