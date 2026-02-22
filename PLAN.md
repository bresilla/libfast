# libfast Production Readiness Plan

This plan tracks the path from prototype to production-ready QUIC library.

## Epoch 1 - Handshake and Connection Correctness

### Slice 1.1 - API event consistency [done]
- Fix `stream_closed` event payload shape to match public API types.
- Add regression tests for event payload correctness.

### Slice 1.2 - Connection lifecycle correctness [done]
- Remove premature connected signaling from `connect()`.
- Emit `connected` exactly once when connection transitions in `poll()`.
- Add tests for event ordering (`connect` then `poll` then `connected`).

### Slice 1.3 - Transport API wiring [done]
- Replace non-existent UDP initialization calls with real socket bind paths.
- Ensure client binds ephemeral local port and server binds configured address.
- Normalize address parsing to IPv4/IPv6 capable parser.

### Slice 1.4 - Packet receive pipeline (MVP) [done]
- In `poll()`, receive datagrams and parse packet headers.
- Convert parse failures into protocol/network events or errors.
- Track basic receive counters and packet visibility for future loss logic.

## Epoch 2 - TLS 1.3/QUIC Handshake Compliance

### Slice 2.1 - ServerHello parsing [done]
- Parse selected cipher suite from ServerHello rather than hardcoding.
- Reject unsupported versions/cipher suites with explicit errors.

### Slice 2.2 - Transcript and Finished verification [done]
- Build transcript from real handshake bytes.
- Verify Finished MAC before marking handshake complete.

### Slice 2.3 - Certificate path validation [done]
- Validate certificate chain and hostname for client mode.
- Add config options for trust anchors and verification policy.

### Slice 2.4 - Handshake test vectors [done]
- Add deterministic handshake vectors and negative tests.
- Validate state machine transitions and failure modes.

## Epoch 3 - Packet, Frame, and Stream Runtime

### Slice 3.1 - Packet number semantics [done]
- Implement variable packet number length encode/decode paths.
- Integrate PN protection bits with header protection flow.

### Slice 3.2 - Frame decode coverage [done]
- Add decode implementations for frequently used control frames.
- Route decoded frames into stream and connection state updates.

### Slice 3.3 - Stream receive/send loop [done]
- Wire STREAM/RESET/STOP handling into stream manager state.
- Emit `stream_readable` and `stream_closed` events from real traffic.

### Slice 3.4 - Connection close semantics [done]
- Encode/decode close frames and transition draining/closed correctly.
- Preserve peer error code and reason through public events.

### Slice 3.5 - FIN-based stream close semantics [done]
- Implement `closeStream(stream_id)` as graceful FIN (not reset/abort).
- Ensure peer-side EOF signaling on FIN and support half-close behavior.
- Add integration tests for close/write/read ordering across both peers.

### Slice 3.6 - SSH/QUIC bidirectional stream policy [done]
- Enforce bidirectional streams for SSH channel mapping.
- Reject or ignore unidirectional stream open attempts in SSH/QUIC mode.
- Add tests for stream ID parity and initiator rules (client: 4,8,12; server: 5,9,13).

### Slice 3.7 - SSH transport cleanup compatibility tests [done]
- Add integration tests proving no dependence on SSH `initial_window_size`/`maximum_packet_size`.
- Assert behavior without SSH-level `CHANNEL_WINDOW_ADJUST` semantics.
- Validate concurrent channel streams over QUIC-only flow control.

## Epoch 4 - Reliability and Congestion Behavior

### Slice 4.1 - ACK integration [done]
- Feed ACK ranges into loss detection state.
- Update in-flight accounting and RTT sampling from ACKed packets.

### Slice 4.2 - Retransmission scheduler [done]
- Retransmit lost ack-eliciting frames with PTO-based probing.
- Avoid spurious retransmits across packet number spaces.

### Slice 4.3 - Congestion controller wiring [done]
- Integrate NewReno cwnd updates with send pacing decisions.
- Enforce send budget under congestion and amplification limits.

### Slice 4.4 - Recovery test harness [done]
- Add scenario tests for loss, reordering, and timeouts.
- Assert bounded recovery time and stable behavior under stress.

## Epoch 5 - Security Hardening and Operational Readiness

### Slice 5.1 - Secret lifecycle hardening [done]
- Remove page allocator usage in secret derivation paths.
- Zeroize transient sensitive buffers consistently.

### Slice 5.2 - Path validation and anti-amplification [done]
- Implement PATH_CHALLENGE/PATH_RESPONSE behavior.
- Enforce pre-validation amplification budget on server.

### Slice 5.3 - Fuzzing and negative testing [done]
- Add fuzz targets for packet/frame/varint decode.
- Add malformed input corpus and crash regression suite.

### Slice 5.4 - Release and compliance
- Finalize license and security reporting policy.
- Add interop CI matrix and publish release gates.

## Definition of Done

- Handshake and connection logic no longer relies on simplified shortcuts.
- TLS path validates server identity and rejects invalid peers.
- Packet/frame paths are interoperable with at least one external QUIC stack.
- Reliability behavior (loss detection/retransmit/congestion) is integrated.
- CI includes unit, integration, and security regression coverage.
