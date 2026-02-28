# Changelog

## [0.0.11] - 2026-02-28

### <!-- 0 -->⛰️  Features

- Support server-side tls handshake completion path
- Add server-side tls clienthello processing API
- Add serverhello builder from clienthello
- Integrate server alpn selection from clienthello
- Enforce zero-rtt frame allowlist with regressions
- Enforce strict initial handshake frame allowlist
- Enforce crypto frame legality by packet space
- Tighten handshake_done legality across packet spaces
- Tighten unknown reserved frame handling by packet space
- Propagate alpn mismatch as deterministic handshake close
- Add server-side alpn selection policy helper
- Normalize negotiation result across tls and ssh
- Add explicit mode capability matrix
- Enforce packet-space frame legality matrix
- Require integrated tls server hello for readiness
- Consume tls transport params from server hello
- Enforce tls alpn verification and establish gating
- Gate stream read and close on negotiation readiness
- Gate app stream traffic on negotiated handshake
- Add handshake negotiated readiness check
- Add negotiation snapshot API
- Expose negotiated alpn in connected metadata
- Wire tls config alpn into connect handshake
- Parse tls extensions and capture alpn
- Encode tls extensions and client params
- Refine connection state transitions and frame validation

### <!-- 1 -->🐛 Bug Fixes

- Reject reserved frame types in application space
- Unify tls handshake failure taxonomy and close mapping
- Validate ssh handshake transport params
- Close on stream receive flow control violations
- Enforce local receive stream data limits
- Enforce negotiated per-stream data limits
- Apply peer transport params via API
- Enforce transport parameter validation and stream limits

### <!-- 6 -->🧪 Testing

- Add targeted loss detection and ack safety regressions
- Add targeted pto and ack-eliciting recovery regressions
- Harden connection-level flow-control edge conformance
- Add packet-space frame legality matrix baseline
- Extend packet-space legality regressions for token and cid frames
- Add ALPN boundary validation in integrated tls path
- Reject duplicate tls extensions in integrated handshake path
- Expand tls handshake failure matrix coverage
- Add paired tls ssh regression scenarios
- Enforce closeStream readiness semantics

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Add dedicated dual-mode regression ci target

## [0.0.10] - 2026-02-27

### <!-- 1 -->🐛 Bug Fixes

- Correctly parse multiple frames in a single packet

## [0.0.9] - 2026-02-27

### <!-- 1 -->🐛 Bug Fixes

- Handle immediate shutdown errors in main loop

## [0.0.7] - 2026-02-24

### <!-- 0 -->⛰️  Features

- Implement robust flow control and keep-alive

## [0.0.6] - 2026-02-22

### <!-- 0 -->⛰️  Features

- Handle challenge-response validation and amplification gates
- Enforce send budget from cwnd and amplification
- Schedule retransmissions and PTO probes
- Wire ack handling into loss and congestion state
- Finalize draining-to-closed transition semantics
- Route stream reset and stop frames into state
- Decode and route control frames in poll loop
- Enforce bidirectional stream policy and channel IDs
- Make closeStream send FIN with half-close behavior
- Encode and decode variable-length packet numbers
- Add peer certificate and hostname verification hooks
- Enforce tls peer verification policy invariants
- Verify Finished data during handshake completion
- Track real handshake transcript bytes
- Parse ServerHello and validate cipher suite
- Parse inbound packet headers in poll loop

### <!-- 1 -->🐛 Bug Fixes

- Align connection lifecycle with transport and event types

### <!-- 2 -->🚜 Refactor

- Remove page allocator usage in secret derivation

### <!-- 3 -->📚 Documentation

- Mark release and compliance slice done
- Mark fuzz and negative testing slice done
- Mark path validation slice done
- Mark secret lifecycle hardening slice done
- Mark recovery harness slice done
- Mark congestion wiring slice done
- Mark retransmission scheduler slice done
- Mark ack integration slice done
- Mark connection close semantics slice done
- Mark stream receive send slice done
- Mark frame decode coverage slice done
- Mark ssh cleanup compatibility slice done
- Mark ssh bidi stream policy slice done
- Mark fin close semantics slice done
- Mark packet number slice done
- Mark handshake vector slice done
- Mark certificate validation slice done
- Mark certificate validation slice in progress
- Mark transcript and finished slice done
- Mark transcript slice in progress
- Mark tls serverhello slice done
- Mark epoch 1 slices as done
- Define production-readiness epochs and slices

### <!-- 6 -->🧪 Testing

- Add malformed decode corpus and fuzz smoke tests
- Relax reordering retransmit bound for stability
- Add loss reordering and timeout stress scenarios
- Stabilize ack congestion integration assertion
- Validate ssh transport cleanup flow control behavior
- Add deterministic handshake vector and state machine guards

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Remove completed roadmap file
- Add ci gates license and security policy

## [0.0.5] - 2026-02-22

### <!-- 0 -->⛰️  Features

- Rename project to libfast

## [0.0.4] - 2026-02-16

### <!-- 0 -->⛰️  Features

- Add examples and documentation (Phase 7.1)
- Add transport parameters (Phase 2.3)
- Add congestion control (Phase 6.3)
- Add loss detection and RTT estimation (Phase 6.2)
- Add flow control (Phase 6.1)
- Add TLS 1.3 handshake and key schedule (Phase 5)
- Add public API (QuicConnection, QuicStream, QuicConfig)
- Add common crypto layer (AEAD, keys, header protection)
- Add SSH key exchange methods and secret derivation
- Add SSH_QUIC_REPLY and SSH_QUIC_CANCEL packets
- Add SSH_QUIC_INIT packet encoding
- Add SSH/QUIC obfuscated envelope
- Add buffer and time utilities
- Add connection state machine
- Add stream management
- Add UDP socket transport
- Add QUIC frame types and encoding
- Add packet header encoding and decoding
- Add main library entry point
- Add variable-length integer encoding
- Add core types and constants
- Init

### <!-- 1 -->🐛 Bug Fixes

- Remove emojis and clarify implementation status in examples README
- Remove emojis from README

### <!-- 6 -->🧪 Testing

- Add SSH key exchange packet flow integration test
- Add integration tests and coverage documentation

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Update Makefile for release process and lib name
- Remove TEST_COVERAGE.md and check_crypto.o

## [0.0.3] - 2026-02-16

### <!-- 0 -->⛰️  Features

- Add examples and documentation (Phase 7.1)
- Add transport parameters (Phase 2.3)
- Add congestion control (Phase 6.3)
- Add loss detection and RTT estimation (Phase 6.2)
- Add flow control (Phase 6.1)
- Add TLS 1.3 handshake and key schedule (Phase 5)
- Add public API (QuicConnection, QuicStream, QuicConfig)
- Add common crypto layer (AEAD, keys, header protection)
- Add SSH key exchange methods and secret derivation
- Add SSH_QUIC_REPLY and SSH_QUIC_CANCEL packets
- Add SSH_QUIC_INIT packet encoding
- Add SSH/QUIC obfuscated envelope
- Add buffer and time utilities
- Add connection state machine
- Add stream management
- Add UDP socket transport
- Add QUIC frame types and encoding
- Add packet header encoding and decoding
- Add main library entry point
- Add variable-length integer encoding
- Add core types and constants
- Init

### <!-- 1 -->🐛 Bug Fixes

- Remove emojis and clarify implementation status in examples README
- Remove emojis from README

### <!-- 6 -->🧪 Testing

- Add SSH key exchange packet flow integration test
- Add integration tests and coverage documentation

### <!-- 7 -->⚙️ Miscellaneous Tasks

- Update Makefile for release process and lib name
- Remove TEST_COVERAGE.md and check_crypto.o

