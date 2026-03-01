# Changelog

## [0.0.12] - 2026-03-01

### <!-- 0 -->⛰️  Features

- Track connection uptime in stats and fuzz decode matrix
- Enrich connection stats with recovery counters
- Route handshake_done and decode crypto frames
- Expose invalid packet stats and regressions
- Decode crypto and padding frames in receive loop
- Enforce long-header version policy and VN behavior
- Make draining timeout-based and idempotent
- Add version negotiation path and bit validation
- Tighten stream EOF and reset read semantics
- Harden stream overlap conflict policy
- Add out-of-order stream reassembly and final-size checks
- Add packet-space ACK validation and PTO tuning
- Enforce packet-space-aware ACK recovery
- Decode ACK delay using peer transport params
- Process full ACK packet sets in recovery
- Apply ACK range hints to recovery updates
- Validate ACK range encoding invariants
- Reject ACKs for unsent packet numbers
- Parse ACK ranges in receive path
- Detect stateless reset on header decode failure
- Harden retry state and expose retry scid
- Add retry integrity validation hook
- Process Retry packets in client receive flow
- Enforce token policy and stateless reset handling
- Add batch drain helper for CID control payloads
- Coalesce pending CID control frames into one payload
- Add queued NEW_CONNECTION_ID frame pop API
- Expose peer CID inventory read API
- Reject duplicate stateless reset tokens across peer CIDs
- Enforce active_connection_id_limit for peer CIDs
- Support monotonic retire_prior_to in NEW_CONNECTION_ID adverts
- Queue and encode local NEW_CONNECTION_ID advertisements
- Add helper to encode pending RETIRE_CONNECTION_ID frame
- Expose pending RETIRE_CONNECTION_ID pop API
- Decode and track NEW_CONNECTION_ID and RETIRE_CONNECTION_ID
- Decode and track BLOCKED family frame signals
- Apply MAX_STREAMS and MAX_STREAM_DATA frame updates
- Handle MAX_DATA frame updates at runtime
- Process multiple frames per received packet

### <!-- 6 -->🧪 Testing

- Verify invalid-packet counters on retry and VN paths
- Stress version handling under mixed packet flows
- Extend connecting and packet-space legality matrix
- Add initial and handshake mixed-ordering regressions
- Expand zero-rtt legality and mixed ordering coverage
- Expand handshake packet-space legality coverage
- Stress draining state under repeated stimuli
- Broaden frame decode boundary corpus
- Extend packet decode edge-case coverage
- Harden transport-params and close-state regressions
- Expand malformed varint boundary coverage
- Stress mixed-frame failure determinism
- Harden close and path malformed regressions
- Add ACK space and CID stress scenarios
- Stress CID edge cases and retire dedup
- Expand malformed packet negative corpus

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

