# Changelog

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

