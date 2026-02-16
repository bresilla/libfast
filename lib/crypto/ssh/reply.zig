const std = @import("std");
const varint = @import("../../utils/varint.zig");
const obfuscation = @import("obfuscation.zig");

/// SSH_QUIC_REPLY packet (Section 2.9)
///
/// Server's response to SSH_QUIC_INIT
///
/// Format:
///   byte        SSH_QUIC_REPLY = 2 (or SSH_QUIC_ERROR_REPLY = 254)
///   short-str   server-connection-id (MAY be empty)
///   uint32      server-quic-version (selected version)
///   string      server-quic-trnsp-params
///   byte        s = nr-server-sig-algs (MUST NOT be zero for normal reply)
///   string[s]   server-sig-algs (signature algorithms)
///   byte        k = nr-server-kex-algs (MUST NOT be zero for normal reply)
///   [repeated]  server-kex-alg entries
///   short-str   quic-tls-cipher-suite (single selected cipher)
///   byte        e = nr-ext-pairs
///   [repeated]  extension pairs
///   byte[0..]   padding (all 0xFF to meet amplification limits)
///
/// Error Reply Format:
///   byte        SSH_QUIC_ERROR_REPLY = 254
///   short-str   server-connection-id (empty)
///   uint32      0 (no version selected)
///   string      error-reason
///   byte[0..]   padding

pub const SSH_QUIC_REPLY: u8 = 2;
pub const SSH_QUIC_ERROR_REPLY: u8 = 254;

/// Amplification factor limit (3x client packet size)
pub const AMPLIFICATION_FACTOR: usize = 3;

pub const ReplyError = error{
    InvalidFormat,
    BufferTooSmall,
    EncodingFailed,
    DecodingFailed,
    AmplificationLimitExceeded,
    OutOfMemory,
} || varint.VarintError || obfuscation.ObfuscationError;

/// Key exchange algorithm entry (server side)
pub const ServerKexAlgorithm = struct {
    name: []const u8,
    data: []const u8, // Key exchange data from server

    pub fn isEmpty(self: ServerKexAlgorithm) bool {
        return self.data.len == 0;
    }
};

/// Extension pair
pub const ExtensionPair = struct {
    name: []const u8,
    data: []const u8,
};

/// SSH_QUIC_REPLY packet structure (success case)
pub const SshQuicReply = struct {
    server_connection_id: []const u8,
    server_quic_version: u32,
    transport_params: []const u8,
    signature_algorithms: []const []const u8,
    kex_algorithms: []const ServerKexAlgorithm,
    cipher_suite: []const u8, // Single selected cipher
    extensions: []const ExtensionPair,

    /// Encode SSH_QUIC_REPLY into buffer (unencrypted payload)
    pub fn encode(self: SshQuicReply, buf: []u8, max_size: usize) ReplyError!usize {
        var pos: usize = 0;

        // Packet type
        if (buf.len < 1) return error.BufferTooSmall;
        buf[pos] = SSH_QUIC_REPLY;
        pos += 1;

        // Server connection ID (short-str: 1 byte length + data)
        if (self.server_connection_id.len > 255) return error.InvalidFormat;
        if (pos + 1 + self.server_connection_id.len > buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(self.server_connection_id.len);
        pos += 1;
        @memcpy(buf[pos..][0..self.server_connection_id.len], self.server_connection_id);
        pos += self.server_connection_id.len;

        // Server QUIC version (selected)
        if (pos + 4 > buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u32, buf[pos..][0..4], self.server_quic_version, .big);
        pos += 4;

        // Transport parameters (string: varint length + data)
        pos += try varint.encode(self.transport_params.len, buf[pos..]);
        if (pos + self.transport_params.len > buf.len) return error.BufferTooSmall;
        @memcpy(buf[pos..][0..self.transport_params.len], self.transport_params);
        pos += self.transport_params.len;

        // Signature algorithms
        if (self.signature_algorithms.len == 0 or self.signature_algorithms.len > 255) {
            return error.InvalidFormat;
        }
        if (pos + 1 > buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(self.signature_algorithms.len);
        pos += 1;
        for (self.signature_algorithms) |sig_alg| {
            pos += try varint.encode(sig_alg.len, buf[pos..]);
            if (pos + sig_alg.len > buf.len) return error.BufferTooSmall;
            @memcpy(buf[pos..][0..sig_alg.len], sig_alg);
            pos += sig_alg.len;
        }

        // Key exchange algorithms
        if (self.kex_algorithms.len == 0 or self.kex_algorithms.len > 255) {
            return error.InvalidFormat;
        }
        if (pos + 1 > buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(self.kex_algorithms.len);
        pos += 1;
        for (self.kex_algorithms) |kex| {
            if (kex.name.len == 0 or kex.name.len > 255) return error.InvalidFormat;
            if (pos + 1 + kex.name.len > buf.len) return error.BufferTooSmall;
            buf[pos] = @intCast(kex.name.len);
            pos += 1;
            @memcpy(buf[pos..][0..kex.name.len], kex.name);
            pos += kex.name.len;

            pos += try varint.encode(kex.data.len, buf[pos..]);
            if (pos + kex.data.len > buf.len) return error.BufferTooSmall;
            @memcpy(buf[pos..][0..kex.data.len], kex.data);
            pos += kex.data.len;
        }

        // Cipher suite (short-str: single selected cipher)
        if (self.cipher_suite.len == 0 or self.cipher_suite.len > 255) {
            return error.InvalidFormat;
        }
        if (pos + 1 + self.cipher_suite.len > buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(self.cipher_suite.len);
        pos += 1;
        @memcpy(buf[pos..][0..self.cipher_suite.len], self.cipher_suite);
        pos += self.cipher_suite.len;

        // Extensions
        if (self.extensions.len > 255) return error.InvalidFormat;
        if (pos + 1 > buf.len) return error.BufferTooSmall;
        buf[pos] = @intCast(self.extensions.len);
        pos += 1;
        for (self.extensions) |ext| {
            if (ext.name.len == 0 or ext.name.len > 255) return error.InvalidFormat;
            if (pos + 1 + ext.name.len > buf.len) return error.BufferTooSmall;
            buf[pos] = @intCast(ext.name.len);
            pos += 1;
            @memcpy(buf[pos..][0..ext.name.len], ext.name);
            pos += ext.name.len;

            pos += try varint.encode(ext.data.len, buf[pos..]);
            if (pos + ext.data.len > buf.len) return error.BufferTooSmall;
            @memcpy(buf[pos..][0..ext.data.len], ext.data);
            pos += ext.data.len;
        }

        // Check amplification limit
        if (pos > max_size) {
            return error.AmplificationLimitExceeded;
        }

        // Padding to respect amplification limit
        if (pos < max_size and pos < buf.len) {
            const padding_len = @min(max_size - pos, buf.len - pos);
            @memset(buf[pos..][0..padding_len], 0xFF);
            pos += padding_len;
        }

        return pos;
    }

    /// Encode and encrypt SSH_QUIC_REPLY into obfuscated envelope
    pub fn encodeEncrypted(
        self: SshQuicReply,
        allocator: std.mem.Allocator,
        key: obfuscation.ObfuscationKey,
        client_init_size: usize,
        output: []u8,
    ) ReplyError!usize {
        // Calculate max size based on amplification factor
        const max_payload_size = client_init_size * AMPLIFICATION_FACTOR;

        // Encode plaintext
        var plaintext_buf = try allocator.alloc(u8, max_payload_size + 1024);
        defer allocator.free(plaintext_buf);

        const plaintext_len = try self.encode(plaintext_buf, max_payload_size);

        // Encrypt
        const encrypted_len = try obfuscation.ObfuscatedEnvelope.encrypt(
            plaintext_buf[0..plaintext_len],
            key,
            output,
        );

        return encrypted_len;
    }
};

/// SSH_QUIC_ERROR_REPLY packet structure
pub const SshQuicErrorReply = struct {
    error_reason: []const u8,

    /// Encode SSH_QUIC_ERROR_REPLY into buffer
    pub fn encode(self: SshQuicErrorReply, buf: []u8, max_size: usize) ReplyError!usize {
        var pos: usize = 0;

        // Packet type
        if (buf.len < 1) return error.BufferTooSmall;
        buf[pos] = SSH_QUIC_ERROR_REPLY;
        pos += 1;

        // Empty server connection ID
        if (pos + 1 > buf.len) return error.BufferTooSmall;
        buf[pos] = 0;
        pos += 1;

        // Version = 0 (no version selected)
        if (pos + 4 > buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u32, buf[pos..][0..4], 0, .big);
        pos += 4;

        // Error reason (string: varint length + data)
        pos += try varint.encode(self.error_reason.len, buf[pos..]);
        if (pos + self.error_reason.len > buf.len) return error.BufferTooSmall;
        @memcpy(buf[pos..][0..self.error_reason.len], self.error_reason);
        pos += self.error_reason.len;

        // Check amplification limit
        if (pos > max_size) {
            return error.AmplificationLimitExceeded;
        }

        // Padding
        if (pos < max_size and pos < buf.len) {
            const padding_len = @min(max_size - pos, buf.len - pos);
            @memset(buf[pos..][0..padding_len], 0xFF);
            pos += padding_len;
        }

        return pos;
    }

    /// Encode and encrypt SSH_QUIC_ERROR_REPLY into obfuscated envelope
    pub fn encodeEncrypted(
        self: SshQuicErrorReply,
        allocator: std.mem.Allocator,
        key: obfuscation.ObfuscationKey,
        client_init_size: usize,
        output: []u8,
    ) ReplyError!usize {
        // Calculate max size based on amplification factor
        const max_payload_size = client_init_size * AMPLIFICATION_FACTOR;

        // Encode plaintext
        var plaintext_buf = try allocator.alloc(u8, max_payload_size + 1024);
        defer allocator.free(plaintext_buf);

        const plaintext_len = try self.encode(plaintext_buf, max_payload_size);

        // Encrypt
        const encrypted_len = try obfuscation.ObfuscatedEnvelope.encrypt(
            plaintext_buf[0..plaintext_len],
            key,
            output,
        );

        return encrypted_len;
    }
};

// Tests

test "SSH_QUIC_REPLY encode basic" {
    const sig_algs = [_][]const u8{"ssh-ed25519"};
    const kex_algs = [_]ServerKexAlgorithm{
        .{ .name = "curve25519-sha256", .data = "server-key-data-here" },
    };

    const reply = SshQuicReply{
        .server_connection_id = &[_]u8{ 9, 10, 11, 12 },
        .server_quic_version = 0x00000001,
        .transport_params = &[_]u8{},
        .signature_algorithms = &sig_algs,
        .kex_algorithms = &kex_algs,
        .cipher_suite = "TLS_AES_256_GCM_SHA384",
        .extensions = &[_]ExtensionPair{},
    };

    var buf: [2048]u8 = undefined;
    const len = try reply.encode(&buf, 2048);

    try std.testing.expect(len > 0);
    try std.testing.expectEqual(SSH_QUIC_REPLY, buf[0]);
    try std.testing.expectEqual(@as(u8, 4), buf[1]); // Connection ID length
}

test "SSH_QUIC_REPLY encode and encrypt" {
    const allocator = std.testing.allocator;

    const sig_algs = [_][]const u8{"ssh-ed25519"};
    const kex_algs = [_]ServerKexAlgorithm{
        .{ .name = "curve25519-sha256", .data = "" },
    };

    const reply = SshQuicReply{
        .server_connection_id = &[_]u8{ 5, 6, 7, 8 },
        .server_quic_version = 0x00000001,
        .transport_params = &[_]u8{},
        .signature_algorithms = &sig_algs,
        .kex_algorithms = &kex_algs,
        .cipher_suite = "TLS_AES_256_GCM_SHA384",
        .extensions = &[_]ExtensionPair{},
    };

    const key = obfuscation.ObfuscationKey.fromKeyword("test-password");
    const client_init_size = 1200;

    var buf: [8192]u8 = undefined;
    const len = try reply.encodeEncrypted(allocator, key, client_init_size, &buf);

    try std.testing.expect(len > 0);
    try std.testing.expect(len <= client_init_size * AMPLIFICATION_FACTOR + obfuscation.ObfuscatedEnvelope.overhead());

    // Verify high bit of nonce is set
    try std.testing.expect((buf[0] & 0x80) != 0);
}

test "SSH_QUIC_REPLY amplification limit" {
    const sig_algs = [_][]const u8{"ssh-ed25519"};
    const kex_algs = [_]ServerKexAlgorithm{
        .{ .name = "curve25519-sha256", .data = "" },
    };

    const reply = SshQuicReply{
        .server_connection_id = &[_]u8{ 1, 2, 3, 4 },
        .server_quic_version = 0x00000001,
        .transport_params = &[_]u8{},
        .signature_algorithms = &sig_algs,
        .kex_algorithms = &kex_algs,
        .cipher_suite = "TLS_AES_256_GCM_SHA384",
        .extensions = &[_]ExtensionPair{},
    };

    var buf: [2048]u8 = undefined;

    // Test with reasonable max_size (simulating 3x client's 1200-byte INIT)
    const max_size = 3600; // 3x amplification factor
    const len = try reply.encode(&buf, max_size);
    try std.testing.expect(len <= max_size);

    // Test that data too large for max_size fails
    const tiny_max = 50; // Too small for the reply
    const result = reply.encode(&buf, tiny_max);
    try std.testing.expectError(error.AmplificationLimitExceeded, result);
}

test "SSH_QUIC_ERROR_REPLY encode" {
    const error_reply = SshQuicErrorReply{
        .error_reason = "Unsupported QUIC version",
    };

    var buf: [2048]u8 = undefined;
    const len = try error_reply.encode(&buf, 2048);

    try std.testing.expect(len > 0);
    try std.testing.expectEqual(SSH_QUIC_ERROR_REPLY, buf[0]);
    try std.testing.expectEqual(@as(u8, 0), buf[1]); // Empty connection ID
    try std.testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, buf[2..6], .big)); // Version = 0
}

test "SSH_QUIC_ERROR_REPLY encode and encrypt" {
    const allocator = std.testing.allocator;

    const error_reply = SshQuicErrorReply{
        .error_reason = "Protocol error",
    };

    const key = obfuscation.ObfuscationKey.fromKeyword("test");
    const client_init_size = 1200;

    var buf: [8192]u8 = undefined;
    const len = try error_reply.encodeEncrypted(allocator, key, client_init_size, &buf);

    try std.testing.expect(len > 0);
    try std.testing.expect(len <= client_init_size * AMPLIFICATION_FACTOR + obfuscation.ObfuscatedEnvelope.overhead());

    // Verify high bit of nonce is set
    try std.testing.expect((buf[0] & 0x80) != 0);
}
