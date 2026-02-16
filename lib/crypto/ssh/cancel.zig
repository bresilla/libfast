const std = @import("std");
const varint = @import("../../utils/varint.zig");
const obfuscation = @import("obfuscation.zig");

/// SSH_QUIC_CANCEL packet (Section 2.10)
///
/// Either party can send this to abort the key exchange
///
/// Format:
///   byte        SSH_QUIC_CANCEL = 3
///   string      reason-phrase (human-readable error description)
///   byte        e = nr-ext-pairs (MAY be zero)
///   [repeated]  extension pairs
///   byte[0..]   padding (all 0xFF, optional)

pub const SSH_QUIC_CANCEL: u8 = 3;

pub const CancelError = error{
    InvalidFormat,
    BufferTooSmall,
    EncodingFailed,
    DecodingFailed,
    OutOfMemory,
} || varint.VarintError || obfuscation.ObfuscationError;

/// Extension pair
pub const ExtensionPair = struct {
    name: []const u8,
    data: []const u8,
};

/// SSH_QUIC_CANCEL packet structure
pub const SshQuicCancel = struct {
    reason_phrase: []const u8,
    extensions: []const ExtensionPair,

    /// Create a cancel packet with a simple reason
    pub fn init(reason: []const u8) SshQuicCancel {
        return SshQuicCancel{
            .reason_phrase = reason,
            .extensions = &[_]ExtensionPair{},
        };
    }

    /// Create cancel for unsupported version
    pub fn unsupportedVersion() SshQuicCancel {
        return init("Unsupported QUIC version");
    }

    /// Create cancel for unsupported key exchange
    pub fn unsupportedKex() SshQuicCancel {
        return init("No compatible key exchange algorithm");
    }

    /// Create cancel for unsupported cipher suite
    pub fn unsupportedCipherSuite() SshQuicCancel {
        return init("No compatible cipher suite");
    }

    /// Create cancel for protocol error
    pub fn protocolError(reason: []const u8) SshQuicCancel {
        return init(reason);
    }

    /// Encode SSH_QUIC_CANCEL into buffer (unencrypted payload)
    pub fn encode(self: SshQuicCancel, buf: []u8) CancelError!usize {
        var pos: usize = 0;

        // Packet type
        if (buf.len < 1) return error.BufferTooSmall;
        buf[pos] = SSH_QUIC_CANCEL;
        pos += 1;

        // Reason phrase (string: varint length + data)
        pos += try varint.encode(self.reason_phrase.len, buf[pos..]);
        if (pos + self.reason_phrase.len > buf.len) return error.BufferTooSmall;
        @memcpy(buf[pos..][0..self.reason_phrase.len], self.reason_phrase);
        pos += self.reason_phrase.len;

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

        // No mandatory padding (unlike INIT and REPLY)
        return pos;
    }

    /// Encode SSH_QUIC_CANCEL with optional padding
    pub fn encodeWithPadding(self: SshQuicCancel, buf: []u8, min_size: usize) CancelError!usize {
        const base_len = try self.encode(buf);

        // Add padding if needed
        if (base_len < min_size) {
            const padding_len = @min(min_size - base_len, buf.len - base_len);
            if (base_len + padding_len > buf.len) return error.BufferTooSmall;
            @memset(buf[base_len..][0..padding_len], 0xFF);
            return base_len + padding_len;
        }

        return base_len;
    }

    /// Encode and encrypt SSH_QUIC_CANCEL into obfuscated envelope
    pub fn encodeEncrypted(
        self: SshQuicCancel,
        allocator: std.mem.Allocator,
        key: obfuscation.ObfuscationKey,
        output: []u8,
    ) CancelError!usize {
        // Encode plaintext (no mandatory padding for CANCEL)
        var plaintext_buf = try allocator.alloc(u8, 1024);
        defer allocator.free(plaintext_buf);

        const plaintext_len = try self.encode(plaintext_buf);

        // Encrypt
        const encrypted_len = try obfuscation.ObfuscatedEnvelope.encrypt(
            plaintext_buf[0..plaintext_len],
            key,
            output,
        );

        return encrypted_len;
    }

    /// Decode SSH_QUIC_CANCEL from buffer
    pub fn decode(allocator: std.mem.Allocator, buf: []const u8) CancelError!SshQuicCancel {
        var pos: usize = 0;

        // Verify packet type
        if (buf.len < 1) return error.BufferTooSmall;
        if (buf[pos] != SSH_QUIC_CANCEL) return error.InvalidFormat;
        pos += 1;

        // Read reason phrase
        const reason_result = try varint.decode(buf[pos..]);
        pos += reason_result.len;
        const reason_len = reason_result.value;

        if (pos + reason_len > buf.len) return error.BufferTooSmall;
        const reason_phrase = try allocator.dupe(u8, buf[pos..][0..reason_len]);
        pos += reason_len;

        // Read extensions
        if (pos >= buf.len) return error.BufferTooSmall;
        const nr_ext = buf[pos];
        pos += 1;

        var extensions = try allocator.alloc(ExtensionPair, nr_ext);
        errdefer allocator.free(extensions);

        for (0..nr_ext) |i| {
            // Extension name
            if (pos >= buf.len) return error.BufferTooSmall;
            const name_len = buf[pos];
            pos += 1;

            if (name_len == 0) return error.InvalidFormat;
            if (pos + name_len > buf.len) return error.BufferTooSmall;
            const name = try allocator.dupe(u8, buf[pos..][0..name_len]);
            pos += name_len;

            // Extension data
            const data_result = try varint.decode(buf[pos..]);
            pos += data_result.len;
            const data_len = data_result.value;

            if (pos + data_len > buf.len) return error.BufferTooSmall;
            const data = try allocator.dupe(u8, buf[pos..][0..data_len]);
            pos += data_len;

            extensions[i] = ExtensionPair{
                .name = name,
                .data = data,
            };
        }

        return SshQuicCancel{
            .reason_phrase = reason_phrase,
            .extensions = extensions,
        };
    }

    /// Free allocated memory
    pub fn deinit(self: *SshQuicCancel, allocator: std.mem.Allocator) void {
        allocator.free(self.reason_phrase);
        for (self.extensions) |ext| {
            allocator.free(ext.name);
            allocator.free(ext.data);
        }
        allocator.free(self.extensions);
    }
};

// Tests

test "SSH_QUIC_CANCEL encode basic" {
    const cancel = SshQuicCancel.init("Connection refused");

    var buf: [256]u8 = undefined;
    const len = try cancel.encode(&buf);

    try std.testing.expect(len > 0);
    try std.testing.expectEqual(SSH_QUIC_CANCEL, buf[0]);
}

test "SSH_QUIC_CANCEL predefined reasons" {
    const cancel1 = SshQuicCancel.unsupportedVersion();
    const cancel2 = SshQuicCancel.unsupportedKex();
    const cancel3 = SshQuicCancel.unsupportedCipherSuite();
    const cancel4 = SshQuicCancel.protocolError("Invalid packet");

    var buf: [256]u8 = undefined;

    _ = try cancel1.encode(&buf);
    _ = try cancel2.encode(&buf);
    _ = try cancel3.encode(&buf);
    _ = try cancel4.encode(&buf);
}

test "SSH_QUIC_CANCEL with extensions" {
    const exts = [_]ExtensionPair{
        .{ .name = "error-code", .data = "0x01" },
    };

    const cancel = SshQuicCancel{
        .reason_phrase = "Protocol error",
        .extensions = &exts,
    };

    var buf: [512]u8 = undefined;
    const len = try cancel.encode(&buf);

    try std.testing.expect(len > 0);
    try std.testing.expectEqual(SSH_QUIC_CANCEL, buf[0]);
}

test "SSH_QUIC_CANCEL with padding" {
    const cancel = SshQuicCancel.init("Short reason");

    var buf: [512]u8 = undefined;
    const len = try cancel.encodeWithPadding(&buf, 200);

    try std.testing.expect(len >= 200);
    try std.testing.expectEqual(SSH_QUIC_CANCEL, buf[0]);
}

test "SSH_QUIC_CANCEL encode and encrypt" {
    const allocator = std.testing.allocator;

    const cancel = SshQuicCancel.init("Key exchange failed");
    const key = obfuscation.ObfuscationKey.fromKeyword("test-password");

    var buf: [1024]u8 = undefined;
    const len = try cancel.encodeEncrypted(allocator, key, &buf);

    try std.testing.expect(len > 0);
    // Verify high bit of nonce is set
    try std.testing.expect((buf[0] & 0x80) != 0);
}

test "SSH_QUIC_CANCEL encode and decode" {
    const allocator = std.testing.allocator;

    const exts = [_]ExtensionPair{
        .{ .name = "test-ext", .data = "test-data" },
    };

    const original = SshQuicCancel{
        .reason_phrase = "Test cancellation",
        .extensions = &exts,
    };

    var buf: [512]u8 = undefined;
    const len = try original.encode(&buf);

    var decoded = try SshQuicCancel.decode(allocator, buf[0..len]);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings(original.reason_phrase, decoded.reason_phrase);
    try std.testing.expectEqual(original.extensions.len, decoded.extensions.len);
    try std.testing.expectEqualStrings(original.extensions[0].name, decoded.extensions[0].name);
    try std.testing.expectEqualStrings(original.extensions[0].data, decoded.extensions[0].data);
}

test "SSH_QUIC_CANCEL empty extensions" {
    const allocator = std.testing.allocator;

    const cancel = SshQuicCancel.init("Minimal cancel");

    var buf: [256]u8 = undefined;
    const len = try cancel.encode(&buf);

    var decoded = try SshQuicCancel.decode(allocator, buf[0..len]);
    defer decoded.deinit(allocator);

    try std.testing.expectEqualStrings(cancel.reason_phrase, decoded.reason_phrase);
    try std.testing.expectEqual(@as(usize, 0), decoded.extensions.len);
}
