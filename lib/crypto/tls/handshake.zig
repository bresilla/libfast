const std = @import("std");

/// TLS 1.3 handshake messages for QUIC (RFC 9001)
///
/// This implements the TLS 1.3 handshake protocol adapted for QUIC transport.
/// Messages are sent via CRYPTO frames rather than TLS records.
pub const HandshakeError = error{
    InvalidMessage,
    BufferTooSmall,
    UnsupportedVersion,
    UnsupportedCipherSuite,
    InvalidSignature,
    CertificateVerificationFailed,
    OutOfMemory,
};

/// TLS handshake message type
pub const HandshakeType = enum(u8) {
    client_hello = 1,
    server_hello = 2,
    new_session_ticket = 4,
    end_of_early_data = 5,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    message_hash = 254,

    pub fn toString(self: HandshakeType) []const u8 {
        return switch (self) {
            .client_hello => "ClientHello",
            .server_hello => "ServerHello",
            .new_session_ticket => "NewSessionTicket",
            .end_of_early_data => "EndOfEarlyData",
            .encrypted_extensions => "EncryptedExtensions",
            .certificate => "Certificate",
            .certificate_request => "CertificateRequest",
            .certificate_verify => "CertificateVerify",
            .finished => "Finished",
            .key_update => "KeyUpdate",
            .message_hash => "MessageHash",
        };
    }
};

/// TLS extension type
pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    application_layer_protocol_negotiation = 16,
    supported_versions = 43,
    key_share = 51,
    quic_transport_parameters = 0x39, // 57

    _,
};

/// Supported TLS version
pub const TLS_VERSION_1_3: u16 = 0x0304;

/// ClientHello message
pub const ClientHello = struct {
    /// Random bytes (32 bytes)
    random: [32]u8,

    /// Legacy session ID (for compatibility)
    legacy_session_id: []const u8 = &[_]u8{},

    /// Cipher suites
    cipher_suites: []const u16,

    /// Extensions
    extensions: []const Extension,

    /// Encode ClientHello message
    pub fn encode(self: ClientHello, allocator: std.mem.Allocator) HandshakeError![]u8 {
        var data: std.ArrayList(u8) = .{};
        errdefer data.deinit(allocator);

        // Message type
        try data.append(allocator, @intFromEnum(HandshakeType.client_hello));

        // Message length (placeholder, will be filled later)
        const length_pos = data.items.len;
        try data.appendNTimes(allocator, 0, 3);

        const content_start = data.items.len;

        // Legacy version (TLS 1.2 for compatibility)
        try data.append(allocator, 0x03);
        try data.append(allocator, 0x03);

        // Random
        try data.appendSlice(allocator, &self.random);

        // Legacy session ID
        try data.append(allocator, @intCast(self.legacy_session_id.len));
        try data.appendSlice(allocator, self.legacy_session_id);

        // Cipher suites
        const cs_len: u16 = @intCast(self.cipher_suites.len * 2);
        try data.append(allocator, @intCast((cs_len >> 8) & 0xFF));
        try data.append(allocator, @intCast(cs_len & 0xFF));
        for (self.cipher_suites) |cs| {
            try data.append(allocator, @intCast((cs >> 8) & 0xFF));
            try data.append(allocator, @intCast(cs & 0xFF));
        }

        // Legacy compression methods (null only)
        try data.append(allocator, 1);
        try data.append(allocator, 0);

        try encodeExtensions(&data, allocator, self.extensions);

        // Fill in message length
        const content_len = data.items.len - content_start;
        data.items[length_pos] = @intCast((content_len >> 16) & 0xFF);
        data.items[length_pos + 1] = @intCast((content_len >> 8) & 0xFF);
        data.items[length_pos + 2] = @intCast(content_len & 0xFF);

        return data.toOwnedSlice(allocator);
    }
};

/// ServerHello message
pub const ServerHello = struct {
    /// Random bytes (32 bytes)
    random: [32]u8,

    /// Selected cipher suite
    cipher_suite: u16,

    /// Extensions
    extensions: []const Extension,

    /// Encode ServerHello message
    pub fn encode(self: ServerHello, allocator: std.mem.Allocator) HandshakeError![]u8 {
        var data: std.ArrayList(u8) = .{};
        errdefer data.deinit(allocator);

        // Message type
        try data.append(allocator, @intFromEnum(HandshakeType.server_hello));

        // Message length (placeholder)
        const length_pos = data.items.len;
        try data.appendNTimes(allocator, 0, 3);

        const content_start = data.items.len;

        // Legacy version
        try data.append(allocator, 0x03);
        try data.append(allocator, 0x03);

        // Random
        try data.appendSlice(allocator, &self.random);

        // Legacy session ID (empty)
        try data.append(allocator, 0);

        // Cipher suite
        try data.append(allocator, @intCast((self.cipher_suite >> 8) & 0xFF));
        try data.append(allocator, @intCast(self.cipher_suite & 0xFF));

        // Legacy compression method
        try data.append(allocator, 0);

        try encodeExtensions(&data, allocator, self.extensions);

        // Fill in length
        const content_len = data.items.len - content_start;
        data.items[length_pos] = @intCast((content_len >> 16) & 0xFF);
        data.items[length_pos + 1] = @intCast((content_len >> 8) & 0xFF);
        data.items[length_pos + 2] = @intCast(content_len & 0xFF);

        return data.toOwnedSlice(allocator);
    }
};

pub const ParsedServerHello = struct {
    random: [32]u8,
    cipher_suite: u16,
    extensions: []const u8,
};

/// Parse a TLS ServerHello message and extract key fields.
pub fn parseServerHello(data: []const u8) HandshakeError!ParsedServerHello {
    if (data.len < 4) return error.InvalidMessage;

    if (data[0] != @intFromEnum(HandshakeType.server_hello)) {
        return error.InvalidMessage;
    }

    const msg_len: usize = (@as(usize, data[1]) << 16) | (@as(usize, data[2]) << 8) | data[3];
    if (data.len < 4 + msg_len) return error.InvalidMessage;

    var pos: usize = 4;

    // Legacy version must be TLS 1.2 for TLS 1.3 handshake messages.
    if (pos + 2 > data.len) return error.InvalidMessage;
    const legacy_version: u16 = (@as(u16, data[pos]) << 8) | data[pos + 1];
    if (legacy_version != 0x0303) return error.UnsupportedVersion;
    pos += 2;

    if (pos + 32 > data.len) return error.InvalidMessage;
    var random: [32]u8 = undefined;
    @memcpy(&random, data[pos .. pos + 32]);
    pos += 32;

    if (pos + 1 > data.len) return error.InvalidMessage;
    const session_id_len = data[pos];
    pos += 1;
    if (pos + session_id_len > data.len) return error.InvalidMessage;
    pos += session_id_len;

    if (pos + 2 > data.len) return error.InvalidMessage;
    const cipher_suite: u16 = (@as(u16, data[pos]) << 8) | data[pos + 1];
    pos += 2;

    if (pos + 1 > data.len) return error.InvalidMessage;
    pos += 1; // legacy compression method

    if (pos + 2 > data.len) return error.InvalidMessage;
    const ext_len: usize = (@as(usize, data[pos]) << 8) | data[pos + 1];
    pos += 2;
    if (pos + ext_len > data.len) return error.InvalidMessage;

    return ParsedServerHello{
        .random = random,
        .cipher_suite = cipher_suite,
        .extensions = data[pos .. pos + ext_len],
    };
}

/// Find a specific extension payload inside encoded extension bytes.
///
/// `extensions` must be the raw extensions vector as returned by
/// `parseServerHello(...).extensions`.
pub fn findExtension(extensions: []const u8, extension_type: u16) HandshakeError!?[]const u8 {
    var pos: usize = 0;
    while (pos < extensions.len) {
        if (pos + 4 > extensions.len) return error.InvalidMessage;
        const ext_type: u16 = (@as(u16, extensions[pos]) << 8) | extensions[pos + 1];
        pos += 2;

        const ext_len: usize = (@as(usize, extensions[pos]) << 8) | extensions[pos + 1];
        pos += 2;

        if (pos + ext_len > extensions.len) return error.InvalidMessage;
        const ext_data = extensions[pos .. pos + ext_len];
        pos += ext_len;

        if (ext_type == extension_type) return ext_data;
    }

    return null;
}

/// TLS extension
pub const Extension = struct {
    extension_type: u16,
    extension_data: []const u8,
};

/// Finished message
pub const Finished = struct {
    /// Verify data (HMAC of transcript)
    verify_data: []const u8,

    /// Encode Finished message
    pub fn encode(self: Finished, allocator: std.mem.Allocator) HandshakeError![]u8 {
        var data: std.ArrayList(u8) = .{};
        errdefer data.deinit(allocator);

        // Message type
        try data.append(allocator, @intFromEnum(HandshakeType.finished));

        // Message length
        const length: u32 = @intCast(self.verify_data.len);
        try data.append(allocator, @intCast((length >> 16) & 0xFF));
        try data.append(allocator, @intCast((length >> 8) & 0xFF));
        try data.append(allocator, @intCast(length & 0xFF));

        // Verify data
        try data.appendSlice(allocator, self.verify_data);

        return data.toOwnedSlice(allocator);
    }
};

/// Certificate message
pub const Certificate = struct {
    /// Certificate request context
    certificate_request_context: []const u8 = &[_]u8{},

    /// Certificate entries
    certificate_list: []const CertificateEntry,

    pub const CertificateEntry = struct {
        cert_data: []const u8,
        extensions: []const Extension,
    };

    /// Encode Certificate message
    pub fn encode(self: Certificate, allocator: std.mem.Allocator) HandshakeError![]u8 {
        _ = self;
        _ = allocator;
        // Certificate encoding is complex and only needed for TLS server mode
        // Client applications don't need to encode certificates
        return error.InvalidMessage;
    }
};

/// EncryptedExtensions message
pub const EncryptedExtensions = struct {
    extensions: []const Extension,

    /// Encode EncryptedExtensions message
    pub fn encode(self: EncryptedExtensions, allocator: std.mem.Allocator) HandshakeError![]u8 {
        var data: std.ArrayList(u8) = .{};
        errdefer data.deinit(allocator);

        // Message type
        try data.append(allocator, @intFromEnum(HandshakeType.encrypted_extensions));

        // Message length (placeholder)
        const length_pos = data.items.len;
        try data.appendNTimes(allocator, 0, 3);

        const content_start = data.items.len;

        try encodeExtensions(&data, allocator, self.extensions);

        // Fill in length
        const content_len = data.items.len - content_start;
        data.items[length_pos] = @intCast((content_len >> 16) & 0xFF);
        data.items[length_pos + 1] = @intCast((content_len >> 8) & 0xFF);
        data.items[length_pos + 2] = @intCast(content_len & 0xFF);

        return data.toOwnedSlice(allocator);
    }
};

fn encodeExtensions(data: *std.ArrayList(u8), allocator: std.mem.Allocator, extensions: []const Extension) HandshakeError!void {
    const len_pos = data.items.len;
    try data.appendNTimes(allocator, 0, 2);

    const start = data.items.len;
    for (extensions) |ext| {
        if (ext.extension_data.len > std.math.maxInt(u16)) {
            return error.InvalidMessage;
        }

        try data.append(allocator, @intCast((ext.extension_type >> 8) & 0xFF));
        try data.append(allocator, @intCast(ext.extension_type & 0xFF));

        const ext_len: u16 = @intCast(ext.extension_data.len);
        try data.append(allocator, @intCast((ext_len >> 8) & 0xFF));
        try data.append(allocator, @intCast(ext_len & 0xFF));
        try data.appendSlice(allocator, ext.extension_data);
    }

    const total_len = data.items.len - start;
    if (total_len > std.math.maxInt(u16)) {
        return error.InvalidMessage;
    }

    data.items[len_pos] = @intCast((total_len >> 8) & 0xFF);
    data.items[len_pos + 1] = @intCast(total_len & 0xFF);
}

/// Cipher suite constants
pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Get cipher suite name
pub fn cipherSuiteName(suite: u16) []const u8 {
    return switch (suite) {
        TLS_AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
        TLS_AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        TLS_CHACHA20_POLY1305_SHA256 => "TLS_CHACHA20_POLY1305_SHA256",
        else => "Unknown",
    };
}

// Tests

test "ClientHello encoding" {
    const allocator = std.testing.allocator;

    const random: [32]u8 = [_]u8{0} ** 32;
    const cipher_suites = [_]u16{TLS_AES_128_GCM_SHA256};

    const client_hello = ClientHello{
        .random = random,
        .cipher_suites = &cipher_suites,
        .extensions = &[_]Extension{},
    };

    const encoded = try client_hello.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len > 0);
    try std.testing.expectEqual(@as(u8, @intFromEnum(HandshakeType.client_hello)), encoded[0]);
}

test "ServerHello encoding" {
    const allocator = std.testing.allocator;

    const random: [32]u8 = [_]u8{1} ** 32;

    const server_hello = ServerHello{
        .random = random,
        .cipher_suite = TLS_AES_128_GCM_SHA256,
        .extensions = &[_]Extension{},
    };

    const encoded = try server_hello.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len > 0);
    try std.testing.expectEqual(@as(u8, @intFromEnum(HandshakeType.server_hello)), encoded[0]);
}

test "Finished message encoding" {
    const allocator = std.testing.allocator;

    const verify_data = "test-verify-data-32-bytes-long!!";

    const finished = Finished{
        .verify_data = verify_data,
    };

    const encoded = try finished.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len > 0);
    try std.testing.expectEqual(@as(u8, @intFromEnum(HandshakeType.finished)), encoded[0]);
}

test "EncryptedExtensions encoding" {
    const allocator = std.testing.allocator;

    const ee = EncryptedExtensions{
        .extensions = &[_]Extension{},
    };

    const encoded = try ee.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expect(encoded.len > 0);
    try std.testing.expectEqual(@as(u8, @intFromEnum(HandshakeType.encrypted_extensions)), encoded[0]);
}

test "Cipher suite names" {
    try std.testing.expectEqualStrings("TLS_AES_128_GCM_SHA256", cipherSuiteName(TLS_AES_128_GCM_SHA256));
    try std.testing.expectEqualStrings("TLS_AES_256_GCM_SHA384", cipherSuiteName(TLS_AES_256_GCM_SHA384));
    try std.testing.expectEqualStrings("TLS_CHACHA20_POLY1305_SHA256", cipherSuiteName(TLS_CHACHA20_POLY1305_SHA256));
}

test "HandshakeType toString" {
    try std.testing.expectEqualStrings("ClientHello", HandshakeType.client_hello.toString());
    try std.testing.expectEqualStrings("ServerHello", HandshakeType.server_hello.toString());
    try std.testing.expectEqualStrings("Finished", HandshakeType.finished.toString());
}

test "Parse ServerHello" {
    const allocator = std.testing.allocator;

    const random: [32]u8 = [_]u8{2} ** 32;
    const server_hello = ServerHello{
        .random = random,
        .cipher_suite = TLS_AES_128_GCM_SHA256,
        .extensions = &[_]Extension{},
    };

    const encoded = try server_hello.encode(allocator);
    defer allocator.free(encoded);

    const parsed = try parseServerHello(encoded);
    try std.testing.expectEqual(TLS_AES_128_GCM_SHA256, parsed.cipher_suite);
    try std.testing.expectEqualSlices(u8, &random, &parsed.random);
    try std.testing.expectEqual(@as(usize, 0), parsed.extensions.len);
}

test "ClientHello encodes extensions" {
    const allocator = std.testing.allocator;

    const random: [32]u8 = [_]u8{0} ** 32;
    const cipher_suites = [_]u16{TLS_AES_128_GCM_SHA256};
    const ext = [_]Extension{
        .{ .extension_type = @intFromEnum(ExtensionType.application_layer_protocol_negotiation), .extension_data = "h3" },
    };

    const client_hello = ClientHello{
        .random = random,
        .cipher_suites = &cipher_suites,
        .extensions = &ext,
    };

    const encoded = try client_hello.encode(allocator);
    defer allocator.free(encoded);

    try std.testing.expect(std.mem.indexOf(u8, encoded, "h3") != null);
}

test "Find extension in parsed ServerHello" {
    const allocator = std.testing.allocator;

    const random: [32]u8 = [_]u8{4} ** 32;
    const ext = [_]Extension{
        .{ .extension_type = @intFromEnum(ExtensionType.application_layer_protocol_negotiation), .extension_data = "h3" },
    };

    const server_hello = ServerHello{
        .random = random,
        .cipher_suite = TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };

    const encoded = try server_hello.encode(allocator);
    defer allocator.free(encoded);

    const parsed = try parseServerHello(encoded);
    const alpn = try findExtension(parsed.extensions, @intFromEnum(ExtensionType.application_layer_protocol_negotiation));
    try std.testing.expect(alpn != null);
    try std.testing.expectEqualStrings("h3", alpn.?);
}

test "Parse ServerHello invalid version" {
    // Valid server hello prefix with invalid legacy version 0x0301
    var msg = [_]u8{0} ** 44;
    msg[0] = @intFromEnum(HandshakeType.server_hello);
    msg[3] = 40; // content length
    msg[4] = 0x03;
    msg[5] = 0x01;
    msg[38] = 0; // session id len
    msg[39] = 0x13;
    msg[40] = 0x01;

    try std.testing.expectError(error.UnsupportedVersion, parseServerHello(&msg));
}
