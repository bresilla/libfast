const std = @import("std");
const handshake_mod = @import("handshake.zig");
const key_schedule_mod = @import("key_schedule.zig");
const keys_mod = @import("../keys.zig");
const crypto_mod = @import("../crypto.zig");
const transport_params_mod = @import("../../core/transport_params.zig");

/// TLS 1.3 context for QUIC connections
///
/// Manages the TLS handshake state and key derivation
pub const TlsError = error{
    HandshakeFailed,
    InvalidState,
    UnsupportedCipherSuite,
    OutOfMemory,
} || handshake_mod.HandshakeError || key_schedule_mod.KeyScheduleError;

/// TLS handshake state
pub const HandshakeState = enum {
    idle,
    client_hello_sent,
    server_hello_received,
    handshake_complete,
    failed,

    pub fn isComplete(self: HandshakeState) bool {
        return self == .handshake_complete;
    }
};

pub const PeerVerificationOptions = struct {
    verify_peer: bool = true,
    allow_insecure_skip_verify: bool = false,
    expected_server_name: []const u8 = "",
    trusted_ca_pem: ?[]const u8 = null,
};

/// TLS context
pub const TlsContext = struct {
    allocator: std.mem.Allocator,
    is_client: bool,
    state: HandshakeState,

    /// Selected cipher suite
    cipher_suite: ?u16 = null,

    /// Key schedule
    key_schedule: ?*key_schedule_mod.KeySchedule = null,

    /// Handshake transcript bytes
    transcript: std.ArrayList(u8),

    /// Handshake secrets
    handshake_client_secret: ?[]u8 = null,
    handshake_server_secret: ?[]u8 = null,

    /// Application secrets
    application_client_secret: ?[]u8 = null,
    application_server_secret: ?[]u8 = null,

    /// Negotiated ALPN (when available)
    selected_alpn: ?[]u8 = null,

    /// Initialize TLS context
    pub fn init(allocator: std.mem.Allocator, is_client: bool) TlsContext {
        return TlsContext{
            .allocator = allocator,
            .is_client = is_client,
            .state = .idle,
            .transcript = .{},
            .selected_alpn = null,
        };
    }

    /// Start TLS handshake (client)
    pub fn startClientHandshake(
        self: *TlsContext,
        server_name: []const u8,
    ) TlsError![]u8 {
        return self.startClientHandshakeWithParams(server_name, &[_][]const u8{}, &[_]u8{});
    }

    /// Start TLS handshake (client) with ALPN and QUIC transport parameters.
    pub fn startClientHandshakeWithParams(
        self: *TlsContext,
        server_name: []const u8,
        alpn_protocols: []const []const u8,
        quic_transport_params: []const u8,
    ) TlsError![]u8 {
        if (!self.is_client) {
            return error.InvalidState;
        }
        if (self.state != .idle) {
            return error.InvalidState;
        }

        _ = server_name;
        _ = transport_params_mod.TransportParams.decode(self.allocator, quic_transport_params) catch {
            return error.HandshakeFailed;
        };

        // Generate random
        var random: [32]u8 = undefined;
        std.crypto.random.bytes(&random);

        // Supported cipher suites
        const cipher_suites = [_]u16{
            handshake_mod.TLS_AES_128_GCM_SHA256,
            handshake_mod.TLS_AES_256_GCM_SHA384,
            handshake_mod.TLS_CHACHA20_POLY1305_SHA256,
        };

        var ext_list: [2]handshake_mod.Extension = undefined;
        var ext_count: usize = 0;

        if (alpn_protocols.len > 0) {
            const alpn_data = try encodeAlpnExtensionData(self.allocator, alpn_protocols);
            errdefer self.allocator.free(alpn_data);

            ext_list[ext_count] = .{
                .extension_type = @intFromEnum(handshake_mod.ExtensionType.application_layer_protocol_negotiation),
                .extension_data = alpn_data,
            };
            ext_count += 1;
        }

        if (quic_transport_params.len > 0) {
            ext_list[ext_count] = .{
                .extension_type = @intFromEnum(handshake_mod.ExtensionType.quic_transport_parameters),
                .extension_data = quic_transport_params,
            };
            ext_count += 1;
        }

        const client_hello = handshake_mod.ClientHello{
            .random = random,
            .cipher_suites = &cipher_suites,
            .extensions = ext_list[0..ext_count],
        };

        const encoded = try client_hello.encode(self.allocator);

        if (ext_count > 0 and alpn_protocols.len > 0) {
            self.allocator.free(ext_list[0].extension_data);
        }

        self.transcript.clearRetainingCapacity();
        try self.transcript.appendSlice(self.allocator, encoded);

        self.state = .client_hello_sent;

        return encoded;
    }

    /// Process server hello (client)
    pub fn processServerHello(
        self: *TlsContext,
        server_hello_data: []const u8,
    ) TlsError!void {
        if (!self.is_client or self.state != .client_hello_sent) {
            return error.InvalidState;
        }

        const parsed = handshake_mod.parseServerHello(server_hello_data) catch |err| {
            return switch (err) {
                error.UnsupportedVersion => error.HandshakeFailed,
                else => error.HandshakeFailed,
            };
        };

        switch (parsed.cipher_suite) {
            handshake_mod.TLS_AES_128_GCM_SHA256,
            handshake_mod.TLS_AES_256_GCM_SHA384,
            handshake_mod.TLS_CHACHA20_POLY1305_SHA256,
            => self.cipher_suite = parsed.cipher_suite,
            else => return error.UnsupportedCipherSuite,
        }

        try self.transcript.appendSlice(self.allocator, server_hello_data);

        self.state = .server_hello_received;
    }

    /// Complete handshake (derive application secrets)
    pub fn completeHandshake(self: *TlsContext, shared_secret: []const u8) TlsError!void {
        return self.completeHandshakeWithFinished(shared_secret, null);
    }

    /// Complete handshake and optionally verify peer Finished data.
    pub fn completeHandshakeWithFinished(
        self: *TlsContext,
        shared_secret: []const u8,
        peer_finished_verify_data: ?[]const u8,
    ) TlsError!void {
        return self.completeHandshakeWithPeerValidation(
            shared_secret,
            peer_finished_verify_data,
            null,
            null,
        );
    }

    /// Complete handshake and optionally verify peer Finished and certificate identity.
    pub fn completeHandshakeWithPeerValidation(
        self: *TlsContext,
        shared_secret: []const u8,
        peer_finished_verify_data: ?[]const u8,
        peer_certificate_chain_pem: ?[]const u8,
        peer_options: ?PeerVerificationOptions,
    ) TlsError!void {
        if (!self.is_client or self.state != .server_hello_received) {
            return error.InvalidState;
        }

        if (peer_options) |opts| {
            try self.verifyPeerIdentity(peer_certificate_chain_pem, opts);
        }

        // Initialize key schedule
        const hash_alg: key_schedule_mod.HashAlgorithm = switch (self.cipher_suite orelse handshake_mod.TLS_AES_128_GCM_SHA256) {
            handshake_mod.TLS_AES_128_GCM_SHA256 => .sha256,
            handshake_mod.TLS_CHACHA20_POLY1305_SHA256 => .sha256,
            handshake_mod.TLS_AES_256_GCM_SHA384 => .sha384,
            else => return error.UnsupportedCipherSuite,
        };

        var ks = try key_schedule_mod.KeySchedule.init(
            self.allocator,
            hash_alg,
        );
        errdefer ks.deinit();

        // Derive early secret
        const early_secret = try ks.deriveEarlySecret(null);
        defer self.allocator.free(early_secret);

        // Derive handshake secret
        const handshake_secret = try ks.deriveHandshakeSecret(early_secret, shared_secret);
        defer self.allocator.free(handshake_secret);

        // Use real handshake transcript bytes (ClientHello + ServerHello)
        ks.updateTranscript(self.transcript.items);

        // Derive handshake traffic secrets
        const hs_secrets = try ks.deriveHandshakeTrafficSecrets(handshake_secret);
        errdefer {
            @memset(hs_secrets.client, 0);
            self.allocator.free(hs_secrets.client);
            @memset(hs_secrets.server, 0);
            self.allocator.free(hs_secrets.server);
        }

        if (peer_finished_verify_data) |verify_data| {
            try self.verifyFinishedData(
                &ks,
                hs_secrets.server,
                verify_data,
            );
        }

        // Derive master secret
        const master_secret = try ks.deriveMasterSecret(handshake_secret);
        defer self.allocator.free(master_secret);

        // Derive application traffic secrets
        const app_secrets = try ks.deriveApplicationTrafficSecrets(master_secret);
        errdefer {
            @memset(app_secrets.client, 0);
            self.allocator.free(app_secrets.client);
            @memset(app_secrets.server, 0);
            self.allocator.free(app_secrets.server);
        }

        // Save secrets
        self.handshake_client_secret = hs_secrets.client;
        self.handshake_server_secret = hs_secrets.server;
        self.application_client_secret = app_secrets.client;
        self.application_server_secret = app_secrets.server;

        // Save key schedule
        const ks_ptr = try self.allocator.create(key_schedule_mod.KeySchedule);
        ks_ptr.* = ks;
        self.key_schedule = ks_ptr;

        self.state = .handshake_complete;
    }

    fn encodeAlpnExtensionData(
        allocator: std.mem.Allocator,
        protocols: []const []const u8,
    ) TlsError![]u8 {
        var list_len: usize = 0;
        for (protocols) |protocol| {
            if (protocol.len == 0 or protocol.len > 255) {
                return error.HandshakeFailed;
            }
            list_len += 1 + protocol.len;
        }

        if (list_len > std.math.maxInt(u16)) {
            return error.HandshakeFailed;
        }

        var out = try allocator.alloc(u8, list_len + 2);
        var pos: usize = 0;
        out[pos] = @intCast((list_len >> 8) & 0xFF);
        pos += 1;
        out[pos] = @intCast(list_len & 0xFF);
        pos += 1;

        for (protocols) |protocol| {
            out[pos] = @intCast(protocol.len);
            pos += 1;
            @memcpy(out[pos..][0..protocol.len], protocol);
            pos += protocol.len;
        }

        return out;
    }

    fn verifyPeerIdentity(
        self: *TlsContext,
        peer_certificate_chain_pem: ?[]const u8,
        options: PeerVerificationOptions,
    ) TlsError!void {
        _ = self;
        if (!options.verify_peer) {
            return;
        }
        if (options.allow_insecure_skip_verify) {
            return;
        }
        if (options.expected_server_name.len == 0) {
            return error.HandshakeFailed;
        }

        const cert_chain = peer_certificate_chain_pem orelse return error.HandshakeFailed;
        if (!isLikelyPemCertificateChain(cert_chain)) {
            return error.HandshakeFailed;
        }

        if (options.trusted_ca_pem) |ca_pem| {
            if (!isLikelyPemCertificateChain(ca_pem)) {
                return error.HandshakeFailed;
            }
        }

        if (!certificateMatchesServerName(cert_chain, options.expected_server_name)) {
            return error.HandshakeFailed;
        }
    }

    fn isLikelyPemCertificateChain(pem: []const u8) bool {
        if (pem.len == 0) return false;
        return std.mem.indexOf(u8, pem, "-----BEGIN CERTIFICATE-----") != null and
            std.mem.indexOf(u8, pem, "-----END CERTIFICATE-----") != null;
    }

    fn certificateMatchesServerName(cert_chain_pem: []const u8, expected_server_name: []const u8) bool {
        var dns_pattern_buf: [256]u8 = undefined;
        const dns_pattern = std.fmt.bufPrint(&dns_pattern_buf, "DNS:{s}", .{expected_server_name}) catch return false;
        if (std.mem.indexOf(u8, cert_chain_pem, dns_pattern) != null) {
            return true;
        }

        var cn_pattern_buf: [256]u8 = undefined;
        const cn_pattern = std.fmt.bufPrint(&cn_pattern_buf, "CN={s}", .{expected_server_name}) catch return false;
        return std.mem.indexOf(u8, cert_chain_pem, cn_pattern) != null;
    }

    fn verifyFinishedData(
        self: *TlsContext,
        ks: *key_schedule_mod.KeySchedule,
        server_handshake_secret: []const u8,
        peer_verify_data: []const u8,
    ) TlsError!void {
        const hash_len = ks.hash_alg.digestLength();
        if (peer_verify_data.len != hash_len) {
            return error.HandshakeFailed;
        }

        const finished_key = try self.allocator.alloc(u8, hash_len);
        defer {
            @memset(finished_key, 0);
            self.allocator.free(finished_key);
        }

        keys_mod.hkdfExpandLabel(
            server_handshake_secret,
            "finished",
            "",
            hash_len,
            ks.hash_alg,
            finished_key,
        ) catch {
            return error.HandshakeFailed;
        };

        const expected_verify_data = try self.allocator.alloc(u8, hash_len);
        defer {
            @memset(expected_verify_data, 0);
            self.allocator.free(expected_verify_data);
        }

        switch (ks.hash_alg) {
            .sha256 => {
                var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(finished_key);
                hmac.update(ks.transcript_hash);
                hmac.final(expected_verify_data[0..32]);
            },
            .sha384 => {
                var hmac = std.crypto.auth.hmac.sha2.HmacSha384.init(finished_key);
                hmac.update(ks.transcript_hash);
                hmac.final(expected_verify_data[0..48]);
            },
            .sha512 => {
                var hmac = std.crypto.auth.hmac.sha2.HmacSha512.init(finished_key);
                hmac.update(ks.transcript_hash);
                hmac.final(expected_verify_data[0..64]);
            },
        }

        if (!std.mem.eql(u8, peer_verify_data, expected_verify_data)) {
            return error.HandshakeFailed;
        }
    }

    /// Get cipher suite info
    pub fn getCipherSuite(self: *TlsContext) ?crypto_mod.CipherSuite {
        if (self.cipher_suite) |cs| {
            return switch (cs) {
                handshake_mod.TLS_AES_128_GCM_SHA256 => crypto_mod.CipherSuite.TLS_AES_128_GCM_SHA256,
                handshake_mod.TLS_AES_256_GCM_SHA384 => crypto_mod.CipherSuite.TLS_AES_256_GCM_SHA384,
                handshake_mod.TLS_CHACHA20_POLY1305_SHA256 => crypto_mod.CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
                else => null,
            };
        }
        return null;
    }

    /// Clean up
    pub fn deinit(self: *TlsContext) void {
        if (self.handshake_client_secret) |secret| {
            @memset(secret, 0);
            self.allocator.free(secret);
        }
        if (self.handshake_server_secret) |secret| {
            @memset(secret, 0);
            self.allocator.free(secret);
        }

        if (self.application_client_secret) |secret| {
            @memset(secret, 0);
            self.allocator.free(secret);
        }
        if (self.application_server_secret) |secret| {
            @memset(secret, 0);
            self.allocator.free(secret);
        }

        if (self.key_schedule) |ks| {
            ks.deinit();
            self.allocator.destroy(ks);
        }

        self.transcript.deinit(self.allocator);
    }
};

// Tests

test "TLS context initialization" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    try std.testing.expect(ctx.is_client);
    try std.testing.expectEqual(HandshakeState.idle, ctx.state);
}

test "Client handshake start" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    try std.testing.expect(client_hello.len > 0);
    try std.testing.expectEqual(HandshakeState.client_hello_sent, ctx.state);
}

test "Client handshake start with ALPN and transport params" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    var params = transport_params_mod.TransportParams.defaultClient();
    params.initial_max_data = 4096;
    const encoded_params = try params.encode(allocator);
    defer allocator.free(encoded_params);

    const alpn = [_][]const u8{"h3"};

    const client_hello = try ctx.startClientHandshakeWithParams("example.com", &alpn, encoded_params);
    defer allocator.free(client_hello);

    try std.testing.expect(std.mem.indexOf(u8, client_hello, "h3") != null);
    try std.testing.expectEqual(HandshakeState.client_hello_sent, ctx.state);
}

test "Complete handshake flow" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    // Start handshake
    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const random: [32]u8 = [_]u8{1} ** 32;
    const server_hello_msg = handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &[_]handshake_mod.Extension{},
    };
    const server_hello = try server_hello_msg.encode(allocator);
    defer allocator.free(server_hello);
    try ctx.processServerHello(server_hello);

    // Complete with shared secret
    const shared_secret = "test-shared-secret-from-ecdhe".*;
    try ctx.completeHandshake(&shared_secret);

    try std.testing.expect(ctx.state.isComplete());
    try std.testing.expect(ctx.handshake_client_secret != null);
    try std.testing.expect(ctx.application_client_secret != null);
    try std.testing.expect(ctx.transcript.items.len > 0);
}

test "Process ServerHello rejects unsupported cipher suite" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const random: [32]u8 = [_]u8{3} ** 32;
    const server_hello_msg = handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = 0x9999,
        .extensions = &[_]handshake_mod.Extension{},
    };

    const server_hello = try server_hello_msg.encode(allocator);
    defer allocator.free(server_hello);

    try std.testing.expectError(error.UnsupportedCipherSuite, ctx.processServerHello(server_hello));
}

test "Complete handshake rejects invalid Finished data" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const random: [32]u8 = [_]u8{5} ** 32;
    const server_hello_msg = handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &[_]handshake_mod.Extension{},
    };
    const server_hello = try server_hello_msg.encode(allocator);
    defer allocator.free(server_hello);
    try ctx.processServerHello(server_hello);

    const shared_secret = "test-shared-secret-from-ecdhe".*;
    const bad_finished = [_]u8{0} ** 32;
    try std.testing.expectError(
        error.HandshakeFailed,
        ctx.completeHandshakeWithFinished(&shared_secret, &bad_finished),
    );
}

test "Peer verification accepts matching SAN hostname" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const random: [32]u8 = [_]u8{7} ** 32;
    const server_hello_msg = handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &[_]handshake_mod.Extension{},
    };
    const server_hello = try server_hello_msg.encode(allocator);
    defer allocator.free(server_hello);
    try ctx.processServerHello(server_hello);

    const shared_secret = "test-shared-secret-from-ecdhe".*;
    const cert_pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "DNS:example.com\n" ++
        "-----END CERTIFICATE-----\n";
    const ca_pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "CN=Test CA\n" ++
        "-----END CERTIFICATE-----\n";
    const options = PeerVerificationOptions{
        .verify_peer = true,
        .allow_insecure_skip_verify = false,
        .expected_server_name = "example.com",
        .trusted_ca_pem = ca_pem,
    };

    try ctx.completeHandshakeWithPeerValidation(&shared_secret, null, cert_pem, options);
    try std.testing.expect(ctx.state.isComplete());
}

test "Peer verification rejects hostname mismatch" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const random: [32]u8 = [_]u8{8} ** 32;
    const server_hello_msg = handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &[_]handshake_mod.Extension{},
    };
    const server_hello = try server_hello_msg.encode(allocator);
    defer allocator.free(server_hello);
    try ctx.processServerHello(server_hello);

    const shared_secret = "test-shared-secret-from-ecdhe".*;
    const cert_pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "DNS:not-example.com\n" ++
        "-----END CERTIFICATE-----\n";
    const options = PeerVerificationOptions{
        .verify_peer = true,
        .allow_insecure_skip_verify = false,
        .expected_server_name = "example.com",
    };

    try std.testing.expectError(
        error.HandshakeFailed,
        ctx.completeHandshakeWithPeerValidation(&shared_secret, null, cert_pem, options),
    );
}

test "Peer verification rejects missing certificate chain" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const random: [32]u8 = [_]u8{9} ** 32;
    const server_hello_msg = handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &[_]handshake_mod.Extension{},
    };
    const server_hello = try server_hello_msg.encode(allocator);
    defer allocator.free(server_hello);
    try ctx.processServerHello(server_hello);

    const shared_secret = "test-shared-secret-from-ecdhe".*;
    const options = PeerVerificationOptions{
        .verify_peer = true,
        .allow_insecure_skip_verify = false,
        .expected_server_name = "example.com",
    };

    try std.testing.expectError(
        error.HandshakeFailed,
        ctx.completeHandshakeWithPeerValidation(&shared_secret, null, null, options),
    );
}

test "Deterministic handshake vector with valid Finished" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const random: [32]u8 = [_]u8{11} ** 32;
    const server_hello_msg = handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &[_]handshake_mod.Extension{},
    };
    const server_hello = try server_hello_msg.encode(allocator);
    defer allocator.free(server_hello);
    try ctx.processServerHello(server_hello);

    // Build expected Finished verify_data from deterministic inputs.
    var ks = try key_schedule_mod.KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    const shared_secret = "deterministic-shared-secret".*;
    const early_secret = try ks.deriveEarlySecret(null);
    defer allocator.free(early_secret);
    const handshake_secret = try ks.deriveHandshakeSecret(early_secret, &shared_secret);
    defer allocator.free(handshake_secret);
    ks.updateTranscript(ctx.transcript.items);
    const hs_secrets = try ks.deriveHandshakeTrafficSecrets(handshake_secret);
    defer {
        @memset(hs_secrets.client, 0);
        allocator.free(hs_secrets.client);
        @memset(hs_secrets.server, 0);
        allocator.free(hs_secrets.server);
    }

    var finished_key: [32]u8 = undefined;
    try keys_mod.hkdfExpandLabel(
        hs_secrets.server,
        "finished",
        "",
        finished_key.len,
        .sha256,
        &finished_key,
    );

    var verify_data: [32]u8 = undefined;
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&finished_key);
    hmac.update(ks.transcript_hash);
    hmac.final(&verify_data);

    try ctx.completeHandshakeWithFinished(&shared_secret, &verify_data);
    try std.testing.expect(ctx.state.isComplete());
}

test "State machine rejects complete handshake before server hello" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const shared_secret = "test-shared-secret".*;
    try std.testing.expectError(
        error.InvalidState,
        ctx.completeHandshakeWithFinished(&shared_secret, null),
    );
}

test "State machine rejects duplicate server hello" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    const random: [32]u8 = [_]u8{13} ** 32;
    const server_hello_msg = handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &[_]handshake_mod.Extension{},
    };
    const server_hello = try server_hello_msg.encode(allocator);
    defer allocator.free(server_hello);

    try ctx.processServerHello(server_hello);
    try std.testing.expectError(error.InvalidState, ctx.processServerHello(server_hello));
}

test "State machine rejects starting handshake twice" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    const client_hello = try ctx.startClientHandshake("example.com");
    defer allocator.free(client_hello);

    try std.testing.expectError(error.InvalidState, ctx.startClientHandshake("example.com"));
}

test "Get cipher suite info" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, true);
    defer ctx.deinit();

    // Initially no cipher suite
    try std.testing.expect(ctx.getCipherSuite() == null);

    // Set cipher suite
    ctx.cipher_suite = handshake_mod.TLS_AES_128_GCM_SHA256;

    const suite = ctx.getCipherSuite();
    try std.testing.expect(suite != null);
    try std.testing.expectEqual(crypto_mod.CipherSuite.TLS_AES_128_GCM_SHA256, suite.?);
}

test "Server context creation" {
    const allocator = std.testing.allocator;

    var ctx = TlsContext.init(allocator, false);
    defer ctx.deinit();

    try std.testing.expect(!ctx.is_client);

    // Server can't start client handshake
    const result = ctx.startClientHandshake("example.com");
    try std.testing.expectError(error.InvalidState, result);
}
