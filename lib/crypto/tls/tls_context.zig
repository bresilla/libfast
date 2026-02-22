const std = @import("std");
const handshake_mod = @import("handshake.zig");
const key_schedule_mod = @import("key_schedule.zig");
const crypto_mod = @import("../crypto.zig");

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

    /// Initialize TLS context
    pub fn init(allocator: std.mem.Allocator, is_client: bool) TlsContext {
        return TlsContext{
            .allocator = allocator,
            .is_client = is_client,
            .state = .idle,
            .transcript = .{},
        };
    }

    /// Start TLS handshake (client)
    pub fn startClientHandshake(
        self: *TlsContext,
        server_name: []const u8,
    ) TlsError![]u8 {
        if (!self.is_client) {
            return error.InvalidState;
        }

        _ = server_name;

        // Generate random
        var random: [32]u8 = undefined;
        std.crypto.random.bytes(&random);

        // Supported cipher suites
        const cipher_suites = [_]u16{
            handshake_mod.TLS_AES_128_GCM_SHA256,
            handshake_mod.TLS_AES_256_GCM_SHA384,
            handshake_mod.TLS_CHACHA20_POLY1305_SHA256,
        };

        const client_hello = handshake_mod.ClientHello{
            .random = random,
            .cipher_suites = &cipher_suites,
            .extensions = &[_]handshake_mod.Extension{},
        };

        const encoded = try client_hello.encode(self.allocator);

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
        // Initialize key schedule
        // SHA256 is correct for TLS_AES_128_GCM_SHA256 (our default cipher suite)
        var ks = try key_schedule_mod.KeySchedule.init(
            self.allocator,
            .sha256,
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

        // Derive master secret
        const master_secret = try ks.deriveMasterSecret(handshake_secret);
        defer self.allocator.free(master_secret);

        // Derive application traffic secrets
        const app_secrets = try ks.deriveApplicationTrafficSecrets(master_secret);

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
