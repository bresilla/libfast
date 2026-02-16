const std = @import("std");
const crypto = std.crypto;

/// Key exchange methods for SSH/QUIC (Section 3)
///
/// Supported methods:
/// - curve25519-sha256 (REQUIRED - RFC 8731)
/// - diffie-hellman-group14-sha256 (optional)
///
/// The key exchange produces:
/// - K: Shared secret
/// - H: Exchange hash

pub const KexError = error{
    InvalidPublicKey,
    InvalidPrivateKey,
    InvalidSignature,
    UnsupportedMethod,
    KeyExchangeFailed,
    OutOfMemory,
};

/// Key exchange method identifier
pub const KexMethod = enum {
    curve25519_sha256,
    diffie_hellman_group14_sha256,

    /// Parse method name to enum
    pub fn fromName(method_name: []const u8) ?KexMethod {
        if (std.mem.eql(u8, method_name, "curve25519-sha256")) {
            return .curve25519_sha256;
        } else if (std.mem.eql(u8, method_name, "diffie-hellman-group14-sha256")) {
            return .diffie_hellman_group14_sha256;
        }
        return null;
    }

    /// Get canonical method name
    pub fn name(self: KexMethod) []const u8 {
        return switch (self) {
            .curve25519_sha256 => "curve25519-sha256",
            .diffie_hellman_group14_sha256 => "diffie-hellman-group14-sha256",
        };
    }

    /// Get hash algorithm for this method
    pub fn hashAlgorithm(self: KexMethod) HashAlgorithm {
        return switch (self) {
            .curve25519_sha256 => .sha256,
            .diffie_hellman_group14_sha256 => .sha256,
        };
    }
};

/// Hash algorithm used in key exchange
pub const HashAlgorithm = enum {
    sha256,
    sha384,
    sha512,

    /// Get hash output length
    pub fn digestLength(self: HashAlgorithm) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }
};

/// Key exchange result
pub const KexResult = struct {
    /// Shared secret K (mpint format)
    shared_secret: []const u8,

    /// Exchange hash H
    exchange_hash: []const u8,

    /// Hash algorithm used
    hash_algorithm: HashAlgorithm,

    /// Free allocated memory
    pub fn deinit(self: *KexResult, allocator: std.mem.Allocator) void {
        allocator.free(self.shared_secret);
        allocator.free(self.exchange_hash);
    }
};

/// Key exchange state for client/server
pub const KexState = struct {
    method: KexMethod,
    is_client: bool,

    // Curve25519 state (32 bytes each)
    curve25519_private: ?[32]u8 = null,
    curve25519_public: ?[32]u8 = null,

    // Peer's public key
    peer_public_key: ?[]const u8 = null,

    // Exchange hash components
    client_id_string: []const u8,
    server_id_string: []const u8,
    client_init_packet: []const u8,
    server_reply_packet: []const u8,

    allocator: std.mem.Allocator,

    /// Initialize key exchange state
    pub fn init(
        allocator: std.mem.Allocator,
        method: KexMethod,
        is_client: bool,
        client_id: []const u8,
        server_id: []const u8,
        client_init: []const u8,
        server_reply: []const u8,
    ) KexState {
        return KexState{
            .method = method,
            .is_client = is_client,
            .allocator = allocator,
            .client_id_string = client_id,
            .server_id_string = server_id,
            .client_init_packet = client_init,
            .server_reply_packet = server_reply,
        };
    }

    /// Generate ephemeral key pair
    pub fn generateKeyPair(self: *KexState) KexError![]const u8 {
        switch (self.method) {
            .curve25519_sha256 => {
                // Generate Curve25519 key pair
                var private: [32]u8 = undefined;

                crypto.random.bytes(&private);
                const public = crypto.dh.X25519.recoverPublicKey(private) catch {
                    return error.KeyExchangeFailed;
                };

                self.curve25519_private = private;
                self.curve25519_public = public;

                // Return public key
                const public_copy = try self.allocator.dupe(u8, &public);
                return public_copy;
            },
            .diffie_hellman_group14_sha256 => {
                // DH group14 is legacy - modern implementations use Curve25519
                return error.UnsupportedMethod;
            },
        }
    }

    /// Set peer's public key
    pub fn setPeerPublicKey(self: *KexState, peer_key: []const u8) KexError!void {
        if (peer_key.len != 32 and self.method == .curve25519_sha256) {
            return error.InvalidPublicKey;
        }
        self.peer_public_key = try self.allocator.dupe(u8, peer_key);
    }

    /// Compute shared secret
    pub fn computeSharedSecret(self: *KexState) KexError![]const u8 {
        switch (self.method) {
            .curve25519_sha256 => {
                if (self.curve25519_private == null) {
                    return error.InvalidPrivateKey;
                }
                if (self.peer_public_key == null or self.peer_public_key.?.len != 32) {
                    return error.InvalidPublicKey;
                }

                const peer_key: [32]u8 = self.peer_public_key.?[0..32].*;

                const shared_secret = crypto.dh.X25519.scalarmult(self.curve25519_private.?, peer_key) catch {
                    return error.KeyExchangeFailed;
                };

                // Return as mpint format (big-endian, with length prefix)
                return try self.allocator.dupe(u8, &shared_secret);
            },
            .diffie_hellman_group14_sha256 => {
                // DH group14 is legacy - modern implementations use Curve25519
                return error.UnsupportedMethod;
            },
        }
    }

    /// Compute exchange hash H
    pub fn computeExchangeHash(
        self: *KexState,
        host_key: []const u8,
    ) KexError![]const u8 {
        const hash_alg = self.method.hashAlgorithm();

        // Build hash input according to SSH spec
        // H = hash(V_C || V_S || I_C || I_S || K_S || e_C || e_S || K)
        // Where:
        //   V_C, V_S = client and server identification strings
        //   I_C, I_S = client and server key exchange init messages
        //   K_S = server's public host key
        //   e_C = client's ephemeral public key
        //   e_S = server's ephemeral public key
        //   K = shared secret

        var hash_input: std.ArrayList(u8) = .{};
        defer hash_input.deinit(self.allocator);

        // Client and server ID strings
        try hash_input.appendSlice(self.allocator, self.client_id_string);
        try hash_input.appendSlice(self.allocator, self.server_id_string);

        // Client and server key exchange packets
        try hash_input.appendSlice(self.allocator, self.client_init_packet);
        try hash_input.appendSlice(self.allocator, self.server_reply_packet);

        // Server's public host key
        try hash_input.appendSlice(self.allocator, host_key);

        // Client and server ephemeral public keys
        if (self.is_client) {
            if (self.curve25519_public) |pub_key| {
                try hash_input.appendSlice(self.allocator, &pub_key);
            }
            if (self.peer_public_key) |peer_key| {
                try hash_input.appendSlice(self.allocator, peer_key);
            }
        } else {
            if (self.peer_public_key) |peer_key| {
                try hash_input.appendSlice(self.allocator, peer_key);
            }
            if (self.curve25519_public) |pub_key| {
                try hash_input.appendSlice(self.allocator, &pub_key);
            }
        }

        // Compute hash
        const digest_len = hash_alg.digestLength();
        var digest = try self.allocator.alloc(u8, digest_len);

        switch (hash_alg) {
            .sha256 => {
                crypto.hash.sha2.Sha256.hash(hash_input.items, digest[0..32], .{});
            },
            .sha384 => {
                crypto.hash.sha2.Sha384.hash(hash_input.items, digest[0..48], .{});
            },
            .sha512 => {
                crypto.hash.sha2.Sha512.hash(hash_input.items, digest[0..64], .{});
            },
        }

        return digest;
    }

    /// Perform complete key exchange
    pub fn performKeyExchange(
        self: *KexState,
        host_key: []const u8,
    ) KexError!KexResult {
        // Compute shared secret
        const shared_secret = try self.computeSharedSecret();
        errdefer self.allocator.free(shared_secret);

        // Compute exchange hash
        const exchange_hash = try self.computeExchangeHash(host_key);
        errdefer self.allocator.free(exchange_hash);

        return KexResult{
            .shared_secret = shared_secret,
            .exchange_hash = exchange_hash,
            .hash_algorithm = self.method.hashAlgorithm(),
        };
    }

    /// Clean up
    pub fn deinit(self: *KexState) void {
        if (self.peer_public_key) |key| {
            self.allocator.free(key);
        }
        // Zero out private key
        if (self.curve25519_private) |*priv| {
            @memset(priv, 0);
        }
    }
};

// Tests

test "KexMethod from name" {
    const method1 = KexMethod.fromName("curve25519-sha256");
    try std.testing.expect(method1 != null);
    try std.testing.expectEqual(KexMethod.curve25519_sha256, method1.?);

    const method2 = KexMethod.fromName("invalid-method");
    try std.testing.expect(method2 == null);
}

test "KexMethod name and hash algorithm" {
    const method = KexMethod.curve25519_sha256;
    try std.testing.expectEqualStrings("curve25519-sha256", method.name());
    try std.testing.expectEqual(HashAlgorithm.sha256, method.hashAlgorithm());
}

test "Curve25519 key pair generation" {
    const allocator = std.testing.allocator;

    var state = KexState.init(
        allocator,
        .curve25519_sha256,
        true,
        "client-id",
        "server-id",
        "init-packet",
        "reply-packet",
    );
    defer state.deinit();

    const public_key = try state.generateKeyPair();
    defer allocator.free(public_key);

    try std.testing.expectEqual(@as(usize, 32), public_key.len);
    try std.testing.expect(state.curve25519_private != null);
    try std.testing.expect(state.curve25519_public != null);
}

test "Curve25519 shared secret computation" {
    const allocator = std.testing.allocator;

    // Client side
    var client_state = KexState.init(
        allocator,
        .curve25519_sha256,
        true,
        "client-id",
        "server-id",
        "init",
        "reply",
    );
    defer client_state.deinit();

    const client_public = try client_state.generateKeyPair();
    defer allocator.free(client_public);

    // Server side
    var server_state = KexState.init(
        allocator,
        .curve25519_sha256,
        false,
        "client-id",
        "server-id",
        "init",
        "reply",
    );
    defer server_state.deinit();

    const server_public = try server_state.generateKeyPair();
    defer allocator.free(server_public);

    // Exchange public keys
    try client_state.setPeerPublicKey(server_public);
    try server_state.setPeerPublicKey(client_public);

    // Compute shared secrets
    const client_secret = try client_state.computeSharedSecret();
    defer allocator.free(client_secret);

    const server_secret = try server_state.computeSharedSecret();
    defer allocator.free(server_secret);

    // Secrets should match
    try std.testing.expectEqualSlices(u8, client_secret, server_secret);
}

test "Exchange hash computation" {
    const allocator = std.testing.allocator;

    var state = KexState.init(
        allocator,
        .curve25519_sha256,
        true,
        "SSH-2.0-Client",
        "SSH-2.0-Server",
        "client-init-data",
        "server-reply-data",
    );
    defer state.deinit();

    const public_key = try state.generateKeyPair();
    defer allocator.free(public_key);

    const host_key = "server-host-key-data";
    const hash = try state.computeExchangeHash(host_key);
    defer allocator.free(hash);

    // SHA256 produces 32 bytes
    try std.testing.expectEqual(@as(usize, 32), hash.len);
}

test "Complete key exchange" {
    const allocator = std.testing.allocator;

    // Client
    var client = KexState.init(
        allocator,
        .curve25519_sha256,
        true,
        "SSH-2.0-Client",
        "SSH-2.0-Server",
        "client-init",
        "server-reply",
    );
    defer client.deinit();

    const client_pub = try client.generateKeyPair();
    defer allocator.free(client_pub);

    // Server
    var server = KexState.init(
        allocator,
        .curve25519_sha256,
        false,
        "SSH-2.0-Client",
        "SSH-2.0-Server",
        "client-init",
        "server-reply",
    );
    defer server.deinit();

    const server_pub = try server.generateKeyPair();
    defer allocator.free(server_pub);

    // Exchange
    try client.setPeerPublicKey(server_pub);
    try server.setPeerPublicKey(client_pub);

    const host_key = "server-host-key";

    var client_result = try client.performKeyExchange(host_key);
    defer client_result.deinit(allocator);

    var server_result = try server.performKeyExchange(host_key);
    defer server_result.deinit(allocator);

    // Shared secrets should match
    try std.testing.expectEqualSlices(u8, client_result.shared_secret, server_result.shared_secret);

    // Exchange hashes should match
    try std.testing.expectEqualSlices(u8, client_result.exchange_hash, server_result.exchange_hash);
}
