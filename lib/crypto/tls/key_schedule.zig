const std = @import("std");
const crypto = std.crypto;
const keys_mod = @import("../keys.zig");

/// TLS 1.3 key schedule for QUIC (RFC 8446, RFC 9001)
///
/// Implements the TLS 1.3 key derivation functions adapted for QUIC.

pub const KeyScheduleError = error{
    InvalidSecret,
    InvalidSecretLength,
    DerivationFailed,
    OutOfMemory,
};

/// Re-export HashAlgorithm from keys module
pub const HashAlgorithm = keys_mod.HashAlgorithm;

/// TLS 1.3 key schedule state
pub const KeySchedule = struct {
    hash_alg: HashAlgorithm,
    transcript_hash: []u8,
    allocator: std.mem.Allocator,

    /// Initialize key schedule
    pub fn init(allocator: std.mem.Allocator, hash_alg: HashAlgorithm) !KeySchedule {
        const hash_len = hash_alg.digestLength();
        const transcript = try allocator.alloc(u8, hash_len);
        @memset(transcript, 0);

        return KeySchedule{
            .hash_alg = hash_alg,
            .transcript_hash = transcript,
            .allocator = allocator,
        };
    }

    /// Clean up
    pub fn deinit(self: *KeySchedule) void {
        @memset(self.transcript_hash, 0);
        self.allocator.free(self.transcript_hash);
    }

    /// Update transcript hash with handshake message
    pub fn updateTranscript(self: *KeySchedule, message: []const u8) void {
        switch (self.hash_alg) {
            .sha256 => {
                var hasher = crypto.hash.sha2.Sha256.init(.{});
                hasher.update(self.transcript_hash);
                hasher.update(message);
                hasher.final(self.transcript_hash[0..32]);
            },
            .sha384 => {
                var hasher = crypto.hash.sha2.Sha384.init(.{});
                hasher.update(self.transcript_hash);
                hasher.update(message);
                hasher.final(self.transcript_hash[0..48]);
            },
            .sha512 => {
                var hasher = crypto.hash.sha2.Sha512.init(.{});
                hasher.update(self.transcript_hash);
                hasher.update(message);
                hasher.final(self.transcript_hash[0..64]);
            },
        }
    }

    /// Derive early secret from PSK (or zero for no PSK)
    pub fn deriveEarlySecret(
        self: *KeySchedule,
        psk: ?[]const u8,
    ) KeyScheduleError![]u8 {
        const hash_len = self.hash_alg.digestLength();
        const salt = try self.allocator.alloc(u8, hash_len);
        defer self.allocator.free(salt);
        @memset(salt, 0);

        const ikm = if (psk) |p| p else blk: {
            const zeros = try self.allocator.alloc(u8, hash_len);
            @memset(zeros, 0);
            break :blk zeros;
        };
        defer if (psk == null) self.allocator.free(ikm);

        return try self.hkdfExtract(salt, ikm);
    }

    /// Derive handshake secret from early secret and (EC)DHE
    pub fn deriveHandshakeSecret(
        self: *KeySchedule,
        early_secret: []const u8,
        ecdhe: []const u8,
    ) KeyScheduleError![]u8 {
        // Derive-Secret(early_secret, "derived", "")
        const derived = try self.deriveSecret(early_secret, "derived", &[_]u8{});
        defer self.allocator.free(derived);

        // HKDF-Extract(derived, ECDHE)
        return try self.hkdfExtract(derived, ecdhe);
    }

    /// Derive master secret from handshake secret
    pub fn deriveMasterSecret(
        self: *KeySchedule,
        handshake_secret: []const u8,
    ) KeyScheduleError![]u8 {
        // Derive-Secret(handshake_secret, "derived", "")
        const derived = try self.deriveSecret(handshake_secret, "derived", &[_]u8{});
        defer self.allocator.free(derived);

        // HKDF-Extract(derived, 0)
        const hash_len = self.hash_alg.digestLength();
        const zeros = try self.allocator.alloc(u8, hash_len);
        defer self.allocator.free(zeros);
        @memset(zeros, 0);

        return try self.hkdfExtract(derived, zeros);
    }

    /// Derive client/server handshake traffic secrets
    pub fn deriveHandshakeTrafficSecrets(
        self: *KeySchedule,
        handshake_secret: []const u8,
    ) KeyScheduleError!struct { client: []u8, server: []u8 } {
        const client = try self.deriveSecret(handshake_secret, "c hs traffic", self.transcript_hash);
        errdefer self.allocator.free(client);

        const server = try self.deriveSecret(handshake_secret, "s hs traffic", self.transcript_hash);

        return .{ .client = client, .server = server };
    }

    /// Derive client/server application traffic secrets
    pub fn deriveApplicationTrafficSecrets(
        self: *KeySchedule,
        master_secret: []const u8,
    ) KeyScheduleError!struct { client: []u8, server: []u8 } {
        const client = try self.deriveSecret(master_secret, "c ap traffic", self.transcript_hash);
        errdefer self.allocator.free(client);

        const server = try self.deriveSecret(master_secret, "s ap traffic", self.transcript_hash);

        return .{ .client = client, .server = server };
    }

    /// Derive-Secret function from TLS 1.3
    fn deriveSecret(
        self: *KeySchedule,
        secret: []const u8,
        label: []const u8,
        context: []const u8,
    ) KeyScheduleError![]u8 {
        const hash_len = self.hash_alg.digestLength();
        const output = try self.allocator.alloc(u8, hash_len);
        errdefer self.allocator.free(output);

        try keys_mod.hkdfExpandLabel(secret, label, context, hash_len, self.hash_alg, output);

        return output;
    }

    /// HKDF-Extract from RFC 5869
    fn hkdfExtract(
        self: *KeySchedule,
        salt: []const u8,
        ikm: []const u8,
    ) KeyScheduleError![]u8 {
        const hash_len = self.hash_alg.digestLength();
        const prk = try self.allocator.alloc(u8, hash_len);

        switch (self.hash_alg) {
            .sha256 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha256.init(salt);
                hmac.update(ikm);
                hmac.final(prk[0..32]);
            },
            .sha384 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha384.init(salt);
                hmac.update(ikm);
                hmac.final(prk[0..48]);
            },
            .sha512 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha512.init(salt);
                hmac.update(ikm);
                hmac.final(prk[0..64]);
            },
        }

        return prk;
    }
};

// Tests

test "Key schedule initialization" {
    const allocator = std.testing.allocator;

    var ks = try KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    try std.testing.expectEqual(HashAlgorithm.sha256, ks.hash_alg);
    try std.testing.expectEqual(@as(usize, 32), ks.transcript_hash.len);
}

test "Derive early secret without PSK" {
    const allocator = std.testing.allocator;

    var ks = try KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    const early_secret = try ks.deriveEarlySecret(null);
    defer allocator.free(early_secret);

    try std.testing.expectEqual(@as(usize, 32), early_secret.len);

    // Verify not all zeros
    var all_zeros = true;
    for (early_secret) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
}

test "Derive handshake secret" {
    const allocator = std.testing.allocator;

    var ks = try KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    const early_secret = try ks.deriveEarlySecret(null);
    defer allocator.free(early_secret);

    const ecdhe = "shared-ecdhe-secret-from-key-exchange".*;

    const handshake_secret = try ks.deriveHandshakeSecret(early_secret, &ecdhe);
    defer allocator.free(handshake_secret);

    try std.testing.expectEqual(@as(usize, 32), handshake_secret.len);
}

test "Derive master secret" {
    const allocator = std.testing.allocator;

    var ks = try KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    const early_secret = try ks.deriveEarlySecret(null);
    defer allocator.free(early_secret);

    const ecdhe = "shared-secret".*;
    const handshake_secret = try ks.deriveHandshakeSecret(early_secret, &ecdhe);
    defer allocator.free(handshake_secret);

    const master_secret = try ks.deriveMasterSecret(handshake_secret);
    defer allocator.free(master_secret);

    try std.testing.expectEqual(@as(usize, 32), master_secret.len);
}

test "Derive handshake traffic secrets" {
    const allocator = std.testing.allocator;

    var ks = try KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    const early_secret = try ks.deriveEarlySecret(null);
    defer allocator.free(early_secret);

    const ecdhe = "shared-secret".*;
    const handshake_secret = try ks.deriveHandshakeSecret(early_secret, &ecdhe);
    defer allocator.free(handshake_secret);

    // Update transcript (simulate handshake messages)
    ks.updateTranscript("ClientHello");
    ks.updateTranscript("ServerHello");

    const secrets = try ks.deriveHandshakeTrafficSecrets(handshake_secret);
    defer allocator.free(secrets.client);
    defer allocator.free(secrets.server);

    try std.testing.expectEqual(@as(usize, 32), secrets.client.len);
    try std.testing.expectEqual(@as(usize, 32), secrets.server.len);

    // Client and server secrets should be different
    try std.testing.expect(!std.mem.eql(u8, secrets.client, secrets.server));
}

test "Derive application traffic secrets" {
    const allocator = std.testing.allocator;

    var ks = try KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    const early_secret = try ks.deriveEarlySecret(null);
    defer allocator.free(early_secret);

    const ecdhe = "shared-secret".*;
    const handshake_secret = try ks.deriveHandshakeSecret(early_secret, &ecdhe);
    defer allocator.free(handshake_secret);

    const master_secret = try ks.deriveMasterSecret(handshake_secret);
    defer allocator.free(master_secret);

    // Update transcript
    ks.updateTranscript("full-handshake-transcript");

    const secrets = try ks.deriveApplicationTrafficSecrets(master_secret);
    defer allocator.free(secrets.client);
    defer allocator.free(secrets.server);

    try std.testing.expectEqual(@as(usize, 32), secrets.client.len);
    try std.testing.expectEqual(@as(usize, 32), secrets.server.len);

    // Client and server secrets should be different
    try std.testing.expect(!std.mem.eql(u8, secrets.client, secrets.server));
}

test "Transcript hash updates" {
    const allocator = std.testing.allocator;

    var ks = try KeySchedule.init(allocator, .sha256);
    defer ks.deinit();

    const initial_hash: [32]u8 = ks.transcript_hash[0..32].*;

    ks.updateTranscript("test-message");

    // Hash should have changed
    try std.testing.expect(!std.mem.eql(u8, &initial_hash, ks.transcript_hash[0..32]));
}

test "Key schedule with different hash algorithms" {
    const allocator = std.testing.allocator;

    var ks256 = try KeySchedule.init(allocator, .sha256);
    defer ks256.deinit();

    var ks384 = try KeySchedule.init(allocator, .sha384);
    defer ks384.deinit();

    try std.testing.expectEqual(@as(usize, 32), ks256.transcript_hash.len);
    try std.testing.expectEqual(@as(usize, 48), ks384.transcript_hash.len);
}
