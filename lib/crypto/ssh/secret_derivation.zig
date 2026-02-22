const std = @import("std");
const crypto = std.crypto;
const kex_methods = @import("kex_methods.zig");

/// Secret derivation for SSH/QUIC (Section 5.1)
///
/// Converts SSH key exchange outputs (K, H) into QUIC secrets
/// using HMAC-HASH(K, H) where HASH is the hash algorithm from
/// the key exchange method.
pub const DerivationError = error{
    InvalidHashAlgorithm,
    DerivationFailed,
    OutOfMemory,
};

/// QUIC secrets derived from SSH key exchange
pub const QuicSecrets = struct {
    /// Client initial secret
    client_initial_secret: [32]u8,

    /// Server initial secret
    server_initial_secret: [32]u8,

    /// Hash algorithm used
    hash_algorithm: kex_methods.HashAlgorithm,

    /// Zero out secrets when done
    pub fn zeroize(self: *QuicSecrets) void {
        @memset(&self.client_initial_secret, 0);
        @memset(&self.server_initial_secret, 0);
    }
};

/// Derive QUIC secrets from SSH key exchange
///
/// Section 5.1: The client and server initial secrets are derived as:
///   client_initial_secret = HMAC-HASH(K, "client" || H)
///   server_initial_secret = HMAC-HASH(K, "server" || H)
///
/// Where:
///   K = shared secret from key exchange
///   H = exchange hash from key exchange
///   HASH = hash algorithm used in key exchange (SHA-256, SHA-384, SHA-512)
pub fn deriveQuicSecrets(
    shared_secret: []const u8,
    exchange_hash: []const u8,
    hash_algorithm: kex_methods.HashAlgorithm,
) DerivationError!QuicSecrets {
    var secrets = QuicSecrets{
        .client_initial_secret = undefined,
        .server_initial_secret = undefined,
        .hash_algorithm = hash_algorithm,
    };

    // Derive client initial secret: HMAC-HASH(K, "client" || H)
    const client_label = "client";

    switch (hash_algorithm) {
        .sha256 => {
            var client_hmac = crypto.auth.hmac.sha2.HmacSha256.init(shared_secret);
            client_hmac.update(client_label);
            client_hmac.update(exchange_hash);
            client_hmac.final(&secrets.client_initial_secret);
        },
        .sha384 => {
            var client_hmac = crypto.auth.hmac.sha2.HmacSha384.init(shared_secret);
            client_hmac.update(client_label);
            client_hmac.update(exchange_hash);
            var client_digest: [48]u8 = undefined;
            defer @memset(&client_digest, 0);
            client_hmac.final(&client_digest);
            // Truncate to 32 bytes for QUIC
            @memcpy(&secrets.client_initial_secret, client_digest[0..32]);
        },
        .sha512 => {
            var client_hmac = crypto.auth.hmac.sha2.HmacSha512.init(shared_secret);
            client_hmac.update(client_label);
            client_hmac.update(exchange_hash);
            var client_digest: [64]u8 = undefined;
            defer @memset(&client_digest, 0);
            client_hmac.final(&client_digest);
            // Truncate to 32 bytes for QUIC
            @memcpy(&secrets.client_initial_secret, client_digest[0..32]);
        },
    }

    // Derive server initial secret: HMAC-HASH(K, "server" || H)
    const server_label = "server";

    switch (hash_algorithm) {
        .sha256 => {
            var server_hmac = crypto.auth.hmac.sha2.HmacSha256.init(shared_secret);
            server_hmac.update(server_label);
            server_hmac.update(exchange_hash);
            server_hmac.final(&secrets.server_initial_secret);
        },
        .sha384 => {
            var server_hmac = crypto.auth.hmac.sha2.HmacSha384.init(shared_secret);
            server_hmac.update(server_label);
            server_hmac.update(exchange_hash);
            var server_digest: [48]u8 = undefined;
            defer @memset(&server_digest, 0);
            server_hmac.final(&server_digest);
            // Truncate to 32 bytes for QUIC
            @memcpy(&secrets.server_initial_secret, server_digest[0..32]);
        },
        .sha512 => {
            var server_hmac = crypto.auth.hmac.sha2.HmacSha512.init(shared_secret);
            server_hmac.update(server_label);
            server_hmac.update(exchange_hash);
            var server_digest: [64]u8 = undefined;
            defer @memset(&server_digest, 0);
            server_hmac.final(&server_digest);
            // Truncate to 32 bytes for QUIC
            @memcpy(&secrets.server_initial_secret, server_digest[0..32]);
        },
    }

    return secrets;
}

/// Derive additional key material using HKDF-Expand-Label pattern
///
/// This follows QUIC's key derivation pattern but uses SSH-derived base secrets
pub fn expandLabel(
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    length: usize,
    hash_algorithm: kex_methods.HashAlgorithm,
    output: []u8,
) DerivationError!void {
    if (output.len < length) return error.DerivationFailed;

    // Build HKDF info directly into HMAC input stream to avoid heap allocations.
    if (length > 0xFFFF) return error.DerivationFailed;

    const length_be = [2]u8{
        @intCast((length >> 8) & 0xFF),
        @intCast(length & 0xFF),
    };

    const prefix = "tls13 ";
    if (prefix.len + label.len > 255) return error.DerivationFailed;
    if (context.len > 255) return error.DerivationFailed;

    const full_label_len: u8 = @intCast(prefix.len + label.len);
    const context_len: u8 = @intCast(context.len);
    const counter = [_]u8{0x01};

    // Use HMAC as PRF for HKDF-Expand
    switch (hash_algorithm) {
        .sha256 => {
            var hmac = crypto.auth.hmac.sha2.HmacSha256.init(secret);
            hmac.update(&length_be);
            hmac.update(&[_]u8{full_label_len});
            hmac.update(prefix);
            hmac.update(label);
            hmac.update(&[_]u8{context_len});
            if (context.len > 0) hmac.update(context);
            hmac.update(&counter); // HKDF counter
            var digest: [32]u8 = undefined;
            defer @memset(&digest, 0);
            hmac.final(&digest);
            @memcpy(output[0..@min(length, 32)], digest[0..@min(length, 32)]);
        },
        .sha384 => {
            var hmac = crypto.auth.hmac.sha2.HmacSha384.init(secret);
            hmac.update(&length_be);
            hmac.update(&[_]u8{full_label_len});
            hmac.update(prefix);
            hmac.update(label);
            hmac.update(&[_]u8{context_len});
            if (context.len > 0) hmac.update(context);
            hmac.update(&counter);
            var digest: [48]u8 = undefined;
            defer @memset(&digest, 0);
            hmac.final(&digest);
            @memcpy(output[0..@min(length, 48)], digest[0..@min(length, 48)]);
        },
        .sha512 => {
            var hmac = crypto.auth.hmac.sha2.HmacSha512.init(secret);
            hmac.update(&length_be);
            hmac.update(&[_]u8{full_label_len});
            hmac.update(prefix);
            hmac.update(label);
            hmac.update(&[_]u8{context_len});
            if (context.len > 0) hmac.update(context);
            hmac.update(&counter);
            var digest: [64]u8 = undefined;
            defer @memset(&digest, 0);
            hmac.final(&digest);
            @memcpy(output[0..@min(length, 64)], digest[0..@min(length, 64)]);
        },
    }
}

// Tests

test "Derive QUIC secrets from SSH key exchange" {
    // Simulate SSH key exchange outputs
    const shared_secret = "test-shared-secret-from-curve25519-key-exchange";
    const exchange_hash = "test-exchange-hash-from-sha256";

    var secrets = try deriveQuicSecrets(
        shared_secret,
        exchange_hash,
        .sha256,
    );
    defer secrets.zeroize();

    // Verify secrets are different
    try std.testing.expect(!std.mem.eql(u8, &secrets.client_initial_secret, &secrets.server_initial_secret));

    // Verify they're not all zeros
    var all_zeros = true;
    for (secrets.client_initial_secret) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
}

test "Derive QUIC secrets with different hash algorithms" {
    const shared_secret = "shared-secret";
    const exchange_hash = "exchange-hash";

    // SHA-256
    var secrets_256 = try deriveQuicSecrets(shared_secret, exchange_hash, .sha256);
    defer secrets_256.zeroize();

    // SHA-384
    var secrets_384 = try deriveQuicSecrets(shared_secret, exchange_hash, .sha384);
    defer secrets_384.zeroize();

    // SHA-512
    var secrets_512 = try deriveQuicSecrets(shared_secret, exchange_hash, .sha512);
    defer secrets_512.zeroize();

    // All should produce different secrets
    try std.testing.expect(!std.mem.eql(u8, &secrets_256.client_initial_secret, &secrets_384.client_initial_secret));
    try std.testing.expect(!std.mem.eql(u8, &secrets_256.client_initial_secret, &secrets_512.client_initial_secret));
    try std.testing.expect(!std.mem.eql(u8, &secrets_384.client_initial_secret, &secrets_512.client_initial_secret));
}

test "Secret derivation is deterministic" {
    const shared_secret = "test-secret";
    const exchange_hash = "test-hash";

    var secrets1 = try deriveQuicSecrets(shared_secret, exchange_hash, .sha256);
    defer secrets1.zeroize();

    var secrets2 = try deriveQuicSecrets(shared_secret, exchange_hash, .sha256);
    defer secrets2.zeroize();

    // Same inputs should produce same outputs
    try std.testing.expectEqualSlices(u8, &secrets1.client_initial_secret, &secrets2.client_initial_secret);
    try std.testing.expectEqualSlices(u8, &secrets1.server_initial_secret, &secrets2.server_initial_secret);
}

test "Expand label for additional key material" {
    const secret = "base-secret-from-key-exchange";
    const label = "quic key";
    const context = "";

    var output: [16]u8 = undefined;
    try expandLabel(secret, label, context, 16, .sha256, &output);

    // Verify output is not all zeros
    var all_zeros = true;
    for (output) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
}

test "Expand label with different labels produces different keys" {
    const secret = "base-secret";
    const context = "";

    var key_output: [16]u8 = undefined;
    var iv_output: [16]u8 = undefined;

    try expandLabel(secret, "quic key", context, 16, .sha256, &key_output);
    try expandLabel(secret, "quic iv", context, 16, .sha256, &iv_output);

    // Different labels should produce different outputs
    try std.testing.expect(!std.mem.eql(u8, &key_output, &iv_output));
}

test "Secrets can be zeroized" {
    const shared_secret = "secret";
    const exchange_hash = "hash";

    var secrets = try deriveQuicSecrets(shared_secret, exchange_hash, .sha256);

    // Verify not all zeros initially
    var all_zeros = true;
    for (secrets.client_initial_secret) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);

    // Zeroize
    secrets.zeroize();

    // Now should be all zeros
    for (secrets.client_initial_secret) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
    for (secrets.server_initial_secret) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}
