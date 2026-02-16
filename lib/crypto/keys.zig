const std = @import("std");
const crypto = std.crypto;
const aead = @import("aead.zig");

/// QUIC key derivation using HKDF (RFC 5869)
///
/// This implements the key derivation specified in RFC 9001 (QUIC-TLS)
/// and adapts it for SSH/QUIC mode.

pub const KeyError = error{
    InvalidSecretLength,
    DerivationFailed,
    OutOfMemory,
};

/// Hash algorithm for key derivation
pub const HashAlgorithm = enum {
    sha256,
    sha384,
    sha512,

    pub fn digestLength(self: HashAlgorithm) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
            .sha512 => 64,
        };
    }
};

/// QUIC key material derived from secrets
pub const KeyMaterial = struct {
    /// Encryption/decryption key
    key: []u8,

    /// Initialization vector (IV)
    iv: []u8,

    /// Header protection key
    hp_key: []u8,

    allocator: std.mem.Allocator,

    /// Free allocated memory
    pub fn deinit(self: *KeyMaterial) void {
        // Zero out sensitive key material
        @memset(self.key, 0);
        @memset(self.iv, 0);
        @memset(self.hp_key, 0);

        self.allocator.free(self.key);
        self.allocator.free(self.iv);
        self.allocator.free(self.hp_key);
    }
};

/// Derive key material from secret using HKDF-Expand-Label
///
/// This implements the TLS 1.3 key schedule adapted for QUIC.
/// Label format: "tls13 " + label
pub fn deriveKeyMaterial(
    allocator: std.mem.Allocator,
    secret: []const u8,
    algorithm: aead.AeadAlgorithm,
    hash_alg: HashAlgorithm,
) KeyError!KeyMaterial {
    const key_len = algorithm.keyLength();
    const iv_len = algorithm.nonceLength();
    const hp_len = key_len; // Header protection key same size as encryption key

    var material = KeyMaterial{
        .key = try allocator.alloc(u8, key_len),
        .iv = try allocator.alloc(u8, iv_len),
        .hp_key = try allocator.alloc(u8, hp_len),
        .allocator = allocator,
    };
    errdefer material.deinit();

    // Derive key: HKDF-Expand-Label(secret, "quic key", "", key_len)
    try hkdfExpandLabel(secret, "quic key", "", key_len, hash_alg, material.key);

    // Derive IV: HKDF-Expand-Label(secret, "quic iv", "", iv_len)
    try hkdfExpandLabel(secret, "quic iv", "", iv_len, hash_alg, material.iv);

    // Derive header protection key: HKDF-Expand-Label(secret, "quic hp", "", hp_len)
    try hkdfExpandLabel(secret, "quic hp", "", hp_len, hash_alg, material.hp_key);

    return material;
}

/// HKDF-Expand-Label as defined in RFC 8446 (TLS 1.3) Section 7.1
///
/// HKDF-Expand-Label(Secret, Label, Context, Length) =
///     HKDF-Expand(Secret, HkdfLabel, Length)
///
/// Where HkdfLabel is:
///   struct {
///       uint16 length = Length;
///       opaque label<7..255> = "tls13 " + Label;
///       opaque context<0..255> = Context;
///   } HkdfLabel;
fn hkdfExpandLabel(
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    length: usize,
    hash_alg: HashAlgorithm,
    output: []u8,
) KeyError!void {
    if (output.len < length) return error.DerivationFailed;

    // Build HkdfLabel
    var hkdf_label: std.ArrayList(u8) = .{};
    defer hkdf_label.deinit(std.heap.page_allocator);

    // Length (2 bytes, big-endian)
    try hkdf_label.append(std.heap.page_allocator, @intCast((length >> 8) & 0xFF));
    try hkdf_label.append(std.heap.page_allocator, @intCast(length & 0xFF));

    // Label: length byte + "tls13 " + label
    const prefix = "tls13 ";
    const full_label_len: u8 = @intCast(prefix.len + label.len);
    try hkdf_label.append(std.heap.page_allocator, full_label_len);
    try hkdf_label.appendSlice(std.heap.page_allocator, prefix);
    try hkdf_label.appendSlice(std.heap.page_allocator, label);

    // Context: length byte + context
    const context_len: u8 = @intCast(context.len);
    try hkdf_label.append(std.heap.page_allocator, context_len);
    if (context.len > 0) {
        try hkdf_label.appendSlice(std.heap.page_allocator, context);
    }

    // HKDF-Expand using HMAC as PRF
    try hkdfExpand(secret, hkdf_label.items, length, hash_alg, output);
}

/// HKDF-Expand as defined in RFC 5869
///
/// HKDF-Expand(PRK, info, L) -> OKM
fn hkdfExpand(
    prk: []const u8,
    info: []const u8,
    length: usize,
    hash_alg: HashAlgorithm,
    output: []u8,
) KeyError!void {
    if (output.len < length) return error.DerivationFailed;

    const hash_len = hash_alg.digestLength();
    const n = (length + hash_len - 1) / hash_len; // Ceiling division

    if (n > 255) return error.DerivationFailed;

    var pos: usize = 0;
    var t_prev: [64]u8 = undefined; // Max hash size (SHA-512)
    var t_prev_len: usize = 0;

    var i: u8 = 1;
    while (i <= n) : (i += 1) {
        // T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
        var t: [64]u8 = undefined;

        switch (hash_alg) {
            .sha256 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha256.init(prk);
                if (t_prev_len > 0) {
                    hmac.update(t_prev[0..t_prev_len]);
                }
                hmac.update(info);
                hmac.update(&[_]u8{i});
                hmac.final(t[0..32]);
                t_prev_len = 32;
            },
            .sha384 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha384.init(prk);
                if (t_prev_len > 0) {
                    hmac.update(t_prev[0..t_prev_len]);
                }
                hmac.update(info);
                hmac.update(&[_]u8{i});
                hmac.final(t[0..48]);
                t_prev_len = 48;
            },
            .sha512 => {
                var hmac = crypto.auth.hmac.sha2.HmacSha512.init(prk);
                if (t_prev_len > 0) {
                    hmac.update(t_prev[0..t_prev_len]);
                }
                hmac.update(info);
                hmac.update(&[_]u8{i});
                hmac.final(t[0..64]);
                t_prev_len = 64;
            },
        }

        // Copy to output
        const copy_len = @min(t_prev_len, length - pos);
        @memcpy(output[pos..][0..copy_len], t[0..copy_len]);
        pos += copy_len;

        // Save for next iteration
        @memcpy(t_prev[0..t_prev_len], t[0..t_prev_len]);

        if (pos >= length) break;
    }
}

/// Update secret for next key phase (RFC 9001 Section 6)
///
/// new_secret = HKDF-Expand-Label(old_secret, "quic ku", "", Hash.length)
pub fn updateSecret(
    allocator: std.mem.Allocator,
    old_secret: []const u8,
    hash_alg: HashAlgorithm,
) KeyError![]u8 {
    const secret_len = hash_alg.digestLength();
    const new_secret = try allocator.alloc(u8, secret_len);
    errdefer allocator.free(new_secret);

    try hkdfExpandLabel(old_secret, "quic ku", "", secret_len, hash_alg, new_secret);

    return new_secret;
}

// Tests

test "Derive key material for AES-128-GCM" {
    const allocator = std.testing.allocator;

    // Test secret (32 bytes)
    const secret = "test-secret-for-aes-128-gcm-key".*;

    var material = try deriveKeyMaterial(
        allocator,
        &secret,
        .aes_128_gcm,
        .sha256,
    );
    defer material.deinit();

    // Verify key lengths
    try std.testing.expectEqual(@as(usize, 16), material.key.len);
    try std.testing.expectEqual(@as(usize, 12), material.iv.len);
    try std.testing.expectEqual(@as(usize, 16), material.hp_key.len);

    // Verify keys are not all zeros
    var all_zeros = true;
    for (material.key) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
}

test "Derive key material for AES-256-GCM" {
    const allocator = std.testing.allocator;

    const secret = "test-secret-for-aes-256-gcm-key-material-derivation".*;

    var material = try deriveKeyMaterial(
        allocator,
        &secret,
        .aes_256_gcm,
        .sha256,
    );
    defer material.deinit();

    // Verify key lengths
    try std.testing.expectEqual(@as(usize, 32), material.key.len);
    try std.testing.expectEqual(@as(usize, 12), material.iv.len);
    try std.testing.expectEqual(@as(usize, 32), material.hp_key.len);
}

test "Derive key material for ChaCha20-Poly1305" {
    const allocator = std.testing.allocator;

    const secret = "test-secret-for-chacha20-poly1305-key-derivation-test".*;

    var material = try deriveKeyMaterial(
        allocator,
        &secret,
        .chacha20_poly1305,
        .sha256,
    );
    defer material.deinit();

    // Verify key lengths
    try std.testing.expectEqual(@as(usize, 32), material.key.len);
    try std.testing.expectEqual(@as(usize, 12), material.iv.len);
    try std.testing.expectEqual(@as(usize, 32), material.hp_key.len);
}

test "Key derivation is deterministic" {
    const allocator = std.testing.allocator;

    const secret = "deterministic-test-secret".*;

    var material1 = try deriveKeyMaterial(allocator, &secret, .aes_128_gcm, .sha256);
    defer material1.deinit();

    var material2 = try deriveKeyMaterial(allocator, &secret, .aes_128_gcm, .sha256);
    defer material2.deinit();

    // Same inputs should produce same outputs
    try std.testing.expectEqualSlices(u8, material1.key, material2.key);
    try std.testing.expectEqualSlices(u8, material1.iv, material2.iv);
    try std.testing.expectEqualSlices(u8, material1.hp_key, material2.hp_key);
}

test "Different secrets produce different keys" {
    const allocator = std.testing.allocator;

    const secret1 = "secret-one-for-key-derivation-test".*;
    const secret2 = "secret-two-for-key-derivation-test".*;

    var material1 = try deriveKeyMaterial(allocator, &secret1, .aes_128_gcm, .sha256);
    defer material1.deinit();

    var material2 = try deriveKeyMaterial(allocator, &secret2, .aes_128_gcm, .sha256);
    defer material2.deinit();

    // Different secrets should produce different keys
    try std.testing.expect(!std.mem.eql(u8, material1.key, material2.key));
    try std.testing.expect(!std.mem.eql(u8, material1.iv, material2.iv));
    try std.testing.expect(!std.mem.eql(u8, material1.hp_key, material2.hp_key));
}

test "Update secret for key phase" {
    const allocator = std.testing.allocator;

    const old_secret = "original-secret-for-key-update".*;

    const new_secret = try updateSecret(allocator, &old_secret, .sha256);
    defer allocator.free(new_secret);

    // New secret should be different
    try std.testing.expect(!std.mem.eql(u8, &old_secret, new_secret));
    try std.testing.expectEqual(@as(usize, 32), new_secret.len); // SHA-256 digest length
}

test "Key update is deterministic" {
    const allocator = std.testing.allocator;

    const old_secret = "test-secret".*;

    const new_secret1 = try updateSecret(allocator, &old_secret, .sha256);
    defer allocator.free(new_secret1);

    const new_secret2 = try updateSecret(allocator, &old_secret, .sha256);
    defer allocator.free(new_secret2);

    // Same input should produce same output
    try std.testing.expectEqualSlices(u8, new_secret1, new_secret2);
}

test "HKDF-Expand with different hash algorithms" {
    const secret = "test-secret-for-hkdf".*;
    const info = "test-info";

    var output_sha256: [32]u8 = undefined;
    var output_sha384: [48]u8 = undefined;
    var output_sha512: [64]u8 = undefined;

    try hkdfExpand(&secret, info, 32, .sha256, &output_sha256);
    try hkdfExpand(&secret, info, 48, .sha384, &output_sha384);
    try hkdfExpand(&secret, info, 64, .sha512, &output_sha512);

    // All should produce non-zero output
    var all_zeros = true;
    for (output_sha256) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
}
