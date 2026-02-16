const std = @import("std");
const crypto = std.crypto;

/// Obfuscated envelope for SSH/QUIC key exchange (Section 2.3)
///
/// Format:
///   byte[16]  obfs-nonce (high bit of first byte MUST be set)
///   byte[]    obfs-payload (encrypted with AEAD_AES_256_GCM)
///   byte[16]  obfs-tag (GCM authentication tag)

pub const ObfuscationError = error{
    InvalidNonce,
    InvalidTag,
    BufferTooSmall,
    EncryptionFailed,
    DecryptionFailed,
    AuthenticationFailed,
};

/// Obfuscation key derived from keyword
pub const ObfuscationKey = struct {
    key: [32]u8,

    /// Derive key from obfuscation keyword (Section 2.3.1)
    pub fn fromKeyword(keyword: []const u8) ObfuscationKey {
        var key: [32]u8 = undefined;

        // Process keyword according to spec:
        // 1. OpaqueString profile (RFC 8265)
        // 2. Remove leading/trailing whitespace
        // 3. Encode as UTF-8
        // For simplicity, we just hash the raw keyword

        crypto.hash.sha2.Sha256.hash(keyword, &key, .{});

        return ObfuscationKey{ .key = key };
    }

    /// Create from empty keyword (default)
    pub fn empty() ObfuscationKey {
        return fromKeyword("");
    }
};

/// Obfuscated envelope
pub const ObfuscatedEnvelope = struct {
    const NONCE_LEN = 16;
    const TAG_LEN = 16;
    const OVERHEAD = NONCE_LEN + TAG_LEN;

    /// Encrypt payload into obfuscated envelope
    pub fn encrypt(
        plaintext: []const u8,
        key: ObfuscationKey,
        output: []u8,
    ) ObfuscationError!usize {
        if (output.len < plaintext.len + OVERHEAD) {
            return error.BufferTooSmall;
        }

        // Generate random nonce (16 bytes)
        var nonce: [NONCE_LEN]u8 = undefined;
        crypto.random.bytes(&nonce);

        // Set high bit of first byte (REQUIRED by spec)
        nonce[0] |= 0x80;

        // Encrypt using AEAD_AES_256_GCM
        // The nonce for GCM is typically 12 bytes, but SSH/QUIC uses 16 bytes
        // We'll use the first 12 bytes as the GCM nonce
        const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;

        const ciphertext = output[NONCE_LEN..][0..plaintext.len];
        const tag = output[NONCE_LEN + plaintext.len..][0..TAG_LEN];

        // Use first 12 bytes of nonce for GCM
        const gcm_nonce = nonce[0..12].*;

        Aes256Gcm.encrypt(
            ciphertext,
            tag,
            plaintext,
            &[_]u8{}, // No associated data
            gcm_nonce,
            key.key,
        );

        // Copy nonce to output
        @memcpy(output[0..NONCE_LEN], &nonce);

        return NONCE_LEN + plaintext.len + TAG_LEN;
    }

    /// Decrypt obfuscated envelope
    pub fn decrypt(
        envelope: []const u8,
        key: ObfuscationKey,
        output: []u8,
    ) ObfuscationError!usize {
        if (envelope.len < OVERHEAD) {
            return error.BufferTooSmall;
        }

        const nonce = envelope[0..NONCE_LEN];
        const ciphertext_len = envelope.len - OVERHEAD;
        const ciphertext = envelope[NONCE_LEN..][0..ciphertext_len];
        const tag = envelope[NONCE_LEN + ciphertext_len..][0..TAG_LEN];

        // Verify high bit of first nonce byte
        if ((nonce[0] & 0x80) == 0) {
            return error.InvalidNonce;
        }

        if (output.len < ciphertext_len) {
            return error.BufferTooSmall;
        }

        // Decrypt using AEAD_AES_256_GCM
        const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;

        // Use first 12 bytes of nonce for GCM
        const gcm_nonce = nonce[0..12].*;

        Aes256Gcm.decrypt(
            output[0..ciphertext_len],
            ciphertext,
            tag.*,
            &[_]u8{}, // No associated data
            gcm_nonce,
            key.key,
        ) catch {
            return error.AuthenticationFailed;
        };

        return ciphertext_len;
    }

    /// Calculate overhead size
    pub fn overhead() usize {
        return OVERHEAD;
    }
};

// Tests

test "obfuscation key from keyword" {
    const key1 = ObfuscationKey.fromKeyword("test-keyword");
    const key2 = ObfuscationKey.fromKeyword("test-keyword");
    const key3 = ObfuscationKey.fromKeyword("different");

    // Same keyword produces same key
    try std.testing.expectEqualSlices(u8, &key1.key, &key2.key);

    // Different keyword produces different key
    try std.testing.expect(!std.mem.eql(u8, &key1.key, &key3.key));
}

test "obfuscation key empty" {
    const key = ObfuscationKey.empty();
    try std.testing.expect(key.key.len == 32);
}

test "obfuscated envelope encrypt and decrypt" {
    const key = ObfuscationKey.fromKeyword("secret");
    const plaintext = "Hello, SSH/QUIC!";

    var encrypted: [1024]u8 = undefined;
    const enc_len = try ObfuscatedEnvelope.encrypt(plaintext, key, &encrypted);

    try std.testing.expect(enc_len == plaintext.len + ObfuscatedEnvelope.overhead());

    // Verify high bit is set in nonce
    try std.testing.expect((encrypted[0] & 0x80) != 0);

    var decrypted: [1024]u8 = undefined;
    const dec_len = try ObfuscatedEnvelope.decrypt(encrypted[0..enc_len], key, &decrypted);

    try std.testing.expectEqual(plaintext.len, dec_len);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..dec_len]);
}

test "obfuscated envelope wrong key fails" {
    const key1 = ObfuscationKey.fromKeyword("secret1");
    const key2 = ObfuscationKey.fromKeyword("secret2");
    const plaintext = "Hello, SSH/QUIC!";

    var encrypted: [1024]u8 = undefined;
    const enc_len = try ObfuscatedEnvelope.encrypt(plaintext, key1, &encrypted);

    var decrypted: [1024]u8 = undefined;
    const result = ObfuscatedEnvelope.decrypt(encrypted[0..enc_len], key2, &decrypted);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "obfuscated envelope tampering detection" {
    const key = ObfuscationKey.fromKeyword("secret");
    const plaintext = "Hello, SSH/QUIC!";

    var encrypted: [1024]u8 = undefined;
    const enc_len = try ObfuscatedEnvelope.encrypt(plaintext, key, &encrypted);

    // Tamper with ciphertext
    encrypted[20] ^= 0xFF;

    var decrypted: [1024]u8 = undefined;
    const result = ObfuscatedEnvelope.decrypt(encrypted[0..enc_len], key, &decrypted);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "obfuscated envelope minimum size" {
    const key = ObfuscationKey.fromKeyword("secret");
    const plaintext = "";

    var encrypted: [1024]u8 = undefined;
    const enc_len = try ObfuscatedEnvelope.encrypt(plaintext, key, &encrypted);

    try std.testing.expectEqual(ObfuscatedEnvelope.overhead(), enc_len);

    var decrypted: [1024]u8 = undefined;
    const dec_len = try ObfuscatedEnvelope.decrypt(encrypted[0..enc_len], key, &decrypted);

    try std.testing.expectEqual(@as(usize, 0), dec_len);
}
