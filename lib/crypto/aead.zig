const std = @import("std");
const crypto = std.crypto;

/// AEAD (Authenticated Encryption with Associated Data) operations for QUIC
///
/// Supports:
/// - AES-128-GCM
/// - AES-256-GCM
/// - ChaCha20-Poly1305

pub const AeadError = error{
    InvalidKeyLength,
    InvalidNonceLength,
    InvalidTagLength,
    EncryptionFailed,
    DecryptionFailed,
    AuthenticationFailed,
};

/// AEAD algorithm identifier
pub const AeadAlgorithm = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    /// Get key length in bytes
    pub fn keyLength(self: AeadAlgorithm) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 32,
            .chacha20_poly1305 => 32,
        };
    }

    /// Get nonce length in bytes
    pub fn nonceLength(self: AeadAlgorithm) usize {
        return switch (self) {
            .aes_128_gcm => 12,
            .aes_256_gcm => 12,
            .chacha20_poly1305 => 12,
        };
    }

    /// Get tag length in bytes
    pub fn tagLength(self: AeadAlgorithm) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm => 16,
            .chacha20_poly1305 => 16,
        };
    }

    /// Get overhead (tag length)
    pub fn overhead(self: AeadAlgorithm) usize {
        return self.tagLength();
    }
};

/// AEAD cipher context
pub const AeadCipher = struct {
    algorithm: AeadAlgorithm,
    key: []const u8,

    /// Initialize AEAD cipher with key
    pub fn init(algorithm: AeadAlgorithm, key: []const u8) AeadError!AeadCipher {
        if (key.len != algorithm.keyLength()) {
            return error.InvalidKeyLength;
        }

        return AeadCipher{
            .algorithm = algorithm,
            .key = key,
        };
    }

    /// Encrypt plaintext with associated data
    ///
    /// Output buffer must have space for plaintext.len + tag_length
    pub fn encrypt(
        self: AeadCipher,
        nonce: []const u8,
        plaintext: []const u8,
        associated_data: []const u8,
        output: []u8,
    ) AeadError!usize {
        if (nonce.len != self.algorithm.nonceLength()) {
            return error.InvalidNonceLength;
        }

        const tag_len = self.algorithm.tagLength();
        if (output.len < plaintext.len + tag_len) {
            return error.EncryptionFailed;
        }

        const ciphertext = output[0..plaintext.len];
        var tag_buf: [16]u8 = undefined;

        switch (self.algorithm) {
            .aes_128_gcm => {
                const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
                const key: [16]u8 = self.key[0..16].*;
                const nonce_arr: [12]u8 = nonce[0..12].*;

                Aes128Gcm.encrypt(ciphertext, &tag_buf, plaintext, associated_data, nonce_arr, key);
            },
            .aes_256_gcm => {
                const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
                const key: [32]u8 = self.key[0..32].*;
                const nonce_arr: [12]u8 = nonce[0..12].*;

                Aes256Gcm.encrypt(ciphertext, &tag_buf, plaintext, associated_data, nonce_arr, key);
            },
            .chacha20_poly1305 => {
                const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
                const key: [32]u8 = self.key[0..32].*;
                const nonce_arr: [12]u8 = nonce[0..12].*;

                ChaCha20Poly1305.encrypt(ciphertext, &tag_buf, plaintext, associated_data, nonce_arr, key);
            },
        }

        // Copy tag to output
        @memcpy(output[plaintext.len..][0..tag_len], tag_buf[0..tag_len]);

        return plaintext.len + tag_len;
    }

    /// Decrypt ciphertext with associated data
    ///
    /// Input must include tag (ciphertext.len + tag_length)
    /// Output buffer must have space for ciphertext.len - tag_length
    pub fn decrypt(
        self: AeadCipher,
        nonce: []const u8,
        ciphertext_and_tag: []const u8,
        associated_data: []const u8,
        output: []u8,
    ) AeadError!usize {
        if (nonce.len != self.algorithm.nonceLength()) {
            return error.InvalidNonceLength;
        }

        const tag_len = self.algorithm.tagLength();
        if (ciphertext_and_tag.len < tag_len) {
            return error.DecryptionFailed;
        }

        const ciphertext_len = ciphertext_and_tag.len - tag_len;
        if (output.len < ciphertext_len) {
            return error.DecryptionFailed;
        }

        const ciphertext = ciphertext_and_tag[0..ciphertext_len];
        const tag = ciphertext_and_tag[ciphertext_len..][0..tag_len];

        switch (self.algorithm) {
            .aes_128_gcm => {
                const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
                const key: [16]u8 = self.key[0..16].*;
                const nonce_arr: [12]u8 = nonce[0..12].*;
                const tag_arr: [16]u8 = tag[0..16].*;

                Aes128Gcm.decrypt(
                    output[0..ciphertext_len],
                    ciphertext,
                    tag_arr,
                    associated_data,
                    nonce_arr,
                    key,
                ) catch {
                    return error.AuthenticationFailed;
                };
            },
            .aes_256_gcm => {
                const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
                const key: [32]u8 = self.key[0..32].*;
                const nonce_arr: [12]u8 = nonce[0..12].*;
                const tag_arr: [16]u8 = tag[0..16].*;

                Aes256Gcm.decrypt(
                    output[0..ciphertext_len],
                    ciphertext,
                    tag_arr,
                    associated_data,
                    nonce_arr,
                    key,
                ) catch {
                    return error.AuthenticationFailed;
                };
            },
            .chacha20_poly1305 => {
                const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
                const key: [32]u8 = self.key[0..32].*;
                const nonce_arr: [12]u8 = nonce[0..12].*;
                const tag_arr: [16]u8 = tag[0..16].*;

                ChaCha20Poly1305.decrypt(
                    output[0..ciphertext_len],
                    ciphertext,
                    tag_arr,
                    associated_data,
                    nonce_arr,
                    key,
                ) catch {
                    return error.AuthenticationFailed;
                };
            },
        }

        return ciphertext_len;
    }
};

// Tests

test "AES-128-GCM encrypt and decrypt" {
    const key = "0123456789abcdef".*; // 16 bytes
    const nonce = "unique nonce".*; // 12 bytes
    const plaintext = "Hello, QUIC with AES-128-GCM!";
    const associated_data = "packet header";

    const cipher = try AeadCipher.init(.aes_128_gcm, &key);

    // Encrypt
    var encrypted: [128]u8 = undefined;
    const enc_len = try cipher.encrypt(&nonce, plaintext, associated_data, &encrypted);

    try std.testing.expect(enc_len == plaintext.len + 16); // 16-byte tag

    // Decrypt
    var decrypted: [128]u8 = undefined;
    const dec_len = try cipher.decrypt(&nonce, encrypted[0..enc_len], associated_data, &decrypted);

    try std.testing.expectEqual(plaintext.len, dec_len);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..dec_len]);
}

test "AES-256-GCM encrypt and decrypt" {
    const key = "01234567890123456789012345678901".*; // 32 bytes
    const nonce = "unique nonce".*; // 12 bytes
    const plaintext = "Hello, QUIC with AES-256-GCM!";
    const associated_data = "packet header";

    const cipher = try AeadCipher.init(.aes_256_gcm, &key);

    // Encrypt
    var encrypted: [128]u8 = undefined;
    const enc_len = try cipher.encrypt(&nonce, plaintext, associated_data, &encrypted);

    try std.testing.expect(enc_len == plaintext.len + 16);

    // Decrypt
    var decrypted: [128]u8 = undefined;
    const dec_len = try cipher.decrypt(&nonce, encrypted[0..enc_len], associated_data, &decrypted);

    try std.testing.expectEqual(plaintext.len, dec_len);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..dec_len]);
}

test "ChaCha20-Poly1305 encrypt and decrypt" {
    const key = "01234567890123456789012345678901".*; // 32 bytes
    const nonce = "unique nonce".*; // 12 bytes
    const plaintext = "Hello, QUIC with ChaCha20-Poly1305!";
    const associated_data = "packet header";

    const cipher = try AeadCipher.init(.chacha20_poly1305, &key);

    // Encrypt
    var encrypted: [128]u8 = undefined;
    const enc_len = try cipher.encrypt(&nonce, plaintext, associated_data, &encrypted);

    try std.testing.expect(enc_len == plaintext.len + 16);

    // Decrypt
    var decrypted: [128]u8 = undefined;
    const dec_len = try cipher.decrypt(&nonce, encrypted[0..enc_len], associated_data, &decrypted);

    try std.testing.expectEqual(plaintext.len, dec_len);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..dec_len]);
}

test "Authentication failure with wrong key" {
    const key1 = "0123456789abcdef".*;
    const key2 = "fedcba9876543210".*;
    const nonce = "unique nonce".*;
    const plaintext = "Secret message";
    const associated_data = "";

    const cipher1 = try AeadCipher.init(.aes_128_gcm, &key1);
    const cipher2 = try AeadCipher.init(.aes_128_gcm, &key2);

    // Encrypt with key1
    var encrypted: [128]u8 = undefined;
    const enc_len = try cipher1.encrypt(&nonce, plaintext, associated_data, &encrypted);

    // Try to decrypt with key2 (should fail)
    var decrypted: [128]u8 = undefined;
    const result = cipher2.decrypt(&nonce, encrypted[0..enc_len], associated_data, &decrypted);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "Authentication failure with wrong associated data" {
    const key = "0123456789abcdef".*;
    const nonce = "unique nonce".*;
    const plaintext = "Secret message";
    const associated_data1 = "header1";
    const associated_data2 = "header2";

    const cipher = try AeadCipher.init(.aes_128_gcm, &key);

    // Encrypt with associated_data1
    var encrypted: [128]u8 = undefined;
    const enc_len = try cipher.encrypt(&nonce, plaintext, associated_data1, &encrypted);

    // Try to decrypt with associated_data2 (should fail)
    var decrypted: [128]u8 = undefined;
    const result = cipher.decrypt(&nonce, encrypted[0..enc_len], associated_data2, &decrypted);

    try std.testing.expectError(error.AuthenticationFailed, result);
}

test "Invalid key length" {
    const short_key = "tooshort".*;
    const result = AeadCipher.init(.aes_128_gcm, &short_key);

    try std.testing.expectError(error.InvalidKeyLength, result);
}

test "AEAD algorithm parameters" {
    try std.testing.expectEqual(@as(usize, 16), AeadAlgorithm.aes_128_gcm.keyLength());
    try std.testing.expectEqual(@as(usize, 32), AeadAlgorithm.aes_256_gcm.keyLength());
    try std.testing.expectEqual(@as(usize, 32), AeadAlgorithm.chacha20_poly1305.keyLength());

    try std.testing.expectEqual(@as(usize, 12), AeadAlgorithm.aes_128_gcm.nonceLength());
    try std.testing.expectEqual(@as(usize, 16), AeadAlgorithm.aes_128_gcm.tagLength());
}
