const std = @import("std");
const crypto = std.crypto;
const aead = @import("aead.zig");

/// Header protection for QUIC packets (RFC 9001 Section 5.4)
///
/// Protects packet numbers and certain header flags from analysis.
/// Uses AES-ECB or ChaCha20 depending on the AEAD algorithm.

pub const HeaderProtectionError = error{
    InvalidKeyLength,
    InvalidSampleLength,
    ProtectionFailed,
};

const SAMPLE_LENGTH = 16; // Always 16 bytes for both AES and ChaCha20

/// Header protection cipher
pub const HeaderProtection = struct {
    algorithm: aead.AeadAlgorithm,
    hp_key: []const u8,

    /// Initialize header protection with key
    pub fn init(algorithm: aead.AeadAlgorithm, hp_key: []const u8) HeaderProtectionError!HeaderProtection {
        const expected_len = algorithm.keyLength();
        if (hp_key.len != expected_len) {
            return error.InvalidKeyLength;
        }

        return HeaderProtection{
            .algorithm = algorithm,
            .hp_key = hp_key,
        };
    }

    /// Generate header protection mask from sample
    ///
    /// Sample is 16 bytes from the packet payload after the packet number
    pub fn generateMask(self: HeaderProtection, sample: []const u8) HeaderProtectionError![]const u8 {
        if (sample.len != SAMPLE_LENGTH) {
            return error.InvalidSampleLength;
        }

        switch (self.algorithm) {
            .aes_128_gcm, .aes_256_gcm => {
                return self.generateMaskAes(sample);
            },
            .chacha20_poly1305 => {
                return self.generateMaskChaCha(sample);
            },
        }
    }

    /// Generate mask using AES-ECB (for AES-GCM ciphers)
    fn generateMaskAes(self: HeaderProtection, sample: []const u8) HeaderProtectionError![]const u8 {
        var mask: [16]u8 = undefined;

        switch (self.algorithm) {
            .aes_128_gcm => {
                const key: [16]u8 = self.hp_key[0..16].*;
                const block_cipher = crypto.core.aes.Aes128.initEnc(key);
                block_cipher.encrypt(&mask, sample[0..16]);
            },
            .aes_256_gcm => {
                const key: [32]u8 = self.hp_key[0..32].*;
                const block_cipher = crypto.core.aes.Aes256.initEnc(key);
                block_cipher.encrypt(&mask, sample[0..16]);
            },
            else => unreachable,
        }

        // Allocate and return mask (caller must free)
        const result = std.heap.page_allocator.alloc(u8, 16) catch {
            return error.ProtectionFailed;
        };
        @memcpy(result, &mask);
        return result;
    }

    /// Generate mask using ChaCha20
    fn generateMaskChaCha(self: HeaderProtection, sample: []const u8) HeaderProtectionError![]const u8 {
        // ChaCha20 with counter=0, key=hp_key, nonce=sample[0..12]
        const key: [32]u8 = self.hp_key[0..32].*;
        const nonce: [12]u8 = sample[0..12].*;

        // Generate 16 bytes of ChaCha20 keystream
        var mask: [16]u8 = undefined;
        const zeros: [16]u8 = [_]u8{0} ** 16;

        // ChaCha20 keystream (XOR with zeros to get the keystream)
        const ChaCha20 = crypto.stream.chacha.ChaCha20IETF;
        ChaCha20.xor(&mask, &zeros, 0, key, nonce);

        // Allocate and return mask
        const result = std.heap.page_allocator.alloc(u8, 16) catch {
            return error.ProtectionFailed;
        };
        @memcpy(result, &mask);
        return result;
    }

    /// Protect packet header (encrypt packet number and flags)
    ///
    /// first_byte: The first byte of the packet header (modified in place)
    /// pn_bytes: Packet number bytes (modified in place)
    /// sample: 16-byte sample from payload
    pub fn protect(
        self: HeaderProtection,
        first_byte: *u8,
        pn_bytes: []u8,
        sample: []const u8,
    ) HeaderProtectionError!void {
        const mask = try self.generateMask(sample);
        defer std.heap.page_allocator.free(mask);

        // Mask first byte (protect certain bits)
        // Long header: protect bits 4-0
        // Short header: protect bits 4-0
        const is_long_header = (first_byte.* & 0x80) != 0;

        if (is_long_header) {
            // Long header: apply mask to lower 4 bits of first byte
            first_byte.* ^= mask[0] & 0x0F;
        } else {
            // Short header: apply mask to lower 5 bits of first byte
            first_byte.* ^= mask[0] & 0x1F;
        }

        // Mask packet number bytes (up to 4 bytes)
        const pn_len = @min(pn_bytes.len, 4);
        for (0..pn_len) |i| {
            pn_bytes[i] ^= mask[1 + i];
        }
    }

    /// Unprotect packet header (decrypt packet number and flags)
    ///
    /// Same operation as protect (XOR is symmetric)
    pub fn unprotect(
        self: HeaderProtection,
        first_byte: *u8,
        pn_bytes: []u8,
        sample: []const u8,
    ) HeaderProtectionError!void {
        // XOR is symmetric, so unprotect = protect
        try self.protect(first_byte, pn_bytes, sample);
    }

    /// Get sample length requirement
    pub fn sampleLength() usize {
        return SAMPLE_LENGTH;
    }
};

// Tests

test "AES-128-GCM header protection" {
    const hp_key = "0123456789abcdef".*; // 16 bytes
    const sample = "sample_data_here".*; // 16 bytes

    const hp = try HeaderProtection.init(.aes_128_gcm, &hp_key);

    // Generate mask
    const mask = try hp.generateMask(&sample);
    defer std.heap.page_allocator.free(mask);

    try std.testing.expectEqual(@as(usize, 16), mask.len);

    // Verify mask is not all zeros
    var all_zeros = true;
    for (mask) |byte| {
        if (byte != 0) {
            all_zeros = false;
            break;
        }
    }
    try std.testing.expect(!all_zeros);
}

test "AES-256-GCM header protection" {
    const hp_key = "01234567890123456789012345678901".*; // 32 bytes
    const sample = "sample_data_here".*;

    const hp = try HeaderProtection.init(.aes_256_gcm, &hp_key);

    const mask = try hp.generateMask(&sample);
    defer std.heap.page_allocator.free(mask);

    try std.testing.expectEqual(@as(usize, 16), mask.len);
}

test "ChaCha20-Poly1305 header protection" {
    const hp_key = "01234567890123456789012345678901".*; // 32 bytes
    const sample = "sample_data_here".*;

    const hp = try HeaderProtection.init(.chacha20_poly1305, &hp_key);

    const mask = try hp.generateMask(&sample);
    defer std.heap.page_allocator.free(mask);

    try std.testing.expectEqual(@as(usize, 16), mask.len);
}

test "Protect and unprotect short header" {
    const hp_key = "0123456789abcdef".*;
    const sample = "sample_data_here".*;

    const hp = try HeaderProtection.init(.aes_128_gcm, &hp_key);

    // Original values
    var first_byte: u8 = 0x40; // Short header
    var pn_bytes = [_]u8{ 0x12, 0x34, 0x56, 0x78 };

    // Save originals
    const orig_first = first_byte;
    const orig_pn = pn_bytes;

    // Protect
    try hp.protect(&first_byte, &pn_bytes, &sample);

    // Verify protection changed values
    try std.testing.expect(first_byte != orig_first);
    try std.testing.expect(!std.mem.eql(u8, &pn_bytes, &orig_pn));

    // Unprotect
    try hp.unprotect(&first_byte, &pn_bytes, &sample);

    // Verify restoration
    try std.testing.expectEqual(orig_first, first_byte);
    try std.testing.expectEqualSlices(u8, &orig_pn, &pn_bytes);
}

test "Protect and unprotect long header" {
    const hp_key = "0123456789abcdef".*;
    const sample = "sample_data_here".*;

    const hp = try HeaderProtection.init(.aes_128_gcm, &hp_key);

    // Original values
    var first_byte: u8 = 0xC0; // Long header
    var pn_bytes = [_]u8{ 0xAB, 0xCD };

    // Save originals
    const orig_first = first_byte;
    const orig_pn = pn_bytes;

    // Protect
    try hp.protect(&first_byte, &pn_bytes, &sample);

    // Verify protection changed values
    try std.testing.expect(first_byte != orig_first);

    // Unprotect
    try hp.unprotect(&first_byte, &pn_bytes, &sample);

    // Verify restoration
    try std.testing.expectEqual(orig_first, first_byte);
    try std.testing.expectEqualSlices(u8, &orig_pn, &pn_bytes);
}

test "Different samples produce different masks" {
    const hp_key = "0123456789abcdef".*;
    const sample1 = "sample_one______".*;
    const sample2 = "sample_two______".*;

    const hp = try HeaderProtection.init(.aes_128_gcm, &hp_key);

    const mask1 = try hp.generateMask(&sample1);
    defer std.heap.page_allocator.free(mask1);

    const mask2 = try hp.generateMask(&sample2);
    defer std.heap.page_allocator.free(mask2);

    // Different samples should produce different masks
    try std.testing.expect(!std.mem.eql(u8, mask1, mask2));
}

test "Same sample produces same mask" {
    const hp_key = "0123456789abcdef".*;
    const sample = "sample_data_here".*;

    const hp = try HeaderProtection.init(.aes_128_gcm, &hp_key);

    const mask1 = try hp.generateMask(&sample);
    defer std.heap.page_allocator.free(mask1);

    const mask2 = try hp.generateMask(&sample);
    defer std.heap.page_allocator.free(mask2);

    // Same sample should produce same mask
    try std.testing.expectEqualSlices(u8, mask1, mask2);
}

test "Invalid key length" {
    const short_key = "tooshort".*;
    const result = HeaderProtection.init(.aes_128_gcm, &short_key);

    try std.testing.expectError(error.InvalidKeyLength, result);
}

test "Invalid sample length" {
    const hp_key = "0123456789abcdef".*;
    const short_sample = "short".*;

    const hp = try HeaderProtection.init(.aes_128_gcm, &hp_key);
    const result = hp.generateMask(&short_sample);

    try std.testing.expectError(error.InvalidSampleLength, result);
}
