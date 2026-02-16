const std = @import("std");
const aead_mod = @import("aead.zig");
const keys_mod = @import("keys.zig");
const header_protection = @import("header_protection.zig");

/// Top-level crypto abstraction for QUIC
///
/// Supports both TLS and SSH modes with unified interface

pub const CryptoError = error{
    InvalidMode,
    InvalidAlgorithm,
    KeyDerivationFailed,
    EncryptionFailed,
    DecryptionFailed,
    OutOfMemory,
} || aead_mod.AeadError || keys_mod.KeyError || header_protection.HeaderProtectionError;

/// Crypto mode for QUIC connection
pub const CryptoMode = enum {
    tls, // Standard TLS 1.3 mode (RFC 9001)
    ssh, // SSH/QUIC key exchange mode

    pub fn toString(self: CryptoMode) []const u8 {
        return switch (self) {
            .tls => "TLS",
            .ssh => "SSH",
        };
    }
};

/// Encryption level for QUIC packets
pub const EncryptionLevel = enum {
    initial, // Initial packets (uses initial secrets)
    handshake, // Handshake packets
    application, // Application data (1-RTT)

    pub fn toString(self: EncryptionLevel) []const u8 {
        return switch (self) {
            .initial => "Initial",
            .handshake => "Handshake",
            .application => "Application",
        };
    }
};

/// Cipher suite configuration
pub const CipherSuite = struct {
    aead: aead_mod.AeadAlgorithm,
    hash: keys_mod.HashAlgorithm,

    /// TLS_AES_128_GCM_SHA256 (mandatory for QUIC)
    pub const TLS_AES_128_GCM_SHA256 = CipherSuite{
        .aead = .aes_128_gcm,
        .hash = .sha256,
    };

    /// TLS_AES_256_GCM_SHA384
    pub const TLS_AES_256_GCM_SHA384 = CipherSuite{
        .aead = .aes_256_gcm,
        .hash = .sha384,
    };

    /// TLS_CHACHA20_POLY1305_SHA256
    pub const TLS_CHACHA20_POLY1305_SHA256 = CipherSuite{
        .aead = .chacha20_poly1305,
        .hash = .sha256,
    };

    /// Get cipher suite by name
    pub fn fromName(suite_name: []const u8) ?CipherSuite {
        if (std.mem.eql(u8, suite_name, "TLS_AES_128_GCM_SHA256")) {
            return TLS_AES_128_GCM_SHA256;
        } else if (std.mem.eql(u8, suite_name, "TLS_AES_256_GCM_SHA384")) {
            return TLS_AES_256_GCM_SHA384;
        } else if (std.mem.eql(u8, suite_name, "TLS_CHACHA20_POLY1305_SHA256")) {
            return TLS_CHACHA20_POLY1305_SHA256;
        }
        return null;
    }

    pub fn name(self: CipherSuite) []const u8 {
        if (self.aead == .aes_128_gcm and self.hash == .sha256) {
            return "TLS_AES_128_GCM_SHA256";
        } else if (self.aead == .aes_256_gcm and self.hash == .sha384) {
            return "TLS_AES_256_GCM_SHA384";
        } else if (self.aead == .chacha20_poly1305 and self.hash == .sha256) {
            return "TLS_CHACHA20_POLY1305_SHA256";
        }
        return "Unknown";
    }
};

/// Crypto context for a QUIC connection
pub const CryptoContext = struct {
    mode: CryptoMode,
    cipher_suite: CipherSuite,
    allocator: std.mem.Allocator,

    // Encryption keys (per level)
    client_keys: ?keys_mod.KeyMaterial = null,
    server_keys: ?keys_mod.KeyMaterial = null,

    // AEAD ciphers
    client_cipher: ?aead_mod.AeadCipher = null,
    server_cipher: ?aead_mod.AeadCipher = null,

    // Header protection
    client_hp: ?header_protection.HeaderProtection = null,
    server_hp: ?header_protection.HeaderProtection = null,

    /// Initialize crypto context
    pub fn init(
        allocator: std.mem.Allocator,
        mode: CryptoMode,
        cipher_suite: CipherSuite,
    ) CryptoContext {
        return CryptoContext{
            .mode = mode,
            .cipher_suite = cipher_suite,
            .allocator = allocator,
        };
    }

    /// Install secrets and derive keys
    pub fn installSecrets(
        self: *CryptoContext,
        client_secret: []const u8,
        server_secret: []const u8,
    ) CryptoError!void {
        // Derive client keys
        var client_keys = try keys_mod.deriveKeyMaterial(
            self.allocator,
            client_secret,
            self.cipher_suite.aead,
            self.cipher_suite.hash,
        );
        errdefer client_keys.deinit();

        // Derive server keys
        var server_keys = try keys_mod.deriveKeyMaterial(
            self.allocator,
            server_secret,
            self.cipher_suite.aead,
            self.cipher_suite.hash,
        );
        errdefer server_keys.deinit();

        // Create AEAD ciphers
        const client_cipher = try aead_mod.AeadCipher.init(
            self.cipher_suite.aead,
            client_keys.key,
        );
        const server_cipher = try aead_mod.AeadCipher.init(
            self.cipher_suite.aead,
            server_keys.key,
        );

        // Create header protection
        const client_hp = try header_protection.HeaderProtection.init(
            self.cipher_suite.aead,
            client_keys.hp_key,
        );
        const server_hp = try header_protection.HeaderProtection.init(
            self.cipher_suite.aead,
            server_keys.hp_key,
        );

        // Clean up old keys if they exist
        if (self.client_keys) |*old| old.deinit();
        if (self.server_keys) |*old| old.deinit();

        // Install new keys
        self.client_keys = client_keys;
        self.server_keys = server_keys;
        self.client_cipher = client_cipher;
        self.server_cipher = server_cipher;
        self.client_hp = client_hp;
        self.server_hp = server_hp;
    }

    /// Encrypt packet payload (client)
    pub fn encryptClient(
        self: *CryptoContext,
        nonce: []const u8,
        plaintext: []const u8,
        associated_data: []const u8,
        output: []u8,
    ) CryptoError!usize {
        if (self.client_cipher == null) return error.EncryptionFailed;

        return self.client_cipher.?.encrypt(
            nonce,
            plaintext,
            associated_data,
            output,
        ) catch error.EncryptionFailed;
    }

    /// Decrypt packet payload (client receives from server)
    pub fn decryptClient(
        self: *CryptoContext,
        nonce: []const u8,
        ciphertext_and_tag: []const u8,
        associated_data: []const u8,
        output: []u8,
    ) CryptoError!usize {
        if (self.server_cipher == null) return error.DecryptionFailed;

        return self.server_cipher.?.decrypt(
            nonce,
            ciphertext_and_tag,
            associated_data,
            output,
        ) catch error.DecryptionFailed;
    }

    /// Encrypt packet payload (server)
    pub fn encryptServer(
        self: *CryptoContext,
        nonce: []const u8,
        plaintext: []const u8,
        associated_data: []const u8,
        output: []u8,
    ) CryptoError!usize {
        if (self.server_cipher == null) return error.EncryptionFailed;

        return self.server_cipher.?.encrypt(
            nonce,
            plaintext,
            associated_data,
            output,
        ) catch error.EncryptionFailed;
    }

    /// Decrypt packet payload (server receives from client)
    pub fn decryptServer(
        self: *CryptoContext,
        nonce: []const u8,
        ciphertext_and_tag: []const u8,
        associated_data: []const u8,
        output: []u8,
    ) CryptoError!usize {
        if (self.client_cipher == null) return error.DecryptionFailed;

        return self.client_cipher.?.decrypt(
            nonce,
            ciphertext_and_tag,
            associated_data,
            output,
        ) catch error.DecryptionFailed;
    }

    /// Protect packet header (client)
    pub fn protectHeaderClient(
        self: *CryptoContext,
        first_byte: *u8,
        pn_bytes: []u8,
        sample: []const u8,
    ) CryptoError!void {
        if (self.client_hp == null) return error.EncryptionFailed;

        try self.client_hp.?.protect(first_byte, pn_bytes, sample);
    }

    /// Unprotect packet header (client receives from server)
    pub fn unprotectHeaderClient(
        self: *CryptoContext,
        first_byte: *u8,
        pn_bytes: []u8,
        sample: []const u8,
    ) CryptoError!void {
        if (self.server_hp == null) return error.DecryptionFailed;

        try self.server_hp.?.unprotect(first_byte, pn_bytes, sample);
    }

    /// Protect packet header (server)
    pub fn protectHeaderServer(
        self: *CryptoContext,
        first_byte: *u8,
        pn_bytes: []u8,
        sample: []const u8,
    ) CryptoError!void {
        if (self.server_hp == null) return error.EncryptionFailed;

        try self.server_hp.?.protect(first_byte, pn_bytes, sample);
    }

    /// Unprotect packet header (server receives from client)
    pub fn unprotectHeaderServer(
        self: *CryptoContext,
        first_byte: *u8,
        pn_bytes: []u8,
        sample: []const u8,
    ) CryptoError!void {
        if (self.client_hp == null) return error.DecryptionFailed;

        try self.client_hp.?.unprotect(first_byte, pn_bytes, sample);
    }

    /// Clean up
    pub fn deinit(self: *CryptoContext) void {
        if (self.client_keys) |*keys| keys.deinit();
        if (self.server_keys) |*keys| keys.deinit();
    }
};

// Tests

test "Create crypto context for TLS mode" {
    const allocator = std.testing.allocator;

    var ctx = CryptoContext.init(
        allocator,
        .tls,
        CipherSuite.TLS_AES_128_GCM_SHA256,
    );
    defer ctx.deinit();

    try std.testing.expectEqual(CryptoMode.tls, ctx.mode);
    try std.testing.expectEqual(aead_mod.AeadAlgorithm.aes_128_gcm, ctx.cipher_suite.aead);
}

test "Create crypto context for SSH mode" {
    const allocator = std.testing.allocator;

    var ctx = CryptoContext.init(
        allocator,
        .ssh,
        CipherSuite.TLS_AES_256_GCM_SHA384,
    );
    defer ctx.deinit();

    try std.testing.expectEqual(CryptoMode.ssh, ctx.mode);
    try std.testing.expectEqual(aead_mod.AeadAlgorithm.aes_256_gcm, ctx.cipher_suite.aead);
}

test "Install secrets and derive keys" {
    const allocator = std.testing.allocator;

    var ctx = CryptoContext.init(
        allocator,
        .tls,
        CipherSuite.TLS_AES_128_GCM_SHA256,
    );
    defer ctx.deinit();

    const client_secret = "client-initial-secret-32-bytes!!".*;
    const server_secret = "server-initial-secret-32-bytes!!".*;

    try ctx.installSecrets(&client_secret, &server_secret);

    // Verify keys were installed
    try std.testing.expect(ctx.client_keys != null);
    try std.testing.expect(ctx.server_keys != null);
    try std.testing.expect(ctx.client_cipher != null);
    try std.testing.expect(ctx.server_cipher != null);
}

test "Client encrypt and server decrypt" {
    const allocator = std.testing.allocator;

    // Client context
    var client_ctx = CryptoContext.init(
        allocator,
        .tls,
        CipherSuite.TLS_AES_128_GCM_SHA256,
    );
    defer client_ctx.deinit();

    // Server context (shares same secrets)
    var server_ctx = CryptoContext.init(
        allocator,
        .tls,
        CipherSuite.TLS_AES_128_GCM_SHA256,
    );
    defer server_ctx.deinit();

    const client_secret = "client-secret-for-test-32bytes!".*;
    const server_secret = "server-secret-for-test-32bytes!".*;

    try client_ctx.installSecrets(&client_secret, &server_secret);
    try server_ctx.installSecrets(&client_secret, &server_secret);

    // Client encrypts
    const nonce = "unique_nonce".*;
    const plaintext = "Hello from client!";
    const associated_data = "packet_header";

    var encrypted: [128]u8 = undefined;
    const enc_len = try client_ctx.encryptClient(
        &nonce,
        plaintext,
        associated_data,
        &encrypted,
    );

    // Server decrypts
    var decrypted: [128]u8 = undefined;
    const dec_len = try server_ctx.decryptServer(
        &nonce,
        encrypted[0..enc_len],
        associated_data,
        &decrypted,
    );

    try std.testing.expectEqual(plaintext.len, dec_len);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..dec_len]);
}

test "Server encrypt and client decrypt" {
    const allocator = std.testing.allocator;

    var client_ctx = CryptoContext.init(allocator, .tls, CipherSuite.TLS_AES_128_GCM_SHA256);
    defer client_ctx.deinit();

    var server_ctx = CryptoContext.init(allocator, .tls, CipherSuite.TLS_AES_128_GCM_SHA256);
    defer server_ctx.deinit();

    const client_secret = "client-secret-32-bytes-for-test!".*;
    const server_secret = "server-secret-32-bytes-for-test!".*;

    try client_ctx.installSecrets(&client_secret, &server_secret);
    try server_ctx.installSecrets(&client_secret, &server_secret);

    // Server encrypts
    const nonce = "unique_nonce".*;
    const plaintext = "Hello from server!";
    const associated_data = "packet_header";

    var encrypted: [128]u8 = undefined;
    const enc_len = try server_ctx.encryptServer(&nonce, plaintext, associated_data, &encrypted);

    // Client decrypts
    var decrypted: [128]u8 = undefined;
    const dec_len = try client_ctx.decryptClient(&nonce, encrypted[0..enc_len], associated_data, &decrypted);

    try std.testing.expectEqual(plaintext.len, dec_len);
    try std.testing.expectEqualStrings(plaintext, decrypted[0..dec_len]);
}

test "Cipher suite from name" {
    const suite1 = CipherSuite.fromName("TLS_AES_128_GCM_SHA256");
    try std.testing.expect(suite1 != null);
    try std.testing.expectEqual(aead_mod.AeadAlgorithm.aes_128_gcm, suite1.?.aead);

    const suite2 = CipherSuite.fromName("TLS_AES_256_GCM_SHA384");
    try std.testing.expect(suite2 != null);
    try std.testing.expectEqual(aead_mod.AeadAlgorithm.aes_256_gcm, suite2.?.aead);

    const suite3 = CipherSuite.fromName("INVALID");
    try std.testing.expect(suite3 == null);
}

test "Cipher suite name" {
    const suite = CipherSuite.TLS_AES_128_GCM_SHA256;
    try std.testing.expectEqualStrings("TLS_AES_128_GCM_SHA256", suite.name());
}
