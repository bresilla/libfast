const std = @import("std");
const runquic = @import("runquic.zig");

// Integration tests - test multiple modules working together

test "integration: packet with frames" {
    // Create a stream frame
    const stream_frame = runquic.frame.StreamFrame{
        .stream_id = 4,
        .offset = 0,
        .data = "Hello, QUIC!",
        .fin = true,
    };

    // Encode the frame
    var frame_buf: [1024]u8 = undefined;
    const frame_len = try stream_frame.encode(&frame_buf);

    try std.testing.expect(frame_len > 0);
    try std.testing.expect(frame_len < frame_buf.len);

    // Decode it back
    const decoded = try runquic.frame.StreamFrame.decode(frame_buf[0..frame_len]);
    try std.testing.expectEqual(stream_frame.stream_id, decoded.frame.stream_id);
    try std.testing.expectEqualStrings(stream_frame.data, decoded.frame.data);
}

test "integration: connection with streams" {
    const allocator = std.testing.allocator;

    const local_cid = try runquic.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try runquic.ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try runquic.connection.Connection.initClient(
        allocator,
        .tls,
        local_cid,
        remote_cid,
    );
    defer conn.deinit();

    conn.markEstablished();

    // Open a stream
    const stream_id = try conn.openStream(true);
    const stream = conn.getStream(stream_id).?;

    // Write data to stream
    const written = try stream.write("Test data");
    try std.testing.expectEqual(@as(usize, 9), written);

    // Check stream has data to send
    try std.testing.expect(stream.hasSendData());
}

test "integration: SSH obfuscated envelope with INIT" {
    const allocator = std.testing.allocator;

    const key = runquic.ssh_obfuscation.ObfuscationKey.fromKeyword("test-password");

    const versions = [_]u32{runquic.QUIC_VERSION_1};
    const kex_algs = [_]runquic.ssh_init.KexAlgorithm{
        .{ .name = "curve25519-sha256", .data = "" },
    };
    const cipher_suites = [_][]const u8{"TLS_AES_256_GCM_SHA384"};

    const init = runquic.ssh_init.SshQuicInit{
        .client_connection_id = &[_]u8{ 1, 2, 3, 4 },
        .server_name_indication = "example.com",
        .quic_versions = &versions,
        .transport_params = &[_]u8{},
        .signature_algorithms = "ssh-ed25519,ssh-rsa",
        .trusted_fingerprints = &[_][]const u8{},
        .kex_algorithms = &kex_algs,
        .cipher_suites = &cipher_suites,
        .extensions = &[_]runquic.ssh_init.ExtensionPair{},
    };

    // Encode and encrypt
    var encrypted: [2048]u8 = undefined;
    const enc_len = try init.encodeEncrypted(allocator, key, &encrypted);

    try std.testing.expect(enc_len >= runquic.ssh_init.MIN_PAYLOAD_SIZE);
    try std.testing.expect((encrypted[0] & 0x80) != 0); // High bit set

    // Decrypt and verify structure
    var decrypted: [2048]u8 = undefined;
    const dec_len = try runquic.ssh_obfuscation.ObfuscatedEnvelope.decrypt(
        encrypted[0..enc_len],
        key,
        &decrypted,
    );

    try std.testing.expect(dec_len >= runquic.ssh_init.MIN_PAYLOAD_SIZE);
    try std.testing.expectEqual(runquic.ssh_init.SSH_QUIC_INIT, decrypted[0]);
}

test "integration: varint in packet encoding" {
    // Test that varint encoding works correctly in packet context
    var buf: [100]u8 = undefined;
    var pos: usize = 0;

    // Encode several varints
    pos += try runquic.varint.encode(0, buf[pos..]);
    pos += try runquic.varint.encode(63, buf[pos..]);
    pos += try runquic.varint.encode(16383, buf[pos..]);
    pos += try runquic.varint.encode(1073741823, buf[pos..]);

    // Decode them back
    var read_pos: usize = 0;

    const v1 = try runquic.varint.decode(buf[read_pos..]);
    read_pos += v1.len;
    try std.testing.expectEqual(@as(u64, 0), v1.value);

    const v2 = try runquic.varint.decode(buf[read_pos..]);
    read_pos += v2.len;
    try std.testing.expectEqual(@as(u64, 63), v2.value);

    const v3 = try runquic.varint.decode(buf[read_pos..]);
    read_pos += v3.len;
    try std.testing.expectEqual(@as(u64, 16383), v3.value);

    const v4 = try runquic.varint.decode(buf[read_pos..]);
    read_pos += v4.len;
    try std.testing.expectEqual(@as(u64, 1073741823), v4.value);

    try std.testing.expectEqual(pos, read_pos);
}

test "integration: UDP socket with buffers" {
    const allocator = std.testing.allocator;

    // Create socket
    var socket = try runquic.udp.UdpSocket.bindAny(allocator, 0);
    defer socket.close();

    // Create ring buffer for receiving
    var ring_buf = try runquic.buffer.RingBuffer.init(allocator, 1024);
    defer ring_buf.deinit();

    // Get local address
    const addr = try socket.getLocalAddress();
    try std.testing.expect(addr.getPort() > 0);

    // Write to buffer
    const written = ring_buf.write("test packet data");
    try std.testing.expectEqual(@as(usize, 16), written);

    // Read from buffer
    var read_buf: [32]u8 = undefined;
    const read_len = ring_buf.read(&read_buf);
    try std.testing.expectEqual(@as(usize, 16), read_len);
    try std.testing.expectEqualStrings("test packet data", read_buf[0..read_len]);
}

test "integration: connection ID hashing and lookup" {
    const allocator = std.testing.allocator;

    var manager = runquic.connection.ConnectionManager.init(allocator);
    defer manager.deinit();

    // Create multiple connections
    const cid1 = try runquic.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const cid2 = try runquic.ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });
    const cid3 = try runquic.ConnectionId.init(&[_]u8{ 9, 10, 11, 12 });

    const remote = try runquic.ConnectionId.init(&[_]u8{ 99, 99, 99, 99 });

    const conn1 = try runquic.connection.Connection.initClient(allocator, .tls, cid1, remote);
    const conn2 = try runquic.connection.Connection.initClient(allocator, .tls, cid2, remote);
    const conn3 = try runquic.connection.Connection.initServer(allocator, .ssh, cid3, remote);

    const hash1 = runquic.connection.ConnectionManager.hashConnectionId(cid1);
    const hash2 = runquic.connection.ConnectionManager.hashConnectionId(cid2);
    const hash3 = runquic.connection.ConnectionManager.hashConnectionId(cid3);

    try manager.addConnection(hash1, conn1);
    try manager.addConnection(hash2, conn2);
    try manager.addConnection(hash3, conn3);

    // Retrieve connections
    const retrieved1 = manager.getConnection(hash1).?;
    try std.testing.expect(retrieved1.local_conn_id.eql(&cid1));
    try std.testing.expectEqual(runquic.QuicMode.tls, retrieved1.mode);

    const retrieved3 = manager.getConnection(hash3).?;
    try std.testing.expect(retrieved3.local_conn_id.eql(&cid3));
    try std.testing.expectEqual(runquic.QuicMode.ssh, retrieved3.mode);
    try std.testing.expect(retrieved3.is_server);
}

test "integration: time-based operations" {
    // Test timer with instant
    const start = runquic.time.Instant.now();

    var timer = runquic.time.Timer.init(runquic.time.Duration.MILLISECOND);

    // Timer should have some remaining time
    const remaining = timer.remaining();
    try std.testing.expect(remaining <= runquic.time.Duration.MILLISECOND);

    // Calculate duration
    const end = runquic.time.Instant.now();
    const elapsed = end.durationSince(start);

    try std.testing.expect(elapsed < runquic.time.Duration.SECOND);
}

test "integration: SSH key exchange packet flow" {
    const allocator = std.testing.allocator;

    // Shared obfuscation key
    const key = runquic.ssh_obfuscation.ObfuscationKey.fromKeyword("shared-secret");

    // Step 1: Client sends SSH_QUIC_INIT
    const versions = [_]u32{runquic.QUIC_VERSION_1};
    const kex_algs = [_]runquic.ssh_init.KexAlgorithm{
        .{ .name = "curve25519-sha256", .data = "" },
    };
    const cipher_suites = [_][]const u8{"TLS_AES_256_GCM_SHA384"};

    const init = runquic.ssh_init.SshQuicInit{
        .client_connection_id = &[_]u8{ 1, 2, 3, 4 },
        .server_name_indication = "example.com",
        .quic_versions = &versions,
        .transport_params = &[_]u8{},
        .signature_algorithms = "ssh-ed25519,ssh-rsa",
        .trusted_fingerprints = &[_][]const u8{},
        .kex_algorithms = &kex_algs,
        .cipher_suites = &cipher_suites,
        .extensions = &[_]runquic.ssh_init.ExtensionPair{},
    };

    var init_encrypted: [4096]u8 = undefined;
    const init_len = try init.encodeEncrypted(allocator, key, &init_encrypted);
    try std.testing.expect(init_len >= runquic.ssh_init.MIN_PAYLOAD_SIZE);

    // Step 2: Server responds with SSH_QUIC_REPLY
    const server_sig_algs = [_][]const u8{"ssh-ed25519"};
    const server_kex_algs = [_]runquic.ssh_reply.ServerKexAlgorithm{
        .{ .name = "curve25519-sha256", .data = "server-ephemeral-key" },
    };

    const reply = runquic.ssh_reply.SshQuicReply{
        .server_connection_id = &[_]u8{ 5, 6, 7, 8 },
        .server_quic_version = runquic.QUIC_VERSION_1,
        .transport_params = &[_]u8{},
        .signature_algorithms = &server_sig_algs,
        .kex_algorithms = &server_kex_algs,
        .cipher_suite = "TLS_AES_256_GCM_SHA384",
        .extensions = &[_]runquic.ssh_reply.ExtensionPair{},
    };

    var reply_encrypted: [8192]u8 = undefined;
    const reply_len = try reply.encodeEncrypted(
        allocator,
        key,
        init_len,
        &reply_encrypted,
    );

    // Verify amplification limit (server reply ≤ 3x client init)
    try std.testing.expect(reply_len <= init_len * runquic.ssh_reply.AMPLIFICATION_FACTOR + 100);

    // Step 3: Either party can send SSH_QUIC_CANCEL on error
    const cancel = runquic.ssh_cancel.SshQuicCancel.unsupportedKex();

    var cancel_encrypted: [2048]u8 = undefined;
    const cancel_len = try cancel.encodeEncrypted(allocator, key, &cancel_encrypted);
    try std.testing.expect(cancel_len > 0);

    // Verify all packets are properly obfuscated (high bit set)
    try std.testing.expect((init_encrypted[0] & 0x80) != 0);
    try std.testing.expect((reply_encrypted[0] & 0x80) != 0);
    try std.testing.expect((cancel_encrypted[0] & 0x80) != 0);

    // Step 4: Decrypt and verify INIT packet
    var init_decrypted: [4096]u8 = undefined;
    const init_dec_len = try runquic.ssh_obfuscation.ObfuscatedEnvelope.decrypt(
        init_encrypted[0..init_len],
        key,
        &init_decrypted,
    );
    try std.testing.expect(init_dec_len >= runquic.ssh_init.MIN_PAYLOAD_SIZE);
    try std.testing.expectEqual(runquic.ssh_init.SSH_QUIC_INIT, init_decrypted[0]);

    // Step 5: Decrypt and verify REPLY packet
    var reply_decrypted: [8192]u8 = undefined;
    const reply_dec_len = try runquic.ssh_obfuscation.ObfuscatedEnvelope.decrypt(
        reply_encrypted[0..reply_len],
        key,
        &reply_decrypted,
    );
    try std.testing.expect(reply_dec_len > 0);
    try std.testing.expectEqual(runquic.ssh_reply.SSH_QUIC_REPLY, reply_decrypted[0]);

    // Step 6: Decrypt and verify CANCEL packet
    var cancel_decrypted: [2048]u8 = undefined;
    const cancel_dec_len = try runquic.ssh_obfuscation.ObfuscatedEnvelope.decrypt(
        cancel_encrypted[0..cancel_len],
        key,
        &cancel_decrypted,
    );
    try std.testing.expect(cancel_dec_len > 0);
    try std.testing.expectEqual(runquic.ssh_cancel.SSH_QUIC_CANCEL, cancel_decrypted[0]);

    // Verify we can decode the cancel packet
    var decoded_cancel = try runquic.ssh_cancel.SshQuicCancel.decode(
        allocator,
        cancel_decrypted[0..cancel_dec_len],
    );
    defer decoded_cancel.deinit(allocator);

    try std.testing.expect(decoded_cancel.reason_phrase.len > 0);
}
