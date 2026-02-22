const std = @import("std");
const config_mod = @import("config.zig");
const types_mod = @import("types.zig");
const conn_internal = @import("../core/connection.zig");
const stream_internal = @import("../core/stream.zig");
const udp_mod = @import("../transport/udp.zig");
const crypto_mod = @import("../crypto/crypto.zig");
const packet_mod = @import("../core/packet.zig");
const frame_mod = @import("../core/frame.zig");
const core_types = @import("../core/types.zig");
const varint = @import("../utils/varint.zig");
const time_mod = @import("../utils/time.zig");

const DEFAULT_SHORT_HEADER_DCID_LEN: u8 = 8;
const CLOSE_REASON_MAX_LEN: usize = 256;

/// Public QUIC connection handle
pub const QuicConnection = struct {
    allocator: std.mem.Allocator,
    config: config_mod.QuicConfig,
    state: types_mod.ConnectionState,

    // Internal connection
    internal_conn: ?*conn_internal.Connection,

    // UDP socket
    socket: ?*udp_mod.UdpSocket,

    // Crypto context
    crypto_ctx: ?*crypto_mod.CryptoContext,

    // Event queue
    events: std.ArrayList(types_mod.ConnectionEvent),

    // Remote address (for client)
    remote_addr: ?std.net.Address,

    // Basic packet visibility counters
    packets_received: u64,
    packets_invalid: u64,

    // Connection close state tracking
    close_reason_buf: [CLOSE_REASON_MAX_LEN]u8,
    close_reason_len: usize,
    close_error_code: u64,
    drain_pending: bool,
    closed_event_emitted: bool,

    /// Initialize a new QUIC connection
    pub fn init(
        allocator: std.mem.Allocator,
        config: config_mod.QuicConfig,
    ) types_mod.QuicError!QuicConnection {
        config.validate() catch |err| {
            return switch (err) {
                error.MissingSshConfig => types_mod.QuicError.MissingSshConfig,
                error.MissingTlsConfig => types_mod.QuicError.MissingTlsConfig,
                error.MissingServerCredentials => types_mod.QuicError.MissingServerCredentials,
                error.MissingServerName => types_mod.QuicError.MissingServerName,
                error.InvalidTlsVerificationConfig => types_mod.QuicError.InvalidTlsVerificationConfig,
            };
        };

        return QuicConnection{
            .allocator = allocator,
            .config = config,
            .state = .idle,
            .internal_conn = null,
            .socket = null,
            .crypto_ctx = null,
            .events = .{},
            .remote_addr = null,
            .packets_received = 0,
            .packets_invalid = 0,
            .close_reason_buf = [_]u8{0} ** CLOSE_REASON_MAX_LEN,
            .close_reason_len = 0,
            .close_error_code = 0,
            .drain_pending = false,
            .closed_event_emitted = false,
        };
    }

    fn setCloseReason(self: *QuicConnection, reason: []const u8) void {
        const len = @min(reason.len, CLOSE_REASON_MAX_LEN);
        @memcpy(self.close_reason_buf[0..len], reason[0..len]);
        self.close_reason_len = len;
    }

    fn closeReason(self: *QuicConnection) []const u8 {
        return self.close_reason_buf[0..self.close_reason_len];
    }

    fn enterDraining(
        self: *QuicConnection,
        error_code: u64,
        reason: []const u8,
    ) types_mod.QuicError!void {
        self.setCloseReason(reason);
        self.close_error_code = error_code;
        self.drain_pending = true;
        self.state = .draining;

        try self.events.append(self.allocator, .{
            .closing = .{
                .error_code = error_code,
                .reason = self.closeReason(),
            },
        });
    }

    fn shortHeaderDcidLen(self: *QuicConnection) u8 {
        if (self.internal_conn) |conn| {
            return conn.local_conn_id.len;
        }
        return DEFAULT_SHORT_HEADER_DCID_LEN;
    }

    fn decodePacketHeader(self: *QuicConnection, packet: []const u8) types_mod.QuicError!usize {
        if (packet.len == 0) {
            return types_mod.QuicError.InvalidPacket;
        }

        const is_long_header = (packet[0] & 0x80) != 0;

        if (is_long_header) {
            const result = packet_mod.LongHeader.decode(packet) catch {
                return types_mod.QuicError.InvalidPacket;
            };
            return result.consumed;
        }

        const dcid_len = self.shortHeaderDcidLen();
        const result = packet_mod.ShortHeader.decode(packet, dcid_len) catch {
            return types_mod.QuicError.InvalidPacket;
        };
        return result.consumed;
    }

    fn queueProtocolViolation(self: *QuicConnection, reason: []const u8) types_mod.QuicError!void {
        if (self.state == .closed) {
            return;
        }

        try self.enterDraining(1, reason);
    }

    fn routeFrame(self: *QuicConnection, payload: []const u8) types_mod.QuicError!void {
        if (payload.len == 0) return;

        const frame_type_result = varint.decode(payload) catch {
            return types_mod.QuicError.InvalidPacket;
        };

        const frame_type = frame_type_result.value;

        if (core_types.FrameType.isStreamFrame(frame_type)) {
            const decoded = frame_mod.StreamFrame.decode(payload) catch {
                return types_mod.QuicError.InvalidPacket;
            };
            const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;
            const stream = conn.getOrCreateStream(decoded.frame.stream_id) catch {
                return types_mod.QuicError.StreamError;
            };

            stream.appendRecvData(decoded.frame.data, decoded.frame.offset, decoded.frame.fin) catch {
                return types_mod.QuicError.InvalidPacket;
            };

            try self.events.append(self.allocator, .{ .stream_readable = decoded.frame.stream_id });
            return;
        }

        switch (frame_type) {
            0x01 => {
                _ = frame_mod.PingFrame.decode(payload) catch {
                    return types_mod.QuicError.InvalidPacket;
                };
            },
            0x02, 0x03 => {
                const decoded = frame_mod.AckFrame.decode(payload) catch {
                    return types_mod.QuicError.InvalidPacket;
                };
                if (self.internal_conn) |conn| {
                    conn.processAckDetailed(decoded.frame.largest_acked, decoded.frame.ack_delay);
                }
            },
            0x1c, 0x1d => {
                const decoded = frame_mod.ConnectionCloseFrame.decode(payload) catch {
                    return types_mod.QuicError.InvalidPacket;
                };

                try self.enterDraining(decoded.frame.error_code, decoded.frame.reason);
            },
            0x04 => {
                const decoded = frame_mod.ResetStreamFrame.decode(payload) catch {
                    return types_mod.QuicError.InvalidPacket;
                };

                const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;
                const stream = conn.getOrCreateStream(decoded.frame.stream_id) catch {
                    return types_mod.QuicError.StreamError;
                };

                stream.recv_state = .reset_read;
                stream.fin_received = true;

                try self.events.append(self.allocator, .{
                    .stream_closed = .{
                        .id = decoded.frame.stream_id,
                        .error_code = decoded.frame.error_code,
                    },
                });
            },
            0x05 => {
                const decoded = frame_mod.StopSendingFrame.decode(payload) catch {
                    return types_mod.QuicError.InvalidPacket;
                };

                const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;
                const stream = conn.getOrCreateStream(decoded.frame.stream_id) catch {
                    return types_mod.QuicError.StreamError;
                };
                stream.reset(decoded.frame.error_code);
            },
            else => {
                // Unknown/unhandled frame type in this slice: ignore.
            },
        }
    }

    /// Start connecting (client only)
    pub fn connect(
        self: *QuicConnection,
        remote_address: []const u8,
        remote_port: u16,
    ) types_mod.QuicError!void {
        if (self.config.role != .client) {
            return types_mod.QuicError.InvalidState;
        }

        if (self.state != .idle) {
            return types_mod.QuicError.InvalidState;
        }

        // Parse address
        const addr = std.net.Address.parseIp(remote_address, remote_port) catch {
            return types_mod.QuicError.InvalidAddress;
        };
        self.remote_addr = addr;

        // Create UDP socket
        const socket = try self.allocator.create(udp_mod.UdpSocket);
        errdefer self.allocator.destroy(socket);

        socket.* = udp_mod.UdpSocket.bindAny(self.allocator, 0) catch {
            return types_mod.QuicError.SocketError;
        };
        self.socket = socket;

        // Create crypto context
        const crypto_ctx = try self.allocator.create(crypto_mod.CryptoContext);
        errdefer self.allocator.destroy(crypto_ctx);

        const crypto_mode: crypto_mod.CryptoMode = switch (self.config.mode) {
            .ssh => .ssh,
            .tls => .tls,
        };

        crypto_ctx.* = crypto_mod.CryptoContext.init(
            self.allocator,
            crypto_mode,
            crypto_mod.CipherSuite.TLS_AES_128_GCM_SHA256,
        );
        self.crypto_ctx = crypto_ctx;

        // Create internal connection
        const internal_conn = try self.allocator.create(conn_internal.Connection);
        errdefer self.allocator.destroy(internal_conn);

        // Generate connection IDs
        var local_cid_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&local_cid_bytes);
        const local_cid = core_types.ConnectionId.init(&local_cid_bytes) catch {
            return types_mod.QuicError.InvalidConfig;
        };

        var remote_cid_bytes: [8]u8 = undefined;
        std.crypto.random.bytes(&remote_cid_bytes);
        const remote_cid = core_types.ConnectionId.init(&remote_cid_bytes) catch {
            return types_mod.QuicError.InvalidConfig;
        };

        const quic_mode: core_types.QuicMode = switch (self.config.mode) {
            .ssh => .ssh,
            .tls => .tls,
        };

        internal_conn.* = conn_internal.Connection.initClient(
            self.allocator,
            quic_mode,
            local_cid,
            remote_cid,
        ) catch {
            return types_mod.QuicError.InvalidConfig;
        };
        self.internal_conn = internal_conn;

        self.state = .connecting;
    }

    /// Accept incoming connection (server only)
    pub fn accept(
        self: *QuicConnection,
        bind_address: []const u8,
        bind_port: u16,
    ) types_mod.QuicError!void {
        if (self.config.role != .server) {
            return types_mod.QuicError.InvalidState;
        }

        if (self.state != .idle) {
            return types_mod.QuicError.InvalidState;
        }

        // Parse bind address
        const addr = std.net.Address.parseIp(bind_address, bind_port) catch {
            return types_mod.QuicError.InvalidAddress;
        };

        // Create and bind UDP socket
        const socket = try self.allocator.create(udp_mod.UdpSocket);
        errdefer self.allocator.destroy(socket);

        socket.* = udp_mod.UdpSocket.bind(self.allocator, addr) catch {
            return types_mod.QuicError.SocketError;
        };
        self.socket = socket;

        // Create crypto context
        const crypto_ctx = try self.allocator.create(crypto_mod.CryptoContext);
        errdefer self.allocator.destroy(crypto_ctx);

        const crypto_mode: crypto_mod.CryptoMode = switch (self.config.mode) {
            .ssh => .ssh,
            .tls => .tls,
        };

        crypto_ctx.* = crypto_mod.CryptoContext.init(
            self.allocator,
            crypto_mode,
            crypto_mod.CipherSuite.TLS_AES_128_GCM_SHA256,
        );
        self.crypto_ctx = crypto_ctx;

        self.state = .connecting;
    }

    /// Open a new stream
    pub fn openStream(
        self: *QuicConnection,
        bidirectional: bool,
    ) types_mod.QuicError!types_mod.StreamId {
        if (self.state != .established) {
            return types_mod.QuicError.ConnectionNotEstablished;
        }

        if (self.internal_conn == null) {
            return types_mod.QuicError.InvalidState;
        }

        const conn = self.internal_conn.?;

        const stream_id = conn.openStream(bidirectional) catch |err| {
            return switch (err) {
                error.UnsupportedStreamType => types_mod.QuicError.StreamError,
                error.StreamError => types_mod.QuicError.StreamLimitReached,
                else => types_mod.QuicError.StreamError,
            };
        };

        // Add event
        try self.events.append(self.allocator, .{ .stream_opened = stream_id });

        return stream_id;
    }

    /// Write data to stream
    pub fn streamWrite(
        self: *QuicConnection,
        stream_id: types_mod.StreamId,
        data: []const u8,
        finish: types_mod.StreamFinish,
    ) types_mod.QuicError!usize {
        if (self.state != .established) {
            return types_mod.QuicError.ConnectionNotEstablished;
        }

        const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;

        // Get stream
        const stream = conn.getStream(stream_id) orelse return types_mod.QuicError.StreamNotFound;

        // Write data to stream
        const written = stream.write(data) catch {
            return types_mod.QuicError.StreamError;
        };

        conn.updateDataSent(written);
        conn.trackPacketSent(written, true);

        // Handle finish flag
        if (finish == .finish) {
            stream.finish();
        }

        return written;
    }

    /// Read data from stream
    pub fn streamRead(
        self: *QuicConnection,
        stream_id: types_mod.StreamId,
        buffer: []u8,
    ) types_mod.QuicError!usize {
        if (self.state != .established) {
            return types_mod.QuicError.ConnectionNotEstablished;
        }

        const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;

        // Get stream
        const stream = conn.getStream(stream_id) orelse return types_mod.QuicError.StreamNotFound;

        // Read data from stream
        const read_count = stream.read(buffer) catch {
            return types_mod.QuicError.StreamError;
        };

        return read_count;
    }

    /// Close a stream
    pub fn closeStream(
        self: *QuicConnection,
        stream_id: types_mod.StreamId,
        error_code: u64,
    ) types_mod.QuicError!void {
        if (self.state != .established) {
            return types_mod.QuicError.ConnectionNotEstablished;
        }

        const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;

        // Get stream
        const stream = conn.getStream(stream_id) orelse return types_mod.QuicError.StreamNotFound;

        _ = error_code;

        // Graceful close: send FIN (half-close), keep receive side open.
        stream.finish();

        if (stream.isClosed()) {
            try self.events.append(self.allocator, .{ .stream_closed = .{ .id = stream_id, .error_code = null } });
        }
    }

    /// Get stream information
    pub fn getStreamInfo(
        self: *QuicConnection,
        stream_id: types_mod.StreamId,
    ) types_mod.QuicError!types_mod.StreamInfo {
        const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;

        const stream = conn.getStream(stream_id) orelse return types_mod.QuicError.StreamNotFound;

        const is_bidi = stream.isBidirectional();

        const send_closed = switch (stream.send_state) {
            .data_sent, .reset_sent, .reset_recvd => true,
            else => false,
        };
        const recv_closed = switch (stream.recv_state) {
            .data_read, .reset_read => true,
            else => false,
        };

        const state: types_mod.StreamState = if (send_closed and recv_closed)
            .closed
        else if (send_closed)
            .send_closed
        else if (recv_closed)
            .recv_closed
        else
            .open;

        return types_mod.StreamInfo{
            .id = stream_id,
            .state = state,
            .is_bidirectional = is_bidi,
            .bytes_sent = stream.send_offset,
            .bytes_received = stream.recv_offset,
            .send_buffer_available = 0,
            .recv_buffer_available = 0,
        };
    }

    /// Process I/O and internal state
    pub fn poll(self: *QuicConnection) types_mod.QuicError!void {
        if (self.state == .closed) {
            return types_mod.QuicError.ConnectionClosed;
        }

        if (self.state == .draining) {
            if (self.drain_pending) {
                self.drain_pending = false;
                return;
            }

            self.state = .closed;
            if (self.internal_conn) |conn| {
                conn.markClosed();
            }

            if (!self.closed_event_emitted) {
                self.closed_event_emitted = true;
                try self.events.append(self.allocator, .{ .closed = {} });
            }
            return;
        }

        if (self.internal_conn) |conn| {
            conn.onPtoTimeout(time_mod.Instant.now());
        }

        // Transition from connecting to established (simplified handshake)
        if (self.state == .connecting) {
            self.state = .established;
            try self.events.append(self.allocator, .{ .connected = {} });
        }

        // Process at most one received datagram
        if (self.socket) |socket| {
            var recv_buffer: [4096]u8 = undefined;
            const recv_result = socket.recvFrom(&recv_buffer) catch |err| {
                if (err == error.WouldBlock) {
                    return;
                }
                return types_mod.QuicError.NetworkError;
            };

            const packet = recv_buffer[0..recv_result.bytes];
            self.packets_received += 1;

            if (self.internal_conn) |conn| {
                conn.updateDataReceived(packet.len);
            }

            const header_len = self.decodePacketHeader(packet) catch {
                self.packets_invalid += 1;
                try self.queueProtocolViolation("invalid packet header");
                return;
            };

            if (header_len >= packet.len) return;

            self.routeFrame(packet[header_len..]) catch {
                self.packets_invalid += 1;
                try self.queueProtocolViolation("invalid frame payload");
                return;
            };
        }
    }

    /// Get next connection event
    pub fn nextEvent(self: *QuicConnection) ?types_mod.ConnectionEvent {
        if (self.events.items.len == 0) {
            return null;
        }

        return self.events.orderedRemove(0);
    }

    /// Get connection statistics
    pub fn getStats(self: *QuicConnection) types_mod.ConnectionStats {
        var stats = types_mod.ConnectionStats{};
        stats.packets_received = self.packets_received;

        if (self.internal_conn) |conn| {
            stats.bytes_sent = conn.data_sent;
            stats.bytes_received = conn.data_received;
        }

        return stats;
    }

    /// Get connection state
    pub fn getState(self: *QuicConnection) types_mod.ConnectionState {
        return self.state;
    }

    /// Close the connection gracefully
    pub fn close(
        self: *QuicConnection,
        error_code: u64,
        reason: []const u8,
    ) types_mod.QuicError!void {
        if (self.state == .closed) {
            return;
        }

        if (self.internal_conn) |conn| {
            conn.close(error_code, reason);
        }

        self.enterDraining(error_code, reason) catch {};
    }

    /// Clean up resources
    pub fn deinit(self: *QuicConnection) void {
        if (self.state != .closed) {
            self.close(0, "Connection closed") catch {};
        }

        if (self.internal_conn) |conn| {
            conn.deinit();
            self.allocator.destroy(conn);
        }

        if (self.socket) |socket| {
            socket.close();
            self.allocator.destroy(socket);
        }

        if (self.crypto_ctx) |ctx| {
            ctx.deinit();
            self.allocator.destroy(ctx);
        }

        self.events.deinit(self.allocator);
        self.state = .closed;
    }
};

// Tests

test "Create SSH client connection" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("example.com", "my-secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try std.testing.expectEqual(types_mod.ConnectionState.idle, conn.state);
    try std.testing.expectEqual(config_mod.QuicMode.ssh, conn.config.mode);
}

test "Create TLS client connection" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.tlsClient("example.com");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try std.testing.expectEqual(types_mod.ConnectionState.idle, conn.state);
    try std.testing.expectEqual(config_mod.QuicMode.tls, conn.config.mode);
}

test "Connection state transitions" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("example.com", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try std.testing.expectEqual(types_mod.ConnectionState.idle, conn.getState());

    conn.state = .connecting;
    try std.testing.expectEqual(types_mod.ConnectionState.connecting, conn.getState());

    conn.state = .established;
    try std.testing.expectEqual(types_mod.ConnectionState.established, conn.getState());
}

test "Get connection stats" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("example.com", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    const stats = conn.getStats();
    try std.testing.expectEqual(@as(u64, 0), stats.packets_sent);
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_received);
}

test "Event queue" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("example.com", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.events.append(allocator, .{ .connected = {} });

    const event = conn.nextEvent();
    try std.testing.expect(event != null);

    const event2 = conn.nextEvent();
    try std.testing.expect(event2 == null);
}

test "connect emits connected event on poll" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try std.testing.expectEqual(types_mod.ConnectionState.connecting, conn.getState());
    try std.testing.expect(conn.nextEvent() == null);

    try conn.poll();
    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .connected);
    try std.testing.expect(conn.nextEvent() == null);
}

test "closeStream is FIN-based half close" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("example.com", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    const internal_conn = try allocator.create(conn_internal.Connection);
    const local_cid = try core_types.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try core_types.ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });
    internal_conn.* = try conn_internal.Connection.initClient(allocator, .ssh, local_cid, remote_cid);
    internal_conn.markEstablished();

    conn.internal_conn = internal_conn;
    conn.state = .established;

    const stream_id = try conn.openStream(true);
    _ = conn.nextEvent(); // drain stream_opened

    try conn.closeStream(stream_id, 42);

    // FIN-based close should not emit stream_closed immediately (half-close)
    try std.testing.expect(conn.nextEvent() == null);

    const info_after_close = try conn.getStreamInfo(stream_id);
    try std.testing.expectEqual(types_mod.StreamState.send_closed, info_after_close.state);

    // Local write after FIN should fail
    try std.testing.expectError(
        types_mod.QuicError.StreamError,
        conn.streamWrite(stream_id, "after-fin", .no_finish),
    );

    // Peer can still send while our send side is closed
    const stream = conn.internal_conn.?.getStream(stream_id).?;
    try stream.appendRecvData("peer-data", 0, false);

    var read_buf: [64]u8 = undefined;
    const read_len = try conn.streamRead(stream_id, &read_buf);
    try std.testing.expectEqual(@as(usize, 9), read_len);
    try std.testing.expectEqualStrings("peer-data", read_buf[0..read_len]);

    // Peer FIN => EOF visible to application
    try stream.appendRecvData(&[_]u8{}, stream.recv_offset, true);
    const eof_len = try conn.streamRead(stream_id, &read_buf);
    try std.testing.expectEqual(@as(usize, 0), eof_len);
}

test "poll parses received long-header packet and updates visibility stats" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try conn.poll();
    _ = conn.nextEvent(); // drain connected

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [256]u8 = undefined;
    const header = packet_mod.LongHeader{
        .packet_type = .initial,
        .version = core_types.QUIC_VERSION_1,
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .src_conn_id = conn.internal_conn.?.remote_conn_id,
        .token = &.{},
        .payload_len = 4,
        .packet_number = 1,
    };

    var packet_len = try header.encode(&packet_buf);
    packet_buf[packet_len] = 0x01; // payload byte (PING frame type)
    packet_len += 1;

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);

    try conn.poll();

    const stats = conn.getStats();
    try std.testing.expectEqual(@as(u64, 1), stats.packets_received);
    try std.testing.expectEqual(@as(u64, packet_len), stats.bytes_received);
    try std.testing.expectEqual(types_mod.ConnectionState.established, conn.getState());
}

test "poll maps invalid packet header to closing event" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try conn.poll();
    _ = conn.nextEvent(); // drain connected

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    const invalid_packet = [_]u8{0x40};
    _ = try sender.sendTo(&invalid_packet, local_addr);

    try conn.poll();

    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .closing);
    try std.testing.expectEqual(@as(u64, 1), event.?.closing.error_code);
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "poll routes ACK frame into connection ack tracking" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try conn.poll();
    _ = conn.nextEvent();

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [256]u8 = undefined;
    const header = packet_mod.LongHeader{
        .packet_type = .initial,
        .version = core_types.QUIC_VERSION_1,
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .src_conn_id = conn.internal_conn.?.remote_conn_id,
        .token = &.{},
        .payload_len = 8,
        .packet_number = 2,
    };

    var packet_len = try header.encode(&packet_buf);
    const ack = frame_mod.AckFrame{
        .largest_acked = 7,
        .ack_delay = 0,
        .first_ack_range = 0,
        .ack_ranges = &.{},
        .ecn_counts = null,
    };
    packet_len += try ack.encode(packet_buf[packet_len..]);

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    try std.testing.expectEqual(@as(u64, 7), conn.internal_conn.?.largest_acked);
}

test "poll routes connection close frame to closing event" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try conn.poll();
    _ = conn.nextEvent();

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [256]u8 = undefined;
    const header = packet_mod.LongHeader{
        .packet_type = .initial,
        .version = core_types.QUIC_VERSION_1,
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .src_conn_id = conn.internal_conn.?.remote_conn_id,
        .token = &.{},
        .payload_len = 16,
        .packet_number = 3,
    };

    var packet_len = try header.encode(&packet_buf);
    const close_frame = frame_mod.ConnectionCloseFrame{
        .error_code = 0x0a,
        .frame_type = null,
        .reason = "bye",
    };
    packet_len += try close_frame.encode(packet_buf[packet_len..]);

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .closing);
    try std.testing.expectEqual(@as(u64, 0x0a), event.?.closing.error_code);
    try std.testing.expectEqualStrings("bye", event.?.closing.reason);
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "draining transitions to closed and emits closed event" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("example.com", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    const internal_conn = try allocator.create(conn_internal.Connection);
    const local_cid = try core_types.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try core_types.ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });
    internal_conn.* = try conn_internal.Connection.initClient(allocator, .ssh, local_cid, remote_cid);
    internal_conn.markEstablished();

    conn.internal_conn = internal_conn;
    conn.state = .established;

    try conn.close(55, "closing-now");
    const closing_event = conn.nextEvent();
    try std.testing.expect(closing_event != null);
    try std.testing.expect(closing_event.? == .closing);
    try std.testing.expectEqual(@as(u64, 55), closing_event.?.closing.error_code);
    try std.testing.expectEqualStrings("closing-now", closing_event.?.closing.reason);

    // First poll in draining acts as grace period
    try conn.poll();
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());

    // Second poll transitions to closed and emits closed event
    try conn.poll();
    try std.testing.expectEqual(types_mod.ConnectionState.closed, conn.getState());

    const closed_event = conn.nextEvent();
    try std.testing.expect(closed_event != null);
    try std.testing.expect(closed_event.? == .closed);
}

test "poll routes STREAM frame into stream data and readable event" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try conn.poll();
    _ = conn.nextEvent();

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [512]u8 = undefined;
    const header = packet_mod.LongHeader{
        .packet_type = .initial,
        .version = core_types.QUIC_VERSION_1,
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .src_conn_id = conn.internal_conn.?.remote_conn_id,
        .token = &.{},
        .payload_len = 24,
        .packet_number = 4,
    };

    var packet_len = try header.encode(&packet_buf);
    const stream_frame = frame_mod.StreamFrame{
        .stream_id = 4,
        .offset = 0,
        .data = "hello-stream",
        .fin = false,
    };
    packet_len += try stream_frame.encode(packet_buf[packet_len..]);

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .stream_readable);
    try std.testing.expectEqual(@as(u64, 4), event.?.stream_readable);

    var read_buf: [64]u8 = undefined;
    const n = try conn.streamRead(4, &read_buf);
    try std.testing.expectEqual(@as(usize, 12), n);
    try std.testing.expectEqualStrings("hello-stream", read_buf[0..n]);
}

test "poll routes RESET_STREAM frame to stream_closed event" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try conn.poll();
    _ = conn.nextEvent();

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [512]u8 = undefined;
    const header = packet_mod.LongHeader{
        .packet_type = .initial,
        .version = core_types.QUIC_VERSION_1,
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .src_conn_id = conn.internal_conn.?.remote_conn_id,
        .token = &.{},
        .payload_len = 20,
        .packet_number = 5,
    };

    var packet_len = try header.encode(&packet_buf);
    const reset_frame = frame_mod.ResetStreamFrame{
        .stream_id = 4,
        .error_code = 99,
        .final_size = 0,
    };
    packet_len += try reset_frame.encode(packet_buf[packet_len..]);

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .stream_closed);
    try std.testing.expectEqual(@as(u64, 4), event.?.stream_closed.id);
    try std.testing.expectEqual(@as(?u64, 99), event.?.stream_closed.error_code);
}

test "ssh mode rejects unidirectional stream open" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("example.com", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    const internal_conn = try allocator.create(conn_internal.Connection);
    const local_cid = try core_types.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try core_types.ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });
    internal_conn.* = try conn_internal.Connection.initClient(allocator, .ssh, local_cid, remote_cid);
    internal_conn.markEstablished();

    conn.internal_conn = internal_conn;
    conn.state = .established;

    try std.testing.expectError(types_mod.QuicError.StreamError, conn.openStream(false));
}
