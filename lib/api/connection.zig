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
        };
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

        internal_conn.* = try conn_internal.Connection.initClient(
            self.allocator,
            quic_mode,
            local_cid,
            remote_cid,
        );
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

        const stream_id = conn.openStream(bidirectional) catch {
            return types_mod.QuicError.StreamLimitReached;
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

        // Handle finish flag
        if (finish == .finish) {
            stream.finishSend() catch {
                return types_mod.QuicError.StreamError;
            };
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

        // Reset stream with error code
        stream.reset(error_code);

        // Add event
        try self.events.append(self.allocator, .{ .stream_closed = .{ .id = stream_id, .error_code = error_code } });
    }

    /// Get stream information
    pub fn getStreamInfo(
        self: *QuicConnection,
        stream_id: types_mod.StreamId,
    ) types_mod.QuicError!types_mod.StreamInfo {
        const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;

        const stream = conn.getStream(stream_id) orelse return types_mod.QuicError.StreamNotFound;

        const is_bidi = stream.isBidirectional();

        const state: types_mod.StreamState = if (stream.isClosed())
            .closed
        else if (stream.send_state == .ready or stream.send_state == .send)
            .open
        else
            .send_closed;

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

        // Transition from connecting to established (simplified handshake)
        if (self.state == .connecting) {
            self.state = .established;
            try self.events.append(self.allocator, .{ .connected = {} });
        }

        // Process received packets (simplified)
        if (self.socket) |socket| {
            var recv_buffer: [4096]u8 = undefined;
            _ = socket.recvFrom(&recv_buffer) catch |err| {
                if (err == error.WouldBlock) {
                    return;
                }
                return types_mod.QuicError.NetworkError;
            };

            // Packet received - packet decode and frame processing are implemented
            // in subsequent production-readiness slices.
            if (self.internal_conn) |conn| {
                conn.updateDataReceived(1);
            }
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

        // Send connection close frame (simplified - just transition state)
        self.state = .draining;

        // Add closing event
        self.events.append(self.allocator, .{
            .closing = .{
                .error_code = error_code,
                .reason = reason,
            },
        }) catch {};
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

test "closeStream emits structured stream_closed event" {
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
    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .stream_closed);
    try std.testing.expectEqual(stream_id, event.?.stream_closed.id);
    try std.testing.expectEqual(@as(?u64, 42), event.?.stream_closed.error_code);
}
