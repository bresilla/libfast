const std = @import("std");
const config_mod = @import("config.zig");
const types_mod = @import("types.zig");
const conn_internal = @import("../core/connection.zig");
const stream_internal = @import("../core/stream.zig");
const udp_mod = @import("../transport/udp.zig");
const crypto_mod = @import("../crypto/crypto.zig");

/// Public QUIC connection handle
///
/// This is the main interface for applications to interact with QUIC connections.
/// It wraps the internal connection implementation and provides a clean API.
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

    /// Initialize a new QUIC connection
    pub fn init(
        allocator: std.mem.Allocator,
        config: config_mod.QuicConfig,
    ) types_mod.QuicError!QuicConnection {
        // Validate configuration
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
        };
    }

    /// Start connecting (client only)
    pub fn connect(
        self: *QuicConnection,
        _remote_address: []const u8,
        _remote_port: u16,
    ) types_mod.QuicError!void {
        _ = _remote_address;
        _ = _remote_port;
        if (self.config.role != .client) {
            return types_mod.QuicError.InvalidState;
        }

        if (self.state != .idle) {
            return types_mod.QuicError.InvalidState;
        }

        // TODO: Create UDP socket
        // TODO: Create internal connection
        // TODO: Start handshake

        self.state = .connecting;

        // Add event
        try self.events.append(self.allocator, .{ .connected = {} });
    }

    /// Accept incoming connection (server only)
    pub fn accept(
        self: *QuicConnection,
        _bind_address: []const u8,
        _bind_port: u16,
    ) types_mod.QuicError!void {
        _ = _bind_address;
        _ = _bind_port;
        if (self.config.role != .server) {
            return types_mod.QuicError.InvalidState;
        }

        if (self.state != .idle) {
            return types_mod.QuicError.InvalidState;
        }

        // TODO: Create and bind UDP socket
        // TODO: Wait for incoming connection
        // TODO: Create internal connection
        // TODO: Start handshake

        self.state = .connecting;
    }

    /// Open a new stream
    pub fn openStream(
        self: *QuicConnection,
        _bidirectional: bool,
    ) types_mod.QuicError!types_mod.StreamId {
        _ = _bidirectional;
        if (self.state != .established) {
            return types_mod.QuicError.ConnectionNotEstablished;
        }

        if (self.internal_conn == null) {
            return types_mod.QuicError.InvalidState;
        }

        // TODO: Open stream through internal connection
        const stream_id: types_mod.StreamId = 0; // Placeholder

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

        if (self.internal_conn == null) {
            return types_mod.QuicError.InvalidState;
        }

        // TODO: Write to stream through internal connection
        _ = stream_id;
        _ = data;
        _ = finish;

        return 0; // Placeholder
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

        if (self.internal_conn == null) {
            return types_mod.QuicError.InvalidState;
        }

        // TODO: Read from stream through internal connection
        _ = stream_id;
        _ = buffer;

        return 0; // Placeholder
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

        if (self.internal_conn == null) {
            return types_mod.QuicError.InvalidState;
        }

        // TODO: Close stream through internal connection
        _ = stream_id;
        _ = error_code;
    }

    /// Get stream information
    pub fn getStreamInfo(
        self: *QuicConnection,
        stream_id: types_mod.StreamId,
    ) types_mod.QuicError!types_mod.StreamInfo {
        if (self.internal_conn == null) {
            return types_mod.QuicError.InvalidState;
        }

        // TODO: Get stream info from internal connection

        return types_mod.StreamInfo{
            .id = stream_id,
            .state = .open,
            .is_bidirectional = true,
            .bytes_sent = 0,
            .bytes_received = 0,
            .send_buffer_available = 0,
            .recv_buffer_available = 0,
        };
    }

    /// Process I/O and internal state
    pub fn poll(self: *QuicConnection) types_mod.QuicError!void {
        if (self.state == .closed) {
            return types_mod.QuicError.ConnectionClosed;
        }

        // TODO: Process received packets
        // TODO: Send pending packets
        // TODO: Update timers
        // TODO: Generate events

        // Placeholder: transition to established if connecting
        if (self.state == .connecting) {
            self.state = .established;
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
        const stats = types_mod.ConnectionStats{};

        if (self.internal_conn) |conn| {
            _ = conn;
            // TODO: Populate stats from internal connection
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

        // TODO: Send connection close frame
        // TODO: Clean up internal state

        _ = error_code;
        _ = reason;

        self.state = .draining;
    }

    /// Clean up resources
    pub fn deinit(self: *QuicConnection) void {
        // Close connection if not already closed
        if (self.state != .closed) {
            self.close(0, "Connection closed") catch {};
        }

        // Clean up internal resources
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

    // Initial state
    try std.testing.expectEqual(types_mod.ConnectionState.idle, conn.getState());

    // Simulate state transitions
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

    // Add event
    try conn.events.append(allocator, .{ .connected = {} });

    // Get event
    const event = conn.nextEvent();
    try std.testing.expect(event != null);

    // Queue should be empty now
    const event2 = conn.nextEvent();
    try std.testing.expect(event2 == null);
}
