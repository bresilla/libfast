const std = @import("std");

/// Public API types for QUIC connections and streams

/// Connection state
pub const ConnectionState = enum {
    idle, // Initial state
    connecting, // Handshake in progress
    established, // Ready for data transfer
    draining, // Connection closing
    closed, // Connection closed

    pub fn toString(self: ConnectionState) []const u8 {
        return switch (self) {
            .idle => "Idle",
            .connecting => "Connecting",
            .established => "Established",
            .draining => "Draining",
            .closed => "Closed",
        };
    }

    pub fn isActive(self: ConnectionState) bool {
        return self == .connecting or self == .established;
    }

    pub fn canSendData(self: ConnectionState) bool {
        return self == .established;
    }
};

/// Stream state
pub const StreamState = enum {
    open, // Stream open, can send/receive
    send_closed, // Local side closed
    recv_closed, // Remote side closed
    closed, // Both sides closed

    pub fn toString(self: StreamState) []const u8 {
        return switch (self) {
            .open => "Open",
            .send_closed => "SendClosed",
            .recv_closed => "RecvClosed",
            .closed => "Closed",
        };
    }

    pub fn canSend(self: StreamState) bool {
        return self == .open;
    }

    pub fn canReceive(self: StreamState) bool {
        return self == .open or self == .send_closed;
    }
};

/// Stream ID (u64)
pub const StreamId = u64;

/// Connection ID (opaque bytes)
pub const ConnectionId = []const u8;

/// Error codes
pub const QuicError = error{
    // Configuration errors
    InvalidConfig,
    MissingSshConfig,
    MissingTlsConfig,
    MissingServerCredentials,

    // Connection errors
    ConnectionNotEstablished,
    ConnectionClosed,
    ConnectionTimedOut,
    HandshakeFailed,
    InvalidState,

    // Stream errors
    StreamNotFound,
    StreamClosed,
    StreamLimitReached,
    FlowControlError,
    StreamError,

    // Transport errors
    NetworkError,
    InvalidPacket,
    ProtocolViolation,
    InvalidAddress,
    SocketError,

    // Crypto errors
    CryptoError,
    KeyExchangeFailed,
    AuthenticationFailed,

    // Resource errors
    OutOfMemory,
    BufferTooSmall,
};

/// Connection statistics
pub const ConnectionStats = struct {
    /// Total packets sent
    packets_sent: u64 = 0,

    /// Total packets received
    packets_received: u64 = 0,

    /// Total bytes sent
    bytes_sent: u64 = 0,

    /// Total bytes received
    bytes_received: u64 = 0,

    /// Number of active streams
    active_streams: u32 = 0,

    /// Round-trip time (microseconds)
    rtt: u64 = 0,

    /// Connection duration (milliseconds)
    duration_ms: u64 = 0,
};

/// Stream information
pub const StreamInfo = struct {
    /// Stream ID
    id: StreamId,

    /// Stream state
    state: StreamState,

    /// Is bidirectional
    is_bidirectional: bool,

    /// Bytes sent
    bytes_sent: u64,

    /// Bytes received
    bytes_received: u64,

    /// Send buffer available space
    send_buffer_available: usize,

    /// Receive buffer data available
    recv_buffer_available: usize,
};

/// Connection event
pub const ConnectionEvent = union(enum) {
    /// Connection established
    connected: void,

    /// Stream opened (by remote peer)
    stream_opened: StreamId,

    /// Stream data available for reading
    stream_readable: StreamId,

    /// Stream ready for writing
    stream_writable: StreamId,

    /// Stream closed
    stream_closed: struct {
        id: StreamId,
        error_code: ?u64,
    },

    /// Connection closing
    closing: struct {
        error_code: u64,
        reason: []const u8,
    },

    /// Connection closed
    closed: void,
};

/// Stream finish flag
pub const StreamFinish = enum {
    /// Don't finish stream
    no_finish,

    /// Finish stream after this write
    finish,
};

// Tests

test "ConnectionState methods" {
    try std.testing.expect(ConnectionState.established.isActive());
    try std.testing.expect(ConnectionState.connecting.isActive());
    try std.testing.expect(!ConnectionState.closed.isActive());

    try std.testing.expect(ConnectionState.established.canSendData());
    try std.testing.expect(!ConnectionState.connecting.canSendData());
}

test "StreamState methods" {
    try std.testing.expect(StreamState.open.canSend());
    try std.testing.expect(!StreamState.send_closed.canSend());

    try std.testing.expect(StreamState.open.canReceive());
    try std.testing.expect(StreamState.send_closed.canReceive());
    try std.testing.expect(!StreamState.recv_closed.canReceive());
}

test "ConnectionStats initialization" {
    const stats = ConnectionStats{};

    try std.testing.expectEqual(@as(u64, 0), stats.packets_sent);
    try std.testing.expectEqual(@as(u64, 0), stats.bytes_sent);
}

test "StreamInfo creation" {
    const info = StreamInfo{
        .id = 4,
        .state = .open,
        .is_bidirectional = true,
        .bytes_sent = 100,
        .bytes_received = 200,
        .send_buffer_available = 1024,
        .recv_buffer_available = 512,
    };

    try std.testing.expectEqual(@as(StreamId, 4), info.id);
    try std.testing.expectEqual(StreamState.open, info.state);
    try std.testing.expect(info.is_bidirectional);
}

test "ConnectionEvent variants" {
    const event1 = ConnectionEvent{ .connected = {} };
    const event2 = ConnectionEvent{ .stream_opened = 4 };
    const event3 = ConnectionEvent{ .stream_readable = 8 };
    const event4 = ConnectionEvent{ .closing = .{ .error_code = 0, .reason = "No error" } };

    _ = event1;
    _ = event2;
    _ = event3;
    _ = event4;
}
