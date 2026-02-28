const std = @import("std");
const types = @import("types.zig");
const stream = @import("stream.zig");
const packet = @import("../core/packet.zig");
const loss_detection = @import("loss_detection.zig");
const congestion = @import("congestion.zig");
const time = @import("../utils/time.zig");

const ConnectionId = types.ConnectionId;
const ConnectionState = types.ConnectionState;
const QuicMode = types.QuicMode;
const TransportParameters = types.TransportParameters;
const StreamManager = stream.StreamManager;
const StreamId = types.StreamId;

/// QUIC Connection
pub const Connection = struct {
    pub const RetransmissionRequest = struct {
        packet_number: u64,
        size: usize,
        is_probe: bool,
    };

    /// Connection IDs
    local_conn_id: ConnectionId,
    remote_conn_id: ConnectionId,

    /// Connection state
    state: ConnectionState,

    /// Crypto mode (TLS or SSH)
    mode: QuicMode,

    /// Is this a server connection?
    is_server: bool,

    /// Address/path validation state for amplification limits
    peer_validated: bool,

    /// QUIC version
    version: u32,

    /// Transport parameters
    local_params: TransportParameters,
    remote_params: ?TransportParameters,

    /// Stream management
    streams: StreamManager,

    /// Packet number tracking
    next_packet_number: u64,
    largest_acked: u64,

    /// Recovery and congestion control
    loss_detection: loss_detection.LossDetection,
    congestion_controller: congestion.CongestionController,
    retransmission_queue: std.ArrayList(RetransmissionRequest),
    pto_count: u32,
    next_pto_at: ?time.Instant,

    /// PATH_CHALLENGE / PATH_RESPONSE tracking
    expected_path_response: ?[8]u8,
    pending_path_responses: std.ArrayList([8]u8),

    /// Flow control
    max_data_local: u64,
    max_data_remote: u64,
    data_sent: u64,
    data_received: u64,

    /// Allocator
    allocator: std.mem.Allocator,

    pub const Error = error{
        InvalidState,
        ConnectionClosed,
        StreamError,
        UnsupportedStreamType,
        FlowControlError,
        InvalidPacket,
    } || std.mem.Allocator.Error;

    /// Create a new client connection
    pub fn initClient(
        allocator: std.mem.Allocator,
        mode: QuicMode,
        local_conn_id: ConnectionId,
        remote_conn_id: ConnectionId,
    ) Error!Connection {
        const params = TransportParameters{};

        var conn = Connection{
            .local_conn_id = local_conn_id,
            .remote_conn_id = remote_conn_id,
            .state = .handshaking,
            .mode = mode,
            .is_server = false,
            .peer_validated = true,
            .version = types.QUIC_VERSION_1,
            .local_params = params,
            .remote_params = null,
            .streams = StreamManager.init(allocator, false, params.initial_max_stream_data_bidi_local),
            .next_packet_number = 0,
            .largest_acked = 0,
            .loss_detection = loss_detection.LossDetection.init(allocator),
            .congestion_controller = congestion.CongestionController.init(1200),
            .retransmission_queue = .{},
            .pto_count = 0,
            .next_pto_at = null,
            .expected_path_response = null,
            .pending_path_responses = .{},
            .max_data_local = params.initial_max_data,
            .max_data_remote = params.initial_max_data,
            .data_sent = 0,
            .data_received = 0,
            .allocator = allocator,
        };

        // SSH/QUIC reserves stream 0 for global/auth traffic.
        // Channel streams begin at 4 for client-initiated bidirectional streams.
        if (mode == .ssh) {
            conn.streams.next_client_bidi = 4;
        }

        conn.streams.setLocalOpenLimits(params.initial_max_streams_bidi, params.initial_max_streams_uni);
        conn.streams.setLocalReceiveStreamDataLimits(
            params.initial_max_stream_data_bidi_local,
            params.initial_max_stream_data_bidi_remote,
            params.initial_max_stream_data_uni,
        );

        return conn;
    }

    /// Create a new server connection
    pub fn initServer(
        allocator: std.mem.Allocator,
        mode: QuicMode,
        local_conn_id: ConnectionId,
        remote_conn_id: ConnectionId,
    ) Error!Connection {
        const params = TransportParameters{};

        var conn = Connection{
            .local_conn_id = local_conn_id,
            .remote_conn_id = remote_conn_id,
            .state = .handshaking,
            .mode = mode,
            .is_server = true,
            .peer_validated = false,
            .version = types.QUIC_VERSION_1,
            .local_params = params,
            .remote_params = null,
            .streams = StreamManager.init(allocator, true, params.initial_max_stream_data_bidi_local),
            .next_packet_number = 0,
            .largest_acked = 0,
            .loss_detection = loss_detection.LossDetection.init(allocator),
            .congestion_controller = congestion.CongestionController.init(1200),
            .retransmission_queue = .{},
            .pto_count = 0,
            .next_pto_at = null,
            .expected_path_response = null,
            .pending_path_responses = .{},
            .max_data_local = params.initial_max_data,
            .max_data_remote = params.initial_max_data,
            .data_sent = 0,
            .data_received = 0,
            .allocator = allocator,
        };

        // SSH/QUIC reserves stream 0 and maps server-initiated channels to 5, 9, 13...
        if (mode == .ssh) {
            conn.streams.next_server_bidi = 5;
        }

        conn.streams.setLocalOpenLimits(params.initial_max_streams_bidi, params.initial_max_streams_uni);
        conn.streams.setLocalReceiveStreamDataLimits(
            params.initial_max_stream_data_bidi_local,
            params.initial_max_stream_data_bidi_remote,
            params.initial_max_stream_data_uni,
        );

        return conn;
    }

    pub fn deinit(self: *Connection) void {
        self.streams.deinit();
        self.loss_detection.deinit();
        self.retransmission_queue.deinit(self.allocator);
        self.pending_path_responses.deinit(self.allocator);
    }

    /// Open a new stream
    pub fn openStream(self: *Connection, bidirectional: bool) Error!StreamId {
        if (self.state != .established) {
            return error.InvalidState;
        }

        // SSH/QUIC channels are always bidirectional streams.
        if (self.mode == .ssh and !bidirectional) {
            return error.UnsupportedStreamType;
        }

        const stream_type = if (bidirectional)
            (if (self.is_server) types.StreamType.server_bidi else types.StreamType.client_bidi)
        else
            (if (self.is_server) types.StreamType.server_uni else types.StreamType.client_uni);

        return self.streams.createStream(stream_type) catch |err| {
            return switch (err) {
                error.StreamLimitReached => error.StreamError,
                error.InvalidStreamType => error.StreamError,
                else => error.StreamError,
            };
        };
    }

    /// Get a stream by ID
    pub fn getStream(self: *Connection, stream_id: StreamId) ?*stream.Stream {
        return self.streams.getStream(stream_id);
    }

    /// Get or create a stream by ID (for receiving)
    pub fn getOrCreateStream(self: *Connection, stream_id: StreamId) Error!*stream.Stream {
        return self.streams.getOrCreateStream(stream_id) catch |err| {
            std.log.err("Failed to get or create stream {}: {}", .{ stream_id, err });
            return error.StreamError;
        };
    }

    /// Get next packet number and increment
    pub fn nextPacketNumber(self: *Connection) u64 {
        const pn = self.next_packet_number;
        self.next_packet_number += 1;
        return pn;
    }

    /// Mark connection as established
    pub fn markEstablished(self: *Connection) void {
        self.state = .established;
        self.peer_validated = true;
    }

    /// Mark peer/path as validated for amplification-limit purposes.
    pub fn markPeerValidated(self: *Connection) void {
        self.peer_validated = true;
    }

    /// Begin path validation: requires PATH_RESPONSE echo before enabling validated path.
    pub fn beginPathValidation(self: *Connection, challenge_data: [8]u8) void {
        self.expected_path_response = challenge_data;
        self.peer_validated = false;
    }

    /// Queue a PATH_RESPONSE token when a PATH_CHALLENGE is received.
    pub fn onPathChallenge(self: *Connection, challenge_data: [8]u8) Error!void {
        try self.pending_path_responses.append(self.allocator, challenge_data);
    }

    /// Pop the next pending PATH_RESPONSE token to send.
    pub fn popPathResponse(self: *Connection) ?[8]u8 {
        if (self.pending_path_responses.items.len == 0) {
            return null;
        }
        return self.pending_path_responses.orderedRemove(0);
    }

    /// Process a received PATH_RESPONSE token.
    pub fn onPathResponse(self: *Connection, response_data: [8]u8) bool {
        if (self.expected_path_response) |expected| {
            if (std.mem.eql(u8, &expected, &response_data)) {
                self.expected_path_response = null;
                self.markPeerValidated();
                return true;
            }
        }
        return false;
    }

    /// Start closing the connection
    pub fn close(self: *Connection, _: u64, _: []const u8) void {
        if (self.state != .closed) {
            self.state = .closing;
        }
    }

    /// Mark connection as closed
    pub fn markClosed(self: *Connection) void {
        self.state = .closed;
    }

    /// Check if connection is closed
    pub fn isClosed(self: Connection) bool {
        return self.state == .closed or self.state == .draining;
    }

    /// Check connection-level flow control
    pub fn checkFlowControl(self: *Connection, additional_data: u64) Error!void {
        if (self.data_sent + additional_data > self.max_data_remote) {
            return error.FlowControlError;
        }
    }

    fn amplificationBudget(self: *Connection) u64 {
        if (!self.is_server or self.peer_validated) {
            return std.math.maxInt(u64);
        }

        if (self.data_received == 0) {
            return 0;
        }

        const max_send = if (self.data_received > std.math.maxInt(u64) / 3)
            std.math.maxInt(u64)
        else
            self.data_received * 3;

        if (self.data_sent >= max_send) {
            return 0;
        }
        return max_send - self.data_sent;
    }

    /// Available send budget considering flow-control, congestion, and amplification limits.
    pub fn availableSendBudget(self: *Connection) u64 {
        const flow_budget = if (self.data_sent >= self.max_data_remote)
            0
        else
            self.max_data_remote - self.data_sent;

        const congestion_budget = self.congestion_controller.availableWindow();
        const amplification_budget = self.amplificationBudget();

        return @min(flow_budget, @min(congestion_budget, amplification_budget));
    }

    /// Update data sent
    pub fn updateDataSent(self: *Connection, amount: u64) void {
        self.data_sent += amount;
    }

    /// Update data received
    pub fn updateDataReceived(self: *Connection, amount: u64) void {
        self.data_received += amount;
    }

    /// Set remote transport parameters
    pub fn setRemoteParams(self: *Connection, params: TransportParameters) void {
        self.remote_params = params;
        self.max_data_remote = params.initial_max_data;
        self.streams.setLocalOpenLimits(params.initial_max_streams_bidi, params.initial_max_streams_uni);
        self.streams.setRemoteStreamDataLimits(
            params.initial_max_stream_data_bidi_local,
            params.initial_max_stream_data_bidi_remote,
            params.initial_max_stream_data_uni,
        );
    }

    /// Process received ACK
    pub fn processAck(self: *Connection, largest_acked: u64) void {
        self.processAckDetailed(largest_acked, 0);
    }

    /// Process received ACK with delay (microseconds), update RTT and congestion state.
    pub fn processAckDetailed(self: *Connection, largest_acked: u64, ack_delay: u64) void {
        const now = time.Instant.now();

        var ack_result = self.loss_detection.onAckReceived(
            .application,
            largest_acked,
            ack_delay,
            now,
        ) catch {
            if (largest_acked > self.largest_acked) {
                self.largest_acked = largest_acked;
            }
            return;
        };
        defer ack_result.lost_packets.deinit(self.allocator);

        if (ack_result.acked_packet) |acked| {
            if (acked.in_flight) {
                self.congestion_controller.onPacketAcked(acked.size, acked.packet_number);
                self.pto_count = 0;
                self.next_pto_at = now.add(self.loss_detection.getPto());
            }
        }

        if (ack_result.lost_packets.items.len > 0) {
            var bytes_lost: u64 = 0;
            var largest_lost: u64 = 0;
            for (ack_result.lost_packets.items) |lost| {
                if (lost.in_flight) {
                    bytes_lost += lost.size;
                }
                if (lost.packet_number > largest_lost) {
                    largest_lost = lost.packet_number;
                }
            }

            if (bytes_lost > 0) {
                self.congestion_controller.onPacketsLost(bytes_lost, largest_lost);

                for (ack_result.lost_packets.items) |lost| {
                    self.retransmission_queue.append(self.allocator, .{
                        .packet_number = lost.packet_number,
                        .size = lost.size,
                        .is_probe = false,
                    }) catch {};
                }
            }
        }

        if (largest_acked > self.largest_acked) {
            self.largest_acked = largest_acked;
        }
    }

    /// Track a sent packet for RTT/loss/congestion accounting.
    pub fn trackPacketSent(self: *Connection, packet_size: usize, ack_eliciting: bool) void {
        const pn = self.nextPacketNumber();
        const now = time.Instant.now();
        const sent = loss_detection.SentPacket.init(pn, now, packet_size, ack_eliciting);

        self.loss_detection.onPacketSent(.application, sent) catch {};
        if (sent.in_flight) {
            self.congestion_controller.onPacketSent(packet_size);
        }

        if (ack_eliciting) {
            self.next_pto_at = now.add(self.loss_detection.getPto());
        }
    }

    /// Schedule probe retransmission when PTO expires.
    pub fn onPtoTimeout(self: *Connection, now: time.Instant) void {
        if (self.next_pto_at) |deadline| {
            if (now.isBefore(deadline)) {
                return;
            }

            self.retransmission_queue.append(self.allocator, .{
                .packet_number = self.next_packet_number,
                .size = @intCast(self.congestion_controller.max_datagram_size),
                .is_probe = true,
            }) catch {};

            self.pto_count += 1;

            const base_pto = self.loss_detection.getPto();
            const shift: u6 = @intCast(@min(self.pto_count, 20));
            const backoff = (@as(u64, 1) << shift);
            self.next_pto_at = now.add(base_pto * backoff);
        }
    }

    /// Pop next pending retransmission request, if any.
    pub fn popRetransmission(self: *Connection) ?RetransmissionRequest {
        if (self.retransmission_queue.items.len == 0) {
            return null;
        }

        return self.retransmission_queue.orderedRemove(0);
    }
};

/// Connection manager for handling multiple connections
pub const ConnectionManager = struct {
    connections: std.AutoHashMap(u64, Connection),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ConnectionManager {
        return ConnectionManager{
            .connections = std.AutoHashMap(u64, Connection).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *ConnectionManager) void {
        var it = self.connections.valueIterator();
        while (it.next()) |conn| {
            conn.deinit();
        }
        self.connections.deinit();
    }

    /// Add a connection
    pub fn addConnection(self: *ConnectionManager, conn_id_hash: u64, conn: Connection) !void {
        try self.connections.put(conn_id_hash, conn);
    }

    /// Get connection by connection ID hash
    pub fn getConnection(self: *ConnectionManager, conn_id_hash: u64) ?*Connection {
        return self.connections.getPtr(conn_id_hash);
    }

    /// Remove connection
    pub fn removeConnection(self: *ConnectionManager, conn_id_hash: u64) void {
        if (self.connections.fetchRemove(conn_id_hash)) |kv| {
            var conn = kv.value;
            conn.deinit();
        }
    }

    /// Remove all closed connections
    pub fn removeClosedConnections(self: *ConnectionManager) !void {
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();

        var it = self.connections.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isClosed()) {
                try to_remove.append(entry.key_ptr.*);
            }
        }

        for (to_remove.items) |conn_id_hash| {
            self.removeConnection(conn_id_hash);
        }
    }

    /// Hash a connection ID for use as key
    pub fn hashConnectionId(conn_id: ConnectionId) u64 {
        return std.hash.Wyhash.hash(0, conn_id.slice());
    }
};

// Tests

test "connection creation client" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();

    try std.testing.expectEqual(ConnectionState.handshaking, conn.state);
    try std.testing.expect(!conn.is_server);
    try std.testing.expectEqual(QuicMode.tls, conn.mode);
}

test "connection creation server" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initServer(allocator, .ssh, local_cid, remote_cid);
    defer conn.deinit();

    try std.testing.expectEqual(ConnectionState.handshaking, conn.state);
    try std.testing.expect(conn.is_server);
    try std.testing.expectEqual(QuicMode.ssh, conn.mode);
}

test "connection stream opening" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();

    // Can't open streams until established
    try std.testing.expectError(error.InvalidState, conn.openStream(true));

    // Mark as established
    conn.markEstablished();

    // Now we can open streams
    const stream_id = try conn.openStream(true);
    try std.testing.expectEqual(@as(u64, 0), stream_id);

    const s = conn.getStream(stream_id).?;
    try std.testing.expect(s.isBidirectional());
}

test "ssh stream id assignment and bidi-only policy" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var client_conn = try Connection.initClient(allocator, .ssh, local_cid, remote_cid);
    defer client_conn.deinit();
    client_conn.markEstablished();

    try std.testing.expectError(error.UnsupportedStreamType, client_conn.openStream(false));

    const c1 = try client_conn.openStream(true);
    const c2 = try client_conn.openStream(true);
    try std.testing.expectEqual(@as(u64, 4), c1);
    try std.testing.expectEqual(@as(u64, 8), c2);

    var server_conn = try Connection.initServer(allocator, .ssh, local_cid, remote_cid);
    defer server_conn.deinit();
    server_conn.markEstablished();

    const s1 = try server_conn.openStream(true);
    const s2 = try server_conn.openStream(true);
    try std.testing.expectEqual(@as(u64, 5), s1);
    try std.testing.expectEqual(@as(u64, 9), s2);
}

test "connection manager" {
    const allocator = std.testing.allocator;

    var manager = ConnectionManager.init(allocator);
    defer manager.deinit();

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    const conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);

    const hash = ConnectionManager.hashConnectionId(local_cid);
    try manager.addConnection(hash, conn);

    const retrieved = manager.getConnection(hash).?;
    try std.testing.expect(retrieved.local_conn_id.eql(&local_cid));
}

test "connection packet numbers" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();

    try std.testing.expectEqual(@as(u64, 0), conn.nextPacketNumber());
    try std.testing.expectEqual(@as(u64, 1), conn.nextPacketNumber());
    try std.testing.expectEqual(@as(u64, 2), conn.nextPacketNumber());
}

test "connection flow control" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();

    // Should be able to send within limit
    try conn.checkFlowControl(1000);

    // Should fail if exceeding limit
    try std.testing.expectError(error.FlowControlError, conn.checkFlowControl(conn.max_data_remote + 1));
}

test "connection applies remote stream limits" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();
    conn.markEstablished();

    var remote = TransportParameters{};
    remote.initial_max_streams_bidi = 1;
    remote.initial_max_streams_uni = 0;
    conn.setRemoteParams(remote);

    _ = try conn.openStream(true);
    try std.testing.expectError(error.StreamError, conn.openStream(true));
    try std.testing.expectError(error.StreamError, conn.openStream(false));
}

test "connection applies remote per-stream data limits" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();
    conn.markEstablished();

    var remote = TransportParameters{};
    remote.initial_max_stream_data_bidi_remote = 4;
    conn.setRemoteParams(remote);

    const stream_id = try conn.openStream(true);
    const s = conn.getStream(stream_id).?;

    try std.testing.expectEqual(@as(u64, 4), s.max_stream_data_remote);
    try std.testing.expectEqual(@as(usize, 4), try s.write("abcdef"));
}

test "connection send budget tracks congestion window" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();
    conn.markEstablished();

    const initial_budget = conn.availableSendBudget();
    try std.testing.expect(initial_budget > 0);

    conn.trackPacketSent(4000, true);
    const reduced_budget = conn.availableSendBudget();
    try std.testing.expect(reduced_budget < initial_budget);
}

test "connection enforces server amplification budget before validation" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initServer(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();

    // No bytes received yet => cannot send due to amplification limit.
    try std.testing.expectEqual(@as(u64, 0), conn.availableSendBudget());

    conn.updateDataReceived(1000);
    try std.testing.expectEqual(@as(u64, 3000), conn.availableSendBudget());

    conn.updateDataSent(2500);
    try std.testing.expectEqual(@as(u64, 500), conn.availableSendBudget());

    // Validation removes amplification cap.
    conn.markPeerValidated();
    try std.testing.expect(conn.availableSendBudget() > 500);
}

test "connection ack integrates congestion accounting" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();

    conn.markEstablished();

    conn.trackPacketSent(1200, true); // pn 0
    conn.trackPacketSent(1200, true); // pn 1
    conn.trackPacketSent(1200, true); // pn 2

    try std.testing.expect(conn.congestion_controller.getBytesInFlight() >= 3600);

    conn.processAckDetailed(2, 0);

    try std.testing.expect(conn.largest_acked >= 2);
    try std.testing.expect(conn.congestion_controller.getBytesInFlight() < 3600);
}

test "connection schedules retransmission for lost packets" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();
    conn.markEstablished();

    conn.trackPacketSent(1200, true); // pn 0
    conn.trackPacketSent(1200, true); // pn 1
    conn.trackPacketSent(1200, true); // pn 2
    conn.trackPacketSent(1200, true); // pn 3
    conn.trackPacketSent(1200, true); // pn 4

    conn.processAckDetailed(4, 0);

    const retransmit = conn.popRetransmission();
    try std.testing.expect(retransmit != null);
    try std.testing.expect(!retransmit.?.is_probe);
}

test "connection schedules PTO probe" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();
    conn.markEstablished();

    conn.trackPacketSent(1200, true);
    try std.testing.expect(conn.next_pto_at != null);

    const trigger_time = conn.next_pto_at.?.add(1);
    conn.onPtoTimeout(trigger_time);

    const probe = conn.popRetransmission();
    try std.testing.expect(probe != null);
    try std.testing.expect(probe.?.is_probe);
    try std.testing.expect(conn.pto_count > 0);
}

test "recovery handles packet reordering without spurious retransmit" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();
    conn.markEstablished();

    conn.trackPacketSent(1200, true); // pn 0
    conn.trackPacketSent(1200, true); // pn 1
    conn.trackPacketSent(1200, true); // pn 2

    // Reordered ACK first acknowledges a newer packet.
    conn.processAckDetailed(2, 0);
    // Late ACK for an older packet follows.
    conn.processAckDetailed(1, 0);

    // Reordering should not trigger uncontrolled retransmit growth.
    var retransmit_count: usize = 0;
    while (conn.popRetransmission()) |_| {
        retransmit_count += 1;
    }
    try std.testing.expect(retransmit_count <= 2);
}

test "pto backoff grows and remains bounded" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();
    conn.markEstablished();

    conn.trackPacketSent(1200, true);

    var last_deadline = conn.next_pto_at.?;
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        conn.onPtoTimeout(last_deadline.add(1));

        const probe = conn.popRetransmission();
        try std.testing.expect(probe != null);
        try std.testing.expect(probe.?.is_probe);

        try std.testing.expect(conn.pto_count == i + 1);
        try std.testing.expect(conn.next_pto_at != null);
        const next_deadline = conn.next_pto_at.?;
        try std.testing.expect(next_deadline.isAfter(last_deadline));
        last_deadline = next_deadline;
    }

    // Guardrail: bounded PTO growth for this harness.
    try std.testing.expect(conn.pto_count <= 5);
}

test "recovery remains stable under mixed loss and timeout stress" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initClient(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();
    conn.markEstablished();

    var round: u32 = 0;
    while (round < 20) : (round += 1) {
        // Send a small burst.
        conn.trackPacketSent(1200, true);
        conn.trackPacketSent(1200, true);
        conn.trackPacketSent(1200, true);

        // ACK the most recent packet to drive loss detection and recovery.
        conn.processAckDetailed(conn.next_packet_number - 1, 0);

        // If PTO expires, queue and consume a probe.
        if (conn.next_pto_at) |deadline| {
            conn.onPtoTimeout(deadline.add(1));
            while (conn.popRetransmission()) |req| {
                // Simulate consuming queued retransmissions/probes.
                _ = req;
            }
        }

        // Stability checks: controller should stay within sane bounds.
        try std.testing.expect(conn.congestion_controller.getCongestionWindow() >= 2 * conn.congestion_controller.max_datagram_size);
        try std.testing.expect(conn.availableSendBudget() <= conn.max_data_remote);
        try std.testing.expect(conn.pto_count <= round + 1);
    }
}

test "path challenge queues matching path response" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initServer(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();

    const token = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    try conn.onPathChallenge(token);

    const queued = conn.popPathResponse();
    try std.testing.expect(queued != null);
    try std.testing.expectEqualSlices(u8, &token, &queued.?);
}

test "path response validates peer and lifts amplification cap" {
    const allocator = std.testing.allocator;

    const local_cid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    var conn = try Connection.initServer(allocator, .tls, local_cid, remote_cid);
    defer conn.deinit();

    conn.updateDataReceived(1000);
    try std.testing.expectEqual(@as(u64, 3000), conn.availableSendBudget());

    const token = [_]u8{ 1, 1, 2, 2, 3, 3, 4, 4 };
    conn.beginPathValidation(token);
    try std.testing.expect(!conn.peer_validated);

    const ok = conn.onPathResponse(token);
    try std.testing.expect(ok);
    try std.testing.expect(conn.peer_validated);
    try std.testing.expect(conn.availableSendBudget() > 3000);
}
