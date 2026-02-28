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
const transport_params_mod = @import("../core/transport_params.zig");
const tls_context_mod = @import("../crypto/tls/tls_context.zig");
const tls_handshake_mod = @import("../crypto/tls/handshake.zig");
const varint = @import("../utils/varint.zig");
const time_mod = @import("../utils/time.zig");

const DEFAULT_SHORT_HEADER_DCID_LEN: u8 = 8;
const CLOSE_REASON_MAX_LEN: usize = 256;

const PacketSpace = enum {
    initial,
    handshake,
    zero_rtt,
    retry,
    application,
};

const ParsedHeader = struct {
    consumed: usize,
    packet_space: PacketSpace,
};

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

    // TLS handshake context (TLS mode)
    tls_ctx: ?*tls_context_mod.TlsContext,

    // Event queue
    events: std.ArrayList(types_mod.ConnectionEvent),

    // Remote address (for client)
    remote_addr: ?std.net.Address,

    // Basic packet visibility counters
    packets_received: u64,
    packets_invalid: u64,

    // Negotiated protocol metadata
    negotiated_alpn: ?[]const u8,

    // TLS integrated handshake progression marker
    tls_server_hello_applied: bool,

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
            .tls_ctx = null,
            .events = .{},
            .remote_addr = null,
            .packets_received = 0,
            .packets_invalid = 0,
            .negotiated_alpn = null,
            .tls_server_hello_applied = false,
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

    fn decodePacketHeader(self: *QuicConnection, packet: []const u8) types_mod.QuicError!ParsedHeader {
        if (packet.len == 0) {
            return types_mod.QuicError.InvalidPacket;
        }

        const is_long_header = (packet[0] & 0x80) != 0;

        if (is_long_header) {
            const result = packet_mod.LongHeader.decode(packet) catch {
                return types_mod.QuicError.InvalidPacket;
            };

            const space: PacketSpace = switch (result.header.packet_type) {
                .initial => .initial,
                .handshake => .handshake,
                .zero_rtt => .zero_rtt,
                .retry => .retry,
                else => .application,
            };

            return .{ .consumed = result.consumed, .packet_space = space };
        }

        const dcid_len = self.shortHeaderDcidLen();
        const result = packet_mod.ShortHeader.decode(packet, dcid_len) catch {
            return types_mod.QuicError.InvalidPacket;
        };
        return .{ .consumed = result.consumed, .packet_space = .application };
    }

    fn queueProtocolViolation(self: *QuicConnection, reason: []const u8) types_mod.QuicError!void {
        if (self.state == .closed) {
            return;
        }

        try self.enterDraining(@intFromEnum(core_types.ErrorCode.protocol_violation), reason);
    }

    fn queueTransportParameterError(self: *QuicConnection, reason: []const u8) types_mod.QuicError!void {
        if (self.state == .closed) {
            return;
        }

        try self.enterDraining(@intFromEnum(core_types.ErrorCode.transport_parameter_error), reason);
    }

    fn queueFlowControlError(self: *QuicConnection, reason: []const u8) types_mod.QuicError!void {
        if (self.state == .closed) {
            return;
        }

        try self.enterDraining(@intFromEnum(core_types.ErrorCode.flow_control_error), reason);
    }

    fn transitionToEstablished(self: *QuicConnection) types_mod.QuicError!void {
        if (self.state != .connecting) {
            return;
        }

        const negotiation = self.buildNegotiationResult();
        if (negotiation.mode == .tls and !negotiation.ready_for_establish) {
            return;
        }

        const conn = self.internal_conn orelse return;
        conn.markEstablished();

        if (self.tls_ctx) |tls_ctx| {
            self.negotiated_alpn = tls_ctx.getSelectedAlpn();
        }

        self.state = .established;
        try self.events.append(self.allocator, .{ .connected = .{ .alpn = self.negotiated_alpn } });
    }

    fn isTlsNegotiatedForEstablish(self: *const QuicConnection) bool {
        const negotiation = self.buildNegotiationResult();
        return negotiation.mode == .tls and negotiation.ready_for_establish;
    }

    fn negotiationMode(self: *const QuicConnection) types_mod.NegotiationMode {
        return switch (self.config.mode) {
            .tls => .tls,
            .ssh => .ssh,
        };
    }

    fn buildNegotiationResult(self: *const QuicConnection) types_mod.NegotiationResult {
        const mode = self.negotiationMode();

        const has_peer_transport_params = blk: {
            const conn = self.internal_conn orelse break :blk false;
            break :blk conn.remote_params != null;
        };

        const tls_handshake_complete = blk: {
            if (mode != .tls) break :blk false;
            const tls_ctx = self.tls_ctx orelse break :blk false;
            break :blk tls_ctx.state.isComplete();
        };

        const ready_for_establish = switch (mode) {
            .tls => has_peer_transport_params and self.tls_server_hello_applied and tls_handshake_complete,
            .ssh => has_peer_transport_params,
        };

        return .{
            .mode = mode,
            .has_peer_transport_params = has_peer_transport_params,
            .tls_server_hello_applied = self.tls_server_hello_applied,
            .tls_handshake_complete = tls_handshake_complete,
            .selected_alpn = self.negotiated_alpn,
            .ready_for_establish = ready_for_establish,
        };
    }

    fn validateFrameAllowedInState(self: *QuicConnection, frame_type: u64) types_mod.QuicError!void {
        if (self.state != .connecting) {
            return;
        }

        if (core_types.FrameType.isStreamFrame(frame_type)) {
            return types_mod.QuicError.ProtocolViolation;
        }

        switch (frame_type) {
            0x04, 0x05, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 => {
                return types_mod.QuicError.ProtocolViolation;
            },
            else => {},
        }
    }

    fn validateFrameAllowedInPacketSpace(self: *QuicConnection, frame_type: u64, packet_space: PacketSpace) types_mod.QuicError!void {
        _ = self;

        if (packet_space == .application) {
            return;
        }

        if (packet_space == .retry) {
            return types_mod.QuicError.ProtocolViolation;
        }

        if (frame_type == 0x01 or frame_type == 0x1c or frame_type == 0x1d) {
            return;
        }

        if (frame_type == 0x02 or frame_type == 0x03) {
            if (packet_space == .zero_rtt) return types_mod.QuicError.ProtocolViolation;
            return;
        }

        if (packet_space != .application and (frame_type == 0x07 or frame_type == 0x18 or frame_type == 0x19 or frame_type == 0x1e)) {
            return types_mod.QuicError.ProtocolViolation;
        }

        if (isReservedFrameType(frame_type)) {
            return types_mod.QuicError.ProtocolViolation;
        }

        if (!isKnownFrameType(frame_type) and packet_space != .application) {
            return types_mod.QuicError.ProtocolViolation;
        }

        if (core_types.FrameType.isStreamFrame(frame_type)) {
            return types_mod.QuicError.ProtocolViolation;
        }

        switch (frame_type) {
            0x04, 0x05, 0x1a, 0x1b => return types_mod.QuicError.ProtocolViolation,
            else => {},
        }
    }

    fn isKnownFrameType(frame_type: u64) bool {
        if (core_types.FrameType.isStreamFrame(frame_type)) {
            return true;
        }

        return switch (frame_type) {
            0x00, // PADDING
            0x01, // PING
            0x02,
            0x03, // ACK
            0x04, // RESET_STREAM
            0x05, // STOP_SENDING
            0x06, // CRYPTO
            0x07, // NEW_TOKEN
            0x10, // MAX_DATA
            0x11, // MAX_STREAM_DATA
            0x12,
            0x13, // MAX_STREAMS
            0x14, // DATA_BLOCKED
            0x15, // STREAM_DATA_BLOCKED
            0x16,
            0x17, // STREAMS_BLOCKED
            0x18, // NEW_CONNECTION_ID
            0x19, // RETIRE_CONNECTION_ID
            0x1a, // PATH_CHALLENGE
            0x1b, // PATH_RESPONSE
            0x1c,
            0x1d, // CONNECTION_CLOSE
            0x1e, // HANDSHAKE_DONE
            => true,
            else => false,
        };
    }

    fn isReservedFrameType(frame_type: u64) bool {
        if (frame_type < 0x1f) {
            return false;
        }

        return (frame_type & 0x1f) == 0x1f;
    }

    fn routeFrame(self: *QuicConnection, payload: []const u8, packet_space: PacketSpace) types_mod.QuicError!void {
        if (payload.len == 0) return;

        const frame_type_result = varint.decode(payload) catch {
            return types_mod.QuicError.InvalidPacket;
        };

        const frame_type = frame_type_result.value;

        try self.validateFrameAllowedInState(frame_type);
        try self.validateFrameAllowedInPacketSpace(frame_type, packet_space);

        if (core_types.FrameType.isStreamFrame(frame_type)) {
            const decoded = frame_mod.StreamFrame.decode(payload) catch {
                return types_mod.QuicError.InvalidPacket;
            };
            const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;
            const stream = conn.getOrCreateStream(decoded.frame.stream_id) catch {
                return types_mod.QuicError.StreamError;
            };

            stream.appendRecvData(decoded.frame.data, decoded.frame.offset, decoded.frame.fin) catch |err| {
                return switch (err) {
                    error.FlowControlError => types_mod.QuicError.FlowControlError,
                    error.OutOfOrderData, error.StreamClosed => types_mod.QuicError.ProtocolViolation,
                    else => types_mod.QuicError.InvalidPacket,
                };
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
            0x1a => {
                const decoded = frame_mod.PathChallengeFrame.decode(payload) catch {
                    return types_mod.QuicError.InvalidPacket;
                };

                const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;
                conn.onPathChallenge(decoded.frame.data) catch {
                    return types_mod.QuicError.OutOfMemory;
                };
            },
            0x1b => {
                const decoded = frame_mod.PathResponseFrame.decode(payload) catch {
                    return types_mod.QuicError.InvalidPacket;
                };

                const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;
                _ = conn.onPathResponse(decoded.frame.data);
            },
            else => {
                // Unknown/unhandled frame type in this slice: ignore.
            },
        }
    }

    fn encodeLocalTransportParams(self: *QuicConnection) types_mod.QuicError![]u8 {
        var params = transport_params_mod.TransportParams.init();
        params.max_idle_timeout = self.config.max_idle_timeout;
        params.initial_max_data = self.config.initial_max_data;
        params.initial_max_stream_data_bidi_local = self.config.initial_max_stream_data_bidi_local;
        params.initial_max_stream_data_bidi_remote = self.config.initial_max_stream_data_bidi_remote;
        params.initial_max_stream_data_uni = self.config.initial_max_stream_data_uni;
        params.initial_max_streams_bidi = self.config.max_bidi_streams;
        params.initial_max_streams_uni = self.config.max_uni_streams;

        return params.encode(self.allocator) catch {
            return types_mod.QuicError.InvalidConfig;
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

        internal_conn.* = conn_internal.Connection.initClient(
            self.allocator,
            quic_mode,
            local_cid,
            remote_cid,
        ) catch {
            return types_mod.QuicError.InvalidConfig;
        };
        self.internal_conn = internal_conn;

        if (self.config.mode == .tls) {
            const tls_cfg = self.config.tls_config orelse return types_mod.QuicError.MissingTlsConfig;

            const encoded_tp = try self.encodeLocalTransportParams();
            defer self.allocator.free(encoded_tp);

            const tls_ctx = try self.allocator.create(tls_context_mod.TlsContext);
            errdefer self.allocator.destroy(tls_ctx);
            tls_ctx.* = tls_context_mod.TlsContext.init(self.allocator, true);

            const client_hello = tls_ctx.startClientHandshakeWithParams(
                tls_cfg.server_name,
                tls_cfg.alpn_protocols,
                encoded_tp,
            ) catch {
                tls_ctx.deinit();
                return types_mod.QuicError.HandshakeFailed;
            };
            defer self.allocator.free(client_hello);

            self.tls_ctx = tls_ctx;
            self.tls_server_hello_applied = false;
        }

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
        if (!self.isHandshakeNegotiated()) {
            return types_mod.QuicError.ConnectionNotEstablished;
        }

        const caps = self.getModeCapabilities();
        if (!bidirectional and !caps.supports_unidirectional_streams) {
            return types_mod.QuicError.StreamError;
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
        if (!self.isHandshakeNegotiated()) {
            return types_mod.QuicError.ConnectionNotEstablished;
        }

        const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;

        // Get stream
        const stream = conn.getStream(stream_id) orelse return types_mod.QuicError.StreamNotFound;

        const budget = conn.availableSendBudget();
        if (budget == 0) {
            return types_mod.QuicError.FlowControlError;
        }

        const write_len: usize = @intCast(@min(@as(u64, data.len), budget));
        const write_data = data[0..write_len];

        // Write data to stream
        const written = stream.write(write_data) catch {
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
        if (!self.isHandshakeNegotiated()) {
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
        if (!self.isHandshakeNegotiated()) {
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

            const header = self.decodePacketHeader(packet) catch {
                self.packets_invalid += 1;
                try self.queueProtocolViolation("invalid packet header");
                return;
            };

            if (header.consumed >= packet.len) return;

            try self.transitionToEstablished();

            self.routeFrame(packet[header.consumed..], header.packet_space) catch |err| {
                self.packets_invalid += 1;
                if (err == types_mod.QuicError.ProtocolViolation) {
                    try self.queueProtocolViolation("frame not allowed in current context");
                    return;
                }

                if (err == types_mod.QuicError.FlowControlError) {
                    try self.queueFlowControlError("stream flow control exceeded");
                    return;
                }

                try self.queueProtocolViolation("invalid frame payload");
                return;
            };
        }
    }

    /// Decode and apply peer transport parameters.
    ///
    /// Both TLS and SSH-like handshake code paths can call this once peer
    /// transport parameters are available. Invalid transport parameters
    /// transition the connection into draining with transport_parameter_error.
    pub fn applyPeerTransportParams(self: *QuicConnection, encoded_params: []const u8) types_mod.QuicError!void {
        const decoded = transport_params_mod.TransportParams.decode(self.allocator, encoded_params) catch {
            try self.queueTransportParameterError("invalid peer transport params");
            return types_mod.QuicError.ProtocolViolation;
        };

        const conn = self.internal_conn orelse return types_mod.QuicError.InvalidState;

        conn.setRemoteParams(.{
            .max_idle_timeout = decoded.max_idle_timeout,
            .max_udp_payload_size = decoded.max_udp_payload_size,
            .initial_max_data = decoded.initial_max_data,
            .initial_max_stream_data_bidi_local = decoded.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = decoded.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = decoded.initial_max_stream_data_uni,
            .initial_max_streams_bidi = decoded.initial_max_streams_bidi,
            .initial_max_streams_uni = decoded.initial_max_streams_uni,
            .ack_delay_exponent = decoded.ack_delay_exponent,
            .max_ack_delay = decoded.max_ack_delay,
            .disable_active_migration = decoded.disable_active_migration,
            .active_connection_id_limit = decoded.active_connection_id_limit,
        });
    }

    /// Processes TLS ServerHello, completes TLS handshake, and applies peer
    /// QUIC transport parameters carried in TLS extensions.
    pub fn processTlsServerHello(self: *QuicConnection, server_hello_data: []const u8, shared_secret: []const u8) types_mod.QuicError!void {
        if (self.config.mode != .tls) {
            return types_mod.QuicError.InvalidState;
        }

        const tls_ctx = self.tls_ctx orelse return types_mod.QuicError.InvalidState;

        tls_ctx.processServerHello(server_hello_data) catch |err| {
            if (err == tls_context_mod.TlsError.AlpnMismatch) {
                try self.enterDraining(@intFromEnum(core_types.ErrorCode.connection_refused), "alpn mismatch");
                return types_mod.QuicError.HandshakeFailed;
            }

            try self.queueProtocolViolation("tls server hello rejected");
            return types_mod.QuicError.HandshakeFailed;
        };

        tls_ctx.completeHandshake(shared_secret) catch {
            try self.queueProtocolViolation("tls handshake completion failed");
            return types_mod.QuicError.HandshakeFailed;
        };

        const peer_tp = tls_ctx.getPeerTransportParams() orelse {
            try self.queueTransportParameterError("missing peer transport params in tls extensions");
            return types_mod.QuicError.HandshakeFailed;
        };

        try self.applyPeerTransportParams(peer_tp);
        self.tls_server_hello_applied = true;
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

    /// Returns negotiated ALPN protocol when available.
    pub fn getNegotiatedAlpn(self: *const QuicConnection) ?[]const u8 {
        return self.negotiated_alpn;
    }

    /// Returns true when handshake negotiation is complete enough to gate app traffic.
    ///
    /// For TLS mode this requires:
    /// - connection established state
    /// - TLS handshake complete
    /// - peer transport parameters applied
    ///
    /// For SSH mode this requires:
    /// - connection established state
    /// - peer transport parameters applied
    pub fn isHandshakeNegotiated(self: *const QuicConnection) bool {
        if (self.state != .established) {
            return false;
        }

        const caps = self.getModeCapabilities();
        const negotiation = self.buildNegotiationResult();
        if (!negotiation.has_peer_transport_params and caps.requires_peer_transport_params) {
            return false;
        }

        if (negotiation.mode == .tls and caps.requires_integrated_tls_server_hello and !negotiation.tls_server_hello_applied) {
            return false;
        }

        return negotiation.ready_for_establish;
    }

    pub fn getModeCapabilities(self: *const QuicConnection) types_mod.ModeCapabilities {
        return types_mod.ModeCapabilities.forMode(self.negotiationMode());
    }

    pub fn getNegotiationResult(self: *const QuicConnection) types_mod.NegotiationResult {
        return self.buildNegotiationResult();
    }

    /// Returns a point-in-time negotiation snapshot.
    pub fn getNegotiationSnapshot(self: *const QuicConnection) ?types_mod.NegotiationSnapshot {
        const conn = self.internal_conn orelse return null;
        const remote_params = conn.remote_params orelse core_types.TransportParameters{};

        const mode = self.negotiationMode();

        return .{
            .mode = mode,
            .is_established = self.state == .established,
            .alpn = self.negotiated_alpn,
            .peer_max_idle_timeout = remote_params.max_idle_timeout,
            .peer_max_udp_payload_size = remote_params.max_udp_payload_size,
            .peer_initial_max_data = remote_params.initial_max_data,
            .peer_initial_max_streams_bidi = remote_params.initial_max_streams_bidi,
            .peer_initial_max_streams_uni = remote_params.initial_max_streams_uni,
        };
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

        if (self.tls_ctx) |ctx| {
            ctx.deinit();
            self.allocator.destroy(ctx);
        }

        self.events.deinit(self.allocator);
        self.state = .closed;
    }
};

// Tests

fn applyDefaultPeerTransportParams(conn: *QuicConnection, allocator: std.mem.Allocator) !void {
    const encoded = try transport_params_mod.TransportParams.defaultServer().encode(allocator);
    defer allocator.free(encoded);
    try conn.applyPeerTransportParams(encoded);
}

fn applyPeerTransportParamsWithLimits(conn: *QuicConnection, allocator: std.mem.Allocator, max_bidi: u64, max_uni: u64) !void {
    var params = transport_params_mod.TransportParams.defaultServer();
    params.initial_max_streams_bidi = max_bidi;
    params.initial_max_streams_uni = max_uni;

    const encoded = try params.encode(allocator);
    defer allocator.free(encoded);
    try conn.applyPeerTransportParams(encoded);
}

fn buildTlsServerHelloForTests(
    allocator: std.mem.Allocator,
    alpn: []const u8,
    tp_payload: []const u8,
) ![]u8 {
    var alpn_wire: [8]u8 = undefined;
    if (alpn.len == 0 or alpn.len > 5) return error.InvalidInput;

    alpn_wire[0] = 0x00;
    alpn_wire[1] = @intCast(alpn.len + 1);
    alpn_wire[2] = @intCast(alpn.len);
    @memcpy(alpn_wire[3 .. 3 + alpn.len], alpn);

    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = alpn_wire[0 .. 3 + alpn.len],
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = tp_payload,
        },
    };

    const random: [32]u8 = [_]u8{61} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };

    return server_hello.encode(allocator);
}

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

test "TLS connect wires config ALPN into ClientHello" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try std.testing.expect(conn.tls_ctx != null);
    try std.testing.expect(conn.tls_ctx.?.state == .client_hello_sent);
    try std.testing.expect(std.mem.indexOf(u8, conn.tls_ctx.?.transcript.items, "h3") != null);
}

test "connected event carries negotiated ALPN metadata" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

    var server_params = transport_params_mod.TransportParams.defaultServer();
    server_params.initial_max_data = 4096;
    const encoded_server_params = try server_params.encode(allocator);
    defer allocator.free(encoded_server_params);

    var alpn_payload: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '3' };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_payload,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = encoded_server_params,
        },
    };
    const random: [32]u8 = [_]u8{7} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const server_hello_bytes = try server_hello.encode(allocator);
    defer allocator.free(server_hello_bytes);
    try conn.processTlsServerHello(server_hello_bytes, "test-shared-secret-from-ecdhe");

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
        .packet_number = 9,
    };
    var packet_len = try header.encode(&packet_buf);
    packet_buf[packet_len] = 0x01;
    packet_len += 1;
    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);

    try conn.poll();

    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .connected);
    try std.testing.expect(event.?.connected.alpn != null);
    try std.testing.expectEqualStrings("h3", event.?.connected.alpn.?);
    try std.testing.expect(conn.getNegotiatedAlpn() != null);
    try std.testing.expectEqualStrings("h3", conn.getNegotiatedAlpn().?);
}

test "TLS connect remains connecting until TLS and transport params negotiated" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

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
        .packet_number = 10,
    };
    var packet_len = try header.encode(&packet_buf);
    packet_buf[packet_len] = 0x01;
    packet_len += 1;
    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);

    try conn.poll();
    try std.testing.expectEqual(types_mod.ConnectionState.connecting, conn.getState());
    try std.testing.expect(conn.nextEvent() == null);
}

test "processTlsServerHello applies peer transport params from tls extension" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();
    try conn.connect("127.0.0.1", 4433);

    var server_params = transport_params_mod.TransportParams.defaultServer();
    server_params.initial_max_streams_bidi = 1;
    const encoded_server_params = try server_params.encode(allocator);
    defer allocator.free(encoded_server_params);

    var alpn_payload: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '3' };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_payload,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = encoded_server_params,
        },
    };
    const random: [32]u8 = [_]u8{31} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const server_hello_bytes = try server_hello.encode(allocator);
    defer allocator.free(server_hello_bytes);

    try conn.processTlsServerHello(server_hello_bytes, "test-shared-secret-from-ecdhe");
    try std.testing.expect(conn.internal_conn.?.remote_params != null);
    try std.testing.expectEqual(@as(u64, 1), conn.internal_conn.?.remote_params.?.initial_max_streams_bidi);
}

test "processTlsServerHello rejects missing peer transport params extension" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();
    try conn.connect("127.0.0.1", 4433);

    var alpn_payload: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '3' };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_payload,
        },
    };
    const random: [32]u8 = [_]u8{32} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const server_hello_bytes = try server_hello.encode(allocator);
    defer allocator.free(server_hello_bytes);

    try std.testing.expectError(
        types_mod.QuicError.HandshakeFailed,
        conn.processTlsServerHello(server_hello_bytes, "test-shared-secret-from-ecdhe"),
    );
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "processTlsServerHello rejects malformed ALPN extension payload" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();
    try conn.connect("127.0.0.1", 4433);

    var server_params = transport_params_mod.TransportParams.defaultServer();
    const encoded_server_params = try server_params.encode(allocator);
    defer allocator.free(encoded_server_params);

    // Malformed ALPN: list length says 3, but payload has only 2 bytes after header.
    var malformed_alpn: [4]u8 = .{ 0x00, 0x03, 0x02, 'h' };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &malformed_alpn,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = encoded_server_params,
        },
    };
    const random: [32]u8 = [_]u8{33} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const server_hello_bytes = try server_hello.encode(allocator);
    defer allocator.free(server_hello_bytes);

    try std.testing.expectError(
        types_mod.QuicError.HandshakeFailed,
        conn.processTlsServerHello(server_hello_bytes, "test-shared-secret-from-ecdhe"),
    );
}

test "processTlsServerHello rejects zero-length selected ALPN protocol" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();
    try conn.connect("127.0.0.1", 4433);

    const tp = try transport_params_mod.TransportParams.defaultServer().encode(allocator);
    defer allocator.free(tp);

    // ALPN list length 1 with a zero-length protocol id.
    var alpn_zero: [3]u8 = .{ 0x00, 0x01, 0x00 };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_zero,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = tp,
        },
    };
    const random: [32]u8 = [_]u8{36} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const server_hello_bytes = try server_hello.encode(allocator);
    defer allocator.free(server_hello_bytes);

    try std.testing.expectError(
        types_mod.QuicError.HandshakeFailed,
        conn.processTlsServerHello(server_hello_bytes, "test-shared-secret-from-ecdhe"),
    );
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "processTlsServerHello rejects invalid transport params extension payload" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();
    try conn.connect("127.0.0.1", 4433);

    var alpn_payload: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '3' };
    // Invalid transport params payload (truncated varint parameter).
    const invalid_tp = [_]u8{ 0x03, 0x02, 0x44 };

    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_payload,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = &invalid_tp,
        },
    };
    const random: [32]u8 = [_]u8{34} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const server_hello_bytes = try server_hello.encode(allocator);
    defer allocator.free(server_hello_bytes);

    try std.testing.expectError(
        types_mod.QuicError.HandshakeFailed,
        conn.processTlsServerHello(server_hello_bytes, "test-shared-secret-from-ecdhe"),
    );
}

test "processTlsServerHello surfaces ALPN mismatch reason" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();
    try conn.connect("127.0.0.1", 4433);

    var server_params = transport_params_mod.TransportParams.defaultServer();
    const encoded_server_params = try server_params.encode(allocator);
    defer allocator.free(encoded_server_params);

    // Server selects h2 although client only offered h3.
    var alpn_payload: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '2' };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_payload,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = encoded_server_params,
        },
    };
    const random: [32]u8 = [_]u8{35} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const server_hello_bytes = try server_hello.encode(allocator);
    defer allocator.free(server_hello_bytes);

    try std.testing.expectError(
        types_mod.QuicError.HandshakeFailed,
        conn.processTlsServerHello(server_hello_bytes, "test-shared-secret-from-ecdhe"),
    );

    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .closing);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(core_types.ErrorCode.connection_refused)),
        event.?.closing.error_code,
    );
    try std.testing.expectEqualStrings("alpn mismatch", event.?.closing.reason);
}

test "processTlsServerHello rejects duplicate ALPN extensions" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();
    try conn.connect("127.0.0.1", 4433);

    const tp = try transport_params_mod.TransportParams.defaultServer().encode(allocator);
    defer allocator.free(tp);

    var alpn_h3: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '3' };
    var alpn_h2: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '2' };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_h3,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_h2,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = tp,
        },
    };

    const random: [32]u8 = [_]u8{41} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const payload = try server_hello.encode(allocator);
    defer allocator.free(payload);

    try std.testing.expectError(types_mod.QuicError.HandshakeFailed, conn.processTlsServerHello(payload, "test-shared-secret-from-ecdhe"));
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "processTlsServerHello rejects duplicate transport parameter extensions" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();
    try conn.connect("127.0.0.1", 4433);

    const tp1 = try transport_params_mod.TransportParams.defaultServer().encode(allocator);
    defer allocator.free(tp1);
    var tp_params2 = transport_params_mod.TransportParams.defaultServer();
    tp_params2.initial_max_data = 12345;
    const tp2 = try tp_params2.encode(allocator);
    defer allocator.free(tp2);

    var alpn_h3: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '3' };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_h3,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = tp1,
        },
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters),
            .extension_data = tp2,
        },
    };

    const random: [32]u8 = [_]u8{42} ** 32;
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const payload = try server_hello.encode(allocator);
    defer allocator.free(payload);

    try std.testing.expectError(types_mod.QuicError.HandshakeFailed, conn.processTlsServerHello(payload, "test-shared-secret-from-ecdhe"));
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "negotiation snapshot exposes mode ALPN and peer params" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    const internal_conn = try allocator.create(conn_internal.Connection);
    const local_cid = try core_types.ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const remote_cid = try core_types.ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });
    internal_conn.* = try conn_internal.Connection.initClient(allocator, .tls, local_cid, remote_cid);
    internal_conn.markEstablished();
    conn.internal_conn = internal_conn;
    conn.state = .established;

    var encoded = transport_params_mod.TransportParams.init();
    encoded.max_idle_timeout = 12345;
    encoded.initial_max_data = 45678;
    encoded.initial_max_streams_bidi = 7;
    encoded.initial_max_streams_uni = 3;
    const payload = try encoded.encode(allocator);
    defer allocator.free(payload);
    try conn.applyPeerTransportParams(payload);

    conn.negotiated_alpn = "h3";

    const snapshot = conn.getNegotiationSnapshot();
    try std.testing.expect(snapshot != null);
    try std.testing.expectEqual(types_mod.NegotiationMode.tls, snapshot.?.mode);
    try std.testing.expect(snapshot.?.is_established);
    try std.testing.expect(snapshot.?.alpn != null);
    try std.testing.expectEqualStrings("h3", snapshot.?.alpn.?);
    try std.testing.expectEqual(@as(u64, 12345), snapshot.?.peer_max_idle_timeout);
    try std.testing.expectEqual(@as(u64, 45678), snapshot.?.peer_initial_max_data);
    try std.testing.expectEqual(@as(u64, 7), snapshot.?.peer_initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 3), snapshot.?.peer_initial_max_streams_uni);
}

test "isHandshakeNegotiated requires integrated TLS server hello processing" {
    const allocator = std.testing.allocator;

    var config = config_mod.QuicConfig.tlsClient("example.com");
    var tls_cfg = config.tls_config.?;
    tls_cfg.alpn_protocols = &[_][]const u8{"h3"};
    config.tls_config = tls_cfg;

    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    conn.internal_conn.?.markEstablished();
    conn.state = .established;

    try std.testing.expect(!conn.isHandshakeNegotiated());

    const tls_ctx = conn.tls_ctx.?;
    const random: [32]u8 = [_]u8{11} ** 32;
    var alpn_payload: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '3' };
    const ext = [_]tls_handshake_mod.Extension{
        .{
            .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation),
            .extension_data = &alpn_payload,
        },
    };
    const server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &ext,
    };
    const server_hello_bytes = try server_hello.encode(allocator);
    defer allocator.free(server_hello_bytes);

    try tls_ctx.processServerHello(server_hello_bytes);
    try tls_ctx.completeHandshake("test-shared-secret-from-ecdhe");
    const encoded = try transport_params_mod.TransportParams.defaultServer().encode(allocator);
    defer allocator.free(encoded);
    try conn.applyPeerTransportParams(encoded);

    // Manual steps are not enough; integrated processing marks completion.
    try std.testing.expect(!conn.isHandshakeNegotiated());

    var conn2 = try QuicConnection.init(allocator, config);
    defer conn2.deinit();
    try conn2.connect("127.0.0.1", 4433);
    conn2.internal_conn.?.markEstablished();
    conn2.state = .established;

    var tp_ext = transport_params_mod.TransportParams.defaultServer();
    const encoded_tp_ext = try tp_ext.encode(allocator);
    defer allocator.free(encoded_tp_ext);
    const ext_with_tp = [_]tls_handshake_mod.Extension{
        .{ .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation), .extension_data = &alpn_payload },
        .{ .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters), .extension_data = encoded_tp_ext },
    };
    const integrated_server_hello = tls_handshake_mod.ServerHello{ .random = random, .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256, .extensions = &ext_with_tp };
    const integrated_server_hello_bytes = try integrated_server_hello.encode(allocator);
    defer allocator.free(integrated_server_hello_bytes);

    try conn2.processTlsServerHello(integrated_server_hello_bytes, "test-shared-secret-from-ecdhe");
    try std.testing.expect(conn2.isHandshakeNegotiated());
}

test "isHandshakeNegotiated requires peer transport params in SSH mode" {
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

    try std.testing.expect(!conn.isHandshakeNegotiated());

    const encoded = try transport_params_mod.TransportParams.defaultServer().encode(allocator);
    defer allocator.free(encoded);
    try conn.applyPeerTransportParams(encoded);

    try std.testing.expect(conn.isHandshakeNegotiated());
}

test "mode capabilities reflect tls and ssh modes" {
    const allocator = std.testing.allocator;

    var tls_conn = try QuicConnection.init(allocator, config_mod.QuicConfig.tlsClient("example.com"));
    defer tls_conn.deinit();

    const tls_caps = tls_conn.getModeCapabilities();
    try std.testing.expect(tls_caps.supports_unidirectional_streams);
    try std.testing.expect(tls_caps.supports_alpn);
    try std.testing.expect(tls_caps.requires_integrated_tls_server_hello);

    var ssh_conn = try QuicConnection.init(allocator, config_mod.QuicConfig.sshClient("example.com", "secret"));
    defer ssh_conn.deinit();

    const ssh_caps = ssh_conn.getModeCapabilities();
    try std.testing.expect(!ssh_caps.supports_unidirectional_streams);
    try std.testing.expect(!ssh_caps.supports_alpn);
    try std.testing.expect(!ssh_caps.requires_integrated_tls_server_hello);
}

test "dual-mode regression stream policy tls vs ssh" {
    const allocator = std.testing.allocator;

    var tls_cfg = config_mod.QuicConfig.tlsClient("example.com");
    tls_cfg.tls_config.?.alpn_protocols = &[_][]const u8{"h3"};
    var tls_conn = try QuicConnection.init(allocator, tls_cfg);
    defer tls_conn.deinit();
    try tls_conn.connect("127.0.0.1", 4433);

    var tls_tp = transport_params_mod.TransportParams.defaultServer();
    tls_tp.initial_max_streams_bidi = 2;
    tls_tp.initial_max_streams_uni = 1;
    const tls_tp_encoded = try tls_tp.encode(allocator);
    defer allocator.free(tls_tp_encoded);

    const server_hello = try buildTlsServerHelloForTests(allocator, "h3", tls_tp_encoded);
    defer allocator.free(server_hello);
    try tls_conn.processTlsServerHello(server_hello, "test-shared-secret-from-ecdhe");
    tls_conn.internal_conn.?.markEstablished();
    tls_conn.state = .established;

    _ = try tls_conn.openStream(false);

    const ssh_cfg = config_mod.QuicConfig.sshClient("example.com", "secret");
    var ssh_conn = try QuicConnection.init(allocator, ssh_cfg);
    defer ssh_conn.deinit();
    try ssh_conn.connect("127.0.0.1", 4433);
    ssh_conn.internal_conn.?.markEstablished();
    ssh_conn.state = .established;
    try applyPeerTransportParamsWithLimits(&ssh_conn, allocator, 2, 1);

    try std.testing.expectError(types_mod.QuicError.StreamError, ssh_conn.openStream(false));
}

test "dual-mode regression negotiated stream limits enforced" {
    const allocator = std.testing.allocator;

    var tls_cfg = config_mod.QuicConfig.tlsClient("example.com");
    tls_cfg.tls_config.?.alpn_protocols = &[_][]const u8{"h3"};
    var tls_conn = try QuicConnection.init(allocator, tls_cfg);
    defer tls_conn.deinit();
    try tls_conn.connect("127.0.0.1", 4433);

    var tls_tp = transport_params_mod.TransportParams.defaultServer();
    tls_tp.initial_max_streams_bidi = 1;
    const tls_tp_encoded = try tls_tp.encode(allocator);
    defer allocator.free(tls_tp_encoded);

    const server_hello = try buildTlsServerHelloForTests(allocator, "h3", tls_tp_encoded);
    defer allocator.free(server_hello);
    try tls_conn.processTlsServerHello(server_hello, "test-shared-secret-from-ecdhe");
    tls_conn.internal_conn.?.markEstablished();
    tls_conn.state = .established;

    _ = try tls_conn.openStream(true);
    try std.testing.expectError(types_mod.QuicError.StreamLimitReached, tls_conn.openStream(true));

    const ssh_cfg = config_mod.QuicConfig.sshClient("example.com", "secret");
    var ssh_conn = try QuicConnection.init(allocator, ssh_cfg);
    defer ssh_conn.deinit();
    try ssh_conn.connect("127.0.0.1", 4433);
    ssh_conn.internal_conn.?.markEstablished();
    ssh_conn.state = .established;
    try applyPeerTransportParamsWithLimits(&ssh_conn, allocator, 1, 0);

    _ = try ssh_conn.openStream(true);
    try std.testing.expectError(types_mod.QuicError.StreamLimitReached, ssh_conn.openStream(true));
}

test "negotiation result is normalized across modes" {
    const allocator = std.testing.allocator;

    var tls_config = config_mod.QuicConfig.tlsClient("example.com");
    tls_config.tls_config.?.alpn_protocols = &[_][]const u8{"h3"};

    var tls_conn = try QuicConnection.init(allocator, tls_config);
    defer tls_conn.deinit();
    try tls_conn.connect("127.0.0.1", 4433);

    var server_params = transport_params_mod.TransportParams.defaultServer();
    const encoded_server_params = try server_params.encode(allocator);
    defer allocator.free(encoded_server_params);

    var alpn_payload: [5]u8 = .{ 0x00, 0x03, 0x02, 'h', '3' };
    const tls_ext = [_]tls_handshake_mod.Extension{
        .{ .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.application_layer_protocol_negotiation), .extension_data = &alpn_payload },
        .{ .extension_type = @intFromEnum(tls_handshake_mod.ExtensionType.quic_transport_parameters), .extension_data = encoded_server_params },
    };
    const random: [32]u8 = [_]u8{51} ** 32;
    const tls_server_hello = tls_handshake_mod.ServerHello{
        .random = random,
        .cipher_suite = tls_handshake_mod.TLS_AES_128_GCM_SHA256,
        .extensions = &tls_ext,
    };
    const tls_server_hello_bytes = try tls_server_hello.encode(allocator);
    defer allocator.free(tls_server_hello_bytes);
    try tls_conn.processTlsServerHello(tls_server_hello_bytes, "test-shared-secret-from-ecdhe");

    const tls_result = tls_conn.getNegotiationResult();
    try std.testing.expectEqual(types_mod.NegotiationMode.tls, tls_result.mode);
    try std.testing.expect(tls_result.has_peer_transport_params);
    try std.testing.expect(tls_result.tls_server_hello_applied);
    try std.testing.expect(tls_result.tls_handshake_complete);
    try std.testing.expect(tls_result.ready_for_establish);

    const ssh_config = config_mod.QuicConfig.sshClient("example.com", "secret");
    var ssh_conn = try QuicConnection.init(allocator, ssh_config);
    defer ssh_conn.deinit();
    try ssh_conn.connect("127.0.0.1", 4433);
    try applyDefaultPeerTransportParams(&ssh_conn, allocator);

    const ssh_result = ssh_conn.getNegotiationResult();
    try std.testing.expectEqual(types_mod.NegotiationMode.ssh, ssh_result.mode);
    try std.testing.expect(ssh_result.has_peer_transport_params);
    try std.testing.expect(!ssh_result.tls_server_hello_applied);
    try std.testing.expect(!ssh_result.tls_handshake_complete);
    try std.testing.expect(ssh_result.ready_for_establish);
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

    try conn.events.append(allocator, .{ .connected = .{} });

    const event = conn.nextEvent();
    try std.testing.expect(event != null);

    const event2 = conn.nextEvent();
    try std.testing.expect(event2 == null);
}

test "connect stays connecting without handshake progress" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    try std.testing.expectEqual(types_mod.ConnectionState.connecting, conn.getState());
    try std.testing.expect(conn.nextEvent() == null);

    try conn.poll();
    try std.testing.expectEqual(types_mod.ConnectionState.connecting, conn.getState());
    try std.testing.expect(conn.nextEvent() == null);
}

test "connect emits connected event when first packet is processed" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

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
    packet_buf[packet_len] = 0x01;
    packet_len += 1;

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
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
    try applyDefaultPeerTransportParams(&conn, allocator);

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

test "streamWrite respects congestion send budget" {
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
    try applyDefaultPeerTransportParams(&conn, allocator);

    const stream_id = try conn.openStream(true);
    _ = conn.nextEvent();

    // Limit send budget to 5 bytes.
    internal_conn.congestion_controller.congestion_window = 5;
    internal_conn.congestion_controller.bytes_in_flight = 0;

    const written = try conn.streamWrite(stream_id, "abcdefghij", .no_finish);
    try std.testing.expectEqual(@as(usize, 5), written);

    // Exhaust budget and ensure write is blocked.
    internal_conn.congestion_controller.bytes_in_flight = 5;
    try std.testing.expectError(
        types_mod.QuicError.FlowControlError,
        conn.streamWrite(stream_id, "x", .no_finish),
    );
}

test "poll parses received long-header packet and updates visibility stats" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

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

    const connected_event = conn.nextEvent();
    try std.testing.expect(connected_event != null);
    try std.testing.expect(connected_event.? == .connected);

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

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    const invalid_packet = [_]u8{0x40};
    _ = try sender.sendTo(&invalid_packet, local_addr);

    try conn.poll();

    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .closing);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(core_types.ErrorCode.protocol_violation)),
        event.?.closing.error_code,
    );
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "poll routes ACK frame into connection ack tracking" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

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

    const connected_event = conn.nextEvent();
    try std.testing.expect(connected_event != null);
    try std.testing.expect(connected_event.? == .connected);

    try std.testing.expectEqual(@as(u64, 7), conn.internal_conn.?.largest_acked);
}

test "poll routes connection close frame to closing event" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

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

    _ = conn.nextEvent(); // connected
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

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [512]u8 = undefined;
    const header = packet_mod.ShortHeader{
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .packet_number = 4,
        .key_phase = false,
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

    _ = conn.nextEvent(); // connected
    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .stream_readable);
    try std.testing.expectEqual(@as(u64, 4), event.?.stream_readable);

    try applyDefaultPeerTransportParams(&conn, allocator);

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

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [512]u8 = undefined;
    const header = packet_mod.ShortHeader{
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .packet_number = 5,
        .key_phase = false,
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

    _ = conn.nextEvent(); // connected
    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .stream_closed);
    try std.testing.expectEqual(@as(u64, 4), event.?.stream_closed.id);
    try std.testing.expectEqual(@as(?u64, 99), event.?.stream_closed.error_code);
}

test "poll routes PATH_CHALLENGE frame and queues response token" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [256]u8 = undefined;
    const header = packet_mod.ShortHeader{
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .packet_number = 6,
        .key_phase = false,
    };

    var packet_len = try header.encode(&packet_buf);
    const challenge = frame_mod.PathChallengeFrame{ .data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    packet_len += try challenge.encode(packet_buf[packet_len..]);

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    _ = conn.nextEvent(); // connected

    const pending = conn.internal_conn.?.popPathResponse();
    try std.testing.expect(pending != null);
    try std.testing.expectEqualSlices(u8, &challenge.data, &pending.?);
}

test "poll routes PATH_RESPONSE frame and validates peer path" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

    const token = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    conn.internal_conn.?.beginPathValidation(token);
    try std.testing.expect(!conn.internal_conn.?.peer_validated);

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [256]u8 = undefined;
    const header = packet_mod.ShortHeader{
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .packet_number = 7,
        .key_phase = false,
    };

    var packet_len = try header.encode(&packet_buf);
    const response = frame_mod.PathResponseFrame{ .data = token };
    packet_len += try response.encode(packet_buf[packet_len..]);

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    _ = conn.nextEvent(); // connected

    try std.testing.expect(conn.internal_conn.?.peer_validated);
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
    try applyDefaultPeerTransportParams(&conn, allocator);

    try std.testing.expectError(types_mod.QuicError.StreamError, conn.openStream(false));
}

test "openStream requires negotiated handshake readiness" {
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

    try std.testing.expectError(types_mod.QuicError.ConnectionNotEstablished, conn.openStream(true));

    try applyDefaultPeerTransportParams(&conn, allocator);
    _ = try conn.openStream(true);
}

test "closeStream requires negotiated handshake readiness" {
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

    const stream_id = try conn.internal_conn.?.openStream(true);
    try std.testing.expectError(
        types_mod.QuicError.ConnectionNotEstablished,
        conn.closeStream(stream_id, 0),
    );

    try applyDefaultPeerTransportParams(&conn, allocator);
    try conn.closeStream(stream_id, 0);
}

test "applyPeerTransportParams rejects invalid peer parameters" {
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

    var encoded = transport_params_mod.TransportParams.init();
    encoded.max_udp_payload_size = 1199;
    const payload = try encoded.encode(allocator);
    defer allocator.free(payload);

    try std.testing.expectError(types_mod.QuicError.ProtocolViolation, conn.applyPeerTransportParams(payload));
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());

    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .closing);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(core_types.ErrorCode.transport_parameter_error)),
        event.?.closing.error_code,
    );
}

test "applyPeerTransportParams updates stream open limits" {
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

    var encoded = transport_params_mod.TransportParams.init();
    encoded.initial_max_streams_bidi = 1;
    encoded.initial_max_streams_uni = 0;
    const payload = try encoded.encode(allocator);
    defer allocator.free(payload);

    try conn.applyPeerTransportParams(payload);

    _ = try conn.openStream(true);
    try std.testing.expectError(types_mod.QuicError.StreamLimitReached, conn.openStream(true));
    try std.testing.expectError(types_mod.QuicError.StreamError, conn.openStream(false));
}

test "poll maps stream receive flow control violation to closing event" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    conn.internal_conn.?.streams.setLocalReceiveStreamDataLimits(4, 4, 4);

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();

    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [512]u8 = undefined;
    const header = packet_mod.ShortHeader{
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .packet_number = 21,
        .key_phase = false,
    };

    var packet_len = try header.encode(&packet_buf);
    const stream_frame = frame_mod.StreamFrame{
        .stream_id = 1,
        .offset = 0,
        .data = "12345",
        .fin = false,
    };
    packet_len += try stream_frame.encode(packet_buf[packet_len..]);

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    _ = conn.nextEvent(); // connected
    const event = conn.nextEvent();
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .closing);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(core_types.ErrorCode.flow_control_error)),
        event.?.closing.error_code,
    );
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "poll rejects stream frame in Initial packet space even when established" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

    conn.internal_conn.?.markEstablished();
    conn.state = .established;
    try applyDefaultPeerTransportParams(&conn, allocator);

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
        .packet_number = 22,
    };

    var packet_len = try header.encode(&packet_buf);
    const stream_frame = frame_mod.StreamFrame{
        .stream_id = 1,
        .offset = 0,
        .data = "abc",
        .fin = false,
    };
    packet_len += try stream_frame.encode(packet_buf[packet_len..]);

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    const first = conn.nextEvent();
    try std.testing.expect(first != null);
    const event = if (first.? == .connected) conn.nextEvent() else first;
    try std.testing.expect(event != null);
    try std.testing.expect(event.? == .closing);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(core_types.ErrorCode.protocol_violation)),
        event.?.closing.error_code,
    );
    try std.testing.expectEqual(types_mod.ConnectionState.draining, conn.getState());
}

test "poll rejects reserved frame type in Initial packet space" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

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
        .packet_number = 23,
    };
    var packet_len = try header.encode(&packet_buf);
    packet_buf[packet_len] = 0x1f; // reserved frame type
    packet_len += 1;

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    const first = conn.nextEvent();
    const second = conn.nextEvent();
    const first_is_closing = first != null and first.? == .closing;
    const second_is_closing = second != null and second.? == .closing;
    try std.testing.expect(first_is_closing or second_is_closing);

    const event = if (first_is_closing) first.? else second.?;
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(core_types.ErrorCode.protocol_violation)),
        event.closing.error_code,
    );
}

test "poll ignores unknown frame type in application packet space" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    conn.internal_conn.?.markEstablished();
    conn.state = .established;
    try applyDefaultPeerTransportParams(&conn, allocator);

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();
    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [256]u8 = undefined;
    const header = packet_mod.ShortHeader{
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .packet_number = 24,
        .key_phase = false,
    };
    var packet_len = try header.encode(&packet_buf);
    packet_buf[packet_len] = 0x2b; // unknown frame type
    packet_len += 1;

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    try std.testing.expect(conn.nextEvent() == null);
    try std.testing.expectEqual(types_mod.ConnectionState.established, conn.getState());
}

test "poll rejects HANDSHAKE_DONE frame in Initial packet space" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);

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
        .packet_number = 25,
    };
    var packet_len = try header.encode(&packet_buf);
    packet_buf[packet_len] = 0x1e; // HANDSHAKE_DONE
    packet_len += 1;

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    const first = conn.nextEvent();
    const second = conn.nextEvent();
    const closing = if (first != null and first.? == .closing)
        first
    else if (second != null and second.? == .closing)
        second
    else
        null;
    try std.testing.expect(closing != null);
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(core_types.ErrorCode.protocol_violation)),
        closing.?.closing.error_code,
    );
}

test "poll allows HANDSHAKE_DONE frame in application packet space" {
    const allocator = std.testing.allocator;

    const config = config_mod.QuicConfig.sshClient("127.0.0.1", "secret");
    var conn = try QuicConnection.init(allocator, config);
    defer conn.deinit();

    try conn.connect("127.0.0.1", 4433);
    conn.internal_conn.?.markEstablished();
    conn.state = .established;
    try applyDefaultPeerTransportParams(&conn, allocator);

    var sender = try udp_mod.UdpSocket.bindAny(allocator, 0);
    defer sender.close();
    const local_addr = try conn.socket.?.getLocalAddress();

    var packet_buf: [256]u8 = undefined;
    const header = packet_mod.ShortHeader{
        .dest_conn_id = conn.internal_conn.?.local_conn_id,
        .packet_number = 26,
        .key_phase = false,
    };
    var packet_len = try header.encode(&packet_buf);
    packet_buf[packet_len] = 0x1e; // HANDSHAKE_DONE
    packet_len += 1;

    _ = try sender.sendTo(packet_buf[0..packet_len], local_addr);
    try conn.poll();

    try std.testing.expect(conn.nextEvent() == null);
    try std.testing.expectEqual(types_mod.ConnectionState.established, conn.getState());
}
