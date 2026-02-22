const std = @import("std");
const types = @import("types.zig");
const varint = @import("../utils/varint.zig");

const FrameType = types.FrameType;
const StreamId = types.StreamId;
const ErrorCode = types.ErrorCode;
const ConnectionId = types.ConnectionId;

pub const FrameError = error{
    InvalidFrameType,
    UnexpectedEof,
    BufferTooSmall,
    InvalidStreamId,
    InvalidData,
} || varint.VarintError;

/// QUIC Frame - tagged union of all frame types
pub const Frame = union(enum) {
    padding: PaddingFrame,
    ping: PingFrame,
    ack: AckFrame,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    crypto: CryptoFrame,
    new_token: NewTokenFrame,
    stream: StreamFrame,
    max_data: MaxDataFrame,
    max_stream_data: MaxStreamDataFrame,
    max_streams: MaxStreamsFrame,
    data_blocked: DataBlockedFrame,
    stream_data_blocked: StreamDataBlockedFrame,
    streams_blocked: StreamsBlockedFrame,
    new_connection_id: NewConnectionIdFrame,
    retire_connection_id: RetireConnectionIdFrame,
    path_challenge: PathChallengeFrame,
    path_response: PathResponseFrame,
    connection_close: ConnectionCloseFrame,
    handshake_done: HandshakeDoneFrame,
};

/// PADDING frame (0x00)
pub const PaddingFrame = struct {};

/// PING frame (0x01)
pub const PingFrame = struct {
    pub fn decode(buf: []const u8) FrameError!struct { frame: PingFrame, consumed: usize } {
        const type_result = try varint.decode(buf);
        if (type_result.value != 0x01) return error.InvalidFrameType;
        return .{ .frame = PingFrame{}, .consumed = type_result.len };
    }
};

/// ACK frame (0x02-0x03)
pub const AckFrame = struct {
    largest_acked: u64,
    ack_delay: u64,
    first_ack_range: u64,
    ack_ranges: []const AckRange,
    ecn_counts: ?EcnCounts = null,

    pub const AckRange = struct {
        gap: u64,
        ack_range_length: u64,
    };

    pub const EcnCounts = struct {
        ect0_count: u64,
        ect1_count: u64,
        ecn_ce_count: u64,
    };

    pub fn encode(self: AckFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;

        // Frame type
        const frame_type: u64 = if (self.ecn_counts != null) 0x03 else 0x02;
        pos += try varint.encode(frame_type, buf[pos..]);

        // Largest Acknowledged
        pos += try varint.encode(self.largest_acked, buf[pos..]);

        // ACK Delay
        pos += try varint.encode(self.ack_delay, buf[pos..]);

        // ACK Range Count
        pos += try varint.encode(self.ack_ranges.len, buf[pos..]);

        // First ACK Range
        pos += try varint.encode(self.first_ack_range, buf[pos..]);

        // ACK Ranges
        for (self.ack_ranges) |range| {
            pos += try varint.encode(range.gap, buf[pos..]);
            pos += try varint.encode(range.ack_range_length, buf[pos..]);
        }

        // ECN Counts (if present)
        if (self.ecn_counts) |ecn| {
            pos += try varint.encode(ecn.ect0_count, buf[pos..]);
            pos += try varint.encode(ecn.ect1_count, buf[pos..]);
            pos += try varint.encode(ecn.ecn_ce_count, buf[pos..]);
        }

        return pos;
    }

    pub fn decode(buf: []const u8) FrameError!struct { frame: AckFrame, consumed: usize } {
        var pos: usize = 0;

        const type_result = try varint.decode(buf[pos..]);
        pos += type_result.len;

        const has_ecn = switch (type_result.value) {
            0x02 => false,
            0x03 => true,
            else => return error.InvalidFrameType,
        };

        const largest_acked_result = try varint.decode(buf[pos..]);
        pos += largest_acked_result.len;

        const ack_delay_result = try varint.decode(buf[pos..]);
        pos += ack_delay_result.len;

        const ack_range_count_result = try varint.decode(buf[pos..]);
        pos += ack_range_count_result.len;

        const first_ack_range_result = try varint.decode(buf[pos..]);
        pos += first_ack_range_result.len;

        // Decode and ignore additional ranges for now; not yet routed.
        var i: u64 = 0;
        while (i < ack_range_count_result.value) : (i += 1) {
            const gap_result = try varint.decode(buf[pos..]);
            pos += gap_result.len;
            const range_len_result = try varint.decode(buf[pos..]);
            pos += range_len_result.len;
        }

        var ecn_counts: ?EcnCounts = null;
        if (has_ecn) {
            const ect0_result = try varint.decode(buf[pos..]);
            pos += ect0_result.len;
            const ect1_result = try varint.decode(buf[pos..]);
            pos += ect1_result.len;
            const ce_result = try varint.decode(buf[pos..]);
            pos += ce_result.len;

            ecn_counts = EcnCounts{
                .ect0_count = ect0_result.value,
                .ect1_count = ect1_result.value,
                .ecn_ce_count = ce_result.value,
            };
        }

        return .{
            .frame = AckFrame{
                .largest_acked = largest_acked_result.value,
                .ack_delay = ack_delay_result.value,
                .first_ack_range = first_ack_range_result.value,
                .ack_ranges = &.{},
                .ecn_counts = ecn_counts,
            },
            .consumed = pos,
        };
    }
};

/// RESET_STREAM frame (0x04)
pub const ResetStreamFrame = struct {
    stream_id: StreamId,
    error_code: u64,
    final_size: u64,

    pub fn encode(self: ResetStreamFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x04, buf[pos..]);
        pos += try varint.encode(self.stream_id, buf[pos..]);
        pos += try varint.encode(self.error_code, buf[pos..]);
        pos += try varint.encode(self.final_size, buf[pos..]);
        return pos;
    }

    pub fn decode(buf: []const u8) FrameError!struct { frame: ResetStreamFrame, consumed: usize } {
        var pos: usize = 0;

        const type_result = try varint.decode(buf[pos..]);
        pos += type_result.len;
        if (type_result.value != 0x04) return error.InvalidFrameType;

        const stream_id_result = try varint.decode(buf[pos..]);
        pos += stream_id_result.len;

        const error_code_result = try varint.decode(buf[pos..]);
        pos += error_code_result.len;

        const final_size_result = try varint.decode(buf[pos..]);
        pos += final_size_result.len;

        return .{
            .frame = ResetStreamFrame{
                .stream_id = stream_id_result.value,
                .error_code = error_code_result.value,
                .final_size = final_size_result.value,
            },
            .consumed = pos,
        };
    }
};

/// STOP_SENDING frame (0x05)
pub const StopSendingFrame = struct {
    stream_id: StreamId,
    error_code: u64,

    pub fn encode(self: StopSendingFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x05, buf[pos..]);
        pos += try varint.encode(self.stream_id, buf[pos..]);
        pos += try varint.encode(self.error_code, buf[pos..]);
        return pos;
    }

    pub fn decode(buf: []const u8) FrameError!struct { frame: StopSendingFrame, consumed: usize } {
        var pos: usize = 0;

        const type_result = try varint.decode(buf[pos..]);
        pos += type_result.len;
        if (type_result.value != 0x05) return error.InvalidFrameType;

        const stream_id_result = try varint.decode(buf[pos..]);
        pos += stream_id_result.len;

        const error_code_result = try varint.decode(buf[pos..]);
        pos += error_code_result.len;

        return .{
            .frame = StopSendingFrame{
                .stream_id = stream_id_result.value,
                .error_code = error_code_result.value,
            },
            .consumed = pos,
        };
    }
};

/// CRYPTO frame (0x06)
pub const CryptoFrame = struct {
    offset: u64,
    data: []const u8,

    pub fn encode(self: CryptoFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x06, buf[pos..]);
        pos += try varint.encode(self.offset, buf[pos..]);
        pos += try varint.encode(self.data.len, buf[pos..]);
        if (pos + self.data.len > buf.len) return error.BufferTooSmall;
        @memcpy(buf[pos..][0..self.data.len], self.data);
        pos += self.data.len;
        return pos;
    }
};

/// NEW_TOKEN frame (0x07)
pub const NewTokenFrame = struct {
    token: []const u8,

    pub fn encode(self: NewTokenFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x07, buf[pos..]);
        pos += try varint.encode(self.token.len, buf[pos..]);
        if (pos + self.token.len > buf.len) return error.BufferTooSmall;
        @memcpy(buf[pos..][0..self.token.len], self.token);
        pos += self.token.len;
        return pos;
    }
};

/// STREAM frame (0x08-0x0f)
pub const StreamFrame = struct {
    stream_id: StreamId,
    offset: u64 = 0,
    data: []const u8,
    fin: bool = false,

    pub fn encode(self: StreamFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;

        // Frame type with flags
        // Bit 0: FIN
        // Bit 1: LEN (always set)
        // Bit 2: OFF (set if offset > 0)
        var frame_type: u64 = 0x08;
        if (self.fin) frame_type |= 0x01;
        frame_type |= 0x02; // Always include length
        if (self.offset > 0) frame_type |= 0x04;

        pos += try varint.encode(frame_type, buf[pos..]);
        pos += try varint.encode(self.stream_id, buf[pos..]);

        if (self.offset > 0) {
            pos += try varint.encode(self.offset, buf[pos..]);
        }

        pos += try varint.encode(self.data.len, buf[pos..]);
        if (pos + self.data.len > buf.len) return error.BufferTooSmall;
        @memcpy(buf[pos..][0..self.data.len], self.data);
        pos += self.data.len;

        return pos;
    }

    pub fn decode(buf: []const u8) FrameError!struct { frame: StreamFrame, consumed: usize } {
        var pos: usize = 0;

        // Frame type
        const frame_type_result = try varint.decode(buf[pos..]);
        pos += frame_type_result.len;
        const frame_type = frame_type_result.value;

        if (!FrameType.isStreamFrame(frame_type)) return error.InvalidFrameType;

        const fin = (frame_type & 0x01) != 0;
        const has_len = (frame_type & 0x02) != 0;
        const has_off = (frame_type & 0x04) != 0;

        // Stream ID
        const stream_id_result = try varint.decode(buf[pos..]);
        pos += stream_id_result.len;
        const stream_id = stream_id_result.value;

        // Offset (if present)
        var offset: u64 = 0;
        if (has_off) {
            const offset_result = try varint.decode(buf[pos..]);
            pos += offset_result.len;
            offset = offset_result.value;
        }

        // Length and data
        var data: []const u8 = undefined;
        if (has_len) {
            const len_result = try varint.decode(buf[pos..]);
            pos += len_result.len;
            const data_len = len_result.value;
            if (pos + data_len > buf.len) return error.UnexpectedEof;
            data = buf[pos..][0..data_len];
            pos += data_len;
        } else {
            // Data extends to end of packet
            data = buf[pos..];
            pos = buf.len;
        }

        return .{
            .frame = StreamFrame{
                .stream_id = stream_id,
                .offset = offset,
                .data = data,
                .fin = fin,
            },
            .consumed = pos,
        };
    }
};

/// MAX_DATA frame (0x10)
pub const MaxDataFrame = struct {
    max_data: u64,

    pub fn encode(self: MaxDataFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x10, buf[pos..]);
        pos += try varint.encode(self.max_data, buf[pos..]);
        return pos;
    }
};

/// MAX_STREAM_DATA frame (0x11)
pub const MaxStreamDataFrame = struct {
    stream_id: StreamId,
    max_stream_data: u64,

    pub fn encode(self: MaxStreamDataFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x11, buf[pos..]);
        pos += try varint.encode(self.stream_id, buf[pos..]);
        pos += try varint.encode(self.max_stream_data, buf[pos..]);
        return pos;
    }
};

/// MAX_STREAMS frame (0x12-0x13)
pub const MaxStreamsFrame = struct {
    max_streams: u64,
    bidirectional: bool,

    pub fn encode(self: MaxStreamsFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        const frame_type: u64 = if (self.bidirectional) 0x12 else 0x13;
        pos += try varint.encode(frame_type, buf[pos..]);
        pos += try varint.encode(self.max_streams, buf[pos..]);
        return pos;
    }
};

/// DATA_BLOCKED frame (0x14)
pub const DataBlockedFrame = struct {
    max_data: u64,

    pub fn encode(self: DataBlockedFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x14, buf[pos..]);
        pos += try varint.encode(self.max_data, buf[pos..]);
        return pos;
    }
};

/// STREAM_DATA_BLOCKED frame (0x15)
pub const StreamDataBlockedFrame = struct {
    stream_id: StreamId,
    max_stream_data: u64,

    pub fn encode(self: StreamDataBlockedFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x15, buf[pos..]);
        pos += try varint.encode(self.stream_id, buf[pos..]);
        pos += try varint.encode(self.max_stream_data, buf[pos..]);
        return pos;
    }
};

/// STREAMS_BLOCKED frame (0x16-0x17)
pub const StreamsBlockedFrame = struct {
    max_streams: u64,
    bidirectional: bool,

    pub fn encode(self: StreamsBlockedFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        const frame_type: u64 = if (self.bidirectional) 0x16 else 0x17;
        pos += try varint.encode(frame_type, buf[pos..]);
        pos += try varint.encode(self.max_streams, buf[pos..]);
        return pos;
    }
};

/// NEW_CONNECTION_ID frame (0x18)
pub const NewConnectionIdFrame = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: ConnectionId,
    stateless_reset_token: [16]u8,

    pub fn encode(self: NewConnectionIdFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x18, buf[pos..]);
        pos += try varint.encode(self.sequence_number, buf[pos..]);
        pos += try varint.encode(self.retire_prior_to, buf[pos..]);

        if (pos + 1 + self.connection_id.len + 16 > buf.len) return error.BufferTooSmall;
        buf[pos] = self.connection_id.len;
        pos += 1;
        @memcpy(buf[pos..][0..self.connection_id.len], self.connection_id.slice());
        pos += self.connection_id.len;
        @memcpy(buf[pos..][0..16], &self.stateless_reset_token);
        pos += 16;

        return pos;
    }
};

/// RETIRE_CONNECTION_ID frame (0x19)
pub const RetireConnectionIdFrame = struct {
    sequence_number: u64,

    pub fn encode(self: RetireConnectionIdFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        pos += try varint.encode(0x19, buf[pos..]);
        pos += try varint.encode(self.sequence_number, buf[pos..]);
        return pos;
    }
};

/// PATH_CHALLENGE frame (0x1a)
pub const PathChallengeFrame = struct {
    data: [8]u8,

    pub fn encode(self: PathChallengeFrame, buf: []u8) FrameError!usize {
        if (buf.len < 9) return error.BufferTooSmall;
        var pos: usize = 0;
        pos += try varint.encode(0x1a, buf[pos..]);
        @memcpy(buf[pos..][0..8], &self.data);
        pos += 8;
        return pos;
    }
};

/// PATH_RESPONSE frame (0x1b)
pub const PathResponseFrame = struct {
    data: [8]u8,

    pub fn encode(self: PathResponseFrame, buf: []u8) FrameError!usize {
        if (buf.len < 9) return error.BufferTooSmall;
        var pos: usize = 0;
        pos += try varint.encode(0x1b, buf[pos..]);
        @memcpy(buf[pos..][0..8], &self.data);
        pos += 8;
        return pos;
    }
};

/// CONNECTION_CLOSE frame (0x1c-0x1d)
pub const ConnectionCloseFrame = struct {
    error_code: u64,
    frame_type: ?u64 = null, // Only for 0x1c (transport error)
    reason: []const u8,

    pub fn encode(self: ConnectionCloseFrame, buf: []u8) FrameError!usize {
        var pos: usize = 0;
        const type_byte: u64 = if (self.frame_type != null) 0x1c else 0x1d;
        pos += try varint.encode(type_byte, buf[pos..]);
        pos += try varint.encode(self.error_code, buf[pos..]);

        if (self.frame_type) |ft| {
            pos += try varint.encode(ft, buf[pos..]);
        }

        pos += try varint.encode(self.reason.len, buf[pos..]);
        if (pos + self.reason.len > buf.len) return error.BufferTooSmall;
        @memcpy(buf[pos..][0..self.reason.len], self.reason);
        pos += self.reason.len;

        return pos;
    }

    pub fn decode(buf: []const u8) FrameError!struct { frame: ConnectionCloseFrame, consumed: usize } {
        var pos: usize = 0;

        const type_result = try varint.decode(buf[pos..]);
        pos += type_result.len;

        const is_transport_close = switch (type_result.value) {
            0x1c => true,
            0x1d => false,
            else => return error.InvalidFrameType,
        };

        const error_code_result = try varint.decode(buf[pos..]);
        pos += error_code_result.len;

        var frame_type: ?u64 = null;
        if (is_transport_close) {
            const frame_type_result = try varint.decode(buf[pos..]);
            pos += frame_type_result.len;
            frame_type = frame_type_result.value;
        }

        const reason_len_result = try varint.decode(buf[pos..]);
        pos += reason_len_result.len;

        const reason_len = reason_len_result.value;
        if (pos + reason_len > buf.len) return error.UnexpectedEof;

        const reason = buf[pos..][0..reason_len];
        pos += reason_len;

        return .{
            .frame = ConnectionCloseFrame{
                .error_code = error_code_result.value,
                .frame_type = frame_type,
                .reason = reason,
            },
            .consumed = pos,
        };
    }
};

/// HANDSHAKE_DONE frame (0x1e)
pub const HandshakeDoneFrame = struct {
    pub fn encode(_: HandshakeDoneFrame, buf: []u8) FrameError!usize {
        return try varint.encode(0x1e, buf);
    }
};

// Tests

test "stream frame encode/decode" {
    const allocator = std.testing.allocator;
    const buf = try allocator.alloc(u8, 1024);
    defer allocator.free(buf);

    const test_data = "Hello, QUIC!";
    const frame = StreamFrame{
        .stream_id = 4,
        .offset = 100,
        .data = test_data,
        .fin = true,
    };

    const encoded_len = try frame.encode(buf);
    try std.testing.expect(encoded_len > 0);

    const result = try StreamFrame.decode(buf[0..encoded_len]);
    try std.testing.expectEqual(@as(u64, 4), result.frame.stream_id);
    try std.testing.expectEqual(@as(u64, 100), result.frame.offset);
    try std.testing.expect(result.frame.fin);
    try std.testing.expectEqualStrings(test_data, result.frame.data);
}

test "crypto frame encode" {
    var buf: [100]u8 = undefined;
    const test_data = "crypto data";
    const frame = CryptoFrame{
        .offset = 0,
        .data = test_data,
    };

    const encoded_len = try frame.encode(&buf);
    try std.testing.expect(encoded_len > 0);
}

test "ack frame encode" {
    const allocator = std.testing.allocator;
    const buf = try allocator.alloc(u8, 1024);
    defer allocator.free(buf);

    const frame = AckFrame{
        .largest_acked = 100,
        .ack_delay = 5,
        .first_ack_range = 10,
        .ack_ranges = &.{},
        .ecn_counts = null,
    };

    const encoded_len = try frame.encode(buf);
    try std.testing.expect(encoded_len > 0);

    const decoded = try AckFrame.decode(buf[0..encoded_len]);
    try std.testing.expectEqual(frame.largest_acked, decoded.frame.largest_acked);
}

test "connection close frame encode" {
    var buf: [100]u8 = undefined;
    const frame = ConnectionCloseFrame{
        .error_code = 0,
        .frame_type = null,
        .reason = "goodbye",
    };

    const encoded_len = try frame.encode(&buf);
    try std.testing.expect(encoded_len > 0);

    const decoded = try ConnectionCloseFrame.decode(buf[0..encoded_len]);
    try std.testing.expectEqual(frame.error_code, decoded.frame.error_code);
    try std.testing.expectEqualStrings(frame.reason, decoded.frame.reason);
}

test "reset stream frame encode/decode" {
    var buf: [100]u8 = undefined;
    const frame = ResetStreamFrame{
        .stream_id = 8,
        .error_code = 42,
        .final_size = 12,
    };

    const encoded_len = try frame.encode(&buf);
    const decoded = try ResetStreamFrame.decode(buf[0..encoded_len]);
    try std.testing.expectEqual(frame.stream_id, decoded.frame.stream_id);
    try std.testing.expectEqual(frame.error_code, decoded.frame.error_code);
    try std.testing.expectEqual(frame.final_size, decoded.frame.final_size);
}

test "stop sending frame encode/decode" {
    var buf: [100]u8 = undefined;
    const frame = StopSendingFrame{
        .stream_id = 9,
        .error_code = 7,
    };

    const encoded_len = try frame.encode(&buf);
    const decoded = try StopSendingFrame.decode(buf[0..encoded_len]);
    try std.testing.expectEqual(frame.stream_id, decoded.frame.stream_id);
    try std.testing.expectEqual(frame.error_code, decoded.frame.error_code);
}

test "ping frame decode" {
    var buf: [8]u8 = undefined;
    const len = try varint.encode(0x01, &buf);

    const decoded = try PingFrame.decode(buf[0..len]);
    _ = decoded.frame;
    try std.testing.expectEqual(len, decoded.consumed);
}
