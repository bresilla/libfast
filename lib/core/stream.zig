const std = @import("std");
const types = @import("types.zig");

const StreamId = types.StreamId;
const StreamType = types.StreamType;
const StreamSendState = types.StreamSendState;
const StreamRecvState = types.StreamRecvState;

/// QUIC Stream
pub const Stream = struct {
    id: StreamId,
    send_state: StreamSendState,
    recv_state: StreamRecvState,
    send_offset: u64,
    recv_offset: u64,
    max_stream_data_local: u64,
    max_stream_data_remote: u64,
    send_buffer: std.ArrayList(u8),
    recv_buffer: std.ArrayList(u8),
    fin_sent: bool,
    fin_received: bool,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, id: StreamId, max_stream_data: u64) Stream {
        return Stream{
            .id = id,
            .send_state = .ready,
            .recv_state = .recv,
            .send_offset = 0,
            .recv_offset = 0,
            .max_stream_data_local = max_stream_data,
            .max_stream_data_remote = max_stream_data,
            .send_buffer = .{},
            .recv_buffer = .{},
            .fin_sent = false,
            .fin_received = false,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.send_buffer.deinit(self.allocator);
        self.recv_buffer.deinit(self.allocator);
    }

    /// Get stream type from stream ID
    pub fn getType(self: Stream) StreamType {
        return StreamType.fromStreamId(self.id);
    }

    /// Check if stream is bidirectional
    pub fn isBidirectional(self: Stream) bool {
        return self.getType().isBidirectional();
    }

    /// Check if stream is unidirectional
    pub fn isUnidirectional(self: Stream) bool {
        return self.getType().isUnidirectional();
    }

    /// Check if stream was initiated by client
    pub fn isClientInitiated(self: Stream) bool {
        return self.getType().isClientInitiated();
    }

    /// Check if stream was initiated by server
    pub fn isServerInitiated(self: Stream) bool {
        return self.getType().isServerInitiated();
    }

    /// Write data to send buffer
    pub fn write(self: *Stream, data: []const u8) !usize {
        if (self.send_state != .ready and self.send_state != .send) {
            return error.StreamNotWritable;
        }

        // Check flow control
        if (self.send_offset + data.len > self.max_stream_data_remote) {
            // Write as much as we can
            const available = self.max_stream_data_remote - self.send_offset;
            if (available == 0) return error.StreamBlocked;
            try self.send_buffer.appendSlice(self.allocator, data[0..available]);
            self.send_state = .send;
            return available;
        }

        try self.send_buffer.appendSlice(self.allocator, data);
        self.send_state = .send;
        return data.len;
    }

    /// Read data from receive buffer
    pub fn read(self: *Stream, buf: []u8) !usize {
        if (self.recv_state != .recv and self.recv_state != .size_known) {
            return error.StreamNotReadable;
        }

        const available = @min(buf.len, self.recv_buffer.items.len);
        if (available == 0) {
            if (self.fin_received and self.recv_state == .size_known) {
                self.recv_state = .data_recvd;
                return 0; // EOF
            }
            return error.WouldBlock;
        }

        @memcpy(buf[0..available], self.recv_buffer.items[0..available]);

        // Remove read data from buffer
        std.mem.copyForwards(u8, self.recv_buffer.items, self.recv_buffer.items[available..]);
        try self.recv_buffer.resize(self.allocator, self.recv_buffer.items.len - available);

        self.recv_offset += available;

        if (self.recv_buffer.items.len == 0 and self.fin_received) {
            self.recv_state = .data_read;
        }

        return available;
    }

    /// Append received data to receive buffer
    pub fn appendRecvData(self: *Stream, data: []const u8, offset: u64, fin: bool) !void {
        if (self.recv_state != .recv and self.recv_state != .size_known) {
            return error.StreamClosed;
        }

        // Enforce in-order delivery (out-of-order packets trigger retransmission)
        // This is simpler than buffering out-of-order data and achieves the same goal
        if (offset != self.recv_offset) {
            return error.OutOfOrderData;
        }

        if (offset + data.len > self.max_stream_data_local) {
            return error.FlowControlError;
        }

        try self.recv_buffer.appendSlice(self.allocator, data);
        self.recv_offset += data.len;

        if (fin) {
            self.fin_received = true;
            self.recv_state = .size_known;
        }
    }

    /// Get data to send (up to max_len bytes)
    pub fn getSendData(self: *Stream, max_len: usize) []const u8 {
        const available = @min(max_len, self.send_buffer.items.len);
        return self.send_buffer.items[0..available];
    }

    /// Mark data as sent and remove from send buffer
    pub fn markSent(self: *Stream, len: usize) !void {
        if (len > self.send_buffer.items.len) {
            return error.InvalidLength;
        }

        std.mem.copyForwards(u8, self.send_buffer.items, self.send_buffer.items[len..]);
        try self.send_buffer.resize(self.allocator, self.send_buffer.items.len - len);
        self.send_offset += len;

        if (self.send_buffer.items.len == 0 and self.fin_sent) {
            self.send_state = .data_sent;
        }
    }

    /// Mark stream as finished (FIN)
    pub fn finish(self: *Stream) void {
        self.fin_sent = true;
        if (self.send_buffer.items.len == 0) {
            self.send_state = .data_sent;
        }
    }

    /// Reset stream with error code
    pub fn reset(self: *Stream, _: u64) void {
        self.send_state = .reset_sent;
    }

    /// Check if stream has data to send
    pub fn hasSendData(self: Stream) bool {
        return self.send_buffer.items.len > 0 or (self.fin_sent and self.send_state == .send);
    }

    /// Check if stream is closed
    pub fn isClosed(self: Stream) bool {
        const send_closed = switch (self.send_state) {
            .data_sent, .reset_sent, .reset_recvd => true,
            else => false,
        };

        const recv_closed = switch (self.recv_state) {
            .data_read, .reset_read => true,
            else => false,
        };

        return send_closed and recv_closed;
    }
};

/// Stream manager
pub const StreamManager = struct {
    streams: std.AutoHashMap(StreamId, Stream),
    next_client_bidi: StreamId,
    next_client_uni: StreamId,
    next_server_bidi: StreamId,
    next_server_uni: StreamId,
    max_local_streams_bidi: u64,
    max_local_streams_uni: u64,
    local_opened_bidi: u64,
    local_opened_uni: u64,
    local_max_stream_data_bidi_local: u64,
    local_max_stream_data_bidi_remote: u64,
    local_max_stream_data_uni: u64,
    remote_max_stream_data_bidi_local: u64,
    remote_max_stream_data_bidi_remote: u64,
    remote_max_stream_data_uni: u64,
    max_stream_data: u64,
    allocator: std.mem.Allocator,
    is_server: bool,

    pub fn init(allocator: std.mem.Allocator, is_server: bool, max_stream_data: u64) StreamManager {
        return StreamManager{
            .streams = std.AutoHashMap(StreamId, Stream).init(allocator),
            .next_client_bidi = 0,
            .next_client_uni = 2,
            .next_server_bidi = 1,
            .next_server_uni = 3,
            .max_local_streams_bidi = 100,
            .max_local_streams_uni = 100,
            .local_opened_bidi = 0,
            .local_opened_uni = 0,
            .local_max_stream_data_bidi_local = max_stream_data,
            .local_max_stream_data_bidi_remote = max_stream_data,
            .local_max_stream_data_uni = max_stream_data,
            .remote_max_stream_data_bidi_local = max_stream_data,
            .remote_max_stream_data_bidi_remote = max_stream_data,
            .remote_max_stream_data_uni = max_stream_data,
            .max_stream_data = max_stream_data,
            .allocator = allocator,
            .is_server = is_server,
        };
    }

    pub fn setLocalOpenLimits(self: *StreamManager, max_streams_bidi: u64, max_streams_uni: u64) void {
        self.max_local_streams_bidi = max_streams_bidi;
        self.max_local_streams_uni = max_streams_uni;
    }

    pub fn onMaxStreams(self: *StreamManager, bidirectional: bool, max_streams: u64) void {
        if (bidirectional) {
            if (max_streams > self.max_local_streams_bidi) {
                self.max_local_streams_bidi = max_streams;
            }
            return;
        }

        if (max_streams > self.max_local_streams_uni) {
            self.max_local_streams_uni = max_streams;
        }
    }

    pub fn onMaxStreamData(self: *StreamManager, stream_id: StreamId, max_stream_data: u64) void {
        const stream = self.streams.getPtr(stream_id) orelse return;
        if (max_stream_data > stream.max_stream_data_remote) {
            stream.max_stream_data_remote = max_stream_data;
        }
    }

    pub fn setRemoteStreamDataLimits(self: *StreamManager, bidi_local: u64, bidi_remote: u64, uni: u64) void {
        self.remote_max_stream_data_bidi_local = bidi_local;
        self.remote_max_stream_data_bidi_remote = bidi_remote;
        self.remote_max_stream_data_uni = uni;

        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.max_stream_data_remote = self.sendLimitForStream(entry.key_ptr.*);
        }
    }

    pub fn setLocalReceiveStreamDataLimits(self: *StreamManager, bidi_local: u64, bidi_remote: u64, uni: u64) void {
        self.local_max_stream_data_bidi_local = bidi_local;
        self.local_max_stream_data_bidi_remote = bidi_remote;
        self.local_max_stream_data_uni = uni;

        var it = self.streams.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.max_stream_data_local = self.receiveLimitForStream(entry.key_ptr.*);
        }
    }

    fn isLocallyInitiated(self: StreamManager, stream_type: StreamType) bool {
        return if (self.is_server) stream_type.isServerInitiated() else stream_type.isClientInitiated();
    }

    fn sendLimitForStreamType(self: StreamManager, stream_type: StreamType) u64 {
        if (stream_type.isBidirectional()) {
            if (self.isLocallyInitiated(stream_type)) {
                return self.remote_max_stream_data_bidi_remote;
            }
            return self.remote_max_stream_data_bidi_local;
        }

        if (self.isLocallyInitiated(stream_type)) {
            return self.remote_max_stream_data_uni;
        }

        return 0;
    }

    fn sendLimitForStream(self: StreamManager, stream_id: StreamId) u64 {
        return self.sendLimitForStreamType(StreamType.fromStreamId(stream_id));
    }

    fn receiveLimitForStreamType(self: StreamManager, stream_type: StreamType) u64 {
        if (stream_type.isBidirectional()) {
            if (self.isLocallyInitiated(stream_type)) {
                return self.local_max_stream_data_bidi_local;
            }
            return self.local_max_stream_data_bidi_remote;
        }

        if (self.isLocallyInitiated(stream_type)) {
            return 0;
        }

        return self.local_max_stream_data_uni;
    }

    fn receiveLimitForStream(self: StreamManager, stream_id: StreamId) u64 {
        return self.receiveLimitForStreamType(StreamType.fromStreamId(stream_id));
    }

    pub fn deinit(self: *StreamManager) void {
        var it = self.streams.valueIterator();
        while (it.next()) |stream| {
            stream.deinit();
        }
        self.streams.deinit();
    }

    /// Create a new stream
    pub fn createStream(self: *StreamManager, stream_type: StreamType) !StreamId {
        if (stream_type.isBidirectional()) {
            if (self.local_opened_bidi >= self.max_local_streams_bidi) {
                return error.StreamLimitReached;
            }
        } else {
            if (self.local_opened_uni >= self.max_local_streams_uni) {
                return error.StreamLimitReached;
            }
        }

        const stream_id = switch (stream_type) {
            .client_bidi => blk: {
                if (self.is_server) return error.InvalidStreamType;
                const id = self.next_client_bidi;
                self.next_client_bidi += 4;
                break :blk id;
            },
            .server_bidi => blk: {
                if (!self.is_server) return error.InvalidStreamType;
                const id = self.next_server_bidi;
                self.next_server_bidi += 4;
                break :blk id;
            },
            .client_uni => blk: {
                if (self.is_server) return error.InvalidStreamType;
                const id = self.next_client_uni;
                self.next_client_uni += 4;
                break :blk id;
            },
            .server_uni => blk: {
                if (!self.is_server) return error.InvalidStreamType;
                const id = self.next_server_uni;
                self.next_server_uni += 4;
                break :blk id;
            },
        };

        var stream = Stream.init(self.allocator, stream_id, self.max_stream_data);
        stream.max_stream_data_remote = self.sendLimitForStream(stream_id);
        stream.max_stream_data_local = self.receiveLimitForStream(stream_id);
        try self.streams.put(stream_id, stream);

        if (stream_type.isBidirectional()) {
            self.local_opened_bidi += 1;
        } else {
            self.local_opened_uni += 1;
        }

        return stream_id;
    }

    /// Get stream by ID
    pub fn getStream(self: *StreamManager, stream_id: StreamId) ?*Stream {
        return self.streams.getPtr(stream_id);
    }

    /// Get or create stream by ID
    pub fn getOrCreateStream(self: *StreamManager, stream_id: StreamId) !*Stream {
        if (self.streams.getPtr(stream_id)) |stream| {
            return stream;
        }

        var stream = Stream.init(self.allocator, stream_id, self.max_stream_data);
        stream.max_stream_data_remote = self.sendLimitForStream(stream_id);
        stream.max_stream_data_local = self.receiveLimitForStream(stream_id);
        try self.streams.put(stream_id, stream);
        return self.streams.getPtr(stream_id).?;
    }

    /// Remove closed streams
    pub fn removeClosedStreams(self: *StreamManager) !void {
        var to_remove = std.ArrayList(StreamId).init(self.allocator);
        defer to_remove.deinit();

        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.isClosed()) {
                try to_remove.append(entry.key_ptr.*);
            }
        }

        for (to_remove.items) |stream_id| {
            if (self.streams.fetchRemove(stream_id)) |kv| {
                var stream = kv.value;
                stream.deinit();
            }
        }
    }
};

// Tests

test "stream creation and type checking" {
    const allocator = std.testing.allocator;

    var stream = Stream.init(allocator, 0, 1024);
    defer stream.deinit();

    try std.testing.expectEqual(@as(u64, 0), stream.id);
    try std.testing.expect(stream.getType() == .client_bidi);
    try std.testing.expect(stream.isBidirectional());
    try std.testing.expect(stream.isClientInitiated());
}

test "stream write and read" {
    const allocator = std.testing.allocator;

    var stream = Stream.init(allocator, 0, 1024);
    defer stream.deinit();

    const test_data = "Hello, QUIC!";
    const written = try stream.write(test_data);
    try std.testing.expectEqual(test_data.len, written);

    // Simulate receiving the data
    try stream.appendRecvData(test_data, 0, false);

    var read_buf: [100]u8 = undefined;
    const read_len = try stream.read(&read_buf);
    try std.testing.expectEqual(test_data.len, read_len);
    try std.testing.expectEqualStrings(test_data, read_buf[0..read_len]);
}

test "stream manager" {
    const allocator = std.testing.allocator;

    var manager = StreamManager.init(allocator, false, 1024);
    defer manager.deinit();

    const stream_id = try manager.createStream(.client_bidi);
    try std.testing.expectEqual(@as(u64, 0), stream_id);

    const stream = manager.getStream(stream_id).?;
    try std.testing.expectEqual(stream_id, stream.id);
}

test "stream manager enforces local stream limits" {
    const allocator = std.testing.allocator;

    var manager = StreamManager.init(allocator, false, 1024);
    defer manager.deinit();

    manager.setLocalOpenLimits(1, 0);

    _ = try manager.createStream(.client_bidi);
    try std.testing.expectError(error.StreamLimitReached, manager.createStream(.client_bidi));
    try std.testing.expectError(error.StreamLimitReached, manager.createStream(.client_uni));
}

test "stream manager applies MAX_STREAMS updates monotonically" {
    const allocator = std.testing.allocator;

    var manager = StreamManager.init(allocator, false, 1024);
    defer manager.deinit();

    manager.setLocalOpenLimits(1, 1);
    manager.onMaxStreams(true, 0);
    try std.testing.expectEqual(@as(u64, 1), manager.max_local_streams_bidi);

    manager.onMaxStreams(true, 3);
    try std.testing.expectEqual(@as(u64, 3), manager.max_local_streams_bidi);

    manager.onMaxStreams(false, 2);
    try std.testing.expectEqual(@as(u64, 2), manager.max_local_streams_uni);
}

test "stream manager applies MAX_STREAM_DATA updates monotonically" {
    const allocator = std.testing.allocator;

    var manager = StreamManager.init(allocator, false, 1024);
    defer manager.deinit();

    const stream_id = try manager.createStream(.client_bidi);
    const before = manager.getStream(stream_id).?.max_stream_data_remote;

    manager.onMaxStreamData(stream_id, before - 1);
    try std.testing.expectEqual(before, manager.getStream(stream_id).?.max_stream_data_remote);

    manager.onMaxStreamData(stream_id, before + 4096);
    try std.testing.expectEqual(before + 4096, manager.getStream(stream_id).?.max_stream_data_remote);
}

test "stream manager applies remote send limits by stream type" {
    const allocator = std.testing.allocator;

    var manager = StreamManager.init(allocator, false, 1024);
    defer manager.deinit();

    manager.setRemoteStreamDataLimits(333, 111, 22);

    const client_bidi = try manager.createStream(.client_bidi);
    const client_uni = try manager.createStream(.client_uni);
    const server_bidi = try manager.getOrCreateStream(1);
    const server_uni = try manager.getOrCreateStream(3);

    try std.testing.expectEqual(@as(u64, 111), manager.getStream(client_bidi).?.max_stream_data_remote);
    try std.testing.expectEqual(@as(u64, 22), manager.getStream(client_uni).?.max_stream_data_remote);
    try std.testing.expectEqual(@as(u64, 333), server_bidi.max_stream_data_remote);
    try std.testing.expectEqual(@as(u64, 0), server_uni.max_stream_data_remote);
}

test "stream manager applies local receive limits by stream type" {
    const allocator = std.testing.allocator;

    var manager = StreamManager.init(allocator, false, 1024);
    defer manager.deinit();

    manager.setLocalReceiveStreamDataLimits(700, 500, 300);

    const client_bidi = try manager.createStream(.client_bidi);
    const client_uni = try manager.createStream(.client_uni);
    const server_bidi = try manager.getOrCreateStream(1);
    const server_uni = try manager.getOrCreateStream(3);

    try std.testing.expectEqual(@as(u64, 700), manager.getStream(client_bidi).?.max_stream_data_local);
    try std.testing.expectEqual(@as(u64, 0), manager.getStream(client_uni).?.max_stream_data_local);
    try std.testing.expectEqual(@as(u64, 500), server_bidi.max_stream_data_local);
    try std.testing.expectEqual(@as(u64, 300), server_uni.max_stream_data_local);
}

test "stream receive flow control enforces local max data" {
    const allocator = std.testing.allocator;

    var stream = Stream.init(allocator, 0, 4);
    defer stream.deinit();

    try stream.appendRecvData("1234", 0, false);
    try std.testing.expectError(error.FlowControlError, stream.appendRecvData("5", 4, false));
}

test "stream flow control" {
    const allocator = std.testing.allocator;

    var stream = Stream.init(allocator, 0, 10); // Small limit
    defer stream.deinit();

    const large_data = "This is more than 10 bytes of data";
    const written = try stream.write(large_data);
    try std.testing.expectEqual(@as(usize, 10), written); // Should only write 10 bytes
}
