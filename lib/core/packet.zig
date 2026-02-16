const std = @import("std");
const types = @import("types.zig");
const varint = @import("../utils/varint.zig");

const ConnectionId = types.ConnectionId;
const PacketType = types.PacketType;
const PacketHeader = types.PacketHeader;
const PacketNumber = types.PacketNumber;

pub const PacketError = error{
    InvalidPacketType,
    InvalidVersion,
    BufferTooSmall,
    UnexpectedEof,
    InvalidPacketNumber,
    ConnectionIdTooLong,
} || varint.VarintError;

/// Packet number encoding/decoding
pub const PacketNumberUtil = struct {
    /// Encode packet number with truncation
    /// Only encodes the least significant bytes needed
    pub fn encode(pn: PacketNumber, largest_acked: PacketNumber, buf: []u8) PacketError!u8 {
        const pn_range = if (pn > largest_acked) pn - largest_acked else 0;

        // Determine number of bytes needed
        const num_bytes: u8 = if (pn_range < 0x80)
            1
        else if (pn_range < 0x8000)
            2
        else if (pn_range < 0x800000)
            3
        else
            4;

        if (buf.len < num_bytes) return error.BufferTooSmall;

        switch (num_bytes) {
            1 => {
                buf[0] = @intCast(pn & 0xFF);
                return 1;
            },
            2 => {
                std.mem.writeInt(u16, buf[0..2], @intCast(pn & 0xFFFF), .big);
                return 2;
            },
            3 => {
                buf[0] = @intCast((pn >> 16) & 0xFF);
                std.mem.writeInt(u16, buf[1..3], @intCast(pn & 0xFFFF), .big);
                return 3;
            },
            4 => {
                std.mem.writeInt(u32, buf[0..4], @intCast(pn & 0xFFFFFFFF), .big);
                return 4;
            },
            else => unreachable,
        }
    }

    /// Decode truncated packet number
    pub fn decode(truncated: []const u8, largest_acked: PacketNumber) PacketError!PacketNumber {
        if (truncated.len == 0 or truncated.len > 4) return error.InvalidPacketNumber;

        const truncated_pn: u64 = switch (truncated.len) {
            1 => truncated[0],
            2 => std.mem.readInt(u16, truncated[0..2], .big),
            3 => blk: {
                const high: u64 = truncated[0];
                const low = std.mem.readInt(u16, truncated[1..3], .big);
                break :blk (high << 16) | low;
            },
            4 => std.mem.readInt(u32, truncated[0..4], .big),
            else => unreachable,
        };

        // Reconstruct full packet number
        const pn_nbits: u6 = @intCast(truncated.len * 8);
        const pn_win: u64 = @as(u64, 1) << pn_nbits;
        const pn_hwin = pn_win / 2;
        const pn_mask = pn_win - 1;

        const expected_pn = largest_acked + 1;
        const candidate = (expected_pn & ~pn_mask) | truncated_pn;

        if (candidate + pn_hwin <= expected_pn) {
            return candidate + pn_win;
        } else if (candidate > expected_pn + pn_hwin and candidate >= pn_win) {
            return candidate - pn_win;
        }
        return candidate;
    }
};

/// Long Header packet format (RFC 9000, Section 17.2)
pub const LongHeader = struct {
    packet_type: PacketType,
    version: u32,
    dest_conn_id: ConnectionId,
    src_conn_id: ConnectionId,
    token: []const u8, // For Initial packets
    payload_len: u64, // Length of packet number + payload
    packet_number: PacketNumber,

    /// Encode Long Header packet
    pub fn encode(self: LongHeader, buf: []u8) PacketError!usize {
        var pos: usize = 0;

        if (buf.len < 7) return error.BufferTooSmall; // Minimum size

        // First byte: packet type and fixed bit
        const type_bits: u8 = switch (self.packet_type) {
            .initial => 0b00,
            .zero_rtt => 0b01,
            .handshake => 0b10,
            .retry => 0b11,
            else => return error.InvalidPacketType,
        };

        // Long Header: 1xxx xxxx (first bit = 1, fixed bit = 1)
        // Format: 11TT LLLL where TT = type, LLLL = packet number length - 1
        const first_byte = 0b11000000 | (type_bits << 4);
        buf[pos] = first_byte; // We'll update packet number length later
        pos += 1;

        // Version (4 bytes)
        if (pos + 4 > buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u32, buf[pos..][0..4], self.version, .big);
        pos += 4;

        // Destination Connection ID
        if (pos + 1 + self.dest_conn_id.len > buf.len) return error.BufferTooSmall;
        buf[pos] = self.dest_conn_id.len;
        pos += 1;
        @memcpy(buf[pos..][0..self.dest_conn_id.len], self.dest_conn_id.slice());
        pos += self.dest_conn_id.len;

        // Source Connection ID
        if (pos + 1 + self.src_conn_id.len > buf.len) return error.BufferTooSmall;
        buf[pos] = self.src_conn_id.len;
        pos += 1;
        @memcpy(buf[pos..][0..self.src_conn_id.len], self.src_conn_id.slice());
        pos += self.src_conn_id.len;

        // Token (for Initial packets)
        if (self.packet_type == .initial) {
            const token_len = try varint.encode(self.token.len, buf[pos..]);
            pos += token_len;
            if (pos + self.token.len > buf.len) return error.BufferTooSmall;
            @memcpy(buf[pos..][0..self.token.len], self.token);
            pos += self.token.len;
        }

        // Payload length (includes packet number + payload)
        const payload_len_size = try varint.encode(self.payload_len, buf[pos..]);
        pos += payload_len_size;

        // Packet number (placeholder for now, will be encoded with proper length)
        // For now, encode as 4 bytes (maximum)
        if (pos + 4 > buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u32, buf[pos..][0..4], @intCast(self.packet_number & 0xFFFFFFFF), .big);
        pos += 4;

        return pos;
    }

    /// Decode Long Header packet
    pub fn decode(buf: []const u8) PacketError!struct { header: LongHeader, consumed: usize } {
        var pos: usize = 0;

        if (buf.len < 7) return error.UnexpectedEof;

        // First byte
        const first_byte = buf[pos];
        pos += 1;

        // Check long header bit
        if ((first_byte & 0x80) == 0) return error.InvalidPacketType;

        // Extract packet type
        const type_bits = (first_byte >> 4) & 0x03;
        const packet_type: PacketType = switch (type_bits) {
            0b00 => .initial,
            0b01 => .zero_rtt,
            0b10 => .handshake,
            0b11 => .retry,
            else => unreachable,
        };

        // Version
        if (pos + 4 > buf.len) return error.UnexpectedEof;
        const version = std.mem.readInt(u32, buf[pos..][0..4], .big);
        pos += 4;

        // Destination Connection ID
        if (pos + 1 > buf.len) return error.UnexpectedEof;
        const dcid_len = buf[pos];
        pos += 1;
        if (pos + dcid_len > buf.len) return error.UnexpectedEof;
        const dest_conn_id = try ConnectionId.init(buf[pos..][0..dcid_len]);
        pos += dcid_len;

        // Source Connection ID
        if (pos + 1 > buf.len) return error.UnexpectedEof;
        const scid_len = buf[pos];
        pos += 1;
        if (pos + scid_len > buf.len) return error.UnexpectedEof;
        const src_conn_id = try ConnectionId.init(buf[pos..][0..scid_len]);
        pos += scid_len;

        // Token (for Initial packets)
        var token: []const u8 = &.{};
        if (packet_type == .initial) {
            const token_len_result = try varint.decode(buf[pos..]);
            pos += token_len_result.len;
            const token_len = token_len_result.value;
            if (pos + token_len > buf.len) return error.UnexpectedEof;
            token = buf[pos..][0..token_len];
            pos += token_len;
        }

        // Payload length
        const payload_len_result = try varint.decode(buf[pos..]);
        pos += payload_len_result.len;
        const payload_len = payload_len_result.value;

        // Packet number (we'll just read 4 bytes for now)
        if (pos + 4 > buf.len) return error.UnexpectedEof;
        const packet_number = std.mem.readInt(u32, buf[pos..][0..4], .big);
        pos += 4;

        const header = LongHeader{
            .packet_type = packet_type,
            .version = version,
            .dest_conn_id = dest_conn_id,
            .src_conn_id = src_conn_id,
            .token = token,
            .payload_len = payload_len,
            .packet_number = packet_number,
        };

        return .{ .header = header, .consumed = pos };
    }
};

/// Short Header packet format (RFC 9000, Section 17.3)
pub const ShortHeader = struct {
    dest_conn_id: ConnectionId,
    packet_number: PacketNumber,
    key_phase: bool,

    /// Encode Short Header packet
    pub fn encode(self: ShortHeader, buf: []u8) PacketError!usize {
        var pos: usize = 0;

        if (buf.len < 1 + self.dest_conn_id.len) return error.BufferTooSmall;

        // First byte: 0 (short header) | 1 (fixed bit) | S (spin bit) | R R (reserved) | K (key phase) | PP (pn length)
        // For now: 01000000 (fixed bit set, rest zeros)
        var first_byte: u8 = 0b01000000;
        if (self.key_phase) {
            first_byte |= 0b00000100; // Set key phase bit
        }
        buf[pos] = first_byte;
        pos += 1;

        // Destination Connection ID
        @memcpy(buf[pos..][0..self.dest_conn_id.len], self.dest_conn_id.slice());
        pos += self.dest_conn_id.len;

        // Packet number (4 bytes for now)
        if (pos + 4 > buf.len) return error.BufferTooSmall;
        std.mem.writeInt(u32, buf[pos..][0..4], @intCast(self.packet_number & 0xFFFFFFFF), .big);
        pos += 4;

        return pos;
    }

    /// Decode Short Header packet
    pub fn decode(buf: []const u8, dcid_len: u8) PacketError!struct { header: ShortHeader, consumed: usize } {
        var pos: usize = 0;

        if (buf.len < 1 + dcid_len) return error.UnexpectedEof;

        // First byte
        const first_byte = buf[pos];
        pos += 1;

        // Check short header bit
        if ((first_byte & 0x80) != 0) return error.InvalidPacketType;

        // Extract key phase bit
        const key_phase = (first_byte & 0x04) != 0;

        // Destination Connection ID
        if (pos + dcid_len > buf.len) return error.UnexpectedEof;
        const dest_conn_id = try ConnectionId.init(buf[pos..][0..dcid_len]);
        pos += dcid_len;

        // Packet number (4 bytes for now)
        if (pos + 4 > buf.len) return error.UnexpectedEof;
        const packet_number = std.mem.readInt(u32, buf[pos..][0..4], .big);
        pos += 4;

        const header = ShortHeader{
            .dest_conn_id = dest_conn_id,
            .packet_number = packet_number,
            .key_phase = key_phase,
        };

        return .{ .header = header, .consumed = pos };
    }
};

// Tests

test "packet number encode/decode" {
    var buf: [4]u8 = undefined;

    // Test 1-byte encoding
    const len1 = try PacketNumberUtil.encode(100, 50, &buf);
    try std.testing.expectEqual(@as(u8, 1), len1);
    const decoded1 = try PacketNumberUtil.decode(buf[0..len1], 50);
    try std.testing.expectEqual(@as(u64, 100), decoded1);

    // Test 2-byte encoding
    const len2 = try PacketNumberUtil.encode(1000, 800, &buf);
    try std.testing.expectEqual(@as(u8, 2), len2);
    const decoded2 = try PacketNumberUtil.decode(buf[0..len2], 800);
    try std.testing.expectEqual(@as(u64, 1000), decoded2);
}

test "long header initial packet encode/decode" {
    const allocator = std.testing.allocator;
    var buf = try allocator.alloc(u8, 1024);
    defer allocator.free(buf);

    const dcid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });
    const scid = try ConnectionId.init(&[_]u8{ 5, 6, 7, 8 });

    const header = LongHeader{
        .packet_type = .initial,
        .version = types.QUIC_VERSION_1,
        .dest_conn_id = dcid,
        .src_conn_id = scid,
        .token = &.{},
        .payload_len = 100,
        .packet_number = 42,
    };

    const encoded_len = try header.encode(buf);
    try std.testing.expect(encoded_len > 0);

    const result = try LongHeader.decode(buf[0..encoded_len]);
    try std.testing.expectEqual(PacketType.initial, result.header.packet_type);
    try std.testing.expectEqual(types.QUIC_VERSION_1, result.header.version);
    try std.testing.expect(result.header.dest_conn_id.eql(&dcid));
    try std.testing.expect(result.header.src_conn_id.eql(&scid));
    try std.testing.expectEqual(@as(u64, 42), result.header.packet_number);
}

test "short header packet encode/decode" {
    var buf: [100]u8 = undefined;

    const dcid = try ConnectionId.init(&[_]u8{ 1, 2, 3, 4 });

    const header = ShortHeader{
        .dest_conn_id = dcid,
        .packet_number = 12345,
        .key_phase = true,
    };

    const encoded_len = try header.encode(&buf);
    try std.testing.expect(encoded_len > 0);

    const result = try ShortHeader.decode(buf[0..encoded_len], dcid.len);
    try std.testing.expect(result.header.dest_conn_id.eql(&dcid));
    try std.testing.expectEqual(@as(u64, 12345), result.header.packet_number);
    try std.testing.expectEqual(true, result.header.key_phase);
}
