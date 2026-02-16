/// RunQUIC - QUIC transport library
/// Supports both TLS and SSH key exchange modes

const std = @import("std");

// Core QUIC protocol
pub const types = @import("core/types.zig");
pub const packet = @import("core/packet.zig");
pub const frame = @import("core/frame.zig");
pub const stream = @import("core/stream.zig");
pub const connection = @import("core/connection.zig");
pub const varint = @import("utils/varint.zig");
pub const buffer = @import("utils/buffer.zig");
pub const time = @import("utils/time.zig");

// Transport
pub const udp = @import("transport/udp.zig");

// Re-export commonly used types
pub const QuicMode = types.QuicMode;
pub const ConnectionId = types.ConnectionId;
pub const StreamId = types.StreamId;
pub const PacketNumber = types.PacketNumber;
pub const ErrorCode = types.ErrorCode;

// Version information
pub const version = "0.1.0";
pub const QUIC_VERSION_1 = types.QUIC_VERSION_1;

test {
    std.testing.refAllDecls(@This());
}
