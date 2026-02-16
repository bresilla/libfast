const std = @import("std");

/// Congestion control for QUIC (RFC 9002)
///
/// Implements NewReno congestion control algorithm with slow start
/// and congestion avoidance.

pub const CongestionError = error{
    InvalidCongestionWindow,
    InvalidSlowStartThreshold,
};

/// Congestion control state
pub const CongestionState = enum {
    /// Slow start phase
    slow_start,

    /// Congestion avoidance phase
    congestion_avoidance,

    /// Recovery phase (after packet loss)
    recovery,

    pub fn toString(self: CongestionState) []const u8 {
        return switch (self) {
            .slow_start => "SlowStart",
            .congestion_avoidance => "CongestionAvoidance",
            .recovery => "Recovery",
        };
    }
};

/// Congestion controller
pub const CongestionController = struct {
    /// Current congestion window (bytes)
    congestion_window: u64,

    /// Bytes in flight
    bytes_in_flight: u64,

    /// Slow start threshold (bytes)
    ssthresh: u64,

    /// Maximum datagram size (bytes)
    max_datagram_size: u64,

    /// Current state
    state: CongestionState,

    /// Number of ACKed bytes in current window (for congestion avoidance)
    acked_bytes_in_window: u64,

    /// End of recovery period (packet number)
    recovery_end_packet: ?u64,

    /// Initialize congestion controller
    pub fn init(max_datagram_size: u64) CongestionController {
        // RFC 9002: Initial window is 10 * max_datagram_size
        const initial_window = 10 * max_datagram_size;

        return CongestionController{
            .congestion_window = initial_window,
            .bytes_in_flight = 0,
            .ssthresh = std.math.maxInt(u64),
            .max_datagram_size = max_datagram_size,
            .state = .slow_start,
            .acked_bytes_in_window = 0,
            .recovery_end_packet = null,
        };
    }

    /// Check if we can send more data
    pub fn canSend(self: *CongestionController) bool {
        return self.bytes_in_flight < self.congestion_window;
    }

    /// Get available congestion window
    pub fn availableWindow(self: *CongestionController) u64 {
        if (self.bytes_in_flight >= self.congestion_window) {
            return 0;
        }
        return self.congestion_window - self.bytes_in_flight;
    }

    /// Record packet sent
    pub fn onPacketSent(self: *CongestionController, bytes: u64) void {
        self.bytes_in_flight += bytes;
    }

    /// Process ACK for packets
    pub fn onPacketAcked(
        self: *CongestionController,
        bytes_acked: u64,
        packet_number: u64,
    ) void {
        // Reduce bytes in flight
        self.bytes_in_flight -|= bytes_acked;

        // Don't increase window if we're in recovery and this ACK is for
        // packets sent before entering recovery
        if (self.recovery_end_packet) |end_pn| {
            if (packet_number <= end_pn) {
                return;
            }
            // We've exited recovery
            self.recovery_end_packet = null;
            self.state = if (self.congestion_window < self.ssthresh)
                .slow_start
            else
                .congestion_avoidance;
        }

        switch (self.state) {
            .slow_start => {
                // In slow start, increase cwnd by bytes_acked
                self.congestion_window += bytes_acked;

                // Check if we've exceeded ssthresh
                if (self.congestion_window >= self.ssthresh) {
                    self.state = .congestion_avoidance;
                    self.acked_bytes_in_window = 0;
                }
            },
            .congestion_avoidance => {
                // In congestion avoidance, increase cwnd by max_datagram_size
                // per RTT (approximated by tracking acked bytes)
                self.acked_bytes_in_window += bytes_acked;

                if (self.acked_bytes_in_window >= self.congestion_window) {
                    self.congestion_window += self.max_datagram_size;
                    self.acked_bytes_in_window = 0;
                }
            },
            .recovery => {
                // Window is not increased in recovery
            },
        }
    }

    /// Handle packet loss
    pub fn onPacketsLost(
        self: *CongestionController,
        bytes_lost: u64,
        largest_lost_packet: u64,
    ) void {
        // Reduce bytes in flight
        self.bytes_in_flight -|= bytes_lost;

        // Don't react to losses during recovery
        if (self.recovery_end_packet) |end_pn| {
            if (largest_lost_packet <= end_pn) {
                return;
            }
        }

        // Enter recovery
        self.state = .recovery;
        self.recovery_end_packet = largest_lost_packet;

        // Reduce ssthresh to half of current window (RFC 9002)
        self.ssthresh = self.congestion_window / 2;

        // Ensure ssthresh is at least 2 * max_datagram_size
        const min_ssthresh = 2 * self.max_datagram_size;
        if (self.ssthresh < min_ssthresh) {
            self.ssthresh = min_ssthresh;
        }

        // Reduce congestion window
        self.congestion_window = self.ssthresh;
        self.acked_bytes_in_window = 0;
    }

    /// Handle persistent congestion (multiple RTOs)
    pub fn onPersistentCongestion(self: *CongestionController) void {
        // Reset to minimal window
        self.congestion_window = 2 * self.max_datagram_size;
        self.ssthresh = std.math.maxInt(u64);
        self.state = .slow_start;
        self.acked_bytes_in_window = 0;
        self.recovery_end_packet = null;
    }

    /// Get current state
    pub fn getState(self: *CongestionController) CongestionState {
        return self.state;
    }

    /// Get congestion window
    pub fn getCongestionWindow(self: *CongestionController) u64 {
        return self.congestion_window;
    }

    /// Get bytes in flight
    pub fn getBytesInFlight(self: *CongestionController) u64 {
        return self.bytes_in_flight;
    }
};

// Tests

test "Congestion controller initialization" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    // Initial window should be 10 * MTU
    try std.testing.expectEqual(@as(u64, 10 * mtu), cc.congestion_window);
    try std.testing.expectEqual(@as(u64, 0), cc.bytes_in_flight);
    try std.testing.expectEqual(CongestionState.slow_start, cc.state);
    try std.testing.expect(cc.canSend());
}

test "Packet sent updates bytes in flight" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    cc.onPacketSent(1000);
    try std.testing.expectEqual(@as(u64, 1000), cc.bytes_in_flight);

    cc.onPacketSent(500);
    try std.testing.expectEqual(@as(u64, 1500), cc.bytes_in_flight);
}

test "Available window calculation" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    // Initial window is 12000
    try std.testing.expectEqual(@as(u64, 12000), cc.availableWindow());

    cc.onPacketSent(5000);
    try std.testing.expectEqual(@as(u64, 7000), cc.availableWindow());

    cc.onPacketSent(7000);
    try std.testing.expectEqual(@as(u64, 0), cc.availableWindow());
    try std.testing.expect(!cc.canSend());
}

test "Slow start window growth" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    const initial_window = cc.congestion_window;

    // ACK 1000 bytes
    cc.onPacketAcked(1000, 1);

    // In slow start, window increases by bytes_acked
    try std.testing.expectEqual(initial_window + 1000, cc.congestion_window);
    try std.testing.expectEqual(CongestionState.slow_start, cc.state);
}

test "Transition to congestion avoidance" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    // Set ssthresh below current window
    cc.ssthresh = 15000;

    // ACK enough to reach ssthresh
    cc.onPacketAcked(5000, 1);

    // Should transition to congestion avoidance
    try std.testing.expectEqual(CongestionState.congestion_avoidance, cc.state);
}

test "Congestion avoidance window growth" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    // Put into congestion avoidance
    cc.state = .congestion_avoidance;
    cc.ssthresh = cc.congestion_window;
    const window_before = cc.congestion_window;

    // ACK entire window worth of bytes
    cc.onPacketAcked(cc.congestion_window, 1);

    // Window should grow by 1 MTU
    try std.testing.expectEqual(window_before + mtu, cc.congestion_window);
}

test "Packet loss triggers recovery" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    const window_before = cc.congestion_window;

    // Lose some packets
    cc.onPacketsLost(1000, 5);

    // Should enter recovery
    try std.testing.expectEqual(CongestionState.recovery, cc.state);

    // Window should be halved
    try std.testing.expectEqual(window_before / 2, cc.congestion_window);

    // ssthresh should be set
    try std.testing.expectEqual(window_before / 2, cc.ssthresh);
}

test "Recovery prevents window growth" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    // Trigger loss
    cc.onPacketsLost(1000, 5);
    const window_during_recovery = cc.congestion_window;

    // ACK packets sent before entering recovery
    cc.onPacketAcked(1000, 3);

    // Window should not grow
    try std.testing.expectEqual(window_during_recovery, cc.congestion_window);
}

test "Exit from recovery" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    // Trigger loss at packet 5
    cc.onPacketsLost(1000, 5);
    try std.testing.expectEqual(CongestionState.recovery, cc.state);

    // ACK packet sent after entering recovery
    cc.onPacketAcked(1000, 10);

    // Should exit recovery
    try std.testing.expect(cc.state != .recovery);
    try std.testing.expect(cc.recovery_end_packet == null);
}

test "Persistent congestion reset" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    // Grow the window
    cc.onPacketAcked(10000, 1);

    // Trigger persistent congestion
    cc.onPersistentCongestion();

    // Should reset to minimal window
    try std.testing.expectEqual(@as(u64, 2 * mtu), cc.congestion_window);
    try std.testing.expectEqual(CongestionState.slow_start, cc.state);
}

test "Minimum ssthresh enforcement" {
    const mtu = 1200;
    var cc = CongestionController.init(mtu);

    // Set very small window
    cc.congestion_window = 1000;

    // Trigger loss
    cc.onPacketsLost(500, 1);

    // ssthresh should be at least 2 * MTU
    try std.testing.expect(cc.ssthresh >= 2 * mtu);
}
