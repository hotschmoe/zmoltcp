// ICMP socket: raw ICMP send/receive with endpoint-based filtering.
//
// Supports two binding modes:
// - Ident: matches echo request/reply by ICMP identifier
// - Udp: matches ICMP error messages (DstUnreachable, TimeExceeded)
//   containing an embedded UDP header from a bound local port
//
// [smoltcp:socket/icmp.rs]

const std = @import("std");
const ipv4 = @import("../wire/ipv4.zig");
const icmp = @import("../wire/icmp.zig");
const ring_buffer_mod = @import("../storage/ring_buffer.zig");

// Extract the transport-layer source port from an ICMP error payload.
// The payload contains: [embedded IPv4 header][transport header fragment].
// Returns null if the payload is too short to contain a valid port.
fn embeddedSrcPort(payload: []const u8) ?u16 {
    if (payload.len < ipv4.HEADER_LEN) return null;
    const ihl: usize = @as(usize, payload[0] & 0x0F) * 4;
    if (ihl < ipv4.HEADER_LEN or payload.len < ihl + 2) return null;
    return @as(u16, payload[ihl]) << 8 | @as(u16, payload[ihl + 1]);
}

// -------------------------------------------------------------------------
// Endpoint types
// -------------------------------------------------------------------------

pub const UdpListenEndpoint = struct {
    addr: ?ipv4.Address = null,
    port: u16 = 0,
};

pub const Endpoint = union(enum) {
    unspecified,
    ident: u16,
    udp: UdpListenEndpoint,

    pub fn isSpecified(self: Endpoint) bool {
        return switch (self) {
            .unspecified => false,
            .ident => true,
            .udp => |ep| ep.port != 0,
        };
    }
};

// -------------------------------------------------------------------------
// Config
// -------------------------------------------------------------------------

pub const Config = struct {
    payload_size: comptime_int,
};

// -------------------------------------------------------------------------
// Socket
// -------------------------------------------------------------------------

pub fn Socket(comptime config: Config) type {
    return struct {
        const Self = @This();

        pub const Packet = struct {
            payload: [config.payload_size]u8 = undefined,
            payload_len: usize = 0,
            addr: ipv4.Address = ipv4.UNSPECIFIED,
        };

        const RingBuffer = ring_buffer_mod.RingBuffer(Packet);

        rx: RingBuffer,
        tx: RingBuffer,
        endpoint: Endpoint,
        hop_limit: ?u8,

        pub const BindError = error{ Unaddressable, InvalidState };
        pub const SendError = error{ Unaddressable, BufferFull };
        pub const RecvError = error{ Exhausted, Truncated };
        pub const HopLimitError = error{InvalidHopLimit};

        pub const RecvResult = struct {
            data_len: usize,
            src_addr: ipv4.Address,
        };

        pub const DispatchResult = struct {
            payload: []const u8,
            dst_addr: ipv4.Address,
            hop_limit: ?u8,
        };

        // -- Init / lifecycle --

        pub fn init(rx_storage: []Packet, tx_storage: []Packet) Self {
            return .{
                .rx = RingBuffer.init(rx_storage),
                .tx = RingBuffer.init(tx_storage),
                .endpoint = .unspecified,
                .hop_limit = null,
            };
        }

        pub fn bind(self: *Self, endpoint: Endpoint) BindError!void {
            if (!endpoint.isSpecified()) return error.Unaddressable;
            if (self.isOpen()) return error.InvalidState;
            self.endpoint = endpoint;
        }

        pub fn close(self: *Self) void {
            self.endpoint = .unspecified;
            self.rx.clear();
            self.tx.clear();
        }

        pub fn isOpen(self: Self) bool {
            return self.endpoint.isSpecified();
        }

        pub fn canSend(self: Self) bool {
            return !self.tx.isFull();
        }

        pub fn canRecv(self: Self) bool {
            return !self.rx.isEmpty();
        }

        pub fn setHopLimit(self: *Self, limit: ?u8) HopLimitError!void {
            if (limit) |l| {
                if (l == 0) return error.InvalidHopLimit;
            }
            self.hop_limit = limit;
        }

        // -- Send --

        pub fn sendSlice(self: *Self, data: []const u8, dst_addr: ipv4.Address) SendError!void {
            if (ipv4.isUnspecified(dst_addr)) return error.Unaddressable;
            if (data.len > config.payload_size) return error.BufferFull;

            const pkt = self.tx.enqueueOne() catch return error.BufferFull;
            @memcpy(pkt.payload[0..data.len], data);
            pkt.payload_len = data.len;
            pkt.addr = dst_addr;
        }

        // -- Receive --

        pub fn recvSlice(self: *Self, buf: []u8) RecvError!RecvResult {
            const pkt = self.rx.dequeueOne() catch return error.Exhausted;
            if (buf.len < pkt.payload_len) return error.Truncated;
            @memcpy(buf[0..pkt.payload_len], pkt.payload[0..pkt.payload_len]);
            return .{
                .data_len = pkt.payload_len,
                .src_addr = pkt.addr,
            };
        }

        // -- Protocol integration --

        pub fn accepts(self: Self, src_addr: ipv4.Address, dst_addr: ipv4.Address, repr: icmp.Repr, payload: []const u8) bool {
            _ = src_addr;
            switch (self.endpoint) {
                .unspecified => return false,
                .ident => |bound_ident| {
                    return switch (repr) {
                        .echo => |echo| echo.identifier == bound_ident,
                        .other => false,
                    };
                },
                .udp => |udp_ep| {
                    const other = switch (repr) {
                        .other => |o| o,
                        .echo => return false,
                    };
                    switch (other.icmp_type) {
                        .dest_unreachable, .time_exceeded => {},
                        else => return false,
                    }
                    if (udp_ep.addr) |bound_addr| {
                        if (!std.mem.eql(u8, &bound_addr, &dst_addr)) return false;
                    }
                    const src_port = embeddedSrcPort(payload) orelse return false;
                    return src_port == udp_ep.port;
                },
            }
        }

        pub fn process(self: *Self, src_addr: ipv4.Address, repr: icmp.Repr, payload: []const u8) void {
            if (icmp.HEADER_LEN + payload.len > config.payload_size) return;

            const pkt = self.rx.enqueueOne() catch return;
            pkt.payload_len = switch (repr) {
                .echo => |echo| icmp.emitEcho(echo, payload, &pkt.payload) catch unreachable,
                .other => |other| icmp.emitOther(other, payload, &pkt.payload) catch unreachable,
            };
            pkt.addr = src_addr;
        }

        pub fn dispatch(self: *Self) ?DispatchResult {
            const pkt = self.tx.dequeueOne() catch return null;
            return .{
                .payload = pkt.payload[0..pkt.payload_len],
                .dst_addr = pkt.addr,
                .hop_limit = self.hop_limit,
            };
        }
    };
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

const TestConfig = Config{ .payload_size = 64 };
const TestSocket = Socket(TestConfig);

const LOCAL_PORT: u16 = 53;
const LOCAL_ADDR: ipv4.Address = .{ 192, 168, 1, 1 };
const REMOTE_ADDR: ipv4.Address = .{ 192, 168, 1, 2 };
const ECHO_IDENT: u16 = 0x1234;
const ECHO_SEQ: u16 = 0x5678;
const ECHO_DATA = [_]u8{0xff} ** 16;

fn buildEchoPacket(buf: []u8) []const u8 {
    const echo_repr = icmp.EchoRepr{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = ECHO_IDENT,
        .sequence = ECHO_SEQ,
    };
    const len = icmp.emitEcho(echo_repr, &ECHO_DATA, buf) catch unreachable;
    return buf[0..len];
}

// [smoltcp:socket/icmp.rs:test_send_unaddressable]
test "send rejects unaddressable destination" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);

    try testing.expectError(error.Unaddressable, s.sendSlice("abcdef", .{ 0, 0, 0, 0 }));
    try s.sendSlice("abcdef", REMOTE_ADDR);
}

// [smoltcp:socket/icmp.rs:test_send_dispatch]
test "send and dispatch outbound packet" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);

    try testing.expect(s.canSend());
    try testing.expect(s.dispatch() == null);

    // Oversized payload returns BufferFull
    const too_large = [_]u8{0xff} ** 65;
    try testing.expectError(error.BufferFull, s.sendSlice(&too_large, REMOTE_ADDR));
    try testing.expect(s.canSend());

    // Send echo packet
    var echo_buf: [24]u8 = undefined;
    const echo_bytes = buildEchoPacket(&echo_buf);
    try s.sendSlice(echo_bytes, REMOTE_ADDR);
    try testing.expectError(error.BufferFull, s.sendSlice("123456", REMOTE_ADDR));
    try testing.expect(!s.canSend());

    // Dispatch returns the packet
    const result = s.dispatch() orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, echo_bytes, result.payload);
    try testing.expectEqualSlices(u8, &REMOTE_ADDR, &result.dst_addr);
    try testing.expect(s.canSend());
}

// [smoltcp:socket/icmp.rs:test_set_hop_limit_v4]
test "hop limit propagates to dispatch" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);

    var echo_buf: [24]u8 = undefined;
    const echo_bytes = buildEchoPacket(&echo_buf);

    try s.setHopLimit(0x2a);
    try s.sendSlice(echo_bytes, REMOTE_ADDR);

    const result = s.dispatch() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(?u8, 0x2a), result.hop_limit);
}

// [smoltcp:socket/icmp.rs:test_recv_process]
test "process inbound and recv" {
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
    try s.bind(.{ .ident = ECHO_IDENT });

    try testing.expect(!s.canRecv());
    var recv_buf: [64]u8 = undefined;
    try testing.expectError(error.Exhausted, s.recvSlice(&recv_buf));

    const echo_repr = icmp.Repr{ .echo = .{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = ECHO_IDENT,
        .sequence = ECHO_SEQ,
    } };

    try testing.expect(s.accepts(REMOTE_ADDR, LOCAL_ADDR, echo_repr, &ECHO_DATA));
    s.process(REMOTE_ADDR, echo_repr, &ECHO_DATA);
    try testing.expect(s.canRecv());

    // Second process to full buffer (rx size 1) is accepted but dropped
    try testing.expect(s.accepts(REMOTE_ADDR, LOCAL_ADDR, echo_repr, &ECHO_DATA));
    s.process(REMOTE_ADDR, echo_repr, &ECHO_DATA);

    // Verify recv returns correctly serialized ICMP echo bytes
    var expected_buf: [24]u8 = undefined;
    const expected = buildEchoPacket(&expected_buf);

    const result = try s.recvSlice(&recv_buf);
    try testing.expectEqual(expected.len, result.data_len);
    try testing.expectEqualSlices(u8, expected, recv_buf[0..result.data_len]);
    try testing.expectEqualSlices(u8, &REMOTE_ADDR, &result.src_addr);
    try testing.expect(!s.canRecv());
}

// [smoltcp:socket/icmp.rs:test_accept_bad_id]
test "rejects packet with wrong identifier" {
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
    try s.bind(.{ .ident = ECHO_IDENT });

    const bad_repr = icmp.Repr{ .echo = .{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x4321,
        .sequence = ECHO_SEQ,
    } };

    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, bad_repr, &ECHO_DATA));
}

// [smoltcp:socket/icmp.rs:test_accepts_udp]
test "accepts ICMP error for bound UDP port" {
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
    try s.bind(.{ .udp = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT } });

    // Construct payload of an ICMP DstUnreachable: embedded IPv4 header + UDP header.
    // The original packet was sent FROM LOCAL_ADDR:LOCAL_PORT TO REMOTE_ADDR:9090.
    const embedded_payload = [_]u8{
        // IPv4 header (20 bytes): version=4, IHL=5, protocol=UDP(17)
        0x45, 0x00, 0x00, 0x1C, // ver/IHL, DSCP/ECN, total_len=28
        0x00, 0x00, 0x00, 0x00, // identification, flags/frag
        0x40, 0x11, 0x00, 0x00, // TTL=64, protocol=UDP, checksum
        192,  168,  1,    1, // src = LOCAL_ADDR
        192,  168,  1,    2, // dst = REMOTE_ADDR
        // UDP header (8 bytes)
        0x00, 0x35, // src_port = 53 (LOCAL_PORT)
        0x23, 0x82, // dst_port = 9090
        0x00, 0x12, // length = 18
        0x00, 0x00, // checksum
    };

    const icmp_repr = icmp.Repr{ .other = .{
        .icmp_type = .dest_unreachable,
        .code = 3, // port unreachable
        .checksum = 0,
        .data = 0,
    } };

    try testing.expect(!s.canRecv());

    // Verify accepts matches the bound UDP port
    try testing.expect(s.accepts(REMOTE_ADDR, LOCAL_ADDR, icmp_repr, &embedded_payload));
    s.process(REMOTE_ADDR, icmp_repr, &embedded_payload);
    try testing.expect(s.canRecv());

    var expected_buf: [icmp.HEADER_LEN + embedded_payload.len]u8 = undefined;
    const expected_len = icmp.emitOther(icmp_repr.other, &embedded_payload, &expected_buf) catch unreachable;

    var recv_buf: [64]u8 = undefined;
    const result = try s.recvSlice(&recv_buf);
    try testing.expectEqual(expected_len, result.data_len);
    try testing.expectEqualSlices(u8, expected_buf[0..expected_len], recv_buf[0..result.data_len]);
    try testing.expectEqualSlices(u8, &REMOTE_ADDR, &result.src_addr);
    try testing.expect(!s.canRecv());
}
