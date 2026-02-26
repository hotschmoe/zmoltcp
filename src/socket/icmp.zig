// ICMP socket: raw ICMP send/receive with endpoint-based filtering.
//
// Supports two binding modes:
// - Ident: matches echo request/reply by ICMP identifier
// - Udp: matches ICMP error messages (DstUnreachable, TimeExceeded)
//   containing an embedded UDP header from a bound local port
//
// Uses dual-ring PacketBuffer for variable-length datagram storage.
//
// [smoltcp:socket/icmp.rs]

const std = @import("std");
const ip_generic = @import("../wire/ip.zig");
const ipv4 = @import("../wire/ipv4.zig");
const ipv6 = @import("../wire/ipv6.zig");
const icmp = @import("../wire/icmp.zig");
const icmpv6_wire = @import("../wire/icmpv6.zig");
const packet_buffer_mod = @import("../storage/packet_buffer.zig");
const time = @import("../time.zig");
const iface_mod = @import("../iface.zig");

const readU16 = @import("../wire/checksum.zig").readU16;
const Instant = time.Instant;

// Extract transport-layer source port from an ICMPv4 error payload.
// Payload: [embedded IPv4 header (variable IHL)][transport header fragment].
fn embeddedSrcPort(payload: []const u8) ?u16 {
    if (payload.len < ipv4.HEADER_LEN) return null;
    const ihl: usize = @as(usize, payload[0] & 0x0F) * 4;
    if (ihl < ipv4.HEADER_LEN or payload.len < ihl + 2) return null;
    return readU16(payload[ihl..][0..2]);
}

// Extract transport-layer source port from an ICMPv6 error payload.
// Payload: [4 msg-specific][40 IPv6 header][transport header fragment].
fn embeddedSrcPortV6(payload: []const u8) ?u16 {
    const offset = 4 + ipv6.HEADER_LEN;
    if (payload.len < offset + 2) return null;
    return readU16(payload[offset..][0..2]);
}

pub fn Socket(comptime Ip: type) type {
    comptime ip_generic.assertIsIp(Ip);
    const is_v6 = Ip.ADDRESS_LEN == 16;
    return struct {
        const Self = @This();

        pub const IcmpRepr = if (is_v6) icmpv6_wire.Repr else icmp.Repr;
        pub const UdpListenEndpoint = ip_generic.ListenEndpoint(Ip);

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

        pub const PacketHeader = struct {
            addr: Ip.Address = Ip.UNSPECIFIED,
        };

        pub const PacketMeta = packet_buffer_mod.PacketMeta(PacketHeader);
        const PktBuf = packet_buffer_mod.PacketBuffer(PacketHeader);

        rx: PktBuf,
        tx: PktBuf,
        endpoint: Endpoint,
        hop_limit: ?u8,

        pub const BindError = error{ Unaddressable, InvalidState };
        pub const SendError = error{ Unaddressable, BufferFull };
        pub const RecvError = error{ Exhausted, Truncated };
        pub const HopLimitError = error{InvalidHopLimit};

        pub const RecvResult = struct {
            data_len: usize,
            src_addr: Ip.Address,
        };

        pub const DispatchResult = struct {
            payload: []const u8,
            dst_addr: Ip.Address,
            hop_limit: ?u8,
            meta: iface_mod.PacketMeta = .{},
        };

        // -- Init / lifecycle --

        pub fn init(
            rx_meta: []PacketMeta,
            rx_payload: []u8,
            tx_meta: []PacketMeta,
            tx_payload: []u8,
        ) Self {
            return .{
                .rx = PktBuf.init(rx_meta, rx_payload),
                .tx = PktBuf.init(tx_meta, tx_payload),
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
            self.rx.reset();
            self.tx.reset();
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

        pub fn sendSlice(self: *Self, data: []const u8, dst_addr: Ip.Address) SendError!void {
            if (Ip.isUnspecified(dst_addr)) return error.Unaddressable;

            const buf = self.tx.enqueue(data.len, .{
                .addr = dst_addr,
            }) catch return error.BufferFull;
            @memcpy(buf[0..data.len], data);
        }

        // -- Receive --

        pub fn recvSlice(self: *Self, buf: []u8) RecvError!RecvResult {
            const result = self.rx.dequeue() catch return error.Exhausted;
            if (buf.len < result.payload.len) return error.Truncated;
            @memcpy(buf[0..result.payload.len], result.payload);
            return .{
                .data_len = result.payload.len,
                .src_addr = result.header.addr,
            };
        }

        // -- Poll scheduling --

        pub fn pollAt(self: Self) ?Instant {
            if (!self.tx.isEmpty()) return Instant.ZERO;
            return null;
        }

        // -- Protocol integration --

        pub fn accepts(self: Self, src_addr: Ip.Address, dst_addr: Ip.Address, repr: IcmpRepr, payload: []const u8) bool {
            _ = src_addr;
            switch (self.endpoint) {
                .unspecified => return false,
                .ident => |bound_ident| {
                    if (comptime is_v6) {
                        return switch (repr) {
                            .echo_request => |e| e.ident == bound_ident,
                            .echo_reply => |e| e.ident == bound_ident,
                            else => false,
                        };
                    } else {
                        return switch (repr) {
                            .echo => |echo| echo.identifier == bound_ident,
                            .other => false,
                        };
                    }
                },
                .udp => |udp_ep| {
                    if (comptime is_v6) {
                        switch (repr) {
                            .dst_unreachable, .pkt_too_big, .time_exceeded, .param_problem => {},
                            else => return false,
                        }
                    } else {
                        const other = switch (repr) {
                            .other => |o| o,
                            .echo => return false,
                        };
                        switch (other.icmp_type) {
                            .dest_unreachable, .time_exceeded => {},
                            else => return false,
                        }
                    }
                    if (udp_ep.addr) |bound_addr| {
                        if (!std.mem.eql(u8, &bound_addr, &dst_addr)) return false;
                    }
                    const src_port = if (comptime is_v6)
                        embeddedSrcPortV6(payload)
                    else
                        embeddedSrcPort(payload);
                    return (src_port orelse return false) == udp_ep.port;
                },
            }
        }

        pub fn process(self: *Self, src_addr: Ip.Address, dst_addr: Ip.Address, repr: IcmpRepr, payload: []const u8) void {
            const total_len = if (comptime is_v6)
                icmpv6_wire.bufferLen(repr)
            else
                icmp.HEADER_LEN + payload.len;

            const buf = self.rx.enqueue(total_len, .{ .addr = src_addr }) catch return;
            if (comptime is_v6) {
                _ = icmpv6_wire.emit(repr, src_addr, dst_addr, buf) catch return;
            } else {
                _ = switch (repr) {
                    .echo => |echo| icmp.emitEcho(echo, payload, buf) catch return,
                    .other => |other| icmp.emitOther(other, payload, buf) catch return,
                };
            }
        }

        pub fn peekDstAddr(self: *Self) ?Ip.Address {
            const result = self.tx.peek() catch return null;
            return result.header.addr;
        }

        pub fn dispatch(self: *Self) ?DispatchResult {
            const result = self.tx.dequeue() catch return null;
            return .{
                .payload = result.payload,
                .dst_addr = result.header.addr,
                .hop_limit = self.hop_limit,
            };
        }
    };
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

const TestSocket = Socket(ipv4);

const LOCAL_PORT: u16 = 53;
const LOCAL_ADDR: ipv4.Address = .{ 192, 168, 1, 1 };
const REMOTE_ADDR: ipv4.Address = .{ 192, 168, 1, 2 };
const ECHO_IDENT: u16 = 0x1234;
const ECHO_SEQ: u16 = 0x5678;
const ECHO_DATA = [_]u8{0xff} ** 16;

fn makeSocket(
    comptime rx_meta_n: usize,
    comptime rx_payload_n: usize,
    comptime tx_meta_n: usize,
    comptime tx_payload_n: usize,
) TestSocket {
    const S = struct {
        var rx_meta: [rx_meta_n]TestSocket.PacketMeta = .{TestSocket.PacketMeta{}} ** rx_meta_n;
        var rx_payload: [rx_payload_n]u8 = .{0} ** rx_payload_n;
        var tx_meta: [tx_meta_n]TestSocket.PacketMeta = .{TestSocket.PacketMeta{}} ** tx_meta_n;
        var tx_payload: [tx_payload_n]u8 = .{0} ** tx_payload_n;
    };
    S.rx_meta = .{TestSocket.PacketMeta{}} ** rx_meta_n;
    S.rx_payload = .{0} ** rx_payload_n;
    S.tx_meta = .{TestSocket.PacketMeta{}} ** tx_meta_n;
    S.tx_payload = .{0} ** tx_payload_n;
    return TestSocket.init(&S.rx_meta, &S.rx_payload, &S.tx_meta, &S.tx_payload);
}

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
    var s = makeSocket(0, 0, 1, 64);

    try testing.expectError(error.Unaddressable, s.sendSlice("abcdef", ipv4.UNSPECIFIED));
    try s.sendSlice("abcdef", REMOTE_ADDR);
}

// [smoltcp:socket/icmp.rs:test_send_dispatch]
test "send and dispatch outbound packet" {
    var s = makeSocket(0, 0, 1, 64);

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
    var s = makeSocket(0, 0, 1, 64);

    var echo_buf: [24]u8 = undefined;
    const echo_bytes = buildEchoPacket(&echo_buf);

    try s.setHopLimit(0x2a);
    try s.sendSlice(echo_bytes, REMOTE_ADDR);

    const result = s.dispatch() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(?u8, 0x2a), result.hop_limit);
}

// [smoltcp:socket/icmp.rs:test_recv_process]
test "process inbound and recv" {
    var s = makeSocket(1, 128, 1, 64);
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
    s.process(REMOTE_ADDR, LOCAL_ADDR, echo_repr, &ECHO_DATA);
    try testing.expect(s.canRecv());

    // Second process to full buffer (rx meta size 1) is accepted but dropped
    try testing.expect(s.accepts(REMOTE_ADDR, LOCAL_ADDR, echo_repr, &ECHO_DATA));
    s.process(REMOTE_ADDR, LOCAL_ADDR, echo_repr, &ECHO_DATA);

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
    var s = makeSocket(1, 128, 1, 64);
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
    var s = makeSocket(1, 128, 1, 64);
    try s.bind(.{ .udp = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT } });

    // Construct payload of an ICMP DstUnreachable: embedded IPv4 header + UDP header.
    const embedded_payload = [_]u8{
        // IPv4 header (20 bytes): version=4, IHL=5, protocol=UDP(17)
        0x45, 0x00, 0x00, 0x1C,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        192,  168,  1,    1,
        192,  168,  1,    2,
        // UDP header (8 bytes)
        0x00, 0x35, // src_port = 53 (LOCAL_PORT)
        0x23, 0x82, // dst_port = 9090
        0x00, 0x12, // length = 18
        0x00, 0x00, // checksum
    };

    const icmp_repr = icmp.Repr{ .other = .{
        .icmp_type = .dest_unreachable,
        .code = 3,
        .checksum = 0,
        .data = 0,
    } };

    try testing.expect(!s.canRecv());

    try testing.expect(s.accepts(REMOTE_ADDR, LOCAL_ADDR, icmp_repr, &embedded_payload));
    s.process(REMOTE_ADDR, LOCAL_ADDR, icmp_repr, &embedded_payload);
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

// (original)
test "pollAt returns ZERO when tx queued, null when empty" {
    var s = makeSocket(0, 0, 1, 64);

    try testing.expectEqual(@as(?Instant, null), s.pollAt());

    var echo_buf: [24]u8 = undefined;
    const echo_bytes = buildEchoPacket(&echo_buf);
    try s.sendSlice(echo_bytes, REMOTE_ADDR);
    try testing.expectEqual(Instant.ZERO, s.pollAt().?);

    _ = s.dispatch();
    try testing.expectEqual(@as(?Instant, null), s.pollAt());
}
