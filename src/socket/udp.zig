// UDP socket: message-oriented datagram send/receive.
//
// Uses dual-ring PacketBuffer for variable-length datagram storage,
// matching smoltcp's PacketBuffer design.
//
// [smoltcp:socket/udp.rs]

const std = @import("std");
const ip_generic = @import("../wire/ip.zig");
const ipv4 = @import("../wire/ipv4.zig");
const packet_buffer_mod = @import("../storage/packet_buffer.zig");
const time = @import("../time.zig");
const iface_mod = @import("../iface.zig");

const Instant = time.Instant;

// -------------------------------------------------------------------------
// Repr (socket-level, mirrors wire/udp.zig Repr minus length/checksum)
// -------------------------------------------------------------------------

pub const UdpRepr = struct {
    src_port: u16,
    dst_port: u16,
};

// -------------------------------------------------------------------------
// Socket
// -------------------------------------------------------------------------

pub fn Socket(comptime Ip: type) type {
    comptime ip_generic.assertIsIp(Ip);
    return struct {
        const Self = @This();

        pub const Endpoint = ip_generic.Endpoint(Ip);
        pub const ListenEndpoint = ip_generic.ListenEndpoint(Ip);

        pub const Metadata = struct {
            endpoint: Endpoint = .{ .addr = Ip.UNSPECIFIED, .port = 0 },
            local_addr: ?Ip.Address = null,
        };

        pub const PacketMeta = packet_buffer_mod.PacketMeta(Metadata);
        const PktBuf = packet_buffer_mod.PacketBuffer(Metadata);

        rx: PktBuf,
        tx: PktBuf,
        local_endpoint: ListenEndpoint,
        hop_limit: ?u8,

        pub const BindError = error{ Unaddressable, InvalidState };
        pub const SendError = error{ Unaddressable, BufferFull };
        pub const RecvError = error{ Exhausted, Truncated };
        pub const HopLimitError = error{InvalidHopLimit};

        pub const RecvResult = struct {
            data_len: usize,
            meta: Metadata,
        };

        pub const PeekResult = struct {
            payload: []const u8,
            meta: Metadata,
        };

        pub const DispatchResult = struct {
            repr: UdpRepr,
            src_addr: Ip.Address,
            dst_addr: Ip.Address,
            hop_limit: ?u8,
            payload: []const u8,
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
                .local_endpoint = .{},
                .hop_limit = null,
            };
        }

        pub fn bind(self: *Self, endpoint: ListenEndpoint) BindError!void {
            if (endpoint.port == 0) return error.Unaddressable;
            if (self.isOpen()) return error.InvalidState;
            self.local_endpoint = endpoint;
        }

        pub fn close(self: *Self) void {
            self.local_endpoint = .{};
            self.rx.reset();
            self.tx.reset();
        }

        pub fn isOpen(self: Self) bool {
            return self.local_endpoint.port != 0;
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

        pub fn sendSlice(self: *Self, data: []const u8, meta: Metadata) SendError!void {
            if (self.local_endpoint.port == 0) return error.Unaddressable;
            if (Ip.isUnspecified(meta.endpoint.addr)) return error.Unaddressable;
            if (meta.endpoint.port == 0) return error.Unaddressable;

            const buf = self.tx.enqueue(data.len, .{
                .endpoint = meta.endpoint,
                .local_addr = meta.local_addr,
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
                .meta = result.header,
            };
        }

        pub fn peek(self: *Self) RecvError!PeekResult {
            const result = self.rx.peek() catch return error.Exhausted;
            return .{
                .payload = result.payload,
                .meta = result.header.*,
            };
        }

        pub fn peekSlice(self: *Self, buf: []u8) RecvError!RecvResult {
            const result = try self.peek();
            if (buf.len < result.payload.len) return error.Truncated;
            @memcpy(buf[0..result.payload.len], result.payload);
            return .{
                .data_len = result.payload.len,
                .meta = result.meta,
            };
        }

        // -- Poll scheduling --

        pub fn pollAt(self: Self) ?Instant {
            if (!self.tx.isEmpty()) return Instant.ZERO;
            return null;
        }

        // -- Protocol integration --

        pub fn accepts(self: Self, src_addr: Ip.Address, dst_addr: Ip.Address, repr: UdpRepr) bool {
            _ = src_addr;
            if (self.local_endpoint.port != repr.dst_port) return false;
            if (self.local_endpoint.addr) |bound_addr| {
                if (!std.mem.eql(u8, &bound_addr, &dst_addr)) return false;
            }
            return true;
        }

        pub fn process(self: *Self, src_addr: Ip.Address, dst_addr: Ip.Address, repr: UdpRepr, payload: []const u8) void {
            const buf = self.rx.enqueue(payload.len, .{
                .endpoint = .{ .addr = src_addr, .port = repr.src_port },
                .local_addr = dst_addr,
            }) catch return;
            @memcpy(buf[0..payload.len], payload);
        }

        pub fn peekDstAddr(self: *Self) ?Ip.Address {
            const result = self.tx.peek() catch return null;
            return result.header.endpoint.addr;
        }

        pub fn dispatch(self: *Self) ?DispatchResult {
            const result = self.tx.dequeue() catch return null;
            const src_addr = result.header.local_addr orelse
                (self.local_endpoint.addr orelse Ip.UNSPECIFIED);
            return .{
                .repr = .{
                    .src_port = self.local_endpoint.port,
                    .dst_port = result.header.endpoint.port,
                },
                .src_addr = src_addr,
                .dst_addr = result.header.endpoint.addr,
                .hop_limit = self.hop_limit,
                .payload = result.payload,
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
const REMOTE_PORT: u16 = 49500;
const LOCAL_ADDR: ipv4.Address = .{ 192, 168, 1, 1 };
const REMOTE_ADDR: ipv4.Address = .{ 192, 168, 1, 2 };
const OTHER_ADDR: ipv4.Address = .{ 192, 168, 1, 3 };

const LOCAL_END = TestSocket.ListenEndpoint{ .addr = LOCAL_ADDR, .port = LOCAL_PORT };
const REMOTE_END = TestSocket.Endpoint{ .addr = REMOTE_ADDR, .port = REMOTE_PORT };

const PAYLOAD = "abcdef";

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

// [smoltcp:socket/udp.rs:test_bind_unaddressable]
test "bind rejects port 0" {
    var s = makeSocket(0, 0, 0, 0);
    try testing.expectError(error.Unaddressable, s.bind(.{ .port = 0 }));
}

// [smoltcp:socket/udp.rs:test_bind_twice]
test "bind twice fails" {
    var s = makeSocket(0, 0, 0, 0);
    try s.bind(.{ .port = 1 });
    try testing.expectError(error.InvalidState, s.bind(.{ .port = 2 }));
}

// [smoltcp:socket/udp.rs:test_set_hop_limit_zero]
test "set hop limit zero rejected" {
    var s = makeSocket(0, 0, 1, 64);
    try testing.expectError(error.InvalidHopLimit, s.setHopLimit(0));
    try s.setHopLimit(42);
    try testing.expectEqual(@as(?u8, 42), s.hop_limit);
    try s.setHopLimit(null);
    try testing.expectEqual(@as(?u8, null), s.hop_limit);
}

// [smoltcp:socket/udp.rs:test_send_unaddressable]
test "send before bind and with bad addresses" {
    var s = makeSocket(0, 0, 1, 64);

    try testing.expectError(error.Unaddressable, s.sendSlice(PAYLOAD, .{ .endpoint = REMOTE_END }));

    try s.bind(.{ .port = LOCAL_PORT });

    try testing.expectError(error.Unaddressable, s.sendSlice(PAYLOAD, .{
        .endpoint = .{ .addr = ipv4.UNSPECIFIED, .port = REMOTE_PORT },
    }));

    try testing.expectError(error.Unaddressable, s.sendSlice(PAYLOAD, .{
        .endpoint = .{ .addr = REMOTE_ADDR, .port = 0 },
    }));

    try s.sendSlice(PAYLOAD, .{ .endpoint = REMOTE_END });
}

// [smoltcp:socket/udp.rs:test_send_with_source]
test "send with explicit local address" {
    var s = makeSocket(0, 0, 1, 64);
    try s.bind(.{ .port = LOCAL_PORT });
    try s.sendSlice(PAYLOAD, .{
        .endpoint = REMOTE_END,
        .local_addr = LOCAL_ADDR,
    });
}

// [smoltcp:socket/udp.rs:test_send_dispatch]
test "send and dispatch outbound packet" {
    var s = makeSocket(0, 0, 1, 64);
    try s.bind(LOCAL_END);

    try testing.expect(s.canSend());
    try testing.expectEqual(@as(?TestSocket.DispatchResult, null), s.dispatch());

    try s.sendSlice(PAYLOAD, .{ .endpoint = REMOTE_END });

    try testing.expectError(error.BufferFull, s.sendSlice("123456", .{ .endpoint = REMOTE_END }));
    try testing.expect(!s.canSend());

    const result = s.dispatch() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(LOCAL_PORT, result.repr.src_port);
    try testing.expectEqual(REMOTE_PORT, result.repr.dst_port);
    try testing.expectEqualSlices(u8, LOCAL_ADDR[0..], result.src_addr[0..]);
    try testing.expectEqualSlices(u8, REMOTE_ADDR[0..], result.dst_addr[0..]);
    try testing.expectEqualSlices(u8, PAYLOAD, result.payload);

    try testing.expect(s.canSend());
}

// [smoltcp:socket/udp.rs:test_recv_process]
test "process inbound and recv" {
    var s = makeSocket(1, 64, 0, 0);
    try s.bind(.{ .port = LOCAL_PORT });

    try testing.expect(!s.canRecv());
    var recv_buf: [32]u8 = undefined;
    try testing.expectError(error.Exhausted, s.recvSlice(&recv_buf));

    const repr = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    try testing.expect(s.accepts(REMOTE_ADDR, LOCAL_ADDR, repr));
    s.process(REMOTE_ADDR, LOCAL_ADDR, repr, PAYLOAD);
    try testing.expect(s.canRecv());

    s.process(REMOTE_ADDR, LOCAL_ADDR, repr, PAYLOAD);

    const result = try s.recvSlice(&recv_buf);
    try testing.expectEqual(PAYLOAD.len, result.data_len);
    try testing.expectEqualSlices(u8, PAYLOAD, recv_buf[0..result.data_len]);
    try testing.expectEqual(REMOTE_PORT, result.meta.endpoint.port);
    try testing.expectEqualSlices(u8, REMOTE_ADDR[0..], result.meta.endpoint.addr[0..]);
    try testing.expect(!s.canRecv());
}

// [smoltcp:socket/udp.rs:test_peek_process]
test "peek returns data without consuming" {
    var s = makeSocket(1, 64, 0, 0);
    try s.bind(.{ .port = LOCAL_PORT });

    try testing.expectError(error.Exhausted, s.peek());

    const repr = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    s.process(REMOTE_ADDR, LOCAL_ADDR, repr, PAYLOAD);

    const peek_result = try s.peek();
    try testing.expectEqualSlices(u8, PAYLOAD, peek_result.payload);

    var recv_buf: [32]u8 = undefined;
    const recv_result = try s.recvSlice(&recv_buf);
    try testing.expectEqualSlices(u8, PAYLOAD, recv_buf[0..recv_result.data_len]);

    try testing.expectError(error.Exhausted, s.peek());
}

// [smoltcp:socket/udp.rs:test_recv_truncated_slice]
test "recv_slice truncated with small buffer" {
    var s = makeSocket(1, 64, 0, 0);
    try s.bind(.{ .port = LOCAL_PORT });

    const repr = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    s.process(REMOTE_ADDR, LOCAL_ADDR, repr, PAYLOAD);

    var small: [4]u8 = undefined;
    try testing.expectError(error.Truncated, s.recvSlice(&small));
}

// [smoltcp:socket/udp.rs:test_peek_truncated_slice]
test "peek_slice non-destructive, recv_slice destructive" {
    var s = makeSocket(1, 64, 0, 0);
    try s.bind(.{ .port = LOCAL_PORT });

    const repr = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    s.process(REMOTE_ADDR, LOCAL_ADDR, repr, PAYLOAD);

    var small: [4]u8 = undefined;
    try testing.expectError(error.Truncated, s.peekSlice(&small));
    try testing.expectError(error.Truncated, s.recvSlice(&small));
    try testing.expectError(error.Exhausted, s.peekSlice(&small));
}

// [smoltcp:socket/udp.rs:test_set_hop_limit]
test "hop limit propagates to dispatch" {
    var s = makeSocket(0, 0, 1, 64);
    try s.bind(LOCAL_END);

    try s.setHopLimit(0x2a);
    try s.sendSlice(PAYLOAD, .{ .endpoint = REMOTE_END });

    const result = s.dispatch() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(?u8, 0x2a), result.hop_limit);
}

// [smoltcp:socket/udp.rs:test_doesnt_accept_wrong_port]
test "rejects packet with wrong destination port" {
    var s = makeSocket(1, 64, 0, 0);
    try s.bind(.{ .port = LOCAL_PORT });

    const good = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    try testing.expect(s.accepts(REMOTE_ADDR, LOCAL_ADDR, good));

    const bad = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT + 1 };
    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, bad));
}

// [smoltcp:socket/udp.rs:test_doesnt_accept_wrong_ip]
test "port-only bind accepts any addr; addr+port rejects wrong" {
    var s1 = makeSocket(1, 64, 0, 0);
    try s1.bind(.{ .port = LOCAL_PORT });

    const repr = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    try testing.expect(s1.accepts(REMOTE_ADDR, OTHER_ADDR, repr));

    var s2 = makeSocket(1, 64, 0, 0);
    try s2.bind(LOCAL_END);

    try testing.expect(!s2.accepts(REMOTE_ADDR, OTHER_ADDR, repr));
    try testing.expect(s2.accepts(REMOTE_ADDR, LOCAL_ADDR, repr));
}

// [smoltcp:socket/udp.rs:test_send_large_packet]
test "payload exceeding capacity returns BufferFull" {
    var s = makeSocket(0, 0, 4, 16);
    try s.bind(LOCAL_END);

    const too_large = "01234567890abcdefX";
    try testing.expectError(error.BufferFull, s.sendSlice(too_large, .{ .endpoint = REMOTE_END }));

    try s.sendSlice(too_large[0..16], .{ .endpoint = REMOTE_END });
}

// [smoltcp:socket/udp.rs:test_process_empty_payload]
test "zero-length datagram is valid" {
    var s = makeSocket(1, 64, 0, 0);
    try s.bind(.{ .port = LOCAL_PORT });

    const repr = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    s.process(REMOTE_ADDR, LOCAL_ADDR, repr, &.{});

    var recv_buf: [32]u8 = undefined;
    const result = try s.recvSlice(&recv_buf);
    try testing.expectEqual(@as(usize, 0), result.data_len);
    try testing.expectEqual(REMOTE_PORT, result.meta.endpoint.port);
}

// [smoltcp:socket/udp.rs:test_closing]
test "close resets socket" {
    var s = makeSocket(1, 64, 0, 0);
    try s.bind(.{ .port = LOCAL_PORT });

    try testing.expect(s.isOpen());
    s.close();
    try testing.expect(!s.isOpen());
}

// (original)
test "pollAt returns ZERO when tx queued, null when empty" {
    var s = makeSocket(0, 0, 1, 64);
    try s.bind(LOCAL_END);

    try testing.expectEqual(@as(?Instant, null), s.pollAt());

    try s.sendSlice(PAYLOAD, .{ .endpoint = REMOTE_END });
    try testing.expectEqual(Instant.ZERO, s.pollAt().?);

    _ = s.dispatch();
    try testing.expectEqual(@as(?Instant, null), s.pollAt());
}
