// UDP socket: message-oriented datagram send/receive.
//
// Implements a connectionless UDP socket with packet-level buffering.
// Each packet is stored as a fixed-size struct in a RingBuffer(Packet),
// avoiding the complexity of smoltcp's dual-ring PacketBuffer.
//
// [smoltcp:socket/udp.rs]

const std = @import("std");
const ipv4 = @import("../wire/ipv4.zig");
const ring_buffer_mod = @import("../storage/ring_buffer.zig");

// -------------------------------------------------------------------------
// Endpoint types
// -------------------------------------------------------------------------

pub const Endpoint = struct {
    addr: ipv4.Address,
    port: u16,
};

pub const ListenEndpoint = struct {
    addr: ?ipv4.Address = null,
    port: u16 = 0,
};

// -------------------------------------------------------------------------
// Repr (socket-level, mirrors wire/udp.zig Repr minus length/checksum)
// -------------------------------------------------------------------------

pub const UdpRepr = struct {
    src_port: u16,
    dst_port: u16,
};

// -------------------------------------------------------------------------
// Metadata carried with each buffered packet
// -------------------------------------------------------------------------

pub const Metadata = struct {
    endpoint: Endpoint = .{ .addr = ipv4.UNSPECIFIED, .port = 0 },
    local_addr: ?ipv4.Address = null,
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
            meta: Metadata = .{},
        };

        const RingBuffer = ring_buffer_mod.RingBuffer(Packet);

        rx: RingBuffer,
        tx: RingBuffer,
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
            src_addr: ipv4.Address,
            dst_addr: ipv4.Address,
            hop_limit: ?u8,
            payload: []const u8,
        };

        // -- Init / lifecycle --

        pub fn init(rx_storage: []Packet, tx_storage: []Packet) Self {
            return .{
                .rx = RingBuffer.init(rx_storage),
                .tx = RingBuffer.init(tx_storage),
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
            self.rx.clear();
            self.tx.clear();
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
            if (ipv4.isUnspecified(meta.endpoint.addr)) return error.Unaddressable;
            if (meta.endpoint.port == 0) return error.Unaddressable;
            if (data.len > config.payload_size) return error.BufferFull;

            const pkt = self.tx.enqueueOne() catch return error.BufferFull;
            @memcpy(pkt.payload[0..data.len], data);
            pkt.payload_len = data.len;
            pkt.meta = .{
                .endpoint = meta.endpoint,
                .local_addr = meta.local_addr,
            };
        }

        // -- Receive --

        pub fn recvSlice(self: *Self, buf: []u8) RecvError!RecvResult {
            const pkt = self.rx.dequeueOne() catch return error.Exhausted;
            if (buf.len < pkt.payload_len) return error.Truncated;
            @memcpy(buf[0..pkt.payload_len], pkt.payload[0..pkt.payload_len]);
            return .{
                .data_len = pkt.payload_len,
                .meta = pkt.meta,
            };
        }

        pub fn peek(self: *Self) RecvError!PeekResult {
            const slice = self.rx.getAllocated(0, 1);
            if (slice.len == 0) return error.Exhausted;
            const pkt = &slice[0];
            return .{
                .payload = pkt.payload[0..pkt.payload_len],
                .meta = pkt.meta,
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

        // -- Protocol integration --

        pub fn accepts(self: Self, src_addr: ipv4.Address, dst_addr: ipv4.Address, repr: UdpRepr) bool {
            _ = src_addr;
            if (self.local_endpoint.port != repr.dst_port) return false;
            if (self.local_endpoint.addr) |bound_addr| {
                if (!std.mem.eql(u8, &bound_addr, &dst_addr)) return false;
            }
            return true;
        }

        pub fn process(self: *Self, src_addr: ipv4.Address, dst_addr: ipv4.Address, repr: UdpRepr, payload: []const u8) void {
            const pkt = self.rx.enqueueOne() catch return;
            const copy_len = @min(payload.len, config.payload_size);
            @memcpy(pkt.payload[0..copy_len], payload[0..copy_len]);
            pkt.payload_len = copy_len;
            pkt.meta = .{
                .endpoint = .{ .addr = src_addr, .port = repr.src_port },
                .local_addr = dst_addr,
            };
        }

        pub fn dispatch(self: *Self) ?DispatchResult {
            const pkt = self.tx.dequeueOne() catch return null;
            const src_addr = pkt.meta.local_addr orelse
                (self.local_endpoint.addr orelse ipv4.UNSPECIFIED);
            return .{
                .repr = .{
                    .src_port = self.local_endpoint.port,
                    .dst_port = pkt.meta.endpoint.port,
                },
                .src_addr = src_addr,
                .dst_addr = pkt.meta.endpoint.addr,
                .hop_limit = self.hop_limit,
                .payload = pkt.payload[0..pkt.payload_len],
            };
        }
    };
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

const TestConfig = Config{ .payload_size = 16 };
const TestSocket = Socket(TestConfig);

const LOCAL_PORT: u16 = 53;
const REMOTE_PORT: u16 = 49500;
const LOCAL_ADDR: ipv4.Address = .{ 192, 168, 1, 1 };
const REMOTE_ADDR: ipv4.Address = .{ 192, 168, 1, 2 };
const OTHER_ADDR: ipv4.Address = .{ 192, 168, 1, 3 };

const LOCAL_END = ListenEndpoint{ .addr = LOCAL_ADDR, .port = LOCAL_PORT };
const REMOTE_END = Endpoint{ .addr = REMOTE_ADDR, .port = REMOTE_PORT };

const PAYLOAD = "abcdef";

// [smoltcp:socket/udp.rs:test_bind_unaddressable]
test "bind rejects port 0" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);
    try testing.expectError(error.Unaddressable, s.bind(.{ .port = 0 }));
}

// [smoltcp:socket/udp.rs:test_bind_twice]
test "bind twice fails" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);
    try s.bind(.{ .port = 1 });
    try testing.expectError(error.InvalidState, s.bind(.{ .port = 2 }));
}

// [smoltcp:socket/udp.rs:test_set_hop_limit_zero]
test "set hop limit zero rejected" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);
    try testing.expectError(error.InvalidHopLimit, s.setHopLimit(0));
    try s.setHopLimit(42);
    try testing.expectEqual(@as(?u8, 42), s.hop_limit);
    try s.setHopLimit(null);
    try testing.expectEqual(@as(?u8, null), s.hop_limit);
}

// [smoltcp:socket/udp.rs:test_send_unaddressable]
test "send before bind and with bad addresses" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);

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
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);
    try s.bind(.{ .port = LOCAL_PORT });
    try s.sendSlice(PAYLOAD, .{
        .endpoint = REMOTE_END,
        .local_addr = LOCAL_ADDR,
    });
}

// [smoltcp:socket/udp.rs:test_send_dispatch]
test "send and dispatch outbound packet" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);
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
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
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
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
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
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
    try s.bind(.{ .port = LOCAL_PORT });

    const repr = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    s.process(REMOTE_ADDR, LOCAL_ADDR, repr, PAYLOAD);

    var small: [4]u8 = undefined;
    try testing.expectError(error.Truncated, s.recvSlice(&small));
}

// [smoltcp:socket/udp.rs:test_peek_truncated_slice]
test "peek_slice non-destructive, recv_slice destructive" {
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
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
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [1]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);
    try s.bind(LOCAL_END);

    try s.setHopLimit(0x2a);
    try s.sendSlice(PAYLOAD, .{ .endpoint = REMOTE_END });

    const result = s.dispatch() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(?u8, 0x2a), result.hop_limit);
}

// [smoltcp:socket/udp.rs:test_doesnt_accept_wrong_port]
test "rejects packet with wrong destination port" {
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
    try s.bind(.{ .port = LOCAL_PORT });

    const good = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    try testing.expect(s.accepts(REMOTE_ADDR, LOCAL_ADDR, good));

    const bad = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT + 1 };
    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, bad));
}

// [smoltcp:socket/udp.rs:test_doesnt_accept_wrong_ip]
test "port-only bind accepts any addr; addr+port rejects wrong" {
    var rx1: [1]TestSocket.Packet = undefined;
    var tx1: [0]TestSocket.Packet = undefined;
    var port_only = TestSocket.init(&rx1, &tx1);
    try port_only.bind(.{ .port = LOCAL_PORT });

    const repr = UdpRepr{ .src_port = REMOTE_PORT, .dst_port = LOCAL_PORT };
    try testing.expect(port_only.accepts(REMOTE_ADDR, OTHER_ADDR, repr));

    var rx2: [1]TestSocket.Packet = undefined;
    var tx2: [0]TestSocket.Packet = undefined;
    var ip_bound = TestSocket.init(&rx2, &tx2);
    try ip_bound.bind(LOCAL_END);

    try testing.expect(!ip_bound.accepts(REMOTE_ADDR, OTHER_ADDR, repr));
    try testing.expect(ip_bound.accepts(REMOTE_ADDR, LOCAL_ADDR, repr));
}

// [smoltcp:socket/udp.rs:test_send_large_packet]
test "payload exceeding capacity returns BufferFull" {
    var rx: [0]TestSocket.Packet = undefined;
    var tx: [4]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx, &tx);
    try s.bind(LOCAL_END);

    const too_large = "01234567890abcdefX";
    try testing.expectError(error.BufferFull, s.sendSlice(too_large, .{ .endpoint = REMOTE_END }));

    try s.sendSlice(too_large[0..16], .{ .endpoint = REMOTE_END });
}

// [smoltcp:socket/udp.rs:test_process_empty_payload]
test "zero-length datagram is valid" {
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
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
    var rx_buf: [1]TestSocket.Packet = undefined;
    var tx_buf: [0]TestSocket.Packet = undefined;
    var s = TestSocket.init(&rx_buf, &tx_buf);
    try s.bind(.{ .port = LOCAL_PORT });

    try testing.expect(s.isOpen());
    s.close();
    try testing.expect(!s.isOpen());
}
