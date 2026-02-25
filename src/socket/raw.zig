// Raw IP socket: sends and receives raw IP payloads for a given protocol.
//
// Binds to an IP protocol number. Received packets include only the IP payload
// (no IP header). Transmitted packets are IP payloads; the stack adds the IP
// header during egress.
//
// [smoltcp:socket/raw.rs]

const std = @import("std");
const ipv4 = @import("../wire/ipv4.zig");
const ring_buffer_mod = @import("../storage/ring_buffer.zig");
const time = @import("../time.zig");
const iface_mod = @import("../iface.zig");

const Instant = time.Instant;

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
            src_addr: ipv4.Address = ipv4.UNSPECIFIED,
        };

        const RingBuffer = ring_buffer_mod.RingBuffer(Packet);

        rx: RingBuffer,
        tx: RingBuffer,
        ip_protocol: ?ipv4.Protocol,
        hop_limit: ?u8,

        pub const BindError = error{InvalidProtocol};
        pub const SendError = error{ Unbound, BufferFull };
        pub const RecvError = error{ Exhausted, Truncated };
        pub const HopLimitError = error{InvalidHopLimit};

        pub const RecvResult = struct {
            data_len: usize,
            src_addr: ipv4.Address,
        };

        pub const PeekResult = struct {
            payload: []const u8,
            src_addr: ipv4.Address,
        };

        pub const DispatchResult = struct {
            ip_protocol: ipv4.Protocol,
            dst_addr: ipv4.Address,
            hop_limit: ?u8,
            payload: []const u8,
            meta: iface_mod.PacketMeta = .{},
        };

        // -- Init / lifecycle --

        pub fn init(rx_storage: []Packet, tx_storage: []Packet) Self {
            return .{
                .rx = RingBuffer.init(rx_storage),
                .tx = RingBuffer.init(tx_storage),
                .ip_protocol = null,
                .hop_limit = null,
            };
        }

        pub fn bind(self: *Self, protocol: ipv4.Protocol) BindError!void {
            self.ip_protocol = protocol;
        }

        pub fn close(self: *Self) void {
            self.ip_protocol = null;
            self.rx.clear();
            self.tx.clear();
        }

        pub fn isOpen(self: Self) bool {
            return self.ip_protocol != null;
        }

        pub fn canSend(self: Self) bool {
            return self.ip_protocol != null and !self.tx.isFull();
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
            if (self.ip_protocol == null) return error.Unbound;
            if (data.len > config.payload_size) return error.BufferFull;

            const pkt = self.tx.enqueueOne() catch return error.BufferFull;
            @memcpy(pkt.payload[0..data.len], data);
            pkt.payload_len = data.len;
            pkt.src_addr = dst_addr;
        }

        // -- Receive --

        pub fn recvSlice(self: *Self, buf: []u8) RecvError!RecvResult {
            const pkt = self.rx.dequeueOne() catch return error.Exhausted;
            if (buf.len < pkt.payload_len) return error.Truncated;
            @memcpy(buf[0..pkt.payload_len], pkt.payload[0..pkt.payload_len]);
            return .{
                .data_len = pkt.payload_len,
                .src_addr = pkt.src_addr,
            };
        }

        pub fn peek(self: *Self) RecvError!PeekResult {
            const slice = self.rx.getAllocated(0, 1);
            if (slice.len == 0) return error.Exhausted;
            const pkt = &slice[0];
            return .{
                .payload = pkt.payload[0..pkt.payload_len],
                .src_addr = pkt.src_addr,
            };
        }

        // -- Poll scheduling --

        pub fn pollAt(self: Self) ?Instant {
            if (!self.tx.isEmpty()) return Instant.ZERO;
            return null;
        }

        // -- Protocol integration --

        pub fn accepts(self: Self, protocol: ipv4.Protocol) bool {
            const bound = self.ip_protocol orelse return false;
            return bound == protocol;
        }

        pub fn process(self: *Self, src_addr: ipv4.Address, protocol: ipv4.Protocol, payload: []const u8) void {
            _ = protocol;
            const pkt = self.rx.enqueueOne() catch return;
            const copy_len = @min(payload.len, config.payload_size);
            @memcpy(pkt.payload[0..copy_len], payload[0..copy_len]);
            pkt.payload_len = copy_len;
            pkt.src_addr = src_addr;
        }

        pub fn peekDstAddr(self: *const Self) ?ipv4.Address {
            const slice = self.tx.getAllocated(0, 1);
            if (slice.len == 0) return null;
            return slice[0].src_addr;
        }

        pub fn dispatch(self: *Self) ?DispatchResult {
            const pkt = self.tx.dequeueOne() catch return null;
            return .{
                .ip_protocol = self.ip_protocol orelse return null,
                .dst_addr = pkt.src_addr,
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

const TestConfig = Config{ .payload_size = 64 };
const TestSocket = Socket(TestConfig);

const LOCAL_ADDR: ipv4.Address = .{ 192, 168, 1, 1 };
const REMOTE_ADDR: ipv4.Address = .{ 192, 168, 1, 2 };
const PAYLOAD = "hello raw";

fn newSocket() TestSocket {
    const S = struct {
        var rx: [4]TestSocket.Packet = undefined;
        var tx: [4]TestSocket.Packet = undefined;
    };
    return TestSocket.init(&S.rx, &S.tx);
}

fn boundSocket() TestSocket {
    var s = newSocket();
    s.bind(.udp) catch unreachable;
    return s;
}

// [smoltcp:socket/raw.rs:test_send_truncated]
test "raw send truncation" {
    var s = boundSocket();
    const big: [65]u8 = .{0xAA} ** 65;
    try testing.expectError(error.BufferFull, s.sendSlice(&big, REMOTE_ADDR));
}

// [smoltcp:socket/raw.rs:test_send_dispatch]
test "raw send dispatch roundtrip" {
    var s = boundSocket();
    try s.sendSlice(PAYLOAD, REMOTE_ADDR);
    const result = s.dispatch() orelse return try testing.expect(false);
    try testing.expectEqual(ipv4.Protocol.udp, result.ip_protocol);
    try testing.expect(std.mem.eql(u8, &REMOTE_ADDR, &result.dst_addr));
    try testing.expectEqualSlices(u8, PAYLOAD, result.payload);
}

// [smoltcp:socket/raw.rs:test_recv_process]
test "raw recv process roundtrip" {
    var s = boundSocket();
    s.process(REMOTE_ADDR, .udp, PAYLOAD);
    try testing.expect(s.canRecv());
    var buf: [64]u8 = undefined;
    const result = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, PAYLOAD.len), result.data_len);
    try testing.expect(std.mem.eql(u8, &REMOTE_ADDR, &result.src_addr));
    try testing.expectEqualSlices(u8, PAYLOAD, buf[0..result.data_len]);
}

// [smoltcp:socket/raw.rs:test_peek]
test "raw peek returns data without consuming" {
    var s = boundSocket();
    s.process(REMOTE_ADDR, .udp, PAYLOAD);
    const peek_result = try s.peek();
    try testing.expectEqualSlices(u8, PAYLOAD, peek_result.payload);
    try testing.expect(s.canRecv());
}

// [smoltcp:socket/raw.rs:test_recv_truncated]
test "raw recv truncated" {
    var s = boundSocket();
    s.process(REMOTE_ADDR, .udp, PAYLOAD);
    var small_buf: [2]u8 = undefined;
    try testing.expectError(error.Truncated, s.recvSlice(&small_buf));
}

test "raw accepts filters by protocol" {
    var s = boundSocket();
    try testing.expect(s.accepts(.udp));
    try testing.expect(!s.accepts(.tcp));
    try testing.expect(!s.accepts(.icmp));
}

test "raw unbound socket rejects all" {
    var s = newSocket();
    try testing.expect(!s.accepts(.udp));
    try testing.expect(!s.canSend());
    try testing.expectError(error.Unbound, s.sendSlice(PAYLOAD, REMOTE_ADDR));
}

test "raw close resets state" {
    var s = boundSocket();
    try s.sendSlice(PAYLOAD, REMOTE_ADDR);
    s.process(REMOTE_ADDR, .udp, PAYLOAD);
    try testing.expect(s.canSend());
    try testing.expect(s.canRecv());
    s.close();
    try testing.expect(!s.isOpen());
    try testing.expect(!s.canRecv());
}

test "raw pollAt returns ZERO when tx pending" {
    var s = boundSocket();
    try testing.expectEqual(@as(?Instant, null), s.pollAt());
    try s.sendSlice(PAYLOAD, REMOTE_ADDR);
    try testing.expectEqual(@as(?Instant, Instant.ZERO), s.pollAt());
}

test "raw setHopLimit validation" {
    var s = newSocket();
    try testing.expectError(error.InvalidHopLimit, s.setHopLimit(0));
    try s.setHopLimit(128);
    try testing.expectEqual(@as(?u8, 128), s.hop_limit);
    try s.setHopLimit(null);
    try testing.expectEqual(@as(?u8, null), s.hop_limit);
}

test "raw process truncates oversized payload" {
    var s = boundSocket();
    const big: [128]u8 = .{0xBB} ** 128;
    s.process(REMOTE_ADDR, .udp, &big);
    const peek_result = try s.peek();
    try testing.expectEqual(@as(usize, 64), peek_result.payload.len);
}
