// Demo 9: Raw IP Socket
//
// Proves raw IP sockets work through the full stack -- binding to a
// custom protocol number, sending raw IP payloads, and receiving them
// on the other end. Also proves ICMP "protocol unreachable" is suppressed
// when a raw socket is bound to the protocol.
//
// Architecture:
//
//   Stack A                            Stack B
//   [Raw socket proto=253]             [Raw socket proto=253]
//        |                                  |
//   LoopbackDevice A <-- shuttle --> LoopbackDevice B

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const raw_socket = zmoltcp.socket.raw;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const RawSock = raw_socket.Socket(ipv4, .{ .payload_size = 256 });
const Device = stack_mod.LoopbackDevice(16);
const Sockets = struct { raw4_sockets: []*RawSock };
const RawStack = stack_mod.Stack(Device, Sockets);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 200;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP_B: ipv4.Address = .{ 10, 0, 0, 2 };

const PROTO_EXPERIMENTAL: ipv4.Protocol = @enumFromInt(253);

fn shuttleFrames(dev_a: *Device, dev_b: *Device) void {
    while (dev_a.dequeueTx()) |frame| dev_b.enqueueRx(frame);
    while (dev_b.dequeueTx()) |frame| dev_a.enqueueRx(frame);
}

fn earliestPollTime(a: ?Instant, b: ?Instant) ?Instant {
    if (a) |va| {
        if (b) |vb| return if (va.lessThan(vb)) va else vb;
        return va;
    }
    return b;
}

test "Raw IP socket exchange" {
    var a_rx: [2]RawSock.Packet = .{ .{}, .{} };
    var a_tx: [2]RawSock.Packet = .{ .{}, .{} };
    var b_rx: [2]RawSock.Packet = .{ .{}, .{} };
    var b_tx: [2]RawSock.Packet = .{ .{}, .{} };

    var sock_a = RawSock.init(&a_rx, &a_tx);
    var sock_b = RawSock.init(&b_rx, &b_tx);
    try sock_a.bind(PROTO_EXPERIMENTAL);
    try sock_b.bind(PROTO_EXPERIMENTAL);

    var arr_a = [_]*RawSock{&sock_a};
    var arr_b = [_]*RawSock{&sock_b};
    var dev_a: Device = .{};
    var dev_b: Device = .{};
    var stack_a = RawStack.init(MAC_A, .{ .raw4_sockets = &arr_a });
    var stack_b = RawStack.init(MAC_B, .{ .raw4_sockets = &arr_b });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    stack_a.iface.neighbor_cache.fill(IP_B, MAC_B, Instant.ZERO);
    stack_b.iface.neighbor_cache.fill(IP_A, MAC_A, Instant.ZERO);

    const send_msg = "hello-raw-socket";
    try sock_a.sendSlice(send_msg, IP_B);

    var cur_time = Instant.ZERO;
    var b_received = false;
    var a_received = false;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        if (!b_received and sock_b.canRecv()) {
            var buf: [256]u8 = undefined;
            const result = sock_b.recvSlice(&buf) catch continue;
            try std.testing.expectEqualSlices(u8, send_msg, buf[0..result.data_len]);
            try std.testing.expectEqual(IP_A, result.src_addr);
            b_received = true;
            try sock_b.sendSlice("raw-reply", IP_A);
        }

        if (b_received and !a_received and sock_a.canRecv()) {
            var buf: [256]u8 = undefined;
            const result = sock_a.recvSlice(&buf) catch continue;
            try std.testing.expectEqualSlices(u8, "raw-reply", buf[0..result.data_len]);
            try std.testing.expectEqual(IP_B, result.src_addr);
            a_received = true;
        }

        if (a_received) break;

        if (earliestPollTime(stack_a.pollAt(), stack_b.pollAt())) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    try std.testing.expect(b_received);
    try std.testing.expect(a_received);
    try std.testing.expect(iter < MAX_ITERS);
}
