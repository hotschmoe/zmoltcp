// Demo 7: IPv4 Fragmentation and Reassembly
//
// Proves large packets are correctly fragmented on egress and
// reassembled on ingress. Stack A has a small-MTU device (576 bytes),
// so a 600-byte UDP payload triggers IPv4 fragmentation. The fragments
// shuttle to Stack B (normal MTU) which reassembles and delivers the
// full datagram to its UDP socket.
//
// Architecture:
//
//   Stack A (sender)                   Stack B (receiver)
//   [UDP socket :8000]                 [UDP socket :9000]
//        |                                  |
//   SmallMtuDevice A               LoopbackDevice B
//   (MTU=576, fragments)           (MTU=1514, reassembles)
//        |                                  |
//        +---------- shuttle --------------+

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const udp_socket = zmoltcp.socket.udp;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const iface_mod = zmoltcp.iface;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

fn SmallMtuDevice(comptime max_frames: usize) type {
    return struct {
        const Self = @This();
        inner: stack_mod.LoopbackDevice(max_frames) = .{},

        pub fn capabilities() iface_mod.DeviceCapabilities {
            return .{ .max_transmission_unit = 576 };
        }
        pub fn receive(self: *Self) ?[]const u8 { return self.inner.receive(); }
        pub fn transmit(self: *Self, frame: []const u8) void { self.inner.transmit(frame); }
        pub fn enqueueRx(self: *Self, frame: []const u8) void { self.inner.enqueueRx(frame); }
        pub fn dequeueTx(self: *Self) ?[]const u8 { return self.inner.dequeueTx(); }
    };
}

const UdpSock = udp_socket.Socket(ipv4);
const SenderDevice = SmallMtuDevice(16);
const ReceiverDevice = stack_mod.LoopbackDevice(16);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 200;
const PAYLOAD_LEN: usize = 600;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP_B: ipv4.Address = .{ 10, 0, 0, 2 };

fn generatePattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i);
}

fn shuttleCross(dev_a: *SenderDevice, dev_b: *ReceiverDevice) void {
    while (dev_a.inner.dequeueTx()) |frame| dev_b.enqueueRx(frame);
    while (dev_b.dequeueTx()) |frame| dev_a.inner.enqueueRx(frame);
}

fn earliestPollTime(a: ?Instant, b: ?Instant) ?Instant {
    if (a) |va| {
        if (b) |vb| return if (va.lessThan(vb)) va else vb;
        return va;
    }
    return b;
}

test "large UDP datagram fragmented and reassembled" {
    const SenderSockets = struct { udp4_sockets: []*UdpSock };
    const ReceiverSockets = struct { udp4_sockets: []*UdpSock };
    const SenderStack = stack_mod.Stack(SenderDevice, SenderSockets);
    const ReceiverStack = stack_mod.Stack(ReceiverDevice, ReceiverSockets);

    var dev_a: SenderDevice = .{};
    var dev_b: ReceiverDevice = .{};

    var a_rx_meta: [1]UdpSock.PacketMeta = .{.{}};
    var a_rx_payload: [64]u8 = undefined;
    var a_tx_meta: [1]UdpSock.PacketMeta = .{.{}};
    var a_tx_payload: [1024]u8 = undefined;
    var sock_a = UdpSock.init(&a_rx_meta, &a_rx_payload, &a_tx_meta, &a_tx_payload);
    try sock_a.bind(.{ .port = 8000 });

    var b_rx_meta: [1]UdpSock.PacketMeta = .{.{}};
    var b_rx_payload: [1024]u8 = undefined;
    var b_tx_meta: [1]UdpSock.PacketMeta = .{.{}};
    var b_tx_payload: [64]u8 = undefined;
    var sock_b = UdpSock.init(&b_rx_meta, &b_rx_payload, &b_tx_meta, &b_tx_payload);
    try sock_b.bind(.{ .port = 9000 });

    var arr_a = [_]*UdpSock{&sock_a};
    var arr_b = [_]*UdpSock{&sock_b};
    var stack_a = SenderStack.init(MAC_A, .{ .udp4_sockets = &arr_a });
    var stack_b = ReceiverStack.init(MAC_B, .{ .udp4_sockets = &arr_b });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    var send_data: [PAYLOAD_LEN]u8 = undefined;
    generatePattern(&send_data);

    try sock_a.sendSlice(&send_data, .{
        .endpoint = .{ .addr = IP_B, .port = 9000 },
    });

    var cur_time = Instant.ZERO;
    var received = false;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleCross(&dev_a, &dev_b);

        if (!received and sock_b.canRecv()) {
            var buf: [1024]u8 = undefined;
            const result = sock_b.recvSlice(&buf) catch continue;
            try std.testing.expectEqual(PAYLOAD_LEN, result.data_len);
            try std.testing.expectEqualSlices(u8, &send_data, buf[0..result.data_len]);
            received = true;
        }

        if (received) break;

        if (earliestPollTime(stack_a.pollAt(), stack_b.pollAt())) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    try std.testing.expect(received);
    try std.testing.expect(iter < MAX_ITERS);
}
