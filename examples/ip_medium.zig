// Demo 6: Point-to-Point IP Medium (No Ethernet)
//
// Proves the Medium::Ip path works -- no MAC addresses, no ARP, no
// Ethernet framing. Raw IP packets shuttle directly between stacks.
// This is the path that matters for tunnels, serial links, and
// kernel-to-stack integration.
//
// Architecture:
//
//   Stack A                            Stack B
//   [UDP socket :5000]                 [UDP socket :6000]
//        |                                  |
//   IpDevice A  <------- shuttle -------> IpDevice B
//        (no ARP, no Ethernet headers)

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

fn IpLoopbackDevice(comptime max_frames: usize) type {
    return struct {
        const Self = @This();
        pub const medium: iface_mod.Medium = .ip;
        inner: stack_mod.LoopbackDevice(max_frames) = .{},

        pub fn receive(self: *Self) ?[]const u8 { return self.inner.receive(); }
        pub fn transmit(self: *Self, frame: []const u8) void { self.inner.transmit(frame); }
        pub fn enqueueRx(self: *Self, frame: []const u8) void { self.inner.enqueueRx(frame); }
        pub fn dequeueTx(self: *Self) ?[]const u8 { return self.inner.dequeueTx(); }
    };
}

const UdpSock = udp_socket.Socket(ipv4);
const Device = IpLoopbackDevice(16);
const Sockets = struct { udp4_sockets: []*UdpSock };
const IpStack = stack_mod.Stack(Device, Sockets);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 200;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP_B: ipv4.Address = .{ 10, 0, 0, 2 };

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

test "UDP echo over IP medium" {
    var dev_a: Device = .{};
    var dev_b: Device = .{};

    var a_rx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var a_rx_payload: [256]u8 = undefined;
    var a_tx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var a_tx_payload: [256]u8 = undefined;
    var sock_a = UdpSock.init(&a_rx_meta, &a_rx_payload, &a_tx_meta, &a_tx_payload);
    try sock_a.bind(.{ .port = 5000 });

    var b_rx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var b_rx_payload: [256]u8 = undefined;
    var b_tx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var b_tx_payload: [256]u8 = undefined;
    var sock_b = UdpSock.init(&b_rx_meta, &b_rx_payload, &b_tx_meta, &b_tx_payload);
    try sock_b.bind(.{ .port = 6000 });

    var arr_a = [_]*UdpSock{&sock_a};
    var arr_b = [_]*UdpSock{&sock_b};
    var stack_a = IpStack.init(MAC_A, .{ .udp4_sockets = &arr_a });
    var stack_b = IpStack.init(MAC_B, .{ .udp4_sockets = &arr_b });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    try sock_b.sendSlice("ping", .{
        .endpoint = .{ .addr = IP_A, .port = 5000 },
    });

    var cur_time = Instant.ZERO;
    var a_received = false;
    var b_received = false;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        if (!a_received and sock_a.canRecv()) {
            var buf: [64]u8 = undefined;
            const result = sock_a.recvSlice(&buf) catch continue;
            try std.testing.expectEqualSlices(u8, "ping", buf[0..result.data_len]);
            a_received = true;
            try sock_a.sendSlice("pong", .{ .endpoint = result.meta.endpoint });
        }

        if (a_received and !b_received and sock_b.canRecv()) {
            var buf: [64]u8 = undefined;
            const result = sock_b.recvSlice(&buf) catch continue;
            try std.testing.expectEqualSlices(u8, "pong", buf[0..result.data_len]);
            b_received = true;
        }

        if (b_received) break;

        if (earliestPollTime(stack_a.pollAt(), stack_b.pollAt())) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    try std.testing.expect(a_received);
    try std.testing.expect(b_received);
    try std.testing.expect(iter < MAX_ITERS);
}
