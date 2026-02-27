// Demo 14: IEEE 802.15.4 / 6LoWPAN
//
// Proves the constrained-network IoT path works end-to-end: 802.15.4
// MAC framing, 6LoWPAN IPHC header compression, UDP NHC, and IPv6
// delivery through the stack. Two 802.15.4 stacks exchange UDP
// datagrams over link-local IPv6 addresses derived from EUI-64.
//
// Architecture:
//
//   Stack A                            Stack B
//   [UDP6 socket :5000]                [UDP6 socket :6000]
//        |                                  |
//   802154Device A <--- shuttle ---> 802154Device B
//        (IPHC + NHC compressed, 127-byte MTU)

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const udp_socket = zmoltcp.socket.udp;
const ipv6 = zmoltcp.wire.ipv6;
const ethernet = zmoltcp.wire.ethernet;
const ieee802154 = zmoltcp.wire.ieee802154;
const iface_mod = zmoltcp.iface;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

fn Ieee802154LoopbackDevice(comptime max_frames: usize) type {
    return struct {
        const Self = @This();
        pub const medium: iface_mod.Medium = .ieee802154;
        inner: stack_mod.LoopbackDevice(max_frames) = .{},

        pub fn receive(self: *Self) ?[]const u8 { return self.inner.receive(); }
        pub fn transmit(self: *Self, frame: []const u8) void { self.inner.transmit(frame); }
        pub fn enqueueRx(self: *Self, data: []const u8) void { self.inner.enqueueRx(data); }
        pub fn dequeueTx(self: *Self) ?[]const u8 { return self.inner.dequeueTx(); }
        pub fn capabilities() iface_mod.DeviceCapabilities {
            return .{ .max_transmission_unit = ieee802154.MAX_FRAME_LEN };
        }
    };
}

const UdpSock = udp_socket.Socket(ipv6);
const Device = Ieee802154LoopbackDevice(16);
const Sockets = struct { udp6_sockets: []*UdpSock };
const LpStack = stack_mod.Stack(Device, Sockets);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 200;

const PAN_ID: u16 = 0xABCD;

const EUI_A = [8]u8{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 };
const EUI_B = [8]u8{ 0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf };

// Dummy MAC addresses (802.15.4 stacks don't use Ethernet MACs for
// on-wire framing, but Stack.init requires one).
const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };

const IP6_A: ipv6.Address = (ieee802154.Address{ .extended = EUI_A }).asLinkLocalAddress();
const IP6_B: ipv6.Address = (ieee802154.Address{ .extended = EUI_B }).asLinkLocalAddress();

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

test "UDP over 6LoWPAN between two 802.15.4 stacks" {
    var dev_a: Device = .{};
    var dev_b: Device = .{};

    var a_rx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var a_rx_pay: [256]u8 = undefined;
    var a_tx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var a_tx_pay: [256]u8 = undefined;
    var sock_a = UdpSock.init(&a_rx_meta, &a_rx_pay, &a_tx_meta, &a_tx_pay);
    try sock_a.bind(.{ .port = 5000 });

    var b_rx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var b_rx_pay: [256]u8 = undefined;
    var b_tx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var b_tx_pay: [256]u8 = undefined;
    var sock_b = UdpSock.init(&b_rx_meta, &b_rx_pay, &b_tx_meta, &b_tx_pay);
    try sock_b.bind(.{ .port = 6000 });

    var arr_a = [_]*UdpSock{&sock_a};
    var arr_b = [_]*UdpSock{&sock_b};

    var stack_a = LpStack.init(MAC_A, .{ .udp6_sockets = &arr_a });
    var stack_b = LpStack.init(MAC_B, .{ .udp6_sockets = &arr_b });

    stack_a.sixlowpan_pan_id = PAN_ID;
    stack_a.sixlowpan_ll_addr = .{ .extended = EUI_A };
    stack_b.sixlowpan_pan_id = PAN_ID;
    stack_b.sixlowpan_ll_addr = .{ .extended = EUI_B };

    stack_a.iface.setIpv6Addrs(&.{.{ .address = IP6_A, .prefix_len = 64 }});
    stack_b.iface.setIpv6Addrs(&.{.{ .address = IP6_B, .prefix_len = 64 }});

    try sock_b.sendSlice("hello-6lowpan", .{
        .endpoint = .{ .addr = IP6_A, .port = 5000 },
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
            try std.testing.expectEqualSlices(u8, "hello-6lowpan", buf[0..result.data_len]);
            a_received = true;
            try sock_a.sendSlice("6lowpan-reply", .{ .endpoint = result.meta.endpoint });
        }

        if (a_received and !b_received and sock_b.canRecv()) {
            var buf: [64]u8 = undefined;
            const result = sock_b.recvSlice(&buf) catch continue;
            try std.testing.expectEqualSlices(u8, "6lowpan-reply", buf[0..result.data_len]);
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
