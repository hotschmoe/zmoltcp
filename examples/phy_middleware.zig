// Demo 12: PHY Middleware Composition
//
// Proves the PHY middleware layer composes correctly through the full
// stack. Stack A uses PcapWriter(Tracer(LoopbackDevice)) to demonstrate
// that Tracer callbacks fire and PcapWriter produces structurally valid
// pcap output. Stack B uses a plain LoopbackDevice.
//
// Architecture:
//
//   Stack A                                Stack B
//   [UDP socket :5000]                     [UDP socket :6000]
//        |                                      |
//   PcapWriter(Tracer(LoopbackDevice))     LoopbackDevice B
//        |  (traces + pcap capture)
//        +------------ shuttle ----------------+

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const udp_socket = zmoltcp.socket.udp;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const phy = zmoltcp.phy;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const UdpSock = udp_socket.Socket(ipv4);
const BaseDevice = stack_mod.LoopbackDevice(16);
const TracedDevice = phy.Tracer(BaseDevice);
const CaptureDevice = phy.PcapWriter(TracedDevice);
const DeviceB = stack_mod.LoopbackDevice(16);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 200;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP_B: ipv4.Address = .{ 10, 0, 0, 2 };

const TraceState = struct {
    var rx_count: usize = 0;
    var tx_count: usize = 0;

    fn trace(dir: TracedDevice.Direction, _: []const u8) void {
        switch (dir) {
            .rx => rx_count += 1,
            .tx => tx_count += 1,
        }
    }

    fn reset() void {
        rx_count = 0;
        tx_count = 0;
    }
};

const PcapState = struct {
    var buf: [8192]u8 = undefined;
    var pos: usize = 0;

    fn write(data: []const u8) void {
        if (pos + data.len <= buf.len) {
            @memcpy(buf[pos..][0..data.len], data);
            pos += data.len;
        }
    }

    fn reset() void {
        pos = 0;
    }
};

fn shuttleFrames(dev_a: *CaptureDevice, dev_b: *DeviceB) void {
    while (dev_a.inner.inner.dequeueTx()) |frame| dev_b.enqueueRx(frame);
    while (dev_b.dequeueTx()) |frame| dev_a.inner.inner.enqueueRx(frame);
}

fn earliestPollTime(a: ?Instant, b: ?Instant) ?Instant {
    if (a) |va| {
        if (b) |vb| return if (va.lessThan(vb)) va else vb;
        return va;
    }
    return b;
}

test "PHY middleware Tracer + PcapWriter composition" {
    const SocketsA = struct { udp4_sockets: []*UdpSock };
    const SocketsB = struct { udp4_sockets: []*UdpSock };
    const StackA = stack_mod.Stack(CaptureDevice, SocketsA);
    const StackB = stack_mod.Stack(DeviceB, SocketsB);

    TraceState.reset();
    PcapState.reset();

    var dev_a = CaptureDevice.init(
        TracedDevice.init(BaseDevice{}, &TraceState.trace),
        &PcapState.write,
        .both,
    );
    var dev_b: DeviceB = .{};

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

    var stack_a = StackA.init(MAC_A, .{ .udp4_sockets = &arr_a });
    var stack_b = StackB.init(MAC_B, .{ .udp4_sockets = &arr_b });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    // Pre-fill caches for determinism.
    stack_a.iface.neighbor_cache.fill(IP_B, MAC_B, Instant.ZERO);
    stack_b.iface.neighbor_cache.fill(IP_A, MAC_A, Instant.ZERO);

    try sock_b.sendSlice("middleware-test", .{
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
            try std.testing.expectEqualSlices(u8, "middleware-test", buf[0..result.data_len]);
            a_received = true;
            try sock_a.sendSlice("middleware-reply", .{ .endpoint = result.meta.endpoint });
        }

        if (a_received and !b_received and sock_b.canRecv()) {
            var buf: [64]u8 = undefined;
            const result = sock_b.recvSlice(&buf) catch continue;
            try std.testing.expectEqualSlices(u8, "middleware-reply", buf[0..result.data_len]);
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

    // Verify Tracer fired: rx and tx counters should both be > 0.
    try std.testing.expect(TraceState.rx_count > 0);
    try std.testing.expect(TraceState.tx_count > 0);

    // Verify PcapWriter produced valid output.
    const pcap = PcapState.buf[0..PcapState.pos];
    try std.testing.expect(pcap.len > 24);

    // Pcap magic number (little-endian 0xa1b2c3d4).
    try std.testing.expectEqual(@as(u8, 0xd4), pcap[0]);
    try std.testing.expectEqual(@as(u8, 0xc3), pcap[1]);
    try std.testing.expectEqual(@as(u8, 0xb2), pcap[2]);
    try std.testing.expectEqual(@as(u8, 0xa1), pcap[3]);

    // Linktype at offset 20: 1 = Ethernet.
    try std.testing.expectEqual(@as(u8, 1), pcap[20]);
    try std.testing.expectEqual(@as(u8, 0), pcap[21]);
    try std.testing.expectEqual(@as(u8, 0), pcap[22]);
    try std.testing.expectEqual(@as(u8, 0), pcap[23]);
}
