// Demo 10: IPv4 + IPv6 Dual-Stack Concurrent
//
// Proves both IPv4 and IPv6 sockets can operate simultaneously on the
// same stacks. TCP4 and UDP6 run concurrently through the same poll loop
// and the protocol demux correctly routes packets for both address families.
//
// Architecture:
//
//   Stack A (server side)              Stack B (client side)
//   [TCP4 server :4000]                [TCP4 client]
//   [UDP6 socket :5000]                [UDP6 socket :6000]
//        |                                  |
//   LoopbackDevice A <-- shuttle --> LoopbackDevice B
//        ARP (IPv4) + NDP (IPv6)

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const tcp_socket = zmoltcp.socket.tcp;
const udp_socket = zmoltcp.socket.udp;
const ipv4 = zmoltcp.wire.ipv4;
const ipv6 = zmoltcp.wire.ipv6;
const ethernet = zmoltcp.wire.ethernet;
const iface_mod = zmoltcp.iface;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const TcpSock4 = tcp_socket.Socket(ipv4, 4);
const UdpSock6 = udp_socket.Socket(ipv6);
const Device = stack_mod.LoopbackDevice(16);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 300;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP4_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP4_B: ipv4.Address = .{ 10, 0, 0, 2 };
const IP6_A: ipv6.Address = iface_mod.Interface.linkLocalFromMac(MAC_A);
const IP6_B: ipv6.Address = iface_mod.Interface.linkLocalFromMac(MAC_B);

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

test "IPv4 TCP + IPv6 UDP concurrent on dual-stack" {
    const Sockets = struct {
        tcp4_sockets: []*TcpSock4,
        udp6_sockets: []*UdpSock6,
    };
    const DualStack = stack_mod.Stack(Device, Sockets);

    // TCP4 sockets
    var srv_rx: [256]u8 = .{0} ** 256;
    var srv_tx: [256]u8 = .{0} ** 256;
    var cli_rx: [256]u8 = .{0} ** 256;
    var cli_tx: [256]u8 = .{0} ** 256;

    var tcp_srv = TcpSock4.init(&srv_rx, &srv_tx);
    var tcp_cli = TcpSock4.init(&cli_rx, &cli_tx);
    tcp_srv.ack_delay = null;
    tcp_cli.ack_delay = null;
    try tcp_srv.listen(.{ .port = 4000 });
    try tcp_cli.connect(IP4_A, 4000, IP4_B, 50000);

    // UDP6 sockets
    var ua_rx_meta: [2]UdpSock6.PacketMeta = .{ .{}, .{} };
    var ua_rx_pay: [256]u8 = undefined;
    var ua_tx_meta: [2]UdpSock6.PacketMeta = .{ .{}, .{} };
    var ua_tx_pay: [256]u8 = undefined;
    var udp_a = UdpSock6.init(&ua_rx_meta, &ua_rx_pay, &ua_tx_meta, &ua_tx_pay);
    try udp_a.bind(.{ .port = 5000 });

    var ub_rx_meta: [2]UdpSock6.PacketMeta = .{ .{}, .{} };
    var ub_rx_pay: [256]u8 = undefined;
    var ub_tx_meta: [2]UdpSock6.PacketMeta = .{ .{}, .{} };
    var ub_tx_pay: [256]u8 = undefined;
    var udp_b = UdpSock6.init(&ub_rx_meta, &ub_rx_pay, &ub_tx_meta, &ub_tx_pay);
    try udp_b.bind(.{ .port = 6000 });

    var tcp_arr_a = [_]*TcpSock4{&tcp_srv};
    var tcp_arr_b = [_]*TcpSock4{&tcp_cli};
    var udp_arr_a = [_]*UdpSock6{&udp_a};
    var udp_arr_b = [_]*UdpSock6{&udp_b};

    var dev_a: Device = .{};
    var dev_b: Device = .{};

    var stack_a = DualStack.init(MAC_A, .{
        .tcp4_sockets = &tcp_arr_a,
        .udp6_sockets = &udp_arr_a,
    });
    var stack_b = DualStack.init(MAC_B, .{
        .tcp4_sockets = &tcp_arr_b,
        .udp6_sockets = &udp_arr_b,
    });

    // Configure IPv4
    stack_a.iface.v4.addIpAddr(.{ .address = IP4_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP4_B, .prefix_len = 24 });
    // Configure IPv6
    stack_a.iface.setIpv6Addrs(&.{.{ .address = IP6_A, .prefix_len = 64 }});
    stack_b.iface.setIpv6Addrs(&.{.{ .address = IP6_B, .prefix_len = 64 }});

    // Pre-fill neighbor caches for determinism
    stack_a.iface.neighbor_cache.fill(IP4_B, MAC_B, Instant.ZERO);
    stack_b.iface.neighbor_cache.fill(IP4_A, MAC_A, Instant.ZERO);
    stack_a.iface.neighbor_cache_v6.fill(IP6_B, MAC_B, Instant.ZERO);
    stack_b.iface.neighbor_cache_v6.fill(IP6_A, MAC_A, Instant.ZERO);

    // Queue UDP6 send
    try udp_b.sendSlice("dual-udp6", .{
        .endpoint = .{ .addr = IP6_A, .port = 5000 },
    });

    var cur_time = Instant.ZERO;
    var tcp_cli_sent = false;
    var tcp_srv_echoed = false;
    var tcp_cli_received = false;
    var udp_a_received = false;
    var udp_b_received = false;
    var recv_buf: [64]u8 = undefined;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        // TCP4: client sends
        if (!tcp_cli_sent and tcp_cli.getState() == .established and tcp_cli.canSend()) {
            _ = tcp_cli.sendSlice("dual-tcp4") catch 0;
            tcp_cli_sent = true;
        }

        // TCP4: server echoes
        if (!tcp_srv_echoed and tcp_srv.getState() == .established and tcp_srv.canRecv()) {
            const n = tcp_srv.recvSlice(&recv_buf) catch 0;
            if (n > 0) {
                try std.testing.expectEqualSlices(u8, "dual-tcp4", recv_buf[0..n]);
                _ = tcp_srv.sendSlice(recv_buf[0..n]) catch 0;
                tcp_srv.close();
                tcp_srv_echoed = true;
            }
        }

        // TCP4: client receives echo
        if (tcp_cli_sent and !tcp_cli_received and tcp_cli.canRecv()) {
            const n = tcp_cli.recvSlice(&recv_buf) catch 0;
            if (n > 0) {
                try std.testing.expectEqualSlices(u8, "dual-tcp4", recv_buf[0..n]);
                tcp_cli.close();
                tcp_cli_received = true;
            }
        }

        // UDP6: A receives and replies
        if (!udp_a_received and udp_a.canRecv()) {
            const result = udp_a.recvSlice(&recv_buf) catch continue;
            try std.testing.expectEqualSlices(u8, "dual-udp6", recv_buf[0..result.data_len]);
            udp_a_received = true;
            try udp_a.sendSlice("dual-udp6-reply", .{ .endpoint = result.meta.endpoint });
        }

        // UDP6: B receives reply
        if (udp_a_received and !udp_b_received and udp_b.canRecv()) {
            const result = udp_b.recvSlice(&recv_buf) catch continue;
            try std.testing.expectEqualSlices(u8, "dual-udp6-reply", recv_buf[0..result.data_len]);
            udp_b_received = true;
        }

        if (tcp_cli_received and udp_b_received) {
            const s_done = tcp_srv.getState() == .closed or tcp_srv.getState() == .time_wait;
            const c_done = tcp_cli.getState() == .closed or tcp_cli.getState() == .time_wait;
            if (s_done and c_done) break;
        }

        if (earliestPollTime(stack_a.pollAt(), stack_b.pollAt())) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    try std.testing.expect(tcp_cli_sent);
    try std.testing.expect(tcp_srv_echoed);
    try std.testing.expect(tcp_cli_received);
    try std.testing.expect(udp_a_received);
    try std.testing.expect(udp_b_received);
    try std.testing.expect(iter < MAX_ITERS);
}
