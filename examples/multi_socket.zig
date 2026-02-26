// Demo 8: Multi-Protocol Concurrent Exchange
//
// Proves TCP, UDP, and ICMP all coexist on the same stacks and the
// protocol demux correctly routes packets when all three are active
// simultaneously.
//
// Architecture:
//
//   Stack A (server side)              Stack B (client side)
//   [TCP server :4000]                 [TCP client]
//   [UDP socket :5000]                 [UDP socket :6000]
//   [ICMP ident=0x1234]
//        |                                  |
//   LoopbackDevice A <-- shuttle --> LoopbackDevice B
//
// Concurrent activities:
//   1. TCP: B connects to A, sends "zmoltcp", A echoes, both close
//   2. UDP: B sends "udp-ping" to A:5000, A replies "udp-pong"
//   3. ICMP: A sends echo request to B, B auto-replies

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const tcp_socket = zmoltcp.socket.tcp;
const udp_socket = zmoltcp.socket.udp;
const icmp_socket = zmoltcp.socket.icmp;
const icmp_wire = zmoltcp.wire.icmp;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const TcpSock = tcp_socket.Socket(ipv4, 4);
const UdpSock = udp_socket.Socket(ipv4);
const IcmpSock = icmp_socket.Socket(ipv4);
const Device = stack_mod.LoopbackDevice(16);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 300;

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

test "TCP + UDP + ICMP concurrent exchange" {
    // --- Stack A sockets: TCP server + UDP + ICMP ---
    var tcp_srv_rx: [256]u8 = .{0} ** 256;
    var tcp_srv_tx: [256]u8 = .{0} ** 256;
    var tcp_srv = TcpSock.init(&tcp_srv_rx, &tcp_srv_tx);
    tcp_srv.ack_delay = null;
    try tcp_srv.listen(.{ .port = 4000 });

    var udp_a_rx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var udp_a_rx_pay: [256]u8 = undefined;
    var udp_a_tx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var udp_a_tx_pay: [256]u8 = undefined;
    var udp_a = UdpSock.init(&udp_a_rx_meta, &udp_a_rx_pay, &udp_a_tx_meta, &udp_a_tx_pay);
    try udp_a.bind(.{ .port = 5000 });

    var icmp_rx_meta: [2]IcmpSock.PacketMeta = .{ .{}, .{} };
    var icmp_rx_pay: [256]u8 = undefined;
    var icmp_tx_meta: [2]IcmpSock.PacketMeta = .{ .{}, .{} };
    var icmp_tx_pay: [256]u8 = undefined;
    var icmp_a = IcmpSock.init(&icmp_rx_meta, &icmp_rx_pay, &icmp_tx_meta, &icmp_tx_pay);
    try icmp_a.bind(.{ .ident = 0x1234 });

    // --- Stack B sockets: TCP client + UDP ---
    var tcp_cli_rx: [256]u8 = .{0} ** 256;
    var tcp_cli_tx: [256]u8 = .{0} ** 256;
    var tcp_cli = TcpSock.init(&tcp_cli_rx, &tcp_cli_tx);
    tcp_cli.ack_delay = null;
    try tcp_cli.connect(IP_A, 4000, IP_B, 50000);

    var udp_b_rx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var udp_b_rx_pay: [256]u8 = undefined;
    var udp_b_tx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var udp_b_tx_pay: [256]u8 = undefined;
    var udp_b = UdpSock.init(&udp_b_rx_meta, &udp_b_rx_pay, &udp_b_tx_meta, &udp_b_tx_pay);
    try udp_b.bind(.{ .port = 6000 });

    // --- Build stacks ---
    const SocketsA = struct {
        tcp4_sockets: []*TcpSock,
        udp4_sockets: []*UdpSock,
        icmp4_sockets: []*IcmpSock,
    };
    const SocketsB = struct {
        tcp4_sockets: []*TcpSock,
        udp4_sockets: []*UdpSock,
    };
    const StackA = stack_mod.Stack(Device, SocketsA);
    const StackB = stack_mod.Stack(Device, SocketsB);

    var tcp_arr_a = [_]*TcpSock{&tcp_srv};
    var udp_arr_a = [_]*UdpSock{&udp_a};
    var icmp_arr_a = [_]*IcmpSock{&icmp_a};
    var tcp_arr_b = [_]*TcpSock{&tcp_cli};
    var udp_arr_b = [_]*UdpSock{&udp_b};

    var dev_a: Device = .{};
    var dev_b: Device = .{};

    var stack_a = StackA.init(MAC_A, .{
        .tcp4_sockets = &tcp_arr_a,
        .udp4_sockets = &udp_arr_a,
        .icmp4_sockets = &icmp_arr_a,
    });
    var stack_b = StackB.init(MAC_B, .{
        .tcp4_sockets = &tcp_arr_b,
        .udp4_sockets = &udp_arr_b,
    });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    // --- Pre-enqueue UDP and ICMP sends ---
    try udp_b.sendSlice("udp-ping", .{
        .endpoint = .{ .addr = IP_A, .port = 5000 },
    });

    const echo_payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var icmp_buf: [icmp_wire.HEADER_LEN + echo_payload.len]u8 = undefined;
    _ = icmp_wire.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 1,
    }, &echo_payload, &icmp_buf) catch unreachable;
    try icmp_a.sendSlice(&icmp_buf, IP_B);

    // --- Poll loop ---
    var cur_time = Instant.ZERO;

    var tcp_cli_sent = false;
    var tcp_srv_echoed = false;
    var tcp_cli_received = false;
    var udp_a_received = false;
    var udp_b_received = false;
    var icmp_got_reply = false;

    var recv_buf: [64]u8 = undefined;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        // --- TCP: client sends, server echoes ---
        if (!tcp_cli_sent and tcp_cli.getState() == .established and tcp_cli.canSend()) {
            _ = tcp_cli.sendSlice("zmoltcp") catch 0;
            tcp_cli_sent = true;
        }

        if (!tcp_srv_echoed and tcp_srv.getState() == .established and tcp_srv.canRecv()) {
            const n = tcp_srv.recvSlice(&recv_buf) catch 0;
            if (n > 0) {
                try std.testing.expectEqualSlices(u8, "zmoltcp", recv_buf[0..n]);
                _ = tcp_srv.sendSlice(recv_buf[0..n]) catch 0;
                tcp_srv.close();
                tcp_srv_echoed = true;
            }
        }

        if (tcp_cli_sent and !tcp_cli_received and tcp_cli.canRecv()) {
            const n = tcp_cli.recvSlice(&recv_buf) catch 0;
            if (n > 0) {
                try std.testing.expectEqualSlices(u8, "zmoltcp", recv_buf[0..n]);
                tcp_cli.close();
                tcp_cli_received = true;
            }
        }

        // --- UDP: A receives ping, sends pong ---
        if (!udp_a_received and udp_a.canRecv()) {
            const result = udp_a.recvSlice(&recv_buf) catch continue;
            try std.testing.expectEqualSlices(u8, "udp-ping", recv_buf[0..result.data_len]);
            udp_a_received = true;
            try udp_a.sendSlice("udp-pong", .{ .endpoint = result.meta.endpoint });
        }

        if (udp_a_received and !udp_b_received and udp_b.canRecv()) {
            const result = udp_b.recvSlice(&recv_buf) catch continue;
            try std.testing.expectEqualSlices(u8, "udp-pong", recv_buf[0..result.data_len]);
            udp_b_received = true;
        }

        // --- ICMP: A receives echo reply ---
        if (!icmp_got_reply and icmp_a.canRecv()) {
            const result = icmp_a.recvSlice(&recv_buf) catch continue;
            const reply = icmp_wire.parse(recv_buf[0..result.data_len]) catch continue;
            switch (reply) {
                .echo => |echo| {
                    if (echo.icmp_type == .echo_reply and echo.identifier == 0x1234) {
                        icmp_got_reply = true;
                    }
                },
                .other => {},
            }
        }

        // All three protocols complete?
        if (tcp_cli_received and udp_b_received and icmp_got_reply) {
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
    try std.testing.expect(icmp_got_reply);
    try std.testing.expect(iter < MAX_ITERS);
}
