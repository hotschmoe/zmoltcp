// Demo 4: IPv6 TCP Echo + ICMPv6 Ping
//
// Proves IPv6 works end-to-end through the stack -- NDP neighbor
// discovery, TCP6 three-way handshake, data echo, graceful close,
// and ICMPv6 echo request/reply.
//
// Architecture:
//
//   Stack A (server)                  Stack B (client)
//   [TCP6 socket] [ICMPv6 socket]    [TCP6 socket]
//        |                                |
//   LoopbackDevice A <-- shuttle --> LoopbackDevice B
//        NDP (NS/NA instead of ARP)
//
// Part 1: TCP6 echo -- B connects, sends data, A echoes, both close
// Part 2: ICMPv6 ping -- A sends echo request, B auto-replies

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const tcp_socket = zmoltcp.socket.tcp;
const icmp_socket = zmoltcp.socket.icmp;
const icmpv6_wire = zmoltcp.wire.icmpv6;
const ipv6 = zmoltcp.wire.ipv6;
const ethernet = zmoltcp.wire.ethernet;
const iface_mod = zmoltcp.iface;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const TcpSock = tcp_socket.Socket(ipv6, 4);
const IcmpSock = icmp_socket.Socket(ipv6);
const Device = stack_mod.LoopbackDevice(16);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 300;
const MESSAGE = "Hello, IPv6!";

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };

// Link-local addresses matching EUI-64 derivation from the MACs.
const IP_A: ipv6.Address = iface_mod.Interface.linkLocalFromMac(MAC_A);
const IP_B: ipv6.Address = iface_mod.Interface.linkLocalFromMac(MAC_B);

const SERVER_PORT: u16 = 4000;
const CLIENT_PORT: u16 = 50000;

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

test "TCP6 echo between two stacks" {
    const Sockets = struct { tcp6_sockets: []*TcpSock };
    const V6Stack = stack_mod.Stack(Device, Sockets);

    var server_rx: [256]u8 = .{0} ** 256;
    var server_tx: [256]u8 = .{0} ** 256;
    var client_rx: [256]u8 = .{0} ** 256;
    var client_tx: [256]u8 = .{0} ** 256;

    var server = TcpSock.init(&server_rx, &server_tx);
    var client = TcpSock.init(&client_rx, &client_tx);
    server.ack_delay = null;
    client.ack_delay = null;

    try server.listen(.{ .port = SERVER_PORT });
    try client.connect(IP_A, SERVER_PORT, IP_B, CLIENT_PORT);

    var arr_a = [_]*TcpSock{&server};
    var arr_b = [_]*TcpSock{&client};
    var dev_a: Device = .{};
    var dev_b: Device = .{};
    var stack_a = V6Stack.init(MAC_A, .{ .tcp6_sockets = &arr_a });
    var stack_b = V6Stack.init(MAC_B, .{ .tcp6_sockets = &arr_b });
    stack_a.iface.setIpv6Addrs(&.{.{ .address = IP_A, .prefix_len = 64 }});
    stack_b.iface.setIpv6Addrs(&.{.{ .address = IP_B, .prefix_len = 64 }});

    // Pre-seed neighbor caches so the demo focuses on TCP, not NDP.
    stack_a.iface.neighbor_cache_v6.fill(IP_B, MAC_B, Instant.ZERO);
    stack_b.iface.neighbor_cache_v6.fill(IP_A, MAC_A, Instant.ZERO);

    var cur_time = Instant.ZERO;
    var client_sent = false;
    var server_echoed = false;
    var client_received = false;
    var recv_buf: [64]u8 = undefined;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        if (!server_echoed and server.getState() == .established and server.canRecv()) {
            const n = server.recvSlice(&recv_buf) catch 0;
            if (n > 0) {
                try std.testing.expectEqualSlices(u8, MESSAGE, recv_buf[0..n]);
                _ = server.sendSlice(recv_buf[0..n]) catch 0;
                server.close();
                server_echoed = true;
            }
        }

        if (!client_sent and client.getState() == .established and client.canSend()) {
            _ = client.sendSlice(MESSAGE) catch 0;
            client_sent = true;
        }

        if (client_sent and !client_received and client.canRecv()) {
            const n = client.recvSlice(&recv_buf) catch 0;
            if (n > 0) {
                try std.testing.expectEqualSlices(u8, MESSAGE, recv_buf[0..n]);
                client.close();
                client_received = true;
            }
        }

        if (client_received and server_echoed) {
            const s_done = server.getState() == .closed or server.getState() == .time_wait;
            const c_done = client.getState() == .closed or client.getState() == .time_wait;
            if (s_done and c_done) break;
        }

        if (earliestPollTime(stack_a.pollAt(), stack_b.pollAt())) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    try std.testing.expect(client_sent);
    try std.testing.expect(server_echoed);
    try std.testing.expect(client_received);
    try std.testing.expect(iter < MAX_ITERS);
}

test "ICMPv6 ping with NDP discovery" {
    const IcmpSockets = struct { icmp6_sockets: []*IcmpSock };
    const IcmpStack = stack_mod.Stack(Device, IcmpSockets);
    const NoSocketStack = stack_mod.Stack(Device, void);

    var dev_a: Device = .{};
    var dev_b: Device = .{};

    var a_rx_meta: [2]IcmpSock.PacketMeta = .{ .{}, .{} };
    var a_rx_payload: [256]u8 = undefined;
    var a_tx_meta: [2]IcmpSock.PacketMeta = .{ .{}, .{} };
    var a_tx_payload: [256]u8 = undefined;
    var icmp_sock = IcmpSock.init(&a_rx_meta, &a_rx_payload, &a_tx_meta, &a_tx_payload);
    try icmp_sock.bind(.{ .ident = 0x1234 });

    var arr_a = [_]*IcmpSock{&icmp_sock};
    var stack_a = IcmpStack.init(MAC_A, .{ .icmp6_sockets = &arr_a });
    var stack_b = NoSocketStack.init(MAC_B, {});
    stack_a.iface.setIpv6Addrs(&.{.{ .address = IP_A, .prefix_len = 64 }});
    stack_b.iface.setIpv6Addrs(&.{.{ .address = IP_B, .prefix_len = 64 }});

    // No neighbor cache pre-seeding -- NDP resolves naturally via shuttle.

    const echo_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const repr: icmpv6_wire.Repr = .{ .echo_request = .{
        .ident = 0x1234,
        .seq_no = 1,
        .data = &echo_data,
    } };
    var icmp_buf: [64]u8 = undefined;
    const icmp_len = icmpv6_wire.emit(repr, IP_A, IP_B, &icmp_buf) catch unreachable;
    try icmp_sock.sendSlice(icmp_buf[0..icmp_len], IP_B);

    var cur_time = Instant.ZERO;
    var got_reply = false;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        if (!got_reply and icmp_sock.canRecv()) {
            var buf: [128]u8 = undefined;
            const result = icmp_sock.recvSlice(&buf) catch continue;
            try std.testing.expectEqual(IP_B, result.src_addr);

            const parsed = icmpv6_wire.parse(
                buf[0..result.data_len],
                result.src_addr,
                IP_A,
            ) catch continue;
            switch (parsed) {
                .echo_reply => |echo| {
                    try std.testing.expectEqual(@as(u16, 0x1234), echo.ident);
                    try std.testing.expectEqual(@as(u16, 1), echo.seq_no);
                    got_reply = true;
                },
                else => {},
            }
        }

        if (got_reply) break;

        if (earliestPollTime(stack_a.pollAt(), stack_b.pollAt())) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    try std.testing.expect(got_reply);
    try std.testing.expect(iter < MAX_ITERS);
}
