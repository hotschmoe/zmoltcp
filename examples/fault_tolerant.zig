// Demo 5: TCP Resilience Under Packet Loss
//
// Proves TCP retransmission and recovery work correctly over a lossy
// link. Two stacks exchange data through FaultInjector-wrapped devices
// that drop 10% of transmitted frames.
//
// Architecture:
//
//   Stack A (server)                       Stack B (client)
//   [TCP socket]                           [TCP socket]
//        |                                      |
//   FaultInjector A                        FaultInjector B
//   (10% TX drop)                          (10% TX drop)
//        |                                      |
//   LoopbackDevice A <---- shuttle ----> LoopbackDevice B
//
// If TCP works under packet loss, it works.

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const tcp_socket = zmoltcp.socket.tcp;
const phy_mod = zmoltcp.phy;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const TcpSock = tcp_socket.Socket(ipv4, 4);
const BaseDevice = stack_mod.LoopbackDevice(32);
const FIDevice = phy_mod.FaultInjector(BaseDevice);
const Sockets = struct { tcp4_sockets: []*TcpSock };
const FIStack = stack_mod.Stack(FIDevice, Sockets);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 5000;
const DATA_LEN: usize = 512;
const SERVER_PORT: u16 = 4000;
const CLIENT_PORT: u16 = 50000;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP_B: ipv4.Address = .{ 10, 0, 0, 2 };

var rng_state: u32 = 42;

fn lcgRng() u32 {
    rng_state *%= 1664525;
    rng_state +%= 1013904223;
    return rng_state;
}

fn generatePattern(buf: []u8) void {
    for (buf, 0..) |*b, i| b.* = @truncate(i);
}

fn shuttleFrames(dev_a: *FIDevice, dev_b: *FIDevice) void {
    while (dev_a.inner.dequeueTx()) |frame| dev_b.inner.enqueueRx(frame);
    while (dev_b.inner.dequeueTx()) |frame| dev_a.inner.enqueueRx(frame);
}

fn earliestPollTime(a: ?Instant, b: ?Instant) ?Instant {
    if (a) |va| {
        if (b) |vb| return if (va.lessThan(vb)) va else vb;
        return va;
    }
    return b;
}

test "TCP data transfer over lossy link" {
    rng_state = 42;

    var server_rx: [4096]u8 = .{0} ** 4096;
    var server_tx: [4096]u8 = .{0} ** 4096;
    var client_rx: [4096]u8 = .{0} ** 4096;
    var client_tx: [4096]u8 = .{0} ** 4096;

    var server_sock = TcpSock.init(&server_rx, &server_tx);
    var client_sock = TcpSock.init(&client_rx, &client_tx);
    server_sock.ack_delay = null;
    client_sock.ack_delay = null;

    try server_sock.listen(.{ .port = SERVER_PORT });
    try client_sock.connect(IP_A, SERVER_PORT, IP_B, CLIENT_PORT);

    var sock_arr_a = [_]*TcpSock{&server_sock};
    var sock_arr_b = [_]*TcpSock{&client_sock};

    var dev_a = FIDevice.init(.{}, .{ .tx_drop_pct = 10 }, &lcgRng);
    var dev_b = FIDevice.init(.{}, .{ .tx_drop_pct = 10 }, &lcgRng);

    var stack_a = FIStack.init(MAC_A, .{ .tcp4_sockets = &sock_arr_a });
    var stack_b = FIStack.init(MAC_B, .{ .tcp4_sockets = &sock_arr_b });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    var send_data: [DATA_LEN]u8 = undefined;
    generatePattern(&send_data);

    var cur_time = Instant.ZERO;
    var client_total_sent: usize = 0;
    var server_total_recv: usize = 0;
    var server_recv_data: [DATA_LEN]u8 = undefined;
    var transfer_done = false;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        if (client_total_sent < DATA_LEN and
            client_sock.getState() == .established and client_sock.canSend())
        {
            const n = client_sock.sendSlice(send_data[client_total_sent..]) catch 0;
            client_total_sent += n;
        }

        if (!transfer_done and
            server_sock.getState() == .established and server_sock.canRecv())
        {
            var buf: [256]u8 = undefined;
            const n = server_sock.recvSlice(&buf) catch 0;
            if (n > 0) {
                const end = server_total_recv + n;
                if (end <= DATA_LEN) {
                    @memcpy(server_recv_data[server_total_recv..][0..n], buf[0..n]);
                }
                server_total_recv += n;
                if (server_total_recv >= DATA_LEN) {
                    server_sock.close();
                    client_sock.close();
                    transfer_done = true;
                }
            }
        }

        if (transfer_done) {
            const s_state = server_sock.getState();
            const c_state = client_sock.getState();
            const s_final = s_state == .closed or s_state == .time_wait;
            const c_final = c_state == .closed or c_state == .time_wait;
            if (s_final and c_final) break;
        }

        if (earliestPollTime(stack_a.pollAt(), stack_b.pollAt())) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    try std.testing.expectEqual(DATA_LEN, server_total_recv);
    try std.testing.expectEqualSlices(u8, &send_data, &server_recv_data);
    try std.testing.expect(iter < MAX_ITERS);
}
