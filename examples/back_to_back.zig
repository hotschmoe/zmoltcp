// Demo 2: TCP Back-to-Back Transfer
//
// Proves two independent stacks can communicate over a simulated wire --
// full ARP discovery, TCP handshake, bidirectional data transfer, and
// graceful teardown.
//
// Architecture:
//
//   Stack A (server)                  Stack B (client)
//   [TCP socket]                      [TCP socket]
//        |                                 |
//   LoopbackDevice A <-- shuttle --> LoopbackDevice B
//
// Inspired by smoltcp's netsim examples.

const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const tcp_socket = zmoltcp.socket.tcp;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const TcpSock = tcp_socket.Socket(ipv4, 4);
const Device = stack_mod.LoopbackDevice(16);
const Sockets = struct { tcp4_sockets: []*TcpSock };
const B2BStack = stack_mod.Stack(Device, Sockets);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 300;
const DATA_LEN: usize = 1024;
const SERVER_PORT: u16 = 4000;
const CLIENT_PORT: u16 = 50000;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP_B: ipv4.Address = .{ 10, 0, 0, 2 };

fn generatePattern(buf: []u8) void {
    for (buf, 0..) |*b, i| {
        b.* = @truncate(i);
    }
}

fn shuttleFrames(dev_a: *Device, dev_b: *Device) void {
    while (dev_a.dequeueTx()) |frame| {
        dev_b.enqueueRx(frame);
    }
    while (dev_b.dequeueTx()) |frame| {
        dev_a.enqueueRx(frame);
    }
}

test "TCP back-to-back transfer" {
    const std = @import("std");

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
    var dev_a: Device = .{};
    var dev_b: Device = .{};
    var stack_a = B2BStack.init(MAC_A, .{ .tcp4_sockets = &sock_arr_a });
    var stack_b = B2BStack.init(MAC_B, .{ .tcp4_sockets = &sock_arr_b });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    // Build the test pattern
    var send_data: [DATA_LEN]u8 = undefined;
    generatePattern(&send_data);

    var cur_time = Instant.ZERO;
    var client_total_sent: usize = 0;
    var server_total_recv: usize = 0;
    var server_recv_data: [DATA_LEN]u8 = undefined;
    var server_echoed = false;
    var server_echo_sent: usize = 0;
    var client_total_recv: usize = 0;
    var client_recv_data: [DATA_LEN]u8 = undefined;
    var client_done = false;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        // Client: send patterned data when established
        if (client_total_sent < DATA_LEN and client_sock.getState() == .established and client_sock.canSend()) {
            const n = client_sock.sendSlice(send_data[client_total_sent..]) catch 0;
            client_total_sent += n;
        }

        // Server: accumulate received data
        if (!server_echoed and server_sock.getState() == .established and server_sock.canRecv()) {
            var buf: [256]u8 = undefined;
            const n = server_sock.recvSlice(&buf) catch 0;
            if (n > 0) {
                const end = server_total_recv + n;
                if (end <= DATA_LEN) {
                    @memcpy(server_recv_data[server_total_recv..][0..n], buf[0..n]);
                }
                server_total_recv += n;
            }
        }

        // Server: once all data received, echo it back
        if (!server_echoed and server_total_recv >= DATA_LEN and server_sock.canSend()) {
            const n = server_sock.sendSlice(server_recv_data[server_echo_sent..DATA_LEN]) catch 0;
            server_echo_sent += n;
            if (server_echo_sent >= DATA_LEN) {
                server_sock.close();
                server_echoed = true;
            }
        }

        // Client: accumulate echoed data
        if (client_total_sent >= DATA_LEN and !client_done and client_sock.canRecv()) {
            var buf: [256]u8 = undefined;
            const n = client_sock.recvSlice(&buf) catch 0;
            if (n > 0) {
                const end = client_total_recv + n;
                if (end <= DATA_LEN) {
                    @memcpy(client_recv_data[client_total_recv..][0..n], buf[0..n]);
                }
                client_total_recv += n;
                if (client_total_recv >= DATA_LEN) {
                    client_sock.close();
                    client_done = true;
                }
            }
        }

        // Check for completion
        if (client_done and server_echoed) {
            const s_state = server_sock.getState();
            const c_state = client_sock.getState();
            const s_final = s_state == .closed or s_state == .time_wait;
            const c_final = c_state == .closed or c_state == .time_wait;
            if (s_final and c_final) break;
        }

        // Advance time
        const next_a = stack_a.pollAt();
        const next_b = stack_b.pollAt();
        const next = if (next_a) |a| (if (next_b) |b| (if (a.lessThan(b)) a else b) else a) else next_b;
        if (next) |n| {
            cur_time = if (n.greaterThanOrEqual(cur_time)) n else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    // Verify data integrity
    try std.testing.expectEqual(DATA_LEN, server_total_recv);
    try std.testing.expectEqualSlices(u8, &send_data, &server_recv_data);
    try std.testing.expectEqual(DATA_LEN, client_total_recv);
    try std.testing.expectEqualSlices(u8, &send_data, &client_recv_data);
    try std.testing.expect(iter < MAX_ITERS);
}
