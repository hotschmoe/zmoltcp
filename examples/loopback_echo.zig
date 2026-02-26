// Demo 1: TCP Loopback Echo
//
// Proves the full TCP lifecycle on a single stack -- ARP resolution,
// three-way handshake, data send/receive, graceful close -- all driven
// by stack.poll() with no manual packet construction.
//
// Architecture:
//
//   [client socket] --> Stack --> LoopbackDevice --> [server socket]
//                   <--       <-- (TX -> RX)
//
// Inspired by smoltcp's loopback.rs example.

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
const TestStack = stack_mod.Stack(Device, Sockets);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 200;
const MESSAGE = "Hello, zmoltcp!";
const LOCAL_MAC: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const LOCAL_IP: ipv4.Address = .{ 127, 0, 0, 1 };
const SERVER_PORT: u16 = 1234;
const CLIENT_PORT: u16 = 65000;

test "TCP loopback echo" {
    var server_rx: [256]u8 = .{0} ** 256;
    var server_tx: [256]u8 = .{0} ** 256;
    var client_rx: [256]u8 = .{0} ** 256;
    var client_tx: [256]u8 = .{0} ** 256;

    var server = TcpSock.init(&server_rx, &server_tx);
    var client = TcpSock.init(&client_rx, &client_tx);
    server.ack_delay = null;
    client.ack_delay = null;

    try server.listen(.{ .port = SERVER_PORT });
    try client.connect(LOCAL_IP, SERVER_PORT, LOCAL_IP, CLIENT_PORT);

    var sock_arr = [_]*TcpSock{ &server, &client };
    var device: Device = .{};
    var s = TestStack.init(LOCAL_MAC, .{ .tcp4_sockets = &sock_arr });
    s.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 8 });

    var cur_time = Instant.ZERO;
    var client_sent = false;
    var server_echoed = false;
    var client_received = false;
    var server_recv_buf: [64]u8 = undefined;
    var client_recv_buf: [64]u8 = undefined;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = s.poll(cur_time, &device);
        device.loopback();

        // Server: when established and data available, read and echo back
        if (!server_echoed and server.getState() == .established and server.canRecv()) {
            const n = server.recvSlice(&server_recv_buf) catch 0;
            if (n > 0) {
                const std = @import("std");
                std.testing.expectEqualSlices(u8, MESSAGE, server_recv_buf[0..n]) catch
                    return error.ServerDataMismatch;
                _ = server.sendSlice(server_recv_buf[0..n]) catch 0;
                server.close();
                server_echoed = true;
            }
        }

        // Client: when established and not yet sent, send the message
        if (!client_sent and client.getState() == .established and client.canSend()) {
            _ = client.sendSlice(MESSAGE) catch 0;
            client_sent = true;
        }

        // Client: when data available, read the echoed response
        if (client_sent and !client_received and client.canRecv()) {
            const n = client.recvSlice(&client_recv_buf) catch 0;
            if (n > 0) {
                const std = @import("std");
                std.testing.expectEqualSlices(u8, MESSAGE, client_recv_buf[0..n]) catch
                    return error.ClientDataMismatch;
                client.close();
                client_received = true;
            }
        }

        // Done when both sides finished
        if (client_received and server_echoed) {
            const server_done = server.getState() == .closed or server.getState() == .time_wait;
            const client_done = client.getState() == .closed or client.getState() == .time_wait;
            if (server_done and client_done) break;
        }

        // Advance time
        if (s.pollAt()) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    const std = @import("std");
    try std.testing.expect(client_sent);
    try std.testing.expect(server_echoed);
    try std.testing.expect(client_received);
    try std.testing.expect(iter < MAX_ITERS);
}
