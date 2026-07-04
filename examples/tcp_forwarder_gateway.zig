// Demo: TCP Forwarder Gateway
//
// A client stack connects to a public IPv4 destination through a gateway. The
// gateway owns policy and a bounded socket pool, then hands one caller-owned TCP
// socket to zmoltcp to terminate the non-local SYN.

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const tcp_socket = zmoltcp.socket.tcp;
const iface = zmoltcp.iface;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const TcpSock = tcp_socket.Socket(ipv4, 4);
const Device = stack_mod.LoopbackDevice(16);

const CLIENT_PORT: u16 = 50000;
const PUBLIC_PORT: u16 = 8080;

const CLIENT_MAC: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x10, 0x02 };
const GATEWAY_MAC: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x10, 0x01 };
const CLIENT_IP: ipv4.Address = .{ 10, 0, 0, 2 };
const GATEWAY_IP: ipv4.Address = .{ 10, 0, 0, 1 };
const PUBLIC_IP: ipv4.Address = .{ 93, 184, 216, 34 };

const Request = tcp_socket.ForwardRequest(ipv4);

const ForwardPolicy = struct {
    sock: *TcpSock,
    request: ?Request = null,

    fn offer(self: *ForwardPolicy, request: Request) ?*TcpSock {
        self.request = request;
        if (request.local.port != PUBLIC_PORT) return null;
        if (self.sock.getState() != .closed) return null;
        return self.sock;
    }
};

const Forwarder = tcp_socket.Forwarder(ipv4, TcpSock, ForwardPolicy);
const ClientSockets = struct { tcp4_sockets: []*TcpSock };
const GatewaySockets = struct {
    tcp4_sockets: []*TcpSock,
    tcp4_forwarder: *Forwarder,
};
const ClientStack = stack_mod.Stack(Device, ClientSockets);
const GatewayStack = stack_mod.Stack(Device, GatewaySockets);

fn shuttleFrames(client_dev: *Device, gateway_dev: *Device) void {
    while (client_dev.dequeueTx()) |frame| gateway_dev.enqueueRx(frame);
    while (gateway_dev.dequeueTx()) |frame| client_dev.enqueueRx(frame);
}

fn earliestPollTime(a: ?Instant, b: ?Instant) ?Instant {
    if (a) |va| {
        if (b) |vb| return if (va.lessThan(vb)) va else vb;
        return va;
    }
    return b;
}

test "gateway accepts non-local TCP SYN and exchanges data" {
    var client_rx: [1024]u8 = .{0} ** 1024;
    var client_tx: [1024]u8 = .{0} ** 1024;
    var gateway_rx: [1024]u8 = .{0} ** 1024;
    var gateway_tx: [1024]u8 = .{0} ** 1024;

    var client_sock = TcpSock.init(&client_rx, &client_tx);
    var gateway_sock = TcpSock.init(&gateway_rx, &gateway_tx);
    client_sock.ack_delay = null;
    gateway_sock.ack_delay = null;

    try client_sock.connect(PUBLIC_IP, PUBLIC_PORT, CLIENT_IP, CLIENT_PORT);

    var client_sock_arr = [_]*TcpSock{&client_sock};
    var gateway_sock_arr = [_]*TcpSock{&gateway_sock};
    var policy = ForwardPolicy{ .sock = &gateway_sock };
    var forwarder = Forwarder.init(&policy, ForwardPolicy.offer);

    var client_stack = ClientStack.init(CLIENT_MAC, .{ .tcp4_sockets = &client_sock_arr });
    var gateway_stack = GatewayStack.init(GATEWAY_MAC, .{
        .tcp4_sockets = &gateway_sock_arr,
        .tcp4_forwarder = &forwarder,
    });
    client_stack.iface.v4.addIpAddr(.{ .address = CLIENT_IP, .prefix_len = 24 });
    gateway_stack.iface.v4.addIpAddr(.{ .address = GATEWAY_IP, .prefix_len = 24 });
    _ = client_stack.iface.v4.routes.add(iface.Route.newDefaultGateway(GATEWAY_IP));

    var client_dev: Device = .{};
    var gateway_dev: Device = .{};

    const request_payload = "ping";
    const response_payload = "pong";
    var client_sent: usize = 0;
    var gateway_recv: [request_payload.len]u8 = undefined;
    var gateway_recv_len: usize = 0;
    var gateway_sent: usize = 0;
    var client_recv: [response_payload.len]u8 = undefined;
    var client_recv_len: usize = 0;

    var now = Instant.ZERO;
    var iter: usize = 0;
    while (iter < 400) : (iter += 1) {
        _ = client_stack.poll(now, &client_dev);
        _ = gateway_stack.poll(now, &gateway_dev);
        shuttleFrames(&client_dev, &gateway_dev);

        if (client_sock.getState() == .established and client_sent < request_payload.len and client_sock.canSend()) {
            client_sent += try client_sock.sendSlice(request_payload[client_sent..]);
        }

        if (gateway_sock.getState() == .established and gateway_sock.canRecv()) {
            var buf: [16]u8 = undefined;
            const n = try gateway_sock.recvSlice(&buf);
            const copy_len = @min(n, gateway_recv.len - gateway_recv_len);
            @memcpy(gateway_recv[gateway_recv_len..][0..copy_len], buf[0..copy_len]);
            gateway_recv_len += copy_len;
        }

        if (gateway_recv_len == request_payload.len and gateway_sent < response_payload.len and gateway_sock.canSend()) {
            gateway_sent += try gateway_sock.sendSlice(response_payload[gateway_sent..]);
        }

        if (client_sock.canRecv()) {
            var buf: [16]u8 = undefined;
            const n = try client_sock.recvSlice(&buf);
            const copy_len = @min(n, client_recv.len - client_recv_len);
            @memcpy(client_recv[client_recv_len..][0..copy_len], buf[0..copy_len]);
            client_recv_len += copy_len;
        }

        if (client_recv_len == response_payload.len) break;

        if (earliestPollTime(client_stack.pollAt(), gateway_stack.pollAt())) |next| {
            now = if (next.greaterThanOrEqual(now)) next else now.add(Duration.fromMillis(1));
        } else {
            now = now.add(Duration.fromMillis(1));
        }
    }

    const accepted = policy.request orelse return error.ExpectedForwardRequest;
    try std.testing.expectEqual(PUBLIC_IP, accepted.local.addr);
    try std.testing.expectEqual(@as(u16, PUBLIC_PORT), accepted.local.port);
    try std.testing.expectEqual(CLIENT_IP, accepted.remote.addr);
    try std.testing.expectEqual(@as(u16, CLIENT_PORT), accepted.remote.port);
    try std.testing.expectEqualSlices(u8, request_payload, &gateway_recv);
    try std.testing.expectEqualSlices(u8, response_payload, &client_recv);
    try std.testing.expect(iter < 400);
}
