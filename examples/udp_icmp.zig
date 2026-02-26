// Demo 3: UDP Exchange + ICMP Ping
//
// Proves UDP datagram delivery and ICMP echo (ping) work end-to-end
// through the stack using two back-to-back stacks.
//
// Part 1: UDP echo -- Stack B sends "ping" to Stack A, Stack A replies "pong"
// Part 2: ICMP ping -- Stack A sends echo request, Stack B auto-replies
//
// Architecture (same back-to-back as Demo 2):
//
//   Stack A                            Stack B
//   [UDP socket] [ICMP socket]         [UDP socket]
//        |                                  |
//   LoopbackDevice A <-- shuttle --> LoopbackDevice B

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const udp_socket = zmoltcp.socket.udp;
const icmp_socket = zmoltcp.socket.icmp;
const icmp_wire = zmoltcp.wire.icmp;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const UdpSock = udp_socket.Socket(ipv4);
const IcmpSock = icmp_socket.Socket(ipv4);
const Device = stack_mod.LoopbackDevice(16);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 200;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP_B: ipv4.Address = .{ 10, 0, 0, 2 };

fn shuttleFrames(dev_a: *Device, dev_b: *Device) void {
    while (dev_a.dequeueTx()) |frame| {
        dev_b.enqueueRx(frame);
    }
    while (dev_b.dequeueTx()) |frame| {
        dev_a.enqueueRx(frame);
    }
}

test "UDP echo between two stacks" {
    const UdpSockets = struct { udp4_sockets: []*UdpSock };
    const UdpStack = stack_mod.Stack(Device, UdpSockets);

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
    var stack_a = UdpStack.init(MAC_A, .{ .udp4_sockets = &arr_a });
    var stack_b = UdpStack.init(MAC_B, .{ .udp4_sockets = &arr_b });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    try sock_b.sendSlice("ping", .{
        .endpoint = .{ .addr = IP_A, .port = 5000 },
    });

    var cur_time = Instant.ZERO;
    var a_received_ping = false;
    var b_received_pong = false;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        if (!a_received_ping and sock_a.canRecv()) {
            var buf: [64]u8 = undefined;
            const result = sock_a.recvSlice(&buf) catch continue;
            try std.testing.expectEqualSlices(u8, "ping", buf[0..result.data_len]);
            a_received_ping = true;
            try sock_a.sendSlice("pong", .{
                .endpoint = result.meta.endpoint,
            });
        }

        if (a_received_ping and !b_received_pong and sock_b.canRecv()) {
            var buf: [64]u8 = undefined;
            const result = sock_b.recvSlice(&buf) catch continue;
            try std.testing.expectEqualSlices(u8, "pong", buf[0..result.data_len]);
            b_received_pong = true;
        }

        if (b_received_pong) break;
        cur_time = cur_time.add(STEP);
    }

    try std.testing.expect(a_received_ping);
    try std.testing.expect(b_received_pong);
    try std.testing.expect(iter < MAX_ITERS);
}

test "ICMP ping between two stacks" {
    const IcmpSockets = struct { icmp4_sockets: []*IcmpSock };
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
    var stack_a = IcmpStack.init(MAC_A, .{ .icmp4_sockets = &arr_a });
    var stack_b = NoSocketStack.init(MAC_B, {});
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    const echo_payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var icmp_buf: [icmp_wire.HEADER_LEN + echo_payload.len]u8 = undefined;
    _ = icmp_wire.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 1,
    }, &echo_payload, &icmp_buf) catch unreachable;
    try icmp_sock.sendSlice(&icmp_buf, IP_B);

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

            const reply = icmp_wire.parse(buf[0..result.data_len]) catch continue;
            switch (reply) {
                .echo => |echo| {
                    try std.testing.expectEqual(icmp_wire.Type.echo_reply, echo.icmp_type);
                    try std.testing.expectEqual(@as(u16, 0x1234), echo.identifier);
                    try std.testing.expectEqual(@as(u16, 1), echo.sequence);
                    got_reply = true;
                },
                .other => {},
            }
        }

        if (got_reply) break;
        cur_time = cur_time.add(STEP);
    }

    try std.testing.expect(got_reply);
    try std.testing.expect(iter < MAX_ITERS);
}
