// Demo 13: DHCP Client Lifecycle
//
// Proves the full DHCP state machine works through the stack:
// DISCOVER -> OFFER -> REQUEST -> ACK -> configured.
//
// A single stack runs a DHCP socket. Server responses are manually
// constructed and injected into the device, following the same pattern
// used in stack.zig's DHCP integration tests.
//
// Architecture:
//
//   Stack (client)
//   [DHCP socket]
//        |
//   LoopbackDevice
//        |
//   Manual frame injection (simulated server)

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const dhcp_socket_mod = zmoltcp.socket.dhcp;
const dhcp_wire = zmoltcp.wire.dhcp;
const udp_wire = zmoltcp.wire.udp;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const time = zmoltcp.time;

const Instant = time.Instant;

const DhcpSock = dhcp_socket_mod.Socket;
const Device = stack_mod.LoopbackDevice(16);
const Sockets = struct { dhcp_sockets: []*DhcpSock };
const DhcpStack = stack_mod.Stack(Device, Sockets);

const MAC_CLIENT: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_SERVER: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0xFF };
const SERVER_IP: ipv4.Address = .{ 10, 0, 0, 1 };
const OFFERED_IP: ipv4.Address = .{ 10, 0, 0, 42 };

fn buildDhcpFrame(
    buf: []u8,
    msg_type: dhcp_wire.MessageType,
    transaction_id: u32,
) []const u8 {
    const dhcp_repr = dhcp_wire.Repr{
        .message_type = msg_type,
        .transaction_id = transaction_id,
        .secs = 0,
        .client_hardware_address = MAC_CLIENT,
        .client_ip = .{ 0, 0, 0, 0 },
        .your_ip = OFFERED_IP,
        .server_ip = SERVER_IP,
        .router = SERVER_IP,
        .subnet_mask = .{ 255, 255, 255, 0 },
        .relay_agent_ip = .{ 0, 0, 0, 0 },
        .broadcast = false,
        .requested_ip = null,
        .client_identifier = null,
        .server_identifier = SERVER_IP,
        .parameter_request_list = null,
        .max_size = null,
        .lease_duration = 3600,
        .renew_duration = null,
        .rebind_duration = null,
        .dns_servers = null,
    };

    var dhcp_buf: [576]u8 = undefined;
    const dhcp_len = dhcp_wire.emit(dhcp_repr, &dhcp_buf) catch unreachable;

    // Wrap in UDP (server:67 -> client:68).
    var udp_buf: [600]u8 = undefined;
    const udp_total: u16 = @intCast(udp_wire.HEADER_LEN + dhcp_len);
    const udp_hdr_len = udp_wire.emit(.{
        .src_port = 67,
        .dst_port = 68,
        .length = udp_total,
        .checksum = 0,
    }, &udp_buf) catch unreachable;
    @memcpy(udp_buf[udp_hdr_len..][0..dhcp_len], dhcp_buf[0..dhcp_len]);

    // Wrap in IPv4.
    const ip_payload_len = udp_hdr_len + dhcp_len;
    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + ip_payload_len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .udp,
        .checksum = 0,
        .src_addr = SERVER_IP,
        .dst_addr = .{ 255, 255, 255, 255 },
    };
    const eth_repr = ethernet.Repr{
        .dst_addr = ethernet.BROADCAST,
        .src_addr = MAC_SERVER,
        .ethertype = .ipv4,
    };

    const eth_len = ethernet.emit(eth_repr, buf) catch unreachable;
    const ip_len = ipv4.emit(ip_repr, buf[eth_len..]) catch unreachable;
    @memcpy(buf[eth_len + ip_len ..][0..ip_payload_len], udp_buf[0..ip_payload_len]);

    return buf[0 .. eth_len + ip_len + ip_payload_len];
}

test "DHCP client full lifecycle" {
    var device: Device = .{};
    var sock = DhcpSock.init(MAC_CLIENT);

    // Consume initial deconfigured event.
    const initial = sock.poll();
    try std.testing.expect(initial != null);
    switch (initial.?) {
        .deconfigured => {},
        .configured => return error.TestUnexpectedResult,
    }

    var sock_arr = [_]*DhcpSock{&sock};
    var stack = DhcpStack.init(MAC_CLIENT, .{ .dhcp_sockets = &sock_arr });
    stack.iface.any_ip = true;

    // Phase 1: poll dispatches DISCOVER.
    _ = stack.poll(Instant.ZERO, &device);
    const discover_frame = device.dequeueTx();
    try std.testing.expect(discover_frame != null);

    // Phase 2: inject OFFER.
    var offer_buf: [1024]u8 = undefined;
    const offer_frame = buildDhcpFrame(&offer_buf, .offer, sock.transaction_id);
    device.enqueueRx(offer_frame);
    _ = stack.poll(Instant.ZERO, &device);

    // Phase 3: stack dispatches REQUEST.
    const request_frame = device.dequeueTx();
    try std.testing.expect(request_frame != null);

    // Phase 4: inject ACK.
    var ack_buf: [1024]u8 = undefined;
    const ack_frame = buildDhcpFrame(&ack_buf, .ack, sock.transaction_id);
    device.enqueueRx(ack_frame);
    _ = stack.poll(Instant.ZERO, &device);

    // Phase 5: socket should report configured.
    const event = sock.poll();
    try std.testing.expect(event != null);
    switch (event.?) {
        .configured => |cfg| {
            try std.testing.expectEqualSlices(u8, &OFFERED_IP, &cfg.address);
            try std.testing.expectEqual(@as(u6, 24), cfg.prefix_len);
            try std.testing.expect(cfg.router != null);
            try std.testing.expectEqualSlices(u8, &SERVER_IP, &cfg.router.?);
        },
        .deconfigured => return error.TestUnexpectedResult,
    }

    // Apply configuration to interface.
    const cfg = switch (event.?) {
        .configured => |c| c,
        .deconfigured => unreachable,
    };
    stack.iface.v4.addIpAddr(.{ .address = cfg.address, .prefix_len = cfg.prefix_len });
}
