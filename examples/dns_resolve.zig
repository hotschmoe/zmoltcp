// Demo 11: DNS Resolution
//
// Proves the DNS client socket resolves names through the full stack.
// A client stack runs a DNS socket that queries "example.com". A server
// stack runs a UDP socket on port 53 that receives the query and sends
// back a valid A-record response. The client then retrieves the result.
//
// Architecture:
//
//   Stack A (client)                   Stack B (DNS server)
//   [DNS socket -> 10.0.0.2:53]       [UDP socket :53]
//        |                                  |
//   LoopbackDevice A <-- shuttle --> LoopbackDevice B

const std = @import("std");
const zmoltcp = @import("zmoltcp");
const stack_mod = zmoltcp.stack;
const dns_socket = zmoltcp.socket.dns;
const udp_socket = zmoltcp.socket.udp;
const dns_wire = zmoltcp.wire.dns;
const ipv4 = zmoltcp.wire.ipv4;
const ethernet = zmoltcp.wire.ethernet;
const time = zmoltcp.time;

const Instant = time.Instant;
const Duration = time.Duration;

const DnsSock = dns_socket.Socket(ipv4);
const UdpSock = udp_socket.Socket(ipv4);
const Device = stack_mod.LoopbackDevice(16);

const STEP = Duration.fromMillis(1);
const MAX_ITERS: usize = 200;

const MAC_A: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
const MAC_B: ethernet.Address = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
const IP_A: ipv4.Address = .{ 10, 0, 0, 1 };
const IP_B: ipv4.Address = .{ 10, 0, 0, 2 };

const ANSWER_IP = [4]u8{ 93, 184, 216, 34 };

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

fn buildDnsResponse(query: []const u8, buf: []u8) usize {
    @memset(buf, 0);

    // Echo transaction ID from query.
    buf[0] = query[0];
    buf[1] = query[1];

    // Flags: response + recursion desired + recursion available.
    const flags: u16 = dns_wire.Flags.RESPONSE | dns_wire.Flags.RECURSION_DESIRED | dns_wire.Flags.RECURSION_AVAILABLE;
    buf[2] = @truncate(flags >> 8);
    buf[3] = @truncate(flags);

    buf[5] = 1; // QDCOUNT = 1
    buf[7] = 1; // ANCOUNT = 1

    // Copy the question section from the query (skip 12-byte header).
    // Question = wire-encoded name + 2 bytes type + 2 bytes class.
    const q_start: usize = 12;
    var q_end: usize = q_start;
    // Walk past name labels until null terminator.
    while (q_end < query.len and query[q_end] != 0) {
        q_end += 1 + query[q_end];
    }
    q_end += 1; // null terminator
    q_end += 4; // TYPE + CLASS

    const q_section = query[q_start..q_end];
    var pos: usize = 12;
    @memcpy(buf[pos..][0..q_section.len], q_section);
    pos += q_section.len;

    // Answer: pointer to name at offset 12.
    buf[pos] = 0xc0;
    buf[pos + 1] = 0x0c;
    pos += 2;
    buf[pos + 1] = 1; // TYPE A
    buf[pos + 3] = 1; // CLASS IN
    pos += 4;
    buf[pos + 3] = 60; // TTL = 60
    pos += 4;
    buf[pos + 1] = 4; // RDLENGTH = 4
    pos += 2;
    @memcpy(buf[pos..][0..4], &ANSWER_IP);
    pos += 4;

    return pos;
}

test "DNS resolution through full stack" {
    const ClientSockets = struct { dns4_sockets: []*DnsSock };
    const ServerSockets = struct { udp4_sockets: []*UdpSock };
    const ClientStack = stack_mod.Stack(Device, ClientSockets);
    const ServerStack = stack_mod.Stack(Device, ServerSockets);

    var dev_a: Device = .{};
    var dev_b: Device = .{};

    const S = struct {
        var slots: [4]DnsSock.QuerySlot = [_]DnsSock.QuerySlot{.{}} ** 4;
    };
    @memset(@as([*]u8, @ptrCast(&S.slots))[0..@sizeOf(@TypeOf(S.slots))], 0);
    const servers = [_][4]u8{IP_B};
    var dns_sock = DnsSock.init(&S.slots, &servers);
    const handle = try dns_sock.startQuery("example.com", .a);

    var b_rx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var b_rx_pay: [512]u8 = undefined;
    var b_tx_meta: [2]UdpSock.PacketMeta = .{ .{}, .{} };
    var b_tx_pay: [512]u8 = undefined;
    var udp_srv = UdpSock.init(&b_rx_meta, &b_rx_pay, &b_tx_meta, &b_tx_pay);
    try udp_srv.bind(.{ .port = 53 });

    var dns_arr = [_]*DnsSock{&dns_sock};
    var udp_arr = [_]*UdpSock{&udp_srv};

    var stack_a = ClientStack.init(MAC_A, .{ .dns4_sockets = &dns_arr });
    var stack_b = ServerStack.init(MAC_B, .{ .udp4_sockets = &udp_arr });
    stack_a.iface.v4.addIpAddr(.{ .address = IP_A, .prefix_len = 24 });
    stack_b.iface.v4.addIpAddr(.{ .address = IP_B, .prefix_len = 24 });

    stack_a.iface.neighbor_cache.fill(IP_B, MAC_B, Instant.ZERO);
    stack_b.iface.neighbor_cache.fill(IP_A, MAC_A, Instant.ZERO);

    var cur_time = Instant.ZERO;
    var server_replied = false;
    var resolved = false;

    var iter: usize = 0;
    while (iter < MAX_ITERS) : (iter += 1) {
        _ = stack_a.poll(cur_time, &dev_a);
        _ = stack_b.poll(cur_time, &dev_b);
        shuttleFrames(&dev_a, &dev_b);

        if (!server_replied and udp_srv.canRecv()) {
            var query_buf: [512]u8 = undefined;
            const result = udp_srv.recvSlice(&query_buf) catch continue;
            const query = query_buf[0..result.data_len];

            var resp_buf: [512]u8 = undefined;
            const resp_len = buildDnsResponse(query, &resp_buf);

            try udp_srv.sendSlice(resp_buf[0..resp_len], .{
                .endpoint = result.meta.endpoint,
            });
            server_replied = true;
        }

        if (server_replied and !resolved) {
            const query_result = dns_sock.getQueryResult(handle) catch continue;
            try std.testing.expectEqual(@as(u8, 1), query_result.len);
            try std.testing.expectEqualSlices(u8, &ANSWER_IP, &query_result.addrs[0]);
            resolved = true;
        }

        if (resolved) break;

        if (earliestPollTime(stack_a.pollAt(), stack_b.pollAt())) |next| {
            cur_time = if (next.greaterThanOrEqual(cur_time)) next else cur_time.add(STEP);
        } else {
            cur_time = cur_time.add(STEP);
        }
    }

    try std.testing.expect(server_replied);
    try std.testing.expect(resolved);
    try std.testing.expect(iter < MAX_ITERS);
}
