// Top-level poll loop: Device I/O -> Interface (ARP, ICMP) -> Sockets.
//
// Reference: smoltcp src/iface/interface.rs (poll, socket_ingress, socket_egress)

const ethernet = @import("wire/ethernet.zig");
const arp = @import("wire/arp.zig");
const ipv4 = @import("wire/ipv4.zig");
const icmp = @import("wire/icmp.zig");
const udp_wire = @import("wire/udp.zig");
const tcp_wire = @import("wire/tcp.zig");
const udp_socket_mod = @import("socket/udp.zig");
const tcp_socket = @import("socket/tcp.zig");
const iface_mod = @import("iface.zig");
const time = @import("time.zig");

const Instant = time.Instant;

/// Maximum frame size for serialization scratch buffers.
pub const MAX_FRAME_LEN = 1514; // Ethernet MTU 1500 + 14-byte header

/// Comptime-generic stack over a Device and optional SocketConfig.
///
/// Device must implement:
///   fn receive(self: *Device) ?[]const u8
///   fn transmit(self: *Device, frame: []const u8) void
///
/// SocketConfig is either `void` (no sockets) or a struct with optional fields:
///   tcp_sockets: []*SomeTcpSocket
///   udp_sockets: []*SomeUdpSocket
///   icmp_sockets: []*SomeIcmpSocket
pub fn Stack(comptime Device: type, comptime SocketConfig: type) type {
    comptime {
        if (!@hasDecl(Device, "receive")) @compileError("Device must have receive()");
        if (!@hasDecl(Device, "transmit")) @compileError("Device must have transmit()");
    }

    const has_tcp = SocketConfig != void and @hasField(SocketConfig, "tcp_sockets");
    const has_udp = SocketConfig != void and @hasField(SocketConfig, "udp_sockets");
    const has_icmp = SocketConfig != void and @hasField(SocketConfig, "icmp_sockets");

    return struct {
        const Self = @This();

        iface: iface_mod.Interface,
        sockets: SocketConfig,

        pub fn init(hw_addr: ethernet.Address, sockets: SocketConfig) Self {
            return .{
                .iface = iface_mod.Interface.init(hw_addr),
                .sockets = sockets,
            };
        }

        pub fn poll(self: *Self, timestamp: Instant, device: *Device) bool {
            self.iface.now = timestamp;
            var processed = false;

            while (device.receive()) |rx_frame| {
                self.processIngress(timestamp, rx_frame, device);
                processed = true;
            }

            return processed;
        }

        pub fn pollAt(self: *const Self) ?Instant {
            _ = self;
            return null;
        }

        fn processIngress(self: *Self, timestamp: Instant, frame: []const u8, device: *Device) void {
            const eth_repr = ethernet.parse(frame) catch return;
            const payload_data = ethernet.payload(frame) catch return;

            switch (eth_repr.ethertype) {
                .arp => {
                    if (self.iface.processArp(payload_data)) |response| {
                        self.emitResponse(response, device);
                    }
                },
                .ipv4 => self.processIpv4Ingress(timestamp, payload_data, device),
                else => {},
            }
        }

        fn processIpv4Ingress(self: *Self, timestamp: Instant, data: []const u8, device: *Device) void {
            const ip_repr = ipv4.parse(data) catch return;
            const is_broadcast = self.iface.isBroadcast(ip_repr.dst_addr);
            if (!is_broadcast and !self.iface.hasIpAddr(ip_repr.dst_addr)) return;

            const ip_payload = ipv4.payloadSlice(data) catch return;

            switch (ip_repr.protocol) {
                .icmp => {
                    self.routeToIcmpSockets(ip_repr, ip_payload);
                    if (self.iface.processIcmp(ip_repr, ip_payload, is_broadcast)) |response| {
                        self.emitResponse(response, device);
                    }
                },
                .udp => {
                    const handled = self.routeToUdpSockets(ip_repr, ip_payload);
                    if (self.iface.processUdp(ip_repr, ip_payload, handled)) |response| {
                        self.emitResponse(response, device);
                    }
                },
                .tcp => {
                    const result = self.routeToTcpSockets(timestamp, ip_repr, ip_payload);
                    if (result.reply) |reply| {
                        self.emitTcpReply(ip_repr, reply, device);
                    }
                    if (self.iface.processTcp(ip_repr, ip_payload, result.handled)) |response| {
                        self.emitResponse(response, device);
                    }
                },
                _ => {
                    if (is_broadcast) return;
                    if (self.iface.icmpProtoUnreachable(ip_repr, ip_payload)) |response| {
                        self.emitResponse(response, device);
                    }
                },
            }
        }

        // -- Socket routing --

        const TcpRouteResult = struct {
            reply: ?tcp_socket.TcpRepr = null,
            handled: bool = false,
        };

        fn routeToTcpSockets(self: *Self, timestamp: Instant, ip_repr: ipv4.Repr, tcp_data: []const u8) TcpRouteResult {
            if (comptime !has_tcp) return .{};

            const sock_repr = tcp_socket.TcpRepr.fromWireBytes(tcp_data) orelse return .{};

            for (self.sockets.tcp_sockets) |sock| {
                if (sock.accepts(ip_repr.src_addr, ip_repr.dst_addr, sock_repr)) {
                    const reply = sock.process(timestamp, ip_repr.src_addr, ip_repr.dst_addr, sock_repr);
                    return .{ .reply = reply, .handled = true };
                }
            }
            return .{};
        }

        fn routeToUdpSockets(self: *Self, ip_repr: ipv4.Repr, raw_udp: []const u8) bool {
            if (comptime !has_udp) return false;

            const wire_repr = udp_wire.parse(raw_udp) catch return false;
            const payload = udp_wire.payloadSlice(raw_udp) catch return false;
            const sock_repr = udp_socket_mod.UdpRepr{
                .src_port = wire_repr.src_port,
                .dst_port = wire_repr.dst_port,
            };

            var handled = false;
            for (self.sockets.udp_sockets) |sock| {
                if (sock.accepts(ip_repr.src_addr, ip_repr.dst_addr, sock_repr)) {
                    sock.process(ip_repr.src_addr, ip_repr.dst_addr, sock_repr, payload);
                    handled = true;
                }
            }
            return handled;
        }

        fn routeToIcmpSockets(self: *Self, ip_repr: ipv4.Repr, icmp_data: []const u8) void {
            if (comptime !has_icmp) return;

            const icmp_repr = icmp.parse(icmp_data) catch return;
            const icmp_payload = if (icmp_data.len > icmp.HEADER_LEN)
                icmp_data[icmp.HEADER_LEN..]
            else
                &[_]u8{};

            for (self.sockets.icmp_sockets) |sock| {
                if (sock.accepts(ip_repr.src_addr, ip_repr.dst_addr, icmp_repr, icmp_payload)) {
                    sock.process(ip_repr.src_addr, icmp_repr, icmp_payload);
                }
            }
        }

        fn emitTcpReply(self: *Self, orig_ip: ipv4.Repr, tcp_repr: tcp_socket.TcpRepr, device: *Device) void {
            const response = iface_mod.Response{ .ipv4 = .{
                .ip = .{
                    .src_addr = orig_ip.dst_addr,
                    .dst_addr = orig_ip.src_addr,
                    .protocol = .tcp,
                    .hop_limit = iface_mod.DEFAULT_HOP_LIMIT,
                },
                .payload = .{ .tcp = tcp_repr },
            } };
            self.emitResponse(response, device);
        }

        // -- Response serialization --

        fn emitResponse(self: *Self, response: iface_mod.Response, device: *Device) void {
            var buf: [MAX_FRAME_LEN]u8 = undefined;

            switch (response) {
                .arp_reply => |arp_repr| {
                    const frame = self.serializeArpReply(arp_repr, &buf) orelse return;
                    device.transmit(frame);
                },
                .ipv4 => |resp| {
                    const frame = self.serializeIpv4Response(resp, &buf) orelse return;
                    device.transmit(frame);
                },
            }
        }

        fn serializeArpReply(self: *const Self, repr: arp.Repr, buf: []u8) ?[]const u8 {
            const eth_repr = ethernet.Repr{
                .dst_addr = repr.target_hardware_addr,
                .src_addr = self.iface.hardware_addr,
                .ethertype = .arp,
            };
            const eth_len = ethernet.emit(eth_repr, buf) catch return null;
            const arp_len = arp.emit(repr, buf[eth_len..]) catch return null;
            return buf[0 .. eth_len + arp_len];
        }

        fn serializeIpv4Response(self: *const Self, resp: iface_mod.Ipv4Response, buf: []u8) ?[]const u8 {
            var payload_buf: [iface_mod.IPV4_MIN_MTU]u8 = undefined;
            const payload_len: usize = switch (resp.payload) {
                .icmp_echo => |echo| icmp.emitEcho(echo.echo, echo.data, &payload_buf) catch return null,
                .icmp_dest_unreachable => |du| blk: {
                    var inner_buf: [iface_mod.IPV4_MIN_MTU]u8 = undefined;
                    const inv_len = ipv4.emit(du.invoking_repr, &inner_buf) catch return null;
                    const data_len = @min(du.data.len, iface_mod.IPV4_MIN_MTU - icmp.HEADER_LEN - inv_len);
                    @memcpy(inner_buf[inv_len..][0..data_len], du.data[0..data_len]);
                    break :blk icmp.emitOther(.{
                        .icmp_type = .dest_unreachable,
                        .code = du.code,
                        .checksum = 0,
                        .data = 0,
                    }, inner_buf[0 .. inv_len + data_len], &payload_buf) catch return null;
                },
                .tcp => |tcp_repr| blk: {
                    const wire_repr = tcp_repr.toWireRepr();
                    const tcp_len = tcp_wire.emit(wire_repr, &payload_buf) catch return null;
                    const cksum = tcp_wire.computeChecksum(
                        resp.ip.src_addr,
                        resp.ip.dst_addr,
                        payload_buf[0..tcp_len],
                    );
                    payload_buf[16] = @truncate(cksum >> 8);
                    payload_buf[17] = @truncate(cksum & 0xFF);
                    break :blk tcp_len;
                },
            };

            const ip_repr = ipv4.Repr{
                .version = 4,
                .ihl = 5,
                .dscp_ecn = 0,
                .total_length = @intCast(ipv4.HEADER_LEN + payload_len),
                .identification = 0,
                .dont_fragment = true,
                .more_fragments = false,
                .fragment_offset = 0,
                .ttl = resp.ip.hop_limit,
                .protocol = resp.ip.protocol,
                .checksum = 0,
                .src_addr = resp.ip.src_addr,
                .dst_addr = resp.ip.dst_addr,
            };

            const dst_mac = self.iface.neighbor_cache.lookup(resp.ip.dst_addr, self.iface.now) orelse
                ethernet.BROADCAST;

            const eth_repr = ethernet.Repr{
                .dst_addr = dst_mac,
                .src_addr = self.iface.hardware_addr,
                .ethertype = .ipv4,
            };

            const eth_len = ethernet.emit(eth_repr, buf) catch return null;
            const ip_len = ipv4.emit(ip_repr, buf[eth_len..]) catch return null;
            @memcpy(buf[eth_len + ip_len ..][0..payload_len], payload_buf[0..payload_len]);
            return buf[0 .. eth_len + ip_len + payload_len];
        }
    };
}

// -------------------------------------------------------------------------
// LoopbackDevice -- in-memory device for testing
// -------------------------------------------------------------------------

pub fn LoopbackDevice(comptime max_frames: usize) type {
    const Frame = struct {
        data: [MAX_FRAME_LEN]u8 = undefined,
        len: usize = 0,
    };

    return struct {
        const Self = @This();

        rx_queue: [max_frames]Frame = [_]Frame{.{}} ** max_frames,
        rx_head: usize = 0,
        rx_count: usize = 0,

        tx_queue: [max_frames]Frame = [_]Frame{.{}} ** max_frames,
        tx_head: usize = 0,
        tx_count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        /// Enqueue a frame into the RX queue (simulates receiving from wire).
        pub fn enqueueRx(self: *Self, frame: []const u8) void {
            if (self.rx_count >= max_frames) return;
            const idx = (self.rx_head + self.rx_count) % max_frames;
            @memcpy(self.rx_queue[idx].data[0..frame.len], frame);
            self.rx_queue[idx].len = frame.len;
            self.rx_count += 1;
        }

        /// Device interface: get next received frame.
        pub fn receive(self: *Self) ?[]const u8 {
            if (self.rx_count == 0) return null;
            const idx = self.rx_head;
            const len = self.rx_queue[idx].len;
            self.rx_head = (self.rx_head + 1) % max_frames;
            self.rx_count -= 1;
            return self.rx_queue[idx].data[0..len];
        }

        /// Device interface: transmit a frame.
        pub fn transmit(self: *Self, frame: []const u8) void {
            if (self.tx_count >= max_frames) return;
            const idx = (self.tx_head + self.tx_count) % max_frames;
            @memcpy(self.tx_queue[idx].data[0..frame.len], frame);
            self.tx_queue[idx].len = frame.len;
            self.tx_count += 1;
        }

        /// Dequeue a frame from the TX queue (for test verification).
        pub fn dequeueTx(self: *Self) ?[]const u8 {
            if (self.tx_count == 0) return null;
            const idx = self.tx_head;
            const len = self.tx_queue[idx].len;
            self.tx_head = (self.tx_head + 1) % max_frames;
            self.tx_count -= 1;
            return self.tx_queue[idx].data[0..len];
        }

        /// Move all TX frames into the RX queue (loopback).
        pub fn loopback(self: *Self) void {
            while (self.dequeueTx()) |frame| {
                self.enqueueRx(frame);
            }
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

const TestDevice = LoopbackDevice(8);
const TestStack = Stack(TestDevice, void);

const LOCAL_HW: ethernet.Address = .{ 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
const REMOTE_HW: ethernet.Address = .{ 0x52, 0x54, 0x00, 0x00, 0x00, 0x00 };
const LOCAL_IP: ipv4.Address = .{ 10, 0, 0, 1 };
const REMOTE_IP: ipv4.Address = .{ 10, 0, 0, 2 };

fn testStack() TestStack {
    var s = TestStack.init(LOCAL_HW, {});
    s.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    return s;
}

fn buildArpRequest(buf: []u8) []const u8 {
    const eth_repr = ethernet.Repr{
        .dst_addr = ethernet.BROADCAST,
        .src_addr = REMOTE_HW,
        .ethertype = .arp,
    };
    const eth_len = ethernet.emit(eth_repr, buf) catch unreachable;
    const arp_repr = arp.Repr{
        .operation = .request,
        .source_hardware_addr = REMOTE_HW,
        .source_protocol_addr = REMOTE_IP,
        .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 },
        .target_protocol_addr = LOCAL_IP,
    };
    const arp_len = arp.emit(arp_repr, buf[eth_len..]) catch unreachable;
    return buf[0 .. eth_len + arp_len];
}

fn buildIcmpEchoRequest(buf: []u8) []const u8 {
    const echo_data = [_]u8{ 0xDE, 0xAD };
    var icmp_buf: [icmp.HEADER_LEN + 2]u8 = undefined;
    _ = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 1,
    }, &echo_data, &icmp_buf) catch unreachable;
    return buildIpv4Frame(buf, .icmp, &icmp_buf);
}

test "stack ARP request produces reply" {
    var device = TestDevice.init();
    var stack = testStack();

    var req_buf: [128]u8 = undefined;
    const req_frame = buildArpRequest(&req_buf);
    device.enqueueRx(req_frame);

    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);

    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;

    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(ethernet.EtherType.arp, eth.ethertype);
    try testing.expectEqual(REMOTE_HW, eth.dst_addr);
    try testing.expectEqual(LOCAL_HW, eth.src_addr);

    const arp_data = try ethernet.payload(tx_frame);
    const arp_repr = try arp.parse(arp_data);
    try testing.expectEqual(arp.Operation.reply, arp_repr.operation);
    try testing.expectEqual(LOCAL_HW, arp_repr.source_hardware_addr);
    try testing.expectEqual(LOCAL_IP, arp_repr.source_protocol_addr);
    try testing.expectEqual(REMOTE_HW, arp_repr.target_hardware_addr);
    try testing.expectEqual(REMOTE_IP, arp_repr.target_protocol_addr);
}

test "stack ICMP echo request produces reply" {
    var device = TestDevice.init();
    var stack = testStack();

    // Populate neighbor cache via ARP exchange
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    var req_buf: [256]u8 = undefined;
    device.enqueueRx(buildIcmpEchoRequest(&req_buf));

    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);

    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;

    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(ethernet.EtherType.ipv4, eth.ethertype);
    try testing.expectEqual(REMOTE_HW, eth.dst_addr);

    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(LOCAL_IP, ip_repr.src_addr);
    try testing.expectEqual(REMOTE_IP, ip_repr.dst_addr);
    try testing.expectEqual(ipv4.Protocol.icmp, ip_repr.protocol);

    const icmp_data = try ipv4.payloadSlice(ip_data);
    const icmp_repr = try icmp.parse(icmp_data);
    switch (icmp_repr) {
        .echo => |echo| {
            try testing.expectEqual(icmp.Type.echo_reply, echo.icmp_type);
            try testing.expectEqual(@as(u16, 0x1234), echo.identifier);
            try testing.expectEqual(@as(u16, 1), echo.sequence);
        },
        .other => return error.ExpectedEchoReply,
    }
    try testing.expect(icmp.verifyChecksum(icmp_data));
}

test "stack empty RX returns false" {
    var device = TestDevice.init();
    var stack = testStack();

    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(!processed);
}

test "stack loopback device round-trip" {
    var device = TestDevice.init();
    var stack = testStack();

    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);

    device.loopback();

    // ARP reply addressed to REMOTE_HW is processed but generates no response
    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);
    try testing.expectEqual(@as(?[]const u8, null), device.dequeueTx());
}

test "stack pollAt returns null with no sockets" {
    var stack = testStack();
    try testing.expectEqual(@as(?Instant, null), stack.pollAt());
}

fn buildIpv4Frame(buf: []u8, protocol: ipv4.Protocol, payload_data: []const u8) []const u8 {
    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + payload_data.len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = protocol,
        .checksum = 0,
        .src_addr = REMOTE_IP,
        .dst_addr = LOCAL_IP,
    };
    const eth_repr = ethernet.Repr{
        .dst_addr = LOCAL_HW,
        .src_addr = REMOTE_HW,
        .ethertype = .ipv4,
    };
    const eth_len = ethernet.emit(eth_repr, buf) catch unreachable;
    const ip_len = ipv4.emit(ip_repr, buf[eth_len..]) catch unreachable;
    @memcpy(buf[eth_len + ip_len ..][0..payload_data.len], payload_data);
    return buf[0 .. eth_len + ip_len + payload_data.len];
}

test "stack TCP SYN no listener produces RST" {
    var device = TestDevice.init();
    var stack = testStack();

    // Populate neighbor cache
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Build TCP SYN
    var tcp_buf: [tcp_wire.HEADER_LEN]u8 = undefined;
    _ = tcp_wire.emit(.{
        .src_port = 4242,
        .dst_port = 4243,
        .seq_number = 12345,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .syn = true },
        .window_size = 1024,
        .checksum = 0,
        .urgent_pointer = 0,
    }, &tcp_buf) catch unreachable;

    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&frame_buf, .tcp, &tcp_buf));
    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);

    // Verify RST response
    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(ethernet.EtherType.ipv4, eth.ethertype);

    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(LOCAL_IP, ip_repr.src_addr);
    try testing.expectEqual(REMOTE_IP, ip_repr.dst_addr);
    try testing.expectEqual(ipv4.Protocol.tcp, ip_repr.protocol);

    const tcp_data = try ipv4.payloadSlice(ip_data);
    const tcp_repr = try tcp_wire.parse(tcp_data);
    try testing.expectEqual(@as(u16, 4243), tcp_repr.src_port);
    try testing.expectEqual(@as(u16, 4242), tcp_repr.dst_port);
    try testing.expect(tcp_repr.flags.rst);
    try testing.expectEqual(@as(u32, 0), tcp_repr.seq_number);
    try testing.expect(tcp_repr.flags.ack);
    try testing.expectEqual(@as(u32, 12346), tcp_repr.ack_number);

    // Verify TCP checksum
    try testing.expectEqual(@as(u16, 0), tcp_wire.computeChecksum(
        ip_repr.src_addr,
        ip_repr.dst_addr,
        tcp_data,
    ));
}

test "stack UDP to bound socket delivers data" {
    const UdpSock = udp_socket_mod.Socket(.{ .payload_size = 64 });
    const Sockets = struct { udp_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 68 });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Build UDP frame
    const udp_payload = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var raw_udp: [udp_wire.HEADER_LEN + 5]u8 = undefined;
    _ = udp_wire.emit(.{
        .src_port = 67,
        .dst_port = 68,
        .length = @intCast(udp_wire.HEADER_LEN + udp_payload.len),
        .checksum = 0,
    }, &raw_udp) catch unreachable;
    @memcpy(raw_udp[udp_wire.HEADER_LEN..], &udp_payload);

    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&frame_buf, .udp, &raw_udp));
    _ = stack.poll(Instant.ZERO, &device);

    // Socket received the data
    try testing.expect(sock.canRecv());
    var recv_buf: [64]u8 = undefined;
    const recv = try sock.recvSlice(&recv_buf);
    try testing.expectEqualSlices(u8, &udp_payload, recv_buf[0..recv.data_len]);

    // No ICMP port unreachable emitted
    try testing.expectEqual(@as(?[]const u8, null), device.dequeueTx());
}

test "stack ICMP echo with bound socket delivers and auto-replies" {
    const icmp_socket_mod = @import("socket/icmp.zig");
    const IcmpSock = icmp_socket_mod.Socket(.{ .payload_size = 128 });
    const Sockets = struct { icmp_sockets: []*IcmpSock };
    const IcmpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]IcmpSock.Packet = undefined;
    var tx_buf: [1]IcmpSock.Packet = undefined;
    var sock = IcmpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .ident = 0x1234 });

    var sock_arr = [_]*IcmpSock{&sock};
    var stack = IcmpStack.init(LOCAL_HW, .{ .icmp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Populate neighbor cache
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Build ICMP echo request
    const echo_data = [_]u8{ 0xDE, 0xAD };
    var icmp_buf: [icmp.HEADER_LEN + 2]u8 = undefined;
    _ = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 42,
    }, &echo_data, &icmp_buf) catch unreachable;

    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&frame_buf, .icmp, &icmp_buf));
    _ = stack.poll(Instant.ZERO, &device);

    // Auto-reply emitted
    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.icmp, ip_repr.protocol);
    const icmp_data = try ipv4.payloadSlice(ip_data);
    const icmp_repr = try icmp.parse(icmp_data);
    switch (icmp_repr) {
        .echo => |echo| {
            try testing.expectEqual(icmp.Type.echo_reply, echo.icmp_type);
            try testing.expectEqual(@as(u16, 0x1234), echo.identifier);
            try testing.expectEqual(@as(u16, 42), echo.sequence);
        },
        .other => return error.ExpectedEchoReply,
    }

    // Socket also received the packet
    try testing.expect(sock.canRecv());
    var recv_buf: [128]u8 = undefined;
    const recv = try sock.recvSlice(&recv_buf);
    try testing.expectEqual(REMOTE_IP, recv.src_addr);
    try testing.expectEqual(icmp.HEADER_LEN + echo_data.len, recv.data_len);
}
