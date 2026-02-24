// Top-level poll loop connecting Device I/O, Interface, and Sockets.
//
// The stack is the integration layer: it receives raw frames from a Device,
// dispatches them through the Interface (ARP, ICMP) and to sockets, then
// serializes and transmits responses and socket egress.
//
// Reference: smoltcp src/iface/interface.rs (poll, socket_ingress, socket_egress)

const ethernet = @import("wire/ethernet.zig");
const arp = @import("wire/arp.zig");
const ipv4 = @import("wire/ipv4.zig");
const icmp = @import("wire/icmp.zig");
const udp_wire = @import("wire/udp.zig");
const tcp_wire = @import("wire/tcp.zig");
const iface_mod = @import("iface.zig");
const time = @import("time.zig");

const Instant = time.Instant;

/// Maximum frame size for serialization scratch buffers.
pub const MAX_FRAME_LEN = 1514; // Ethernet MTU 1500 + 14-byte header

/// Comptime-generic stack over a Device type.
///
/// Device must implement:
///   fn receive(self: *Device) ?[]const u8
///   fn transmit(self: *Device, frame: []const u8) void
pub fn Stack(comptime Device: type) type {
    comptime {
        // Validate Device interface at comptime
        if (!@hasDecl(Device, "receive")) @compileError("Device must have receive()");
        if (!@hasDecl(Device, "transmit")) @compileError("Device must have transmit()");
    }

    return struct {
        const Self = @This();

        iface: iface_mod.Interface,

        pub fn init(hw_addr: ethernet.Address) Self {
            return .{ .iface = iface_mod.Interface.init(hw_addr) };
        }

        /// Process all pending ingress frames and emit responses.
        /// Returns true if any frame was processed.
        pub fn poll(self: *Self, timestamp: Instant, device: *Device) bool {
            self.iface.now = timestamp;
            var processed = false;

            // Drain the RX queue
            while (device.receive()) |rx_frame| {
                self.processIngress(rx_frame, device);
                processed = true;
            }

            return processed;
        }

        /// Compute the next time poll() should be called.
        /// Returns null if there is no pending timer (poll only on new RX).
        pub fn pollAt(self: *const Self) ?Instant {
            _ = self;
            // Interface-level has no timers (ARP expiry is checked on lookup).
            // Socket-level poll_at will be added when socket dispatch is integrated.
            return null;
        }

        fn processIngress(self: *Self, frame: []const u8, device: *Device) void {
            const response = self.iface.processEthernet(frame) orelse return;
            self.emitResponse(response, device);
        }

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
            // First, serialize the IP payload to compute its length
            var payload_buf: [iface_mod.IPV4_MIN_MTU]u8 = undefined;
            const payload_len: usize = switch (resp.payload) {
                .icmp_echo => |echo| icmp.emitEcho(echo.echo, echo.data, &payload_buf) catch return null,
                .icmp_dest_unreachable => |du| blk: {
                    // ICMP dest unreachable: header(8) + invoking IP header + data
                    var invoking_buf: [ipv4.MAX_HEADER_LEN]u8 = undefined;
                    const inv_len = ipv4.emit(du.invoking_repr, &invoking_buf) catch return null;
                    const data_len = @min(du.data.len, iface_mod.IPV4_MIN_MTU - icmp.HEADER_LEN - inv_len);
                    var combined: [iface_mod.IPV4_MIN_MTU]u8 = undefined;
                    @memcpy(combined[0..inv_len], invoking_buf[0..inv_len]);
                    @memcpy(combined[inv_len..][0..data_len], du.data[0..data_len]);
                    const other = icmp.OtherRepr{
                        .icmp_type = .dest_unreachable,
                        .code = du.code,
                        .checksum = 0,
                        .data = 0,
                    };
                    break :blk icmp.emitOther(other, combined[0 .. inv_len + data_len], &payload_buf) catch return null;
                },
            };

            // Now wrap in Ethernet + IPv4
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

            // Look up destination MAC from neighbor cache
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
const TestStack = Stack(TestDevice);

const LOCAL_HW: ethernet.Address = .{ 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
const REMOTE_HW: ethernet.Address = .{ 0x52, 0x54, 0x00, 0x00, 0x00, 0x00 };
const LOCAL_IP: ipv4.Address = .{ 10, 0, 0, 1 };
const REMOTE_IP: ipv4.Address = .{ 10, 0, 0, 2 };

fn testStack() TestStack {
    var s = TestStack.init(LOCAL_HW);
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
    const icmp_len = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 1,
    }, &echo_data, &icmp_buf) catch unreachable;

    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + icmp_len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .icmp,
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
    @memcpy(buf[eth_len + ip_len ..][0..icmp_len], icmp_buf[0..icmp_len]);
    return buf[0 .. eth_len + ip_len + icmp_len];
}

test "stack ARP request produces reply" {
    var device = TestDevice.init();
    var stack = testStack();

    var req_buf: [128]u8 = undefined;
    const req_frame = buildArpRequest(&req_buf);
    device.enqueueRx(req_frame);

    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);

    // Verify TX queue has an ARP reply
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

    // First, do an ARP exchange so the neighbor cache is populated
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx(); // drain ARP reply

    // Now send ICMP echo request
    var req_buf: [256]u8 = undefined;
    device.enqueueRx(buildIcmpEchoRequest(&req_buf));

    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);

    // Verify TX queue has an ICMP echo reply
    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;

    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(ethernet.EtherType.ipv4, eth.ethertype);

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

    // Verify echo reply has valid checksum
    try testing.expect(icmp.verifyChecksum(icmp_data));

    // Verify the destination MAC was resolved from neighbor cache
    try testing.expectEqual(REMOTE_HW, eth.dst_addr);
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

    // Send ARP, poll, loopback the reply, poll again
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);

    // Loopback TX -> RX
    device.loopback();

    // Poll again -- the ARP reply we sent is now received back.
    // Since it's addressed to REMOTE_HW (not us), processEthernet
    // won't generate a response. But it should still be processed.
    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);

    // No new TX frames
    try testing.expectEqual(@as(?[]const u8, null), device.dequeueTx());
}

test "stack pollAt returns null with no sockets" {
    var stack = testStack();
    try testing.expectEqual(@as(?Instant, null), stack.pollAt());
}
