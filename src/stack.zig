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
const dhcp_wire = @import("wire/dhcp.zig");
const dhcp_socket_mod = @import("socket/dhcp.zig");
const dns_socket_mod = @import("socket/dns.zig");
const iface_mod = @import("iface.zig");
const frag_mod = @import("fragmentation.zig");
const time = @import("time.zig");

const Instant = time.Instant;

/// Maximum frame size for serialization scratch buffers.
pub const MAX_FRAME_LEN = 1514; // Ethernet MTU 1500 + 14-byte header

/// Maximum IP payload size (frame minus Ethernet + IPv4 headers).
const IP_PAYLOAD_MAX = MAX_FRAME_LEN - ethernet.HEADER_LEN - ipv4.HEADER_LEN;

/// Serialize a TCP repr (header + payload + checksum) into buf.
/// Returns total byte length on success, or null if buf is too small.
fn serializeTcp(
    repr: tcp_socket.TcpRepr,
    src_addr: ipv4.Address,
    dst_addr: ipv4.Address,
    buf: []u8,
) ?usize {
    const wire_repr = repr.toWireRepr();
    const tcp_len = tcp_wire.emit(wire_repr, buf) catch return null;
    const total = tcp_len + repr.payload.len;
    if (total > buf.len) return null;
    @memcpy(buf[tcp_len..][0..repr.payload.len], repr.payload);
    const cksum = tcp_wire.computeChecksum(src_addr, dst_addr, buf[0..total]);
    buf[16] = @truncate(cksum >> 8);
    buf[17] = @truncate(cksum & 0xFF);
    return total;
}

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
    const has_dhcp = SocketConfig != void and @hasField(SocketConfig, "dhcp_sockets");
    const has_dns = SocketConfig != void and @hasField(SocketConfig, "dns_sockets");

    const FRAG_BUFFER_SIZE = 4096;
    const IP_MTU = MAX_FRAME_LEN - ethernet.HEADER_LEN;

    return struct {
        const Self = @This();

        iface: iface_mod.Interface,
        sockets: SocketConfig,
        fragmenter: frag_mod.Fragmenter(FRAG_BUFFER_SIZE) = .{},
        ipv4_id: u16 = 0,

        pub fn init(hw_addr: ethernet.Address, sockets: SocketConfig) Self {
            return .{
                .iface = iface_mod.Interface.init(hw_addr),
                .sockets = sockets,
            };
        }

        pub fn poll(self: *Self, timestamp: Instant, device: *Device) bool {
            self.iface.now = timestamp;
            var activity = false;

            while (device.receive()) |rx_frame| {
                self.processIngress(timestamp, rx_frame, device);
                activity = true;
            }

            if (self.processEgress(timestamp, device)) activity = true;

            if (!self.fragmenter.isEmpty()) {
                if (self.fragmenter.finished()) {
                    self.fragmenter.reset();
                } else {
                    var frame_buf: [MAX_FRAME_LEN]u8 = undefined;
                    if (self.fragmenter.emitNext(&frame_buf, self.iface.hardware_addr, IP_MTU)) |len| {
                        device.transmit(frame_buf[0..len]);
                        activity = true;
                    }
                }
            }

            return activity;
        }

        pub fn pollAt(self: *const Self) ?Instant {
            var result: ?Instant = null;

            if (comptime has_tcp) {
                for (self.sockets.tcp_sockets) |sock| {
                    result = minOptInstant(result, sock.pollAt());
                }
            }
            if (comptime has_udp) {
                for (self.sockets.udp_sockets) |sock| {
                    result = minOptInstant(result, sock.pollAt());
                }
            }
            if (comptime has_icmp) {
                for (self.sockets.icmp_sockets) |sock| {
                    result = minOptInstant(result, sock.pollAt());
                }
            }
            if (comptime has_dhcp) {
                for (self.sockets.dhcp_sockets) |sock| {
                    result = minOptInstant(result, sock.pollAt());
                }
            }
            if (comptime has_dns) {
                for (self.sockets.dns_sockets) |sock| {
                    result = minOptInstant(result, sock.pollAt());
                }
            }

            return result;
        }

        fn minOptInstant(a: ?Instant, b: ?Instant) ?Instant {
            const bv = b orelse return a;
            const av = a orelse return bv;
            return if (bv.lessThan(av)) bv else av;
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
                    if (comptime has_dhcp) {
                        if (self.routeToDhcpSockets(timestamp, ip_repr, ip_payload)) return;
                    }
                    var handled = self.routeToUdpSockets(ip_repr, ip_payload);
                    if (comptime has_dns) {
                        if (!handled) handled = self.routeToDnsSockets(ip_payload);
                    }
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

        fn routeToDhcpSockets(self: *Self, timestamp: Instant, ip_repr: ipv4.Repr, raw_udp: []const u8) bool {
            if (comptime !has_dhcp) return false;

            const wire_repr = udp_wire.parse(raw_udp) catch return false;
            const payload = udp_wire.payloadSlice(raw_udp) catch return false;

            for (self.sockets.dhcp_sockets) |sock| {
                if (wire_repr.dst_port == sock.client_port and wire_repr.src_port == sock.server_port) {
                    const dhcp_repr = dhcp_wire.parse(payload) catch return false;
                    sock.process(timestamp, ip_repr.src_addr, dhcp_repr);
                    return true;
                }
            }
            return false;
        }

        fn routeToDnsSockets(self: *Self, raw_udp: []const u8) bool {
            if (comptime !has_dns) return false;

            const wire_repr = udp_wire.parse(raw_udp) catch return false;
            if (wire_repr.src_port != dns_socket_mod.DNS_PORT) return false;
            const payload = udp_wire.payloadSlice(raw_udp) catch return false;

            for (self.sockets.dns_sockets) |sock| {
                sock.process(wire_repr.dst_port, payload);
            }
            return true;
        }

        // -- Egress --

        fn processEgress(self: *Self, timestamp: Instant, device: *Device) bool {
            var dispatched = false;

            if (comptime has_tcp) {
                for (self.sockets.tcp_sockets) |sock| {
                    while (sock.dispatch(timestamp)) |result| {
                        self.emitTcpEgress(
                            result.src_addr,
                            result.dst_addr,
                            result.repr,
                            result.hop_limit,
                            device,
                        );
                        dispatched = true;
                    }
                }
            }

            if (comptime has_udp) {
                for (self.sockets.udp_sockets) |sock| {
                    while (sock.dispatch()) |result| {
                        self.emitUdpEgress(result, device);
                        dispatched = true;
                    }
                }
            }

            if (comptime has_icmp) {
                for (self.sockets.icmp_sockets) |sock| {
                    while (sock.dispatch()) |result| {
                        self.emitIcmpEgress(result, device);
                        dispatched = true;
                    }
                }
            }

            if (comptime has_dhcp) {
                for (self.sockets.dhcp_sockets) |sock| {
                    if (sock.dispatch(timestamp)) |result| {
                        self.emitDhcpEgress(sock, result, device);
                        dispatched = true;
                    }
                }
            }

            if (comptime has_dns) {
                for (self.sockets.dns_sockets) |sock| {
                    var dns_buf: [512]u8 = undefined;
                    while (sock.dispatch(timestamp, &dns_buf)) |result| {
                        self.emitDnsEgress(result, device);
                        dispatched = true;
                    }
                }
            }

            return dispatched;
        }

        fn emitIpv4Frame(
            self: *Self,
            src_addr: ipv4.Address,
            dst_addr: ipv4.Address,
            protocol: ipv4.Protocol,
            hop_limit: u8,
            payload_data: []const u8,
            device: *Device,
        ) void {
            const total_ip_len = ipv4.HEADER_LEN + payload_data.len;
            const dst_mac = self.iface.neighbor_cache.lookup(dst_addr, self.iface.now) orelse
                ethernet.BROADCAST;

            if (total_ip_len > IP_MTU) {
                self.ipv4_id +%= 1;
                if (!self.fragmenter.stage(
                    payload_data,
                    src_addr,
                    dst_addr,
                    protocol,
                    hop_limit,
                    self.ipv4_id,
                    dst_mac,
                )) return;

                var frame_buf: [MAX_FRAME_LEN]u8 = undefined;
                if (self.fragmenter.emitNext(&frame_buf, self.iface.hardware_addr, IP_MTU)) |len| {
                    device.transmit(frame_buf[0..len]);
                }
                return;
            }

            var buf: [MAX_FRAME_LEN]u8 = undefined;

            const eth_len = ethernet.emit(.{
                .dst_addr = dst_mac,
                .src_addr = self.iface.hardware_addr,
                .ethertype = .ipv4,
            }, &buf) catch return;

            const ip_len = ipv4.emit(.{
                .version = 4,
                .ihl = 5,
                .dscp_ecn = 0,
                .total_length = @intCast(total_ip_len),
                .identification = 0,
                .dont_fragment = true,
                .more_fragments = false,
                .fragment_offset = 0,
                .ttl = hop_limit,
                .protocol = protocol,
                .checksum = 0,
                .src_addr = src_addr,
                .dst_addr = dst_addr,
            }, buf[eth_len..]) catch return;

            const total = eth_len + ip_len + payload_data.len;
            if (total > buf.len) return;
            @memcpy(buf[eth_len + ip_len ..][0..payload_data.len], payload_data);
            device.transmit(buf[0..total]);
        }

        fn emitTcpEgress(
            self: *Self,
            src_addr: ipv4.Address,
            dst_addr: ipv4.Address,
            repr: tcp_socket.TcpRepr,
            hop_limit: u8,
            device: *Device,
        ) void {
            var payload_buf: [IP_PAYLOAD_MAX]u8 = undefined;
            const total_tcp = serializeTcp(repr, src_addr, dst_addr, &payload_buf) orelse return;
            self.emitIpv4Frame(src_addr, dst_addr, .tcp, hop_limit, payload_buf[0..total_tcp], device);
        }

        fn emitUdpEgress(self: *Self, result: anytype, device: *Device) void {
            var payload_buf: [IP_PAYLOAD_MAX]u8 = undefined;
            const udp_total: u16 = @intCast(udp_wire.HEADER_LEN + result.payload.len);
            const hdr_len = udp_wire.emit(.{
                .src_port = result.repr.src_port,
                .dst_port = result.repr.dst_port,
                .length = udp_total,
                .checksum = 0,
            }, &payload_buf) catch return;
            if (hdr_len + result.payload.len > payload_buf.len) return;
            @memcpy(payload_buf[hdr_len..][0..result.payload.len], result.payload);
            const total = hdr_len + result.payload.len;

            const src_addr = if (!ipv4.isUnspecified(result.src_addr))
                result.src_addr
            else
                (self.iface.getSourceAddress(result.dst_addr) orelse return);

            udp_wire.fillChecksum(payload_buf[0..total], src_addr, result.dst_addr);
            const hop_limit = result.hop_limit orelse iface_mod.DEFAULT_HOP_LIMIT;
            self.emitIpv4Frame(src_addr, result.dst_addr, .udp, hop_limit, payload_buf[0..total], device);
        }

        fn emitIcmpEgress(self: *Self, result: anytype, device: *Device) void {
            const src_addr = self.iface.getSourceAddress(result.dst_addr) orelse
                (self.iface.ipv4Addr() orelse return);
            const hop_limit = result.hop_limit orelse iface_mod.DEFAULT_HOP_LIMIT;
            self.emitIpv4Frame(src_addr, result.dst_addr, .icmp, hop_limit, result.payload, device);
        }

        fn emitDhcpEgress(self: *Self, sock: anytype, result: dhcp_socket_mod.DispatchResult, device: *Device) void {
            var payload_buf: [IP_PAYLOAD_MAX]u8 = undefined;
            const dhcp_len = dhcp_wire.bufferLen(result.dhcp_repr);
            const udp_total: u16 = @intCast(udp_wire.HEADER_LEN + dhcp_len);
            const hdr_len = udp_wire.emit(.{
                .src_port = sock.client_port,
                .dst_port = sock.server_port,
                .length = udp_total,
                .checksum = 0,
            }, &payload_buf) catch return;
            if (hdr_len + dhcp_len > payload_buf.len) return;
            _ = dhcp_wire.emit(result.dhcp_repr, payload_buf[hdr_len..]) catch return;
            const total = hdr_len + dhcp_len;

            udp_wire.fillChecksum(payload_buf[0..total], result.src_ip, result.dst_ip);
            self.emitIpv4Frame(result.src_ip, result.dst_ip, .udp, iface_mod.DEFAULT_HOP_LIMIT, payload_buf[0..total], device);
        }

        fn emitDnsEgress(self: *Self, result: dns_socket_mod.DispatchResult, device: *Device) void {
            var payload_buf: [IP_PAYLOAD_MAX]u8 = undefined;
            const udp_total: u16 = @intCast(udp_wire.HEADER_LEN + result.payload.len);
            const hdr_len = udp_wire.emit(.{
                .src_port = result.src_port,
                .dst_port = dns_socket_mod.DNS_PORT,
                .length = udp_total,
                .checksum = 0,
            }, &payload_buf) catch return;
            if (hdr_len + result.payload.len > payload_buf.len) return;
            @memcpy(payload_buf[hdr_len..][0..result.payload.len], result.payload);
            const total = hdr_len + result.payload.len;

            const src_addr = self.iface.getSourceAddress(result.dst_ip) orelse return;
            udp_wire.fillChecksum(payload_buf[0..total], src_addr, result.dst_ip);
            self.emitIpv4Frame(src_addr, result.dst_ip, .udp, iface_mod.DEFAULT_HOP_LIMIT, payload_buf[0..total], device);
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
            var payload_buf: [IP_PAYLOAD_MAX]u8 = undefined;
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
                .tcp => |tcp_repr| serializeTcp(tcp_repr, resp.ip.src_addr, resp.ip.dst_addr, &payload_buf) orelse return null,
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
    return buildIpv4FrameFrom(buf, REMOTE_IP, LOCAL_IP, protocol, payload_data);
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

// -------------------------------------------------------------------------
// Egress tests
// -------------------------------------------------------------------------

const icmp_socket_mod = @import("socket/icmp.zig");

test "stack TCP egress dispatches SYN on connect" {
    const TcpSock = tcp_socket.Socket(4);
    const Sockets = struct { tcp_sockets: []*TcpSock };
    const TcpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var rx_buf: [64]u8 = .{0} ** 64;
        var tx_buf: [64]u8 = .{0} ** 64;
    };
    @memset(&S.rx_buf, 0);
    @memset(&S.tx_buf, 0);
    var sock = TcpSock.init(&S.rx_buf, &S.tx_buf);
    sock.ack_delay = null;
    try sock.connect(REMOTE_IP, 4242, LOCAL_IP, 4243);

    var sock_arr = [_]*TcpSock{&sock};
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);

    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(ethernet.EtherType.ipv4, eth.ethertype);

    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.tcp, ip_repr.protocol);
    try testing.expectEqual(LOCAL_IP, ip_repr.src_addr);
    try testing.expectEqual(REMOTE_IP, ip_repr.dst_addr);

    const tcp_data = try ipv4.payloadSlice(ip_data);
    const tcp_repr = try tcp_wire.parse(tcp_data);
    try testing.expect(tcp_repr.flags.syn);
    try testing.expectEqual(@as(u16, 4243), tcp_repr.src_port);
    try testing.expectEqual(@as(u16, 4242), tcp_repr.dst_port);

    // Verify TCP checksum
    try testing.expectEqual(@as(u16, 0), tcp_wire.computeChecksum(
        ip_repr.src_addr,
        ip_repr.dst_addr,
        tcp_data,
    ));
}

test "stack TCP handshake completes via listen" {
    const TcpSock = tcp_socket.Socket(4);
    const Sockets = struct { tcp_sockets: []*TcpSock };
    const TcpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var rx_buf: [256]u8 = .{0} ** 256;
        var tx_buf: [256]u8 = .{0} ** 256;
    };
    @memset(&S.rx_buf, 0);
    @memset(&S.tx_buf, 0);
    var sock = TcpSock.init(&S.rx_buf, &S.tx_buf);
    sock.ack_delay = null;
    try sock.listen(.{ .port = 4243 });

    var sock_arr = [_]*TcpSock{&sock};
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Populate neighbor cache via ARP.
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // -- Step 1: Inject SYN from remote --
    const REMOTE_SEQ: u32 = 1000;
    var syn_buf: [tcp_wire.HEADER_LEN]u8 = undefined;
    _ = tcp_wire.emit(.{
        .src_port = 4242,
        .dst_port = 4243,
        .seq_number = REMOTE_SEQ,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .syn = true },
        .window_size = 1024,
        .checksum = 0,
        .urgent_pointer = 0,
    }, &syn_buf) catch unreachable;

    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&frame_buf, .tcp, &syn_buf));
    _ = stack.poll(Instant.ZERO, &device);

    // -- Step 2: Dequeue SYN-ACK, verify flags, extract server ISN --
    const synack_frame = device.dequeueTx() orelse return error.ExpectedSynAck;
    const synack_ip = try ethernet.payload(synack_frame);
    const synack_tcp = try ipv4.payloadSlice(synack_ip);
    const synack_repr = try tcp_wire.parse(synack_tcp);
    try testing.expect(synack_repr.flags.syn);
    try testing.expect(synack_repr.flags.ack);
    try testing.expectEqual(REMOTE_SEQ + 1, synack_repr.ack_number);
    const server_isn = synack_repr.seq_number;

    // -- Step 3: Inject ACK to complete handshake --
    var ack_buf: [tcp_wire.HEADER_LEN]u8 = undefined;
    _ = tcp_wire.emit(.{
        .src_port = 4242,
        .dst_port = 4243,
        .seq_number = REMOTE_SEQ + 1,
        .ack_number = server_isn + 1,
        .data_offset = 5,
        .flags = .{ .ack = true },
        .window_size = 1024,
        .checksum = 0,
        .urgent_pointer = 0,
    }, &ack_buf) catch unreachable;

    var ack_frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&ack_frame_buf, .tcp, &ack_buf));
    _ = stack.poll(Instant.ZERO, &device);

    try testing.expectEqual(tcp_socket.State.established, sock.state);

    // -- Step 4: Inject data segment with "Hi" --
    const payload = "Hi";
    var data_tcp_buf: [tcp_wire.HEADER_LEN + payload.len]u8 = undefined;
    _ = tcp_wire.emit(.{
        .src_port = 4242,
        .dst_port = 4243,
        .seq_number = REMOTE_SEQ + 1,
        .ack_number = server_isn + 1,
        .data_offset = 5,
        .flags = .{ .ack = true, .psh = true },
        .window_size = 1024,
        .checksum = 0,
        .urgent_pointer = 0,
    }, &data_tcp_buf) catch unreachable;
    @memcpy(data_tcp_buf[tcp_wire.HEADER_LEN..], payload);

    var data_frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&data_frame_buf, .tcp, &data_tcp_buf));
    _ = stack.poll(Instant.ZERO, &device);

    try testing.expect(sock.canRecv());
    var recv_buf: [64]u8 = undefined;
    const n = try sock.recvSlice(&recv_buf);
    try testing.expectEqualSlices(u8, payload, recv_buf[0..n]);
}

test "stack UDP egress dispatches datagram" {
    const UdpSock = udp_socket_mod.Socket(.{ .payload_size = 64 });
    const Sockets = struct { udp_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 12345 });
    try sock.sendSlice("Hello", .{
        .endpoint = .{ .addr = REMOTE_IP, .port = 54321 },
    });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);

    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.udp, ip_repr.protocol);
    try testing.expectEqual(LOCAL_IP, ip_repr.src_addr);
    try testing.expectEqual(REMOTE_IP, ip_repr.dst_addr);

    const udp_data = try ipv4.payloadSlice(ip_data);
    const udp_repr = try udp_wire.parse(udp_data);
    try testing.expectEqual(@as(u16, 12345), udp_repr.src_port);
    try testing.expectEqual(@as(u16, 54321), udp_repr.dst_port);
    try testing.expectEqual(@as(u16, udp_wire.HEADER_LEN + 5), udp_repr.length);

    const payload = try udp_wire.payloadSlice(udp_data);
    try testing.expectEqualSlices(u8, "Hello", payload);

    // Verify UDP checksum
    try testing.expect(udp_wire.verifyChecksum(udp_data, ip_repr.src_addr, ip_repr.dst_addr));
}

test "stack ICMP egress dispatches echo request" {
    const IcmpSock = icmp_socket_mod.Socket(.{ .payload_size = 128 });
    const Sockets = struct { icmp_sockets: []*IcmpSock };
    const IcmpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]IcmpSock.Packet = undefined;
    var tx_buf: [1]IcmpSock.Packet = undefined;
    var sock = IcmpSock.init(&rx_buf, &tx_buf);

    // Build an ICMP echo request to send
    const echo_data = [_]u8{ 0xCA, 0xFE };
    var icmp_buf: [icmp.HEADER_LEN + 2]u8 = undefined;
    _ = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0xABCD,
        .sequence = 7,
    }, &echo_data, &icmp_buf) catch unreachable;

    try sock.sendSlice(&icmp_buf, REMOTE_IP);

    var sock_arr = [_]*IcmpSock{&sock};
    var stack = IcmpStack.init(LOCAL_HW, .{ .icmp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);

    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.icmp, ip_repr.protocol);
    try testing.expectEqual(LOCAL_IP, ip_repr.src_addr);
    try testing.expectEqual(REMOTE_IP, ip_repr.dst_addr);

    const icmp_data = try ipv4.payloadSlice(ip_data);
    try testing.expectEqualSlices(u8, &icmp_buf, icmp_data);
}

test "stack poll returns true for egress-only activity" {
    const UdpSock = udp_socket_mod.Socket(.{ .payload_size = 64 });
    const Sockets = struct { udp_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 100 });
    try sock.sendSlice("X", .{
        .endpoint = .{ .addr = REMOTE_IP, .port = 200 },
    });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // No RX frames, but socket has data to send.
    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);
    try testing.expect(device.dequeueTx() != null);
}

test "stack pollAt returns ZERO for pending TCP SYN-SENT" {
    const TcpSock = tcp_socket.Socket(4);
    const Sockets = struct { tcp_sockets: []*TcpSock };
    const TcpStack = Stack(TestDevice, Sockets);

    const S = struct {
        var rx_buf: [64]u8 = .{0} ** 64;
        var tx_buf: [64]u8 = .{0} ** 64;
    };
    @memset(&S.rx_buf, 0);
    @memset(&S.tx_buf, 0);
    var sock = TcpSock.init(&S.rx_buf, &S.tx_buf);
    sock.ack_delay = null;
    try sock.connect(REMOTE_IP, 80, LOCAL_IP, 5000);

    var sock_arr = [_]*TcpSock{&sock};
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    try testing.expectEqual(Instant.ZERO, stack.pollAt().?);
}

test "stack pollAt returns null for idle sockets" {
    const UdpSock = udp_socket_mod.Socket(.{ .payload_size = 64 });
    const Sockets = struct { udp_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 100 });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Socket bound but no pending TX -- pollAt should be null.
    try testing.expectEqual(@as(?Instant, null), stack.pollAt());
}

test "stack egress uses cached neighbor MAC" {
    const UdpSock = udp_socket_mod.Socket(.{ .payload_size = 64 });
    const Sockets = struct { udp_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 100 });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Populate neighbor cache via ARP exchange
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx(); // ARP reply

    // Now send a UDP packet; it should use the cached MAC for REMOTE_IP
    try sock.sendSlice("hi", .{
        .endpoint = .{ .addr = REMOTE_IP, .port = 200 },
    });
    _ = stack.poll(Instant.ZERO, &device);

    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(REMOTE_HW, eth.dst_addr);
}

test "stack pollAt returns retransmit deadline after SYN dispatch" {
    const TcpSock = tcp_socket.Socket(4);
    const Sockets = struct { tcp_sockets: []*TcpSock };
    const TcpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var rx_buf: [64]u8 = .{0} ** 64;
        var tx_buf: [64]u8 = .{0} ** 64;
    };
    @memset(&S.rx_buf, 0);
    @memset(&S.tx_buf, 0);
    var sock = TcpSock.init(&S.rx_buf, &S.tx_buf);
    sock.ack_delay = null;
    try sock.connect(REMOTE_IP, 80, LOCAL_IP, 5000);

    var sock_arr = [_]*TcpSock{&sock};
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Before poll: SYN-SENT needs to transmit, so pollAt = ZERO
    try testing.expectEqual(Instant.ZERO, stack.pollAt().?);

    // After poll: SYN dispatched, retransmit timer armed (RTO = 1000ms)
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    const poll_at = stack.pollAt() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Instant.fromMillis(1000), poll_at);
}

// -------------------------------------------------------------------------
// DHCP stack integration tests
// -------------------------------------------------------------------------

test "stack DHCP discover dispatches via UDP broadcast" {
    const DhcpSock = dhcp_socket_mod.Socket;
    const Sockets = struct { dhcp_sockets: []*DhcpSock };
    const DhcpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();
    var sock = DhcpSock.init(LOCAL_HW);
    _ = sock.poll(); // consume initial deconfigured event

    var sock_arr = [_]*DhcpSock{&sock};
    var stack = DhcpStack.init(LOCAL_HW, .{ .dhcp_sockets = &sock_arr });

    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);

    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(ethernet.BROADCAST, eth.dst_addr);

    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual([4]u8{ 0, 0, 0, 0 }, ip_repr.src_addr);
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, ip_repr.dst_addr);
    try testing.expectEqual(ipv4.Protocol.udp, ip_repr.protocol);

    const udp_data = try ipv4.payloadSlice(ip_data);
    const udp_repr = try udp_wire.parse(udp_data);
    try testing.expectEqual(@as(u16, 68), udp_repr.src_port);
    try testing.expectEqual(@as(u16, 67), udp_repr.dst_port);

    const dhcp_payload = try udp_wire.payloadSlice(udp_data);
    const dhcp_repr = try dhcp_wire.parse(dhcp_payload);
    try testing.expectEqual(dhcp_wire.MessageType.discover, dhcp_repr.message_type);
}

test "stack DHCP ingress processes offer" {
    const DhcpSock = dhcp_socket_mod.Socket;
    const Sockets = struct { dhcp_sockets: []*DhcpSock };
    const DhcpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();
    var sock = DhcpSock.init(LOCAL_HW);
    _ = sock.poll();

    var sock_arr = [_]*DhcpSock{&sock};
    var stack = DhcpStack.init(LOCAL_HW, .{ .dhcp_sockets = &sock_arr });

    // Dispatch discover.
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Build OFFER frame: Server -> client.
    const server_ip = [4]u8{ 10, 0, 0, 1 };
    const offered_ip = [4]u8{ 10, 0, 0, 42 };

    const offer_repr = dhcp_wire.Repr{
        .message_type = .offer,
        .transaction_id = sock.transaction_id,
        .secs = 0,
        .client_hardware_address = LOCAL_HW,
        .client_ip = .{ 0, 0, 0, 0 },
        .your_ip = offered_ip,
        .server_ip = server_ip,
        .router = server_ip,
        .subnet_mask = .{ 255, 255, 255, 0 },
        .relay_agent_ip = .{ 0, 0, 0, 0 },
        .broadcast = false,
        .requested_ip = null,
        .client_identifier = null,
        .server_identifier = server_ip,
        .parameter_request_list = null,
        .max_size = null,
        .lease_duration = 3600,
        .renew_duration = null,
        .rebind_duration = null,
        .dns_servers = null,
    };

    var dhcp_buf: [576]u8 = undefined;
    const dhcp_len = dhcp_wire.emit(offer_repr, &dhcp_buf) catch unreachable;

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
    var frame_buf: [MAX_FRAME_LEN]u8 = undefined;
    const frame_ip = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + udp_hdr_len + dhcp_len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .udp,
        .checksum = 0,
        .src_addr = server_ip,
        .dst_addr = .{ 255, 255, 255, 255 },
    };
    const frame_eth = ethernet.Repr{
        .dst_addr = ethernet.BROADCAST,
        .src_addr = REMOTE_HW,
        .ethertype = .ipv4,
    };
    const eth_len = ethernet.emit(frame_eth, &frame_buf) catch unreachable;
    const ip_len = ipv4.emit(frame_ip, frame_buf[eth_len..]) catch unreachable;
    @memcpy(frame_buf[eth_len + ip_len ..][0 .. udp_hdr_len + dhcp_len], udp_buf[0 .. udp_hdr_len + dhcp_len]);
    const total_frame_len = eth_len + ip_len + udp_hdr_len + dhcp_len;

    // Need to accept broadcast -- set any_ip or add broadcast addr.
    stack.iface.any_ip = true;
    device.enqueueRx(frame_buf[0..total_frame_len]);
    _ = stack.poll(Instant.ZERO, &device);

    // Socket should have transitioned to requesting -> dispatch produces REQUEST.
    const tx2 = device.dequeueTx();
    if (tx2) |frame| {
        const ip_data2 = ethernet.payload(frame) catch unreachable;
        const udp_data2 = ipv4.payloadSlice(ip_data2) catch unreachable;
        const dhcp_payload2 = udp_wire.payloadSlice(udp_data2) catch unreachable;
        const dhcp_repr2 = dhcp_wire.parse(dhcp_payload2) catch unreachable;
        try testing.expectEqual(dhcp_wire.MessageType.request, dhcp_repr2.message_type);
    } else {
        // Socket processed the offer; verify state transition to requesting.
        switch (sock.state) {
            .requesting => {},
            else => return error.TestExpectedEqual,
        }
    }
}

test "stack DHCP pollAt returns socket deadline" {
    const DhcpSock = dhcp_socket_mod.Socket;
    const Sockets = struct { dhcp_sockets: []*DhcpSock };
    const DhcpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();
    var sock = DhcpSock.init(LOCAL_HW);
    _ = sock.poll();

    var sock_arr = [_]*DhcpSock{&sock};
    var stack = DhcpStack.init(LOCAL_HW, .{ .dhcp_sockets = &sock_arr });

    // Before dispatch: pollAt should be ZERO (ready to discover immediately).
    try testing.expectEqual(Instant.ZERO, stack.pollAt().?);

    // After discover dispatch: retry timeout is 10s.
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    const poll_at = stack.pollAt() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Instant.fromSecs(10), poll_at);
}

// -------------------------------------------------------------------------
// DNS stack integration tests
// -------------------------------------------------------------------------

test "stack DNS query dispatches via UDP" {
    const DnsSock = dns_socket_mod.Socket;
    const Sockets = struct { dns_sockets: []*DnsSock };
    const DnsStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var slots: [4]dns_socket_mod.QuerySlot = [_]dns_socket_mod.QuerySlot{.{}} ** 4;
    };
    @memset(@as([*]u8, @ptrCast(&S.slots))[0..@sizeOf(@TypeOf(S.slots))], 0);
    const servers = [_][4]u8{.{ 8, 8, 8, 8 }};
    var sock = DnsSock.init(&S.slots, &servers);
    _ = try sock.startQuery("example.com", .a);

    var sock_arr = [_]*DnsSock{&sock};
    var stack = DnsStack.init(LOCAL_HW, .{ .dns_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);

    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.udp, ip_repr.protocol);
    try testing.expectEqual(LOCAL_IP, ip_repr.src_addr);
    try testing.expectEqual([4]u8{ 8, 8, 8, 8 }, ip_repr.dst_addr);

    const udp_data = try ipv4.payloadSlice(ip_data);
    const udp_repr = try udp_wire.parse(udp_data);
    try testing.expectEqual(@as(u16, 49152), udp_repr.src_port);
    try testing.expectEqual(@as(u16, 53), udp_repr.dst_port);
}

test "stack DNS ingress delivers response" {
    const dns_wire = @import("wire/dns.zig");
    const DnsSock = dns_socket_mod.Socket;
    const Sockets = struct { dns_sockets: []*DnsSock };
    const DnsStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var slots: [4]dns_socket_mod.QuerySlot = [_]dns_socket_mod.QuerySlot{.{}} ** 4;
    };
    @memset(@as([*]u8, @ptrCast(&S.slots))[0..@sizeOf(@TypeOf(S.slots))], 0);
    const servers = [_][4]u8{.{ 8, 8, 8, 8 }};
    var sock = DnsSock.init(&S.slots, &servers);
    const handle = try sock.startQuery("example.com", .a);

    var sock_arr = [_]*DnsSock{&sock};
    var stack = DnsStack.init(LOCAL_HW, .{ .dns_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Dispatch query.
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Build DNS A-record response.
    const txid: u16 = 0xABCD;
    const answer_ip = [4]u8{ 93, 184, 216, 34 };

    // Encode "example.com" in wire format.
    const wire_name = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    var resp_buf: [512]u8 = undefined;
    @memset(&resp_buf, 0);

    // DNS header.
    resp_buf[0] = @truncate(txid >> 8);
    resp_buf[1] = @truncate(txid);
    const resp_flags: u16 = dns_wire.Flags.RESPONSE | dns_wire.Flags.RECURSION_DESIRED | dns_wire.Flags.RECURSION_AVAILABLE;
    resp_buf[2] = @truncate(resp_flags >> 8);
    resp_buf[3] = @truncate(resp_flags);
    resp_buf[5] = 1; // QDCOUNT
    resp_buf[7] = 1; // ANCOUNT

    // Question section.
    var pos: usize = 12;
    @memcpy(resp_buf[pos..][0..wire_name.len], &wire_name);
    pos += wire_name.len;
    resp_buf[pos + 1] = 1; // TYPE A
    resp_buf[pos + 3] = 1; // CLASS IN
    pos += 4;

    // Answer: pointer to name at offset 12.
    resp_buf[pos] = 0xc0;
    resp_buf[pos + 1] = 0x0c;
    pos += 2;
    resp_buf[pos + 1] = 1; // TYPE A
    resp_buf[pos + 3] = 1; // CLASS IN
    pos += 4;
    resp_buf[pos + 3] = 60; // TTL
    pos += 4;
    resp_buf[pos + 1] = 4; // RDLENGTH
    pos += 2;
    @memcpy(resp_buf[pos..][0..4], &answer_ip);
    pos += 4;

    // Wrap in UDP (53 -> 49152).
    var udp_resp: [600]u8 = undefined;
    const resp_udp_total: u16 = @intCast(udp_wire.HEADER_LEN + pos);
    const resp_udp_hdr = udp_wire.emit(.{
        .src_port = 53,
        .dst_port = 49152,
        .length = resp_udp_total,
        .checksum = 0,
    }, &udp_resp) catch unreachable;
    @memcpy(udp_resp[resp_udp_hdr..][0..pos], resp_buf[0..pos]);

    var frame_buf: [MAX_FRAME_LEN]u8 = undefined;
    const resp_frame = buildIpv4FrameFrom(&frame_buf, .{ 8, 8, 8, 8 }, LOCAL_IP, .udp, udp_resp[0 .. resp_udp_hdr + pos]);
    device.enqueueRx(resp_frame);
    _ = stack.poll(Instant.fromMillis(100), &device);

    const result = try sock.getQueryResult(handle);
    try testing.expectEqual(@as(u8, 1), result.len);
    try testing.expectEqualSlices(u8, &answer_ip, &result.addrs[0]);
}

test "stack DNS pollAt returns retransmit deadline" {
    const DnsSock = dns_socket_mod.Socket;
    const Sockets = struct { dns_sockets: []*DnsSock };
    const DnsStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var slots: [4]dns_socket_mod.QuerySlot = [_]dns_socket_mod.QuerySlot{.{}} ** 4;
    };
    @memset(@as([*]u8, @ptrCast(&S.slots))[0..@sizeOf(@TypeOf(S.slots))], 0);
    const servers = [_][4]u8{.{ 8, 8, 8, 8 }};
    var sock = DnsSock.init(&S.slots, &servers);
    _ = try sock.startQuery("example.com", .a);

    var sock_arr = [_]*DnsSock{&sock};
    var stack = DnsStack.init(LOCAL_HW, .{ .dns_sockets = &sock_arr });
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // After dispatch: retransmit delay is 1s.
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    const poll_at = stack.pollAt() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Instant.fromSecs(1), poll_at);
}

// -------------------------------------------------------------------------
// IPv4 fragmentation integration tests
// -------------------------------------------------------------------------

test "stack IPv4 fragmentation never exceeds MTU" {
    // [smoltcp:iface/interface/tests/ipv4.rs:test_packet_len]
    const FragDevice = LoopbackDevice(16);
    const FragStack = Stack(FragDevice, void);

    var device = FragDevice.init();
    var stack = FragStack.init(LOCAL_HW, {});
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Populate neighbor cache via ARP exchange.
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Test payload sizes: fits in one frame, exactly at IP MTU limit,
    // one byte over, and well over (multiple fragments).
    const test_sizes = [_]usize{ 100, IP_PAYLOAD_MAX, IP_PAYLOAD_MAX + 1, 3000 };

    for (test_sizes) |size| {
        var payload: [3000]u8 = undefined;
        for (payload[0..size], 0..) |*b, i| b.* = @truncate(i);

        stack.emitIpv4Frame(LOCAL_IP, REMOTE_IP, .udp, 64, payload[0..size], &device);

        while (device.dequeueTx()) |frame| {
            try testing.expect(frame.len <= MAX_FRAME_LEN);
        }

        // Drain remaining fragments via poll.
        while (!stack.fragmenter.isEmpty()) {
            if (stack.fragmenter.finished()) {
                stack.fragmenter.reset();
                break;
            }
            _ = stack.poll(Instant.ZERO, &device);
            while (device.dequeueTx()) |frame| {
                try testing.expect(frame.len <= MAX_FRAME_LEN);
            }
        }
        stack.fragmenter.reset();
    }
}

test "stack IPv4 fragment payload is 8-byte aligned" {
    // [smoltcp:iface/interface/tests/ipv4.rs:test_ipv4_fragment_size]
    const FragDevice = LoopbackDevice(16);
    const FragStack = Stack(FragDevice, void);

    var device = FragDevice.init();
    var stack = FragStack.init(LOCAL_HW, {});
    stack.iface.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Populate neighbor cache.
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Send a payload requiring 3+ fragments.
    var payload: [3000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    stack.emitIpv4Frame(LOCAL_IP, REMOTE_IP, .udp, 64, &payload, &device);

    var frag_count: usize = 0;
    var total_ip_payload: usize = 0;

    while (true) {
        while (device.dequeueTx()) |frame| {
            const ip_data = try ethernet.payload(frame);
            const ip_repr = try ipv4.parse(ip_data);
            const ip_payload_len = @as(usize, ip_repr.total_length) - ipv4.HEADER_LEN;
            total_ip_payload += ip_payload_len;

            // Non-final fragments must have 8-byte-aligned payloads.
            if (ip_repr.more_fragments) {
                try testing.expect(ip_payload_len % frag_mod.IPV4_FRAGMENT_ALIGNMENT == 0);
            }
            frag_count += 1;
        }

        if (stack.fragmenter.isEmpty() or stack.fragmenter.finished()) break;
        _ = stack.poll(Instant.ZERO, &device);
    }

    try testing.expect(frag_count >= 3);
    try testing.expectEqual(@as(usize, 3000), total_ip_payload);
}

fn buildIpv4FrameFrom(buf: []u8, src: ipv4.Address, dst: ipv4.Address, protocol: ipv4.Protocol, payload_data: []const u8) []const u8 {
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
        .src_addr = src,
        .dst_addr = dst,
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
