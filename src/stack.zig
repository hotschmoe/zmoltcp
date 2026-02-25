// Top-level poll loop: Device I/O -> Interface (ARP, ICMP) -> Sockets.
//
// Reference: smoltcp src/iface/interface.rs (poll, socket_ingress, socket_egress)

const std = @import("std");
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
const raw_socket_mod = @import("socket/raw.zig");
const igmp_wire = @import("wire/igmp.zig");
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
/// When `fill_checksum` is false, the checksum field is left zeroed
/// (for hardware offload).
fn serializeTcp(
    repr: tcp_socket.TcpRepr,
    src_addr: ipv4.Address,
    dst_addr: ipv4.Address,
    buf: []u8,
    fill_checksum: bool,
) ?usize {
    const wire_repr = repr.toWireRepr();
    const tcp_len = tcp_wire.emit(wire_repr, buf) catch return null;
    const total = tcp_len + repr.payload.len;
    if (total > buf.len) return null;
    @memcpy(buf[tcp_len..][0..repr.payload.len], repr.payload);
    if (fill_checksum) {
        const cksum = tcp_wire.computeChecksum(src_addr, dst_addr, buf[0..total]);
        buf[16] = @truncate(cksum >> 8);
        buf[17] = @truncate(cksum & 0xFF);
    }
    return total;
}

/// Comptime-generic stack over a Device and optional SocketConfig.
///
/// Device must implement:
///   fn receive(self: *Device) ?[]const u8
///   fn transmit(self: *Device, frame: []const u8) void
///
/// SocketConfig is either `void` (no sockets) or a struct with optional fields:
///   tcp4_sockets: []*SomeTcpSocket
///   udp4_sockets: []*SomeUdpSocket
///   icmp4_sockets: []*SomeIcmpSocket
///   raw4_sockets: []*SomeRawSocket
pub fn Stack(comptime Device: type, comptime SocketConfig: type) type {
    comptime {
        if (!@hasDecl(Device, "receive")) @compileError("Device must have receive()");
        if (!@hasDecl(Device, "transmit")) @compileError("Device must have transmit()");
    }

    const has_tcp4 = SocketConfig != void and @hasField(SocketConfig, "tcp4_sockets");
    const has_udp4 = SocketConfig != void and @hasField(SocketConfig, "udp4_sockets");
    const has_icmp4 = SocketConfig != void and @hasField(SocketConfig, "icmp4_sockets");
    const has_dhcp = SocketConfig != void and @hasField(SocketConfig, "dhcp_sockets");
    const has_dns4 = SocketConfig != void and @hasField(SocketConfig, "dns4_sockets");
    const has_raw4 = SocketConfig != void and @hasField(SocketConfig, "raw4_sockets");

    const FRAG_BUFFER_SIZE = 4096;
    const REASSEMBLY_BUFFER_SIZE = 1500;
    const REASSEMBLY_MAX_SEGMENTS = 4;
    const IP_MTU = MAX_FRAME_LEN - ethernet.HEADER_LEN;

    const device_caps: iface_mod.DeviceCapabilities = if (@hasDecl(Device, "capabilities"))
        Device.capabilities()
    else
        .{};

    return struct {
        const Self = @This();

        const EmitResult = enum { sent, neighbor_pending };
        pub const DEFAULT_REASSEMBLY_TIMEOUT = time.Duration.fromSecs(60);

        iface: iface_mod.Interface,
        sockets: SocketConfig,
        fragmenter: frag_mod.Fragmenter(FRAG_BUFFER_SIZE) = .{},
        reassembler: frag_mod.Reassembler(.{
            .buffer_size = REASSEMBLY_BUFFER_SIZE,
            .max_segments = REASSEMBLY_MAX_SEGMENTS,
        }) = .{},
        ipv4_id: u16 = 0,
        reassembly_timeout: time.Duration = DEFAULT_REASSEMBLY_TIMEOUT,

        pub fn init(hw_addr: ethernet.Address, sockets: SocketConfig) Self {
            return .{
                .iface = iface_mod.Interface.init(hw_addr),
                .sockets = sockets,
            };
        }

        pub fn poll(self: *Self, timestamp: Instant, device: *Device) bool {
            self.iface.now = timestamp;
            self.reassembler.removeExpired(timestamp);
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

            if (comptime has_tcp4) {
                for (self.sockets.tcp4_sockets) |sock| {
                    if (sock.pollAt()) |sock_at| {
                        const effective = self.adjustForNeighbor(sock_at, if (sock.tuple) |t| t.remote.addr else null);
                        result = minOptInstant(result, effective);
                    }
                }
            }
            if (comptime has_udp4) {
                for (self.sockets.udp4_sockets) |sock| {
                    if (sock.pollAt()) |sock_at| {
                        const effective = self.adjustForNeighbor(sock_at, sock.peekDstAddr());
                        result = minOptInstant(result, effective);
                    }
                }
            }
            if (comptime has_icmp4) {
                for (self.sockets.icmp4_sockets) |sock| {
                    if (sock.pollAt()) |sock_at| {
                        const effective = self.adjustForNeighbor(sock_at, sock.peekDstAddr());
                        result = minOptInstant(result, effective);
                    }
                }
            }
            if (comptime has_dhcp) {
                for (self.sockets.dhcp_sockets) |sock| {
                    result = minOptInstant(result, sock.pollAt());
                }
            }
            if (comptime has_dns4) {
                for (self.sockets.dns4_sockets) |sock| {
                    result = minOptInstant(result, sock.pollAt());
                }
            }
            if (comptime has_raw4) {
                for (self.sockets.raw4_sockets) |sock| {
                    if (sock.pollAt()) |sock_at| {
                        const effective = self.adjustForNeighbor(sock_at, sock.peekDstAddr());
                        result = minOptInstant(result, effective);
                    }
                }
            }

            return result;
        }

        fn adjustForNeighbor(self: *const Self, sock_at: Instant, dst: ?ipv4.Address) Instant {
            const addr = dst orelse return sock_at;
            if (self.iface.isBroadcast(addr) or ipv4.isBroadcast(addr)) return sock_at;
            const next_hop = self.iface.route(addr) orelse return sock_at;
            return switch (self.iface.neighbor_cache.lookupFull(next_hop, sock_at)) {
                .rate_limited => self.iface.neighbor_cache.silent_until,
                else => sock_at,
            };
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
                .ipv4 => {
                    const ip_repr = ipv4.parse(payload_data) catch return;
                    // RFC 1122: reject packets with broadcast or multicast
                    // source address -- such packets are never valid.
                    if (ipv4.isBroadcast(ip_repr.src_addr) or ipv4.isMulticast(ip_repr.src_addr)) return;
                    // Opportunistic neighbor caching: learn source MAC from
                    // incoming IPv4 frames when the source is on our subnet,
                    // so response packets can find the neighbor without a
                    // separate ARP exchange.
                    if (!ipv4.isUnspecified(ip_repr.src_addr) and self.iface.v4.inSameNetwork(ip_repr.src_addr)) {
                        self.iface.neighbor_cache.fill(ip_repr.src_addr, eth_repr.src_addr, self.iface.now);
                    }
                    self.processIpv4Ingress(timestamp, ip_repr, payload_data, device);
                },
                else => {},
            }
        }

        fn processIpv4Ingress(self: *Self, timestamp: Instant, ip_repr: ipv4.Repr, data: []const u8, device: *Device) void {
            const is_broadcast = self.iface.isBroadcast(ip_repr.dst_addr);
            const is_multicast = ipv4.isMulticast(ip_repr.dst_addr) and self.iface.hasMulticastGroup(ip_repr.dst_addr);
            if (!is_broadcast and !is_multicast and !self.iface.v4.hasIpAddr(ip_repr.dst_addr)) return;

            const raw_payload = ipv4.payloadSlice(data) catch return;

            const ip_payload = if (frag_mod.isFragment(ip_repr)) blk: {
                const key = frag_mod.FragKey{
                    .id = ip_repr.identification,
                    .src_addr = ip_repr.src_addr,
                    .dst_addr = ip_repr.dst_addr,
                    .protocol = ip_repr.protocol,
                };
                const byte_offset = @as(usize, ip_repr.fragment_offset) * 8;
                const expires_at = timestamp.add(self.reassembly_timeout);
                self.reassembler.accept(key, expires_at);
                if (!ip_repr.more_fragments) {
                    self.reassembler.setTotalSize(byte_offset + raw_payload.len);
                }
                if (!self.reassembler.add(raw_payload, byte_offset)) return;
                break :blk self.reassembler.assemble() orelse return;
            } else raw_payload;

            const raw_handled = self.routeToRawSockets(ip_repr, ip_payload);

            switch (ip_repr.protocol) {
                .icmp => {
                    self.routeToIcmpSockets(ip_repr, ip_payload);
                    if (self.iface.processIcmp(ip_repr, ip_payload, is_broadcast)) |response| {
                        self.emitResponse(response, device);
                    }
                },
                .udp => {
                    if (self.routeToDhcpSockets(timestamp, ip_repr, ip_payload)) return;
                    var handled = self.routeToUdpSockets(ip_repr, ip_payload);
                    if (!handled) handled = self.routeToDnsSockets(ip_payload);
                    if (self.iface.processUdp(ip_repr, ip_payload, handled)) |response| {
                        self.emitResponse(response, device);
                    }
                },
                .igmp => {
                    self.processIgmp(ip_payload, device);
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
                    if (is_broadcast or raw_handled) return;
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
            if (comptime !has_tcp4) return .{};

            const sock_repr = tcp_socket.TcpRepr.fromWireBytes(tcp_data) orelse return .{};

            for (self.sockets.tcp4_sockets) |sock| {
                if (sock.accepts(ip_repr.src_addr, ip_repr.dst_addr, sock_repr)) {
                    const reply = sock.process(timestamp, ip_repr.src_addr, ip_repr.dst_addr, sock_repr);
                    return .{ .reply = reply, .handled = true };
                }
            }
            return .{};
        }

        fn routeToUdpSockets(self: *Self, ip_repr: ipv4.Repr, raw_udp: []const u8) bool {
            if (comptime !has_udp4) return false;

            const wire_repr = udp_wire.parse(raw_udp) catch return false;
            const payload = udp_wire.payloadSlice(raw_udp) catch return false;
            const sock_repr = udp_socket_mod.UdpRepr{
                .src_port = wire_repr.src_port,
                .dst_port = wire_repr.dst_port,
            };

            var handled = false;
            for (self.sockets.udp4_sockets) |sock| {
                if (sock.accepts(ip_repr.src_addr, ip_repr.dst_addr, sock_repr)) {
                    sock.process(ip_repr.src_addr, ip_repr.dst_addr, sock_repr, payload);
                    handled = true;
                }
            }
            return handled;
        }

        fn routeToIcmpSockets(self: *Self, ip_repr: ipv4.Repr, icmp_data: []const u8) void {
            if (comptime !has_icmp4) return;

            const icmp_repr = icmp.parse(icmp_data) catch return;
            const icmp_payload = if (icmp_data.len > icmp.HEADER_LEN)
                icmp_data[icmp.HEADER_LEN..]
            else
                &[_]u8{};

            for (self.sockets.icmp4_sockets) |sock| {
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
            if (comptime !has_dns4) return false;

            const wire_repr = udp_wire.parse(raw_udp) catch return false;
            if (wire_repr.src_port != dns_socket_mod.DNS_PORT) return false;
            const payload = udp_wire.payloadSlice(raw_udp) catch return false;

            for (self.sockets.dns4_sockets) |sock| {
                sock.process(wire_repr.dst_port, payload);
            }
            return true;
        }

        fn processIgmp(self: *Self, ip_payload: []const u8, device: *Device) void {
            const repr = igmp_wire.parse(ip_payload) catch return;
            switch (repr) {
                .membership_query => |q| {
                    if (ipv4.isUnspecified(q.group_addr)) {
                        for (self.iface.multicast_groups) |slot| {
                            if (slot) |group| {
                                self.emitIgmpReport(group, device);
                            }
                        }
                    } else if (self.iface.hasMulticastGroup(q.group_addr)) {
                        self.emitIgmpReport(q.group_addr, device);
                    }
                },
                .membership_report, .leave_group => {},
            }
        }

        fn emitIgmpReport(self: *Self, group_addr: ipv4.Address, device: *Device) void {
            var igmp_buf: [igmp_wire.HEADER_LEN]u8 = undefined;
            _ = igmp_wire.emit(.{ .membership_report = .{
                .group_addr = group_addr,
                .version = .v2,
            } }, &igmp_buf) catch return;
            const src_addr = self.iface.ipv4Addr() orelse return;
            _ = self.emitIpv4Frame(src_addr, group_addr, .igmp, 1, &igmp_buf, device);
        }

        fn multicastMac(addr: ipv4.Address) ethernet.Address {
            return .{ 0x01, 0x00, 0x5e, addr[1] & 0x7F, addr[2], addr[3] };
        }

        fn routeToRawSockets(self: *Self, ip_repr: ipv4.Repr, ip_payload: []const u8) bool {
            if (comptime !has_raw4) return false;

            var handled = false;
            for (self.sockets.raw4_sockets) |sock| {
                if (sock.accepts(ip_repr.protocol)) {
                    sock.process(ip_repr.src_addr, ip_repr.protocol, ip_payload);
                    handled = true;
                }
            }
            return handled;
        }

        // -- Egress --

        fn processEgress(self: *Self, timestamp: Instant, device: *Device) bool {
            var dispatched = false;
            var burst_budget: usize = device_caps.max_burst_size orelse std.math.maxInt(usize);

            if (comptime has_tcp4) {
                for (self.sockets.tcp4_sockets) |sock| {
                    if (burst_budget == 0) break;
                    if (sock.tuple) |tuple| {
                        if (!self.neighborAvailableOrRequest(tuple.remote.addr, device)) continue;
                    }
                    while (sock.dispatch(timestamp)) |result| {
                        _ = self.emitTcpEgress(
                            result.src_addr,
                            result.dst_addr,
                            result.repr,
                            result.hop_limit,
                            device,
                        );
                        dispatched = true;
                        burst_budget -= 1;
                        if (burst_budget == 0) break;
                    }
                }
            }

            if (comptime has_udp4) {
                for (self.sockets.udp4_sockets) |sock| {
                    if (burst_budget == 0) break;
                    if (sock.peekDstAddr()) |dst| {
                        if (!self.neighborAvailableOrRequest(dst, device)) continue;
                    }
                    while (sock.dispatch()) |result| {
                        _ = self.emitUdpEgress(result, device);
                        dispatched = true;
                        burst_budget -= 1;
                        if (burst_budget == 0) break;
                    }
                }
            }

            if (comptime has_icmp4) {
                for (self.sockets.icmp4_sockets) |sock| {
                    if (burst_budget == 0) break;
                    if (sock.peekDstAddr()) |dst| {
                        if (!self.neighborAvailableOrRequest(dst, device)) continue;
                    }
                    while (sock.dispatch()) |result| {
                        _ = self.emitIcmpEgress(result, device);
                        dispatched = true;
                        burst_budget -= 1;
                        if (burst_budget == 0) break;
                    }
                }
            }

            if (comptime has_dhcp) {
                for (self.sockets.dhcp_sockets) |sock| {
                    if (burst_budget == 0) break;
                    if (sock.dispatch(timestamp)) |result| {
                        self.emitDhcpEgress(sock, result, device);
                        dispatched = true;
                        burst_budget -= 1;
                    }
                }
            }

            if (comptime has_dns4) {
                for (self.sockets.dns4_sockets) |sock| {
                    if (burst_budget == 0) break;
                    var dns_buf: [512]u8 = undefined;
                    while (sock.dispatch(timestamp, &dns_buf)) |result| {
                        if (self.emitDnsEgress(result, device) == .neighbor_pending) break;
                        dispatched = true;
                        burst_budget -= 1;
                        if (burst_budget == 0) break;
                    }
                }
            }

            if (comptime has_raw4) {
                for (self.sockets.raw4_sockets) |sock| {
                    if (burst_budget == 0) break;
                    if (sock.peekDstAddr()) |dst| {
                        if (!self.neighborAvailableOrRequest(dst, device)) continue;
                    }
                    while (sock.dispatch()) |result| {
                        _ = self.emitRawEgress(result, device);
                        dispatched = true;
                        burst_budget -= 1;
                        if (burst_budget == 0) break;
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
        ) EmitResult {
            const dst_mac = if (ipv4.isMulticast(dst_addr))
                multicastMac(dst_addr)
            else if (self.iface.isBroadcast(dst_addr) or ipv4.isBroadcast(dst_addr))
                ethernet.BROADCAST
            else blk: {
                const next_hop = self.iface.route(dst_addr) orelse return .neighbor_pending;
                break :blk switch (self.iface.neighbor_cache.lookupFull(next_hop, self.iface.now)) {
                    .found => |mac| mac,
                    .rate_limited => return .neighbor_pending,
                    .not_found => {
                        self.emitArpRequest(next_hop, device);
                        self.iface.neighbor_cache.limitRate(self.iface.now);
                        return .neighbor_pending;
                    },
                };
            };

            const total_ip_len = ipv4.HEADER_LEN + payload_data.len;

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
                )) return .sent;

                var frame_buf: [MAX_FRAME_LEN]u8 = undefined;
                if (self.fragmenter.emitNext(&frame_buf, self.iface.hardware_addr, IP_MTU)) |len| {
                    device.transmit(frame_buf[0..len]);
                }
                return .sent;
            }

            var buf: [MAX_FRAME_LEN]u8 = undefined;

            const eth_len = ethernet.emit(.{
                .dst_addr = dst_mac,
                .src_addr = self.iface.hardware_addr,
                .ethertype = .ipv4,
            }, &buf) catch return .sent;

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
            }, buf[eth_len..]) catch return .sent;

            const total = eth_len + ip_len + payload_data.len;
            if (total > buf.len) return .sent;
            @memcpy(buf[eth_len + ip_len ..][0..payload_data.len], payload_data);
            device.transmit(buf[0..total]);
            return .sent;
        }

        fn emitArpRequest(self: *Self, target_ip: ipv4.Address, device: *Device) void {
            const src_ip = self.iface.v4.getSourceAddress(target_ip) orelse
                (self.iface.ipv4Addr() orelse return);
            var buf: [ethernet.HEADER_LEN + arp.HEADER_LEN]u8 = undefined;
            const eth_len = ethernet.emit(.{
                .dst_addr = ethernet.BROADCAST,
                .src_addr = self.iface.hardware_addr,
                .ethertype = .arp,
            }, &buf) catch return;
            const arp_len = arp.emit(.{
                .operation = .request,
                .source_hardware_addr = self.iface.hardware_addr,
                .source_protocol_addr = src_ip,
                .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 },
                .target_protocol_addr = target_ip,
            }, buf[eth_len..]) catch return;
            device.transmit(buf[0 .. eth_len + arp_len]);
        }

        fn neighborAvailableOrRequest(self: *Self, dst_addr: ipv4.Address, device: *Device) bool {
            if (self.iface.isBroadcast(dst_addr) or ipv4.isBroadcast(dst_addr)) return true;
            const next_hop = self.iface.route(dst_addr) orelse return false;
            switch (self.iface.neighbor_cache.lookupFull(next_hop, self.iface.now)) {
                .found => return true,
                .rate_limited => return false,
                .not_found => {
                    self.emitArpRequest(next_hop, device);
                    self.iface.neighbor_cache.limitRate(self.iface.now);
                    return false;
                },
            }
        }

        fn emitTcpEgress(
            self: *Self,
            src_addr: ipv4.Address,
            dst_addr: ipv4.Address,
            repr: tcp_socket.TcpRepr,
            hop_limit: u8,
            device: *Device,
        ) EmitResult {
            var payload_buf: [IP_PAYLOAD_MAX]u8 = undefined;
            const total_tcp = serializeTcp(repr, src_addr, dst_addr, &payload_buf, device_caps.checksum.tcp.shouldComputeTx()) orelse return .sent;
            return self.emitIpv4Frame(src_addr, dst_addr, .tcp, hop_limit, payload_buf[0..total_tcp], device);
        }

        fn emitUdpEgress(self: *Self, result: anytype, device: *Device) EmitResult {
            var payload_buf: [IP_PAYLOAD_MAX]u8 = undefined;
            const udp_total: u16 = @intCast(udp_wire.HEADER_LEN + result.payload.len);
            const hdr_len = udp_wire.emit(.{
                .src_port = result.repr.src_port,
                .dst_port = result.repr.dst_port,
                .length = udp_total,
                .checksum = 0,
            }, &payload_buf) catch return .sent;
            if (hdr_len + result.payload.len > payload_buf.len) return .sent;
            @memcpy(payload_buf[hdr_len..][0..result.payload.len], result.payload);
            const total = hdr_len + result.payload.len;

            const src_addr = if (!ipv4.isUnspecified(result.src_addr))
                result.src_addr
            else
                (self.iface.v4.getSourceAddress(result.dst_addr) orelse return .sent);

            if (device_caps.checksum.udp.shouldComputeTx())
                udp_wire.fillChecksum(payload_buf[0..total], src_addr, result.dst_addr);
            const hop_limit = result.hop_limit orelse iface_mod.DEFAULT_HOP_LIMIT;
            return self.emitIpv4Frame(src_addr, result.dst_addr, .udp, hop_limit, payload_buf[0..total], device);
        }

        fn emitIcmpEgress(self: *Self, result: anytype, device: *Device) EmitResult {
            const src_addr = self.iface.v4.getSourceAddress(result.dst_addr) orelse
                (self.iface.ipv4Addr() orelse return .sent);
            const hop_limit = result.hop_limit orelse iface_mod.DEFAULT_HOP_LIMIT;
            return self.emitIpv4Frame(src_addr, result.dst_addr, .icmp, hop_limit, result.payload, device);
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

            if (device_caps.checksum.udp.shouldComputeTx())
                udp_wire.fillChecksum(payload_buf[0..total], result.src_ip, result.dst_ip);
            _ = self.emitIpv4Frame(result.src_ip, result.dst_ip, .udp, iface_mod.DEFAULT_HOP_LIMIT, payload_buf[0..total], device);
        }

        fn emitDnsEgress(self: *Self, result: anytype, device: *Device) EmitResult {
            var payload_buf: [IP_PAYLOAD_MAX]u8 = undefined;
            const udp_total: u16 = @intCast(udp_wire.HEADER_LEN + result.payload.len);
            const hdr_len = udp_wire.emit(.{
                .src_port = result.src_port,
                .dst_port = dns_socket_mod.DNS_PORT,
                .length = udp_total,
                .checksum = 0,
            }, &payload_buf) catch return .sent;
            if (hdr_len + result.payload.len > payload_buf.len) return .sent;
            @memcpy(payload_buf[hdr_len..][0..result.payload.len], result.payload);
            const total = hdr_len + result.payload.len;

            const src_addr = self.iface.v4.getSourceAddress(result.dst_ip) orelse return .sent;
            if (device_caps.checksum.udp.shouldComputeTx())
                udp_wire.fillChecksum(payload_buf[0..total], src_addr, result.dst_ip);
            return self.emitIpv4Frame(src_addr, result.dst_ip, .udp, iface_mod.DEFAULT_HOP_LIMIT, payload_buf[0..total], device);
        }

        fn emitRawEgress(self: *Self, result: anytype, device: *Device) EmitResult {
            const src_addr = self.iface.v4.getSourceAddress(result.dst_addr) orelse
                (self.iface.ipv4Addr() orelse return .sent);
            const hop_limit = result.hop_limit orelse iface_mod.DEFAULT_HOP_LIMIT;
            return self.emitIpv4Frame(src_addr, result.dst_addr, result.ip_protocol, hop_limit, result.payload, device);
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
                .tcp => |tcp_repr| serializeTcp(tcp_repr, resp.ip.src_addr, resp.ip.dst_addr, &payload_buf, device_caps.checksum.tcp.shouldComputeTx()) orelse return null,
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

            const dst_mac = if (self.iface.isBroadcast(resp.ip.dst_addr) or ipv4.isBroadcast(resp.ip.dst_addr))
                ethernet.BROADCAST
            else blk: {
                const next_hop = self.iface.route(resp.ip.dst_addr) orelse return null;
                break :blk self.iface.neighbor_cache.lookup(next_hop, self.iface.now) orelse return null;
            };

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
    s.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
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

fn emitTestFrame(buf: []u8, ip_repr: ipv4.Repr, payload_data: []const u8) []const u8 {
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

fn buildIpv4FrameFrom(buf: []u8, src: ipv4.Address, dst: ipv4.Address, protocol: ipv4.Protocol, payload_data: []const u8) []const u8 {
    return emitTestFrame(buf, .{
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
    }, payload_data);
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
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 68 });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

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
    const IcmpSock = icmp_socket_mod.Socket(ipv4, .{ .payload_size = 128 });
    const Sockets = struct { icmp4_sockets: []*IcmpSock };
    const IcmpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]IcmpSock.Packet = undefined;
    var tx_buf: [1]IcmpSock.Packet = undefined;
    var sock = IcmpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .ident = 0x1234 });

    var sock_arr = [_]*IcmpSock{&sock};
    var stack = IcmpStack.init(LOCAL_HW, .{ .icmp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

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
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
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
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    stack.iface.neighbor_cache.fill(REMOTE_IP, REMOTE_HW, Instant.ZERO);

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
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
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
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

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
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
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
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    stack.iface.neighbor_cache.fill(REMOTE_IP, REMOTE_HW, Instant.ZERO);

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
    const IcmpSock = icmp_socket_mod.Socket(ipv4, .{ .payload_size = 128 });
    const Sockets = struct { icmp4_sockets: []*IcmpSock };
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
    var stack = IcmpStack.init(LOCAL_HW, .{ .icmp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    stack.iface.neighbor_cache.fill(REMOTE_IP, REMOTE_HW, Instant.ZERO);

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
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
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
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    stack.iface.neighbor_cache.fill(REMOTE_IP, REMOTE_HW, Instant.ZERO);

    // No RX frames, but socket has data to send.
    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);
    try testing.expect(device.dequeueTx() != null);
}

test "stack pollAt returns ZERO for pending TCP SYN-SENT" {
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
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
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    try testing.expectEqual(Instant.ZERO, stack.pollAt().?);
}

test "stack pollAt returns null for idle sockets" {
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 100 });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Socket bound but no pending TX -- pollAt should be null.
    try testing.expectEqual(@as(?Instant, null), stack.pollAt());
}

test "stack egress uses cached neighbor MAC" {
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 100 });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

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
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
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
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

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
    const DnsSock = dns_socket_mod.Socket(ipv4);
    const Sockets = struct { dns4_sockets: []*DnsSock };
    const DnsStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var slots: [4]DnsSock.QuerySlot = [_]DnsSock.QuerySlot{.{}} ** 4;
    };
    @memset(@as([*]u8, @ptrCast(&S.slots))[0..@sizeOf(@TypeOf(S.slots))], 0);
    const servers = [_][4]u8{.{ 8, 8, 8, 8 }};
    var sock = DnsSock.init(&S.slots, &servers);
    _ = try sock.startQuery("example.com", .a);

    var sock_arr = [_]*DnsSock{&sock};
    var stack = DnsStack.init(LOCAL_HW, .{ .dns4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    // DNS server 8.8.8.8 is off-subnet; add a default gateway route.
    const gateway: ipv4.Address = .{ 10, 0, 0, 254 };
    _ = stack.iface.v4.routes.add(iface_mod.Route.newDefaultGateway(gateway));
    stack.iface.neighbor_cache.fill(gateway, REMOTE_HW, Instant.ZERO);

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
    const DnsSock = dns_socket_mod.Socket(ipv4);
    const Sockets = struct { dns4_sockets: []*DnsSock };
    const DnsStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var slots: [4]DnsSock.QuerySlot = [_]DnsSock.QuerySlot{.{}} ** 4;
    };
    @memset(@as([*]u8, @ptrCast(&S.slots))[0..@sizeOf(@TypeOf(S.slots))], 0);
    const servers = [_][4]u8{.{ 8, 8, 8, 8 }};
    var sock = DnsSock.init(&S.slots, &servers);
    const handle = try sock.startQuery("example.com", .a);

    var sock_arr = [_]*DnsSock{&sock};
    var stack = DnsStack.init(LOCAL_HW, .{ .dns4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    const gateway2: ipv4.Address = .{ 10, 0, 0, 254 };
    _ = stack.iface.v4.routes.add(iface_mod.Route.newDefaultGateway(gateway2));
    stack.iface.neighbor_cache.fill(gateway2, REMOTE_HW, Instant.ZERO);

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
    const DnsSock = dns_socket_mod.Socket(ipv4);
    const Sockets = struct { dns4_sockets: []*DnsSock };
    const DnsStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var slots: [4]DnsSock.QuerySlot = [_]DnsSock.QuerySlot{.{}} ** 4;
    };
    @memset(@as([*]u8, @ptrCast(&S.slots))[0..@sizeOf(@TypeOf(S.slots))], 0);
    const servers = [_][4]u8{.{ 8, 8, 8, 8 }};
    var sock = DnsSock.init(&S.slots, &servers);
    _ = try sock.startQuery("example.com", .a);

    var sock_arr = [_]*DnsSock{&sock};
    var stack = DnsStack.init(LOCAL_HW, .{ .dns4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    const gateway3: ipv4.Address = .{ 10, 0, 0, 254 };
    _ = stack.iface.v4.routes.add(iface_mod.Route.newDefaultGateway(gateway3));
    stack.iface.neighbor_cache.fill(gateway3, REMOTE_HW, Instant.ZERO);

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
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

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

        _ = stack.emitIpv4Frame(LOCAL_IP, REMOTE_IP, .udp, 64, payload[0..size], &device);

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
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Populate neighbor cache.
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Send a payload requiring 3+ fragments.
    var payload: [3000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    _ = stack.emitIpv4Frame(LOCAL_IP, REMOTE_IP, .udp, 64, &payload, &device);

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

// -------------------------------------------------------------------------
// ARP neighbor resolution tests
// -------------------------------------------------------------------------

test "stack emits ARP request for unknown neighbor on TCP egress" {
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
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
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    // Do NOT populate neighbor cache -- force ARP resolution.

    _ = stack.poll(Instant.ZERO, &device);

    // Should have emitted an ARP request, not a TCP SYN.
    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(ethernet.EtherType.arp, eth.ethertype);

    const arp_data = try ethernet.payload(tx_frame);
    const arp_repr = try arp.parse(arp_data);
    try testing.expectEqual(arp.Operation.request, arp_repr.operation);
    try testing.expectEqual(LOCAL_IP, arp_repr.source_protocol_addr);
    try testing.expectEqual(REMOTE_IP, arp_repr.target_protocol_addr);

    // No more frames -- TCP SYN was held back.
    try testing.expect(device.dequeueTx() == null);
}

test "stack TCP SYN sent after ARP resolution" {
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
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
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // First poll: unknown neighbor -> ARP request.
    _ = stack.poll(Instant.ZERO, &device);
    const arp_frame = device.dequeueTx() orelse return error.ExpectedArpFrame;
    const eth0 = try ethernet.parse(arp_frame);
    try testing.expectEqual(ethernet.EtherType.arp, eth0.ethertype);

    // Simulate ARP reply arriving (populate neighbor cache).
    stack.iface.neighbor_cache.fill(REMOTE_IP, REMOTE_HW, Instant.ZERO);

    // Advance past rate-limit window.
    const after_silent = Instant.fromMillis(iface_mod.NeighborCache.SILENT_TIME.totalMillis() + 1);
    const activity = stack.poll(after_silent, &device);
    try testing.expect(activity);

    // Now the TCP SYN should be emitted.
    const syn_frame = device.dequeueTx() orelse return error.ExpectedSynFrame;
    const eth1 = try ethernet.parse(syn_frame);
    try testing.expectEqual(ethernet.EtherType.ipv4, eth1.ethertype);

    const ip_data = try ethernet.payload(syn_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.tcp, ip_repr.protocol);
}

test "stack ARP request rate limited" {
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
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
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // First poll at t=0: emits ARP request.
    _ = stack.poll(Instant.ZERO, &device);
    try testing.expect(device.dequeueTx() != null); // ARP request
    try testing.expect(device.dequeueTx() == null);

    // Second poll at t=500ms (within SILENT_TIME): should NOT emit another ARP.
    _ = stack.poll(Instant.fromMillis(500), &device);
    try testing.expect(device.dequeueTx() == null);

    // Third poll at t=1001ms (past SILENT_TIME): should emit new ARP request.
    _ = stack.poll(Instant.fromMillis(1001), &device);
    const frame = device.dequeueTx() orelse return error.ExpectedArpRetry;
    const eth = try ethernet.parse(frame);
    try testing.expectEqual(ethernet.EtherType.arp, eth.ethertype);
}

test "stack UDP does not lose packet during ARP resolution" {
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
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
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // First poll: unknown neighbor -> ARP request, packet stays in TX buffer.
    _ = stack.poll(Instant.ZERO, &device);
    const arp_frame = device.dequeueTx() orelse return error.ExpectedArpFrame;
    const eth0 = try ethernet.parse(arp_frame);
    try testing.expectEqual(ethernet.EtherType.arp, eth0.ethertype);
    try testing.expect(device.dequeueTx() == null);

    // Packet should still be queued -- peekDstAddr still returns something.
    try testing.expect(sock.peekDstAddr() != null);

    // Resolve neighbor and advance past rate-limit.
    stack.iface.neighbor_cache.fill(REMOTE_IP, REMOTE_HW, Instant.ZERO);
    const after_silent = Instant.fromMillis(iface_mod.NeighborCache.SILENT_TIME.totalMillis() + 1);
    _ = stack.poll(after_silent, &device);

    // Now the UDP datagram should be emitted.
    const udp_frame = device.dequeueTx() orelse return error.ExpectedUdpFrame;
    const ip_data = try ethernet.payload(udp_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.udp, ip_repr.protocol);
    try testing.expectEqual(REMOTE_IP, ip_repr.dst_addr);
}

test "stack ICMP echo reply uses cached neighbor from ingress" {
    var device = TestDevice.init();
    var stack = testStack();

    // Send an ICMP echo request from REMOTE_IP (arriving on wire, no prior ARP).
    const echo_data = [_]u8{ 0xDE, 0xAD };
    var icmp_buf: [icmp.HEADER_LEN + 2]u8 = undefined;
    _ = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 1,
    }, &echo_data, &icmp_buf) catch unreachable;

    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&frame_buf, .icmp, &icmp_buf));

    _ = stack.poll(Instant.ZERO, &device);

    // Opportunistic caching should have learned REMOTE_IP -> REMOTE_HW.
    const cached = stack.iface.neighbor_cache.lookup(REMOTE_IP, Instant.ZERO);
    try testing.expect(cached != null);
    try testing.expectEqual(REMOTE_HW, cached.?);

    // The ICMP echo reply should have been emitted (not dropped).
    const reply_frame = device.dequeueTx() orelse {
        // Might also be an ARP reply from the buildIpv4Frame's ARP, skip it.
        return error.ExpectedReplyFrame;
    };
    const ip_data = try ethernet.payload(reply_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.icmp, ip_repr.protocol);
    try testing.expectEqual(REMOTE_IP, ip_repr.dst_addr);
}

test "stack pollAt accounts for neighbor resolution delay" {
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
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
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Trigger ARP request (sets rate limit).
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx(); // ARP request

    // pollAt should return silent_until, not ZERO.
    const poll_at = stack.pollAt() orelse return error.ExpectedPollAt;
    try testing.expect(poll_at.greaterThanOrEqual(Instant.fromMillis(
        iface_mod.NeighborCache.SILENT_TIME.totalMillis(),
    )));
}

test "stack broadcast destination skips ARP resolution" {
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 100 });
    // Send to broadcast address.
    try sock.sendSlice("bcast", .{
        .endpoint = .{ .addr = .{ 255, 255, 255, 255 }, .port = 200 },
    });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    // Do NOT populate neighbor cache.

    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);

    // Should emit the UDP frame directly (no ARP).
    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(ethernet.EtherType.ipv4, eth.ethertype);
    try testing.expectEqual(ethernet.BROADCAST, eth.dst_addr);

    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.udp, ip_repr.protocol);
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, ip_repr.dst_addr);
}

// -------------------------------------------------------------------------
// IPv4 reassembly tests
// -------------------------------------------------------------------------

fn buildFragment(
    buf: []u8,
    protocol: ipv4.Protocol,
    ident: u16,
    frag_offset_8: u13,
    more_frags: bool,
    payload_data: []const u8,
) []const u8 {
    return emitTestFrame(buf, .{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + payload_data.len),
        .identification = ident,
        .dont_fragment = false,
        .more_fragments = more_frags,
        .fragment_offset = frag_offset_8,
        .ttl = 64,
        .protocol = protocol,
        .checksum = 0,
        .src_addr = REMOTE_IP,
        .dst_addr = LOCAL_IP,
    }, payload_data);
}

test "stack reassembles two-fragment ICMP echo" {
    var device = TestDevice.init();
    var stack = testStack();

    // Build an ICMP echo request split into two fragments.
    // Fragment 1: bytes [0..8) with more_fragments=true
    // Fragment 2: bytes [8..16) with more_fragments=false
    var icmp_payload: [16]u8 = undefined;
    // ICMP header (8 bytes): type=8 (echo request), code=0, checksum=0, id=0x1234, seq=1
    icmp_payload[0] = 8; // echo request
    icmp_payload[1] = 0; // code
    icmp_payload[2] = 0; // checksum (high)
    icmp_payload[3] = 0; // checksum (low)
    icmp_payload[4] = 0x12; // identifier high
    icmp_payload[5] = 0x34; // identifier low
    icmp_payload[6] = 0x00; // sequence high
    icmp_payload[7] = 0x01; // sequence low
    // Echo data: 8 bytes
    for (icmp_payload[8..], 0..) |*b, i| b.* = @as(u8, @truncate(i + 0xA0));

    // Compute ICMP checksum over full payload.
    var cksum: u32 = 0;
    var ci: usize = 0;
    while (ci < icmp_payload.len) : (ci += 2) {
        cksum += @as(u32, icmp_payload[ci]) << 8 | icmp_payload[ci + 1];
    }
    while (cksum >> 16 != 0) cksum = (cksum & 0xFFFF) + (cksum >> 16);
    const final_cksum: u16 = @truncate(~cksum);
    icmp_payload[2] = @truncate(final_cksum >> 8);
    icmp_payload[3] = @truncate(final_cksum & 0xFF);

    var frag1_buf: [256]u8 = undefined;
    var frag2_buf: [256]u8 = undefined;

    // Fragment 1: offset=0, more_fragments=true, 8 bytes of ICMP
    device.enqueueRx(buildFragment(&frag1_buf, .icmp, 42, 0, true, icmp_payload[0..8]));
    _ = stack.poll(Instant.ZERO, &device);
    // Should not produce a reply yet (incomplete).
    try testing.expect(device.dequeueTx() == null);

    // Fragment 2: offset=1 (8 bytes / 8), more_fragments=false, 8 bytes
    device.enqueueRx(buildFragment(&frag2_buf, .icmp, 42, 1, false, icmp_payload[8..16]));
    _ = stack.poll(Instant.ZERO, &device);

    // Should produce an ICMP echo reply.
    const reply_frame = device.dequeueTx() orelse return error.ExpectedReply;
    const ip_data = try ethernet.payload(reply_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.icmp, ip_repr.protocol);
    try testing.expectEqual(REMOTE_IP, ip_repr.dst_addr);
}

test "stack reassembles out-of-order UDP fragments" {
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 128 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
    const UdpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();
    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 12345 });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = UdpStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Build a UDP payload split into two fragments (out of order).
    // Total: UDP header (8 bytes) + 8 bytes data = 16 bytes
    var udp_payload: [16]u8 = undefined;
    // UDP header: src_port=54321, dst_port=12345, length=16, checksum=0
    udp_payload[0] = 0xD4; // src_port high (54321 = 0xD431)
    udp_payload[1] = 0x31; // src_port low
    udp_payload[2] = 0x30; // dst_port high (12345 = 0x3039)
    udp_payload[3] = 0x39; // dst_port low
    udp_payload[4] = 0x00; // length high
    udp_payload[5] = 0x10; // length low (16)
    udp_payload[6] = 0x00; // checksum disabled
    udp_payload[7] = 0x00;
    for (udp_payload[8..], 0..) |*b, i| b.* = @as(u8, @truncate(i + 0xBB));

    var frag1_buf: [256]u8 = undefined;
    var frag2_buf: [256]u8 = undefined;

    // Send fragment 2 first (out of order): offset=1 (8/8), 8 bytes, more_fragments=false
    device.enqueueRx(buildFragment(&frag2_buf, .udp, 99, 1, false, udp_payload[8..16]));
    _ = stack.poll(Instant.ZERO, &device);
    try testing.expect(!sock.canRecv());

    // Send fragment 1: offset=0, 8 bytes, more_fragments=true
    device.enqueueRx(buildFragment(&frag1_buf, .udp, 99, 0, true, udp_payload[0..8]));
    _ = stack.poll(Instant.ZERO, &device);

    // Socket should have received the reassembled datagram.
    try testing.expect(sock.canRecv());
}

test "stack non-fragmented packets bypass reassembly" {
    var device = TestDevice.init();
    var stack = testStack();

    // Send a normal (non-fragmented) ICMP echo request.
    const echo_data = [_]u8{ 0xCA, 0xFE };
    var icmp_buf: [icmp.HEADER_LEN + 2]u8 = undefined;
    _ = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x5678,
        .sequence = 1,
    }, &echo_data, &icmp_buf) catch unreachable;

    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&frame_buf, .icmp, &icmp_buf));
    _ = stack.poll(Instant.ZERO, &device);

    // Should get an immediate ICMP echo reply (no reassembly involved).
    const reply = device.dequeueTx() orelse return error.ExpectedReply;
    const ip_data = try ethernet.payload(reply);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.icmp, ip_repr.protocol);

    // Reassembler should still be free (never touched).
    try testing.expect(stack.reassembler.isFree());
}

// -- Ingress hardening tests --

test "stack rejects IPv4 with broadcast source address" {
    var device = TestDevice.init();
    var stack = testStack();

    // Populate neighbor cache so a response would normally be sent.
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Build ICMP echo with broadcast source address (255.255.255.255).
    const echo_data = [_]u8{ 0xDE, 0xAD };
    var icmp_buf: [icmp.HEADER_LEN + 2]u8 = undefined;
    _ = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 1,
    }, &echo_data, &icmp_buf) catch unreachable;

    var frame_buf: [256]u8 = undefined;
    const bcast_src: ipv4.Address = .{ 255, 255, 255, 255 };
    device.enqueueRx(buildIpv4FrameFrom(&frame_buf, bcast_src, LOCAL_IP, .icmp, &icmp_buf));

    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);
    // No reply should be generated for broadcast-sourced packets.
    try testing.expectEqual(@as(?[]const u8, null), device.dequeueTx());
}

test "stack rejects IPv4 with multicast source address" {
    var device = TestDevice.init();
    var stack = testStack();

    // Populate neighbor cache.
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Build ICMP echo with multicast source address (224.0.0.1).
    const echo_data = [_]u8{ 0xDE, 0xAD };
    var icmp_buf: [icmp.HEADER_LEN + 2]u8 = undefined;
    _ = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 1,
    }, &echo_data, &icmp_buf) catch unreachable;

    var frame_buf: [256]u8 = undefined;
    const mcast_src: ipv4.Address = .{ 224, 0, 0, 1 };
    device.enqueueRx(buildIpv4FrameFrom(&frame_buf, mcast_src, LOCAL_IP, .icmp, &icmp_buf));

    const processed = stack.poll(Instant.ZERO, &device);
    try testing.expect(processed);
    try testing.expectEqual(@as(?[]const u8, null), device.dequeueTx());
}

test "stack neighbor cache refresh gated by same network" {
    var device = TestDevice.init();
    var stack = testStack();

    // Send ICMP from a same-subnet source (10.0.0.99).
    const echo_data = [_]u8{ 0xDE, 0xAD };
    var icmp_buf: [icmp.HEADER_LEN + 2]u8 = undefined;
    _ = icmp.emitEcho(.{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 1,
    }, &echo_data, &icmp_buf) catch unreachable;

    const same_net: ipv4.Address = .{ 10, 0, 0, 99 };
    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4FrameFrom(&frame_buf, same_net, LOCAL_IP, .icmp, &icmp_buf));
    _ = stack.poll(Instant.ZERO, &device);

    // Same-subnet source should be cached.
    try testing.expect(stack.iface.neighbor_cache.lookup(same_net, stack.iface.now) != null);

    // Now send from a different subnet (192.168.1.1) -- should NOT be cached.
    const diff_net: ipv4.Address = .{ 192, 168, 1, 1 };
    // We need the packet to actually be accepted by processIpv4Ingress,
    // so we add the diff_net address to the interface.
    stack.iface.v4.addIpAddr(.{ .address = diff_net, .prefix_len = 24 });

    var frame_buf2: [256]u8 = undefined;
    device.enqueueRx(buildIpv4FrameFrom(&frame_buf2, .{ 192, 168, 1, 50 }, diff_net, .icmp, &icmp_buf));
    _ = stack.poll(Instant.ZERO, &device);

    // 192.168.1.50 is on the 192.168.1.0/24 subnet we just added, so it
    // SHOULD be cached (it's in the same network as an interface address).
    try testing.expect(stack.iface.neighbor_cache.lookup(.{ 192, 168, 1, 50 }, stack.iface.now) != null);
}

test "stack egress routes via gateway for off-subnet destination" {
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
    const TcpStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    const S = struct {
        var rx_buf: [64]u8 = undefined;
        var tx_buf: [64]u8 = undefined;
    };
    @memset(&S.rx_buf, 0);
    @memset(&S.tx_buf, 0);
    var sock = TcpSock.init(&S.rx_buf, &S.tx_buf);

    var sock_arr = [_]*TcpSock{&sock};
    var stack = TcpStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Add a default gateway.
    const gateway: ipv4.Address = .{ 10, 0, 0, 254 };
    const gw_mac: ethernet.Address = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    _ = stack.iface.v4.routes.add(iface_mod.Route.newDefaultGateway(gateway));
    stack.iface.neighbor_cache.fill(gateway, gw_mac, Instant.ZERO);

    // Connect to off-subnet destination.
    const remote: ipv4.Address = .{ 8, 8, 8, 8 };
    try sock.connect(remote, 80, LOCAL_IP, 12345);

    // Poll to dispatch SYN.
    const activity = stack.poll(Instant.ZERO, &device);
    try testing.expect(activity);

    // The SYN frame should be sent to the gateway's MAC, not the remote's.
    const tx_frame = device.dequeueTx() orelse return error.ExpectedTxFrame;
    const eth = try ethernet.parse(tx_frame);
    try testing.expectEqual(gw_mac, eth.dst_addr);

    // IP destination should still be the remote address.
    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(remote, ip_repr.dst_addr);
}

test "stack raw socket receives IP payload" {
    const RawSock = raw_socket_mod.Socket(ipv4, .{ .payload_size = 128 });
    const Sockets = struct { raw4_sockets: []*RawSock };
    const RawStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [2]RawSock.Packet = undefined;
    var tx_buf: [2]RawSock.Packet = undefined;
    var sock = RawSock.init(&rx_buf, &tx_buf);
    try sock.bind(.udp);

    var sock_arr = [_]*RawSock{&sock};
    var stack = RawStack.init(LOCAL_HW, .{ .raw4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Build a raw UDP-protocol IP frame.
    const udp_payload = [_]u8{ 0x00, 0x43, 0x00, 0x44, 0x00, 0x0D, 0x00, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&frame_buf, .udp, &udp_payload));
    _ = stack.poll(Instant.ZERO, &device);

    try testing.expect(sock.canRecv());
    var recv_buf: [128]u8 = undefined;
    const result = try sock.recvSlice(&recv_buf);
    try testing.expectEqualSlices(u8, &udp_payload, recv_buf[0..result.data_len]);
}

test "stack raw socket suppresses ICMP proto unreachable" {
    const RawSock = raw_socket_mod.Socket(ipv4, .{ .payload_size = 128 });
    const Sockets = struct { raw4_sockets: []*RawSock };
    const RawStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [2]RawSock.Packet = undefined;
    var tx_buf: [2]RawSock.Packet = undefined;
    var sock = RawSock.init(&rx_buf, &tx_buf);
    // Bind to protocol 253 (experimental).
    try sock.bind(@enumFromInt(253));

    var sock_arr = [_]*RawSock{&sock};
    var stack = RawStack.init(LOCAL_HW, .{ .raw4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    // Populate neighbor cache for reply path.
    var arp_buf: [128]u8 = undefined;
    device.enqueueRx(buildArpRequest(&arp_buf));
    _ = stack.poll(Instant.ZERO, &device);
    _ = device.dequeueTx();

    // Send a packet with protocol 253.
    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4Frame(&frame_buf, @enumFromInt(253), &payload));
    _ = stack.poll(Instant.ZERO, &device);

    // Raw socket should have received it.
    try testing.expect(sock.canRecv());

    // No ICMP protocol unreachable should be emitted.
    try testing.expectEqual(@as(?[]const u8, null), device.dequeueTx());
}

test "stack IGMP query triggers report for joined group" {
    var device = TestDevice.init();
    var stack = testStack();
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    const group = ipv4.Address{ 239, 1, 2, 3 };
    try testing.expect(stack.iface.joinMulticastGroup(group));

    // Build IGMP general query (type=0x11, max_resp=100, group=0.0.0.0).
    var igmp_buf: [igmp_wire.HEADER_LEN]u8 = undefined;
    _ = igmp_wire.emit(.{ .membership_query = .{
        .max_resp_time = 100,
        .group_addr = ipv4.UNSPECIFIED,
        .version = .v2,
    } }, &igmp_buf) catch unreachable;

    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4FrameFrom(&frame_buf, REMOTE_IP, igmp_wire.IPV4_MULTICAST_ALL_SYSTEMS, .igmp, &igmp_buf));
    // Join the all-systems group so the packet is accepted.
    try testing.expect(stack.iface.joinMulticastGroup(igmp_wire.IPV4_MULTICAST_ALL_SYSTEMS));
    _ = stack.poll(Instant.ZERO, &device);

    // Should have emitted a report for the joined group(s).
    const tx_frame = device.dequeueTx();
    try testing.expect(tx_frame != null);
}

test "stack multicast destination accepted for joined group" {
    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
    const McastStack = Stack(TestDevice, Sockets);

    var device = TestDevice.init();

    var rx_buf: [1]UdpSock.Packet = undefined;
    var tx_buf: [1]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 5000 });

    var sock_arr = [_]*UdpSock{&sock};
    var stack = McastStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });

    const mcast_group = ipv4.Address{ 239, 1, 2, 3 };
    try testing.expect(stack.iface.joinMulticastGroup(mcast_group));

    // Build UDP frame destined for multicast group address.
    const udp_payload = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    var raw_udp: [udp_wire.HEADER_LEN + 5]u8 = undefined;
    _ = udp_wire.emit(.{
        .src_port = 9999,
        .dst_port = 5000,
        .length = @intCast(udp_wire.HEADER_LEN + udp_payload.len),
        .checksum = 0,
    }, &raw_udp) catch unreachable;
    @memcpy(raw_udp[udp_wire.HEADER_LEN..], &udp_payload);

    var frame_buf: [256]u8 = undefined;
    device.enqueueRx(buildIpv4FrameFrom(&frame_buf, REMOTE_IP, mcast_group, .udp, &raw_udp));
    _ = stack.poll(Instant.ZERO, &device);

    try testing.expect(sock.canRecv());
}

// -- Device Capabilities Tests --

fn TestDeviceWithCaps(comptime caps: iface_mod.DeviceCapabilities) type {
    return struct {
        const Self = @This();
        inner: TestDevice = TestDevice.init(),

        pub fn capabilities() iface_mod.DeviceCapabilities {
            return caps;
        }

        pub fn receive(self: *Self) ?[]const u8 {
            return self.inner.receive();
        }

        pub fn transmit(self: *Self, frame: []const u8) void {
            self.inner.transmit(frame);
        }
    };
}

test "TCP checksum offload skips computation" {
    const OffloadDevice = TestDeviceWithCaps(.{ .checksum = .{ .tcp = .rx_only } });
    const TcpSock = tcp_socket.Socket(ipv4, 4);
    const Sockets = struct { tcp4_sockets: []*TcpSock };
    const OffloadStack = Stack(OffloadDevice, Sockets);

    var device = OffloadDevice{};

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
    var stack = OffloadStack.init(LOCAL_HW, .{ .tcp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    stack.iface.neighbor_cache.fill(REMOTE_IP, REMOTE_HW, Instant.ZERO);

    _ = stack.poll(Instant.ZERO, &device);

    const tx_frame = device.inner.dequeueTx() orelse return error.ExpectedTxFrame;
    const ip_data = try ethernet.payload(tx_frame);
    const ip_repr = try ipv4.parse(ip_data);
    try testing.expectEqual(ipv4.Protocol.tcp, ip_repr.protocol);

    // Checksum field should be left zeroed (hardware computes TX checksum).
    const tcp_data = try ipv4.payloadSlice(ip_data);
    const tcp_cksum = @as(u16, tcp_data[16]) << 8 | @as(u16, tcp_data[17]);
    try testing.expectEqual(@as(u16, 0), tcp_cksum);
}

test "burst size limits frames per poll cycle" {
    const BurstDevice = TestDeviceWithCaps(.{ .max_burst_size = 1 });

    const UdpSock = udp_socket_mod.Socket(ipv4, .{ .payload_size = 64 });
    const Sockets = struct { udp4_sockets: []*UdpSock };
    const BurstStack = Stack(BurstDevice, Sockets);

    var device = BurstDevice{};

    var rx_buf: [4]UdpSock.Packet = undefined;
    var tx_buf: [4]UdpSock.Packet = undefined;
    var sock = UdpSock.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 3000 });

    // Enqueue 3 outgoing UDP packets.
    const meta = UdpSock.Metadata{ .endpoint = .{ .addr = REMOTE_IP, .port = 4000 } };
    try sock.sendSlice("aaa", meta);
    try sock.sendSlice("bbb", meta);
    try sock.sendSlice("ccc", meta);

    var sock_arr = [_]*UdpSock{&sock};
    var stack = BurstStack.init(LOCAL_HW, .{ .udp4_sockets = &sock_arr });
    stack.iface.v4.addIpAddr(.{ .address = LOCAL_IP, .prefix_len = 24 });
    stack.iface.neighbor_cache.fill(REMOTE_IP, REMOTE_HW, Instant.ZERO);

    // First poll: burst=1 means only 1 frame emitted.
    _ = stack.poll(Instant.ZERO, &device);
    try testing.expectEqual(@as(usize, 1), device.inner.tx_count);

    // Second poll: another 1 frame.
    _ = stack.poll(Instant.ZERO, &device);
    try testing.expectEqual(@as(usize, 2), device.inner.tx_count);

    // Third poll: last frame.
    _ = stack.poll(Instant.ZERO, &device);
    try testing.expectEqual(@as(usize, 3), device.inner.tx_count);

    // Fourth poll: no more frames.
    _ = stack.poll(Instant.ZERO, &device);
    try testing.expectEqual(@as(usize, 3), device.inner.tx_count);
}

test "DeviceCapabilities defaults enable all checksums" {
    const caps = iface_mod.DeviceCapabilities{};
    try testing.expect(caps.checksum.ipv4.shouldComputeTx());
    try testing.expect(caps.checksum.ipv4.shouldVerifyRx());
    try testing.expect(caps.checksum.tcp.shouldComputeTx());
    try testing.expect(caps.checksum.tcp.shouldVerifyRx());
    try testing.expect(caps.checksum.udp.shouldComputeTx());
    try testing.expect(caps.checksum.udp.shouldVerifyRx());
    try testing.expect(caps.checksum.icmp.shouldComputeTx());
    try testing.expect(caps.checksum.icmp.shouldVerifyRx());
    try testing.expectEqual(@as(?u16, null), caps.max_burst_size);
}

test "ChecksumMode shouldVerifyRx and shouldComputeTx" {
    const both = iface_mod.ChecksumMode.both;
    try testing.expect(both.shouldVerifyRx());
    try testing.expect(both.shouldComputeTx());

    const tx_only = iface_mod.ChecksumMode.tx_only;
    try testing.expect(!tx_only.shouldVerifyRx());
    try testing.expect(tx_only.shouldComputeTx());

    const rx_only = iface_mod.ChecksumMode.rx_only;
    try testing.expect(rx_only.shouldVerifyRx());
    try testing.expect(!rx_only.shouldComputeTx());

    const none_mode = iface_mod.ChecksumMode.none;
    try testing.expect(!none_mode.shouldVerifyRx());
    try testing.expect(!none_mode.shouldComputeTx());
}

