// Network interface: Ethernet frame processing, ARP neighbor cache,
// ICMP auto-reply, and address management.
//
// Sits between the wire layer and socket layer. Parses incoming Ethernet
// frames, routes them to protocol handlers, manages ARP, generates ICMP
// error and echo replies.
//
// Reference: smoltcp src/iface/interface.rs, tests/ipv4.rs

const std = @import("std");
const ethernet = @import("wire/ethernet.zig");
const arp = @import("wire/arp.zig");
const ip_generic = @import("wire/ip.zig");
const ipv4 = @import("wire/ipv4.zig");
const icmp = @import("wire/icmp.zig");
const udp = @import("wire/udp.zig");
const tcp_wire = @import("wire/tcp.zig");
const tcp_socket = @import("socket/tcp.zig");
const time = @import("time.zig");

// -------------------------------------------------------------------------
// Device Capabilities
// -------------------------------------------------------------------------

pub const ChecksumMode = enum {
    both,
    tx_only,
    rx_only,
    none,

    pub fn shouldVerifyRx(self: ChecksumMode) bool {
        return self == .both or self == .rx_only;
    }

    pub fn shouldComputeTx(self: ChecksumMode) bool {
        return self == .both or self == .tx_only;
    }
};

pub const DeviceCapabilities = struct {
    max_transmission_unit: u16 = 1514,
    max_burst_size: ?u16 = null,
    checksum: struct {
        ipv4: ChecksumMode = .both,
        tcp: ChecksumMode = .both,
        udp: ChecksumMode = .both,
        icmp: ChecksumMode = .both,
    } = .{},
};

/// Opaque per-packet metadata for hardware timestamping, flow IDs,
/// or other device-specific information. Attached to socket dispatch
/// results and packet buffers. The stack does not interpret this value.
pub const PacketMeta = struct {
    token: usize = 0,
};

pub const MAX_ADDR_COUNT = 4;
pub const MAX_MULTICAST_GROUPS = 4;
pub const DEFAULT_HOP_LIMIT: u8 = 64;
pub const IPV4_MIN_MTU: usize = 576;

const NEIGHBOR_CACHE_SIZE = 8;
const NEIGHBOR_LIFETIME = time.Duration.fromSecs(60);

// Max ICMP error payload: IPV4_MIN_MTU minus outer IP + ICMP + invoking IP headers
const ICMP_ERROR_MAX_DATA = IPV4_MIN_MTU - ipv4.HEADER_LEN - icmp.HEADER_LEN - ipv4.HEADER_LEN;

pub const IpCidr = ip_generic.Cidr(ipv4);

// -------------------------------------------------------------------------
// Routing table
// -------------------------------------------------------------------------

pub const MAX_ROUTE_COUNT = 4;

pub fn RouteFor(comptime Ip: type) type {
    return struct {
        cidr: ip_generic.Cidr(Ip),
        via_router: Ip.Address,
        expires_at: ?time.Instant = null,

        pub fn newDefaultGateway(gateway: Ip.Address) @This() {
            return .{
                .cidr = .{ .address = Ip.UNSPECIFIED, .prefix_len = 0 },
                .via_router = gateway,
            };
        }
    };
}

pub const Route = RouteFor(ipv4);

pub fn RoutesFor(comptime Ip: type) type {
    return struct {
        const R = RouteFor(Ip);
        entries: [MAX_ROUTE_COUNT]?R = .{null} ** MAX_ROUTE_COUNT,

        pub fn add(self: *@This(), route: R) bool {
            for (&self.entries) |*slot| {
                if (slot.* == null) {
                    slot.* = route;
                    return true;
                }
            }
            return false;
        }

        pub fn lookup(self: *const @This(), addr: Ip.Address, now: time.Instant) ?Ip.Address {
            var best_prefix: ?u8 = null;
            var best_router: ?Ip.Address = null;
            for (self.entries) |maybe_route| {
                const route = maybe_route orelse continue;
                if (route.expires_at) |exp| {
                    if (exp.lessThan(now)) continue;
                }
                if (!route.cidr.contains(addr)) continue;
                if (best_prefix == null or route.cidr.prefix_len > best_prefix.?) {
                    best_prefix = route.cidr.prefix_len;
                    best_router = route.via_router;
                }
            }
            return best_router;
        }
    };
}

pub const Routes = RoutesFor(ipv4);

pub const NeighborCache = struct {
    pub const SILENT_TIME = time.Duration.fromMillis(1000);

    pub const LookupResult = union(enum) {
        found: ethernet.Address,
        not_found,
        rate_limited,
    };

    const Entry = struct {
        protocol_addr: ipv4.Address = ipv4.UNSPECIFIED,
        hardware_addr: ethernet.Address = .{ 0, 0, 0, 0, 0, 0 },
        expires_at: time.Instant = time.Instant.ZERO,
    };

    entries: [NEIGHBOR_CACHE_SIZE]Entry = [_]Entry{.{}} ** NEIGHBOR_CACHE_SIZE,
    silent_until: time.Instant = time.Instant.ZERO,

    fn isOccupied(entry: Entry) bool {
        return !ipv4.isUnspecified(entry.protocol_addr);
    }

    pub fn fill(self: *NeighborCache, ip: ipv4.Address, mac: ethernet.Address, now: time.Instant) void {
        const expires = now.add(NEIGHBOR_LIFETIME);
        const new_entry = Entry{ .protocol_addr = ip, .hardware_addr = mac, .expires_at = expires };

        for (&self.entries) |*entry| {
            if (isOccupied(entry.*) and std.mem.eql(u8, &entry.protocol_addr, &ip)) {
                entry.hardware_addr = mac;
                entry.expires_at = expires;
                return;
            }
        }

        for (&self.entries) |*entry| {
            if (!isOccupied(entry.*)) {
                entry.* = new_entry;
                return;
            }
        }

        // Evict oldest
        var oldest: *Entry = &self.entries[0];
        for (self.entries[1..]) |*entry| {
            if (entry.expires_at.lessThan(oldest.expires_at)) oldest = entry;
        }
        oldest.* = new_entry;
    }

    pub fn lookup(self: *const NeighborCache, ip: ipv4.Address, now: time.Instant) ?ethernet.Address {
        return switch (self.lookupFull(ip, now)) {
            .found => |mac| mac,
            .not_found, .rate_limited => null,
        };
    }

    pub fn lookupFull(self: *const NeighborCache, ip: ipv4.Address, now: time.Instant) LookupResult {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, &entry.protocol_addr, &ip)) {
                if (entry.expires_at.greaterThanOrEqual(now)) return .{ .found = entry.hardware_addr };
                break;
            }
        }
        if (now.lessThan(self.silent_until)) return .rate_limited;
        return .not_found;
    }

    pub fn limitRate(self: *NeighborCache, now: time.Instant) void {
        self.silent_until = now.add(SILENT_TIME);
    }

    pub fn hasNeighbor(self: *const NeighborCache, ip: ipv4.Address) bool {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, &entry.protocol_addr, &ip)) return true;
        }
        return false;
    }

    pub fn flush(self: *NeighborCache) void {
        self.entries = [_]Entry{.{}} ** NEIGHBOR_CACHE_SIZE;
        self.silent_until = time.Instant.ZERO;
    }
};

pub const IpMeta = struct {
    src_addr: ipv4.Address,
    dst_addr: ipv4.Address,
    protocol: ipv4.Protocol,
    hop_limit: u8,
};

pub const IpPayload = union(enum) {
    icmp_echo: struct {
        echo: icmp.EchoRepr,
        data: []const u8,
    },
    icmp_dest_unreachable: struct {
        code: u8,
        invoking_repr: ipv4.Repr,
        data: []const u8,
    },
    tcp: tcp_socket.TcpRepr,
};

pub const Ipv4Response = struct {
    ip: IpMeta,
    payload: IpPayload,
};

pub const Response = union(enum) {
    arp_reply: arp.Repr,
    ipv4: Ipv4Response,
};

pub const Interface = struct {
    hardware_addr: ethernet.Address,
    ip_addrs: [MAX_ADDR_COUNT]IpCidr = undefined,
    ip_addr_count: usize = 0,
    neighbor_cache: NeighborCache = .{},
    routes: Routes = .{},
    now: time.Instant = time.Instant.ZERO,
    any_ip: bool = false,
    multicast_groups: [MAX_MULTICAST_GROUPS]?ipv4.Address = .{null} ** MAX_MULTICAST_GROUPS,

    pub fn init(hw_addr: ethernet.Address) Interface {
        return .{ .hardware_addr = hw_addr };
    }

    pub fn addIpAddr(self: *Interface, cidr: IpCidr) void {
        if (self.ip_addr_count < MAX_ADDR_COUNT) {
            self.ip_addrs[self.ip_addr_count] = cidr;
            self.ip_addr_count += 1;
        }
    }

    pub fn setIpAddrs(self: *Interface, cidrs: []const IpCidr) void {
        const count = @min(cidrs.len, MAX_ADDR_COUNT);
        for (cidrs[0..count], 0..) |c, i| {
            self.ip_addrs[i] = c;
        }
        self.ip_addr_count = count;
        self.neighbor_cache.flush();
    }

    pub fn ipAddrs(self: *const Interface) []const IpCidr {
        return self.ip_addrs[0..self.ip_addr_count];
    }

    pub fn hasIpAddr(self: *const Interface, addr: ipv4.Address) bool {
        for (self.ipAddrs()) |cidr| {
            if (std.mem.eql(u8, &cidr.address, &addr)) return true;
        }
        return false;
    }

    pub fn isBroadcast(self: *const Interface, addr: ipv4.Address) bool {
        if (ipv4.isBroadcast(addr)) return true;
        for (self.ipAddrs()) |cidr| {
            if (cidr.broadcast()) |bcast| {
                if (std.mem.eql(u8, &addr, &bcast)) return true;
            }
        }
        return false;
    }

    pub fn ipv4Addr(self: *const Interface) ?ipv4.Address {
        if (self.ip_addr_count == 0) return null;
        return self.ip_addrs[0].address;
    }

    pub fn getSourceAddress(self: *const Interface, dst: ipv4.Address) ?ipv4.Address {
        if (self.ip_addr_count == 0) return null;
        for (self.ipAddrs()) |cidr| {
            if (cidr.contains(dst)) return cidr.address;
        }
        return self.ip_addrs[0].address;
    }

    pub fn inSameNetwork(self: *const Interface, addr: ipv4.Address) bool {
        for (self.ipAddrs()) |cidr| {
            if (cidr.contains(addr)) return true;
        }
        return false;
    }

    pub fn route(self: *const Interface, dst: ipv4.Address) ?ipv4.Address {
        if (self.inSameNetwork(dst) or self.isBroadcast(dst)) return dst;
        return self.routes.lookup(dst, self.now);
    }

    pub fn hasNeighbor(self: *const Interface, dst: ipv4.Address) bool {
        const next_hop = self.route(dst) orelse return false;
        return self.neighbor_cache.lookup(next_hop, self.now) != null;
    }

    // -- Multicast group management --

    pub fn joinMulticastGroup(self: *Interface, addr: ipv4.Address) bool {
        for (&self.multicast_groups) |*slot| {
            if (slot.*) |existing| {
                if (std.mem.eql(u8, &existing, &addr)) return true;
            }
        }
        for (&self.multicast_groups) |*slot| {
            if (slot.* == null) {
                slot.* = addr;
                return true;
            }
        }
        return false;
    }

    pub fn leaveMulticastGroup(self: *Interface, addr: ipv4.Address) bool {
        for (&self.multicast_groups) |*slot| {
            if (slot.*) |existing| {
                if (std.mem.eql(u8, &existing, &addr)) {
                    slot.* = null;
                    return true;
                }
            }
        }
        return false;
    }

    pub fn hasMulticastGroup(self: *const Interface, addr: ipv4.Address) bool {
        for (self.multicast_groups) |slot| {
            if (slot) |existing| {
                if (std.mem.eql(u8, &existing, &addr)) return true;
            }
        }
        return false;
    }

    pub fn processEthernet(self: *Interface, frame: []const u8) ?Response {
        const eth_repr = ethernet.parse(frame) catch return null;
        const payload_data = ethernet.payload(frame) catch return null;
        return switch (eth_repr.ethertype) {
            .arp => self.processArp(payload_data),
            .ipv4 => self.processIpv4(payload_data),
            else => null,
        };
    }

    pub fn processArp(self: *Interface, data: []const u8) ?Response {
        const repr = arp.parse(data) catch return null;
        if (!self.any_ip and !self.hasIpAddr(repr.target_protocol_addr)) return null;

        self.neighbor_cache.fill(repr.source_protocol_addr, repr.source_hardware_addr, self.now);

        if (repr.operation == .request) {
            return .{ .arp_reply = .{
                .operation = .reply,
                .source_hardware_addr = self.hardware_addr,
                .source_protocol_addr = repr.target_protocol_addr,
                .target_hardware_addr = repr.source_hardware_addr,
                .target_protocol_addr = repr.source_protocol_addr,
            } };
        }
        return null;
    }

    pub fn processIpv4(self: *Interface, data: []const u8) ?Response {
        const ip_repr = ipv4.parse(data) catch return null;
        const is_broadcast = self.isBroadcast(ip_repr.dst_addr);

        if (!is_broadcast and !self.hasIpAddr(ip_repr.dst_addr)) return null;

        const ip_payload = ipv4.payloadSlice(data) catch return null;

        switch (ip_repr.protocol) {
            .icmp => return self.processIcmp(ip_repr, ip_payload, is_broadcast),
            .igmp => return null, // caller handles via stack
            .udp => return null, // caller handles via processUdp
            .tcp => return null, // caller handles
            _ => {
                if (is_broadcast) return null; // RFC 1122: no ICMP for broadcast
                return self.icmpProtoUnreachable(ip_repr, ip_payload);
            },
        }
    }

    pub fn processIcmp(self: *const Interface, ip_repr: ipv4.Repr, payload_data: []const u8, is_broadcast: bool) ?Response {
        const icmp_repr = icmp.parse(payload_data) catch return null;
        switch (icmp_repr) {
            .echo => |echo| {
                if (echo.icmp_type != .echo_request) return null;
                const echo_data = if (payload_data.len > icmp.HEADER_LEN)
                    payload_data[icmp.HEADER_LEN..]
                else
                    &[_]u8{};
                const src = if (is_broadcast)
                    (self.ipv4Addr() orelse return null)
                else
                    ip_repr.dst_addr;
                return .{ .ipv4 = .{
                    .ip = .{
                        .src_addr = src,
                        .dst_addr = ip_repr.src_addr,
                        .protocol = .icmp,
                        .hop_limit = DEFAULT_HOP_LIMIT,
                    },
                    .payload = .{ .icmp_echo = .{
                        .echo = .{
                            .icmp_type = .echo_reply,
                            .code = 0,
                            .checksum = 0,
                            .identifier = echo.identifier,
                            .sequence = echo.sequence,
                        },
                        .data = echo_data,
                    } },
                } };
            },
            .other => return null,
        }
    }

    pub fn icmpProtoUnreachable(self: *const Interface, ip_repr: ipv4.Repr, ip_payload: []const u8) ?Response {
        const src = self.getSourceAddress(ip_repr.src_addr) orelse return null;
        return .{ .ipv4 = .{
            .ip = .{
                .src_addr = src,
                .dst_addr = ip_repr.src_addr,
                .protocol = .icmp,
                .hop_limit = DEFAULT_HOP_LIMIT,
            },
            .payload = .{ .icmp_dest_unreachable = .{
                .code = 2, // protocol unreachable
                .invoking_repr = ip_repr,
                .data = ip_payload,
            } },
        } };
    }

    pub fn processUdp(self: *const Interface, ip_repr: ipv4.Repr, udp_data: []const u8, socket_handled: bool) ?Response {
        if (socket_handled) return null;
        if (self.isBroadcast(ip_repr.dst_addr)) return null;
        const src = self.getSourceAddress(ip_repr.src_addr) orelse return null;
        const data = udp_data[0..@min(udp_data.len, ICMP_ERROR_MAX_DATA)];
        return .{ .ipv4 = .{
            .ip = .{
                .src_addr = src,
                .dst_addr = ip_repr.src_addr,
                .protocol = .icmp,
                .hop_limit = DEFAULT_HOP_LIMIT,
            },
            .payload = .{ .icmp_dest_unreachable = .{
                .code = 3, // port unreachable
                .invoking_repr = ip_repr,
                .data = data,
            } },
        } };
    }

    pub fn processTcp(self: *const Interface, ip_repr: ipv4.Repr, tcp_data: []const u8, socket_handled: bool) ?Response {
        _ = self;
        if (socket_handled) return null;

        const sock_repr = tcp_socket.TcpRepr.fromWireBytes(tcp_data) orelse return null;
        if (sock_repr.control == .rst) return null;
        if (ipv4.isUnspecified(ip_repr.src_addr)) return null;
        if (ipv4.isUnspecified(ip_repr.dst_addr)) return null;

        const rst = tcp_socket.rstReply(sock_repr);

        return .{ .ipv4 = .{
            .ip = .{
                .src_addr = ip_repr.dst_addr,
                .dst_addr = ip_repr.src_addr,
                .protocol = .tcp,
                .hop_limit = DEFAULT_HOP_LIMIT,
            },
            .payload = .{ .tcp = rst },
        } };
    }
};

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;

const LOCAL_HW_ADDR: ethernet.Address = .{ 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
const REMOTE_HW_ADDR: ethernet.Address = .{ 0x52, 0x54, 0x00, 0x00, 0x00, 0x00 };
const LOCAL_IP: ipv4.Address = .{ 127, 0, 0, 1 };
const REMOTE_IP: ipv4.Address = .{ 127, 0, 0, 2 };
const LOCAL_CIDR = IpCidr{ .address = LOCAL_IP, .prefix_len = 8 };

fn testInterface() Interface {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.addIpAddr(.{ .address = .{ 192, 168, 1, 1 }, .prefix_len = 24 });
    iface.addIpAddr(LOCAL_CIDR);
    return iface;
}

fn testIpv4Repr(protocol: ipv4.Protocol, src: ipv4.Address, dst: ipv4.Address, payload_len: usize) ipv4.Repr {
    return .{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + payload_len),
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
}

fn buildArpFrame(buf: []u8, arp_repr: arp.Repr) []const u8 {
    const eth_repr = ethernet.Repr{
        .dst_addr = ethernet.BROADCAST,
        .src_addr = REMOTE_HW_ADDR,
        .ethertype = .arp,
    };
    const eth_len = ethernet.emit(eth_repr, buf) catch unreachable;
    const arp_len = arp.emit(arp_repr, buf[eth_len..]) catch unreachable;
    return buf[0 .. eth_len + arp_len];
}

fn buildIpv4Frame(buf: []u8, ip_repr: ipv4.Repr, payload_data: []const u8) []const u8 {
    const eth_repr = ethernet.Repr{
        .dst_addr = LOCAL_HW_ADDR,
        .src_addr = REMOTE_HW_ADDR,
        .ethertype = .ipv4,
    };
    const eth_len = ethernet.emit(eth_repr, buf) catch unreachable;
    const ip_len = ipv4.emit(ip_repr, buf[eth_len..]) catch unreachable;
    @memcpy(buf[eth_len + ip_len ..][0..payload_data.len], payload_data);
    return buf[0 .. eth_len + ip_len + payload_data.len];
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_local_subnet_broadcasts]
test "local subnet broadcasts" {
    var iface = Interface.init(LOCAL_HW_ADDR);

    // /24
    iface.ip_addr_count = 0;
    iface.addIpAddr(.{ .address = .{ 192, 168, 1, 23 }, .prefix_len = 24 });
    try testing.expect(iface.isBroadcast(.{ 255, 255, 255, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 255, 255, 255, 254 }));
    try testing.expect(iface.isBroadcast(.{ 192, 168, 1, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 168, 1, 254 }));

    // /16
    iface.ip_addr_count = 0;
    iface.addIpAddr(.{ .address = .{ 192, 168, 23, 24 }, .prefix_len = 16 });
    try testing.expect(iface.isBroadcast(.{ 255, 255, 255, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 255, 255, 255, 254 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 168, 23, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 168, 23, 254 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 168, 255, 254 }));
    try testing.expect(iface.isBroadcast(.{ 192, 168, 255, 255 }));

    // /8
    iface.ip_addr_count = 0;
    iface.addIpAddr(.{ .address = .{ 192, 168, 23, 24 }, .prefix_len = 8 });
    try testing.expect(iface.isBroadcast(.{ 255, 255, 255, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 255, 255, 255, 254 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 23, 1, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 23, 1, 254 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 255, 255, 254 }));
    try testing.expect(iface.isBroadcast(.{ 192, 255, 255, 255 }));
}

// [smoltcp:iface/interface/tests/ipv4.rs:get_source_address]
test "get source address" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.setIpAddrs(&.{
        .{ .address = .{ 172, 18, 1, 2 }, .prefix_len = 24 },
        .{ .address = .{ 172, 24, 24, 14 }, .prefix_len = 24 },
    });

    try testing.expectEqual(
        @as(?ipv4.Address, .{ 172, 18, 1, 2 }),
        iface.getSourceAddress(.{ 172, 18, 1, 254 }),
    );
    try testing.expectEqual(
        @as(?ipv4.Address, .{ 172, 24, 24, 14 }),
        iface.getSourceAddress(.{ 172, 24, 24, 12 }),
    );
    // Not in any subnet -> fall back to first
    try testing.expectEqual(
        @as(?ipv4.Address, .{ 172, 18, 1, 2 }),
        iface.getSourceAddress(.{ 172, 24, 23, 254 }),
    );
}

// [smoltcp:iface/interface/tests/ipv4.rs:get_source_address_empty_interface]
test "get source address empty interface" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.ip_addr_count = 0;

    try testing.expectEqual(@as(?ipv4.Address, null), iface.getSourceAddress(.{ 172, 18, 1, 254 }));
    try testing.expectEqual(@as(?ipv4.Address, null), iface.getSourceAddress(.{ 172, 24, 24, 12 }));
    try testing.expectEqual(@as(?ipv4.Address, null), iface.getSourceAddress(.{ 172, 24, 23, 254 }));
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_handle_valid_arp_request]
test "handle valid ARP request" {
    var iface = testInterface();

    var buf: [128]u8 = undefined;
    const frame = buildArpFrame(&buf, .{
        .operation = .request,
        .source_hardware_addr = REMOTE_HW_ADDR,
        .source_protocol_addr = REMOTE_IP,
        .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 },
        .target_protocol_addr = LOCAL_IP,
    });

    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;

    switch (result) {
        .arp_reply => |reply| {
            try testing.expectEqual(arp.Operation.reply, reply.operation);
            try testing.expectEqual(LOCAL_HW_ADDR, reply.source_hardware_addr);
            try testing.expectEqual(LOCAL_IP, reply.source_protocol_addr);
            try testing.expectEqual(REMOTE_HW_ADDR, reply.target_hardware_addr);
            try testing.expectEqual(REMOTE_IP, reply.target_protocol_addr);
        },
        else => return error.UnexpectedResponseType,
    }

    try testing.expect(iface.neighbor_cache.hasNeighbor(REMOTE_IP));
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_handle_other_arp_request]
test "handle other ARP request" {
    var iface = testInterface();

    var buf: [128]u8 = undefined;
    const frame = buildArpFrame(&buf, .{
        .operation = .request,
        .source_hardware_addr = REMOTE_HW_ADDR,
        .source_protocol_addr = REMOTE_IP,
        .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 },
        .target_protocol_addr = .{ 127, 0, 0, 3 },
    });

    const result = iface.processEthernet(frame);
    try testing.expectEqual(@as(?Response, null), result);
    try testing.expect(!iface.neighbor_cache.hasNeighbor(REMOTE_IP));
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_arp_flush_after_update_ip]
test "ARP flush after update IP" {
    var iface = testInterface();

    var buf: [128]u8 = undefined;
    const frame = buildArpFrame(&buf, .{
        .operation = .request,
        .source_hardware_addr = REMOTE_HW_ADDR,
        .source_protocol_addr = REMOTE_IP,
        .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 },
        .target_protocol_addr = LOCAL_IP,
    });

    const result = iface.processEthernet(frame);
    try testing.expect(result != null);
    try testing.expect(iface.neighbor_cache.hasNeighbor(REMOTE_IP));

    iface.setIpAddrs(&.{
        .{ .address = .{ 127, 0, 0, 1 }, .prefix_len = 24 },
    });
    try testing.expect(!iface.neighbor_cache.hasNeighbor(REMOTE_IP));
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_handle_ipv4_broadcast]
test "handle IPv4 broadcast" {
    var iface = testInterface();

    const icmp_data = [_]u8{ 0xAA, 0x00, 0x00, 0xFF };
    const icmp_echo = icmp.EchoRepr{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 0xABCD,
    };
    var icmp_buf: [icmp.HEADER_LEN + 4]u8 = undefined;
    _ = icmp.emitEcho(icmp_echo, &icmp_data, &icmp_buf) catch unreachable;

    const ip_repr = testIpv4Repr(.icmp, REMOTE_IP, .{ 255, 255, 255, 255 }, icmp_buf.len);

    var frame_buf: [256]u8 = undefined;
    const frame = buildIpv4Frame(&frame_buf, ip_repr, &icmp_buf);

    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;

    switch (result) {
        .ipv4 => |resp| {
            try testing.expectEqual(ipv4.Address{ 192, 168, 1, 1 }, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_IP, resp.ip.dst_addr);
            try testing.expectEqual(ipv4.Protocol.icmp, resp.ip.protocol);
            switch (resp.payload) {
                .icmp_echo => |echo_resp| {
                    try testing.expectEqual(icmp.Type.echo_reply, echo_resp.echo.icmp_type);
                    try testing.expectEqual(@as(u16, 0x1234), echo_resp.echo.identifier);
                    try testing.expectEqual(@as(u16, 0xABCD), echo_resp.echo.sequence);
                    try testing.expectEqualSlices(u8, &icmp_data, echo_resp.data);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_no_icmp_no_unicast]
test "no ICMP for unknown protocol to broadcast" {
    var iface = testInterface();

    const ip_repr = testIpv4Repr(@enumFromInt(0x0C), LOCAL_IP, .{ 255, 255, 255, 255 }, 0);

    var frame_buf: [128]u8 = undefined;
    const frame = buildIpv4Frame(&frame_buf, ip_repr, &.{});

    const result = iface.processEthernet(frame);
    try testing.expectEqual(@as(?Response, null), result);
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_icmp_error_no_payload]
test "ICMP error no payload" {
    var iface = testInterface();

    const ip_repr = testIpv4Repr(@enumFromInt(0x0C), REMOTE_IP, LOCAL_IP, 0);

    var frame_buf: [128]u8 = undefined;
    const frame = buildIpv4Frame(&frame_buf, ip_repr, &.{});

    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;

    switch (result) {
        .ipv4 => |resp| {
            try testing.expectEqual(LOCAL_IP, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_IP, resp.ip.dst_addr);
            try testing.expectEqual(ipv4.Protocol.icmp, resp.ip.protocol);
            switch (resp.payload) {
                .icmp_dest_unreachable => |du| {
                    try testing.expectEqual(@as(u8, 2), du.code);
                    try testing.expectEqual(@as(usize, 0), du.data.len);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_icmp_error_port_unreachable]
test "ICMP error port unreachable" {
    var iface = testInterface();

    const udp_payload = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x57, 0x6f, 0x6c, 0x64, 0x21 };
    const udp_repr_wire = udp.Repr{
        .src_port = 67,
        .dst_port = 68,
        .length = @intCast(udp.HEADER_LEN + udp_payload.len),
        .checksum = 0,
    };
    var udp_buf: [udp.HEADER_LEN + 12]u8 = undefined;
    _ = udp.emit(udp_repr_wire, &udp_buf) catch unreachable;
    @memcpy(udp_buf[udp.HEADER_LEN..], &udp_payload);

    const ip_repr = testIpv4Repr(.udp, REMOTE_IP, LOCAL_IP, udp_buf.len);

    const result = iface.processUdp(ip_repr, &udp_buf, false) orelse return error.ExpectedResponse;
    switch (result) {
        .ipv4 => |resp| {
            try testing.expectEqual(LOCAL_IP, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_IP, resp.ip.dst_addr);
            switch (resp.payload) {
                .icmp_dest_unreachable => |du| {
                    try testing.expectEqual(@as(u8, 3), du.code);
                    try testing.expectEqualSlices(u8, &udp_buf, du.data);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }

    // Broadcast -> no ICMP
    const bcast_ip_repr = testIpv4Repr(.udp, REMOTE_IP, .{ 255, 255, 255, 255 }, udp_buf.len);
    const bcast_result = iface.processUdp(bcast_ip_repr, &udp_buf, false);
    try testing.expectEqual(@as(?Response, null), bcast_result);
}

// [smoltcp:iface/interface/tests/mod.rs:test_handle_udp_broadcast]
test "handle UDP broadcast" {
    const UdpSocket = @import("socket/udp.zig").Socket(ipv4, .{ .payload_size = 64 });
    const UdpRepr = @import("socket/udp.zig").UdpRepr;

    var iface = testInterface();

    var rx_buf: [1]UdpSocket.Packet = undefined;
    var tx_buf: [1]UdpSocket.Packet = undefined;
    var sock = UdpSocket.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 68 });

    try testing.expect(!sock.canRecv());
    try testing.expect(sock.canSend());

    const udp_payload = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };

    const udp_repr_sock = UdpRepr{ .src_port = 67, .dst_port = 68 };
    const ip_src: ipv4.Address = .{ 127, 0, 0, 2 };
    const ip_dst: ipv4.Address = .{ 255, 255, 255, 255 };

    try testing.expect(sock.accepts(ip_src, ip_dst, udp_repr_sock));
    sock.process(ip_src, ip_dst, udp_repr_sock, &udp_payload);

    const ip_repr = testIpv4Repr(.udp, ip_src, ip_dst, udp.HEADER_LEN + udp_payload.len);

    var full_udp_buf: [udp.HEADER_LEN + 5]u8 = undefined;
    const udp_wire = udp.Repr{
        .src_port = 67,
        .dst_port = 68,
        .length = @intCast(udp.HEADER_LEN + udp_payload.len),
        .checksum = 0,
    };
    _ = udp.emit(udp_wire, &full_udp_buf) catch unreachable;
    @memcpy(full_udp_buf[udp.HEADER_LEN..], &udp_payload);

    const result = iface.processUdp(ip_repr, &full_udp_buf, true);
    try testing.expectEqual(@as(?Response, null), result);

    try testing.expect(sock.canRecv());
    var recv_buf: [64]u8 = undefined;
    const recv_result = try sock.recvSlice(&recv_buf);
    try testing.expectEqualSlices(u8, &udp_payload, recv_buf[0..recv_result.data_len]);
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_icmp_reply_size]
test "ICMP reply size" {
    var iface = testInterface();

    var large_udp_buf: [udp.HEADER_LEN + ICMP_ERROR_MAX_DATA]u8 = undefined;
    const udp_wire = udp.Repr{
        .src_port = 67,
        .dst_port = 68,
        .length = @intCast(large_udp_buf.len),
        .checksum = 0,
    };
    _ = udp.emit(udp_wire, &large_udp_buf) catch unreachable;
    @memset(large_udp_buf[udp.HEADER_LEN..], 0x2A);

    const ip_repr = testIpv4Repr(.udp, .{ 192, 168, 1, 1 }, .{ 192, 168, 1, 2 }, large_udp_buf.len);

    const result = iface.processUdp(ip_repr, &large_udp_buf, false) orelse return error.ExpectedResponse;

    switch (result) {
        .ipv4 => |resp| {
            switch (resp.payload) {
                .icmp_dest_unreachable => |du| {
                    try testing.expectEqual(@as(u8, 3), du.code);
                    try testing.expectEqual(ICMP_ERROR_MAX_DATA, du.data.len);
                    const total = ipv4.HEADER_LEN + icmp.HEADER_LEN + ipv4.HEADER_LEN + du.data.len;
                    try testing.expectEqual(IPV4_MIN_MTU, total);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_any_ip_accept_arp]
test "any_ip accepts ARP for unknown address" {
    var iface = testInterface();
    const UNKNOWN_IP: ipv4.Address = .{ 10, 0, 0, 99 };

    var buf: [128]u8 = undefined;
    const frame = buildArpFrame(&buf, .{
        .operation = .request,
        .source_hardware_addr = REMOTE_HW_ADDR,
        .source_protocol_addr = REMOTE_IP,
        .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 },
        .target_protocol_addr = UNKNOWN_IP,
    });

    // Without any_ip, ARP for unknown IP is ignored
    try testing.expectEqual(@as(?Response, null), iface.processEthernet(frame));

    // With any_ip, ARP for unknown IP gets a reply
    iface.any_ip = true;
    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;
    switch (result) {
        .arp_reply => |reply| {
            try testing.expectEqual(arp.Operation.reply, reply.operation);
            try testing.expectEqual(LOCAL_HW_ADDR, reply.source_hardware_addr);
            try testing.expectEqual(UNKNOWN_IP, reply.source_protocol_addr);
            try testing.expectEqual(REMOTE_HW_ADDR, reply.target_hardware_addr);
            try testing.expectEqual(REMOTE_IP, reply.target_protocol_addr);
        },
        else => return error.UnexpectedResponseType,
    }
}

// [smoltcp:iface/interface/tests/ipv4.rs:test_icmpv4_socket]
test "ICMP socket receives echo request and auto-reply" {
    const IcmpSocket = @import("socket/icmp.zig").Socket(ipv4, .{ .payload_size = 128 });

    var iface_inst = testInterface();

    var rx_buf: [1]IcmpSocket.Packet = undefined;
    var tx_buf: [1]IcmpSocket.Packet = undefined;
    var sock = IcmpSocket.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .ident = 0x1234 });

    const echo_data = [_]u8{0xAA} ** 16;
    const echo_repr = icmp.EchoRepr{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 0x5432,
    };
    var icmp_buf: [icmp.HEADER_LEN + 16]u8 = undefined;
    _ = icmp.emitEcho(echo_repr, &echo_data, &icmp_buf) catch unreachable;

    const ip_repr = testIpv4Repr(.icmp, REMOTE_IP, LOCAL_IP, icmp_buf.len);

    // Parse ICMP and deliver to socket
    const icmp_repr = icmp.parse(&icmp_buf) catch return error.ParseFailed;
    const icmp_payload = icmp_buf[icmp.HEADER_LEN..];
    try testing.expect(sock.accepts(REMOTE_IP, LOCAL_IP, icmp_repr, icmp_payload));
    sock.process(REMOTE_IP, icmp_repr, icmp_payload);

    // Auto-reply still works
    const result = iface_inst.processIcmp(ip_repr, &icmp_buf, false) orelse
        return error.ExpectedResponse;
    switch (result) {
        .ipv4 => |resp| {
            try testing.expectEqual(LOCAL_IP, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_IP, resp.ip.dst_addr);
            switch (resp.payload) {
                .icmp_echo => |echo_resp| {
                    try testing.expectEqual(icmp.Type.echo_reply, echo_resp.echo.icmp_type);
                    try testing.expectEqual(@as(u16, 0x1234), echo_resp.echo.identifier);
                    try testing.expectEqual(@as(u16, 0x5432), echo_resp.echo.sequence);
                    try testing.expectEqualSlices(u8, &echo_data, echo_resp.data);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }

    // Verify socket received the packet
    try testing.expect(sock.canRecv());
    var recv_buf: [128]u8 = undefined;
    const recv_result = try sock.recvSlice(&recv_buf);
    try testing.expectEqual(REMOTE_IP, recv_result.src_addr);
    // Socket stores the full ICMP packet (header + data)
    try testing.expectEqual(icmp.HEADER_LEN + echo_data.len, recv_result.data_len);
}

// [smoltcp:iface/interface/tests/mod.rs:test_tcp_not_accepted]
test "TCP SYN with no listener produces RST" {
    var iface_inst = testInterface();

    // Build TCP SYN
    const syn_wire = tcp_wire.Repr{
        .src_port = 4242,
        .dst_port = 4243,
        .seq_number = 12345,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .syn = true },
        .window_size = 1024,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    var tcp_buf: [tcp_wire.HEADER_LEN]u8 = undefined;
    _ = tcp_wire.emit(syn_wire, &tcp_buf) catch unreachable;

    const ip_repr = testIpv4Repr(.tcp, REMOTE_IP, LOCAL_IP, tcp_buf.len);

    // No socket handled -> should produce RST
    const result = iface_inst.processTcp(ip_repr, &tcp_buf, false) orelse
        return error.ExpectedResponse;
    switch (result) {
        .ipv4 => |resp| {
            try testing.expectEqual(LOCAL_IP, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_IP, resp.ip.dst_addr);
            try testing.expectEqual(ipv4.Protocol.tcp, resp.ip.protocol);
            switch (resp.payload) {
                .tcp => |rst| {
                    try testing.expectEqual(@as(u16, 4243), rst.src_port);
                    try testing.expectEqual(@as(u16, 4242), rst.dst_port);
                    try testing.expectEqual(tcp_wire.Control.rst, rst.control);
                    try testing.expect(rst.seq_number.eql(tcp_wire.SeqNumber.ZERO));
                    // SYN without ACK: ack = seq + segmentLen (1 for SYN)
                    try testing.expect(rst.ack_number.?.eql(
                        tcp_wire.SeqNumber.fromU32(12345 + 1),
                    ));
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }

    // RST input -> no response (never RST a RST)
    const rst_wire = tcp_wire.Repr{
        .src_port = 4242,
        .dst_port = 4243,
        .seq_number = 0,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .rst = true },
        .window_size = 0,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    var rst_buf: [tcp_wire.HEADER_LEN]u8 = undefined;
    _ = tcp_wire.emit(rst_wire, &rst_buf) catch unreachable;
    const rst_ip = testIpv4Repr(.tcp, REMOTE_IP, LOCAL_IP, rst_buf.len);
    try testing.expectEqual(@as(?Response, null), iface_inst.processTcp(rst_ip, &rst_buf, false));

    // Unspecified source -> no response
    const unspec_ip = testIpv4Repr(.tcp, ipv4.UNSPECIFIED, LOCAL_IP, tcp_buf.len);
    try testing.expectEqual(@as(?Response, null), iface_inst.processTcp(unspec_ip, &tcp_buf, false));

    // Socket handled -> no response
    try testing.expectEqual(@as(?Response, null), iface_inst.processTcp(ip_repr, &tcp_buf, true));
}

// -------------------------------------------------------------------------
// NeighborCache unit tests
// -------------------------------------------------------------------------

// [smoltcp:iface/neighbor.rs:test_fill]
test "neighbor cache fill and lookup" {
    var cache = NeighborCache{};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const ip2: ipv4.Address = .{ 10, 0, 0, 2 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    // Not found initially
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, time.Instant.ZERO));
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip2, time.Instant.ZERO));

    // Fill ip1 -> mac_a
    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip2, time.Instant.ZERO));

    // Expired after 2x lifetime
    const expired = time.Instant.ZERO.add(NEIGHBOR_LIFETIME).add(NEIGHBOR_LIFETIME);
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, expired));

    // Re-fill, ip2 still not found
    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip2, time.Instant.ZERO));
}

// [smoltcp:iface/neighbor.rs:test_expire]
test "neighbor cache entry expires" {
    var cache = NeighborCache{};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);

    const expired = time.Instant.ZERO.add(NEIGHBOR_LIFETIME).add(NEIGHBOR_LIFETIME);
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, expired));
}

// [smoltcp:iface/neighbor.rs:test_replace]
test "neighbor cache replace entry" {
    var cache = NeighborCache{};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };
    const mac_b: ethernet.Address = .{ 0, 0, 0, 0, 0, 2 };

    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);

    cache.fill(ip1, mac_b, time.Instant.ZERO);
    try testing.expectEqual(mac_b, cache.lookup(ip1, time.Instant.ZERO).?);
}

// [smoltcp:iface/neighbor.rs:test_evict]
test "neighbor cache evicts oldest entry" {
    var cache = NeighborCache{};

    const macs = [NEIGHBOR_CACHE_SIZE + 1]ethernet.Address{
        .{ 0, 0, 0, 0, 0, 1 },
        .{ 0, 0, 0, 0, 0, 2 },
        .{ 0, 0, 0, 0, 0, 3 },
        .{ 0, 0, 0, 0, 0, 4 },
        .{ 0, 0, 0, 0, 0, 5 },
        .{ 0, 0, 0, 0, 0, 6 },
        .{ 0, 0, 0, 0, 0, 7 },
        .{ 0, 0, 0, 0, 0, 8 },
        .{ 0, 0, 0, 0, 0, 9 },
    };

    // Fill all 8 slots. Slot 1 (index 1) gets the earliest timestamp.
    var i: usize = 0;
    while (i < NEIGHBOR_CACHE_SIZE) : (i += 1) {
        const ip: ipv4.Address = .{ 10, 0, 0, @intCast(i + 1) };
        const ts = if (i == 1)
            time.Instant.fromMillis(50)
        else
            time.Instant.fromMillis(@intCast((i + 1) * 100));
        cache.fill(ip, macs[i], ts);
    }

    // All 8 should be present (at any time before expiry)
    const lookup_time = time.Instant.fromMillis(1000);
    const ip2: ipv4.Address = .{ 10, 0, 0, 2 };
    try testing.expectEqual(macs[1], cache.lookup(ip2, lookup_time).?);

    // ip9 not present yet
    const ip9: ipv4.Address = .{ 10, 0, 0, 9 };
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip9, lookup_time));

    // Fill a 9th entry -- evicts the one with earliest expires_at (slot 1, t=50)
    cache.fill(ip9, macs[8], time.Instant.fromMillis(300));

    // ip2 was evicted
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip2, lookup_time));
    // ip9 is now present
    try testing.expectEqual(macs[8], cache.lookup(ip9, lookup_time).?);
}

// [smoltcp:iface/neighbor.rs:test_flush]
test "neighbor cache flush" {
    var cache = NeighborCache{};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);

    cache.flush();
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, time.Instant.ZERO));
}

// [smoltcp:iface/neighbor.rs:test_hush -- lookupFull tri-state]
test "neighbor cache lookupFull found/not_found/rate_limited" {
    var cache = NeighborCache{};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    // Not found initially
    try testing.expectEqual(NeighborCache.LookupResult.not_found, cache.lookupFull(ip1, time.Instant.ZERO));

    // Rate-limited after limitRate
    cache.limitRate(time.Instant.ZERO);
    try testing.expectEqual(NeighborCache.LookupResult.rate_limited, cache.lookupFull(ip1, time.Instant.fromMillis(100)));

    // Rate limit expires after SILENT_TIME
    try testing.expectEqual(NeighborCache.LookupResult.not_found, cache.lookupFull(ip1, time.Instant.fromMillis(2000)));

    // Found after fill
    cache.fill(ip1, mac_a, time.Instant.ZERO);
    switch (cache.lookupFull(ip1, time.Instant.ZERO)) {
        .found => |mac| try testing.expectEqual(mac_a, mac),
        else => return error.ExpectedFound,
    }
}

test "neighbor cache rate limit expires" {
    var cache = NeighborCache{};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };

    cache.limitRate(time.Instant.fromMillis(500));

    // Within silent period: rate_limited
    try testing.expectEqual(NeighborCache.LookupResult.rate_limited, cache.lookupFull(ip1, time.Instant.fromMillis(600)));
    try testing.expectEqual(NeighborCache.LookupResult.rate_limited, cache.lookupFull(ip1, time.Instant.fromMillis(1499)));

    // At exactly silent_until boundary: not rate_limited (greaterThan, not greaterThanOrEqual)
    try testing.expectEqual(NeighborCache.LookupResult.not_found, cache.lookupFull(ip1, time.Instant.fromMillis(1500)));

    // Well past: not_found
    try testing.expectEqual(NeighborCache.LookupResult.not_found, cache.lookupFull(ip1, time.Instant.fromMillis(5000)));
}

test "neighbor cache flush clears rate limit" {
    var cache = NeighborCache{};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };

    cache.limitRate(time.Instant.ZERO);
    try testing.expectEqual(NeighborCache.LookupResult.rate_limited, cache.lookupFull(ip1, time.Instant.fromMillis(100)));

    cache.flush();
    try testing.expectEqual(NeighborCache.LookupResult.not_found, cache.lookupFull(ip1, time.Instant.fromMillis(100)));
}

test "neighbor cache lookupFull prefers found over rate_limited" {
    var cache = NeighborCache{};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    // Fill + rate limit simultaneously
    cache.fill(ip1, mac_a, time.Instant.ZERO);
    cache.limitRate(time.Instant.ZERO);

    // Found takes precedence over rate_limited
    switch (cache.lookupFull(ip1, time.Instant.fromMillis(100))) {
        .found => |mac| try testing.expectEqual(mac_a, mac),
        else => return error.ExpectedFound,
    }
}

// -------------------------------------------------------------------------
// Route tests
// -------------------------------------------------------------------------

// [smoltcp:iface/route.rs:test_fill]
test "route lookup empty table" {
    const routes = Routes{};
    try testing.expectEqual(@as(?ipv4.Address, null), routes.lookup(.{ 192, 0, 2, 1 }, time.Instant.ZERO));
}

test "route lookup match and no match" {
    var routes = Routes{};
    _ = routes.add(.{
        .cidr = .{ .address = .{ 192, 0, 2, 0 }, .prefix_len = 24 },
        .via_router = .{ 192, 0, 2, 1 },
    });

    // Address in the route's subnet should match.
    try testing.expectEqual([4]u8{ 192, 0, 2, 1 }, routes.lookup(.{ 192, 0, 2, 13 }, time.Instant.ZERO).?);
    try testing.expectEqual([4]u8{ 192, 0, 2, 1 }, routes.lookup(.{ 192, 0, 2, 42 }, time.Instant.ZERO).?);
    // Address outside the subnet should not match.
    try testing.expectEqual(@as(?ipv4.Address, null), routes.lookup(.{ 198, 51, 100, 1 }, time.Instant.ZERO));
}

test "route lookup longest prefix match" {
    var routes = Routes{};
    _ = routes.add(.{
        .cidr = .{ .address = .{ 10, 0, 0, 0 }, .prefix_len = 8 },
        .via_router = .{ 10, 0, 0, 1 },
    });
    _ = routes.add(.{
        .cidr = .{ .address = .{ 10, 1, 0, 0 }, .prefix_len = 16 },
        .via_router = .{ 10, 1, 0, 1 },
    });
    // /16 is more specific than /8 for 10.1.x.x addresses.
    try testing.expectEqual([4]u8{ 10, 1, 0, 1 }, routes.lookup(.{ 10, 1, 2, 3 }, time.Instant.ZERO).?);
    // 10.2.x.x only matches the /8.
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, routes.lookup(.{ 10, 2, 3, 4 }, time.Instant.ZERO).?);
}

test "route lookup expiry" {
    var routes = Routes{};
    _ = routes.add(.{
        .cidr = .{ .address = .{ 198, 51, 100, 0 }, .prefix_len = 24 },
        .via_router = .{ 198, 51, 100, 1 },
        .expires_at = time.Instant.fromMillis(10),
    });
    // Before expiry: should match.
    try testing.expectEqual([4]u8{ 198, 51, 100, 1 }, routes.lookup(.{ 198, 51, 100, 21 }, time.Instant.ZERO).?);
    // At expiry: should still match (not strictly after).
    try testing.expectEqual([4]u8{ 198, 51, 100, 1 }, routes.lookup(.{ 198, 51, 100, 21 }, time.Instant.fromMillis(10)).?);
    // After expiry: should not match.
    try testing.expectEqual(@as(?ipv4.Address, null), routes.lookup(.{ 198, 51, 100, 21 }, time.Instant.fromMillis(11)));
}

test "route default gateway" {
    const gw = Route.newDefaultGateway(.{ 10, 0, 0, 1 });
    try testing.expectEqual(@as(u8, 0), gw.cidr.prefix_len);
    var routes = Routes{};
    _ = routes.add(gw);
    // Default gateway matches any address.
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, routes.lookup(.{ 1, 2, 3, 4 }, time.Instant.ZERO).?);
    try testing.expectEqual([4]u8{ 10, 0, 0, 1 }, routes.lookup(.{ 192, 168, 1, 1 }, time.Instant.ZERO).?);
}

test "interface route direct delivery vs gateway" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.addIpAddr(.{ .address = .{ 10, 0, 0, 1 }, .prefix_len = 24 });
    _ = iface.routes.add(Route.newDefaultGateway(.{ 10, 0, 0, 254 }));

    // Same-subnet address: direct delivery (returns dst itself).
    try testing.expectEqual([4]u8{ 10, 0, 0, 99 }, iface.route(.{ 10, 0, 0, 99 }).?);
    // Off-subnet address: via gateway.
    try testing.expectEqual([4]u8{ 10, 0, 0, 254 }, iface.route(.{ 8, 8, 8, 8 }).?);
    // Broadcast: direct delivery.
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, iface.route(.{ 255, 255, 255, 255 }).?);
}

test "interface hasNeighbor with routing" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.addIpAddr(.{ .address = .{ 10, 0, 0, 1 }, .prefix_len = 24 });
    _ = iface.routes.add(Route.newDefaultGateway(.{ 10, 0, 0, 254 }));
    iface.neighbor_cache.fill(.{ 10, 0, 0, 254 }, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, time.Instant.ZERO);

    // Off-subnet: gateway neighbor is cached.
    try testing.expect(iface.hasNeighbor(.{ 8, 8, 8, 8 }));
    // Same-subnet with no cache entry: no neighbor.
    try testing.expect(!iface.hasNeighbor(.{ 10, 0, 0, 99 }));
}

test "multicast group join leave has" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    const group1 = ipv4.Address{ 224, 0, 0, 1 };
    const group2 = ipv4.Address{ 239, 1, 2, 3 };

    try testing.expect(!iface.hasMulticastGroup(group1));
    try testing.expect(iface.joinMulticastGroup(group1));
    try testing.expect(iface.hasMulticastGroup(group1));

    // Duplicate join is OK.
    try testing.expect(iface.joinMulticastGroup(group1));

    try testing.expect(iface.joinMulticastGroup(group2));
    try testing.expect(iface.hasMulticastGroup(group2));

    try testing.expect(iface.leaveMulticastGroup(group1));
    try testing.expect(!iface.hasMulticastGroup(group1));
    try testing.expect(iface.hasMulticastGroup(group2));

    // Leave non-member is false.
    try testing.expect(!iface.leaveMulticastGroup(group1));
}

test "multicast group full capacity" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    var i: u8 = 0;
    while (i < MAX_MULTICAST_GROUPS) : (i += 1) {
        try testing.expect(iface.joinMulticastGroup(.{ 224, 0, 0, i + 1 }));
    }
    // Table is full.
    try testing.expect(!iface.joinMulticastGroup(.{ 224, 0, 0, 99 }));
}
