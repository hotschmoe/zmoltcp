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
const ipv6 = @import("wire/ipv6.zig");
const icmp = @import("wire/icmp.zig");
const icmpv6 = @import("wire/icmpv6.zig");
const ndisc = @import("wire/ndisc.zig");
const ndiscoption = @import("wire/ndiscoption.zig");
const mld = @import("wire/mld.zig");
const ipv6hbh = @import("wire/ipv6hbh.zig");
const ipv6ext_header = @import("wire/ipv6ext_header.zig");
const ipv6option = @import("wire/ipv6option.zig");
const udp = @import("wire/udp.zig");
const tcp_wire = @import("wire/tcp.zig");
const tcp_socket = @import("socket/tcp.zig");
const time = @import("time.zig");

// -------------------------------------------------------------------------
// Medium
// -------------------------------------------------------------------------

pub const Medium = enum {
    /// Ethernet: 14-byte frame header, ARP/NDP neighbor resolution.
    ethernet,
    /// Raw IP: no link-layer framing, point-to-point (TUN, PPP).
    ip,
    /// IEEE 802.15.4: 6LoWPAN header compression over constrained radios.
    ieee802154,
};

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
        icmpv6: ChecksumMode = .both,
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
pub const IpCidrV6 = ip_generic.Cidr(ipv6);

pub const IPV6_MIN_MTU: usize = 1280;
const ICMPV6_HEADER_LEN: usize = 8;
pub const ICMPV6_ERROR_MAX_DATA: usize = IPV6_MIN_MTU - ipv6.HEADER_LEN - ICMPV6_HEADER_LEN;
pub const MAX_MULTICAST_GROUPS_V6 = 8;

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
pub const RouteV6 = RouteFor(ipv6);

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
pub const RoutesV6 = RoutesFor(ipv6);

pub fn NeighborCache(comptime Ip: type) type {
    return struct {
        const Self = @This();
        pub const SILENT_TIME = time.Duration.fromMillis(1000);

        pub const LookupResult = union(enum) {
            found: ethernet.Address,
            not_found,
            rate_limited,
        };

        const Entry = struct {
            protocol_addr: Ip.Address = Ip.UNSPECIFIED,
            hardware_addr: ethernet.Address = .{ 0, 0, 0, 0, 0, 0 },
            expires_at: time.Instant = time.Instant.ZERO,
        };

        entries: [NEIGHBOR_CACHE_SIZE]Entry = [_]Entry{.{}} ** NEIGHBOR_CACHE_SIZE,
        silent_until: time.Instant = time.Instant.ZERO,

        fn isOccupied(entry: Entry) bool {
            return !Ip.isUnspecified(entry.protocol_addr);
        }

        pub fn fill(self: *Self, ip: Ip.Address, mac: ethernet.Address, now: time.Instant) void {
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

        pub fn lookup(self: *const Self, ip: Ip.Address, now: time.Instant) ?ethernet.Address {
            return switch (self.lookupFull(ip, now)) {
                .found => |mac| mac,
                .not_found, .rate_limited => null,
            };
        }

        pub fn lookupFull(self: *const Self, ip: Ip.Address, now: time.Instant) LookupResult {
            for (self.entries) |entry| {
                if (std.mem.eql(u8, &entry.protocol_addr, &ip)) {
                    if (entry.expires_at.greaterThanOrEqual(now)) return .{ .found = entry.hardware_addr };
                    break;
                }
            }
            if (now.lessThan(self.silent_until)) return .rate_limited;
            return .not_found;
        }

        pub fn limitRate(self: *Self, now: time.Instant) void {
            self.silent_until = now.add(SILENT_TIME);
        }

        pub fn hasNeighbor(self: *const Self, ip: Ip.Address) bool {
            for (self.entries) |entry| {
                if (std.mem.eql(u8, &entry.protocol_addr, &ip)) return true;
            }
            return false;
        }

        pub fn flush(self: *Self) void {
            self.entries = [_]Entry{.{}} ** NEIGHBOR_CACHE_SIZE;
            self.silent_until = time.Instant.ZERO;
        }
    };
}

pub fn IpMetaFor(comptime Ip: type) type {
    return struct {
        src_addr: Ip.Address,
        dst_addr: Ip.Address,
        protocol: Ip.Protocol,
        hop_limit: u8,
    };
}

pub const IpMeta = IpMetaFor(ipv4);
pub const IpMetaV6 = IpMetaFor(ipv6);

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

pub const Ipv6Payload = union(enum) {
    icmpv6_echo: struct {
        ident: u16,
        seq_no: u16,
        data: []const u8,
    },
    icmpv6_dst_unreachable: struct {
        reason: icmpv6.DstUnreachable,
        data: []const u8,
    },
    icmpv6_pkt_too_big: struct {
        mtu: u32,
        data: []const u8,
    },
    icmpv6_param_problem: struct {
        reason: icmpv6.ParamProblem,
        pointer: u32,
        data: []const u8,
    },
    ndisc: ndisc.Repr,
    tcp: tcp_socket.TcpRepr,
};

pub const Ipv6Response = struct {
    ip: IpMetaV6,
    payload: Ipv6Payload,
};

pub const Response = union(enum) {
    arp_reply: arp.Repr,
    ipv4: Ipv4Response,
    ipv6: Ipv6Response,
};

pub fn IpState(comptime Ip: type) type {
    const Cidr = ip_generic.Cidr(Ip);

    return struct {
        const Self = @This();

        ip_addrs: [MAX_ADDR_COUNT]Cidr = undefined,
        ip_addr_count: usize = 0,
        routes: RoutesFor(Ip) = .{},

        pub fn addIpAddr(self: *Self, cidr: Cidr) void {
            if (self.ip_addr_count < MAX_ADDR_COUNT) {
                self.ip_addrs[self.ip_addr_count] = cidr;
                self.ip_addr_count += 1;
            }
        }

        pub fn setAddrs(self: *Self, cidrs: []const Cidr) void {
            const count = @min(cidrs.len, MAX_ADDR_COUNT);
            for (cidrs[0..count], 0..) |c, i| {
                self.ip_addrs[i] = c;
            }
            self.ip_addr_count = count;
        }

        pub fn ipAddrs(self: *const Self) []const Cidr {
            return self.ip_addrs[0..self.ip_addr_count];
        }

        pub fn hasIpAddr(self: *const Self, addr: Ip.Address) bool {
            for (self.ipAddrs()) |cidr| {
                if (std.mem.eql(u8, &cidr.address, &addr)) return true;
            }
            return false;
        }

        pub fn getSourceAddress(self: *const Self, dst: Ip.Address) ?Ip.Address {
            if (self.ip_addr_count == 0) return null;
            for (self.ipAddrs()) |cidr| {
                if (cidr.contains(dst)) return cidr.address;
            }
            return self.ip_addrs[0].address;
        }

        pub fn inSameNetwork(self: *const Self, addr: Ip.Address) bool {
            for (self.ipAddrs()) |cidr| {
                if (cidr.contains(addr)) return true;
            }
            return false;
        }

        pub fn routeLookup(self: *const Self, dst: Ip.Address, now: time.Instant) ?Ip.Address {
            if (self.inSameNetwork(dst)) return dst;
            return self.routes.lookup(dst, now);
        }
    };
}

pub const MulticastGroupState = enum { joining, joined, leaving };

pub const MulticastGroupEntryV6 = struct {
    addr: ipv6.Address = ipv6.UNSPECIFIED,
    state: MulticastGroupState = .joining,
};

pub const SlaacState = struct {
    pub const MAX_PREFIXES = 4;
    pub const MAX_RS_RETRIES: u8 = 3;
    pub const RS_RETRY_INTERVAL = time.Duration.fromSecs(4);

    const PrefixEntry = struct {
        prefix: IpCidrV6,
        valid_until: time.Instant,
        preferred_until: time.Instant,
    };

    phase: enum { idle, soliciting, configured } = .idle,
    prefixes: [MAX_PREFIXES]?PrefixEntry = .{null} ** MAX_PREFIXES,
    rs_retries_left: u8 = MAX_RS_RETRIES,
    next_rs_at: time.Instant = time.Instant.ZERO,
    default_router: ?ipv6.Address = null,
    router_lifetime_until: ?time.Instant = null,
};

pub const Interface = struct {
    hardware_addr: ethernet.Address,
    v4: IpState(ipv4) = .{},
    v6: IpState(ipv6) = .{},
    neighbor_cache: NeighborCache(ipv4) = .{},
    neighbor_cache_v6: NeighborCache(ipv6) = .{},
    now: time.Instant = time.Instant.ZERO,
    any_ip: bool = false,
    auto_icmp_echo_reply: bool = true,
    multicast_groups: [MAX_MULTICAST_GROUPS]?ipv4.Address = .{null} ** MAX_MULTICAST_GROUPS,
    multicast_groups_v6: [MAX_MULTICAST_GROUPS_V6]?MulticastGroupEntryV6 = .{null} ** MAX_MULTICAST_GROUPS_V6,
    slaac: ?SlaacState = null,

    pub fn init(hw_addr: ethernet.Address) Interface {
        return .{ .hardware_addr = hw_addr };
    }

    pub fn setIpAddrs(self: *Interface, cidrs: []const IpCidr) void {
        self.v4.setAddrs(cidrs);
        self.neighbor_cache.flush();
    }

    pub fn isBroadcast(self: *const Interface, addr: ipv4.Address) bool {
        if (ipv4.isBroadcast(addr)) return true;
        for (self.v4.ipAddrs()) |cidr| {
            if (cidr.broadcast()) |bcast| {
                if (std.mem.eql(u8, &addr, &bcast)) return true;
            }
        }
        return false;
    }

    pub fn ipv4Addr(self: *const Interface) ?ipv4.Address {
        const addrs = self.v4.ipAddrs();
        if (addrs.len == 0) return null;
        return addrs[0].address;
    }

    pub fn route(self: *const Interface, dst: ipv4.Address) ?ipv4.Address {
        if (self.isBroadcast(dst)) return dst;
        return self.v4.routeLookup(dst, self.now);
    }

    pub fn routeV6(self: *const Interface, dst: ipv6.Address) ?ipv6.Address {
        return self.v6.routeLookup(dst, self.now);
    }

    pub fn hasNeighbor(self: *const Interface, dst: ipv4.Address) bool {
        const next_hop = self.route(dst) orelse return false;
        return self.neighbor_cache.lookup(next_hop, self.now) != null;
    }

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

    fn removeMulticastGroupV6(self: *Interface, addr: ipv6.Address) void {
        for (&self.multicast_groups_v6) |*slot| {
            if (slot.*) |entry| {
                if (std.mem.eql(u8, &entry.addr, &addr)) {
                    slot.* = null;
                    return;
                }
            }
        }
    }

    pub fn setIpv6Addrs(self: *Interface, cidrs: []const IpCidrV6) void {
        // Remove old solicited-node multicast groups (immediate, no MLD)
        for (self.v6.ipAddrs()) |old_cidr| {
            const sn = ipv6.solicitedNode(old_cidr.address);
            self.removeMulticastGroupV6(sn);
        }
        self.v6.setAddrs(cidrs);
        self.neighbor_cache_v6.flush();
        // Auto-join all-nodes link-local and solicited-node multicast.
        // These are joined in .joined state (no MLD report needed for
        // implicitly required groups per RFC 3810 S5).
        _ = self.joinMulticastGroupV6WithState(ipv6.LINK_LOCAL_ALL_NODES, .joined);
        for (self.v6.ipAddrs()) |cidr| {
            const sn = ipv6.solicitedNode(cidr.address);
            _ = self.joinMulticastGroupV6WithState(sn, .joined);
        }
    }

    pub fn ipv6Addr(self: *const Interface) ?ipv6.Address {
        const addrs = self.v6.ipAddrs();
        if (addrs.len == 0) return null;
        return addrs[0].address;
    }

    pub fn linkLocalIpv6Addr(self: *const Interface) ?ipv6.Address {
        for (self.v6.ipAddrs()) |cidr| {
            if (ipv6.isLinkLocal(cidr.address)) return cidr.address;
        }
        return null;
    }

    pub fn hasSolicitedNode(self: *const Interface, mcast_addr: ipv6.Address) bool {
        for (self.v6.ipAddrs()) |cidr| {
            if (std.mem.eql(u8, &ipv6.solicitedNode(cidr.address), &mcast_addr)) return true;
        }
        return false;
    }

    fn isIpv6Destination(self: *const Interface, dst: ipv6.Address, is_multicast: bool) bool {
        if (is_multicast)
            return self.hasMulticastGroupV6(dst) or self.hasSolicitedNode(dst);
        return self.v6.hasIpAddr(dst) or ipv6.isLoopback(dst);
    }

    pub fn joinMulticastGroupV6(self: *Interface, addr: ipv6.Address) bool {
        return self.joinMulticastGroupV6WithState(addr, .joining);
    }

    fn joinMulticastGroupV6WithState(self: *Interface, addr: ipv6.Address, initial_state: MulticastGroupState) bool {
        for (&self.multicast_groups_v6) |*slot| {
            if (slot.*) |*entry| {
                if (std.mem.eql(u8, &entry.addr, &addr)) {
                    if (entry.state == .leaving) entry.state = .joined;
                    return true;
                }
            }
        }
        for (&self.multicast_groups_v6) |*slot| {
            if (slot.* == null) {
                slot.* = .{ .addr = addr, .state = initial_state };
                return true;
            }
        }
        return false;
    }

    pub fn leaveMulticastGroupV6(self: *Interface, addr: ipv6.Address) bool {
        for (&self.multicast_groups_v6) |*slot| {
            if (slot.*) |*entry| {
                if (std.mem.eql(u8, &entry.addr, &addr)) {
                    if (entry.state == .leaving) return false;
                    entry.state = .leaving;
                    return true;
                }
            }
        }
        return false;
    }

    pub fn hasMulticastGroupV6(self: *const Interface, addr: ipv6.Address) bool {
        for (self.multicast_groups_v6) |slot| {
            if (slot) |entry| {
                if (entry.state != .leaving and std.mem.eql(u8, &entry.addr, &addr)) return true;
            }
        }
        return false;
    }

    pub fn hasPendingMldV6(self: *const Interface) bool {
        for (self.multicast_groups_v6) |slot| {
            if (slot) |entry| {
                if (entry.state != .joined) return true;
            }
        }
        return false;
    }

    pub fn markMldReported(self: *Interface, addr: ipv6.Address) void {
        for (&self.multicast_groups_v6) |*slot| {
            if (slot.*) |*entry| {
                if (std.mem.eql(u8, &entry.addr, &addr)) {
                    switch (entry.state) {
                        .joining => entry.state = .joined,
                        .leaving => slot.* = null,
                        .joined => {},
                    }
                    return;
                }
            }
        }
    }

    pub fn markAllGroupsForReport(self: *Interface) void {
        for (&self.multicast_groups_v6) |*slot| {
            if (slot.*) |*entry| {
                if (entry.state == .joined) entry.state = .joining;
            }
        }
    }

    pub fn markGroupForReport(self: *Interface, addr: ipv6.Address) void {
        for (&self.multicast_groups_v6) |*slot| {
            if (slot.*) |*entry| {
                if (std.mem.eql(u8, &entry.addr, &addr) and entry.state == .joined) {
                    entry.state = .joining;
                }
            }
        }
    }

    pub fn enableSlaac(self: *Interface) void {
        self.slaac = .{ .phase = .soliciting };
        const ll = linkLocalFromMac(self.hardware_addr);
        self.v6.addIpAddr(.{ .address = ll, .prefix_len = 64 });
        const sn = ipv6.solicitedNode(ll);
        _ = self.joinMulticastGroupV6WithState(sn, .joined);
        _ = self.joinMulticastGroupV6WithState(ipv6.LINK_LOCAL_ALL_NODES, .joined);
    }

    pub fn processRouterAdvertisement(
        self: *Interface,
        ip_repr: ipv6.Repr,
        ra: ndisc.Repr,
    ) void {
        const slaac = &(self.slaac orelse return);
        const ra_data = switch (ra) {
            .router_advert => |d| d,
            else => return,
        };

        if (ra_data.router_lifetime > 0) {
            slaac.default_router = ip_repr.src_addr;
            slaac.router_lifetime_until = self.now.add(
                time.Duration.fromSecs(@as(i64, ra_data.router_lifetime)),
            );
        }

        const prefix_info = ra_data.prefix_info orelse return;
        if (!prefix_info.flags.addrconf) return;
        if (prefix_info.prefix_len != 64) return;

        const iid = eui64InterfaceId(self.hardware_addr);
        var addr: ipv6.Address = prefix_info.prefix;
        @memcpy(addr[8..16], &iid);

        const cidr = IpCidrV6{ .address = addr, .prefix_len = 64 };
        const valid_until = self.now.add(time.Duration.fromSecs(@as(i64, prefix_info.valid_lifetime)));
        const preferred_until = self.now.add(time.Duration.fromSecs(@as(i64, prefix_info.preferred_lifetime)));

        for (&slaac.prefixes) |*slot| {
            if (slot.*) |*entry| {
                if (std.mem.eql(u8, &entry.prefix.address, &cidr.address)) {
                    entry.valid_until = valid_until;
                    entry.preferred_until = preferred_until;
                    slaac.phase = .configured;
                    return;
                }
            }
        }

        // New prefix: insert entry, add address, join solicited-node multicast
        for (&slaac.prefixes) |*slot| {
            if (slot.* == null) {
                slot.* = .{ .prefix = cidr, .valid_until = valid_until, .preferred_until = preferred_until };
                break;
            }
        }
        self.v6.addIpAddr(cidr);
        _ = self.joinMulticastGroupV6WithState(ipv6.solicitedNode(addr), .joined);

        slaac.phase = .configured;
    }

    pub fn slaacMaintenance(self: *Interface, now: time.Instant) void {
        const slaac = &(self.slaac orelse return);

        // Remove expired default route
        if (slaac.router_lifetime_until) |until| {
            if (!now.lessThan(until)) {
                slaac.default_router = null;
                slaac.router_lifetime_until = null;
            }
        }

        // Remove expired prefixes and their addresses
        var any_valid = false;
        for (&slaac.prefixes) |*slot| {
            if (slot.*) |entry| {
                if (!now.lessThan(entry.valid_until)) {
                    // Prefix expired: remove address
                    // (simplified: we don't actively remove from v6 ip_addrs
                    // to avoid complex index management; IpState.addIpAddr
                    // only adds, so expired addresses stay until setIpv6Addrs
                    // is called. In practice, SLAAC renews before expiry.)
                    slot.* = null;
                } else {
                    any_valid = true;
                }
            }
        }

        // If all prefixes expired and we had been configured, go back to soliciting
        if (!any_valid and slaac.phase == .configured) {
            slaac.phase = .soliciting;
            slaac.rs_retries_left = SlaacState.MAX_RS_RETRIES;
            slaac.next_rs_at = now;
        }
    }

    pub fn slaacPollAt(self: *const Interface) ?time.Instant {
        const slaac = self.slaac orelse return null;
        switch (slaac.phase) {
            .soliciting => {
                if (slaac.rs_retries_left > 0) return slaac.next_rs_at;
                return null;
            },
            .configured => {
                var earliest: ?time.Instant = slaac.router_lifetime_until;
                for (slaac.prefixes) |slot| {
                    const entry = slot orelse continue;
                    if (earliest == null or entry.valid_until.lessThan(earliest.?)) {
                        earliest = entry.valid_until;
                    }
                }
                return earliest;
            },
            .idle => return null,
        }
    }

    pub fn eui64InterfaceId(mac: ethernet.Address) [8]u8 {
        return .{
            mac[0] ^ 0x02, // flip U/L bit
            mac[1],
            mac[2],
            0xFF,
            0xFE,
            mac[3],
            mac[4],
            mac[5],
        };
    }

    pub fn linkLocalFromMac(mac: ethernet.Address) ipv6.Address {
        const iid = eui64InterfaceId(mac);
        return .{ 0xFE, 0x80, 0, 0, 0, 0, 0, 0, iid[0], iid[1], iid[2], iid[3], iid[4], iid[5], iid[6], iid[7] };
    }

    pub fn processEthernet(self: *Interface, frame: []const u8) ?Response {
        const eth_repr = ethernet.parse(frame) catch return null;
        const payload_data = ethernet.payload(frame) catch return null;
        return switch (eth_repr.ethertype) {
            .arp => self.processArp(payload_data),
            .ipv4 => self.processIpv4(payload_data),
            .ipv6 => self.processIpv6(payload_data),
            else => null,
        };
    }

    pub fn processArp(self: *Interface, data: []const u8) ?Response {
        const repr = arp.parse(data) catch return null;
        if (!self.any_ip and !self.v4.hasIpAddr(repr.target_protocol_addr)) return null;

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

        if (!is_broadcast and !self.v4.hasIpAddr(ip_repr.dst_addr)) return null;

        const ip_payload = ipv4.payloadSlice(data) catch return null;

        switch (ip_repr.protocol) {
            .icmp => return self.processIcmp(ip_repr, ip_payload, is_broadcast),
            .igmp => return null, // caller handles via stack
            .udp => return null, // caller handles via processUdp
            .tcp => return null, // caller handles
            .ipsec_esp, .ipsec_ah, _ => {
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
                if (!self.auto_icmp_echo_reply) return null;
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
        const src = self.v4.getSourceAddress(ip_repr.src_addr) orelse return null;
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
        const src = self.v4.getSourceAddress(ip_repr.src_addr) orelse return null;
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

    fn generateTcpRst(comptime Ip: type, src_addr: Ip.Address, dst_addr: Ip.Address, tcp_data: []const u8, socket_handled: bool) ?tcp_socket.TcpRepr {
        if (socket_handled) return null;
        const sock_repr = tcp_socket.TcpRepr.fromWireBytes(tcp_data) orelse return null;
        if (sock_repr.control == .rst) return null;
        if (Ip.isUnspecified(src_addr)) return null;
        if (Ip.isUnspecified(dst_addr)) return null;
        return tcp_socket.rstReply(sock_repr);
    }

    pub fn processTcp(self: *const Interface, ip_repr: ipv4.Repr, tcp_data: []const u8, socket_handled: bool) ?Response {
        _ = self;
        const rst = generateTcpRst(ipv4, ip_repr.src_addr, ip_repr.dst_addr, tcp_data, socket_handled) orelse return null;
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

    pub fn processIpv6(self: *Interface, data: []const u8) ?Response {
        const ip_repr = ipv6.parse(data) catch return null;
        if (ipv6.isMulticast(ip_repr.src_addr)) return null;

        const ip_payload = data[ipv6.HEADER_LEN..][0..ip_repr.payload_len];
        const is_multicast = ipv6.isMulticast(ip_repr.dst_addr);

        if (!self.isIpv6Destination(ip_repr.dst_addr, is_multicast)) return null;

        return switch (ip_repr.next_header) {
            .icmpv6 => self.processIcmpv6(ip_repr, ip_payload, is_multicast),
            .udp => null, // stack handles
            .tcp => null, // stack handles
            .hop_by_hop => null, // stack handles (requires extension header walking)
            .routing, .fragment, .destination => null, // stack handles extension headers
            .no_next_header => null,
            .ipsec_esp, .ipsec_ah, _ => self.icmpv6ParamProblem(ip_repr, .unrecognized_nxt_hdr, 6, ip_payload),
        };
    }

    pub fn processIcmpv6(self: *Interface, ip_repr: ipv6.Repr, payload: []const u8, is_multicast: bool) ?Response {
        const icmpv6_repr = icmpv6.parse(payload, ip_repr.src_addr, ip_repr.dst_addr) catch return null;

        switch (icmpv6_repr) {
            .echo_request => |echo| {
                if (!self.auto_icmp_echo_reply) return null;
                const src = if (is_multicast)
                    (self.ipv6Addr() orelse return null)
                else
                    ip_repr.dst_addr;
                return .{ .ipv6 = .{
                    .ip = .{
                        .src_addr = src,
                        .dst_addr = ip_repr.src_addr,
                        .protocol = .icmpv6,
                        .hop_limit = DEFAULT_HOP_LIMIT,
                    },
                    .payload = .{ .icmpv6_echo = .{
                        .ident = echo.ident,
                        .seq_no = echo.seq_no,
                        .data = echo.data,
                    } },
                } };
            },
            .ndisc => |ndisc_repr| {
                // NDP requires hop_limit == 255
                if (ip_repr.hop_limit != 255) return null;
                return self.processNdisc(ip_repr, ndisc_repr);
            },
            .mld => return null, // stack handles MLD queries
            .rpl => return null, // stack handles RPL control messages
            .dst_unreachable, .pkt_too_big, .time_exceeded, .param_problem => return null, // deliver to sockets
            .echo_reply => return null,
        }
    }

    pub fn processNdisc(self: *Interface, ip_repr: ipv6.Repr, ndisc_repr: ndisc.Repr) ?Response {
        switch (ndisc_repr) {
            .neighbor_solicit => |ns| {
                if (ns.lladdr) |lladdr| {
                    if (!ipv6.isUnspecified(ip_repr.src_addr)) {
                        self.neighbor_cache_v6.fill(ip_repr.src_addr, lladdr, self.now);
                    }
                }
                if (!self.v6.hasIpAddr(ns.target_addr)) return null;
                // Multicast dst must be solicited-node for target
                if (ipv6.isMulticast(ip_repr.dst_addr) and
                    !self.hasSolicitedNode(ip_repr.dst_addr))
                {
                    return null;
                }

                return .{ .ipv6 = .{
                    .ip = .{
                        .src_addr = ns.target_addr,
                        .dst_addr = if (ipv6.isUnspecified(ip_repr.src_addr))
                            ipv6.LINK_LOCAL_ALL_NODES
                        else
                            ip_repr.src_addr,
                        .protocol = .icmpv6,
                        .hop_limit = 255,
                    },
                    .payload = .{ .ndisc = .{ .neighbor_advert = .{
                        .flags = .{
                            .router = false,
                            .solicited = !ipv6.isUnspecified(ip_repr.src_addr),
                            .override_ = true,
                        },
                        .target_addr = ns.target_addr,
                        .lladdr = self.hardware_addr,
                    } } },
                } };
            },
            .neighbor_advert => |na| {
                if (na.lladdr) |lladdr| {
                    if (na.flags.override_ or
                        !self.neighbor_cache_v6.hasNeighbor(na.target_addr))
                    {
                        self.neighbor_cache_v6.fill(na.target_addr, lladdr, self.now);
                    }
                }
                return null;
            },
            .router_solicit, .router_advert, .redirect => return null, // RA handled by stack/SLAAC
        }
    }

    pub fn processMldQuery(self: *Interface, ip_repr: ipv6.Repr, query: mld.Repr) void {
        switch (query) {
            .query => |q| {
                if (ip_repr.hop_limit != 1) return;
                if (ipv6.isUnspecified(q.mcast_addr)) {
                    self.markAllGroupsForReport(); // general query
                } else if (self.hasMulticastGroupV6(q.mcast_addr)) {
                    self.markGroupForReport(q.mcast_addr); // group-specific query
                }
            },
            .report => {},
        }
    }

    pub fn icmpv6ParamProblem(
        self: *const Interface,
        ip_repr: ipv6.Repr,
        reason: icmpv6.ParamProblem,
        pointer: usize,
        payload: []const u8,
    ) ?Response {
        if (ipv6.isMulticast(ip_repr.src_addr)) return null;
        if (ipv6.isUnspecified(ip_repr.src_addr)) return null;
        const src = self.v6.getSourceAddress(ip_repr.src_addr) orelse return null;
        const clamped = payload[0..@min(payload.len, ICMPV6_ERROR_MAX_DATA)];
        return .{ .ipv6 = .{
            .ip = .{
                .src_addr = src,
                .dst_addr = ip_repr.src_addr,
                .protocol = .icmpv6,
                .hop_limit = DEFAULT_HOP_LIMIT,
            },
            .payload = .{ .icmpv6_param_problem = .{
                .reason = reason,
                .pointer = @intCast(pointer),
                .data = clamped,
            } },
        } };
    }

    pub fn processUdpV6(self: *const Interface, ip_repr: ipv6.Repr, udp_data: []const u8, socket_handled: bool) ?Response {
        if (socket_handled) return null;
        if (ipv6.isMulticast(ip_repr.dst_addr)) return null;
        const src = self.v6.getSourceAddress(ip_repr.src_addr) orelse return null;
        const data = udp_data[0..@min(udp_data.len, ICMPV6_ERROR_MAX_DATA)];
        return .{ .ipv6 = .{
            .ip = .{
                .src_addr = src,
                .dst_addr = ip_repr.src_addr,
                .protocol = .icmpv6,
                .hop_limit = DEFAULT_HOP_LIMIT,
            },
            .payload = .{ .icmpv6_dst_unreachable = .{
                .reason = .port_unreachable,
                .data = data,
            } },
        } };
    }

    pub fn processTcpV6(self: *const Interface, ip_repr: ipv6.Repr, tcp_data: []const u8, socket_handled: bool) ?Response {
        _ = self;
        const rst = generateTcpRst(ipv6, ip_repr.src_addr, ip_repr.dst_addr, tcp_data, socket_handled) orelse return null;
        return .{ .ipv6 = .{
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
    iface.v4.addIpAddr(.{ .address = .{ 192, 168, 1, 1 }, .prefix_len = 24 });
    iface.v4.addIpAddr(LOCAL_CIDR);
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
    iface.v4.ip_addr_count = 0;
    iface.v4.addIpAddr(.{ .address = .{ 192, 168, 1, 23 }, .prefix_len = 24 });
    try testing.expect(iface.isBroadcast(.{ 255, 255, 255, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 255, 255, 255, 254 }));
    try testing.expect(iface.isBroadcast(.{ 192, 168, 1, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 168, 1, 254 }));

    // /16
    iface.v4.ip_addr_count = 0;
    iface.v4.addIpAddr(.{ .address = .{ 192, 168, 23, 24 }, .prefix_len = 16 });
    try testing.expect(iface.isBroadcast(.{ 255, 255, 255, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 255, 255, 255, 254 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 168, 23, 255 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 168, 23, 254 }));
    try testing.expect(!iface.isBroadcast(.{ 192, 168, 255, 254 }));
    try testing.expect(iface.isBroadcast(.{ 192, 168, 255, 255 }));

    // /8
    iface.v4.ip_addr_count = 0;
    iface.v4.addIpAddr(.{ .address = .{ 192, 168, 23, 24 }, .prefix_len = 8 });
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
        iface.v4.getSourceAddress(.{ 172, 18, 1, 254 }),
    );
    try testing.expectEqual(
        @as(?ipv4.Address, .{ 172, 24, 24, 14 }),
        iface.v4.getSourceAddress(.{ 172, 24, 24, 12 }),
    );
    // Not in any subnet -> fall back to first
    try testing.expectEqual(
        @as(?ipv4.Address, .{ 172, 18, 1, 2 }),
        iface.v4.getSourceAddress(.{ 172, 24, 23, 254 }),
    );
}

// [smoltcp:iface/interface/tests/ipv4.rs:get_source_address_empty_interface]
test "get source address empty interface" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.v4.ip_addr_count = 0;

    try testing.expectEqual(@as(?ipv4.Address, null), iface.v4.getSourceAddress(.{ 172, 18, 1, 254 }));
    try testing.expectEqual(@as(?ipv4.Address, null), iface.v4.getSourceAddress(.{ 172, 24, 24, 12 }));
    try testing.expectEqual(@as(?ipv4.Address, null), iface.v4.getSourceAddress(.{ 172, 24, 23, 254 }));
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
    const UdpSocket = @import("socket/udp.zig").Socket(ipv4);
    const UdpRepr = @import("socket/udp.zig").UdpRepr;

    var iface = testInterface();

    var rx_meta: [1]UdpSocket.PacketMeta = .{.{}};
    var rx_payload: [64]u8 = undefined;
    var tx_meta: [1]UdpSocket.PacketMeta = .{.{}};
    var tx_payload: [64]u8 = undefined;
    var sock = UdpSocket.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);
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
    const IcmpSocket = @import("socket/icmp.zig").Socket(ipv4);

    var iface_inst = testInterface();

    var rx_meta: [1]IcmpSocket.PacketMeta = .{.{}};
    var rx_payload: [128]u8 = undefined;
    var tx_meta: [1]IcmpSocket.PacketMeta = .{.{}};
    var tx_payload: [128]u8 = undefined;
    var sock = IcmpSocket.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);
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
    sock.process(REMOTE_IP, LOCAL_IP, icmp_repr, icmp_payload);

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
    var cache = NeighborCache(ipv4){};

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
    var cache = NeighborCache(ipv4){};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);

    const expired = time.Instant.ZERO.add(NEIGHBOR_LIFETIME).add(NEIGHBOR_LIFETIME);
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, expired));
}

// [smoltcp:iface/neighbor.rs:test_replace]
test "neighbor cache replace entry" {
    var cache = NeighborCache(ipv4){};

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
    var cache = NeighborCache(ipv4){};

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
    var cache = NeighborCache(ipv4){};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);

    cache.flush();
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, time.Instant.ZERO));
}

// [smoltcp:iface/neighbor.rs:test_hush -- lookupFull tri-state]
test "neighbor cache lookupFull found/not_found/rate_limited" {
    var cache = NeighborCache(ipv4){};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    // Not found initially
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.not_found, cache.lookupFull(ip1, time.Instant.ZERO));

    // Rate-limited after limitRate
    cache.limitRate(time.Instant.ZERO);
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.rate_limited, cache.lookupFull(ip1, time.Instant.fromMillis(100)));

    // Rate limit expires after SILENT_TIME
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.not_found, cache.lookupFull(ip1, time.Instant.fromMillis(2000)));

    // Found after fill
    cache.fill(ip1, mac_a, time.Instant.ZERO);
    switch (cache.lookupFull(ip1, time.Instant.ZERO)) {
        .found => |mac| try testing.expectEqual(mac_a, mac),
        else => return error.ExpectedFound,
    }
}

test "neighbor cache rate limit expires" {
    var cache = NeighborCache(ipv4){};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };

    cache.limitRate(time.Instant.fromMillis(500));

    // Within silent period: rate_limited
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.rate_limited, cache.lookupFull(ip1, time.Instant.fromMillis(600)));
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.rate_limited, cache.lookupFull(ip1, time.Instant.fromMillis(1499)));

    // At exactly silent_until boundary: not rate_limited (greaterThan, not greaterThanOrEqual)
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.not_found, cache.lookupFull(ip1, time.Instant.fromMillis(1500)));

    // Well past: not_found
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.not_found, cache.lookupFull(ip1, time.Instant.fromMillis(5000)));
}

test "neighbor cache flush clears rate limit" {
    var cache = NeighborCache(ipv4){};

    const ip1: ipv4.Address = .{ 10, 0, 0, 1 };

    cache.limitRate(time.Instant.ZERO);
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.rate_limited, cache.lookupFull(ip1, time.Instant.fromMillis(100)));

    cache.flush();
    try testing.expectEqual(NeighborCache(ipv4).LookupResult.not_found, cache.lookupFull(ip1, time.Instant.fromMillis(100)));
}

test "neighbor cache lookupFull prefers found over rate_limited" {
    var cache = NeighborCache(ipv4){};

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
    iface.v4.addIpAddr(.{ .address = .{ 10, 0, 0, 1 }, .prefix_len = 24 });
    _ = iface.v4.routes.add(Route.newDefaultGateway(.{ 10, 0, 0, 254 }));

    // Same-subnet address: direct delivery (returns dst itself).
    try testing.expectEqual([4]u8{ 10, 0, 0, 99 }, iface.route(.{ 10, 0, 0, 99 }).?);
    // Off-subnet address: via gateway.
    try testing.expectEqual([4]u8{ 10, 0, 0, 254 }, iface.route(.{ 8, 8, 8, 8 }).?);
    // Broadcast: direct delivery.
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, iface.route(.{ 255, 255, 255, 255 }).?);
}

test "interface hasNeighbor with routing" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.v4.addIpAddr(.{ .address = .{ 10, 0, 0, 1 }, .prefix_len = 24 });
    _ = iface.v4.routes.add(Route.newDefaultGateway(.{ 10, 0, 0, 254 }));
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

// -------------------------------------------------------------------------
// NeighborCache(ipv6) unit tests
// -------------------------------------------------------------------------

test "v6 neighbor cache fill and lookup" {
    var cache = NeighborCache(ipv6){};

    const ip1: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const ip2: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, time.Instant.ZERO));
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip2, time.Instant.ZERO));

    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip2, time.Instant.ZERO));

    const expired = time.Instant.ZERO.add(NEIGHBOR_LIFETIME).add(NEIGHBOR_LIFETIME);
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, expired));
}

test "v6 neighbor cache replace entry" {
    var cache = NeighborCache(ipv6){};

    const ip1: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };
    const mac_b: ethernet.Address = .{ 0, 0, 0, 0, 0, 2 };

    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);

    cache.fill(ip1, mac_b, time.Instant.ZERO);
    try testing.expectEqual(mac_b, cache.lookup(ip1, time.Instant.ZERO).?);
}

test "v6 neighbor cache evicts oldest entry" {
    var cache = NeighborCache(ipv6){};

    // Fill all NEIGHBOR_CACHE_SIZE slots with distinct timestamps.
    var i: usize = 0;
    while (i < NEIGHBOR_CACHE_SIZE) : (i += 1) {
        var addr: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        addr[15] = @intCast(i + 1);
        const mac = ethernet.Address{ 0, 0, 0, 0, 0, @intCast(i + 1) };
        const ts = if (i == 1)
            time.Instant.fromMillis(50)
        else
            time.Instant.fromMillis(@intCast((i + 1) * 100));
        cache.fill(addr, mac, ts);
    }

    const lookup_time = time.Instant.fromMillis(1000);
    const ip2: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
    try testing.expectEqual(ethernet.Address{ 0, 0, 0, 0, 0, 2 }, cache.lookup(ip2, lookup_time).?);

    // Overflow entry evicts slot with earliest timestamp (slot 1, t=50).
    const ip_new: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF };
    cache.fill(ip_new, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, time.Instant.fromMillis(300));

    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip2, lookup_time));
    try testing.expectEqual(ethernet.Address{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, cache.lookup(ip_new, lookup_time).?);
}

test "v6 neighbor cache flush" {
    var cache = NeighborCache(ipv6){};

    const ip1: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const mac_a: ethernet.Address = .{ 0, 0, 0, 0, 0, 1 };

    cache.fill(ip1, mac_a, time.Instant.ZERO);
    try testing.expectEqual(mac_a, cache.lookup(ip1, time.Instant.ZERO).?);

    cache.flush();
    try testing.expectEqual(@as(?ethernet.Address, null), cache.lookup(ip1, time.Instant.ZERO));
}

// -------------------------------------------------------------------------
// IPv6 address management tests
// -------------------------------------------------------------------------

const LOCAL_V6_LL: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const LOCAL_V6_GLOBAL: ipv6.Address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const LOCAL_V6_LL_CIDR = IpCidrV6{ .address = LOCAL_V6_LL, .prefix_len = 64 };
const LOCAL_V6_GLOBAL_CIDR = IpCidrV6{ .address = LOCAL_V6_GLOBAL, .prefix_len = 64 };

test "setIpv6Addrs flushes v6 neighbor cache" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.neighbor_cache_v6.fill(LOCAL_V6_LL, .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, time.Instant.ZERO);
    try testing.expect(iface.neighbor_cache_v6.hasNeighbor(LOCAL_V6_LL));

    iface.setIpv6Addrs(&.{LOCAL_V6_LL_CIDR});
    try testing.expect(!iface.neighbor_cache_v6.hasNeighbor(LOCAL_V6_LL));
}

test "ipv6Addr and linkLocalIpv6Addr" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    try testing.expectEqual(@as(?ipv6.Address, null), iface.ipv6Addr());
    try testing.expectEqual(@as(?ipv6.Address, null), iface.linkLocalIpv6Addr());

    iface.setIpv6Addrs(&.{ LOCAL_V6_GLOBAL_CIDR, LOCAL_V6_LL_CIDR });
    try testing.expectEqual(LOCAL_V6_GLOBAL, iface.ipv6Addr().?);
    try testing.expectEqual(LOCAL_V6_LL, iface.linkLocalIpv6Addr().?);
}

test "solicitedNodeAddr computation" {
    // fe80::1 -> solicited-node ff02::1:ff00:0001
    const expected: ipv6.Address = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0, 0, 1 };
    try testing.expectEqual(expected, ipv6.solicitedNode(LOCAL_V6_LL));

    // 2001:db8::1 -> ff02::1:ff00:0001
    try testing.expectEqual(expected, ipv6.solicitedNode(LOCAL_V6_GLOBAL));

    // 2001:db8::abcd:ef12 -> ff02::1:ffcd:ef12
    const addr: ipv6.Address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xab, 0xcd, 0xef, 0x12 };
    const exp2: ipv6.Address = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0xcd, 0xef, 0x12 };
    try testing.expectEqual(exp2, ipv6.solicitedNode(addr));
}

test "hasSolicitedNode positive and negative" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.setIpv6Addrs(&.{LOCAL_V6_LL_CIDR});

    const sn = ipv6.solicitedNode(LOCAL_V6_LL);
    try testing.expect(iface.hasSolicitedNode(sn));

    const other_sn: ipv6.Address = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0xAA, 0xBB, 0xCC };
    try testing.expect(!iface.hasSolicitedNode(other_sn));
}

test "setIpv6Addrs auto-joins solicited-node and all-nodes multicast" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.setIpv6Addrs(&.{LOCAL_V6_LL_CIDR});

    // all-nodes link-local (ff02::1)
    try testing.expect(iface.hasMulticastGroupV6(ipv6.LINK_LOCAL_ALL_NODES));
    // solicited-node for LOCAL_V6_LL
    const sn = ipv6.solicitedNode(LOCAL_V6_LL);
    try testing.expect(iface.hasMulticastGroupV6(sn));
}

test "multicast group v6 join leave has" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    const group1: ipv6.Address = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x42 };
    const group2: ipv6.Address = .{ 0xFF, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };

    try testing.expect(!iface.hasMulticastGroupV6(group1));
    try testing.expect(iface.joinMulticastGroupV6(group1));
    try testing.expect(iface.hasMulticastGroupV6(group1));

    try testing.expect(iface.joinMulticastGroupV6(group1)); // duplicate OK
    try testing.expect(iface.joinMulticastGroupV6(group2));
    try testing.expect(iface.hasMulticastGroupV6(group2));

    try testing.expect(iface.leaveMulticastGroupV6(group1));
    try testing.expect(!iface.hasMulticastGroupV6(group1));
    try testing.expect(iface.hasMulticastGroupV6(group2));

    try testing.expect(!iface.leaveMulticastGroupV6(group1)); // not a member
}

test "multicast group v6 full capacity" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    var i: u8 = 0;
    while (i < MAX_MULTICAST_GROUPS_V6) : (i += 1) {
        var addr: ipv6.Address = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
        addr[15] = i + 1;
        try testing.expect(iface.joinMulticastGroupV6(addr));
    }
    try testing.expect(!iface.joinMulticastGroupV6(.{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99 }));
}

test "eui64InterfaceId derivation" {
    // MAC: 02:02:02:02:02:02 -> EUI-64: 00:02:02:FF:FE:02:02:02
    // (flip U/L bit: 02 ^ 02 = 00)
    const iid = Interface.eui64InterfaceId(LOCAL_HW_ADDR);
    try testing.expectEqual([8]u8{ 0x00, 0x02, 0x02, 0xFF, 0xFE, 0x02, 0x02, 0x02 }, iid);

    // MAC: 52:54:00:00:00:00 -> EUI-64: 50:54:00:FF:FE:00:00:00
    const iid2 = Interface.eui64InterfaceId(REMOTE_HW_ADDR);
    try testing.expectEqual([8]u8{ 0x50, 0x54, 0x00, 0xFF, 0xFE, 0x00, 0x00, 0x00 }, iid2);
}

test "linkLocalFromMac derivation" {
    const ll = Interface.linkLocalFromMac(LOCAL_HW_ADDR);
    try testing.expect(ipv6.isLinkLocal(ll));
    // fe80::0002:02ff:fe02:0202
    const expected: ipv6.Address = .{ 0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x02, 0x02, 0xFF, 0xFE, 0x02, 0x02, 0x02 };
    try testing.expectEqual(expected, ll);
}

// -------------------------------------------------------------------------
// IPv6 ingress tests
// -------------------------------------------------------------------------

const REMOTE_V6_LL: ipv6.Address = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
const checksum_wire = @import("wire/checksum.zig");

fn testV6Interface() Interface {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.setIpv6Addrs(&.{LOCAL_V6_LL_CIDR});
    return iface;
}

fn buildIpv6Frame(buf: []u8, ip_repr: ipv6.Repr, payload_data: []const u8) []const u8 {
    const eth_repr = ethernet.Repr{
        .dst_addr = LOCAL_HW_ADDR,
        .src_addr = REMOTE_HW_ADDR,
        .ethertype = .ipv6,
    };
    const eth_len = ethernet.emit(eth_repr, buf) catch unreachable;
    const ip_len = ipv6.emit(ip_repr, buf[eth_len..]) catch unreachable;
    @memcpy(buf[eth_len + ip_len ..][0..payload_data.len], payload_data);
    return buf[0 .. eth_len + ip_len + payload_data.len];
}

fn buildIcmpv6EchoRequest(buf: []u8, src: ipv6.Address, dst: ipv6.Address, ident: u16, seq: u16, echo_data: []const u8) []const u8 {
    const repr = icmpv6.Repr{ .echo_request = .{
        .ident = ident,
        .seq_no = seq,
        .data = echo_data,
    } };
    var icmp_buf: [256]u8 = undefined;
    const icmp_len = icmpv6.emit(repr, src, dst, &icmp_buf) catch unreachable;
    const ip_repr = ipv6.Repr{
        .src_addr = src,
        .dst_addr = dst,
        .next_header = .icmpv6,
        .payload_len = @intCast(icmp_len),
        .hop_limit = 64,
    };
    return buildIpv6Frame(buf, ip_repr, icmp_buf[0..icmp_len]);
}

test "IPv6 echo request -> reply (unicast)" {
    var iface = testV6Interface();
    const echo_data = [_]u8{ 0xDE, 0xAD };
    var buf: [512]u8 = undefined;
    const frame = buildIcmpv6EchoRequest(&buf, REMOTE_V6_LL, LOCAL_V6_LL, 0x1234, 1, &echo_data);
    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;
    switch (result) {
        .ipv6 => |resp| {
            try testing.expectEqual(LOCAL_V6_LL, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_V6_LL, resp.ip.dst_addr);
            try testing.expectEqual(ipv6.Protocol.icmpv6, resp.ip.protocol);
            switch (resp.payload) {
                .icmpv6_echo => |echo| {
                    try testing.expectEqual(@as(u16, 0x1234), echo.ident);
                    try testing.expectEqual(@as(u16, 1), echo.seq_no);
                    try testing.expectEqualSlices(u8, &echo_data, echo.data);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}

test "IPv6 echo request -> reply (multicast, src from configured addr)" {
    var iface = testV6Interface();
    const echo_data = [_]u8{0xAA};
    var buf: [512]u8 = undefined;
    const frame = buildIcmpv6EchoRequest(&buf, REMOTE_V6_LL, ipv6.LINK_LOCAL_ALL_NODES, 0x5678, 2, &echo_data);
    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;
    switch (result) {
        .ipv6 => |resp| {
            // src should be first configured address, not multicast dst
            try testing.expectEqual(LOCAL_V6_LL, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_V6_LL, resp.ip.dst_addr);
        },
        else => return error.UnexpectedResponseType,
    }
}

test "IPv6 reject multicast source" {
    var iface = testV6Interface();
    const echo_data = [_]u8{0xBB};
    var icmp_buf: [256]u8 = undefined;
    const repr = icmpv6.Repr{ .echo_request = .{
        .ident = 1,
        .seq_no = 1,
        .data = &echo_data,
    } };
    const mcast_src = ipv6.LINK_LOCAL_ALL_NODES;
    const icmp_len = icmpv6.emit(repr, mcast_src, LOCAL_V6_LL, &icmp_buf) catch unreachable;
    var buf: [512]u8 = undefined;
    const ip_repr = ipv6.Repr{
        .src_addr = mcast_src,
        .dst_addr = LOCAL_V6_LL,
        .next_header = .icmpv6,
        .payload_len = @intCast(icmp_len),
        .hop_limit = 64,
    };
    const frame = buildIpv6Frame(&buf, ip_repr, icmp_buf[0..icmp_len]);
    try testing.expectEqual(@as(?Response, null), iface.processEthernet(frame));
}

test "IPv6 drop for unknown destination" {
    var iface = testV6Interface();
    const unknown: ipv6.Address = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF };
    const echo_data = [_]u8{0xCC};
    var buf: [512]u8 = undefined;
    const frame = buildIcmpv6EchoRequest(&buf, REMOTE_V6_LL, unknown, 1, 1, &echo_data);
    try testing.expectEqual(@as(?Response, null), iface.processEthernet(frame));
}

fn buildNdpNsFrame(buf: []u8, src: ipv6.Address, dst: ipv6.Address, target: ipv6.Address, lladdr: ?ethernet.Address) []const u8 {
    const ndisc_repr = ndisc.Repr{ .neighbor_solicit = .{
        .target_addr = target,
        .lladdr = lladdr,
    } };
    const icmpv6_repr = icmpv6.Repr{ .ndisc = ndisc_repr };
    var icmp_buf: [256]u8 = undefined;
    const icmp_len = icmpv6.emit(icmpv6_repr, src, dst, &icmp_buf) catch unreachable;
    return buildIpv6Frame(buf, .{
        .src_addr = src,
        .dst_addr = dst,
        .next_header = .icmpv6,
        .payload_len = @intCast(icmp_len),
        .hop_limit = 255,
    }, icmp_buf[0..icmp_len]);
}

test "NS -> NA reply (with solicited flag)" {
    var iface = testV6Interface();
    const sn_dst = ipv6.solicitedNode(LOCAL_V6_LL);
    var buf: [512]u8 = undefined;
    const frame = buildNdpNsFrame(&buf, REMOTE_V6_LL, sn_dst, LOCAL_V6_LL, REMOTE_HW_ADDR);
    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;
    switch (result) {
        .ipv6 => |resp| {
            try testing.expectEqual(LOCAL_V6_LL, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_V6_LL, resp.ip.dst_addr);
            try testing.expectEqual(@as(u8, 255), resp.ip.hop_limit);
            switch (resp.payload) {
                .ndisc => |n| switch (n) {
                    .neighbor_advert => |na| {
                        try testing.expect(na.flags.solicited);
                        try testing.expect(na.flags.override_);
                        try testing.expectEqual(LOCAL_V6_LL, na.target_addr);
                        try testing.expectEqual(LOCAL_HW_ADDR, na.lladdr.?);
                    },
                    else => return error.UnexpectedNdisc,
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}

test "NS learns neighbor from LLAddr option" {
    var iface = testV6Interface();
    const sn_dst = ipv6.solicitedNode(LOCAL_V6_LL);
    var buf: [512]u8 = undefined;
    const frame = buildNdpNsFrame(&buf, REMOTE_V6_LL, sn_dst, LOCAL_V6_LL, REMOTE_HW_ADDR);
    _ = iface.processEthernet(frame);
    try testing.expect(iface.neighbor_cache_v6.hasNeighbor(REMOTE_V6_LL));
}

test "NA fills cache (override flag)" {
    var iface = testV6Interface();
    const new_mac: ethernet.Address = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const na_repr = ndisc.Repr{ .neighbor_advert = .{
        .flags = .{ .router = false, .solicited = true, .override_ = true },
        .target_addr = REMOTE_V6_LL,
        .lladdr = new_mac,
    } };
    var icmp_buf: [256]u8 = undefined;
    const icmpv6_repr = icmpv6.Repr{ .ndisc = na_repr };
    const icmp_len = icmpv6.emit(icmpv6_repr, REMOTE_V6_LL, LOCAL_V6_LL, &icmp_buf) catch unreachable;
    var buf: [512]u8 = undefined;
    const frame = buildIpv6Frame(&buf, .{
        .src_addr = REMOTE_V6_LL,
        .dst_addr = LOCAL_V6_LL,
        .next_header = .icmpv6,
        .payload_len = @intCast(icmp_len),
        .hop_limit = 255,
    }, icmp_buf[0..icmp_len]);
    _ = iface.processEthernet(frame);
    try testing.expectEqual(new_mac, iface.neighbor_cache_v6.lookup(REMOTE_V6_LL, time.Instant.ZERO).?);
}

test "NA does not overwrite without override" {
    var iface = testV6Interface();
    const old_mac: ethernet.Address = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };
    iface.neighbor_cache_v6.fill(REMOTE_V6_LL, old_mac, time.Instant.ZERO);

    const new_mac: ethernet.Address = .{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const na_repr = ndisc.Repr{ .neighbor_advert = .{
        .flags = .{ .router = false, .solicited = true, .override_ = false },
        .target_addr = REMOTE_V6_LL,
        .lladdr = new_mac,
    } };
    var icmp_buf: [256]u8 = undefined;
    const icmpv6_repr = icmpv6.Repr{ .ndisc = na_repr };
    const icmp_len = icmpv6.emit(icmpv6_repr, REMOTE_V6_LL, LOCAL_V6_LL, &icmp_buf) catch unreachable;
    var buf: [512]u8 = undefined;
    const frame = buildIpv6Frame(&buf, .{
        .src_addr = REMOTE_V6_LL,
        .dst_addr = LOCAL_V6_LL,
        .next_header = .icmpv6,
        .payload_len = @intCast(icmp_len),
        .hop_limit = 255,
    }, icmp_buf[0..icmp_len]);
    _ = iface.processEthernet(frame);
    // Old MAC should persist (no override)
    try testing.expectEqual(old_mac, iface.neighbor_cache_v6.lookup(REMOTE_V6_LL, time.Instant.ZERO).?);
}

test "NDP rejected when hop_limit != 255" {
    var iface = testV6Interface();
    const sn_dst = ipv6.solicitedNode(LOCAL_V6_LL);
    const ndisc_repr = ndisc.Repr{ .neighbor_solicit = .{
        .target_addr = LOCAL_V6_LL,
        .lladdr = REMOTE_HW_ADDR,
    } };
    var icmp_buf: [256]u8 = undefined;
    const icmpv6_repr = icmpv6.Repr{ .ndisc = ndisc_repr };
    const icmp_len = icmpv6.emit(icmpv6_repr, REMOTE_V6_LL, sn_dst, &icmp_buf) catch unreachable;
    var buf: [512]u8 = undefined;
    // hop_limit=64 instead of 255 -> must be rejected
    const frame = buildIpv6Frame(&buf, .{
        .src_addr = REMOTE_V6_LL,
        .dst_addr = sn_dst,
        .next_header = .icmpv6,
        .payload_len = @intCast(icmp_len),
        .hop_limit = 64,
    }, icmp_buf[0..icmp_len]);
    try testing.expectEqual(@as(?Response, null), iface.processEthernet(frame));
}

test "IPv6 param problem for unrecognized next header" {
    var iface = testV6Interface();
    const unknown_payload = [_]u8{0xFF} ** 8;
    var buf: [512]u8 = undefined;
    const frame = buildIpv6Frame(&buf, .{
        .src_addr = REMOTE_V6_LL,
        .dst_addr = LOCAL_V6_LL,
        .next_header = @enumFromInt(253), // experimental
        .payload_len = unknown_payload.len,
        .hop_limit = 64,
    }, &unknown_payload);
    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;
    switch (result) {
        .ipv6 => |resp| {
            try testing.expectEqual(ipv6.Protocol.icmpv6, resp.ip.protocol);
            switch (resp.payload) {
                .icmpv6_param_problem => |pp| {
                    try testing.expectEqual(icmpv6.ParamProblem.unrecognized_nxt_hdr, pp.reason);
                    try testing.expectEqual(@as(u32, 6), pp.pointer);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}

test "UDP port unreachable v6" {
    var iface = testV6Interface();
    const udp_payload = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    const ip_repr = ipv6.Repr{
        .src_addr = REMOTE_V6_LL,
        .dst_addr = LOCAL_V6_LL,
        .next_header = .udp,
        .payload_len = @intCast(udp.HEADER_LEN + udp_payload.len),
        .hop_limit = 64,
    };
    var udp_buf: [udp.HEADER_LEN + 5]u8 = undefined;
    _ = udp.emit(.{
        .src_port = 12345,
        .dst_port = 54321,
        .length = @intCast(udp.HEADER_LEN + udp_payload.len),
        .checksum = 0,
    }, &udp_buf) catch unreachable;
    @memcpy(udp_buf[udp.HEADER_LEN..], &udp_payload);

    const result = iface.processUdpV6(ip_repr, &udp_buf, false) orelse return error.ExpectedResponse;
    switch (result) {
        .ipv6 => |resp| {
            try testing.expectEqual(LOCAL_V6_LL, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_V6_LL, resp.ip.dst_addr);
            switch (resp.payload) {
                .icmpv6_dst_unreachable => |du| {
                    try testing.expectEqual(icmpv6.DstUnreachable.port_unreachable, du.reason);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
    // Handled -> no response
    try testing.expectEqual(@as(?Response, null), iface.processUdpV6(ip_repr, &udp_buf, true));
}

test "TCP RST v6" {
    var iface = testV6Interface();
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
    const ip_repr = ipv6.Repr{
        .src_addr = REMOTE_V6_LL,
        .dst_addr = LOCAL_V6_LL,
        .next_header = .tcp,
        .payload_len = tcp_wire.HEADER_LEN,
        .hop_limit = 64,
    };
    const result = iface.processTcpV6(ip_repr, &tcp_buf, false) orelse return error.ExpectedResponse;
    switch (result) {
        .ipv6 => |resp| {
            try testing.expectEqual(LOCAL_V6_LL, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_V6_LL, resp.ip.dst_addr);
            switch (resp.payload) {
                .tcp => |rst| {
                    try testing.expectEqual(tcp_wire.Control.rst, rst.control);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}

test "TCP RST suppressed for RST input v6" {
    var iface = testV6Interface();
    var rst_buf: [tcp_wire.HEADER_LEN]u8 = undefined;
    _ = tcp_wire.emit(.{
        .src_port = 4242,
        .dst_port = 4243,
        .seq_number = 0,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .rst = true },
        .window_size = 0,
        .checksum = 0,
        .urgent_pointer = 0,
    }, &rst_buf) catch unreachable;
    const ip_repr = ipv6.Repr{
        .src_addr = REMOTE_V6_LL,
        .dst_addr = LOCAL_V6_LL,
        .next_header = .tcp,
        .payload_len = tcp_wire.HEADER_LEN,
        .hop_limit = 64,
    };
    try testing.expectEqual(@as(?Response, null), iface.processTcpV6(ip_repr, &rst_buf, false));
}

test "auto_icmp_echo_reply defaults to true (v4 echo reply generated)" {
    var iface = testInterface();
    try testing.expect(iface.auto_icmp_echo_reply);

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
    const ip_repr = testIpv4Repr(.icmp, REMOTE_IP, LOCAL_IP, icmp_buf.len);
    const result = iface.processIcmp(ip_repr, &icmp_buf, false);
    try testing.expect(result != null);
}

test "auto_icmp_echo_reply disabled suppresses v4 echo reply" {
    var iface = testInterface();
    iface.auto_icmp_echo_reply = false;

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
    const ip_repr = testIpv4Repr(.icmp, REMOTE_IP, LOCAL_IP, icmp_buf.len);
    try testing.expectEqual(@as(?Response, null), iface.processIcmp(ip_repr, &icmp_buf, false));
}

test "auto_icmp_echo_reply disabled suppresses v6 echo reply" {
    var iface = testV6Interface();
    iface.auto_icmp_echo_reply = false;

    const echo_data = [_]u8{ 0xDE, 0xAD };
    var icmp_buf: [256]u8 = undefined;
    const repr = icmpv6.Repr{ .echo_request = .{
        .ident = 0x1234,
        .seq_no = 1,
        .data = &echo_data,
    } };
    const icmp_len = icmpv6.emit(repr, REMOTE_V6_LL, LOCAL_V6_LL, &icmp_buf) catch unreachable;
    const ip_repr = ipv6.Repr{
        .src_addr = REMOTE_V6_LL,
        .dst_addr = LOCAL_V6_LL,
        .next_header = .icmpv6,
        .payload_len = @intCast(icmp_len),
        .hop_limit = 64,
    };
    try testing.expectEqual(@as(?Response, null), iface.processIcmpv6(ip_repr, icmp_buf[0..icmp_len], false));
}
