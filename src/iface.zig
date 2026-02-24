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
const ipv4 = @import("wire/ipv4.zig");
const icmp = @import("wire/icmp.zig");
const udp = @import("wire/udp.zig");
const time = @import("time.zig");

pub const MAX_ADDR_COUNT = 4;
pub const DEFAULT_HOP_LIMIT: u8 = 64;
pub const IPV4_MIN_MTU: usize = 576;

const NEIGHBOR_CACHE_SIZE = 8;
const NEIGHBOR_LIFETIME = time.Duration.fromSecs(60);

// -------------------------------------------------------------------------
// IpCidr
// -------------------------------------------------------------------------

pub const IpCidr = struct {
    address: ipv4.Address,
    prefix_len: u6,

    fn addrToU32(addr: ipv4.Address) u32 {
        return @as(u32, addr[0]) << 24 | @as(u32, addr[1]) << 16 |
            @as(u32, addr[2]) << 8 | @as(u32, addr[3]);
    }

    fn u32ToAddr(val: u32) ipv4.Address {
        return .{
            @truncate(val >> 24),
            @truncate(val >> 16),
            @truncate(val >> 8),
            @truncate(val),
        };
    }

    fn hostMask(self: IpCidr) u32 {
        if (self.prefix_len >= 32) return 0;
        return (@as(u32, 1) << @intCast(32 - @as(u6, self.prefix_len))) -% 1;
    }

    pub fn networkMask(self: IpCidr) u32 {
        return ~self.hostMask();
    }

    pub fn networkAddr(self: IpCidr) ipv4.Address {
        return u32ToAddr(addrToU32(self.address) & self.networkMask());
    }

    pub fn broadcast(self: IpCidr) ?ipv4.Address {
        if (self.prefix_len >= 31) return null;
        return u32ToAddr(addrToU32(self.address) | self.hostMask());
    }

    pub fn contains(self: IpCidr, addr: ipv4.Address) bool {
        return (addrToU32(addr) & self.networkMask()) == (addrToU32(self.address) & self.networkMask());
    }
};

// -------------------------------------------------------------------------
// NeighborCache
// -------------------------------------------------------------------------

pub const NeighborCache = struct {
    const Entry = struct {
        protocol_addr: ipv4.Address = .{ 0, 0, 0, 0 },
        hardware_addr: ethernet.Address = .{ 0, 0, 0, 0, 0, 0 },
        expires_at: time.Instant = time.Instant.ZERO,
        occupied: bool = false,
    };

    entries: [NEIGHBOR_CACHE_SIZE]Entry = [_]Entry{.{}} ** NEIGHBOR_CACHE_SIZE,

    pub fn fill(self: *NeighborCache, ip: ipv4.Address, mac: ethernet.Address, now: time.Instant) void {
        const expires = now.add(NEIGHBOR_LIFETIME);
        // Update existing entry
        for (0..NEIGHBOR_CACHE_SIZE) |i| {
            if (self.entries[i].occupied and std.mem.eql(u8, &self.entries[i].protocol_addr, &ip)) {
                self.entries[i].hardware_addr = mac;
                self.entries[i].expires_at = expires;
                return;
            }
        }
        // Find empty slot
        for (0..NEIGHBOR_CACHE_SIZE) |i| {
            if (!self.entries[i].occupied) {
                self.entries[i] = .{
                    .protocol_addr = ip,
                    .hardware_addr = mac,
                    .expires_at = expires,
                    .occupied = true,
                };
                return;
            }
        }
        // Evict oldest
        var oldest_idx: usize = 0;
        for (1..NEIGHBOR_CACHE_SIZE) |i| {
            if (self.entries[i].expires_at.lessThan(self.entries[oldest_idx].expires_at)) {
                oldest_idx = i;
            }
        }
        self.entries[oldest_idx] = .{
            .protocol_addr = ip,
            .hardware_addr = mac,
            .expires_at = expires,
            .occupied = true,
        };
    }

    pub fn lookup(self: *const NeighborCache, ip: ipv4.Address, now: time.Instant) ?ethernet.Address {
        for (self.entries) |e| {
            if (e.occupied and std.mem.eql(u8, &e.protocol_addr, &ip)) {
                if (e.expires_at.greaterThanOrEqual(now)) return e.hardware_addr;
                return null;
            }
        }
        return null;
    }

    pub fn hasNeighbor(self: *const NeighborCache, ip: ipv4.Address) bool {
        for (self.entries) |e| {
            if (e.occupied and std.mem.eql(u8, &e.protocol_addr, &ip)) return true;
        }
        return false;
    }

    pub fn flush(self: *NeighborCache) void {
        self.entries = [_]Entry{.{}} ** NEIGHBOR_CACHE_SIZE;
    }
};

// -------------------------------------------------------------------------
// Response types
// -------------------------------------------------------------------------

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
};

pub const Ipv4Response = struct {
    ip: IpMeta,
    payload: IpPayload,
};

pub const Response = union(enum) {
    arp_reply: arp.Repr,
    ipv4: Ipv4Response,
};

// -------------------------------------------------------------------------
// Interface
// -------------------------------------------------------------------------

pub const Interface = struct {
    hardware_addr: ethernet.Address,
    ip_addrs: [MAX_ADDR_COUNT]IpCidr = [_]IpCidr{.{ .address = .{ 0, 0, 0, 0 }, .prefix_len = 0 }} ** MAX_ADDR_COUNT,
    ip_addr_count: usize = 0,
    neighbor_cache: NeighborCache = .{},
    now: time.Instant = time.Instant.ZERO,

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
        const GLOBAL_BROADCAST: ipv4.Address = .{ 255, 255, 255, 255 };
        if (std.mem.eql(u8, &addr, &GLOBAL_BROADCAST)) return true;
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

    // -----------------------------------------------------------------
    // Ingress pipeline
    // -----------------------------------------------------------------

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
        if (!self.hasIpAddr(repr.target_protocol_addr)) return null;

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
            .udp => return null, // caller handles via processUdp
            .tcp => return null, // caller handles
            _ => {
                if (is_broadcast) return null; // RFC 1122: no ICMP for broadcast
                return self.icmpProtoUnreachable(ip_repr, ip_payload);
            },
        }
    }

    fn processIcmp(self: *const Interface, ip_repr: ipv4.Repr, payload_data: []const u8, is_broadcast: bool) ?Response {
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

    fn icmpProtoUnreachable(self: *const Interface, ip_repr: ipv4.Repr, ip_payload: []const u8) ?Response {
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
        // Clamp ICMP error data to fit within IPV4_MIN_MTU
        const max_data_len = IPV4_MIN_MTU - ipv4.HEADER_LEN - icmp.HEADER_LEN - ipv4.HEADER_LEN;
        const data = udp_data[0..@min(udp_data.len, max_data_len)];
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
};

// =========================================================================
// Tests
// =========================================================================

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

// -----------------------------------------------------------------
// Test 1: local subnet broadcasts
// [smoltcp:iface/interface/tests/ipv4.rs:test_local_subnet_broadcasts]
// -----------------------------------------------------------------

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

// -----------------------------------------------------------------
// Test 2: get source address
// [smoltcp:iface/interface/tests/ipv4.rs:get_source_address]
// -----------------------------------------------------------------

test "get source address" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.setIpAddrs(&.{
        .{ .address = .{ 172, 18, 1, 2 }, .prefix_len = 24 },
        .{ .address = .{ 172, 24, 24, 14 }, .prefix_len = 24 },
    });

    // 172.18.1.254 in subnet 172.18.1.0/24 -> pick 172.18.1.2
    try testing.expectEqual(
        @as(?ipv4.Address, .{ 172, 18, 1, 2 }),
        iface.getSourceAddress(.{ 172, 18, 1, 254 }),
    );
    // 172.24.24.12 in subnet 172.24.24.0/24 -> pick 172.24.24.14
    try testing.expectEqual(
        @as(?ipv4.Address, .{ 172, 24, 24, 14 }),
        iface.getSourceAddress(.{ 172, 24, 24, 12 }),
    );
    // 172.24.23.254 in neither subnet -> fall back to first
    try testing.expectEqual(
        @as(?ipv4.Address, .{ 172, 18, 1, 2 }),
        iface.getSourceAddress(.{ 172, 24, 23, 254 }),
    );
}

// -----------------------------------------------------------------
// Test 3: get source address empty interface
// [smoltcp:iface/interface/tests/ipv4.rs:get_source_address_empty_interface]
// -----------------------------------------------------------------

test "get source address empty interface" {
    var iface = Interface.init(LOCAL_HW_ADDR);
    iface.ip_addr_count = 0;

    try testing.expectEqual(@as(?ipv4.Address, null), iface.getSourceAddress(.{ 172, 18, 1, 254 }));
    try testing.expectEqual(@as(?ipv4.Address, null), iface.getSourceAddress(.{ 172, 24, 24, 12 }));
    try testing.expectEqual(@as(?ipv4.Address, null), iface.getSourceAddress(.{ 172, 24, 23, 254 }));
}

// -----------------------------------------------------------------
// Test 4: handle valid ARP request
// [smoltcp:iface/interface/tests/ipv4.rs:test_handle_valid_arp_request]
// -----------------------------------------------------------------

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

    // Requester should be in neighbor cache
    try testing.expect(iface.neighbor_cache.hasNeighbor(REMOTE_IP));
}

// -----------------------------------------------------------------
// Test 5: handle ARP request for wrong IP
// [smoltcp:iface/interface/tests/ipv4.rs:test_handle_other_arp_request]
// -----------------------------------------------------------------

test "handle other ARP request" {
    var iface = testInterface();

    var buf: [128]u8 = undefined;
    const frame = buildArpFrame(&buf, .{
        .operation = .request,
        .source_hardware_addr = REMOTE_HW_ADDR,
        .source_protocol_addr = REMOTE_IP,
        .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 },
        .target_protocol_addr = .{ 127, 0, 0, 3 }, // not our IP
    });

    const result = iface.processEthernet(frame);
    try testing.expectEqual(@as(?Response, null), result);

    // Requester should NOT be in neighbor cache
    try testing.expect(!iface.neighbor_cache.hasNeighbor(REMOTE_IP));
}

// -----------------------------------------------------------------
// Test 6: ARP flush after IP update
// [smoltcp:iface/interface/tests/ipv4.rs:test_arp_flush_after_update_ip]
// -----------------------------------------------------------------

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

    // Process ARP -> fills cache
    const result = iface.processEthernet(frame);
    try testing.expect(result != null);
    try testing.expect(iface.neighbor_cache.hasNeighbor(REMOTE_IP));

    // Update IP addresses -> cache flushed
    iface.setIpAddrs(&.{
        .{ .address = .{ 127, 0, 0, 1 }, .prefix_len = 24 },
    });
    try testing.expect(!iface.neighbor_cache.hasNeighbor(REMOTE_IP));
}

// -----------------------------------------------------------------
// Test 7: handle IPv4 broadcast (ICMP echo to broadcast -> reply)
// [smoltcp:iface/interface/tests/ipv4.rs:test_handle_ipv4_broadcast]
// -----------------------------------------------------------------

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

    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + icmp_buf.len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .icmp,
        .checksum = 0,
        .src_addr = REMOTE_IP,
        .dst_addr = .{ 255, 255, 255, 255 }, // global broadcast
    };

    var frame_buf: [256]u8 = undefined;
    const frame = buildIpv4Frame(&frame_buf, ip_repr, &icmp_buf);

    const result = iface.processEthernet(frame) orelse return error.ExpectedResponse;

    switch (result) {
        .ipv4 => |resp| {
            // Reply src should be our first configured address (192.168.1.1)
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

// -----------------------------------------------------------------
// Test 8: no ICMP for unknown protocol to broadcast
// [smoltcp:iface/interface/tests/ipv4.rs:test_no_icmp_no_unicast]
// -----------------------------------------------------------------

test "no ICMP for unknown protocol to broadcast" {
    var iface = testInterface();

    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = @enumFromInt(0x0C), // unknown protocol
        .checksum = 0,
        .src_addr = LOCAL_IP,
        .dst_addr = .{ 255, 255, 255, 255 },
    };

    var frame_buf: [128]u8 = undefined;
    const frame = buildIpv4Frame(&frame_buf, ip_repr, &.{});

    const result = iface.processEthernet(frame);
    try testing.expectEqual(@as(?Response, null), result);
}

// -----------------------------------------------------------------
// Test 9: ICMP protocol unreachable for unknown protocol to unicast
// [smoltcp:iface/interface/tests/ipv4.rs:test_icmp_error_no_payload]
// -----------------------------------------------------------------

test "ICMP error no payload" {
    var iface = testInterface();

    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = @enumFromInt(0x0C), // unknown protocol
        .checksum = 0,
        .src_addr = REMOTE_IP,
        .dst_addr = LOCAL_IP, // unicast to us
    };

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
                    try testing.expectEqual(@as(u8, 2), du.code); // protocol unreachable
                    try testing.expectEqual(@as(usize, 0), du.data.len);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}

// -----------------------------------------------------------------
// Test 10: ICMP port unreachable for UDP to closed port
// [smoltcp:iface/interface/tests/ipv4.rs:test_icmp_error_port_unreachable]
// -----------------------------------------------------------------

test "ICMP error port unreachable" {
    var iface = testInterface();

    // Build UDP packet bytes (src_port=67, dst_port=68, "Hello, Wold!")
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

    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + udp_buf.len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .udp,
        .checksum = 0,
        .src_addr = REMOTE_IP,
        .dst_addr = LOCAL_IP,
    };

    // Case 1: unicast -> ICMP port unreachable
    const result = iface.processUdp(ip_repr, &udp_buf, false) orelse return error.ExpectedResponse;
    switch (result) {
        .ipv4 => |resp| {
            try testing.expectEqual(LOCAL_IP, resp.ip.src_addr);
            try testing.expectEqual(REMOTE_IP, resp.ip.dst_addr);
            switch (resp.payload) {
                .icmp_dest_unreachable => |du| {
                    try testing.expectEqual(@as(u8, 3), du.code); // port unreachable
                    try testing.expectEqualSlices(u8, &udp_buf, du.data);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }

    // Case 2: broadcast -> no ICMP
    const bcast_ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + udp_buf.len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .udp,
        .checksum = 0,
        .src_addr = REMOTE_IP,
        .dst_addr = .{ 255, 255, 255, 255 },
    };
    const bcast_result = iface.processUdp(bcast_ip_repr, &udp_buf, false);
    try testing.expectEqual(@as(?Response, null), bcast_result);
}

// -----------------------------------------------------------------
// Test 11: UDP broadcast delivered to bound socket
// [smoltcp:iface/interface/tests/mod.rs:test_handle_udp_broadcast]
// -----------------------------------------------------------------

test "handle UDP broadcast" {
    const UdpSocket = @import("socket/udp.zig").Socket(.{ .payload_size = 64 });
    const UdpRepr = @import("socket/udp.zig").UdpRepr;

    var iface = testInterface();

    var rx_buf: [1]UdpSocket.Packet = undefined;
    var tx_buf: [1]UdpSocket.Packet = undefined;
    var sock = UdpSocket.init(&rx_buf, &tx_buf);
    try sock.bind(.{ .port = 68 });

    try testing.expect(!sock.canRecv());
    try testing.expect(sock.canSend());

    const udp_payload = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f }; // "Hello"

    const udp_repr_sock = UdpRepr{ .src_port = 67, .dst_port = 68 };
    const ip_src: ipv4.Address = .{ 127, 0, 0, 2 };
    const ip_dst: ipv4.Address = .{ 255, 255, 255, 255 };

    // Socket accepts this packet
    try testing.expect(sock.accepts(ip_src, ip_dst, udp_repr_sock));
    sock.process(ip_src, ip_dst, udp_repr_sock, &udp_payload);

    // iface.processUdp should return null (socket handled it)
    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + udp.HEADER_LEN + udp_payload.len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .udp,
        .checksum = 0,
        .src_addr = ip_src,
        .dst_addr = ip_dst,
    };

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

    // Socket should have received the payload
    try testing.expect(sock.canRecv());
    var recv_buf: [64]u8 = undefined;
    const recv_result = try sock.recvSlice(&recv_buf);
    try testing.expectEqualSlices(u8, &udp_payload, recv_buf[0..recv_result.data_len]);
}

// -----------------------------------------------------------------
// Test 12: ICMP reply size clamped to IPV4_MIN_MTU
// [smoltcp:iface/interface/tests/ipv4.rs:test_icmp_reply_size]
// -----------------------------------------------------------------

test "ICMP reply size" {
    var iface = testInterface();

    const max_data_len: usize = IPV4_MIN_MTU - ipv4.HEADER_LEN - icmp.HEADER_LEN - ipv4.HEADER_LEN;
    // max_data_len = 576 - 20 - 8 - 20 = 528

    // Build a large UDP payload that would exceed MIN_MTU in the ICMP error
    var large_udp_buf: [udp.HEADER_LEN + max_data_len]u8 = undefined;
    const udp_wire = udp.Repr{
        .src_port = 67,
        .dst_port = 68,
        .length = @intCast(large_udp_buf.len),
        .checksum = 0,
    };
    _ = udp.emit(udp_wire, &large_udp_buf) catch unreachable;
    @memset(large_udp_buf[udp.HEADER_LEN..], 0x2A);

    const ip_repr = ipv4.Repr{
        .version = 4,
        .ihl = 5,
        .dscp_ecn = 0,
        .total_length = @intCast(ipv4.HEADER_LEN + large_udp_buf.len),
        .identification = 0,
        .dont_fragment = false,
        .more_fragments = false,
        .fragment_offset = 0,
        .ttl = 64,
        .protocol = .udp,
        .checksum = 0,
        .src_addr = .{ 192, 168, 1, 1 },
        .dst_addr = .{ 192, 168, 1, 2 },
    };

    const result = iface.processUdp(ip_repr, &large_udp_buf, false) orelse return error.ExpectedResponse;

    switch (result) {
        .ipv4 => |resp| {
            switch (resp.payload) {
                .icmp_dest_unreachable => |du| {
                    try testing.expectEqual(@as(u8, 3), du.code); // port unreachable
                    // The data should be clamped to max_data_len
                    try testing.expectEqual(max_data_len, du.data.len);
                    // Verify: IP header + ICMP header + invoking IP header + data = MIN_MTU
                    const total = ipv4.HEADER_LEN + icmp.HEADER_LEN + ipv4.HEADER_LEN + du.data.len;
                    try testing.expectEqual(IPV4_MIN_MTU, total);
                },
                else => return error.UnexpectedPayload,
            }
        },
        else => return error.UnexpectedResponseType,
    }
}
