// Neighbor Discovery Protocol (NDP) parsing and serialization.
//
// Reference: RFC 4861, smoltcp src/wire/ndisc.rs
//
// NDP messages are carried inside ICMPv6. The data parameter starts at
// byte 4 of the ICMPv6 message (after type+code+checksum).

const ipv6 = @import("ipv6.zig");
const ethernet = @import("ethernet.zig");
const ndiscoption = @import("ndiscoption.zig");
const checksum = @import("checksum.zig");

const readU16 = checksum.readU16;
const readU32 = checksum.readU32;
const writeU16 = checksum.writeU16;
const writeU32 = checksum.writeU32;

pub const ROUTER_SOLICIT: u8 = 0x85;
pub const ROUTER_ADVERT: u8 = 0x86;
pub const NEIGHBOR_SOLICIT: u8 = 0x87;
pub const NEIGHBOR_ADVERT: u8 = 0x88;
pub const REDIRECT: u8 = 0x89;

pub const RouterFlags = struct {
    managed: bool,
    other: bool,
};

pub const NeighborFlags = struct {
    router: bool,
    solicited: bool,
    override_: bool,
};

pub const Repr = union(enum) {
    router_solicit: struct {
        lladdr: ?ethernet.Address,
    },
    router_advert: struct {
        hop_limit: u8,
        flags: RouterFlags,
        router_lifetime: u16,
        reachable_time: u32,
        retrans_time: u32,
        lladdr: ?ethernet.Address,
        mtu: ?u32,
        prefix_info: ?ndiscoption.PrefixInformation,
    },
    neighbor_solicit: struct {
        target_addr: ipv6.Address,
        lladdr: ?ethernet.Address,
    },
    neighbor_advert: struct {
        flags: NeighborFlags,
        target_addr: ipv6.Address,
        lladdr: ?ethernet.Address,
    },
    redirect: struct {
        target_addr: ipv6.Address,
        dest_addr: ipv6.Address,
        lladdr: ?ethernet.Address,
    },
};

pub fn bufferLen(repr: Repr) usize {
    var len: usize = switch (repr) {
        .router_solicit => 4, // reserved(4)
        .router_advert => 12, // hop(1)+flags(1)+lifetime(2)+reachable(4)+retrans(4)
        .neighbor_solicit => 20, // reserved(4) + target(16)
        .neighbor_advert => 20, // flags(4) + target(16)
        .redirect => 36, // reserved(4) + target(16) + dest(16)
    };
    // Options
    switch (repr) {
        .router_solicit => |rs| {
            if (rs.lladdr != null) len += 8;
        },
        .router_advert => |ra| {
            if (ra.lladdr != null) len += 8;
            if (ra.mtu != null) len += 8;
            if (ra.prefix_info != null) len += 32;
        },
        .neighbor_solicit => |ns| {
            if (ns.lladdr != null) len += 8;
        },
        .neighbor_advert => |na| {
            if (na.lladdr != null) len += 8;
        },
        .redirect => |rd| {
            if (rd.lladdr != null) len += 8;
        },
    }
    return len;
}

/// Parse NDP message body. msg_type is the ICMPv6 type byte, data starts
/// at byte 4 of the ICMPv6 message.
pub fn parse(msg_type: u8, data: []const u8) error{ Truncated, BadLength, Unrecognized }!Repr {
    switch (msg_type) {
        ROUTER_SOLICIT => {
            if (data.len < 4) return error.Truncated;
            var lladdr: ?ethernet.Address = null;
            try parseOptions(data[4..], &lladdr, null, null, null);
            return .{ .router_solicit = .{ .lladdr = lladdr } };
        },
        ROUTER_ADVERT => {
            if (data.len < 12) return error.Truncated;
            const flag_byte = data[1];
            var lladdr: ?ethernet.Address = null;
            var mtu_val: ?u32 = null;
            var prefix_info: ?ndiscoption.PrefixInformation = null;
            try parseOptions(data[12..], &lladdr, &mtu_val, &prefix_info, null);
            return .{ .router_advert = .{
                .hop_limit = data[0],
                .flags = .{
                    .managed = (flag_byte & 0x80) != 0,
                    .other = (flag_byte & 0x40) != 0,
                },
                .router_lifetime = readU16(data[2..4]),
                .reachable_time = readU32(data[4..8]),
                .retrans_time = readU32(data[8..12]),
                .lladdr = lladdr,
                .mtu = mtu_val,
                .prefix_info = prefix_info,
            } };
        },
        NEIGHBOR_SOLICIT => {
            if (data.len < 20) return error.Truncated;
            var lladdr: ?ethernet.Address = null;
            try parseOptions(data[20..], &lladdr, null, null, null);
            return .{ .neighbor_solicit = .{
                .target_addr = data[4..20].*,
                .lladdr = lladdr,
            } };
        },
        NEIGHBOR_ADVERT => {
            if (data.len < 20) return error.Truncated;
            const flag_byte = data[0];
            var lladdr: ?ethernet.Address = null;
            try parseOptions(data[20..], null, null, null, &lladdr);
            return .{ .neighbor_advert = .{
                .flags = .{
                    .router = (flag_byte & 0x80) != 0,
                    .solicited = (flag_byte & 0x40) != 0,
                    .override_ = (flag_byte & 0x20) != 0,
                },
                .target_addr = data[4..20].*,
                .lladdr = lladdr,
            } };
        },
        REDIRECT => {
            if (data.len < 36) return error.Truncated;
            var lladdr: ?ethernet.Address = null;
            try parseOptions(data[36..], &lladdr, null, null, null);
            return .{ .redirect = .{
                .target_addr = data[4..20].*,
                .dest_addr = data[20..36].*,
                .lladdr = lladdr,
            } };
        },
        else => return error.Unrecognized,
    }
}

fn parseOptions(
    options_data: []const u8,
    src_lladdr: ?*?ethernet.Address,
    mtu_out: ?*?u32,
    prefix_out: ?*?ndiscoption.PrefixInformation,
    target_lladdr: ?*?ethernet.Address,
) error{ Truncated, BadLength }!void {
    var offset: usize = 0;
    while (offset < options_data.len) {
        const remaining = options_data[offset..];
        const opt_len = ndiscoption.optionLen(remaining) catch |err| switch (err) {
            error.Truncated => break,
            error.BadLength => return error.BadLength,
        };
        if (ndiscoption.parse(remaining)) |opt| {
            switch (opt) {
                .source_link_layer_addr => |addr| {
                    if (src_lladdr) |out| out.* = addr;
                },
                .target_link_layer_addr => |addr| {
                    if (target_lladdr) |out| out.* = addr;
                },
                .mtu => |val| {
                    if (mtu_out) |out| out.* = val;
                },
                .prefix_information => |pi| {
                    if (prefix_out) |out| out.* = pi;
                },
                .unknown => {},
            }
        } else |_| {}
        offset += opt_len;
    }
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const len = bufferLen(repr);
    if (buf.len < len) return error.BufferTooSmall;

    switch (repr) {
        .router_solicit => |rs| {
            @memset(buf[0..4], 0); // reserved
            if (rs.lladdr) |addr| {
                _ = try ndiscoption.emit(.{ .source_link_layer_addr = addr }, buf[4..]);
            }
        },
        .router_advert => |ra| {
            buf[0] = ra.hop_limit;
            var flags: u8 = 0;
            if (ra.flags.managed) flags |= 0x80;
            if (ra.flags.other) flags |= 0x40;
            buf[1] = flags;
            writeU16(buf[2..4], ra.router_lifetime);
            writeU32(buf[4..8], ra.reachable_time);
            writeU32(buf[8..12], ra.retrans_time);
            var pos: usize = 12;
            if (ra.lladdr) |addr| {
                pos += try ndiscoption.emit(.{ .source_link_layer_addr = addr }, buf[pos..]);
            }
            if (ra.mtu) |val| {
                pos += try ndiscoption.emit(.{ .mtu = val }, buf[pos..]);
            }
            if (ra.prefix_info) |pi| {
                pos += try ndiscoption.emit(.{ .prefix_information = pi }, buf[pos..]);
            }
        },
        .neighbor_solicit => |ns| {
            @memset(buf[0..4], 0); // reserved
            @memcpy(buf[4..20], &ns.target_addr);
            if (ns.lladdr) |addr| {
                _ = try ndiscoption.emit(.{ .source_link_layer_addr = addr }, buf[20..]);
            }
        },
        .neighbor_advert => |na| {
            var flags: u8 = 0;
            if (na.flags.router) flags |= 0x80;
            if (na.flags.solicited) flags |= 0x40;
            if (na.flags.override_) flags |= 0x20;
            buf[0] = flags;
            @memset(buf[1..4], 0); // reserved
            @memcpy(buf[4..20], &na.target_addr);
            if (na.lladdr) |addr| {
                _ = try ndiscoption.emit(.{ .target_link_layer_addr = addr }, buf[20..]);
            }
        },
        .redirect => |rd| {
            @memset(buf[0..4], 0); // reserved
            @memcpy(buf[4..20], &rd.target_addr);
            @memcpy(buf[20..36], &rd.dest_addr);
            if (rd.lladdr) |addr| {
                _ = try ndiscoption.emit(.{ .source_link_layer_addr = addr }, buf[36..]);
            }
        },
    }
    return len;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ndisc.rs:test_router_advert_parse]
test "parse router advertisement" {
    // Body after ICMPv6 type+code+checksum: hop_limit=64, flags=MANAGED,
    // router_lifetime=900, reachable=900ms, retrans=900ms + source lladdr option
    const data = [_]u8{
        0x40, // cur_hop_limit=64
        0x80, // flags=MANAGED
        0x03, 0x84, // router_lifetime=900
        0x00, 0x00, 0x03, 0x84, // reachable_time=900
        0x00, 0x00, 0x03, 0x84, // retrans_time=900
        // SourceLinkLayerAddr option:
        0x01, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
    };
    const repr = try parse(ROUTER_ADVERT, &data);
    const ra = repr.router_advert;
    try testing.expectEqual(@as(u8, 64), ra.hop_limit);
    try testing.expect(ra.flags.managed);
    try testing.expect(!ra.flags.other);
    try testing.expectEqual(@as(u16, 900), ra.router_lifetime);
    try testing.expectEqual(@as(u32, 900), ra.reachable_time);
    try testing.expectEqual(@as(u32, 900), ra.retrans_time);
    try testing.expectEqual(ethernet.Address{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 }, ra.lladdr.?);
}

test "parse neighbor solicit" {
    const data = [_]u8{
        0x00, 0x00, 0x00, 0x00, // reserved
        // target = fe80::1
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const repr = try parse(NEIGHBOR_SOLICIT, &data);
    const ns = repr.neighbor_solicit;
    const expected = ipv6.Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectEqual(expected, ns.target_addr);
    try testing.expect(ns.lladdr == null);
}

test "router advertisement roundtrip" {
    const original = [_]u8{
        0x40, 0x80, 0x03, 0x84,
        0x00, 0x00, 0x03, 0x84,
        0x00, 0x00, 0x03, 0x84,
        0x01, 0x01, 0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
    };
    const repr = try parse(ROUTER_ADVERT, &original);
    var buf: [20]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqualSlices(u8, &original, &buf);
}

test "parse unrecognized NDP type" {
    try testing.expectError(error.Unrecognized, parse(0x01, &[_]u8{ 0, 0, 0, 0 }));
}
