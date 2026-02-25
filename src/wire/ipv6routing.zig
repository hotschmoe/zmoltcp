// IPv6 routing header parsing and serialization.
//
// Reference: RFC 6554 (RPL), RFC 6275 (Type 2), smoltcp src/wire/ipv6routing.rs
//
// Data starts at byte 0 of the routing-specific payload (after the
// generic extension header's next_header + length bytes).

const ipv6 = @import("ipv6.zig");

pub const RoutingType = enum(u8) {
    type2 = 2,
    rpl = 3,
    _,
};

pub const Repr = union(enum) {
    type2: struct {
        segments_left: u8,
        home_address: ipv6.Address,
    },
    rpl: struct {
        segments_left: u8,
        cmpr_i: u8,
        cmpr_e: u8,
        pad: u8,
        addresses: []const u8,
    },
};

pub fn bufferLen(repr: Repr) usize {
    return switch (repr) {
        .type2 => 22, // type(1) + seg(1) + reserved(4) + addr(16)
        .rpl => |r| 6 + r.addresses.len, // type(1) + seg(1) + cmpr(1) + pad(1) + reserved(2) + addrs
    };
}

pub fn parse(data: []const u8) error{ Truncated, Unrecognized }!Repr {
    if (data.len < 2) return error.Truncated;

    const routing_type: RoutingType = @enumFromInt(data[0]);
    const segments_left = data[1];

    switch (routing_type) {
        .type2 => {
            if (data.len < 22) return error.Truncated;
            return .{ .type2 = .{
                .segments_left = segments_left,
                .home_address = data[6..22].*,
            } };
        },
        .rpl => {
            if (data.len < 6) return error.Truncated;
            return .{ .rpl = .{
                .segments_left = segments_left,
                .cmpr_i = data[2] >> 4,
                .cmpr_e = data[2] & 0x0F,
                .pad = data[3] >> 4,
                .addresses = data[6..],
            } };
        },
        _ => return error.Unrecognized,
    }
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const len = bufferLen(repr);
    if (buf.len < len) return error.BufferTooSmall;

    switch (repr) {
        .type2 => |t| {
            buf[0] = @intFromEnum(RoutingType.type2);
            buf[1] = t.segments_left;
            @memset(buf[2..6], 0); // reserved
            @memcpy(buf[6..22], &t.home_address);
        },
        .rpl => |r| {
            buf[0] = @intFromEnum(RoutingType.rpl);
            buf[1] = r.segments_left;
            buf[2] = (r.cmpr_i << 4) | (r.cmpr_e & 0x0F);
            buf[3] = r.pad << 4;
            @memset(buf[4..6], 0); // reserved
            @memcpy(buf[6 .. 6 + r.addresses.len], r.addresses);
        },
    }
    return len;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ipv6routing.rs:test_deconstruct_type2]
test "parse Type2 routing header" {
    const data = [_]u8{
        0x02, 0x01, // type=2, seg=1
        0x00, 0x00, 0x00, 0x00, // reserved
        // home addr = ::1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u8, 1), repr.type2.segments_left);
    try testing.expectEqual(ipv6.LOOPBACK, repr.type2.home_address);
}

// [smoltcp:wire/ipv6routing.rs:test_construct_type2]
test "Type2 roundtrip" {
    const original = [_]u8{
        0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const repr = try parse(&original);
    var buf: [22]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqualSlices(u8, &original, &buf);
}

// [smoltcp:wire/ipv6routing.rs:test_deconstruct_rpl_elided]
test "parse RPL elided" {
    const data = [_]u8{
        0x03, 0x02, // type=3, seg=2
        0xFE, 0x50, // cmpr_i=15, cmpr_e=14, pad=5
        0x00, 0x00, // reserved
        0x02, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u8, 2), repr.rpl.segments_left);
    try testing.expectEqual(@as(u8, 15), repr.rpl.cmpr_i);
    try testing.expectEqual(@as(u8, 14), repr.rpl.cmpr_e);
    try testing.expectEqual(@as(u8, 5), repr.rpl.pad);
    try testing.expectEqual(@as(usize, 8), repr.rpl.addresses.len);
}

test "unrecognized routing type" {
    const data = [_]u8{ 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    try testing.expectError(error.Unrecognized, parse(&data));
}
