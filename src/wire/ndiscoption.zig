// NDP option parsing and serialization.
//
// Reference: RFC 4861 S4.6, smoltcp src/wire/ndiscoption.rs
//
// NDP options use 8-byte-unit length encoding. The length field counts
// the type and length bytes, so total_bytes = length * 8.

const ipv6 = @import("ipv6.zig");
const ethernet = @import("ethernet.zig");
const checksum = @import("checksum.zig");

const readU32 = checksum.readU32;
const writeU32 = checksum.writeU32;

pub const Type = enum(u8) {
    source_link_layer_addr = 1,
    target_link_layer_addr = 2,
    prefix_information = 3,
    redirected_header = 4,
    mtu = 5,
    _,
};

pub const PrefixInfoFlags = struct {
    on_link: bool,
    addrconf: bool,
};

pub const PrefixInformation = struct {
    prefix_len: u8,
    flags: PrefixInfoFlags,
    valid_lifetime: u32,
    preferred_lifetime: u32,
    prefix: ipv6.Address,
};

pub const Repr = union(enum) {
    source_link_layer_addr: ethernet.Address,
    target_link_layer_addr: ethernet.Address,
    prefix_information: PrefixInformation,
    mtu: u32,
    unknown: struct {
        option_type: u8,
        length: u8,
        data: []const u8,
    },
};

pub fn bufferLen(repr: Repr) usize {
    return switch (repr) {
        .source_link_layer_addr, .target_link_layer_addr => 8,
        .prefix_information => 32,
        .mtu => 8,
        .unknown => |u| @as(usize, u.length) * 8,
    };
}

/// Total byte length of an NDP option at the start of data.
pub fn optionLen(data: []const u8) error{ Truncated, BadLength }!usize {
    if (data.len < 2) return error.Truncated;
    if (data[1] == 0) return error.BadLength;
    const total: usize = @as(usize, data[1]) * 8;
    if (data.len < total) return error.Truncated;
    return total;
}

pub fn parse(data: []const u8) error{ Truncated, BadLength }!Repr {
    if (data.len < 2) return error.Truncated;
    if (data[1] == 0) return error.BadLength;

    const opt_type: Type = @enumFromInt(data[0]);
    const length = data[1];
    const total: usize = @as(usize, length) * 8;
    if (data.len < total) return error.Truncated;

    switch (opt_type) {
        .source_link_layer_addr, .target_link_layer_addr => {
            if (total < 2 + ethernet.ADDR_LEN) return error.Truncated;
            const addr = data[2..8].*;
            if (opt_type == .source_link_layer_addr)
                return .{ .source_link_layer_addr = addr }
            else
                return .{ .target_link_layer_addr = addr };
        },
        .prefix_information => {
            if (length != 4) return error.BadLength;
            const flag_byte = data[3];
            return .{ .prefix_information = .{
                .prefix_len = data[2],
                .flags = .{
                    .on_link = (flag_byte & 0x80) != 0,
                    .addrconf = (flag_byte & 0x40) != 0,
                },
                .valid_lifetime = readU32(data[4..8]),
                .preferred_lifetime = readU32(data[8..12]),
                .prefix = data[16..32].*,
            } };
        },
        .mtu => {
            if (length != 1) return error.BadLength;
            return .{ .mtu = readU32(data[4..8]) };
        },
        else => {
            return .{ .unknown = .{
                .option_type = data[0],
                .length = length,
                .data = data[2..total],
            } };
        },
    }
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const len = bufferLen(repr);
    if (buf.len < len) return error.BufferTooSmall;

    switch (repr) {
        .source_link_layer_addr, .target_link_layer_addr => |addr| {
            buf[0] = switch (repr) {
                .source_link_layer_addr => @intFromEnum(Type.source_link_layer_addr),
                .target_link_layer_addr => @intFromEnum(Type.target_link_layer_addr),
                else => unreachable,
            };
            buf[1] = 1;
            @memcpy(buf[2..8], &addr);
        },
        .prefix_information => |pi| {
            buf[0] = @intFromEnum(Type.prefix_information);
            buf[1] = 4;
            buf[2] = pi.prefix_len;
            var flags: u8 = 0;
            if (pi.flags.on_link) flags |= 0x80;
            if (pi.flags.addrconf) flags |= 0x40;
            buf[3] = flags;
            writeU32(buf[4..8], pi.valid_lifetime);
            writeU32(buf[8..12], pi.preferred_lifetime);
            @memset(buf[12..16], 0); // reserved
            @memcpy(buf[16..32], &pi.prefix);
        },
        .mtu => |val| {
            buf[0] = @intFromEnum(Type.mtu);
            buf[1] = 1;
            buf[2] = 0; // reserved
            buf[3] = 0;
            writeU32(buf[4..8], val);
        },
        .unknown => |u| {
            buf[0] = u.option_type;
            buf[1] = u.length;
            @memcpy(buf[2 .. 2 + u.data.len], u.data);
        },
    }
    return len;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ndiscoption.rs:test_parse_source_lladdr]
test "parse source link-layer address" {
    const data = [_]u8{ 0x01, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34 };
    const repr = try parse(&data);
    try testing.expectEqual(ethernet.Address{ 0x54, 0x52, 0x00, 0x12, 0x23, 0x34 }, repr.source_link_layer_addr);
    try testing.expectEqual(@as(usize, 8), bufferLen(repr));
}

test "parse target link-layer address" {
    const data = [_]u8{ 0x02, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34 };
    const repr = try parse(&data);
    try testing.expectEqual(ethernet.Address{ 0x54, 0x52, 0x00, 0x12, 0x23, 0x34 }, repr.target_link_layer_addr);
}

// [smoltcp:wire/ndiscoption.rs:test_parse_prefix_info]
test "parse prefix information" {
    const data = [_]u8{
        0x03, 0x04, // type=PrefixInfo, length=4 (32 bytes)
        0x40, // prefix_len=64
        0xC0, // flags=ON_LINK|ADDRCONF
        0x00, 0x00, 0x03, 0x84, // valid_lifetime=900
        0x00, 0x00, 0x03, 0xE8, // preferred_lifetime=1000
        0x00, 0x00, 0x00, 0x00, // reserved
        // prefix = fe80::1
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const repr = try parse(&data);
    const pi = repr.prefix_information;
    try testing.expectEqual(@as(u8, 64), pi.prefix_len);
    try testing.expect(pi.flags.on_link);
    try testing.expect(pi.flags.addrconf);
    try testing.expectEqual(@as(u32, 900), pi.valid_lifetime);
    try testing.expectEqual(@as(u32, 1000), pi.preferred_lifetime);
    const expected_prefix = ipv6.Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expectEqual(expected_prefix, pi.prefix);
    try testing.expectEqual(@as(usize, 32), bufferLen(repr));
}

// [smoltcp:wire/ndiscoption.rs:test_parse_mtu]
test "parse MTU option" {
    const data = [_]u8{ 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xDC };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u32, 1500), repr.mtu);
    try testing.expectEqual(@as(usize, 8), bufferLen(repr));
}

test "parse unknown option" {
    const data = [_]u8{ 0xFF, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u8, 0xFF), repr.unknown.option_type);
    try testing.expectEqual(@as(u8, 1), repr.unknown.length);
}

test "parse length zero is error" {
    const data = [_]u8{ 0x01, 0x00 };
    try testing.expectError(error.BadLength, parse(&data));
}

test "optionLen basic" {
    const data = [_]u8{ 0x01, 0x01, 0x54, 0x52, 0x00, 0x12, 0x23, 0x34 };
    try testing.expectEqual(@as(usize, 8), try optionLen(&data));
}

// [smoltcp:wire/ndiscoption.rs:test_construct_prefix_info]
test "prefix information roundtrip" {
    const original = [_]u8{
        0x03, 0x04, 0x40, 0xC0,
        0x00, 0x00, 0x03, 0x84,
        0x00, 0x00, 0x03, 0xE8,
        0x00, 0x00, 0x00, 0x00,
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const repr = try parse(&original);
    var buf: [32]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqualSlices(u8, &original, &buf);
}
