// IGMPv1/v2 wire format: parse, emit, repr.
//
// 8-byte message: type(1) + max_resp_time(1) + checksum(2) + group_addr(4)
//
// [smoltcp:wire/igmp.rs]

const std = @import("std");
const ipv4 = @import("ipv4.zig");
const checksum_mod = @import("checksum.zig");

pub const HEADER_LEN: usize = 8;

pub const IPV4_MULTICAST_ALL_SYSTEMS: ipv4.Address = .{ 224, 0, 0, 1 };
pub const IPV4_MULTICAST_ALL_ROUTERS: ipv4.Address = .{ 224, 0, 0, 2 };

pub const IgmpVersion = enum { v1, v2 };

pub const MessageType = enum(u8) {
    membership_query = 0x11,
    membership_report_v1 = 0x12,
    membership_report_v2 = 0x16,
    leave_group = 0x17,
    _,
};

// -------------------------------------------------------------------------
// Repr
// -------------------------------------------------------------------------

pub const Repr = union(enum) {
    membership_query: struct {
        max_resp_time: u8,
        group_addr: ipv4.Address,
        version: IgmpVersion,
    },
    membership_report: struct {
        group_addr: ipv4.Address,
        version: IgmpVersion,
    },
    leave_group: struct {
        group_addr: ipv4.Address,
    },
};

fn groupAddr(repr: Repr) ipv4.Address {
    return switch (repr) {
        .membership_query => |q| q.group_addr,
        .membership_report => |r| r.group_addr,
        .leave_group => |l| l.group_addr,
    };
}

// -------------------------------------------------------------------------
// Parse
// -------------------------------------------------------------------------

pub const ParseError = error{
    TooShort,
    InvalidGroupAddr,
    UnknownType,
    ChecksumError,
};

pub fn parse(data: []const u8) ParseError!Repr {
    if (data.len < HEADER_LEN) return error.TooShort;

    if (checksum_mod.internetChecksum(data[0..HEADER_LEN]) != 0) {
        return error.ChecksumError;
    }

    const msg_type: MessageType = @enumFromInt(data[0]);
    const max_resp_code = data[1];
    const group_addr: ipv4.Address = data[4..8].*;

    // Group address must be unspecified or multicast.
    if (!ipv4.isUnspecified(group_addr) and !ipv4.isMulticast(group_addr)) {
        return error.InvalidGroupAddr;
    }

    return switch (msg_type) {
        .membership_query => .{ .membership_query = .{
            .max_resp_time = max_resp_code,
            .group_addr = group_addr,
            .version = if (max_resp_code == 0) .v1 else .v2,
        } },
        .membership_report_v1 => .{ .membership_report = .{
            .group_addr = group_addr,
            .version = .v1,
        } },
        .membership_report_v2 => .{ .membership_report = .{
            .group_addr = group_addr,
            .version = .v2,
        } },
        .leave_group => .{ .leave_group = .{
            .group_addr = group_addr,
        } },
        _ => error.UnknownType,
    };
}

// -------------------------------------------------------------------------
// Emit
// -------------------------------------------------------------------------

pub fn emit(repr: Repr, buf: []u8) !usize {
    if (buf.len < HEADER_LEN) return error.TooShort;

    @memset(buf[0..HEADER_LEN], 0);

    switch (repr) {
        .membership_query => |q| {
            buf[0] = @intFromEnum(MessageType.membership_query);
            buf[1] = q.max_resp_time;
        },
        .membership_report => |r| {
            buf[0] = switch (r.version) {
                .v1 => @intFromEnum(MessageType.membership_report_v1),
                .v2 => @intFromEnum(MessageType.membership_report_v2),
            };
        },
        .leave_group => {
            buf[0] = @intFromEnum(MessageType.leave_group);
        },
    }

    buf[4..8].* = groupAddr(repr);
    fillChecksum(buf[0..HEADER_LEN]);
    return HEADER_LEN;
}

fn fillChecksum(header: *[HEADER_LEN]u8) void {
    header[2] = 0;
    header[3] = 0;
    const cksum = checksum_mod.internetChecksum(header);
    header[2] = @truncate(cksum >> 8);
    header[3] = @truncate(cksum & 0xFF);
}

pub fn bufferLen(_: Repr) usize {
    return HEADER_LEN;
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;

// [smoltcp:wire/igmp.rs:test_leave_group_deconstruct]
test "IGMP leave group parse" {
    const data = [_]u8{ 0x17, 0x00, 0x02, 0x69, 0xe0, 0x00, 0x06, 0x96 };
    const repr = try parse(&data);
    switch (repr) {
        .leave_group => |l| {
            try testing.expectEqual(ipv4.Address{ 0xe0, 0x00, 0x06, 0x96 }, l.group_addr);
        },
        else => return error.UnexpectedType,
    }
}

// [smoltcp:wire/igmp.rs:test_report_deconstruct]
test "IGMP membership report v2 parse" {
    const data = [_]u8{ 0x16, 0x00, 0x08, 0xda, 0xe1, 0x00, 0x00, 0x25 };
    const repr = try parse(&data);
    switch (repr) {
        .membership_report => |r| {
            try testing.expectEqual(ipv4.Address{ 0xe1, 0x00, 0x00, 0x25 }, r.group_addr);
            try testing.expectEqual(IgmpVersion.v2, r.version);
        },
        else => return error.UnexpectedType,
    }
}

// [smoltcp:wire/igmp.rs:test_leave_construct]
test "IGMP leave group emit and checksum" {
    var buf: [8]u8 = undefined;
    const len = try emit(.{ .leave_group = .{
        .group_addr = .{ 0xe0, 0x00, 0x06, 0x96 },
    } }, &buf);
    try testing.expectEqual(@as(usize, 8), len);
    try testing.expectEqual(@as(u8, 0x17), buf[0]);
    try testing.expectEqual(@as(u16, 0), checksum_mod.internetChecksum(&buf));
}

// [smoltcp:wire/igmp.rs:test_report_construct]
test "IGMP report v2 emit and checksum" {
    var buf: [8]u8 = undefined;
    const len = try emit(.{ .membership_report = .{
        .group_addr = .{ 0xe1, 0x00, 0x00, 0x25 },
        .version = .v2,
    } }, &buf);
    try testing.expectEqual(@as(usize, 8), len);
    try testing.expectEqual(@as(u8, 0x16), buf[0]);
    try testing.expectEqual(@as(u16, 0), checksum_mod.internetChecksum(&buf));
}

test "IGMP parse rejects too short" {
    const data = [_]u8{ 0x17, 0x00, 0x02 };
    try testing.expectError(error.TooShort, parse(&data));
}

test "IGMP parse rejects non-multicast group" {
    // Valid checksum but unicast group addr
    var data = [_]u8{ 0x17, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01 };
    // Fix checksum
    data[2] = 0;
    data[3] = 0;
    const cksum = checksum_mod.internetChecksum(&data);
    data[2] = @truncate(cksum >> 8);
    data[3] = @truncate(cksum & 0xFF);
    try testing.expectError(error.InvalidGroupAddr, parse(&data));
}

test "IGMP emit roundtrip" {
    const original = Repr{ .membership_query = .{
        .max_resp_time = 100,
        .group_addr = .{ 0xe0, 0x00, 0x00, 0x01 },
        .version = .v2,
    } };
    var buf: [8]u8 = undefined;
    _ = try emit(original, &buf);
    const parsed = try parse(&buf);
    switch (parsed) {
        .membership_query => |q| {
            try testing.expectEqual(@as(u8, 100), q.max_resp_time);
            try testing.expectEqual(ipv4.Address{ 0xe0, 0x00, 0x00, 0x01 }, q.group_addr);
            try testing.expectEqual(IgmpVersion.v2, q.version);
        },
        else => return error.UnexpectedType,
    }
}

test "IGMP v1 query detected by zero max_resp_code" {
    var buf: [8]u8 = undefined;
    _ = try emit(.{ .membership_query = .{
        .max_resp_time = 0,
        .group_addr = ipv4.UNSPECIFIED,
        .version = .v1,
    } }, &buf);
    const repr = try parse(&buf);
    switch (repr) {
        .membership_query => |q| {
            try testing.expectEqual(IgmpVersion.v1, q.version);
        },
        else => return error.UnexpectedType,
    }
}
