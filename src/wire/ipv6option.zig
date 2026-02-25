// IPv6 extension header option parsing and serialization.
//
// Reference: RFC 8200 S4.2, smoltcp src/wire/ipv6option.rs

pub const Type = enum(u8) {
    pad1 = 0x00,
    padn = 0x01,
    router_alert = 0x05,
    rpl = 0x63,
    _,
};

pub const FailureType = enum(u2) {
    skip = 0,
    discard = 1,
    discard_send_all = 2,
    discard_send_unicast = 3,
};

pub fn failureTypeFromOptionType(opt_type: u8) FailureType {
    return @enumFromInt(@as(u2, @truncate(opt_type >> 6)));
}

pub const RouterAlert = enum(u16) {
    multicast_listener_discovery = 0,
    rsvp = 1,
    active_networks = 2,
    _,
};

pub const Repr = union(enum) {
    pad1,
    padn: u8,
    router_alert: RouterAlert,
    unknown: struct {
        option_type: u8,
        length: u8,
        data: []const u8,
    },

    pub fn bufferLen(self: Repr) usize {
        return switch (self) {
            .pad1 => 1,
            .padn => |n| 2 + @as(usize, n),
            .router_alert => 4,
            .unknown => |u| 2 + @as(usize, u.length),
        };
    }
};

pub fn parse(data: []const u8) error{ Truncated, BadOption }!Repr {
    if (data.len < 1) return error.Truncated;

    const opt_type: Type = @enumFromInt(data[0]);

    if (opt_type == .pad1) return .pad1;

    if (data.len < 2) return error.Truncated;
    const length = data[1];
    if (data.len < 2 + @as(usize, length)) return error.Truncated;

    return switch (opt_type) {
        .padn => .{ .padn = length },
        .router_alert => blk: {
            if (length != 2) break :blk error.BadOption;
            const val: u16 = @as(u16, data[2]) << 8 | @as(u16, data[3]);
            break :blk .{ .router_alert = @enumFromInt(val) };
        },
        else => .{ .unknown = .{
            .option_type = data[0],
            .length = length,
            .data = data[2 .. 2 + @as(usize, length)],
        } },
    };
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const len = repr.bufferLen();
    if (buf.len < len) return error.BufferTooSmall;

    switch (repr) {
        .pad1 => {
            buf[0] = 0x00;
        },
        .padn => |n| {
            buf[0] = @intFromEnum(Type.padn);
            buf[1] = n;
            @memset(buf[2 .. 2 + @as(usize, n)], 0);
        },
        .router_alert => |alert| {
            buf[0] = @intFromEnum(Type.router_alert);
            buf[1] = 2;
            const val: u16 = @intFromEnum(alert);
            buf[2] = @truncate(val >> 8);
            buf[3] = @truncate(val);
        },
        .unknown => |u| {
            buf[0] = u.option_type;
            buf[1] = u.length;
            @memcpy(buf[2 .. 2 + @as(usize, u.length)], u.data);
        },
    }
    return len;
}

pub const Iterator = struct {
    data: []const u8,
    pos: usize,
    hit_error: bool,

    pub fn next(self: *Iterator) ?Repr {
        if (self.hit_error or self.pos >= self.data.len) return null;
        const repr = parse(self.data[self.pos..]) catch {
            self.hit_error = true;
            return null;
        };
        self.pos += repr.bufferLen();
        return repr;
    }
};

pub fn iterator(data: []const u8) Iterator {
    return .{ .data = data, .pos = 0, .hit_error = false };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ipv6option.rs:test_check_len]
test "parse Pad1" {
    const data = [_]u8{0x00};
    const repr = try parse(&data);
    try testing.expect(repr == .pad1);
    try testing.expectEqual(@as(usize, 1), repr.bufferLen());
}

test "parse PadN" {
    const data = [_]u8{ 0x01, 0x01, 0x00 };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u8, 1), repr.padn);
    try testing.expectEqual(@as(usize, 3), repr.bufferLen());
}

test "parse RouterAlert MLD" {
    const data = [_]u8{ 0x05, 0x02, 0x00, 0x00 };
    const repr = try parse(&data);
    try testing.expectEqual(RouterAlert.multicast_listener_discovery, repr.router_alert);
    try testing.expectEqual(@as(usize, 4), repr.bufferLen());
}

test "parse RouterAlert RSVP" {
    const data = [_]u8{ 0x05, 0x02, 0x00, 0x01 };
    const repr = try parse(&data);
    try testing.expectEqual(RouterAlert.rsvp, repr.router_alert);
}

test "parse unknown option" {
    const data = [_]u8{ 0xFF, 0x03, 0x00, 0x00, 0x00 };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u8, 0xFF), repr.unknown.option_type);
    try testing.expectEqual(@as(u8, 3), repr.unknown.length);
}

// [smoltcp:wire/ipv6option.rs:test_option_deconstruct]
test "option roundtrip" {
    const ra_data = [_]u8{ 0x05, 0x02, 0x00, 0x01 };
    const repr = try parse(&ra_data);
    var buf: [4]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqualSlices(u8, &ra_data, &buf);
}

test "iterator with mixed options" {
    const data = [_]u8{
        0x00, // Pad1
        0x01, 0x01, 0x00, // PadN(1)
        0x01, 0x02, 0x00, 0x00, // PadN(2)
        0x01, 0x00, // PadN(0)
        0x00, // Pad1
        0x05, 0x02, 0x00, 0x01, // RouterAlert(RSVP)
    };
    var iter = iterator(&data);
    try testing.expect(iter.next().? == .pad1); // Pad1
    try testing.expectEqual(@as(u8, 1), iter.next().?.padn); // PadN(1)
    try testing.expectEqual(@as(u8, 2), iter.next().?.padn); // PadN(2)
    try testing.expectEqual(@as(u8, 0), iter.next().?.padn); // PadN(0)
    try testing.expect(iter.next().? == .pad1); // Pad1
    try testing.expectEqual(RouterAlert.rsvp, iter.next().?.router_alert);
    try testing.expect(iter.next() == null); // end
}
