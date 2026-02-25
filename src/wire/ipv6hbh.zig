// IPv6 Hop-by-Hop options header parsing and serialization.
//
// Reference: RFC 8200 S4.3, smoltcp src/wire/ipv6hopbyhop.rs
//
// Parses/emits the options payload of a Hop-by-Hop extension header
// (after the 2-byte next_header + length prefix handled by ipv6ext_header).

const ipv6option = @import("ipv6option.zig");

pub const MAX_OPTIONS: usize = 8;

pub const Repr = struct {
    options: [MAX_OPTIONS]?ipv6option.Repr,
    count: u8,

    pub fn bufferLen(self: Repr) usize {
        var total: usize = 0;
        for (0..self.count) |i| {
            total += self.options[i].?.bufferLen();
        }
        return total;
    }
};

pub fn mldv2RouterAlert() Repr {
    var repr: Repr = .{
        .options = .{null} ** MAX_OPTIONS,
        .count = 1,
    };
    repr.options[0] = .{ .router_alert = .multicast_listener_discovery };
    return repr;
}

pub fn parse(data: []const u8) Repr {
    var repr: Repr = .{
        .options = .{null} ** MAX_OPTIONS,
        .count = 0,
    };
    var iter = ipv6option.iterator(data);
    while (iter.next()) |opt| {
        if (repr.count >= MAX_OPTIONS) break;
        repr.options[repr.count] = opt;
        repr.count += 1;
    }
    return repr;
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const len = repr.bufferLen();
    if (buf.len < len) return error.BufferTooSmall;
    var pos: usize = 0;
    for (0..repr.count) |i| {
        pos += try ipv6option.emit(repr.options[i].?, buf[pos..]);
    }
    return pos;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ipv6hopbyhop.rs:test_hbh_deconstruct]
test "parse HBH with PadN(4)" {
    const data = [_]u8{ 0x01, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const repr = parse(&data);
    try testing.expectEqual(@as(u8, 1), repr.count);
    try testing.expectEqual(@as(u8, 4), repr.options[0].?.padn);
}

test "parse HBH with multiple options" {
    const data = [_]u8{
        0x00, // Pad1
        0x05, 0x02, 0x00, 0x00, // RouterAlert(MLD)
        0x01, 0x01, 0x00, // PadN(1)
    };
    const repr = parse(&data);
    try testing.expectEqual(@as(u8, 3), repr.count);
    try testing.expect(repr.options[0].? == .pad1);
    try testing.expectEqual(ipv6option.RouterAlert.multicast_listener_discovery, repr.options[1].?.router_alert);
    try testing.expectEqual(@as(u8, 1), repr.options[2].?.padn);
}

test "mldv2RouterAlert preset" {
    const repr = mldv2RouterAlert();
    try testing.expectEqual(@as(u8, 1), repr.count);
    try testing.expectEqual(ipv6option.RouterAlert.multicast_listener_discovery, repr.options[0].?.router_alert);
    try testing.expectEqual(@as(usize, 4), repr.bufferLen());
    var buf: [4]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x05, 0x02, 0x00, 0x00 }, &buf);
}
