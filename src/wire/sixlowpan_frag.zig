// 6LoWPAN fragmentation headers per RFC 4944 S5.3.
//
// Reference: smoltcp src/wire/sixlowpan/frag.rs

const checksum = @import("checksum.zig");
const readU16 = checksum.readU16;
const writeU16 = checksum.writeU16;

pub const FIRST_FRAGMENT_HEADER_SIZE: usize = 4;
pub const NEXT_FRAGMENT_HEADER_SIZE: usize = 5;

pub const DISPATCH_FIRST_FRAGMENT: u8 = 0b11000;
pub const DISPATCH_NEXT_FRAGMENT: u8 = 0b11100;

pub const Repr = union(enum) {
    first_fragment: FirstFragment,
    next_fragment: NextFragment,

    pub const FirstFragment = struct {
        datagram_size: u16,
        datagram_tag: u16,
    };

    pub const NextFragment = struct {
        datagram_size: u16,
        datagram_tag: u16,
        datagram_offset: u8,
    };
};

pub fn parse(data: []const u8) error{ Truncated, Malformed }!Repr {
    if (data.len < 2) return error.Truncated;

    const dispatch = data[0] >> 3;

    if (dispatch == DISPATCH_FIRST_FRAGMENT) {
        if (data.len < FIRST_FRAGMENT_HEADER_SIZE) return error.Truncated;
        const size_word = readU16(data[0..2]);
        const datagram_size = size_word & 0x7FF;
        const datagram_tag = readU16(data[2..4]);
        return .{ .first_fragment = .{
            .datagram_size = datagram_size,
            .datagram_tag = datagram_tag,
        } };
    }

    if (dispatch == DISPATCH_NEXT_FRAGMENT) {
        if (data.len < NEXT_FRAGMENT_HEADER_SIZE) return error.Truncated;
        const size_word = readU16(data[0..2]);
        const datagram_size = size_word & 0x7FF;
        const datagram_tag = readU16(data[2..4]);
        return .{ .next_fragment = .{
            .datagram_size = datagram_size,
            .datagram_tag = datagram_tag,
            .datagram_offset = data[4],
        } };
    }

    return error.Malformed;
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const needed = bufferLen(repr);
    if (buf.len < needed) return error.BufferTooSmall;

    switch (repr) {
        .first_fragment => |f| {
            const val: u16 = (@as(u16, DISPATCH_FIRST_FRAGMENT) << 11) | (f.datagram_size & 0x7FF);
            writeU16(buf[0..2], val);
            writeU16(buf[2..4], f.datagram_tag);
            return FIRST_FRAGMENT_HEADER_SIZE;
        },
        .next_fragment => |f| {
            const val: u16 = (@as(u16, DISPATCH_NEXT_FRAGMENT) << 11) | (f.datagram_size & 0x7FF);
            writeU16(buf[0..2], val);
            writeU16(buf[2..4], f.datagram_tag);
            buf[4] = f.datagram_offset;
            return NEXT_FRAGMENT_HEADER_SIZE;
        },
    }
}

pub fn bufferLen(repr: Repr) usize {
    return switch (repr) {
        .first_fragment => FIRST_FRAGMENT_HEADER_SIZE,
        .next_fragment => NEXT_FRAGMENT_HEADER_SIZE,
    };
}

pub fn payloadSlice(data: []const u8) error{ Truncated, Malformed }![]const u8 {
    const repr = try parse(data);
    const hdr_len = bufferLen(repr);
    if (data.len < hdr_len) return error.Truncated;
    return data[hdr_len..];
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:sixlowpan/mod.rs:sixlowpan_fragment_emit - first fragment]
test "first fragment parse and emit roundtrip" {
    const wire = [_]u8{ 0xc0, 0xff, 0xab, 0xcd };
    const repr = try parse(&wire);
    try testing.expectEqual(Repr{ .first_fragment = .{
        .datagram_size = 0xff,
        .datagram_tag = 0xabcd,
    } }, repr);
    try testing.expectEqual(@as(usize, 4), bufferLen(repr));

    var buf: [4]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 4), len);
    try testing.expectEqualSlices(u8, &wire, &buf);
}

// [smoltcp:sixlowpan/mod.rs:sixlowpan_fragment_emit - subsequent fragment]
test "subsequent fragment parse and emit roundtrip" {
    const wire = [_]u8{ 0xe0, 0xff, 0xab, 0xcd, 0xcc };
    const repr = try parse(&wire);
    try testing.expectEqual(Repr{ .next_fragment = .{
        .datagram_size = 0xff,
        .datagram_tag = 0xabcd,
        .datagram_offset = 0xcc,
    } }, repr);
    try testing.expectEqual(@as(usize, 5), bufferLen(repr));

    var buf: [5]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 5), len);
    try testing.expectEqualSlices(u8, &wire, &buf);
}

test "payloadSlice first fragment" {
    const wire = [_]u8{ 0xc0, 0xff, 0xab, 0xcd, 0xDE, 0xAD };
    const payload = try payloadSlice(&wire);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, payload);
}

test "payloadSlice subsequent fragment" {
    const wire = [_]u8{ 0xe0, 0xff, 0xab, 0xcd, 0x11, 0xBE, 0xEF };
    const payload = try payloadSlice(&wire);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xBE, 0xEF }, payload);
}

test "truncated errors" {
    try testing.expectError(error.Truncated, parse(&[_]u8{0xc0}));
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0xc0, 0xff, 0xab }));
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0xe0, 0xff, 0xab, 0xcd }));
}

test "malformed dispatch" {
    try testing.expectError(error.Malformed, parse(&[_]u8{ 0x00, 0x00, 0x00, 0x00 }));
}

test "bufferLen consistency" {
    const first = Repr{ .first_fragment = .{ .datagram_size = 100, .datagram_tag = 1 } };
    try testing.expectEqual(@as(usize, FIRST_FRAGMENT_HEADER_SIZE), bufferLen(first));

    const next = Repr{ .next_fragment = .{ .datagram_size = 200, .datagram_tag = 2, .datagram_offset = 10 } };
    try testing.expectEqual(@as(usize, NEXT_FRAGMENT_HEADER_SIZE), bufferLen(next));

    var buf: [5]u8 = undefined;
    const emitted = try emit(first, &buf);
    try testing.expectEqual(bufferLen(first), emitted);

    const emitted2 = try emit(next, &buf);
    try testing.expectEqual(bufferLen(next), emitted2);
}

test "emit buffer too small" {
    const repr = Repr{ .first_fragment = .{ .datagram_size = 0xff, .datagram_tag = 0xabcd } };
    var buf: [3]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, emit(repr, &buf));
}
