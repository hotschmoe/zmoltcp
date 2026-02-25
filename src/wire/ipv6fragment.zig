// IPv6 fragment header parsing and serialization.
//
// Reference: RFC 8200 S4.5, smoltcp src/wire/ipv6fragment.rs
//
// Layout (8 bytes total):
//   Byte 0:    next_header
//   Byte 1:    reserved
//   Bytes 2-3: fragment_offset(13 bits) | reserved(2 bits) | more_frags(1 bit)
//   Bytes 4-7: identification (u32 big-endian)

pub const HEADER_LEN: usize = 8;

pub const Repr = struct {
    next_header: u8,
    frag_offset: u16,
    more_frags: bool,
    ident: u32,
};

pub fn parse(data: []const u8) error{Truncated}!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;

    const offset_flags: u16 = @as(u16, data[2]) << 8 | @as(u16, data[3]);

    return .{
        .next_header = data[0],
        .frag_offset = offset_flags >> 3,
        .more_frags = (offset_flags & 0x01) != 0,
        .ident = @as(u32, data[4]) << 24 | @as(u32, data[5]) << 16 |
            @as(u32, data[6]) << 8 | @as(u32, data[7]),
    };
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    if (buf.len < HEADER_LEN) return error.BufferTooSmall;

    buf[0] = repr.next_header;
    buf[1] = 0; // reserved

    var offset_flags: u16 = (repr.frag_offset & 0x1FFF) << 3;
    if (repr.more_frags) offset_flags |= 0x01;
    buf[2] = @truncate(offset_flags >> 8);
    buf[3] = @truncate(offset_flags);

    buf[4] = @truncate(repr.ident >> 24);
    buf[5] = @truncate(repr.ident >> 16);
    buf[6] = @truncate(repr.ident >> 8);
    buf[7] = @truncate(repr.ident);

    return HEADER_LEN;
}

pub fn bufferLen(_: Repr) usize {
    return HEADER_LEN;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ipv6fragment.rs:test_frag_header_deconstruct]
test "parse fragment header more_frags" {
    // more_frags=true, offset=0, ident=12345
    const data = [_]u8{ 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x30, 0x39 };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u8, 0x06), repr.next_header);
    try testing.expectEqual(@as(u16, 0), repr.frag_offset);
    try testing.expect(repr.more_frags);
    try testing.expectEqual(@as(u32, 12345), repr.ident);
}

test "parse fragment header last frag" {
    // more_frags=false, offset=320, ident=67890
    const data = [_]u8{ 0x06, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x09, 0x32 };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u16, 320), repr.frag_offset);
    try testing.expect(!repr.more_frags);
    try testing.expectEqual(@as(u32, 67890), repr.ident);
}

test "fragment header roundtrip" {
    const original = [_]u8{ 0x06, 0x00, 0x0a, 0x00, 0x00, 0x01, 0x09, 0x32 };
    const repr = try parse(&original);
    var buf: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqualSlices(u8, &original, &buf);
}

test "parse fragment truncated" {
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0x06, 0x00, 0x00 }));
}
