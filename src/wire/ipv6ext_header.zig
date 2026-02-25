// IPv6 generic extension header parsing and serialization.
//
// Reference: RFC 8200 S4.2, smoltcp src/wire/ipv6ext_header.rs
//
// Extension headers share a common 2-byte prefix: next_header + length.
// The length field encodes total size as (length + 1) * 8 bytes.

pub const MIN_HEADER_LEN: usize = 8;

pub const Repr = struct {
    next_header: u8,
    length: u8,
    data: []const u8,
};

/// Total byte length of an extension header given its length field value.
pub fn headerLen(length_field: u8) usize {
    return (@as(usize, length_field) + 1) * 8;
}

pub fn parse(data: []const u8) error{Truncated}!Repr {
    if (data.len < 2) return error.Truncated;
    const total_len = headerLen(data[1]);
    if (data.len < total_len) return error.Truncated;
    return .{
        .next_header = data[0],
        .length = data[1],
        .data = data[2..total_len],
    };
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const total_len = headerLen(repr.length);
    if (buf.len < total_len) return error.BufferTooSmall;
    buf[0] = repr.next_header;
    buf[1] = repr.length;
    @memcpy(buf[2 .. 2 + repr.data.len], repr.data);
    // Zero any remaining pad bytes
    if (total_len > 2 + repr.data.len) {
        @memset(buf[2 + repr.data.len .. total_len], 0);
    }
    return total_len;
}

pub fn payloadSlice(data: []const u8) error{Truncated}![]const u8 {
    if (data.len < 2) return error.Truncated;
    const total_len = headerLen(data[1]);
    if (data.len < total_len) return error.Truncated;
    return data[2..total_len];
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

test "headerLen encoding" {
    try testing.expectEqual(@as(usize, 8), headerLen(0));
    try testing.expectEqual(@as(usize, 16), headerLen(1));
    try testing.expectEqual(@as(usize, 24), headerLen(2));
}

// [smoltcp:wire/ipv6ext_header.rs:test_ext_header_deconstruct]
test "parse extension header with PadN(4)" {
    const data = [_]u8{ 0x06, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u8, 0x06), repr.next_header);
    try testing.expectEqual(@as(u8, 0), repr.length);
    try testing.expectEqual(@as(usize, 6), repr.data.len);
}

test "parse extension header with PadN(12)" {
    const data = [_]u8{
        0x06, 0x01, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u8, 0x06), repr.next_header);
    try testing.expectEqual(@as(u8, 1), repr.length);
    try testing.expectEqual(@as(usize, 14), repr.data.len);
}

// [smoltcp:wire/ipv6ext_header.rs:test_ext_header_construct]
test "extension header roundtrip" {
    const original = [_]u8{ 0x06, 0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00 };
    const repr = try parse(&original);
    var buf: [8]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqualSlices(u8, &original, &buf);
}

test "parse truncated" {
    try testing.expectError(error.Truncated, parse(&[_]u8{0x06}));
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0x06, 0x01, 0x00, 0x00 }));
}
