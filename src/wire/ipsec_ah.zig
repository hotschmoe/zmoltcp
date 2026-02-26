// IPsec Authentication Header (AH) parsing and serialization.
//
// Reference: RFC 4302, smoltcp src/wire/ipsec_ah.rs

const ipv4 = @import("ipv4.zig");

pub const MIN_HEADER_LEN: usize = 12;

pub const Repr = struct {
    next_header: ipv4.Protocol,
    spi: u32,
    sequence_number: u32,
    icv_len: usize,
};

pub fn parse(data: []const u8) error{Truncated}!Repr {
    if (data.len < MIN_HEADER_LEN) return error.Truncated;
    const payload_len = data[1];
    const total = headerLen(data);
    if (data.len < total) return error.Truncated;
    return .{
        .next_header = @enumFromInt(data[0]),
        .spi = readU32(data[4..8]),
        .sequence_number = readU32(data[8..12]),
        .icv_len = (@as(usize, payload_len) + 2) * 4 - MIN_HEADER_LEN,
    };
}

pub fn emit(repr: Repr, icv: []const u8, buf: []u8) error{Truncated}!void {
    const total = bufferLen(repr);
    if (buf.len < total) return error.Truncated;
    if (icv.len != repr.icv_len) return error.Truncated;
    buf[0] = @intFromEnum(repr.next_header);
    buf[1] = @intCast((total / 4) - 2);
    buf[2] = 0; // reserved
    buf[3] = 0;
    writeU32(buf[4..8], repr.spi);
    writeU32(buf[8..12], repr.sequence_number);
    @memcpy(buf[12..][0..icv.len], icv);
}

pub fn bufferLen(repr: Repr) usize {
    return MIN_HEADER_LEN + repr.icv_len;
}

pub fn headerLen(data: []const u8) usize {
    return (@as(usize, data[1]) + 2) * 4;
}

fn readU32(b: *const [4]u8) u32 {
    return @as(u32, b[0]) << 24 | @as(u32, b[1]) << 16 | @as(u32, b[2]) << 8 | b[3];
}

fn writeU32(b: *[4]u8, v: u32) void {
    b[0] = @truncate(v >> 24);
    b[1] = @truncate(v >> 16);
    b[2] = @truncate(v >> 8);
    b[3] = @truncate(v);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ipsec_ah.rs:PACKET_BYTES1]
const PACKET_BYTES1 = [_]u8{
    0x32, 0x04, 0x00, 0x00, 0x81, 0x79, 0xb7, 0x05, 0x00, 0x00, 0x00, 0x01, 0x27, 0xcf, 0xc0,
    0xa5, 0xe4, 0x3d, 0x69, 0xb3, 0x72, 0x8e, 0xc5, 0xb0,
};

// [smoltcp:wire/ipsec_ah.rs:PACKET_BYTES2]
const PACKET_BYTES2 = [_]u8{
    0x32, 0x04, 0x00, 0x00, 0xba, 0x8b, 0xd0, 0x60, 0x00, 0x00, 0x00, 0x01, 0xaf, 0xd2, 0xe7,
    0xa1, 0x73, 0xd3, 0x29, 0x0b, 0xfe, 0x6b, 0x63, 0x73,
};

const ICV1 = [_]u8{ 0x27, 0xcf, 0xc0, 0xa5, 0xe4, 0x3d, 0x69, 0xb3, 0x72, 0x8e, 0xc5, 0xb0 };
const ICV2 = [_]u8{ 0xaf, 0xd2, 0xe7, 0xa1, 0x73, 0xd3, 0x29, 0x0b, 0xfe, 0x6b, 0x63, 0x73 };

fn packetRepr1() Repr {
    return .{
        .next_header = @enumFromInt(0x32), // ipsec_esp = 50
        .spi = 0x8179b705,
        .sequence_number = 1,
        .icv_len = 12,
    };
}

fn packetRepr2() Repr {
    return .{
        .next_header = @enumFromInt(0x32),
        .spi = 0xba8bd060,
        .sequence_number = 1,
        .icv_len = 12,
    };
}

// [smoltcp:wire/ipsec_ah.rs:test_deconstruct]
test "parse AH header fields" {
    const repr = try parse(&PACKET_BYTES1);
    try testing.expectEqual(@as(u8, 0x32), @intFromEnum(repr.next_header));
    try testing.expectEqual(@as(u32, 0x8179b705), repr.spi);
    try testing.expectEqual(@as(u32, 1), repr.sequence_number);
    try testing.expectEqual(@as(usize, 12), repr.icv_len);
    try testing.expectEqualSlices(u8, &ICV1, PACKET_BYTES1[12..24]);
}

// [smoltcp:wire/ipsec_ah.rs:test_construct]
test "emit AH header matches wire bytes" {
    var buf: [24]u8 = undefined;
    try emit(packetRepr2(), &ICV2, &buf);
    try testing.expectEqualSlices(u8, &PACKET_BYTES2, &buf);
}

// [smoltcp:wire/ipsec_ah.rs:test_check_len]
test "AH parse rejects truncated buffers" {
    try testing.expectError(error.Truncated, parse(PACKET_BYTES1[0..10]));
    try testing.expectError(error.Truncated, parse(PACKET_BYTES1[0..22]));
    _ = try parse(&PACKET_BYTES1);
}

// [smoltcp:wire/ipsec_ah.rs:test_parse]
test "AH parse returns correct repr" {
    const repr = try parse(&PACKET_BYTES2);
    const expected = packetRepr2();
    try testing.expectEqual(expected.next_header, repr.next_header);
    try testing.expectEqual(expected.spi, repr.spi);
    try testing.expectEqual(expected.sequence_number, repr.sequence_number);
    try testing.expectEqual(expected.icv_len, repr.icv_len);
}

// [smoltcp:wire/ipsec_ah.rs:test_emit]
test "AH emit into fresh buffer" {
    var buf: [24]u8 = undefined;
    @memset(&buf, 0);
    try emit(packetRepr2(), &ICV2, &buf);
    try testing.expectEqualSlices(u8, &PACKET_BYTES2, &buf);
}

// [smoltcp:wire/ipsec_ah.rs:test_buffer_len]
test "AH bufferLen matches packet length" {
    try testing.expectEqual(@as(usize, 24), bufferLen(packetRepr1()));
}
