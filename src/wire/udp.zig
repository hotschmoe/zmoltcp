// UDP datagram parsing and serialization.
//
// Reference: RFC 768, smoltcp src/wire/udp.rs

const checksum = @import("checksum.zig");

pub const HEADER_LEN = 8;

/// High-level representation of a UDP datagram header.
pub const Repr = struct {
    src_port: u16,
    dst_port: u16,
    length: u16,
    checksum: u16,
};

/// Parse a UDP header from raw bytes (after IP header).
pub fn parse(data: []const u8) error{Truncated}!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;
    return .{
        .src_port = @as(u16, data[0]) << 8 | @as(u16, data[1]),
        .dst_port = @as(u16, data[2]) << 8 | @as(u16, data[3]),
        .length = @as(u16, data[4]) << 8 | @as(u16, data[5]),
        .checksum = @as(u16, data[6]) << 8 | @as(u16, data[7]),
    };
}

/// Serialize a UDP header into a buffer. Returns header length (always 8).
pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    if (buf.len < HEADER_LEN) return error.BufferTooSmall;
    buf[0] = @truncate(repr.src_port >> 8);
    buf[1] = @truncate(repr.src_port & 0xFF);
    buf[2] = @truncate(repr.dst_port >> 8);
    buf[3] = @truncate(repr.dst_port & 0xFF);
    buf[4] = @truncate(repr.length >> 8);
    buf[5] = @truncate(repr.length & 0xFF);
    buf[6] = @truncate(repr.checksum >> 8);
    buf[7] = @truncate(repr.checksum & 0xFF);
    return HEADER_LEN;
}

/// Compute UDP checksum with pseudo-header.
pub fn computeChecksum(src_ip: [4]u8, dst_ip: [4]u8, udp_data: []const u8) u16 {
    var sum: u32 = 0;
    sum = checksum.calculate(&src_ip, sum);
    sum = checksum.calculate(&dst_ip, sum);
    const proto_len = [_]u8{ 0, 17, @truncate(udp_data.len >> 8), @truncate(udp_data.len & 0xFF) };
    sum = checksum.calculate(&proto_len, sum);
    sum = checksum.calculate(udp_data, sum);
    return checksum.finish(sum);
}

/// Returns the payload portion of a UDP datagram.
pub fn payloadSlice(data: []const u8) error{Truncated}![]const u8 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return data[HEADER_LEN..];
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/udp.rs:test_parse]
test "parse UDP datagram" {
    const data = [_]u8{
        0x00, 0x35, // src_port = 53 (DNS)
        0xC0, 0x01, // dst_port = 49153
        0x00, 0x1C, // length = 28
        0xAB, 0xCD, // checksum
        // payload follows...
        0xDE, 0xAD, 0xBE, 0xEF,
    };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u16, 53), repr.src_port);
    try testing.expectEqual(@as(u16, 49153), repr.dst_port);
    try testing.expectEqual(@as(u16, 28), repr.length);
}

test "parse UDP truncated" {
    const short = [_]u8{ 0x00, 0x35, 0xC0, 0x01 };
    try testing.expectError(error.Truncated, parse(&short));
}

// [smoltcp:wire/udp.rs:roundtrip]
test "UDP roundtrip" {
    const original = [_]u8{
        0x00, 0x35, 0xC0, 0x01,
        0x00, 0x1C, 0xAB, 0xCD,
    };
    const repr = try parse(&original);
    var emitted: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &emitted);
    try testing.expectEqualSlices(u8, &original, &emitted);
}

test "UDP payload extraction" {
    const data = [_]u8{
        0x00, 0x35, 0xC0, 0x01,
        0x00, 0x0C, 0x00, 0x00,
        0xCA, 0xFE, 0xBA, 0xBE,
    };
    const p = try payloadSlice(&data);
    try testing.expectEqual(@as(usize, 4), p.len);
    try testing.expectEqual(@as(u8, 0xCA), p[0]);
}
