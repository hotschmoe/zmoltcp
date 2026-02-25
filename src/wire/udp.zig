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

/// Compute UDP checksum with IPv6 pseudo-header (mandatory per RFC 8200 S8.1).
pub fn computeChecksumV6(src_ip: [16]u8, dst_ip: [16]u8, udp_data: []const u8) u16 {
    const partial = checksum.pseudoHeaderChecksumV6(src_ip, dst_ip, 17, @intCast(udp_data.len));
    return checksum.finish(checksum.calculate(udp_data, partial));
}

/// Write the computed UDP checksum into an already-serialized buffer.
/// RFC 768: if the computed checksum is zero, it is transmitted as 0xFFFF.
pub fn fillChecksum(buf: []u8, src_ip: [4]u8, dst_ip: [4]u8) void {
    checksum.writeU16(buf[6..8], 0);
    writeChecksumField(buf, computeChecksum(src_ip, dst_ip, buf));
}

/// Write the computed IPv6 UDP checksum into an already-serialized buffer.
/// RFC 8200: UDP checksum is mandatory over IPv6; zero checksum is forbidden.
pub fn fillChecksumV6(buf: []u8, src_ip: [16]u8, dst_ip: [16]u8) void {
    checksum.writeU16(buf[6..8], 0);
    writeChecksumField(buf, computeChecksumV6(src_ip, dst_ip, buf));
}

/// Verify UDP checksum. Returns true if valid or if checksum is disabled (0x0000).
pub fn verifyChecksum(data: []const u8, src_ip: [4]u8, dst_ip: [4]u8) bool {
    if (data.len < HEADER_LEN) return false;
    if (readChecksumField(data) == 0) return true; // checksum disabled per RFC 768
    return computeChecksum(src_ip, dst_ip, data) == 0;
}

/// Verify UDP checksum over IPv6 pseudo-header.
/// Unlike IPv4, zero checksum is NOT valid over IPv6 (RFC 8200 S8.1).
pub fn verifyChecksumV6(data: []const u8, src_ip: [16]u8, dst_ip: [16]u8) bool {
    if (data.len < HEADER_LEN) return false;
    if (readChecksumField(data) == 0) return false; // zero checksum forbidden over IPv6
    return computeChecksumV6(src_ip, dst_ip, data) == 0;
}

fn readChecksumField(data: []const u8) u16 {
    return checksum.readU16(data[6..8]);
}

fn writeChecksumField(buf: []u8, raw: u16) void {
    checksum.writeU16(buf[6..8], if (raw == 0) 0xFFFF else raw);
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

const SRC_ADDR: [4]u8 = .{ 192, 168, 1, 1 };
const DST_ADDR: [4]u8 = .{ 192, 168, 1, 2 };

const PACKET_BYTES = [_]u8{
    0xbf, 0x00, 0x00, 0x35, 0x00, 0x0c, 0x12, 0x4d, 0xaa, 0x00, 0x00, 0xff,
};

const PAYLOAD_BYTES = [_]u8{ 0xaa, 0x00, 0x00, 0xff };

// [smoltcp:wire/udp.rs:test_deconstruct]
test "UDP deconstruct raw fields" {
    const repr = try parse(&PACKET_BYTES);
    try testing.expectEqual(@as(u16, 48896), repr.src_port);
    try testing.expectEqual(@as(u16, 53), repr.dst_port);
    try testing.expectEqual(@as(u16, 12), repr.length);
    try testing.expectEqual(@as(u16, 0x124d), repr.checksum);
    const p = try payloadSlice(&PACKET_BYTES);
    try testing.expectEqualSlices(u8, &PAYLOAD_BYTES, p);
    try testing.expect(verifyChecksum(&PACKET_BYTES, SRC_ADDR, DST_ADDR));
}

// [smoltcp:wire/udp.rs:test_construct]
test "UDP construct with checksum" {
    var buf: [12]u8 = [_]u8{0xa5} ** 12;
    _ = try emit(.{
        .src_port = 48896,
        .dst_port = 53,
        .length = 12,
        .checksum = 0xFFFF,
    }, &buf);
    @memcpy(buf[HEADER_LEN..], &PAYLOAD_BYTES);
    fillChecksum(&buf, SRC_ADDR, DST_ADDR);
    try testing.expectEqualSlices(u8, &PACKET_BYTES, &buf);
}

// [smoltcp:wire/udp.rs:test_zero_checksum]
test "UDP zero checksum becomes 0xFFFF" {
    var buf: [8]u8 = [_]u8{0} ** 8;
    _ = try emit(.{
        .src_port = 1,
        .dst_port = 31881,
        .length = 8,
        .checksum = 0,
    }, &buf);
    fillChecksum(&buf, SRC_ADDR, DST_ADDR);
    const cksum = readChecksumField(&buf);
    try testing.expectEqual(@as(u16, 0xFFFF), cksum);
}

// [smoltcp:wire/udp.rs:test_no_checksum]
test "UDP disabled checksum passes verify" {
    var buf: [8]u8 = undefined;
    _ = try emit(.{
        .src_port = 1,
        .dst_port = 31881,
        .length = 8,
        .checksum = 0,
    }, &buf);
    try testing.expect(verifyChecksum(&buf, SRC_ADDR, DST_ADDR));
}

// -------------------------------------------------------------------------
// IPv6 checksum tests
// -------------------------------------------------------------------------

const SRC_V6: [16]u8 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const DST_V6: [16]u8 = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

test "UDP v6 checksum roundtrip" {
    var buf: [12]u8 = undefined;
    _ = try emit(.{
        .src_port = 48896,
        .dst_port = 53,
        .length = 12,
        .checksum = 0,
    }, &buf);
    @memcpy(buf[HEADER_LEN..], &PAYLOAD_BYTES);
    fillChecksumV6(&buf, SRC_V6, DST_V6);
    // Checksum must be non-zero (mandatory for IPv6)
    const cksum = readChecksumField(&buf);
    try testing.expect(cksum != 0);
    // Verify passes
    try testing.expect(verifyChecksumV6(&buf, SRC_V6, DST_V6));
}

test "UDP v6 zero checksum is forbidden" {
    // A buffer with checksum field = 0 must fail verification
    var buf: [8]u8 = undefined;
    _ = try emit(.{
        .src_port = 1,
        .dst_port = 2,
        .length = 8,
        .checksum = 0,
    }, &buf);
    try testing.expect(!verifyChecksumV6(&buf, SRC_V6, DST_V6));
}

test "UDP v6 fillChecksum avoids zero" {
    // Same port combo that produces zero checksum over IPv4 should still
    // produce non-zero (0xFFFF) over IPv6 if the raw sum is zero.
    var buf: [8]u8 = [_]u8{0} ** 8;
    _ = try emit(.{
        .src_port = 1,
        .dst_port = 31881,
        .length = 8,
        .checksum = 0,
    }, &buf);
    fillChecksumV6(&buf, SRC_V6, DST_V6);
    const cksum = readChecksumField(&buf);
    try testing.expect(cksum != 0);
}
