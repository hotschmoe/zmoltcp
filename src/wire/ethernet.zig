// Ethernet II frame parsing and serialization.
//
// Reference: IEEE 802.3, smoltcp src/wire/ethernet.rs

pub const HEADER_LEN = 14;
pub const ADDR_LEN = 6;
pub const MIN_FRAME_LEN = 64;

pub const Address = [ADDR_LEN]u8;

pub const BROADCAST: Address = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

pub const EtherType = enum(u16) {
    ipv4 = 0x0800,
    arp = 0x0806,
    ipv6 = 0x86DD,
    _,
};

/// High-level representation of an Ethernet II frame header.
pub const Repr = struct {
    dst_addr: Address,
    src_addr: Address,
    ethertype: EtherType,
};

/// Parse an Ethernet II frame header from raw bytes.
pub fn parse(data: []const u8) error{Truncated}!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;
    return .{
        .dst_addr = data[0..ADDR_LEN].*,
        .src_addr = data[ADDR_LEN..][0..ADDR_LEN].*,
        .ethertype = @enumFromInt(@as(u16, data[12]) << 8 | @as(u16, data[13])),
    };
}

/// Serialize an Ethernet II frame header into a buffer.
/// Returns the header length (always 14).
pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    if (buf.len < HEADER_LEN) return error.BufferTooSmall;
    @memcpy(buf[0..ADDR_LEN], &repr.dst_addr);
    @memcpy(buf[ADDR_LEN..][0..ADDR_LEN], &repr.src_addr);
    buf[12] = @truncate(@intFromEnum(repr.ethertype) >> 8);
    buf[13] = @truncate(@intFromEnum(repr.ethertype) & 0xFF);
    return HEADER_LEN;
}

/// Returns the payload portion of an Ethernet frame (after the header).
pub fn payload(data: []const u8) error{Truncated}![]const u8 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return data[HEADER_LEN..];
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ethernet.rs:test_parse]
test "parse ethernet frame" {
    const frame = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // dst
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, // src
        0x08, 0x00, // IPv4
        0xDE, 0xAD, // payload
    };
    const repr = try parse(&frame);
    try testing.expectEqual(Address{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }, repr.dst_addr);
    try testing.expectEqual(Address{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 }, repr.src_addr);
    try testing.expectEqual(EtherType.ipv4, repr.ethertype);
}

test "parse ethernet truncated" {
    const short = [_]u8{ 0x01, 0x02, 0x03 };
    try testing.expectError(error.Truncated, parse(&short));
}

// [smoltcp:wire/ethernet.rs:test_emit]
test "emit ethernet frame" {
    const repr = Repr{
        .dst_addr = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 },
        .src_addr = .{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16 },
        .ethertype = .arp,
    };
    var buf: [HEADER_LEN]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, HEADER_LEN), len);
    try testing.expectEqual(@as(u8, 0x08), buf[12]);
    try testing.expectEqual(@as(u8, 0x06), buf[13]);
}

// [smoltcp:wire/ethernet.rs:roundtrip]
test "ethernet roundtrip" {
    const original = [_]u8{
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x52, 0x54, 0x00, 0x12, 0x34, 0x56,
        0x08, 0x06,
    };
    const repr = try parse(&original);
    var emitted: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &emitted);
    try testing.expectEqualSlices(u8, &original, &emitted);
}

test "payload extraction" {
    const frame = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
        0x08, 0x00,
        0xCA, 0xFE, 0xBA, 0xBE,
    };
    const p = try payload(&frame);
    try testing.expectEqual(@as(usize, 4), p.len);
    try testing.expectEqual(@as(u8, 0xCA), p[0]);
}
