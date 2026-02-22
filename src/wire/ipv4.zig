// IPv4 header parsing and serialization.
//
// Reference: RFC 791, smoltcp src/wire/ipv4.rs

const checksum = @import("checksum.zig");

pub const HEADER_LEN = 20; // Minimum (no options)
pub const MAX_HEADER_LEN = 60; // IHL=15 * 4

pub const Protocol = enum(u8) {
    icmp = 1,
    tcp = 6,
    udp = 17,
    _,
};

pub const Address = [4]u8;

/// High-level representation of an IPv4 header.
pub const Repr = struct {
    version: u4,
    ihl: u4,
    dscp_ecn: u8,
    total_length: u16,
    identification: u16,
    dont_fragment: bool,
    more_fragments: bool,
    fragment_offset: u13,
    ttl: u8,
    protocol: Protocol,
    checksum: u16,
    src_addr: Address,
    dst_addr: Address,
};

/// Parse an IPv4 header from raw bytes.
pub fn parse(data: []const u8) error{ Truncated, BadVersion, BadHeaderLen }!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;

    const version: u4 = @truncate(data[0] >> 4);
    if (version != 4) return error.BadVersion;

    const ihl: u4 = @truncate(data[0] & 0x0F);
    if (ihl < 5) return error.BadHeaderLen;

    const header_len: usize = @as(usize, ihl) * 4;
    if (data.len < header_len) return error.Truncated;

    const flags_frag: u16 = @as(u16, data[6]) << 8 | @as(u16, data[7]);

    return .{
        .version = version,
        .ihl = ihl,
        .dscp_ecn = data[1],
        .total_length = @as(u16, data[2]) << 8 | @as(u16, data[3]),
        .identification = @as(u16, data[4]) << 8 | @as(u16, data[5]),
        .dont_fragment = (flags_frag & 0x4000) != 0,
        .more_fragments = (flags_frag & 0x2000) != 0,
        .fragment_offset = @truncate(flags_frag & 0x1FFF),
        .ttl = data[8],
        .protocol = @enumFromInt(data[9]),
        .checksum = @as(u16, data[10]) << 8 | @as(u16, data[11]),
        .src_addr = data[12..16].*,
        .dst_addr = data[16..20].*,
    };
}

/// Serialize an IPv4 header into a buffer. Computes checksum automatically.
/// Returns the header length in bytes.
pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const header_len: usize = @as(usize, repr.ihl) * 4;
    if (buf.len < header_len) return error.BufferTooSmall;

    buf[0] = (@as(u8, repr.version) << 4) | @as(u8, repr.ihl);
    buf[1] = repr.dscp_ecn;
    buf[2] = @truncate(repr.total_length >> 8);
    buf[3] = @truncate(repr.total_length & 0xFF);
    buf[4] = @truncate(repr.identification >> 8);
    buf[5] = @truncate(repr.identification & 0xFF);

    var flags_frag: u16 = @as(u16, repr.fragment_offset);
    if (repr.dont_fragment) flags_frag |= 0x4000;
    if (repr.more_fragments) flags_frag |= 0x2000;
    buf[6] = @truncate(flags_frag >> 8);
    buf[7] = @truncate(flags_frag & 0xFF);

    buf[8] = repr.ttl;
    buf[9] = @intFromEnum(repr.protocol);

    // Zero checksum field before computing
    buf[10] = 0;
    buf[11] = 0;

    @memcpy(buf[12..16], &repr.src_addr);
    @memcpy(buf[16..20], &repr.dst_addr);

    // Zero any option bytes (IHL > 5)
    if (header_len > HEADER_LEN) {
        @memset(buf[HEADER_LEN..header_len], 0);
    }

    // Compute and fill checksum
    const cksum = checksum.internetChecksum(buf[0..header_len]);
    buf[10] = @truncate(cksum >> 8);
    buf[11] = @truncate(cksum & 0xFF);

    return header_len;
}

/// Validate the header checksum. Returns true if valid.
pub fn verifyChecksum(data: []const u8) bool {
    if (data.len < HEADER_LEN) return false;
    const ihl: usize = @as(usize, data[0] & 0x0F) * 4;
    if (data.len < ihl) return false;
    return checksum.internetChecksum(data[0..ihl]) == 0;
}

/// Returns the payload portion of an IPv4 packet (after the header).
pub fn payloadSlice(data: []const u8) error{ Truncated, BadHeaderLen }![]const u8 {
    if (data.len < HEADER_LEN) return error.Truncated;
    const ihl: usize = @as(usize, data[0] & 0x0F) * 4;
    if (ihl < HEADER_LEN) return error.BadHeaderLen;
    if (data.len < ihl) return error.Truncated;
    return data[ihl..];
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

const SAMPLE_IPV4 = [_]u8{
    0x45, 0x00, 0x00, 0x28, // version=4, IHL=5, total_length=40
    0xAB, 0xCD, 0x40, 0x00, // id=0xABCD, DF=1, frag_offset=0
    0x40, 0x06, 0x00, 0x00, // TTL=64, protocol=TCP, checksum=0 (to be filled)
    0x0A, 0x00, 0x02, 0x0F, // src = 10.0.2.15
    0x0A, 0x00, 0x02, 0x02, // dst = 10.0.2.2
};

// [smoltcp:wire/ipv4.rs:test_parse]
test "parse IPv4 header" {
    const repr = try parse(&SAMPLE_IPV4);
    try testing.expectEqual(@as(u4, 4), repr.version);
    try testing.expectEqual(@as(u4, 5), repr.ihl);
    try testing.expectEqual(@as(u16, 40), repr.total_length);
    try testing.expectEqual(@as(u16, 0xABCD), repr.identification);
    try testing.expect(repr.dont_fragment);
    try testing.expect(!repr.more_fragments);
    try testing.expectEqual(@as(u13, 0), repr.fragment_offset);
    try testing.expectEqual(@as(u8, 64), repr.ttl);
    try testing.expectEqual(Protocol.tcp, repr.protocol);
    try testing.expectEqual(Address{ 0x0A, 0x00, 0x02, 0x0F }, repr.src_addr);
    try testing.expectEqual(Address{ 0x0A, 0x00, 0x02, 0x02 }, repr.dst_addr);
}

test "parse IPv4 truncated" {
    try testing.expectError(error.Truncated, parse(SAMPLE_IPV4[0..10]));
}

test "parse IPv4 bad version" {
    var bad = SAMPLE_IPV4;
    bad[0] = 0x65; // version 6
    try testing.expectError(error.BadVersion, parse(&bad));
}

test "parse IPv4 bad IHL" {
    var bad = SAMPLE_IPV4;
    bad[0] = 0x43; // IHL=3, less than minimum 5
    try testing.expectError(error.BadHeaderLen, parse(&bad));
}

// [smoltcp:wire/ipv4.rs:roundtrip]
test "IPv4 roundtrip" {
    const repr = try parse(&SAMPLE_IPV4);
    var emitted: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &emitted);

    // Compare all fields except checksum (positions 10-11)
    // because the sample has checksum=0 but emit computes it
    try testing.expectEqualSlices(u8, SAMPLE_IPV4[0..10], emitted[0..10]);
    try testing.expectEqualSlices(u8, SAMPLE_IPV4[12..20], emitted[12..20]);
}

test "IPv4 emit produces valid checksum" {
    const repr = try parse(&SAMPLE_IPV4);
    var emitted: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &emitted);

    // Checksum of emitted header should verify to 0
    try testing.expect(verifyChecksum(&emitted));
}

test "IPv4 payload extraction" {
    const pkt = SAMPLE_IPV4 ++ [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const p = try payloadSlice(&pkt);
    try testing.expectEqual(@as(usize, 4), p.len);
    try testing.expectEqual(@as(u8, 0xDE), p[0]);
}
