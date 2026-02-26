// IPv6 header parsing and serialization.
//
// Reference: RFC 8200, smoltcp src/wire/ipv6.rs

pub const HEADER_LEN: usize = 40;
pub const MIN_MTU: usize = 1280;

pub const ADDRESS_LEN: usize = 16;
pub const Address = [ADDRESS_LEN]u8;

pub const UNSPECIFIED: Address = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
pub const LOOPBACK: Address = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
pub const LINK_LOCAL_ALL_NODES: Address = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
pub const LINK_LOCAL_ALL_ROUTERS: Address = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
pub const LINK_LOCAL_ALL_MLDV2_ROUTERS: Address = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16 };
pub const LINK_LOCAL_ALL_RPL_NODES: Address = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1a };

pub const Protocol = enum(u8) {
    hop_by_hop = 0,
    tcp = 6,
    udp = 17,
    routing = 43,
    fragment = 44,
    ipsec_esp = 50,
    ipsec_ah = 51,
    icmpv6 = 58,
    no_next_header = 59,
    destination = 60,
    _,
};

pub fn isUnspecified(addr: Address) bool {
    return eql(addr, UNSPECIFIED);
}

pub fn isBroadcast(_: Address) bool {
    return false;
}

pub fn isMulticast(addr: Address) bool {
    return addr[0] == 0xFF;
}

pub fn isLoopback(addr: Address) bool {
    return eql(addr, LOOPBACK);
}

pub fn isLinkLocal(addr: Address) bool {
    return addr[0] == 0xFE and (addr[1] & 0xC0) == 0x80;
}

pub fn isUniqueLocal(addr: Address) bool {
    return (addr[0] & 0xFE) == 0xFC;
}

pub fn isGlobalUnicast(addr: Address) bool {
    return (addr[0] >> 5) == 0b001;
}

// ff02::1:ffXX:XXXX -- last 3 bytes vary per solicited address
const SOLICITED_NODE_PREFIX = [13]u8{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF };

pub fn isSolicitedNodeMulticast(addr: Address) bool {
    for (addr[0..13], SOLICITED_NODE_PREFIX) |a, b| {
        if (a != b) return false;
    }
    return true;
}

pub fn solicitedNode(addr: Address) Address {
    return .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, addr[13], addr[14], addr[15] };
}

fn eql(a: Address, b: Address) bool {
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

/// Format an IPv6 address per RFC 5952 (zero-compression with ::).
pub fn formatAddr(addr: Address, buf: *[39]u8) []const u8 {
    var groups: [8]u16 = undefined;
    for (0..8) |i| {
        groups[i] = @as(u16, addr[i * 2]) << 8 | @as(u16, addr[i * 2 + 1]);
    }

    // Find the longest run of consecutive zero groups
    var best_start: usize = 8;
    var best_len: usize = 0;
    var run_start: usize = 0;
    var run_len: usize = 0;
    for (0..8) |i| {
        if (groups[i] == 0) {
            if (run_len == 0) run_start = i;
            run_len += 1;
        } else {
            if (run_len > best_len and run_len >= 2) {
                best_start = run_start;
                best_len = run_len;
            }
            run_len = 0;
        }
    }
    if (run_len > best_len and run_len >= 2) {
        best_start = run_start;
        best_len = run_len;
    }

    var pos: usize = 0;
    var i: usize = 0;
    while (i < 8) {
        if (i == best_start and best_len > 0) {
            buf[pos] = ':';
            pos += 1;
            buf[pos] = ':';
            pos += 1;
            i += best_len;
            continue;
        }
        if (i > 0 and !(i == best_start + best_len and best_start < 8)) {
            buf[pos] = ':';
            pos += 1;
        }
        pos = writeHexGroup(buf, pos, groups[i]);
        i += 1;
    }

    return buf[0..pos];
}

fn writeHexGroup(buf: *[39]u8, start: usize, val: u16) usize {
    const hex = "0123456789abcdef";
    var pos = start;
    if (val >= 0x1000) {
        buf[pos] = hex[(val >> 12) & 0xF];
        pos += 1;
    }
    if (val >= 0x100) {
        buf[pos] = hex[(val >> 8) & 0xF];
        pos += 1;
    }
    if (val >= 0x10) {
        buf[pos] = hex[(val >> 4) & 0xF];
        pos += 1;
    }
    buf[pos] = hex[val & 0xF];
    pos += 1;
    return pos;
}

pub const Repr = struct {
    src_addr: Address,
    dst_addr: Address,
    next_header: Protocol,
    payload_len: u16,
    hop_limit: u8,
};

pub fn parse(data: []const u8) error{ Truncated, BadVersion }!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;

    const version: u4 = @truncate(data[0] >> 4);
    if (version != 6) return error.BadVersion;

    const payload_len: u16 = @as(u16, data[4]) << 8 | @as(u16, data[5]);
    if (data.len < HEADER_LEN + @as(usize, payload_len)) return error.Truncated;

    return .{
        .next_header = @enumFromInt(data[6]),
        .hop_limit = data[7],
        .payload_len = payload_len,
        .src_addr = data[8..24].*,
        .dst_addr = data[24..40].*,
    };
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    if (buf.len < HEADER_LEN) return error.BufferTooSmall;

    // Version=6, traffic_class=0, flow_label=0
    buf[0] = 0x60;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;

    buf[4] = @truncate(repr.payload_len >> 8);
    buf[5] = @truncate(repr.payload_len);
    buf[6] = @intFromEnum(repr.next_header);
    buf[7] = repr.hop_limit;

    @memcpy(buf[8..24], &repr.src_addr);
    @memcpy(buf[24..40], &repr.dst_addr);

    return HEADER_LEN;
}

pub fn bufferLen(_: Repr) usize {
    return HEADER_LEN;
}

pub fn checkLen(data: []const u8) error{ Truncated, BadVersion }!void {
    if (data.len < HEADER_LEN) return error.Truncated;
    const version: u4 = @truncate(data[0] >> 4);
    if (version != 6) return error.BadVersion;
    const payload_len: usize = @as(usize, data[4]) << 8 | @as(usize, data[5]);
    if (data.len < HEADER_LEN + payload_len) return error.Truncated;
}

pub fn payloadSlice(data: []const u8) error{Truncated}![]const u8 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return data[HEADER_LEN..];
}

pub fn payloadSliceClamped(data: []const u8) error{Truncated}![]const u8 {
    if (data.len < HEADER_LEN) return error.Truncated;
    const payload_len: usize = @as(usize, data[4]) << 8 | @as(usize, data[5]);
    const end = @min(HEADER_LEN + payload_len, data.len);
    return data[HEADER_LEN..end];
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/ipv6.rs:test_repr_parse]
const REPR_PACKET_BYTES = [_]u8{
    0x60, 0x00, 0x00, 0x00, // ver=6, tc=0, flow=0
    0x00, 0x0c, // payload_len=12
    0x11, // next_header=UDP
    0x40, // hop_limit=64
    // src: fe80::1
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    // dst: ff02::1
    0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    // payload (12 bytes)
    0x00, 0x01, 0x00, 0x02, 0x00, 0x0c, 0x02, 0x4e, 0xff, 0xff, 0xff, 0xff,
};

test "parse IPv6 header" {
    const repr = try parse(&REPR_PACKET_BYTES);
    try testing.expectEqual(Protocol.udp, repr.next_header);
    try testing.expectEqual(@as(u8, 64), repr.hop_limit);
    try testing.expectEqual(@as(u16, 12), repr.payload_len);
    try testing.expectEqual(Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, repr.src_addr);
    try testing.expectEqual(Address{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, repr.dst_addr);
}

test "parse IPv6 truncated" {
    try testing.expectError(error.Truncated, parse(REPR_PACKET_BYTES[0..20]));
}

test "parse IPv6 bad version" {
    var bad = REPR_PACKET_BYTES;
    bad[0] = 0x40; // version 4
    try testing.expectError(error.BadVersion, parse(&bad));
}

// [smoltcp:wire/ipv6.rs:test_repr_emit]
test "IPv6 roundtrip" {
    const repr = try parse(&REPR_PACKET_BYTES);
    var emitted: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &emitted);
    try testing.expectEqualSlices(u8, REPR_PACKET_BYTES[0..HEADER_LEN], &emitted);
}

test "IPv6 emit buffer too small" {
    var small: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, emit(.{
        .src_addr = UNSPECIFIED,
        .dst_addr = UNSPECIFIED,
        .next_header = .tcp,
        .payload_len = 0,
        .hop_limit = 64,
    }, &small));
}

test "IPv6 payload extraction" {
    const p = try payloadSlice(&REPR_PACKET_BYTES);
    try testing.expectEqual(@as(usize, 12), p.len);
    try testing.expectEqual(@as(u8, 0x00), p[0]);
}

test "IPv6 payload clamped" {
    const p = try payloadSliceClamped(&REPR_PACKET_BYTES);
    try testing.expectEqual(@as(usize, 12), p.len);
}

test "IPv6 checkLen valid" {
    try checkLen(&REPR_PACKET_BYTES);
}

test "IPv6 checkLen truncated payload" {
    try testing.expectError(error.Truncated, checkLen(REPR_PACKET_BYTES[0..HEADER_LEN]));
}

test "IPv6 address classification" {
    try testing.expect(isUnspecified(UNSPECIFIED));
    try testing.expect(!isMulticast(UNSPECIFIED));
    try testing.expect(!isLoopback(UNSPECIFIED));
    try testing.expect(!isLinkLocal(UNSPECIFIED));

    try testing.expect(isLoopback(LOOPBACK));
    try testing.expect(!isMulticast(LOOPBACK));
    try testing.expect(!isLinkLocal(LOOPBACK));

    try testing.expect(isMulticast(LINK_LOCAL_ALL_NODES));
    try testing.expect(!isLoopback(LINK_LOCAL_ALL_NODES));

    const link_local = Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expect(isLinkLocal(link_local));
    try testing.expect(!isMulticast(link_local));

    try testing.expect(!isBroadcast(Address{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }));

    const unique_local = Address{ 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expect(isUniqueLocal(unique_local));
    try testing.expect(!isGlobalUnicast(unique_local));

    const global = Address{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try testing.expect(isGlobalUnicast(global));
    try testing.expect(!isUniqueLocal(global));
}

test "IPv6 solicited-node multicast" {
    const addr = Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x56 };
    const sn = solicitedNode(addr);
    try testing.expectEqual(Address{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0x12, 0x34, 0x56 }, sn);
    try testing.expect(isSolicitedNodeMulticast(sn));
    try testing.expect(!isSolicitedNodeMulticast(addr));
}

test "IPv6 formatAddr compressed" {
    var buf: [39]u8 = undefined;
    try testing.expectEqualSlices(u8, "::", formatAddr(UNSPECIFIED, &buf));
    try testing.expectEqualSlices(u8, "::1", formatAddr(LOOPBACK, &buf));
    try testing.expectEqualSlices(u8, "ff02::1", formatAddr(LINK_LOCAL_ALL_NODES, &buf));
    try testing.expectEqualSlices(u8, "fe80::1", formatAddr(.{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &buf));
    try testing.expectEqualSlices(u8, "2001:db8::1", formatAddr(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &buf));
    // No zero compression for a single zero group
    try testing.expectEqualSlices(u8, "2001:db8:0:1:2:3:4:5", formatAddr(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5 }, &buf));
}
