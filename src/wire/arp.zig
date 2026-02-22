// ARP (Address Resolution Protocol) parsing and serialization.
//
// Reference: RFC 826, smoltcp src/wire/arp.rs
// Only supports Ethernet + IPv4 (hardware type 1, protocol type 0x0800).

const ethernet = @import("ethernet.zig");

pub const HEADER_LEN = 28;

pub const HardwareType = enum(u16) {
    ethernet = 1,
    _,
};

pub const Operation = enum(u16) {
    request = 1,
    reply = 2,
    _,
};

/// High-level representation of an ARP packet (Ethernet + IPv4 only).
pub const Repr = struct {
    operation: Operation,
    source_hardware_addr: ethernet.Address,
    source_protocol_addr: [4]u8,
    target_hardware_addr: ethernet.Address,
    target_protocol_addr: [4]u8,
};

/// Parse an ARP packet from raw bytes (after Ethernet header).
pub fn parse(data: []const u8) error{ Truncated, UnsupportedHardware, UnsupportedProtocol }!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;

    // Hardware type must be Ethernet (1)
    const hw_type: u16 = @as(u16, data[0]) << 8 | @as(u16, data[1]);
    if (hw_type != 1) return error.UnsupportedHardware;

    // Protocol type must be IPv4 (0x0800)
    const proto_type: u16 = @as(u16, data[2]) << 8 | @as(u16, data[3]);
    if (proto_type != 0x0800) return error.UnsupportedProtocol;

    const operation: u16 = @as(u16, data[6]) << 8 | @as(u16, data[7]);

    return .{
        .operation = @enumFromInt(operation),
        .source_hardware_addr = data[8..14].*,
        .source_protocol_addr = data[14..18].*,
        .target_hardware_addr = data[18..24].*,
        .target_protocol_addr = data[24..28].*,
    };
}

/// Serialize an ARP packet into a buffer.
pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    if (buf.len < HEADER_LEN) return error.BufferTooSmall;

    // Hardware type: Ethernet
    buf[0] = 0x00;
    buf[1] = 0x01;
    // Protocol type: IPv4
    buf[2] = 0x08;
    buf[3] = 0x00;
    // Hardware address length
    buf[4] = 6;
    // Protocol address length
    buf[5] = 4;
    // Operation
    buf[6] = @truncate(@intFromEnum(repr.operation) >> 8);
    buf[7] = @truncate(@intFromEnum(repr.operation) & 0xFF);
    // Addresses
    @memcpy(buf[8..14], &repr.source_hardware_addr);
    @memcpy(buf[14..18], &repr.source_protocol_addr);
    @memcpy(buf[18..24], &repr.target_hardware_addr);
    @memcpy(buf[24..28], &repr.target_protocol_addr);

    return HEADER_LEN;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

const SAMPLE_ARP_REQUEST = [_]u8{
    0x00, 0x01, // hardware type: Ethernet
    0x08, 0x00, // protocol type: IPv4
    0x06, // hardware addr len
    0x04, // protocol addr len
    0x00, 0x01, // operation: request
    0x52, 0x54, 0x00, 0x12, 0x34, 0x56, // sender MAC
    0x0A, 0x00, 0x02, 0x0F, // sender IP: 10.0.2.15
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (unknown)
    0x0A, 0x00, 0x02, 0x02, // target IP: 10.0.2.2
};

// [smoltcp:wire/arp.rs:test_parse]
test "parse ARP request" {
    const repr = try parse(&SAMPLE_ARP_REQUEST);
    try testing.expectEqual(Operation.request, repr.operation);
    try testing.expectEqual([4]u8{ 0x0A, 0x00, 0x02, 0x0F }, repr.source_protocol_addr);
    try testing.expectEqual([4]u8{ 0x0A, 0x00, 0x02, 0x02 }, repr.target_protocol_addr);
}

test "parse ARP truncated" {
    try testing.expectError(error.Truncated, parse(SAMPLE_ARP_REQUEST[0..10]));
}

test "parse ARP unsupported hardware" {
    var bad = SAMPLE_ARP_REQUEST;
    bad[1] = 0x06; // not Ethernet
    try testing.expectError(error.UnsupportedHardware, parse(&bad));
}

// [smoltcp:wire/arp.rs:roundtrip]
test "ARP roundtrip" {
    const repr = try parse(&SAMPLE_ARP_REQUEST);
    var emitted: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &emitted);
    try testing.expectEqualSlices(u8, &SAMPLE_ARP_REQUEST, &emitted);
}

test "emit ARP reply" {
    const repr = Repr{
        .operation = .reply,
        .source_hardware_addr = .{ 0x52, 0x55, 0x0A, 0x00, 0x02, 0x02 },
        .source_protocol_addr = .{ 0x0A, 0x00, 0x02, 0x02 },
        .target_hardware_addr = .{ 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 },
        .target_protocol_addr = .{ 0x0A, 0x00, 0x02, 0x0F },
    };
    var buf: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqual(@as(u8, 0x00), buf[6]); // operation high byte
    try testing.expectEqual(@as(u8, 0x02), buf[7]); // operation low byte = reply
}
