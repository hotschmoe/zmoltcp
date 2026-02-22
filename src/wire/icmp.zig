// ICMPv4 parsing and serialization.
//
// Reference: RFC 792, smoltcp src/wire/icmpv4.rs

const checksum_mod = @import("checksum.zig");

pub const HEADER_LEN = 8; // Type + Code + Checksum + 4 bytes data/id+seq

pub const Type = enum(u8) {
    echo_reply = 0,
    dest_unreachable = 3,
    source_quench = 4,
    redirect = 5,
    echo_request = 8,
    time_exceeded = 11,
    parameter_problem = 12,
    timestamp = 13,
    timestamp_reply = 14,
    _,
};

/// High-level representation of an ICMP message.
/// Only echo request/reply are fully parsed; others provide raw data.
pub const Repr = union(enum) {
    echo: EchoRepr,
    other: OtherRepr,
};

pub const EchoRepr = struct {
    icmp_type: Type, // echo_request or echo_reply
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
};

pub const OtherRepr = struct {
    icmp_type: Type,
    code: u8,
    checksum: u16,
    data: u32, // type-specific 4-byte field
};

/// Parse an ICMP message from raw bytes (after IP header).
pub fn parse(data: []const u8) error{Truncated}!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;

    const icmp_type: Type = @enumFromInt(data[0]);
    const code = data[1];
    const cksum: u16 = @as(u16, data[2]) << 8 | @as(u16, data[3]);

    switch (icmp_type) {
        .echo_request, .echo_reply => {
            return .{ .echo = .{
                .icmp_type = icmp_type,
                .code = code,
                .checksum = cksum,
                .identifier = @as(u16, data[4]) << 8 | @as(u16, data[5]),
                .sequence = @as(u16, data[6]) << 8 | @as(u16, data[7]),
            } };
        },
        else => {
            return .{ .other = .{
                .icmp_type = icmp_type,
                .code = code,
                .checksum = cksum,
                .data = @as(u32, data[4]) << 24 | @as(u32, data[5]) << 16 |
                    @as(u32, data[6]) << 8 | @as(u32, data[7]),
            } };
        },
    }
}

/// Serialize an ICMP echo request/reply into a buffer.
/// Computes checksum over the entire ICMP message (header + payload).
pub fn emitEcho(repr: EchoRepr, payload_data: []const u8, buf: []u8) error{BufferTooSmall}!usize {
    const total = HEADER_LEN + payload_data.len;
    if (buf.len < total) return error.BufferTooSmall;

    buf[0] = @intFromEnum(repr.icmp_type);
    buf[1] = repr.code;
    // Checksum zeroed before computation
    buf[2] = 0;
    buf[3] = 0;
    buf[4] = @truncate(repr.identifier >> 8);
    buf[5] = @truncate(repr.identifier & 0xFF);
    buf[6] = @truncate(repr.sequence >> 8);
    buf[7] = @truncate(repr.sequence & 0xFF);

    @memcpy(buf[HEADER_LEN..][0..payload_data.len], payload_data);

    // Compute checksum over entire message
    const cksum = checksum_mod.internetChecksum(buf[0..total]);
    buf[2] = @truncate(cksum >> 8);
    buf[3] = @truncate(cksum & 0xFF);

    return total;
}

/// Verify ICMP checksum. Returns true if valid.
pub fn verifyChecksum(data: []const u8) bool {
    if (data.len < HEADER_LEN) return false;
    return checksum_mod.internetChecksum(data) == 0;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/icmpv4.rs:test_parse_echo_request]
test "parse ICMP echo request" {
    const data = [_]u8{
        0x08, // type = echo request
        0x00, // code = 0
        0x00, 0x00, // checksum (not verified here)
        0xAB, 0xCD, // identifier
        0x00, 0x01, // sequence = 1
    };
    const repr = try parse(&data);
    switch (repr) {
        .echo => |echo| {
            try testing.expectEqual(Type.echo_request, echo.icmp_type);
            try testing.expectEqual(@as(u16, 0xABCD), echo.identifier);
            try testing.expectEqual(@as(u16, 1), echo.sequence);
        },
        .other => return error.UnexpectedVariant,
    }
}

test "parse ICMP dest unreachable" {
    const data = [_]u8{
        0x03, // type = dest_unreachable
        0x01, // code = host unreachable
        0x00, 0x00, // checksum
        0x00, 0x00, 0x00, 0x00, // unused
    };
    const repr = try parse(&data);
    switch (repr) {
        .other => |other| {
            try testing.expectEqual(Type.dest_unreachable, other.icmp_type);
            try testing.expectEqual(@as(u8, 1), other.code);
        },
        .echo => return error.UnexpectedVariant,
    }
}

test "ICMP echo emit with valid checksum" {
    const echo = EchoRepr{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0xABCD,
        .sequence = 1,
    };
    const payload_data = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    var buf: [12]u8 = undefined;
    const len = try emitEcho(echo, &payload_data, &buf);
    try testing.expectEqual(@as(usize, 12), len);

    // Verify checksum
    try testing.expect(verifyChecksum(buf[0..len]));
}

test "ICMP echo roundtrip" {
    const echo = EchoRepr{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = 0x1234,
        .sequence = 42,
    };
    var buf: [HEADER_LEN]u8 = undefined;
    _ = try emitEcho(echo, &[_]u8{}, &buf);

    const parsed = try parse(&buf);
    switch (parsed) {
        .echo => |e| {
            try testing.expectEqual(Type.echo_request, e.icmp_type);
            try testing.expectEqual(@as(u16, 0x1234), e.identifier);
            try testing.expectEqual(@as(u16, 42), e.sequence);
        },
        .other => return error.UnexpectedVariant,
    }
}
