// Internet checksum (RFC 1071)
//
// Used by IPv4, TCP, UDP, and ICMP. Computes the one's complement sum
// of 16-bit words, then takes the one's complement of the result.

/// Compute the internet checksum over a byte slice.
/// Returns the checksum in host byte order.
pub fn internetChecksum(data: []const u8) u16 {
    return finish(calculate(data, 0));
}

/// Accumulate checksum over a byte slice, starting from a partial sum.
/// Use this to checksum non-contiguous data (e.g., pseudo-header + payload).
pub fn calculate(data: []const u8, initial: u32) u32 {
    var sum: u32 = initial;
    var i: usize = 0;

    while (i + 1 < data.len) : (i += 2) {
        const word: u16 = (@as(u16, data[i]) << 8) | @as(u16, data[i + 1]);
        sum +%= word;
    }

    // Odd trailing byte
    if (i < data.len) {
        sum +%= @as(u32, data[i]) << 8;
    }

    return sum;
}

/// Fold a 32-bit accumulator to 16 bits and complement.
pub fn finish(sum: u32) u16 {
    var s = sum;
    while ((s >> 16) != 0) {
        s = (s & 0xFFFF) +% (s >> 16);
    }
    return @truncate(~s);
}

/// Build the IPv6 pseudo-header checksum accumulator per RFC 8200 S8.1.
/// Returns a raw u32 accumulator -- callers chain with calculate() for the
/// upper-layer payload, then finish() to get the final 16-bit checksum.
pub fn pseudoHeaderChecksumV6(
    src: [16]u8,
    dst: [16]u8,
    next_header: u8,
    upper_layer_len: u32,
) u32 {
    var pseudo: [40]u8 = undefined;
    @memcpy(pseudo[0..16], &src);
    @memcpy(pseudo[16..32], &dst);
    pseudo[32] = @truncate(upper_layer_len >> 24);
    pseudo[33] = @truncate(upper_layer_len >> 16);
    pseudo[34] = @truncate(upper_layer_len >> 8);
    pseudo[35] = @truncate(upper_layer_len);
    pseudo[36] = 0;
    pseudo[37] = 0;
    pseudo[38] = 0;
    pseudo[39] = next_header;
    return calculate(&pseudo, 0);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/mod.rs:checksum - RFC 1071 Section 3 example]
test "checksum of all zeros" {
    const data = [_]u8{ 0, 0, 0, 0 };
    try testing.expectEqual(@as(u16, 0xFFFF), internetChecksum(&data));
}

test "checksum of 0xFF bytes" {
    const data = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    try testing.expectEqual(@as(u16, 0x0000), internetChecksum(&data));
}

test "checksum odd length" {
    // Odd-length data: trailing byte padded with zero
    const data = [_]u8{ 0x00, 0x01, 0xF2 };
    const expected = internetChecksum(&data);
    // Verify by manually computing:
    // words: 0x0001, 0xF200 -> sum = 0xF201, ~sum = 0x0DFE
    try testing.expectEqual(@as(u16, 0x0DFE), expected);
}

test "checksum accumulate non-contiguous" {
    // Checksum of [A, B] should equal accumulating A then B
    const a = [_]u8{ 0x45, 0x00, 0x00, 0x28 };
    const b = [_]u8{ 0x00, 0x01, 0x00, 0x00 };

    const combined = [_]u8{ 0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00 };

    const sum_parts = calculate(&b, calculate(&a, 0));
    const sum_whole = calculate(&combined, 0);

    try testing.expectEqual(finish(sum_whole), finish(sum_parts));
}

test "IPv6 pseudo-header checksum" {
    // ICMPv6 echo from fe80::1 to ff02::1, payload len = 12
    const src = [_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const dst = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const sum = pseudoHeaderChecksumV6(src, dst, 58, 12);
    // Chain with a dummy payload and finish -- result should be a valid u16
    const payload = [_]u8{ 0x80, 0x00, 0x00, 0x00, 0x12, 0x34, 0xab, 0xcd, 0xaa, 0x00, 0x00, 0xff };
    const total = calculate(&payload, sum);
    const cksum = finish(total);
    // Verify the checksum is non-zero (valid for this input)
    try testing.expect(cksum != 0);
    // Verify round-trip: inserting the checksum into bytes 2-3 should yield 0
    var with_cksum = payload;
    with_cksum[2] = @truncate(cksum >> 8);
    with_cksum[3] = @truncate(cksum & 0xFF);
    const verify = calculate(&with_cksum, sum);
    try testing.expectEqual(@as(u16, 0), finish(verify));
}

test "IPv4 header checksum known value" {
    // Example IPv4 header (20 bytes, checksum field zeroed)
    // src=10.0.2.15 dst=10.0.2.2 proto=TCP ttl=64
    const header = [_]u8{
        0x45, 0x00, 0x00, 0x28, // version/IHL, DSCP, total length
        0x00, 0x00, 0x00, 0x00, // identification, flags/fragment
        0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP, checksum=0
        0x0A, 0x00, 0x02, 0x0F, // src = 10.0.2.15
        0x0A, 0x00, 0x02, 0x02, // dst = 10.0.2.2
    };
    const cksum = internetChecksum(&header);
    // Verify checksum is valid (non-zero for this header)
    try testing.expect(cksum != 0);

    // Verify that including the checksum in the header yields 0
    var with_cksum = header;
    with_cksum[10] = @truncate(cksum >> 8);
    with_cksum[11] = @truncate(cksum & 0xFF);
    try testing.expectEqual(@as(u16, 0), internetChecksum(&with_cksum));
}
