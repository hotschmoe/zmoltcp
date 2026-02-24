// IPv4 fragmentation support (RFC 791).
//
// Egress: Fragmenter buffers an oversized IP payload and emits it
//         as multiple fragments across poll cycles.
// Ingress: Reassembly is not yet implemented.
//
// Reference: smoltcp src/iface/fragmentation.rs

const ipv4 = @import("wire/ipv4.zig");
const ethernet = @import("wire/ethernet.zig");

/// Fragment payloads must be multiples of 8 bytes (except the last).
pub const IPV4_FRAGMENT_ALIGNMENT: usize = 8;

/// Compute the maximum fragment payload size (excluding IP header),
/// aligned to 8-byte boundary per RFC 791.
pub fn maxIpv4FragmentPayload(ip_header_len: usize, ip_mtu: usize) usize {
    const payload_mtu = ip_mtu - ip_header_len;
    return payload_mtu - (payload_mtu % IPV4_FRAGMENT_ALIGNMENT);
}

/// Holds one oversized IP payload being fragmented across poll cycles.
pub fn Fragmenter(comptime buffer_size: usize) type {
    return struct {
        const Self = @This();

        buffer: [buffer_size]u8 = undefined,
        payload_len: usize = 0,
        sent_bytes: usize = 0,
        frag_offset: u16 = 0,
        ident: u16 = 0,

        src_addr: ipv4.Address = ipv4.UNSPECIFIED,
        dst_addr: ipv4.Address = ipv4.UNSPECIFIED,
        protocol: ipv4.Protocol = .tcp,
        hop_limit: u8 = 64,
        dst_mac: ethernet.Address = .{ 0, 0, 0, 0, 0, 0 },

        pub fn isEmpty(self: *const Self) bool {
            return self.payload_len == 0;
        }

        pub fn finished(self: *const Self) bool {
            return self.payload_len > 0 and self.sent_bytes >= self.payload_len;
        }

        pub fn reset(self: *Self) void {
            self.payload_len = 0;
            self.sent_bytes = 0;
            self.frag_offset = 0;
        }

        /// Stage a payload for fragmentation. Returns false if too large.
        pub fn stage(
            self: *Self,
            payload: []const u8,
            src_addr: ipv4.Address,
            dst_addr: ipv4.Address,
            protocol: ipv4.Protocol,
            hop_limit: u8,
            ident: u16,
            dst_mac: ethernet.Address,
        ) bool {
            if (payload.len > buffer_size) return false;
            @memcpy(self.buffer[0..payload.len], payload);
            self.payload_len = payload.len;
            self.sent_bytes = 0;
            self.frag_offset = 0;
            self.ident = ident;
            self.src_addr = src_addr;
            self.dst_addr = dst_addr;
            self.protocol = protocol;
            self.hop_limit = hop_limit;
            self.dst_mac = dst_mac;
            return true;
        }

        /// Emit the next fragment into buf. Returns bytes written, or null
        /// if no pending fragment or buffer too small.
        pub fn emitNext(
            self: *Self,
            buf: []u8,
            hw_addr: ethernet.Address,
            ip_mtu: usize,
        ) ?usize {
            if (self.isEmpty() or self.finished()) return null;

            const remaining = self.payload_len - self.sent_bytes;
            const max_frag = maxIpv4FragmentPayload(ipv4.HEADER_LEN, ip_mtu);
            const this_payload = @min(remaining, max_frag);
            const more_frags = (remaining != this_payload);

            const total = ethernet.HEADER_LEN + ipv4.HEADER_LEN + this_payload;
            if (buf.len < total) return null;

            const eth_len = ethernet.emit(.{
                .dst_addr = self.dst_mac,
                .src_addr = hw_addr,
                .ethertype = .ipv4,
            }, buf) catch return null;

            const ip_repr = ipv4.Repr{
                .version = 4,
                .ihl = 5,
                .dscp_ecn = 0,
                .total_length = @intCast(ipv4.HEADER_LEN + this_payload),
                .identification = self.ident,
                .dont_fragment = false,
                .more_fragments = more_frags,
                .fragment_offset = @intCast(self.frag_offset / IPV4_FRAGMENT_ALIGNMENT),
                .ttl = self.hop_limit,
                .protocol = self.protocol,
                .checksum = 0,
                .src_addr = self.src_addr,
                .dst_addr = self.dst_addr,
            };
            _ = ipv4.emit(ip_repr, buf[eth_len..]) catch return null;

            @memcpy(
                buf[eth_len + ipv4.HEADER_LEN ..][0..this_payload],
                self.buffer[self.sent_bytes..][0..this_payload],
            );

            self.sent_bytes += this_payload;
            self.frag_offset += @intCast(this_payload);

            return total;
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

test "maxIpv4FragmentPayload alignment" {
    // For each possible header len variation, result must be 8-aligned.
    var i: usize = 0;
    while (i < IPV4_FRAGMENT_ALIGNMENT) : (i += 1) {
        const result = maxIpv4FragmentPayload(ipv4.HEADER_LEN + i, 1500);
        try testing.expect(result % IPV4_FRAGMENT_ALIGNMENT == 0);
        try testing.expect(result > 0);
    }

    // Standard case: MTU=1500, header=20 -> payload_mtu=1480, already aligned.
    try testing.expectEqual(@as(usize, 1480), maxIpv4FragmentPayload(20, 1500));
    // header=21 -> payload_mtu=1479, aligned down to 1472.
    try testing.expectEqual(@as(usize, 1472), maxIpv4FragmentPayload(21, 1500));
}

test "fragmenter stage and emit" {
    const Frag = Fragmenter(4096);
    var f = Frag{};
    try testing.expect(f.isEmpty());

    // Stage a 3000-byte payload (exceeds IP_PAYLOAD_MAX of 1480).
    var payload: [3000]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    const hw = ethernet.Address{ 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
    const src = ipv4.Address{ 10, 0, 0, 1 };
    const dst = ipv4.Address{ 10, 0, 0, 2 };
    const dst_mac = ethernet.Address{ 0x52, 0x54, 0x00, 0x00, 0x00, 0x01 };

    try testing.expect(f.stage(&payload, src, dst, .udp, 64, 42, dst_mac));
    try testing.expect(!f.isEmpty());
    try testing.expect(!f.finished());

    const ip_mtu: usize = 1500;
    const max_frag = maxIpv4FragmentPayload(ipv4.HEADER_LEN, ip_mtu);
    var frame_buf: [1514]u8 = undefined;

    // First fragment.
    const len1 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    try testing.expect(len1 <= 1514);
    try testing.expectEqual(ethernet.HEADER_LEN + ipv4.HEADER_LEN + max_frag, len1);
    try testing.expect(!f.finished());

    // Second fragment.
    const len2 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    try testing.expect(len2 <= 1514);
    try testing.expect(!f.finished());

    // Third (last) fragment -- remaining bytes.
    const len3 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    try testing.expect(len3 <= 1514);
    const expected_last = 3000 - 2 * max_frag;
    try testing.expectEqual(ethernet.HEADER_LEN + ipv4.HEADER_LEN + expected_last, len3);
    try testing.expect(f.finished());

    // No more fragments.
    try testing.expect(f.emitNext(&frame_buf, hw, ip_mtu) == null);
}
