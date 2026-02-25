// IPv4 fragmentation support (RFC 791).
//
// Egress: Fragmenter buffers an oversized IP payload and emits it
//         as multiple fragments across poll cycles.
// Ingress: Reassembler collects fragments into a single payload buffer,
//          using the Assembler hole-tracker for out-of-order support.
//
// Single-slot design: only one packet ID can be in-flight at a time.
// If a new key arrives while another is in-progress, the old one is
// evicted. Acceptable for embedded targets where fragmentation is rare.
//
// Reference: smoltcp src/iface/fragmentation.rs

const ipv4 = @import("wire/ipv4.zig");
const ethernet = @import("wire/ethernet.zig");
const time = @import("time.zig");
const Assembler = @import("storage/assembler.zig").Assembler;

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
// Ingress reassembly
// -------------------------------------------------------------------------

pub const FragKey = struct {
    id: u16,
    src_addr: ipv4.Address,
    dst_addr: ipv4.Address,
    protocol: ipv4.Protocol,

    pub fn eql(a: FragKey, b: FragKey) bool {
        return a.id == b.id and
            std.mem.eql(u8, &a.src_addr, &b.src_addr) and
            std.mem.eql(u8, &a.dst_addr, &b.dst_addr) and
            a.protocol == b.protocol;
    }
};

pub fn isFragment(ip_repr: ipv4.Repr) bool {
    return ip_repr.more_fragments or ip_repr.fragment_offset != 0;
}

pub const ReassemblerConfig = struct {
    buffer_size: usize = 1500,
    max_segments: usize = 4,
};

pub fn Reassembler(comptime config: ReassemblerConfig) type {
    return struct {
        const Self = @This();
        const Asm = Assembler(config.max_segments);

        key: ?FragKey = null,
        buffer: [config.buffer_size]u8 = undefined,
        assembler: Asm = Asm.init(),
        total_size: ?usize = null,
        expires_at: time.Instant = time.Instant.ZERO,

        pub fn isFree(self: *const Self) bool {
            return self.key == null;
        }

        pub fn accept(self: *Self, key: FragKey, expires_at: time.Instant) void {
            if (self.key) |current| {
                if (current.eql(key)) {
                    return;
                }
            }
            self.reset();
            self.key = key;
            self.expires_at = expires_at;
        }

        pub fn add(self: *Self, data: []const u8, byte_offset: usize) bool {
            if (self.key == null) return false;
            if (byte_offset + data.len > config.buffer_size) return false;
            @memcpy(self.buffer[byte_offset..][0..data.len], data);
            self.assembler.add(byte_offset, data.len) catch return false;
            return true;
        }

        pub fn setTotalSize(self: *Self, size: usize) void {
            self.total_size = size;
        }

        pub fn assemble(self: *Self) ?[]const u8 {
            const total = self.total_size orelse return null;
            if (self.assembler.peekFront() != total) return null;
            const result = self.buffer[0..total];
            self.reset();
            return result;
        }

        pub fn removeExpired(self: *Self, now: time.Instant) void {
            if (self.key == null) return;
            if (self.expires_at.lessThan(now)) {
                self.reset();
            }
        }

        pub fn reset(self: *Self) void {
            self.key = null;
            self.assembler = Asm.init();
            self.total_size = null;
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const std = @import("std");
const testing = std.testing;

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

// -------------------------------------------------------------------------
// Reassembler tests
// -------------------------------------------------------------------------

const test_key = FragKey{
    .id = 1,
    .src_addr = .{ 10, 0, 0, 2 },
    .dst_addr = .{ 10, 0, 0, 1 },
    .protocol = .udp,
};

test "reassembler two-part assembly" {
    // [smoltcp:iface/fragmentation.rs:packet_assembler_assemble]
    const R = Reassembler(.{ .buffer_size = 64, .max_segments = 4 });
    var r = R{};
    try testing.expect(r.isFree());

    r.accept(test_key, time.Instant.fromSecs(60));
    try testing.expect(!r.isFree());

    r.setTotalSize(12);
    try testing.expect(r.add("Hello ", 0));
    try testing.expect(r.assemble() == null);

    try testing.expect(r.add("World!", 6));
    const result = r.assemble() orelse return error.ExpectedAssembly;
    try testing.expectEqualSlices(u8, "Hello World!", result);
    try testing.expect(r.isFree());
}

test "reassembler out-of-order assembly" {
    // [smoltcp:iface/fragmentation.rs:packet_assembler_out_of_order_assemble]
    const R = Reassembler(.{ .buffer_size = 64, .max_segments = 4 });
    var r = R{};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(12);

    try testing.expect(r.add("World!", 6));
    try testing.expect(r.assemble() == null);

    try testing.expect(r.add("Hello ", 0));
    const result = r.assemble() orelse return error.ExpectedAssembly;
    try testing.expectEqualSlices(u8, "Hello World!", result);
}

test "reassembler overlapping fragments" {
    // [smoltcp:iface/fragmentation.rs:packet_assembler_overlap]
    const R = Reassembler(.{ .buffer_size = 64, .max_segments = 4 });
    var r = R{};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(5);

    try testing.expect(r.add("Rust", 0));
    try testing.expect(r.add("Rust", 1));
    const result = r.assemble() orelse return error.ExpectedAssembly;
    try testing.expectEqualSlices(u8, "RRust", result);
}

test "reassembler expiry" {
    const R = Reassembler(.{ .buffer_size = 64, .max_segments = 4 });
    var r = R{};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(6);
    try testing.expect(r.add("abc", 0));
    try testing.expect(!r.isFree());

    // Not expired at t=30s.
    r.removeExpired(time.Instant.fromSecs(30));
    try testing.expect(!r.isFree());

    // Expired at t=61s.
    r.removeExpired(time.Instant.fromSecs(61));
    try testing.expect(r.isFree());
}

test "reassembler eviction on new key" {
    const R = Reassembler(.{ .buffer_size = 64, .max_segments = 4 });
    var r = R{};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(6);
    try testing.expect(r.add("abc", 0));

    // New key evicts old.
    const key2 = FragKey{
        .id = 2,
        .src_addr = .{ 10, 0, 0, 3 },
        .dst_addr = .{ 10, 0, 0, 1 },
        .protocol = .tcp,
    };
    r.accept(key2, time.Instant.fromSecs(120));

    // Old partial assembly is gone; new slot is clean.
    try testing.expect(r.assemble() == null);
    try testing.expect(!r.isFree());

    // Complete the new key's payload.
    r.setTotalSize(4);
    try testing.expect(r.add("ABCD", 0));
    const result = r.assemble() orelse return error.ExpectedAssembly;
    try testing.expectEqualSlices(u8, "ABCD", result);
}

test "reassembler buffer overflow" {
    const R = Reassembler(.{ .buffer_size = 8, .max_segments = 4 });
    var r = R{};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(16);

    // First add fits.
    try testing.expect(r.add("12345678", 0));
    // Second add exceeds buffer -- rejected.
    try testing.expect(!r.add("overflow!", 8));
}
