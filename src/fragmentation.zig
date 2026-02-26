// IP fragmentation support (RFC 791 egress, RFC 815 ingress reassembly).
//
// Egress: Fragmenter buffers an oversized payload, emitting fragments
//         across poll cycles.
// Ingress: Reassembler collects fragments into a contiguous buffer using
//          the Assembler hole-tracker for out-of-order support.
//
// Single-slot design: one packet ID in-flight at a time. New keys evict
// in-progress reassembly. Acceptable for embedded targets.
//
// Reference: smoltcp src/iface/fragmentation.rs

const std = @import("std");
const ipv4 = @import("wire/ipv4.zig");
const ipv6 = @import("wire/ipv6.zig");
const ipv6fragment = @import("wire/ipv6fragment.zig");
const ethernet = @import("wire/ethernet.zig");
const ieee802154 = @import("wire/ieee802154.zig");
const sixlowpan_frag = @import("wire/sixlowpan_frag.zig");
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

/// Buffers one oversized IP payload, emitting fragments across poll cycles.
/// When `emit_ethernet` is false, fragments are emitted as raw IP packets
/// (no Ethernet header) for Medium::Ip devices.
pub fn Fragmenter(comptime buffer_size: usize, comptime emit_ethernet: bool) type {
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

            const frame_overhead = if (comptime emit_ethernet) ethernet.HEADER_LEN else 0;
            const total = frame_overhead + ipv4.HEADER_LEN + this_payload;
            if (buf.len < total) return null;

            var pos: usize = 0;
            if (comptime emit_ethernet) {
                pos += ethernet.emit(.{
                    .dst_addr = self.dst_mac,
                    .src_addr = hw_addr,
                    .ethertype = .ipv4,
                }, buf) catch return null;
            }

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
            _ = ipv4.emit(ip_repr, buf[pos..]) catch return null;

            @memcpy(
                buf[pos + ipv4.HEADER_LEN ..][0..this_payload],
                self.buffer[self.sent_bytes..][0..this_payload],
            );

            self.sent_bytes += this_payload;
            self.frag_offset += @intCast(this_payload);

            return total;
        }
    };
}

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

pub const FragKeyV6 = struct {
    id: u32,
    src_addr: ipv6.Address,
    dst_addr: ipv6.Address,

    pub fn eql(a: FragKeyV6, b: FragKeyV6) bool {
        return a.id == b.id and
            std.mem.eql(u8, &a.src_addr, &b.src_addr) and
            std.mem.eql(u8, &a.dst_addr, &b.dst_addr);
    }
};

pub fn isFragmentV6(frag_repr: ipv6fragment.Repr) bool {
    return frag_repr.more_frags or frag_repr.frag_offset != 0;
}

/// Reassembly key for 6LoWPAN fragmented datagrams (RFC 4944 S5.3).
pub const FragKey6LoWPAN = struct {
    datagram_tag: u16,
    datagram_size: u16,
    ll_src_addr: [8]u8, // normalized to EUI-64
    ll_dst_addr: [8]u8,

    pub fn eql(a: FragKey6LoWPAN, b: FragKey6LoWPAN) bool {
        return a.datagram_tag == b.datagram_tag and
            a.datagram_size == b.datagram_size and
            std.mem.eql(u8, &a.ll_src_addr, &b.ll_src_addr) and
            std.mem.eql(u8, &a.ll_dst_addr, &b.ll_dst_addr);
    }

    pub fn fromAddrs(
        src: ieee802154.Address,
        dst: ieee802154.Address,
        tag: u16,
        size: u16,
    ) FragKey6LoWPAN {
        return .{
            .datagram_tag = tag,
            .datagram_size = size,
            .ll_src_addr = src.asEui64(),
            .ll_dst_addr = dst.asEui64(),
        };
    }
};

/// Buffers one 6LoWPAN compressed payload for fragmented egress via
/// IEEE 802.15.4 frames.
pub fn SixlowpanFragmenter(comptime buffer_size: usize) type {
    return struct {
        const Self = @This();

        buffer: [buffer_size]u8 = undefined,
        packet_len: usize = 0,
        sent_bytes: usize = 0,
        datagram_size: u16 = 0,
        datagram_tag: u16 = 0,

        ll_src_addr: ieee802154.Address = .absent,
        ll_dst_addr: ieee802154.Address = .absent,
        pan_id: ?u16 = null,
        header_diff: usize = 0, // uncompressed_hdr_size - compressed_hdr_size

        pub fn isEmpty(self: *const Self) bool {
            return self.packet_len == 0;
        }

        pub fn finished(self: *const Self) bool {
            return self.packet_len > 0 and self.sent_bytes >= self.packet_len;
        }

        pub fn reset(self: *Self) void {
            self.packet_len = 0;
            self.sent_bytes = 0;
        }

        pub fn stage(
            self: *Self,
            compressed: []const u8,
            datagram_size: u16,
            datagram_tag: u16,
            header_diff: usize,
            ll_src: ieee802154.Address,
            ll_dst: ieee802154.Address,
            pan_id: ?u16,
        ) bool {
            if (compressed.len > buffer_size) return false;
            @memcpy(self.buffer[0..compressed.len], compressed);
            self.packet_len = compressed.len;
            self.sent_bytes = 0;
            self.datagram_size = datagram_size;
            self.datagram_tag = datagram_tag;
            self.header_diff = header_diff;
            self.ll_src_addr = ll_src;
            self.ll_dst_addr = ll_dst;
            self.pan_id = pan_id;
            return true;
        }

        pub fn emitNext(
            self: *Self,
            buf: []u8,
            seq_no: u8,
        ) ?usize {
            if (self.isEmpty() or self.finished()) return null;

            const is_first = self.sent_bytes == 0;
            const frag_hdr_len: usize = if (is_first)
                sixlowpan_frag.FIRST_FRAGMENT_HEADER_SIZE
            else
                sixlowpan_frag.NEXT_FRAGMENT_HEADER_SIZE;

            const mac_repr = ieee802154.Repr{
                .frame_type = .data,
                .frame_version = .ieee802154_2003,
                .security = false,
                .frame_pending = false,
                .ack_request = false,
                .pan_id_compression = self.pan_id != null,
                .sequence_number = seq_no,
                .dst_pan_id = self.pan_id,
                .dst_addr = self.ll_dst_addr,
                .src_pan_id = null,
                .src_addr = self.ll_src_addr,
            };
            const mac_len = ieee802154.bufferLen(mac_repr);

            const budget = ieee802154.MAX_FRAME_LEN - mac_len - frag_hdr_len;
            const max_payload = budget - (budget % 8);

            const remaining = self.packet_len - self.sent_bytes;
            const this_payload = @min(remaining, max_payload);
            const total = mac_len + frag_hdr_len + this_payload;
            if (buf.len < total) return null;

            var pos = ieee802154.emit(mac_repr, buf) catch return null;

            const frag_repr: sixlowpan_frag.Repr = if (is_first)
                .{ .first_fragment = .{
                    .datagram_size = self.datagram_size,
                    .datagram_tag = self.datagram_tag,
                } }
            else
                .{ .next_fragment = .{
                    .datagram_size = self.datagram_size,
                    .datagram_tag = self.datagram_tag,
                    // Offset accounts for header size difference (uncompressed - compressed).
                    .datagram_offset = @intCast((self.sent_bytes + self.header_diff) / 8),
                } };
            pos += sixlowpan_frag.emit(frag_repr, buf[pos..]) catch return null;

            @memcpy(buf[pos..][0..this_payload], self.buffer[self.sent_bytes..][0..this_payload]);
            self.sent_bytes += this_payload;

            return pos + this_payload;
        }
    };
}

pub const ReassemblerConfig = struct {
    buffer_size: usize = 1500,
    max_segments: usize = 4,
};

pub fn Reassembler(comptime Key: type, comptime config: ReassemblerConfig) type {
    return struct {
        const Self = @This();
        const Asm = Assembler(config.max_segments);

        key: ?Key = null,
        buffer: [config.buffer_size]u8 = undefined,
        assembler: Asm = Asm.init(),
        total_size: ?usize = null,
        expires_at: time.Instant = time.Instant.ZERO,

        pub fn isFree(self: *const Self) bool {
            return self.key == null;
        }

        pub fn accept(self: *Self, key: Key, expires_at: time.Instant) void {
            if (self.key) |current| if (current.eql(key)) return;
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

const testing = std.testing;

test "maxIpv4FragmentPayload alignment" {
    var i: usize = 0;
    while (i < IPV4_FRAGMENT_ALIGNMENT) : (i += 1) {
        const result = maxIpv4FragmentPayload(ipv4.HEADER_LEN + i, 1500);
        try testing.expect(result % IPV4_FRAGMENT_ALIGNMENT == 0);
        try testing.expect(result > 0);
    }

    try testing.expectEqual(@as(usize, 1480), maxIpv4FragmentPayload(20, 1500));
    try testing.expectEqual(@as(usize, 1472), maxIpv4FragmentPayload(21, 1500));
}

test "fragmenter stage and emit" {
    const Frag = Fragmenter(4096, true);
    var f = Frag{};
    try testing.expect(f.isEmpty());

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

    const len1 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    try testing.expect(len1 <= 1514);
    try testing.expectEqual(ethernet.HEADER_LEN + ipv4.HEADER_LEN + max_frag, len1);
    try testing.expect(!f.finished());

    const len2 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    try testing.expect(len2 <= 1514);
    try testing.expect(!f.finished());

    const len3 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    try testing.expect(len3 <= 1514);
    const expected_last = 3000 - 2 * max_frag;
    try testing.expectEqual(ethernet.HEADER_LEN + ipv4.HEADER_LEN + expected_last, len3);
    try testing.expect(f.finished());

    try testing.expect(f.emitNext(&frame_buf, hw, ip_mtu) == null);
}

const TestReassembler = Reassembler(FragKey, .{ .buffer_size = 64, .max_segments = 4 });

const test_key = FragKey{
    .id = 1,
    .src_addr = .{ 10, 0, 0, 2 },
    .dst_addr = .{ 10, 0, 0, 1 },
    .protocol = .udp,
};

test "reassembler two-part assembly" {
    // [smoltcp:iface/fragmentation.rs:packet_assembler_assemble]
    var r = TestReassembler{};
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
    var r = TestReassembler{};

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
    var r = TestReassembler{};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(5);

    try testing.expect(r.add("Rust", 0));
    try testing.expect(r.add("Rust", 1));
    const result = r.assemble() orelse return error.ExpectedAssembly;
    try testing.expectEqualSlices(u8, "RRust", result);
}

test "reassembler expiry" {
    var r = TestReassembler{};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(6);
    try testing.expect(r.add("abc", 0));
    try testing.expect(!r.isFree());

    r.removeExpired(time.Instant.fromSecs(30));
    try testing.expect(!r.isFree());

    r.removeExpired(time.Instant.fromSecs(61));
    try testing.expect(r.isFree());
}

test "reassembler eviction on new key" {
    var r = TestReassembler{};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(6);
    try testing.expect(r.add("abc", 0));

    const key2 = FragKey{
        .id = 2,
        .src_addr = .{ 10, 0, 0, 3 },
        .dst_addr = .{ 10, 0, 0, 1 },
        .protocol = .tcp,
    };
    r.accept(key2, time.Instant.fromSecs(120));

    try testing.expect(r.assemble() == null);
    try testing.expect(!r.isFree());

    r.setTotalSize(4);
    try testing.expect(r.add("ABCD", 0));
    const result = r.assemble() orelse return error.ExpectedAssembly;
    try testing.expectEqualSlices(u8, "ABCD", result);
}

test "reassembler buffer overflow" {
    var r = Reassembler(FragKey, .{ .buffer_size = 8, .max_segments = 4 }){};

    r.accept(test_key, time.Instant.fromSecs(60));
    r.setTotalSize(16);

    try testing.expect(r.add("12345678", 0));
    try testing.expect(!r.add("overflow!", 8));
}

test "FragKeyV6 equality" {
    const key_a = FragKeyV6{
        .id = 0x12345678,
        .src_addr = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .dst_addr = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
    };
    const key_b = key_a;
    try testing.expect(key_a.eql(key_b));

    var key_c = key_a;
    key_c.id = 0xDEADBEEF;
    try testing.expect(!key_a.eql(key_c));

    var key_d = key_a;
    key_d.src_addr[15] = 0xFF;
    try testing.expect(!key_a.eql(key_d));
}

test "reassembler with v6 keys" {
    const TestV6Reassembler = Reassembler(FragKeyV6, .{ .buffer_size = 64, .max_segments = 4 });
    var r = TestV6Reassembler{};
    try testing.expect(r.isFree());

    const key = FragKeyV6{
        .id = 42,
        .src_addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .dst_addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
    };

    r.accept(key, time.Instant.fromSecs(60));
    try testing.expect(!r.isFree());

    r.setTotalSize(12);
    try testing.expect(r.add("Hello ", 0));
    try testing.expect(r.assemble() == null);

    try testing.expect(r.add("World!", 6));
    const result = r.assemble() orelse return error.ExpectedAssembly;
    try testing.expectEqualSlices(u8, "Hello World!", result);
    try testing.expect(r.isFree());
}

test "isFragmentV6" {
    try testing.expect(!isFragmentV6(.{
        .next_header = 6,
        .frag_offset = 0,
        .more_frags = false,
        .ident = 0,
    }));
    try testing.expect(isFragmentV6(.{
        .next_header = 6,
        .frag_offset = 0,
        .more_frags = true,
        .ident = 0,
    }));
    try testing.expect(isFragmentV6(.{
        .next_header = 6,
        .frag_offset = 100,
        .more_frags = false,
        .ident = 0,
    }));
}

test "Fragmenter emit_ethernet=false raw IP output" {
    const Frag = Fragmenter(4096, false);
    var f = Frag{};
    try testing.expect(f.isEmpty());

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

    const len1 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(ipv4.HEADER_LEN + max_frag, len1);
    try testing.expectEqual(@as(u8, 0x45), frame_buf[0]);
    try testing.expect(!f.finished());

    const len2 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    try testing.expect(len2 <= 1514);
    try testing.expect(!f.finished());

    const len3 = f.emitNext(&frame_buf, hw, ip_mtu) orelse return error.TestUnexpectedResult;
    const expected_last = 3000 - 2 * max_frag;
    try testing.expectEqual(ipv4.HEADER_LEN + expected_last, len3);
    try testing.expect(f.finished());

    try testing.expect(f.emitNext(&frame_buf, hw, ip_mtu) == null);
}

test "FragKey6LoWPAN equality" {
    const src = ieee802154.Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 } };
    const dst = ieee802154.Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf } };

    const key_a = FragKey6LoWPAN.fromAddrs(src, dst, 0x003f, 307);
    const key_b = FragKey6LoWPAN.fromAddrs(src, dst, 0x003f, 307);
    try testing.expect(key_a.eql(key_b));

    const key_c = FragKey6LoWPAN.fromAddrs(src, dst, 0x0040, 307);
    try testing.expect(!key_a.eql(key_c));

    const key_d = FragKey6LoWPAN.fromAddrs(src, dst, 0x003f, 308);
    try testing.expect(!key_a.eql(key_d));
}

test "FragKey6LoWPAN from short address" {
    const src = ieee802154.Address{ .short = .{ 0xab, 0xcd } };
    const key = FragKey6LoWPAN.fromAddrs(src, .absent, 42, 100);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0xff, 0xfe, 0, 0xab, 0xcd }, &key.ll_src_addr);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, &key.ll_dst_addr);
}

test "reassembler with 6LoWPAN keys" {
    const TestReassembler6L = Reassembler(FragKey6LoWPAN, .{ .buffer_size = 256, .max_segments = 4 });
    var r = TestReassembler6L{};
    try testing.expect(r.isFree());

    const src = ieee802154.Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 } };
    const dst = ieee802154.Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf } };
    const key = FragKey6LoWPAN.fromAddrs(src, dst, 0x003f, 12);

    r.accept(key, time.Instant.fromSecs(60));
    try testing.expect(!r.isFree());

    r.setTotalSize(12);
    try testing.expect(r.add("Hello ", 0));
    try testing.expect(r.assemble() == null);

    try testing.expect(r.add("World!", 6));
    const result = r.assemble() orelse return error.ExpectedAssembly;
    try testing.expectEqualSlices(u8, "Hello World!", result);
    try testing.expect(r.isFree());
}

test "SixlowpanFragmenter stage and emit" {
    const Frag = SixlowpanFragmenter(1500);
    var f = Frag{};
    try testing.expect(f.isEmpty());

    var payload: [300]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    const src_ll = ieee802154.Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 } };
    const dst_ll = ieee802154.Address{ .short = .{ 0xff, 0xff } };

    try testing.expect(f.stage(&payload, 340, 0x1234, 40, src_ll, dst_ll, 0xabcd));
    try testing.expect(!f.isEmpty());
    try testing.expect(!f.finished());

    var frame_buf: [128]u8 = undefined;
    var frag_count: usize = 0;

    while (!f.finished()) {
        const len = f.emitNext(&frame_buf, @truncate(frag_count)) orelse break;
        try testing.expect(len <= ieee802154.MAX_FRAME_LEN);
        frag_count += 1;
    }

    try testing.expect(frag_count >= 3);
    try testing.expect(f.finished());
}
