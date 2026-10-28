//! Executable laws (zirakzigil) for the wire parsers, sequence numbers and
//! storage. Imported only from root.zig's test block;
//! run by `zig build test`.

const std = @import("std");
const zv = @import("zv");

const arp = @import("wire/arp.zig");
const dhcp = @import("wire/dhcp.zig");
const dns = @import("wire/dns.zig");
const ethernet = @import("wire/ethernet.zig");
const icmp = @import("wire/icmp.zig");
const icmpv6 = @import("wire/icmpv6.zig");
const ieee802154 = @import("wire/ieee802154.zig");
const igmp = @import("wire/igmp.zig");
const ipsec_ah = @import("wire/ipsec_ah.zig");
const ipsec_esp = @import("wire/ipsec_esp.zig");
const ipv4 = @import("wire/ipv4.zig");
const ipv6 = @import("wire/ipv6.zig");
const ipv6ext_header = @import("wire/ipv6ext_header.zig");
const ipv6fragment = @import("wire/ipv6fragment.zig");
const ipv6hbh = @import("wire/ipv6hbh.zig");
const ipv6option = @import("wire/ipv6option.zig");
const ipv6routing = @import("wire/ipv6routing.zig");
const mld = @import("wire/mld.zig");
const ndisc = @import("wire/ndisc.zig");
const ndiscoption = @import("wire/ndiscoption.zig");
const rpl = @import("wire/rpl.zig");
const sixlowpan = @import("wire/sixlowpan.zig");
const sixlowpan_frag = @import("wire/sixlowpan_frag.zig");
const tcp = @import("wire/tcp.zig");
const udp = @import("wire/udp.zig");

const ring_buffer = @import("storage/ring_buffer.zig");
const assembler = @import("storage/assembler.zig");
const packet_buffer = @import("storage/packet_buffer.zig");

const iterations = 50_000;

/// Parsers must classify any input as a value or an error; reaching the
/// end of the function is the property (a panic aborts the test binary).
fn consume(result: anytype) bool {
    return tally(@typeName(@TypeOf(result)), result);
}

pub const totality = struct {
    pub fn arpParse(in: zv.Bytes(64)) bool {
        return consume(arp.parse(in.slice()));
    }
    pub fn dhcpParse(in: zv.Bytes(400)) bool {
        return consume(dhcp.parse(in.slice()));
    }
    pub fn dhcpParseWithCookie(in: zv.Bytes(400)) bool {
        var buf: [400]u8 = @splat(0);
        const n = in.slice().len;
        @memcpy(buf[0..n], in.slice());
        if (n < 241) return true;
        buf[1] = 1;
        buf[2] = 6;
        buf[236..240].* = .{ 0x63, 0x82, 0x53, 0x63 };
        return consume(dhcp.parse(buf[0..n]));
    }
    pub fn dnsParseName(in: zv.Bytes(300), start: u8) bool {
        return consume(dns.parseName(in.slice(), start));
    }
    pub fn dnsParseNamePart(in: zv.Bytes(300)) bool {
        return consume(dns.parseNamePart(in.slice()));
    }
    pub fn dnsParseQuestion(in: zv.Bytes(300)) bool {
        return consume(dns.parseQuestion(in.slice()));
    }
    pub fn dnsParseRecord(in: zv.Bytes(300)) bool {
        return consume(dns.parseRecord(in.slice()));
    }
    pub fn ethernetParse(in: zv.Bytes(32)) bool {
        return consume(ethernet.parse(in.slice()));
    }
    pub fn icmpParse(in: zv.Bytes(64)) bool {
        return consume(icmp.parse(in.slice()));
    }
    pub fn icmpv6Parse(in: zv.Bytes(96), src: [16]u8, dst: [16]u8) bool {
        return consume(icmpv6.parse(in.slice(), src, dst));
    }
    pub fn ieee802154Parse(in: zv.Bytes(64)) bool {
        return consume(ieee802154.parse(in.slice()));
    }
    pub fn igmpParse(in: zv.Bytes(32)) bool {
        return consume(igmp.parse(in.slice()));
    }
    pub fn ipsecAhParse(in: zv.Bytes(32)) bool {
        return consume(ipsec_ah.parse(in.slice()));
    }
    pub fn ipsecEspParse(in: zv.Bytes(16)) bool {
        return consume(ipsec_esp.parse(in.slice()));
    }
    pub fn ipv4Parse(in: zv.Bytes(80)) bool {
        return consume(ipv4.parse(in.slice()));
    }
    pub fn ipv4CheckLen(in: zv.Bytes(80)) bool {
        return consume(ipv4.checkLen(in.slice()));
    }
    pub fn ipv6Parse(in: zv.Bytes(64)) bool {
        return consume(ipv6.parse(in.slice()));
    }
    pub fn ipv6CheckLen(in: zv.Bytes(64)) bool {
        return consume(ipv6.checkLen(in.slice()));
    }
    pub fn ipv6ExtHeaderParse(in: zv.Bytes(32)) bool {
        return consume(ipv6ext_header.parse(in.slice()));
    }
    pub fn ipv6FragmentParse(in: zv.Bytes(32)) bool {
        return consume(ipv6fragment.parse(in.slice()));
    }
    pub fn ipv6HbhParse(in: zv.Bytes(64)) bool {
        return consume(ipv6hbh.parse(in.slice()));
    }
    pub fn ipv6OptionParse(in: zv.Bytes(32)) bool {
        return consume(ipv6option.parse(in.slice()));
    }
    pub fn ipv6RoutingParse(in: zv.Bytes(64)) bool {
        return consume(ipv6routing.parse(in.slice()));
    }
    pub fn mldParse(msg_type: u8, in: zv.Bytes(64)) bool {
        return consume(mld.parse(msg_type, in.slice()));
    }
    pub fn mldParseAddressRecord(in: zv.Bytes(32)) bool {
        return consume(mld.parseAddressRecord(in.slice()));
    }
    pub fn ndiscParse(msg_type: u8, in: zv.Bytes(96)) bool {
        return consume(ndisc.parse(msg_type, in.slice()));
    }
    pub fn ndiscOptionParse(in: zv.Bytes(64)) bool {
        return consume(ndiscoption.parse(in.slice()));
    }
    pub fn rplParse(code: u8, in: zv.Bytes(96)) bool {
        return consume(rpl.parse(code, in.slice()));
    }
    pub fn rplOptions(in: zv.Bytes(48)) bool {
        _ = consume(rpl.DodagConfigurationOption.parseOption(in.slice()));
        _ = consume(rpl.RplTargetOption.parseOption(in.slice()));
        _ = consume(rpl.TransitInformationOption.parseOption(in.slice()));
        return consume(rpl.HopByHopRepr.parseOption(in.slice()));
    }
    pub fn sixlowpanIphc(in: zv.Bytes(64), ctx0: [8]u8, ctx1: [8]u8, src: LinkAddr, dst: LinkAddr) bool {
        const contexts = [_]sixlowpan.AddressContext{ ctx0, ctx1 };
        return consume(sixlowpan.parseIphc(in.slice(), src.get(), dst.get(), &contexts));
    }
    pub fn sixlowpanIphcDispatch(in: zv.Bytes(64), src: LinkAddr, dst: LinkAddr) bool {
        var buf: [64]u8 = undefined;
        const n = in.slice().len;
        @memcpy(buf[0..n], in.slice());
        if (n >= 1) buf[0] = (buf[0] & 0x1f) | 0x60;
        const contexts = [_]sixlowpan.AddressContext{ .{ 0x20, 1, 0, 0, 0, 0, 0, 0 }, @splat(0xab) };
        return consume(sixlowpan.parseIphc(buf[0..n], src.get(), dst.get(), &contexts));
    }
    pub fn sixlowpanExtHeaderNhc(in: zv.Bytes(32)) bool {
        return consume(sixlowpan.parseExtHeaderNhc(in.slice()));
    }
    pub fn sixlowpanUdpNhc(in: zv.Bytes(32)) bool {
        return consume(sixlowpan.parseUdpNhc(in.slice()));
    }
    pub fn sixlowpanFragParse(in: zv.Bytes(32)) bool {
        return consume(sixlowpan_frag.parse(in.slice()));
    }
    pub fn tcpParse(in: zv.Bytes(80)) bool {
        return consume(tcp.parse(in.slice()));
    }
    pub fn tcpParseWithOffset(in: zv.Bytes(80)) bool {
        var buf: [80]u8 = undefined;
        const n = in.slice().len;
        @memcpy(buf[0..n], in.slice());
        if (n < 20) return true;
        buf[12] = (@as(u8, @intCast(@min(n, 60) / 4)) << 4) | (buf[12] & 0x0f);
        return consume(tcp.parse(buf[0..n]));
    }
    pub fn udpParse(in: zv.Bytes(16)) bool {
        return consume(udp.parse(in.slice()));
    }
};

const LinkAddr = struct {
    kind: u2,
    bytes: [8]u8,

    fn get(self: LinkAddr) ieee802154.Address {
        return switch (self.kind) {
            0 => .absent,
            1 => .{ .short = self.bytes[0..2].* },
            else => .{ .extended = self.bytes },
        };
    }
};

test "laws: parser totality" {
    try zv.checkLaws(totality, .{ .iterations = iterations, .seed = 1 });
}

fn deepEq(a: anytype, b: @TypeOf(a)) bool {
    std.testing.expectEqualDeep(a, b) catch return false;
    return true;
}

/// parse -> emit -> parse yields an equal value, for modules shaped
/// `parse(data) !Repr` and `emit(repr, buf) !usize`.
fn roundTrip(comptime M: type, data: []const u8, comptime norm: anytype) bool {
    return roundTripMin(M, data, norm, 0);
}

/// `min_len` stands in for the payload a header-only frame needs to be accepted.
fn roundTripMin(comptime M: type, data: []const u8, comptime norm: anytype, comptime min_len: usize) bool {
    var first = M.parse(data) catch return true;
    var buf: [512]u8 = @splat(0xAA);
    const n = M.emit(first, &buf) catch return false;
    var second = M.parse(buf[0..@max(n, min_len)]) catch return false;
    norm(&first);
    norm(&second);
    return deepEq(first, second);
}

fn keep(_: anytype) void {}

pub const roundtrip = struct {
    pub fn arpRoundTrip(in: zv.Bytes(64)) bool {
        return roundTrip(arp, in.slice(), keep);
    }
    pub fn ethernetRoundTrip(in: zv.Bytes(32)) bool {
        return roundTrip(ethernet, in.slice(), keep);
    }
    pub fn ipv4RoundTrip(in: zv.Bytes(80)) bool {
        return roundTrip(ipv4, in.slice(), struct {
            fn f(r: *ipv4.Repr) void {
                r.checksum = 0;
            }
        }.f);
    }
    pub fn tcpRoundTrip(in: zv.Bytes(80)) bool {
        return roundTrip(tcp, in.slice(), tcpNormalize);
    }
    pub fn udpRoundTrip(in: zv.Bytes(16)) bool {
        return roundTrip(udp, in.slice(), keep);
    }
    pub fn ipv6RoundTrip(in: zv.Bytes(64)) bool {
        return roundTrip(ipv6, in.slice(), keep);
    }
    pub fn ipv6ExtHeaderRoundTrip(in: zv.Bytes(32)) bool {
        return roundTrip(ipv6ext_header, in.slice(), keep);
    }
    pub fn ipv6FragmentRoundTrip(in: zv.Bytes(32)) bool {
        return roundTrip(ipv6fragment, in.slice(), keep);
    }
    pub fn ipv6HbhRoundTrip(in: zv.Bytes(64)) bool {
        return roundTrip(ipv6hbh, in.slice(), keep);
    }
    pub fn ipv6OptionRoundTrip(in: zv.Bytes(32)) bool {
        return roundTrip(ipv6option, in.slice(), keep);
    }
    pub fn ipv6RoutingRoundTrip(in: zv.Bytes(64)) bool {
        return roundTrip(ipv6routing, in.slice(), keep);
    }
    pub fn ndiscOptionRoundTrip(in: zv.Bytes(64)) bool {
        return roundTrip(ndiscoption, in.slice(), keep);
    }
    pub fn sixlowpanFragRoundTrip(in: zv.Bytes(32)) bool {
        return roundTrip(sixlowpan_frag, in.slice(), keep);
    }
    pub fn ieee802154RoundTrip(in: zv.Bytes(64)) bool {
        return roundTripMin(ieee802154, in.slice(), keep, 3);
    }
    pub fn igmpRoundTrip(in: zv.Bytes(32)) bool {
        return roundTrip(igmp, in.slice(), keep);
    }
};

test "laws: parse/emit round-trips" {
    try zv.checkLaws(roundtrip, .{ .iterations = iterations, .seed = 2 });
}

const Op = struct { kind: u8, a: u8, b: u8 };

fn shiftDown(cells: []?u8, len: *usize, k: usize) void {
    std.debug.assert(k <= len.*);
    var i: usize = 0;
    while (i + k < cells.len) : (i += 1) cells[i] = cells[i + k];
    for (cells[cells.len - k ..]) |*c| c.* = null;
    len.* -= k;
}

pub const storage = struct {
    /// A ring buffer behaves like a FIFO whose unallocated tail can be
    /// written ahead of time. Cells never written are unknown (null).
    pub fn ringMatchesModel(cap_raw: u8, ops: [32]Op) bool {
        const cap: usize = cap_raw % 17;
        var backing: [16]u8 = @splat(0);
        var ring = ring_buffer.RingBuffer(u8).init(backing[0..cap]);
        var cells: [96]?u8 = @splat(null);
        var len: usize = 0;
        var counter: u8 = 1;

        for (ops) |op| {
            const window = cap - len;
            switch (op.kind % 9) {
                0 => {
                    var data: [20]u8 = undefined;
                    const n = op.b % 21;
                    for (data[0..n]) |*d| {
                        d.* = counter;
                        counter +%= 1;
                    }
                    if (len == 0) cells = @splat(null);
                    const got = ring.enqueueSlice(data[0..n]);
                    if (got != @min(n, window)) return false;
                    for (data[0..got], 0..) |d, i| cells[len + i] = d;
                    len += got;
                },
                1 => {
                    var out: [20]u8 = undefined;
                    const n = op.b % 21;
                    const got = ring.dequeueSlice(out[0..n]);
                    if (got != @min(n, len)) return false;
                    for (out[0..got], cells[0..got]) |o, c| if (c != null and c.? != o) return false;
                    shiftDown(&cells, &len, got);
                },
                2 => {
                    var data: [12]u8 = undefined;
                    const off: usize = op.a % 21;
                    const n = op.b % 13;
                    for (data[0..n]) |*d| {
                        d.* = counter;
                        counter +%= 1;
                    }
                    const got = ring.writeUnallocated(off, data[0..n]);
                    const want = if (off > window) 0 else @min(n, window - off);
                    if (got != want) return false;
                    for (data[0..got], 0..) |d, i| cells[len + off + i] = d;
                },
                3 => {
                    var out: [20]u8 = undefined;
                    const off: usize = op.a % 21;
                    const n = op.b % 21;
                    const got = ring.readAllocated(off, out[0..n]);
                    const want = if (off > len) 0 else @min(n, len - off);
                    if (got != want) return false;
                    for (out[0..got], cells[off..][0..got]) |o, c| if (c != null and c.? != o) return false;
                },
                4 => {
                    const k = op.a % (len + 1);
                    ring.dequeueAllocated(k);
                    shiftDown(&cells, &len, k);
                },
                5 => {
                    const k = op.a % (window + 1);
                    ring.enqueueUnallocated(k);
                    len += k;
                },
                6 => {
                    const max = op.b % 21;
                    if (len == 0) cells = @splat(null);
                    const slice = ring.enqueueMany(max);
                    if (slice.len > @min(max, window)) return false;
                    for (slice, 0..) |*d, i| {
                        d.* = counter;
                        cells[len + i] = counter;
                        counter +%= 1;
                    }
                    len += slice.len;
                },
                7 => {
                    const max = op.b % 21;
                    const slice = ring.dequeueMany(max);
                    if (slice.len > @min(max, len)) return false;
                    if (len > 0 and max > 0 and slice.len == 0) return false;
                    for (slice, cells[0..slice.len]) |o, c| if (c != null and c.? != o) return false;
                    const k = slice.len;
                    shiftDown(&cells, &len, k);
                },
                else => {
                    if (op.b & 1 == 0) {
                        const slot = ring.enqueueOne() catch {
                            if (window != 0) return false;
                            continue;
                        };
                        if (window == 0) return false;
                        slot.* = counter;
                        cells[len] = counter;
                        counter +%= 1;
                        len += 1;
                    } else {
                        const slot = ring.dequeueOne() catch {
                            if (len != 0) return false;
                            continue;
                        };
                        if (len == 0) return false;
                        if (cells[0] != null and cells[0].? != slot.*) return false;
                        shiftDown(&cells, &len, 1);
                    }
                },
            }
            if (ring.len() != len or ring.window() != cap - len) return false;
            if (ring.contiguousWindow() > ring.window()) return false;
        }
        return true;
    }

    /// Packets come out in order, intact, and an empty buffer always accepts
    /// a packet that fits the payload ring.
    pub fn packetBufferIsFifo(meta_cap_raw: u8, payload_cap_raw: u8, ops: [32]Op) bool {
        const Buf = packet_buffer.PacketBuffer(u8);
        const meta_cap = meta_cap_raw % 5;
        const payload_cap: usize = payload_cap_raw % 33;
        var meta_storage: [4]packet_buffer.PacketMeta(u8) = @splat(.{});
        var payload_storage: [32]u8 = @splat(0);
        var buf = Buf.init(meta_storage[0..meta_cap], payload_storage[0..payload_cap]);

        var queued_id: [8]u8 = undefined;
        var queued_size: [8]usize = undefined;
        var count: usize = 0;
        var next_id: u8 = 1;
        var used: usize = 0;

        for (ops) |op| {
            if (op.kind % 3 == 0) {
                const size: usize = op.b % 40;
                const fits_when_empty = count == 0 and size <= payload_cap and meta_cap >= 1;
                const slice = buf.enqueue(size, next_id) catch {
                    if (fits_when_empty) return false;
                    continue;
                };
                if (slice.len != size or count == queued_id.len) return false;
                @memset(slice, next_id);
                queued_id[count] = next_id;
                queued_size[count] = size;
                count += 1;
                used += size;
                next_id +%= 1;
                if (used > payload_cap) return false;
            } else {
                const peeked = buf.peek() catch {
                    if (count != 0) return false;
                    if (buf.dequeue()) |_| return false else |_| {}
                    continue;
                };
                if (count == 0) return false;
                if (peeked.header.* != queued_id[0] or peeked.payload.len != queued_size[0]) return false;
                if (op.kind % 3 == 2) continue;
                const got = buf.dequeue() catch return false;
                if (got.header != queued_id[0] or got.payload.len != queued_size[0]) return false;
                for (got.payload) |byte| if (byte != got.header) return false;
                used -= queued_size[0];
                for (0..count - 1) |k| {
                    queued_id[k] = queued_id[k + 1];
                    queued_size[k] = queued_size[k + 1];
                }
                count -= 1;
            }
            if (buf.isEmpty() != (count == 0)) return false;
        }
        return true;
    }

    /// The assembler tracks received byte ranges: compare with a bitmap.
    pub fn assemblerMatchesModel(ops: [32]Op) bool {
        const max_segments = 3;
        var asmb = assembler.Assembler(max_segments).init();
        var bits: u128 = 0;

        for (ops) |op| {
            const offset: u7 = @intCast(op.a % 72);
            const size: u7 = @intCast(op.b % 24);
            switch (op.kind % 3) {
                0, 1 => {
                    const range: u128 = if (size == 0) 0 else ((@as(u128, 1) << size) - 1) << offset;
                    const after = bits | range;
                    const in_order = op.kind % 3 == 1;
                    const hole_before_data = bits != 0 and size < @ctz(bits);
                    const consumed_in_place = in_order and offset == 0 and hole_before_data;
                    const fits = consumed_in_place or runCount(after) <= max_segments;
                    if (in_order) {
                        const got = asmb.addThenRemoveFront(offset, size) catch {
                            if (fits) return false;
                            if (!sameRuns(&asmb, bits)) return false;
                            continue;
                        };
                        if (!fits) return false;
                        const lead = leadingRun(after);
                        if (got != lead) return false;
                        bits = after >> @intCast(lead);
                    } else {
                        asmb.add(offset, size) catch {
                            if (fits) return false;
                            if (!sameRuns(&asmb, bits)) return false;
                            continue;
                        };
                        if (!fits) return false;
                        bits = after;
                    }
                },
                else => {
                    const lead = leadingRun(bits);
                    const got = asmb.removeFront();
                    if (got != lead) return false;
                    bits >>= @intCast(lead);
                },
            }
            if (!sameRuns(&asmb, bits)) return false;
            if (asmb.peekFront() != leadingRun(bits)) return false;
            if (asmb.isEmpty() != (bits == 0)) return false;
        }
        return true;
    }
};

fn leadingRun(bits: u128) usize {
    return @ctz(~bits);
}

fn runCount(bits: u128) usize {
    return @popCount(bits & ~(bits << 1));
}

fn sameRuns(asmb: anytype, bits: u128) bool {
    var it = asmb.iterData(0);
    var pos: usize = 0;
    var seen: u128 = 0;
    while (it.next()) |run| {
        if (run[0] >= run[1] or run[1] > 128 or run[0] < pos) return false;
        pos = run[1];
        seen |= ((@as(u128, 1) << @intCast(run[1] - run[0])) - 1) << @intCast(run[0]);
    }
    return seen == bits;
}

test "laws: storage models" {
    try zv.checkLaws(storage, .{ .iterations = iterations, .seed = 3 });
}

pub const seq = struct {
    const Seq = tcp.SeqNumber;
    const window_max = std.math.maxInt(i32);

    pub fn u32RoundTrip(v: u32) bool {
        return Seq.fromU32(v).toU32() == v;
    }
    pub fn addSubInverse(a: u32, n_raw: u32) bool {
        const n: usize = n_raw & window_max;
        const s = Seq.fromU32(a);
        return s.add(n).sub(n).eql(s) and s.sub(n).add(n).eql(s) and s.add(n).toU32() == a +% @as(u32, @intCast(n));
    }
    pub fn diffRecoversDistance(a: u32, n_raw: u32) bool {
        const n: usize = n_raw & window_max;
        const s = Seq.fromU32(a);
        return s.add(n).diff(s) == n;
    }
    pub fn orderWithinWindow(a: u32, n_raw: u32) bool {
        const n: usize = n_raw & window_max;
        const s = Seq.fromU32(a);
        const t = s.add(n);
        if (n == 0) return s.cmp(t) == .eq and s.eql(t);
        return s.lessThan(t) and t.greaterThan(s) and !t.lessThan(s) and !s.greaterThan(t) and
            s.lessThanOrEqual(t) and t.greaterThanOrEqual(s) and !s.greaterThanOrEqual(t);
    }
    pub fn orderIsTransitiveWithinWindow(a: u32, n_raw: u32, m_raw: u32) bool {
        const n: usize = n_raw & 0x3fffffff;
        const m: usize = m_raw & 0x3fffffff;
        const s = Seq.fromU32(a);
        const t = s.add(n);
        const u = t.add(m);
        if (!s.lessThanOrEqual(t) or !t.lessThanOrEqual(u)) return false;
        return s.lessThanOrEqual(u) and u.diff(s) == n + m;
    }
    pub fn minMaxAgreeWithOrder(a: u32, n_raw: u32) bool {
        const n: usize = n_raw & window_max;
        const s = Seq.fromU32(a);
        const t = s.add(n);
        return s.max(t).eql(t) and t.max(s).eql(t) and s.min(t).eql(s) and t.min(s).eql(s);
    }
};

test "laws: sequence numbers" {
    try zv.checkLaws(seq, .{ .iterations = iterations, .seed = 4 });
}

// -------------------------------------------------------------------------
// Structure-aware laws. Random bytes die at the first guard (version nibble,
// checksum, magic), so these fix the gating fields and let everything else
// stay random. The reach report at the bottom shows how deep each one gets.
// -------------------------------------------------------------------------

const checksum = @import("wire/checksum.zig");

const Probe = struct {
    name: []const u8,
    ok: usize = 0,
    err_names: [12][]const u8 = undefined,
    err_counts: [12]usize = @splat(0),
    err_kinds: usize = 0,

    fn record(self: *Probe, err_name: []const u8) void {
        for (self.err_names[0..self.err_kinds], self.err_counts[0..self.err_kinds]) |n, *c| {
            if (std.mem.eql(u8, n, err_name)) {
                c.* += 1;
                return;
            }
        }
        if (self.err_kinds == self.err_names.len) return;
        self.err_names[self.err_kinds] = err_name;
        self.err_counts[self.err_kinds] = 1;
        self.err_kinds += 1;
    }
};

var probes: [160]*Probe = undefined;
var probe_count: usize = 0;

/// Count how often a parser call ends in a value or in each error. Returns
/// true so it composes as the tail of a totality law.
fn tally(comptime name: []const u8, result: anytype) bool {
    const S = struct {
        var probe: Probe = .{ .name = name };
        var registered = false;
    };
    if (!S.registered) {
        S.registered = true;
        probes[probe_count] = &S.probe;
        probe_count += 1;
    }
    if (result) |_| S.probe.ok += 1 else |err| S.probe.record(@errorName(err));
    return true;
}

fn load(comptime n: usize, in: zv.Bytes(n), buf: *[n]u8) usize {
    const s = in.slice();
    @memset(buf, 0);
    @memcpy(buf[0..s.len], s);
    return s.len;
}

fn putU16(buf: []u8, v: u16) void {
    buf[0] = @truncate(v >> 8);
    buf[1] = @truncate(v);
}

pub const structured = struct {
    pub fn arpRoundTrip(in: zv.Bytes(32)) bool {
        var buf: [32]u8 = undefined;
        const n = @max(load(32, in, &buf), arp.HEADER_LEN);
        buf[0..8].* = .{ 0, 1, 8, 0, 6, 4, 0, 1 + buf[7] % 2 };
        _ = tally("arp*", arp.parse(buf[0..n]));
        return roundTrip(arp, buf[0..n], keep);
    }

    /// A one-label name followed by class IN, then random type and data.
    pub fn dnsQuestionAndRecord(in: zv.Bytes(64)) bool {
        var buf: [64]u8 = undefined;
        const n = @max(load(64, in, &buf), 24);
        const label: usize = buf[0] % 8;
        buf[0] = @intCast(label);
        buf[label + 1] = 0;
        const class_at = label + 4;
        buf[class_at] = 0;
        buf[class_at + 1] = 1;
        _ = tally("dns question*", dns.parseQuestion(buf[0..n]));
        return tally("dns record*", dns.parseRecord(buf[0..n]));
    }

    pub fn ipv4Parse(in: zv.Bytes(80)) bool {
        var buf: [80]u8 = undefined;
        const n = load(80, in, &buf);
        const ihl: usize = 5 + (buf[0] & 0x0f) % 11;
        buf[0] = 0x40 | @as(u8, @intCast(ihl));
        return tally("ipv4*", ipv4.parse(buf[0 .. @max(n, ihl * 4)]));
    }

    pub fn ipv4ChecksumFill(in: zv.Bytes(80)) bool {
        var buf: [80]u8 = undefined;
        const n = load(80, in, &buf);
        const ihl: usize = 5 + (buf[0] & 0x0f) % 11;
        const len = @max(n, ihl * 4);
        buf[0] = 0x40 | @as(u8, @intCast(ihl));
        putU16(buf[10..12], 0);
        putU16(buf[10..12], checksum.internetChecksum(buf[0 .. ihl * 4]));
        return ipv4.verifyChecksum(buf[0..len]);
    }

    /// checkLen and payloadSlice are two views of one validity predicate.
    pub fn ipv4LengthViewsAgree(in: zv.Bytes(80)) bool {
        var buf: [80]u8 = undefined;
        const n = load(80, in, &buf);
        const ihl: usize = 5 + (buf[0] & 0x0f) % 11;
        const len = @max(n, ihl * 4);
        buf[0] = 0x40 | @as(u8, @intCast(ihl));
        putU16(buf[2..4], @intCast(ihl * 4 + (@as(usize, buf[2]) * 7 + buf[3]) % (len - ihl * 4 + 3)));
        const data = buf[0..len];
        const checked = ipv4.checkLen(data);
        const slice = ipv4.payloadSlice(data);
        if (checked) |_| {
            const p = slice catch return false;
            const total = @as(usize, buf[2]) << 8 | buf[3];
            return p.len == total - ihl * 4 and p.ptr == data.ptr + ihl * 4;
        } else |_| {
            _ = slice catch return true;
            return false;
        }
    }

    pub fn tcpParse(in: zv.Bytes(80)) bool {
        var buf: [80]u8 = undefined;
        const n = load(80, in, &buf);
        const words = 5 + (buf[12] >> 4) % 11;
        buf[12] = (buf[12] & 0x0f) | (words << 4);
        return tally("tcp*", tcp.parse(buf[0 .. @max(n, @as(usize, words) * 4)]));
    }

    /// Options built from a grammar that is well formed most of the time.
    pub fn tcpOptionsRoundTrip(ops: [8]Op, flags: u8) bool {
        var buf: [60]u8 = @splat(0);
        buf[12] = 0x50;
        buf[13] = flags;
        var pos: usize = tcp.HEADER_LEN;
        for (ops) |op| {
            const well_formed = op.b & 3 != 0;
            const kind: u8 = switch (op.kind % 9) {
                0 => 0,
                1 => 1,
                2 => 2,
                3 => 3,
                4 => 4,
                5 => 5,
                6 => 8,
                else => op.kind,
            };
            const len: usize = if (!well_formed) op.b else switch (kind) {
                2 => 4,
                3 => 3,
                4 => 2,
                5 => 2 + 8 * @as(usize, op.a % 4),
                8 => 10,
                else => 2 + op.a % 4,
            };
            const used: usize = if (kind <= 1) 1 else len;
            if (pos + @max(used, 2) > buf.len) break;
            buf[pos] = kind;
            if (kind > 1) buf[pos + 1] = @truncate(len);
            for (buf[pos + 2 ..][0..@min(used -| 2, buf.len - pos - 2)], 0..) |*b, i| b.* = op.a +% @as(u8, @truncate(i * 31));
            if (kind == 3 and well_formed) buf[pos + 2] = op.a % 16;
            pos += used;
        }
        const words = (pos + 3) / 4;
        buf[12] = @as(u8, @intCast(words)) << 4;
        const data = buf[0 .. words * 4];
        _ = tally("tcp options*", tcp.parse(data));
        return roundTrip(tcp, data, tcpNormalize);
    }

    /// Reprs the socket layer could build must survive emit -> parse.
    pub fn tcpEmitParseIdentity(repr_in: tcp.Repr) bool {
        var repr = repr_in;
        if (repr.window_scale) |ws| repr.window_scale = ws % (tcp.MAX_WINDOW_SCALE + 1);
        if (tcp.headerLen(repr) > tcp.MAX_HEADER_LEN) return true;
        var buf: [60]u8 = undefined;
        const n = tcp.emit(repr, &buf) catch return false;
        const again = tcp.parse(buf[0..n]) catch return false;
        var want = repr;
        var got = again;
        tcpNormalize(&want);
        tcpNormalize(&got);
        return deepEq(want, got);
    }

    pub fn tcpChecksumFill(in: zv.Bytes(60), src: [4]u8, dst: [4]u8, src6: [16]u8, dst6: [16]u8) bool {
        var buf: [60]u8 = undefined;
        const n = load(60, in, &buf);
        if (n < tcp.HEADER_LEN) return true;
        const seg = buf[0..n];
        putU16(seg[16..18], 0);
        putU16(seg[16..18], tcp.computeChecksum(src, dst, seg));
        if (!tcp.verifyChecksum(src, dst, seg)) return false;
        putU16(seg[16..18], 0);
        const sum6 = checksum.finish(checksum.calculate(seg, checksum.pseudoHeaderChecksumV6(src6, dst6, 6, @intCast(n))));
        putU16(seg[16..18], sum6);
        return tcp.verifyChecksumV6(src6, dst6, seg);
    }

    pub fn udpChecksumFill(in: zv.Bytes(60), src: [4]u8, dst: [4]u8, src6: [16]u8, dst6: [16]u8) bool {
        var buf: [60]u8 = undefined;
        const n = load(60, in, &buf);
        if (n < udp.HEADER_LEN) return true;
        const dgram = buf[0..n];
        putU16(dgram[4..6], @intCast(n));
        udp.fillChecksum(dgram, src, dst);
        if (!udp.verifyChecksum(dgram, src, dst)) return false;
        udp.fillChecksumV6(dgram, src6, dst6);
        return udp.verifyChecksumV6(dgram, src6, dst6);
    }

    pub fn icmpRoundTrip(in: zv.Bytes(48)) bool {
        var buf: [48]u8 = undefined;
        const n = @max(load(48, in, &buf), icmp.HEADER_LEN);
        putU16(buf[2..4], 0);
        putU16(buf[2..4], checksum.internetChecksum(buf[0..n]));
        const data = buf[0..n];
        _ = tally("icmp*", icmp.parse(data));
        const repr = icmp.parse(data) catch return false;
        var out: [48]u8 = undefined;
        const m = switch (repr) {
            .echo => |e| icmp.emitEcho(e, data[icmp.HEADER_LEN..], &out),
            .other => |o| icmp.emitOther(o, data[icmp.HEADER_LEN..], &out),
        } catch return false;
        const again = icmp.parse(out[0..m]) catch return false;
        return switch (repr) {
            .echo => |e| again == .echo and sameEcho(e, again.echo),
            .other => |o| again == .other and o.icmp_type == again.other.icmp_type and o.code == again.other.code and o.data == again.other.data,
        } and m == n;
    }

    pub fn igmpRoundTrip(in: zv.Bytes(16), type_sel: u8, multicast: bool) bool {
        var buf: [16]u8 = undefined;
        const n = @max(load(16, in, &buf), igmp.HEADER_LEN);
        buf[0] = ([_]u8{ 0x11, 0x12, 0x16, 0x17 })[type_sel % 4];
        if (multicast) buf[4] = 224 | (buf[4] & 0x0f);
        putU16(buf[2..4], 0);
        putU16(buf[2..4], checksum.internetChecksum(buf[0..igmp.HEADER_LEN]));
        const data = buf[0..n];
        _ = tally("igmp*", igmp.parse(data));
        return roundTrip(igmp, data, keep);
    }

    pub fn ipv6Parse(in: zv.Bytes(64)) bool {
        var buf: [64]u8 = undefined;
        const n = @max(load(64, in, &buf), ipv6.HEADER_LEN);
        buf[0] = 0x60 | (buf[0] & 0x0f);
        putU16(buf[4..6], @intCast((@as(usize, buf[4]) << 8 | buf[5]) % (n - ipv6.HEADER_LEN + 2)));
        _ = tally("ipv6*", ipv6.checkLen(buf[0..n]));
        return tally("ipv6*", ipv6.parse(buf[0..n]));
    }

    pub fn icmpv6RoundTrip(in: zv.Bytes(96), type_sel: u8, src: [16]u8, dst: [16]u8) bool {
        const types = [_]u8{ 1, 2, 3, 4, 128, 129, 130, 131, 133, 134, 135, 136, 137, 143, 155 };
        var buf: [96]u8 = undefined;
        const n = @max(load(96, in, &buf), icmpv6.HEADER_LEN);
        buf[0] = types[type_sel % types.len];
        if (buf[0] >= 1 and buf[0] <= 4 and n >= 8 + ipv6.HEADER_LEN) buf[8] = 0x60 | (buf[8] & 0x0f);
        putU16(buf[2..4], 0);
        const pseudo = checksum.pseudoHeaderChecksumV6(src, dst, @backingInt(ipv6.Protocol.icmpv6), @intCast(n));
        putU16(buf[2..4], checksum.finish(checksum.calculate(buf[0..n], pseudo)));
        const data = buf[0..n];
        _ = tally("icmpv6*", icmpv6.parse(data, src, dst));
        const repr = icmpv6.parse(data, src, dst) catch return true;
        var out: [512]u8 = undefined;
        const m = icmpv6.emit(repr, src, dst, &out) catch return false;
        const again = icmpv6.parse(out[0..m], src, dst) catch return false;
        return deepEq(repr, again);
    }

    pub fn mldRoundTrip(in: zv.Bytes(64), type_sel: u8) bool {
        var buf: [64]u8 = undefined;
        const n = load(64, in, &buf);
        const msg_type: u8 = if (type_sel & 1 == 0) 0x82 else 0x8F;
        const count_at: usize = if (msg_type == 0x82) 22 else 2;
        buf[count_at] = 0;
        buf[count_at + 1] %= 3;
        _ = tally("mld*", mld.parse(msg_type, buf[0..n]));
        const repr = mld.parse(msg_type, buf[0..n]) catch return true;
        // emit writes only the fixed part; sources and records follow separately
        switch (repr) {
            .query => |q| if (q.num_srcs != 0) return true,
            .report => |r| if (r.nr_mcast_addr_rcrds != 0) return true,
        }
        var out: [64]u8 = undefined;
        const m = mld.emit(repr, &out) catch return false;
        const again = mld.parse(msg_type, out[0..m]) catch return false;
        return deepEq(repr, again);
    }

    pub fn ndiscRoundTrip(in: zv.Bytes(96), type_sel: u8) bool {
        var buf: [96]u8 = undefined;
        const n = load(96, in, &buf);
        const msg_type: u8 = 133 + type_sel % 5;
        _ = tally("ndisc*", ndisc.parse(msg_type, buf[0..n]));
        const repr = ndisc.parse(msg_type, buf[0..n]) catch return true;
        var out: [256]u8 = undefined;
        const m = ndisc.emit(repr, &out) catch return false;
        const again = ndisc.parse(msg_type, out[0..m]) catch return false;
        return deepEq(repr, again);
    }

    pub fn rplRoundTrip(in: zv.Bytes(96), type_sel: u8) bool {
        var buf: [96]u8 = undefined;
        const n = load(96, in, &buf);
        const code: u8 = type_sel % 4;
        _ = tally("rpl*", rpl.parse(code, buf[0..n]));
        const repr = rpl.parse(code, buf[0..n]) catch return true;
        var out: [256]u8 = undefined;
        const m = rpl.emit(repr, &out) catch return false;
        const again = rpl.parse(code, out[0..m]) catch return false;
        return deepEq(repr, again);
    }

    pub fn ieee802154RoundTrip(in: zv.Bytes(64)) bool {
        var buf: [64]u8 = undefined;
        const n = @max(load(64, in, &buf), 3);
        buf[0] &= ~@as(u8, 0x08);
        const modes = [_]u8{ 0, 2, 3 };
        const dst = modes[(buf[1] >> 2) % 3];
        const src = modes[(buf[1] >> 4) % 3];
        const version: u8 = (buf[1] >> 6) % 3;
        buf[1] = (dst << 2) | (version << 4) | (src << 6);
        _ = tally("ieee802154*", ieee802154.parse(buf[0..n]));
        return roundTripMin(ieee802154, buf[0..n], keep, 3);
    }

    pub fn dhcpRoundTrip(in: zv.Bytes(400), msg: u8) bool {
        var buf: [400]u8 = undefined;
        const n = load(400, in, &buf);
        if (n < 241) return true;
        buf[1] = 1;
        buf[2] = 6;
        buf[236..240].* = .{ 0x63, 0x82, 0x53, 0x63 };
        const mt: u8 = 1 + msg % 8;
        buf[0] = if (mt == 2 or mt == 5 or mt == 6) 2 else 1;
        // splice in a message-type option so options after it are reached
        buf[240..243].* = .{ 53, 1, mt };
        _ = tally("dhcp*", dhcp.parse(buf[0..n]));
        var first = dhcp.parse(buf[0..n]) catch return true;
        var out: [512]u8 = undefined;
        const m = dhcp.emit(first, &out) catch return false;
        var second = dhcp.parse(out[0..m]) catch return false;
        // smoltcp parses T1/T2 but its emit does not write them either
        first.renew_duration = null;
        first.rebind_duration = null;
        second.renew_duration = null;
        second.rebind_duration = null;
        return dhcpEql(first, second);
    }
};

fn tcpNormalize(r: *tcp.Repr) void {
    r.data_offset = 0;
    if (r.sack_permitted) r.sack_ranges = .{ null, null, null };
    var packed_ranges: [3]?tcp.SackRange = .{ null, null, null };
    var k: usize = 0;
    for (r.sack_ranges) |range| if (range != null) {
        packed_ranges[k] = range;
        k += 1;
    };
    r.sack_ranges = packed_ranges;
}

fn sameEcho(a: icmp.EchoRepr, b: icmp.EchoRepr) bool {
    return a.icmp_type == b.icmp_type and a.code == b.code and a.identifier == b.identifier and a.sequence == b.sequence;
}

fn dhcpEql(a: dhcp.Repr, b: dhcp.Repr) bool {
    if ((a.dns_servers == null) != (b.dns_servers == null)) return false;
    if (a.dns_servers) |s| if (!s.eql(&b.dns_servers.?)) return false;
    var x = a;
    var y = b;
    x.dns_servers = null;
    y.dns_servers = null;
    return deepEq(x, y);
}

test "laws: structure-aware" {
    try zv.checkLaws(structured, .{ .iterations = iterations, .seed = 5 });
}


// -------------------------------------------------------------------------
// Stateful TCP socket law. Operations are interpreted relative to the
// socket's current state (next expected sequence number, last dispatched
// segment), so a short script reaches established connections, windows and
// FIN handling that blind random segments never would.
// -------------------------------------------------------------------------

const tcp_socket = @import("socket/tcp.zig");
const time_mod = @import("time.zig");

const TcpOp = struct { kind: u8, a: u16, b: u16, c: u8 };
const TcpOpts = struct { v6: bool, ws: bool, ts: bool, sack: bool };

const rx_sizes = [_]usize{ 32, 64, 1000, 4096, 65535, 65536, 70000, 140000 };
const max_rx = 140_000;

var rx_mem: [max_rx]u8 = undefined;
var tx_mem: [4096]u8 = undefined;
var payload_mem: [2 * max_rx]u8 = @splat(0x5a);

const local_v4 = ipv4.Address{ 10, 0, 0, 1 };
const peer_v4 = ipv4.Address{ 10, 0, 0, 2 };

pub const tcp_state = struct {
    const Seq = tcp.SeqNumber;

    const Check = enum { rings_in_bounds, window_fits_ring, fin_follows_all_data, dispatch_fits_egress };

    /// No operation sequence overflows the buffers or panics.
    pub fn ringsStayInBounds(rx_pick: u8, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.rings_in_bounds, rx_pick, peer_isn, o, ops);
    }

    /// What the in-window test admits fits the free space of the receive ring.
    pub fn advertisedWindowFitsRing(rx_pick: u8, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.window_fits_ring, rx_pick, peer_isn, o, ops);
    }

    /// A FIN is only consumed once every byte before it was accepted.
    pub fn finConsumesAllPrecedingData(rx_pick: u8, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.fin_follows_all_data, rx_pick, peer_isn, o, ops);
    }

    /// Every segment the socket dispatches serializes into the stack's scratch buffer.
    pub fn dispatchedSegmentsFitEgress(rx_pick: u8, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.dispatch_fits_egress, rx_pick, peer_isn, o, ops);
    }

    fn pick(comptime check: Check, rx_pick: u8, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return if (o.v6) run(ipv6, check, rx_pick, peer_isn, o, ops) else run(ipv4, check, rx_pick, peer_isn, o, ops);
    }

    fn addrOf(comptime Ip: type, last: u8) Ip.Address {
        var a: Ip.Address = @splat(0);
        a[0] = if (a.len == 16) 0xfe else 10;
        a[a.len - 1] = last;
        return a;
    }

    fn tsGen() u32 {
        return 7;
    }

    fn run(comptime Ip: type, comptime check: Check, rx_pick: u8, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        const Sock = tcp_socket.Socket(Ip, 4);
        const local_addr = addrOf(Ip, 1);
        const peer_addr = addrOf(Ip, 2);
        const egress_limit: usize = if (Ip.ADDRESS_LEN == 16) 1460 else 1480;
        const cap = rx_sizes[rx_pick % rx_sizes.len];
        var s = Sock.initWithInitialSequenceSecret(rx_mem[0..cap], &tx_mem, peer_isn);
        s.listen(.{ .port = 80 }) catch unreachable;
        if (o.ts) s.setTsvalGenerator(&tsGen);
        var now_ms: i64 = 0;
        var last_sent_end: ?Seq = null;
        const isn = Seq.fromU32(peer_isn);

        for (ops) |op| {
            now_ms += op.c;
            const now = time_mod.Instant.fromMillis(now_ms);
            switch (op.kind % 14) {
                0, 1, 2, 3, 4, 5, 6, 7 => {
                    var r: tcp_socket.TcpRepr = .{ .src_port = 5000, .dst_port = 80 };
                    const handshaking = s.state == .listen or s.state == .syn_sent;
                    r.control = if (s.state == .listen) .syn else switch (op.a % 9) {
                        0 => .syn,
                        1, 2 => .fin,
                        3 => .rst,
                        4 => .psh,
                        else => .none,
                    };
                    if (r.control == .syn and o.ws) r.window_scale = @intCast(op.b % 15);
                    if (r.control == .syn) r.max_seg_size = if (op.b & 1 == 0) null else op.b;
                    if (r.control == .syn) r.sack_permitted = o.sack;
                    if (r.control == .syn and o.ts) r.timestamp = .{ .tsval = 1, .tsecr = 0 };
                    const base = if (handshaking) isn else s.remote_seq_no.add(s.rx_buffer.len());
                    const offset: usize = switch (op.c % 8) {
                        0, 1, 2 => 0,
                        3 => op.b % 100,
                        4 => cap / 2 + op.b % 64,
                        5 => cap -| (op.b % 64),
                        6 => cap + op.b % 64,
                        else => op.b,
                    };
                    r.seq_number = if (r.control == .syn) isn else base.add(offset);
                    if (s.state != .listen and !(s.state == .syn_sent and r.control == .syn and op.b & 4 != 0)) {
                        r.ack_number = switch (op.b % 6) {
                            0, 1, 2 => last_sent_end orelse s.local_seq_no,
                            3 => s.local_seq_no.add(1),
                            4 => s.local_seq_no,
                            else => Seq.fromU32(@as(u32, op.a) *% 65537),
                        };
                    }
                    r.window_len = switch (op.a % 5) {
                        0 => 0,
                        1 => 100,
                        2 => 65535,
                        else => op.a,
                    };
                    const plen: usize = switch ((op.a >> 4) % 8) {
                        0, 1, 2 => 0,
                        3 => 1,
                        4 => op.b % 64,
                        5 => cap / 2,
                        6 => cap + op.b % 129,
                        else => @min(2 * cap, payload_mem.len),
                    };
                    r.payload = payload_mem[0..plen];
                    if (!s.accepts(peer_addr, local_addr, r)) continue;
                    const was_fin = s.rx_fin_received;
                    // a conforming peer sends nothing, in or out of order, beyond its FIN
                    const next_before = s.remote_seq_no.add(s.rx_buffer.len());
                    const fin_is_new = s.assembler.isEmpty() and !next_before.greaterThan(r.seq_number.add(r.payload.len));
                    _ = s.process(now, peer_addr, local_addr, r);
                    if (check == .fin_follows_all_data and fin_is_new and r.control == .fin and !was_fin and s.rx_fin_received) {
                        const fin_end = r.seq_number.add(r.payload.len).add(1);
                        if (!s.remote_seq_no.add(s.rx_buffer.len()).eql(fin_end)) return false;
                    }
                },
                8, 9 => {
                    if (s.dispatch(now)) |d| {
                        last_sent_end = d.repr.seq_number.add(d.repr.segmentLen());
                        if (check == .dispatch_fits_egress and tcp.headerLen(d.repr.toWireRepr()) + d.repr.payload.len > egress_limit) return false;
                    }
                },
                10 => {
                    var out: [512]u8 = undefined;
                    _ = s.recvSlice(out[0 .. op.a % 512]) catch {};
                },
                11 => _ = s.sendSlice(payload_mem[0 .. op.a % 1500]) catch 0,
                12 => switch (op.a % 5) {
                    0 => s.close(),
                    1 => s.abort(),
                    2 => if (!s.isOpen()) s.connect(peer_addr, 5000, local_addr, 80) catch {},
                    3 => if (!s.isOpen()) s.listen(.{ .port = 80 }) catch {},
                    else => {},
                },
                else => {},
            }
            _ = s.pollAt();
            switch (check) {
                .rings_in_bounds => if (s.rx_buffer.len() > s.rx_buffer.capacity() or s.tx_buffer.len() > s.tx_buffer.capacity()) return false,
                .window_fits_ring => if (!windowFitsRing(&s)) return false,
                .fin_follows_all_data, .dispatch_fits_egress => {},
            }
        }
        return true;
    }

    fn windowFitsRing(s: anytype) bool {
        switch (s.state) {
            .closed, .listen, .syn_sent => return true,
            else => {},
        }
        const last_ack = s.remote_last_ack orelse return true;
        const edge = last_ack.add(@as(usize, s.remote_last_win) << @intCast(s.remote_win_shift));
        const next = s.remote_seq_no.add(s.rx_buffer.len());
        const room: i32 = edge.value -% next.value;
        return room <= @as(i64, @intCast(s.rx_buffer.window()));
    }
};

test "laws: tcp socket state machine" {
    try zv.checkLaws(tcp_state, .{ .iterations = 50_000, .seed = 6 });
}

test "laws: reach report" {
    std.debug.print("\nlaw reach (parser result counts)\n", .{});
    for (probes[0..probe_count]) |p| {
        var total: usize = p.ok;
        for (p.err_counts[0..p.err_kinds]) |c| total += c;
        const name = if (std.mem.indexOfScalar(u8, p.name, '!')) |i| p.name[i + 1 ..] else p.name;
        std.debug.print("  {s: <46} ok {d: >7} of {d: >7}", .{ name[0..@min(name.len, 46)], p.ok, total });
        for (p.err_names[0..p.err_kinds], p.err_counts[0..p.err_kinds]) |n, c| std.debug.print("  {s}={d}", .{ n, c });
        std.debug.print("\n", .{});
        if (std.mem.endsWith(u8, p.name, "*")) try std.testing.expect(p.ok > 0);
    }
}
