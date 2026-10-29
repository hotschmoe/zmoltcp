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
const ip_mod = @import("wire/ip.zig");
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
fn roundTripMin(comptime M: type, data: []const u8, comptime norm: anytype, min_len: usize) bool {
    var first = M.parse(data) catch return true;
    var buf: [512]u8 = @splat(0xAA);
    const n = M.emit(first, &buf) catch return false;
    if (@hasDecl(M, "bufferLen") and M.bufferLen(first) != n) return false;
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
    pub fn ringMatchesModel(capacity: zv.Ranged(0, 16), ops: [32]Op) bool {
        const cap: usize = capacity.get();
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
    pub fn packetBufferIsFifo(meta_capacity: zv.Ranged(0, 4), payload_capacity: zv.Ranged(0, 32), ops: [32]Op) bool {
        const Buf = packet_buffer.PacketBuffer(u8);
        const meta_cap: usize = meta_capacity.get();
        const payload_cap: usize = payload_capacity.get();
        var meta_storage: [4]packet_buffer.PacketMeta(u8) = @splat(.{});
        var payload_storage: [32]u8 = @splat(0);
        var buf = Buf.init(meta_storage[0..meta_cap], payload_storage[0..payload_cap]);
        if (buf.packetCapacity() != meta_cap or buf.payloadCapacity() != payload_cap) return false;

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
    const Distance = zv.Ranged(0, window_max);
    const HalfWindow = zv.Ranged(0, window_max / 2);

    pub fn addSubInverse(a: u32, distance: Distance) bool {
        const n: usize = distance.get();
        const s = Seq.fromU32(a);
        return s.add(n).sub(n).eql(s) and s.sub(n).add(n).eql(s) and s.add(n).toU32() == a +% @as(u32, @intCast(n));
    }
    pub fn diffRecoversDistance(a: u32, distance: Distance) bool {
        const n: usize = distance.get();
        const s = Seq.fromU32(a);
        return s.add(n).diff(s) == n;
    }
    pub fn orderWithinWindow(a: u32, distance: Distance) bool {
        const n: usize = distance.get();
        const s = Seq.fromU32(a);
        const t = s.add(n);
        if (n == 0) return s.cmp(t) == .eq and s.eql(t);
        return s.lessThan(t) and t.greaterThan(s) and !t.lessThan(s) and !s.greaterThan(t) and
            s.lessThanOrEqual(t) and t.greaterThanOrEqual(s) and !s.greaterThanOrEqual(t);
    }
    pub fn orderIsTransitiveWithinWindow(a: u32, first: HalfWindow, second: HalfWindow) bool {
        const n: usize = first.get();
        const m: usize = second.get();
        const s = Seq.fromU32(a);
        const t = s.add(n);
        const u = t.add(m);
        if (!s.lessThanOrEqual(t) or !t.lessThanOrEqual(u)) return false;
        return s.lessThanOrEqual(u) and u.diff(s) == n + m;
    }
    pub fn minMaxAgreeWithOrder(a: u32, distance: Distance) bool {
        const n: usize = distance.get();
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
        return tally("ipv4*", ipv4.parse(buf[0..@max(n, ihl * 4)]));
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
            const total = (@as(usize, buf[2]) << 8) | buf[3];
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
        return tally("tcp*", tcp.parse(buf[0..@max(n, @as(usize, words) * 4)]));
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
        putU16(buf[4..6], @intCast(((@as(usize, buf[4]) << 8) | buf[5]) % (n - ipv6.HEADER_LEN + 2)));
        _ = tally("ipv6*", ipv6.checkLen(buf[0..n]));
        _ = tally("ipv6*", ipv6.parse(buf[0..n]));
        return roundTripMin(ipv6, buf[0..n], keep, n);
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
const RxPick = zv.Ranged(0, rx_sizes.len - 1);
const max_rx = 140_000;

var rx_mem: [max_rx]u8 = undefined;
var tx_mem: [4096]u8 = undefined;
var payload_mem: [2 * max_rx]u8 = @splat(0x5a);

const local_v4 = ipv4.Address{ 10, 0, 0, 1 };
const peer_v4 = ipv4.Address{ 10, 0, 0, 2 };

pub const tcp_state = struct {
    /// A scaled-window listener (140000 byte ring, shift 2) takes a SYN advertising 65535 and
    /// scale 3, then dispatches: the SYN-ACK must not provoke a window update of itself.
    const syn_then_dispatch: [48]TcpOp = blk: {
        var ops: [48]TcpOp = @splat(.{ .kind = 13, .a = 0, .b = 0, .c = 0 });
        ops[0] = .{ .kind = 0, .a = 2, .b = 3, .c = 0 };
        ops[1] = .{ .kind = 8, .a = 0, .b = 0, .c = 0 };
        break :blk ops;
    };

    pub const pinned = .{
        .dispatchQuiesces = .{
            .{ 7, 0, .{ .v6 = false, .ws = true, .ts = false, .sack = false }, syn_then_dispatch },
        },
        .ringsStayInBounds = .{
            .{
                6,
                0,
                .{ .v6 = false, .ws = false, .ts = false, .sack = true },
                .{
                    .{ .kind = 222, .a = 54317, .b = 48549, .c = 1 },
                    .{ .kind = 178, .a = 8610, .b = 1, .c = 255 },
                    .{ .kind = 1, .a = 45385, .b = 64307, .c = 1 },
                    .{ .kind = 0, .a = 0, .b = 1, .c = 0 },
                    .{ .kind = 140, .a = 0, .b = 0, .c = 1 },
                    .{ .kind = 159, .a = 35355, .b = 0, .c = 0 },
                    .{ .kind = 0, .a = 51164, .b = 56572, .c = 84 },
                    .{ .kind = 0, .a = 65535, .b = 4314, .c = 0 },
                    .{ .kind = 1, .a = 41895, .b = 1, .c = 178 },
                    .{ .kind = 1, .a = 0, .b = 0, .c = 161 },
                    .{ .kind = 255, .a = 847, .b = 0, .c = 0 },
                    .{ .kind = 1, .a = 65535, .b = 1001, .c = 1 },
                    .{ .kind = 1, .a = 0, .b = 26340, .c = 245 },
                    .{ .kind = 79, .a = 0, .b = 61477, .c = 255 },
                    .{ .kind = 1, .a = 5439, .b = 8888, .c = 1 },
                    .{ .kind = 0, .a = 45440, .b = 1, .c = 206 },
                    .{ .kind = 195, .a = 1, .b = 0, .c = 248 },
                    .{ .kind = 131, .a = 21558, .b = 1, .c = 0 },
                    .{ .kind = 0, .a = 55989, .b = 0, .c = 89 },
                    .{ .kind = 0, .a = 8831, .b = 33141, .c = 255 },
                    .{ .kind = 1, .a = 65535, .b = 0, .c = 147 },
                    .{ .kind = 1, .a = 32419, .b = 65535, .c = 9 },
                    .{ .kind = 1, .a = 31877, .b = 0, .c = 206 },
                    .{ .kind = 97, .a = 42976, .b = 20219, .c = 0 },
                    .{ .kind = 0, .a = 29430, .b = 65535, .c = 0 },
                    .{ .kind = 172, .a = 57199, .b = 0, .c = 0 },
                    .{ .kind = 26, .a = 1, .b = 65535, .c = 1 },
                    .{ .kind = 83, .a = 1, .b = 37376, .c = 1 },
                    .{ .kind = 1, .a = 0, .b = 8212, .c = 105 },
                    .{ .kind = 255, .a = 0, .b = 31722, .c = 255 },
                    .{ .kind = 130, .a = 2293, .b = 0, .c = 68 },
                    .{ .kind = 197, .a = 23654, .b = 0, .c = 90 },
                    .{ .kind = 0, .a = 1, .b = 0, .c = 255 },
                    .{ .kind = 0, .a = 45635, .b = 1, .c = 1 },
                    .{ .kind = 0, .a = 33310, .b = 62874, .c = 0 },
                    .{ .kind = 225, .a = 19148, .b = 1, .c = 255 },
                    .{ .kind = 87, .a = 0, .b = 54154, .c = 0 },
                    .{ .kind = 78, .a = 51028, .b = 43900, .c = 93 },
                    .{ .kind = 47, .a = 65535, .b = 51588, .c = 140 },
                    .{ .kind = 255, .a = 0, .b = 0, .c = 0 },
                    .{ .kind = 169, .a = 55786, .b = 0, .c = 58 },
                    .{ .kind = 0, .a = 22201, .b = 18204, .c = 0 },
                    .{ .kind = 1, .a = 0, .b = 1, .c = 40 },
                    .{ .kind = 26, .a = 65367, .b = 0, .c = 255 },
                    .{ .kind = 1, .a = 13851, .b = 65535, .c = 1 },
                    .{ .kind = 0, .a = 65535, .b = 0, .c = 1 },
                    .{ .kind = 17, .a = 1, .b = 65535, .c = 0 },
                    .{ .kind = 0, .a = 41440, .b = 1, .c = 149 },
                },
            },
            .{
                6,
                0,
                .{ .v6 = false, .ws = true, .ts = false, .sack = false },
                .{
                    .{ .kind = 0, .a = 0, .b = 56848, .c = 208 },
                    .{ .kind = 255, .a = 36753, .b = 65535, .c = 230 },
                    .{ .kind = 219, .a = 24188, .b = 65535, .c = 155 },
                    .{ .kind = 0, .a = 1, .b = 0, .c = 116 },
                    .{ .kind = 0, .a = 65535, .b = 0, .c = 0 },
                    .{ .kind = 215, .a = 25443, .b = 1, .c = 255 },
                    .{ .kind = 0, .a = 33846, .b = 65535, .c = 156 },
                    .{ .kind = 95, .a = 1, .b = 16699, .c = 0 },
                    .{ .kind = 244, .a = 20627, .b = 42219, .c = 1 },
                    .{ .kind = 103, .a = 3526, .b = 0, .c = 248 },
                    .{ .kind = 40, .a = 0, .b = 6765, .c = 255 },
                    .{ .kind = 238, .a = 65535, .b = 0, .c = 0 },
                    .{ .kind = 255, .a = 0, .b = 53279, .c = 126 },
                    .{ .kind = 0, .a = 0, .b = 0, .c = 188 },
                    .{ .kind = 73, .a = 65535, .b = 0, .c = 255 },
                    .{ .kind = 255, .a = 1, .b = 1, .c = 8 },
                    .{ .kind = 255, .a = 51139, .b = 44032, .c = 0 },
                    .{ .kind = 0, .a = 48768, .b = 0, .c = 0 },
                    .{ .kind = 251, .a = 65535, .b = 65535, .c = 198 },
                    .{ .kind = 0, .a = 0, .b = 65535, .c = 0 },
                    .{ .kind = 1, .a = 44427, .b = 1, .c = 100 },
                    .{ .kind = 0, .a = 0, .b = 13655, .c = 0 },
                    .{ .kind = 0, .a = 0, .b = 0, .c = 0 },
                    .{ .kind = 1, .a = 1, .b = 21181, .c = 0 },
                    .{ .kind = 200, .a = 35953, .b = 32309, .c = 211 },
                    .{ .kind = 92, .a = 46116, .b = 57614, .c = 185 },
                    .{ .kind = 180, .a = 46160, .b = 12342, .c = 97 },
                    .{ .kind = 1, .a = 33429, .b = 46506, .c = 62 },
                    .{ .kind = 1, .a = 0, .b = 23731, .c = 85 },
                    .{ .kind = 255, .a = 65535, .b = 1, .c = 255 },
                    .{ .kind = 121, .a = 59625, .b = 7371, .c = 1 },
                    .{ .kind = 255, .a = 0, .b = 62779, .c = 0 },
                    .{ .kind = 159, .a = 43854, .b = 0, .c = 31 },
                    .{ .kind = 255, .a = 2979, .b = 22086, .c = 162 },
                    .{ .kind = 0, .a = 33334, .b = 1, .c = 0 },
                    .{ .kind = 0, .a = 41523, .b = 0, .c = 116 },
                    .{ .kind = 168, .a = 2509, .b = 49758, .c = 0 },
                    .{ .kind = 0, .a = 41299, .b = 1, .c = 140 },
                    .{ .kind = 111, .a = 0, .b = 59657, .c = 1 },
                    .{ .kind = 2, .a = 5923, .b = 38417, .c = 42 },
                    .{ .kind = 132, .a = 18161, .b = 0, .c = 1 },
                    .{ .kind = 22, .a = 0, .b = 63607, .c = 113 },
                    .{ .kind = 91, .a = 1, .b = 8970, .c = 232 },
                    .{ .kind = 255, .a = 30002, .b = 1, .c = 126 },
                    .{ .kind = 238, .a = 0, .b = 1, .c = 255 },
                    .{ .kind = 255, .a = 63863, .b = 48245, .c = 0 },
                    .{ .kind = 117, .a = 0, .b = 0, .c = 255 },
                    .{ .kind = 72, .a = 0, .b = 32195, .c = 6 },
                },
            },
        },
        .finConsumesAllPrecedingData = .{
            .{
                0,
                826401848,
                .{ .v6 = false, .ws = true, .ts = false, .sack = true },
                .{
                    .{ .kind = 231, .a = 0, .b = 1, .c = 240 },
                    .{ .kind = 226, .a = 0, .b = 39105, .c = 1 },
                    .{ .kind = 0, .a = 0, .b = 1, .c = 43 },
                    .{ .kind = 1, .a = 39655, .b = 65535, .c = 221 },
                    .{ .kind = 0, .a = 0, .b = 43450, .c = 71 },
                    .{ .kind = 1, .a = 60121, .b = 43878, .c = 0 },
                    .{ .kind = 122, .a = 19730, .b = 0, .c = 0 },
                    .{ .kind = 0, .a = 59409, .b = 0, .c = 1 },
                    .{ .kind = 195, .a = 0, .b = 50021, .c = 1 },
                    .{ .kind = 64, .a = 64210, .b = 65535, .c = 53 },
                    .{ .kind = 220, .a = 16530, .b = 45535, .c = 167 },
                    .{ .kind = 187, .a = 33499, .b = 1, .c = 246 },
                    .{ .kind = 118, .a = 4322, .b = 35297, .c = 139 },
                    .{ .kind = 169, .a = 6604, .b = 1, .c = 220 },
                    .{ .kind = 17, .a = 65535, .b = 52460, .c = 255 },
                    .{ .kind = 255, .a = 65535, .b = 0, .c = 1 },
                    .{ .kind = 255, .a = 65535, .b = 30709, .c = 0 },
                    .{ .kind = 43, .a = 0, .b = 1, .c = 158 },
                    .{ .kind = 255, .a = 4375, .b = 55238, .c = 0 },
                    .{ .kind = 0, .a = 58539, .b = 1, .c = 0 },
                    .{ .kind = 96, .a = 1, .b = 0, .c = 0 },
                    .{ .kind = 255, .a = 0, .b = 30607, .c = 208 },
                    .{ .kind = 204, .a = 51101, .b = 28880, .c = 0 },
                    .{ .kind = 0, .a = 0, .b = 0, .c = 86 },
                    .{ .kind = 36, .a = 1, .b = 37734, .c = 0 },
                    .{ .kind = 1, .a = 10371, .b = 0, .c = 178 },
                    .{ .kind = 134, .a = 61912, .b = 57351, .c = 1 },
                    .{ .kind = 255, .a = 0, .b = 0, .c = 255 },
                    .{ .kind = 0, .a = 12722, .b = 65535, .c = 144 },
                    .{ .kind = 173, .a = 39192, .b = 33393, .c = 174 },
                    .{ .kind = 1, .a = 0, .b = 21960, .c = 1 },
                    .{ .kind = 13, .a = 62099, .b = 41592, .c = 255 },
                    .{ .kind = 2, .a = 23168, .b = 0, .c = 1 },
                    .{ .kind = 221, .a = 0, .b = 0, .c = 6 },
                    .{ .kind = 255, .a = 65535, .b = 18224, .c = 255 },
                    .{ .kind = 41, .a = 0, .b = 0, .c = 37 },
                    .{ .kind = 240, .a = 65535, .b = 65535, .c = 1 },
                    .{ .kind = 231, .a = 35040, .b = 31545, .c = 109 },
                    .{ .kind = 166, .a = 0, .b = 39828, .c = 241 },
                    .{ .kind = 63, .a = 34567, .b = 3135, .c = 151 },
                    .{ .kind = 30, .a = 51182, .b = 41409, .c = 230 },
                    .{ .kind = 174, .a = 1, .b = 0, .c = 0 },
                    .{ .kind = 107, .a = 25356, .b = 7282, .c = 0 },
                    .{ .kind = 1, .a = 23360, .b = 25800, .c = 127 },
                    .{ .kind = 0, .a = 4833, .b = 0, .c = 143 },
                    .{ .kind = 210, .a = 65535, .b = 219, .c = 0 },
                    .{ .kind = 204, .a = 62415, .b = 65535, .c = 0 },
                    .{ .kind = 1, .a = 18415, .b = 1, .c = 132 },
                },
            },
        },
        .dispatchedSegmentsFitEgress = .{
            .{
                6,
                2641736916,
                .{ .v6 = false, .ws = true, .ts = true, .sack = false },
                .{
                    .{ .kind = 179, .a = 33162, .b = 32395, .c = 0 },
                    .{ .kind = 0, .a = 61433, .b = 32209, .c = 198 },
                    .{ .kind = 212, .a = 0, .b = 18190, .c = 112 },
                    .{ .kind = 255, .a = 58683, .b = 65535, .c = 234 },
                    .{ .kind = 0, .a = 65535, .b = 49641, .c = 93 },
                    .{ .kind = 89, .a = 40403, .b = 0, .c = 124 },
                    .{ .kind = 67, .a = 14787, .b = 65535, .c = 1 },
                    .{ .kind = 42, .a = 1633, .b = 64935, .c = 161 },
                    .{ .kind = 255, .a = 0, .b = 62141, .c = 172 },
                    .{ .kind = 0, .a = 60983, .b = 15769, .c = 255 },
                    .{ .kind = 0, .a = 1, .b = 1, .c = 0 },
                    .{ .kind = 168, .a = 65535, .b = 0, .c = 114 },
                    .{ .kind = 107, .a = 64025, .b = 1944, .c = 1 },
                    .{ .kind = 89, .a = 65178, .b = 0, .c = 204 },
                    .{ .kind = 116, .a = 30739, .b = 1, .c = 255 },
                    .{ .kind = 255, .a = 62666, .b = 65535, .c = 0 },
                    .{ .kind = 249, .a = 65535, .b = 1, .c = 155 },
                    .{ .kind = 1, .a = 42884, .b = 65535, .c = 255 },
                    .{ .kind = 228, .a = 0, .b = 0, .c = 0 },
                    .{ .kind = 1, .a = 65214, .b = 1, .c = 215 },
                    .{ .kind = 1, .a = 0, .b = 1, .c = 13 },
                    .{ .kind = 233, .a = 54482, .b = 65535, .c = 0 },
                    .{ .kind = 1, .a = 0, .b = 64276, .c = 0 },
                    .{ .kind = 23, .a = 1, .b = 1, .c = 1 },
                    .{ .kind = 0, .a = 4748, .b = 53380, .c = 255 },
                    .{ .kind = 1, .a = 0, .b = 0, .c = 100 },
                    .{ .kind = 37, .a = 0, .b = 1, .c = 190 },
                    .{ .kind = 44, .a = 36825, .b = 0, .c = 57 },
                    .{ .kind = 178, .a = 0, .b = 0, .c = 255 },
                    .{ .kind = 189, .a = 0, .b = 0, .c = 0 },
                    .{ .kind = 0, .a = 12738, .b = 50004, .c = 147 },
                    .{ .kind = 1, .a = 0, .b = 0, .c = 32 },
                    .{ .kind = 222, .a = 65535, .b = 63078, .c = 244 },
                    .{ .kind = 1, .a = 0, .b = 42365, .c = 255 },
                    .{ .kind = 174, .a = 47134, .b = 65535, .c = 26 },
                    .{ .kind = 2, .a = 27508, .b = 0, .c = 215 },
                    .{ .kind = 109, .a = 19523, .b = 65535, .c = 246 },
                    .{ .kind = 109, .a = 51727, .b = 65535, .c = 255 },
                    .{ .kind = 154, .a = 0, .b = 0, .c = 228 },
                    .{ .kind = 187, .a = 41102, .b = 60361, .c = 255 },
                    .{ .kind = 255, .a = 1, .b = 2409, .c = 1 },
                    .{ .kind = 184, .a = 18931, .b = 0, .c = 0 },
                    .{ .kind = 36, .a = 0, .b = 0, .c = 1 },
                    .{ .kind = 0, .a = 38209, .b = 0, .c = 20 },
                    .{ .kind = 1, .a = 31016, .b = 2873, .c = 0 },
                    .{ .kind = 0, .a = 65535, .b = 145, .c = 0 },
                    .{ .kind = 0, .a = 0, .b = 47326, .c = 0 },
                    .{ .kind = 235, .a = 0, .b = 65535, .c = 0 },
                },
            },
        },
    };

    const Seq = tcp.SeqNumber;

    const Check = enum { rings_in_bounds, window_fits_ring, fin_follows_all_data, dispatch_fits_egress, dispatch_quiesces };

    /// No operation sequence overflows the buffers or panics.
    pub fn ringsStayInBounds(rx_pick: RxPick, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.rings_in_bounds, rx_pick, peer_isn, o, ops);
    }

    /// What the in-window test admits fits the free space of the receive ring.
    pub fn advertisedWindowFitsRing(rx_pick: RxPick, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.window_fits_ring, rx_pick, peer_isn, o, ops);
    }

    /// A FIN is only consumed once every byte before it was accepted.
    pub fn finConsumesAllPrecedingData(rx_pick: RxPick, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.fin_follows_all_data, rx_pick, peer_isn, o, ops);
    }

    /// Every segment the socket dispatches serializes into the stack's scratch buffer.
    pub fn dispatchedSegmentsFitEgress(rx_pick: RxPick, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.dispatch_fits_egress, rx_pick, peer_isn, o, ops);
    }

    /// Dispatching repeatedly at one instant ends (a 1-byte MSS makes the run long, never endless): the
    /// stack drains a socket with `while (dispatch)`.
    pub fn dispatchQuiesces(rx_pick: RxPick, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        return pick(.dispatch_quiesces, rx_pick, peer_isn, o, ops);
    }

    fn pick(comptime check: Check, rx_pick: RxPick, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
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

    fn run(comptime Ip: type, comptime check: Check, rx_pick: RxPick, peer_isn: u32, o: TcpOpts, ops: [48]TcpOp) bool {
        const Sock = tcp_socket.Socket(Ip, 4);
        const local_addr = addrOf(Ip, 1);
        const peer_addr = addrOf(Ip, 2);
        const egress_limit: usize = if (Ip.ADDRESS_LEN == 16) 1460 else 1480;
        const cap = rx_sizes[rx_pick.get()];
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
                        if (check == .dispatch_quiesces) {
                            var again: usize = 0;
                            while (s.dispatch(now) != null) {
                                again += 1;
                                if (again > 1 << 20) return false;
                            }
                        }
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
            if (s.isListening() and (!s.isOpen() or s.isActive() or s.maySend() or s.mayRecv())) return false;
            switch (check) {
                .rings_in_bounds => if (s.rx_buffer.len() > s.rx_buffer.capacity() or s.tx_buffer.len() > s.tx_buffer.capacity()) return false,
                .window_fits_ring => if (!windowFitsRing(&s)) return false,
                .fin_follows_all_data, .dispatch_fits_egress, .dispatch_quiesces => {},
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

// -------------------------------------------------------------------------
// Neighbor cache integrity and ICMP reply rules.
// -------------------------------------------------------------------------

const iface_mod = @import("iface.zig");
const ethernet_mod = @import("wire/ethernet.zig");

fn lawInterface() iface_mod.Interface {
    var iface = iface_mod.Interface.init(.{ 0x02, 0, 0, 0, 0, 1 });
    iface.v4.addIpAddr(.{ .address = .{ 10, 0, 0, 1 }, .prefix_len = 24 });
    return iface;
}

fn cacheIsClean(iface: *const iface_mod.Interface) bool {
    for (iface.neighbor_cache.entries) |entry| {
        if (ipv4.isUnspecified(entry.protocol_addr)) continue;
        if (!ethernet_mod.isUnicast(entry.hardware_addr)) return false;
        if (ipv4.isMulticast(entry.protocol_addr) or iface.isBroadcast(entry.protocol_addr)) return false;
        if (!iface.v4.inSameNetwork(entry.protocol_addr)) return false;
    }
    return true;
}

pub const neighbors = struct {
    /// Whatever ARP frames arrive, the cache only holds unicast on-link neighbors.
    pub fn arpNeverPoisonsCache(frames: [6]ArpFrame) bool {
        var iface = lawInterface();
        for (frames) |f| {
            var buf: [arp.HEADER_LEN]u8 = undefined;
            const n = arp.emit(.{
                .operation = if (f.reply) .reply else .request,
                .source_hardware_addr = f.mac,
                .source_protocol_addr = f.ip,
                .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 },
                .target_protocol_addr = if (f.to_us) .{ 10, 0, 0, 1 } else f.ip,
            }, &buf) catch return false;
            _ = iface.processArp(buf[0..n]);
            if (!cacheIsClean(&iface)) return false;
        }
        return true;
    }

    /// Refreshing from unauthenticated data packets never creates or changes an entry.
    pub fn refreshNeverCreatesOrChangesEntries(victim_last: u8, ops: [24]NeighborOp) bool {
        var iface = lawInterface();
        const victim_ip: ipv4.Address = .{ 10, 0, 0, @max(victim_last, 2) };
        const victim_mac: ethernet_mod.Address = .{ 0x02, 0, 0, 0, 0, 0x99 };
        iface.neighbor_cache.fill(victim_ip, victim_mac, time_mod.Instant.ZERO);
        var now_ms: i64 = 0;
        for (ops) |op| {
            now_ms += op.dt;
            const ip: ipv4.Address = .{ 10, 0, 0, @max(op.ip_last, 2) };
            const mac: ethernet_mod.Address = .{ op.mac_first & 0xfe, 0, 0, 0, 0, op.mac_last };
            iface.neighbor_cache.refreshIfExisting(ip, mac, time_mod.Instant.fromMillis(now_ms));
            const found = iface.neighbor_cache.lookup(victim_ip, time_mod.Instant.fromMillis(now_ms));
            if (found == null or !std.mem.eql(u8, &found.?, &victim_mac)) return false;
            var occupied: usize = 0;
            for (iface.neighbor_cache.entries) |entry| {
                if (!ipv4.isUnspecified(entry.protocol_addr)) occupied += 1;
            }
            if (occupied != 1) return false;
        }
        return true;
    }
};

const ArpFrame = struct { reply: bool, to_us: bool, ip: ipv4.Address, mac: ethernet_mod.Address };
const NeighborOp = struct { ip_last: u8, mac_first: u8, mac_last: u8, dt: u8 };

pub const icmp_replies = struct {
    pub const pinned = .{
        .echoReplyRules = .{
            .{ .{ 10, 0, 0, 2 }, .{ 224, 0, 0, 251 }, false },
            .{ .{ 0, 0, 0, 0 }, .{ 10, 0, 0, 1 }, false },
        },
    };

    /// Echo replies only go to unicast sources, from the address the request targeted.
    pub fn echoReplyRules(src: ipv4.Address, dst: ipv4.Address, broadcast: bool) bool {
        var iface = lawInterface();
        if (!broadcast and !iface.v4.hasIpAddr(dst) and !ipv4.isMulticast(dst)) return true;
        var msg: [icmp.HEADER_LEN]u8 = undefined;
        _ = icmp.emitEcho(.{ .icmp_type = .echo_request, .code = 0, .checksum = 0, .identifier = 1, .sequence = 1 }, &.{}, &msg) catch return false;
        const repr: ipv4.Repr = .{
            .version = 4,
            .ihl = 5,
            .dscp_ecn = 0,
            .total_length = ipv4.HEADER_LEN + msg.len,
            .identification = 0,
            .dont_fragment = false,
            .more_fragments = false,
            .fragment_offset = 0,
            .ttl = 64,
            .protocol = .icmp,
            .checksum = 0,
            .src_addr = src,
            .dst_addr = dst,
        };
        const reply = iface.processIcmp(repr, &msg, broadcast) orelse return true;
        const out = switch (reply) {
            .ipv4 => |v| v.ip,
            else => return false,
        };
        const src_ok = !ipv4.isUnspecified(src) and !ipv4.isMulticast(src) and !iface.isBroadcast(src);
        return src_ok and !ipv4.isMulticast(out.src_addr) and !ipv4.isUnspecified(out.src_addr);
    }
};

test "laws: neighbor cache and ICMP replies" {
    try zv.checkLaws(neighbors, .{ .iterations = iterations, .seed = 8 });
    try zv.checkLaws(icmp_replies, .{ .iterations = iterations, .seed = 9 });
}

// -------------------------------------------------------------------------
// Handles and send-size limits.
// -------------------------------------------------------------------------

const dns_socket = @import("socket/dns.zig");
const udp_socket = @import("socket/udp.zig");
const icmp_socket = @import("socket/icmp.zig");
const raw_socket = @import("socket/raw.zig");

pub const handles = struct {
    const Dns = dns_socket.Socket(ipv4);

    pub const pinned = .{
        .staleDnsHandlesAreRejected = .{
            .{.{
                .{ .kind = 0, .a = 0, .b = 0 },
                .{ .kind = 1, .a = 0, .b = 0 },
                .{ .kind = 2, .a = 0, .b = 0 },
                .{ .kind = 0, .a = 0, .b = 0 },
                .{ .kind = 2, .a = 0, .b = 0 },
                .{ .kind = 0, .a = 0, .b = 0 },
                .{ .kind = 1, .a = 1, .b = 0 },
                .{ .kind = 2, .a = 1, .b = 0 },
                .{ .kind = 0, .a = 0, .b = 0 },
                .{ .kind = 0, .a = 0, .b = 0 },
                .{ .kind = 2, .a = 0, .b = 0 },
                .{ .kind = 2, .a = 1, .b = 0 },
                .{ .kind = 1, .a = 0, .b = 0 },
                .{ .kind = 0, .a = 0, .b = 0 },
                .{ .kind = 2, .a = 0, .b = 0 },
                .{ .kind = 2, .a = 0, .b = 0 },
            }},
        },
    };

    /// A query handle works until the query is cancelled or read; afterwards
    /// it is stale even when its slot has been reused.
    pub fn staleDnsHandlesAreRejected(ops: [16]Op) bool {
        var slots: [2]Dns.QuerySlot = @splat(.{});
        var sock = Dns.initWithSeed(&slots, &.{.{ 10, 0, 0, 53 }}, 1);
        var live: [2]?Dns.QueryHandle = .{ null, null };
        var dead: [16]Dns.QueryHandle = undefined;
        var dead_count: usize = 0;
        for (ops) |op| {
            const k = op.a & 1;
            switch (op.kind % 3) {
                0 => if (sock.startQuery("example.com", .a)) |h| {
                    live[h.index] = h;
                } else |_| {},
                1 => if (live[k]) |h| {
                    sock.cancelQuery(h);
                    live[k] = null;
                    dead[dead_count % dead.len] = h;
                    dead_count += 1;
                },
                else => if (live[k]) |h| {
                    if (sock.getQueryResult(h)) |_| {} else |err| if (err != error.Pending) return false;
                },
            }
            for (dead[0..@min(dead_count, dead.len)]) |h| {
                if (sock.getQueryResult(h)) |_| return false else |err| if (err != error.StaleHandle) return false;
            }
            for (live) |maybe| if (maybe) |h| {
                if (sock.getQueryResult(h)) |_| {} else |err| if (err == error.StaleHandle) return false;
            };
        }
        return true;
    }
};

pub const send_limits = struct {
    pub const pinned = .{
        .udpSendLimit = .{ .{ 4, false }, .{ 4, true } },
        .icmpSendLimit = .{ .{ 4, false }, .{ 4, true } },
    };

    /// A payload up to MAX_PAYLOAD_LEN is accepted; one byte more is refused
    /// at send time instead of being dropped by the stack.
    pub fn udpSendLimit(extra: u8, v6: bool) bool {
        return if (v6) udpSendLimitFor(ipv6, extra) else udpSendLimitFor(ipv4, extra);
    }

    fn udpSendLimitFor(comptime Ip: type, extra: u8) bool {
        const Sock = udp_socket.Socket(Ip);
        var rx_meta: [1]Sock.PacketMeta = .{.{}};
        var rx_payload: [8]u8 = undefined;
        var tx_meta: [1]Sock.PacketMeta = .{.{}};
        var tx_payload: [8192]u8 = undefined;
        var sock = Sock.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);
        sock.bind(.{ .port = 1000 }) catch return false;
        var dest: Ip.Address = @splat(1);
        dest[0] = 10;
        const meta = Sock.Metadata{ .endpoint = .{ .addr = dest, .port = 2000 } };
        const len = Sock.MAX_PAYLOAD_LEN - 2 + extra % 5;
        const result = sock.sendSlice(payload_mem[0..len], meta);
        if (len > Sock.MAX_PAYLOAD_LEN) return result == error.PayloadTooLarge;
        return if (result) |_| true else |_| false;
    }

    pub fn icmpSendLimit(extra: u8, v6: bool) bool {
        return if (v6) icmpSendLimitFor(ipv6, extra) else icmpSendLimitFor(ipv4, extra);
    }

    fn icmpSendLimitFor(comptime Ip: type, extra: u8) bool {
        const Sock = icmp_socket.Socket(Ip);
        var rx_meta: [1]Sock.PacketMeta = .{.{}};
        var rx_payload: [8]u8 = undefined;
        var tx_meta: [1]Sock.PacketMeta = .{.{}};
        var tx_payload: [8192]u8 = undefined;
        var sock = Sock.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);
        var dest: Ip.Address = @splat(1);
        dest[0] = 10;
        const len = Sock.MAX_PAYLOAD_LEN - 2 + extra % 5;
        const result = sock.sendSlice(payload_mem[0..len], dest);
        if (len > Sock.MAX_PAYLOAD_LEN) return result == error.PayloadTooLarge;
        return if (result) |_| true else |_| false;
    }
};

// -------------------------------------------------------------------------
// Pinned counterexamples. Each (law, seed, iteration) failed on the code
// before the named fix; replay regenerates the exact arguments.
// -------------------------------------------------------------------------

test "laws: handles and send limits" {
    try zv.checkLaws(handles, .{ .iterations = iterations, .seed = 10 });
    try zv.checkLaws(send_limits, .{ .iterations = 2_000, .seed = 11 });
}

// -------------------------------------------------------------------------
// Every address-family generic is instantiated and analyzed for both families,
// so a method that only compiles for one (an uninstantiated Socket(ipv6) once
// hid a compile error) fails here.
// -------------------------------------------------------------------------

test "generics compile for both IP families" {
    inline for (.{ ipv4, ipv6 }) |Ip| {
        std.testing.refAllDecls(tcp_socket.Socket(Ip, 4));
        std.testing.refAllDecls(udp_socket.Socket(Ip));
        std.testing.refAllDecls(icmp_socket.Socket(Ip));
        std.testing.refAllDecls(raw_socket.Socket(Ip, .{ .payload_size = 64 }));
        std.testing.refAllDecls(dns_socket.Socket(Ip));
        std.testing.refAllDecls(iface_mod.NeighborCache(Ip));
        std.testing.refAllDecls(iface_mod.IpState(Ip));
        std.testing.refAllDecls(iface_mod.RoutesFor(Ip));
        std.testing.refAllDecls(@import("wire/ip.zig").Cidr(Ip));
    }
}

// -------------------------------------------------------------------------
// Generic shapes: framing and single-bit integrity.
// -------------------------------------------------------------------------

fn within(outer: []const u8, inner: []const u8) bool {
    const o = @intFromPtr(outer.ptr);
    const n = @intFromPtr(inner.ptr);
    return n >= o and n + inner.len <= o + outer.len;
}

pub const framing = struct {
    pub const pinned = .{
        .ipv6PayloadInsideInput = .{
            .{.{ 255, 255, 255, 255, 255, 255, 255, 255 }},
        },
    };

    /// Payload views handed to upper layers lie inside the input and respect the declared length.
    pub fn ipv4PayloadInsideInput(in: zv.Bytes(80)) bool {
        var buf: [80]u8 = undefined;
        const n = load(80, in, &buf);
        const ihl: usize = 5 + (buf[0] & 0x0f) % 11;
        buf[0] = 0x40 | @as(u8, @intCast(ihl));
        const data = buf[0..@max(n, ihl * 4)];
        const p = ipv4.payloadSlice(data) catch return true;
        const declared = (@as(usize, data[2]) << 8) | data[3];
        return within(data, p) and p.len + ihl * 4 == declared;
    }
    pub fn ipv6PayloadInsideInput(in: zv.Bytes(64)) bool {
        var buf: [64]u8 = undefined;
        const n = @max(load(64, in, &buf), ipv6.HEADER_LEN);
        buf[0] = 0x60 | (buf[0] & 0x0f);
        const data = buf[0..n];
        const p = ipv6.payloadSlice(data) catch return true;
        const declared = (@as(usize, data[4]) << 8) | data[5];
        return within(data, p) and p.len == declared;
    }
    pub fn udpPayloadInsideInput(in: zv.Bytes(48)) bool {
        var buf: [48]u8 = undefined;
        const n = load(48, in, &buf);
        const data = buf[0..n];
        const p = udp.payloadSlice(data) catch return true;
        const declared = if (n >= 6) (@as(usize, data[4]) << 8) | data[5] else 0;
        return within(data, p) and p.len + udp.HEADER_LEN == declared;
    }
    pub fn ethernetPayloadInsideInput(in: zv.Bytes(32)) bool {
        const data = in.slice();
        const p = ethernet.payload(data) catch return true;
        return within(data, p) and p.len + ethernet.HEADER_LEN == data.len;
    }
    pub fn ieee802154PayloadInsideInput(in: zv.Bytes(64)) bool {
        const data = in.slice();
        const p = ieee802154.payloadSlice(data) catch return true;
        return within(data, p);
    }
    pub fn extensionViewsInsideInput(in: zv.Bytes(64)) bool {
        const data = in.slice();
        if (ipv6ext_header.parse(data)) |r| {
            if (!within(data, r.data) or ipv6ext_header.headerLen(r.length) > data.len) return false;
        } else |_| {}
        if (ipv6ext_header.payloadSlice(data)) |p| {
            if (!within(data, p) or p.len + 2 != ipv6ext_header.headerLen(data[1])) return false;
        } else |_| {}
        if (ipv6routing.parse(data)) |r| switch (r) {
            .rpl => |v| if (!within(data, v.addresses)) return false,
            else => {},
        } else |_| {}
        if (ndiscoption.parse(data)) |r| switch (r) {
            .unknown => |v| if (!within(data, v.data)) return false,
            else => {},
        } else |_| {}
        if (ipv6option.parse(data)) |r| switch (r) {
            .unknown => |v| if (!within(data, v.data)) return false,
            else => {},
        } else |_| {}
        return true;
    }
    pub fn dnsViewsInsideInput(in: zv.Bytes(64)) bool {
        var buf: [64]u8 = undefined;
        const n = @max(load(64, in, &buf), 24);
        const label: usize = buf[0] % 8;
        buf[0] = @intCast(label);
        buf[label + 1] = 0;
        buf[label + 4] = 0;
        buf[label + 5] = 1;
        const data = buf[0..n];
        if (dns.parseQuestion(data)) |q| {
            if (!within(data, q.rest) or !within(data, q.question.name)) return false;
        } else |_| {}
        if (dns.parseRecord(data)) |r| {
            if (!within(data, r.rest) or !within(data, r.record.name)) return false;
        } else |_| {}
        return true;
    }
};

pub const integrity = struct {
    fn flip(buf: []u8, bit: u16) void {
        buf[(bit / 8) % buf.len] ^= @as(u8, 1) << @intCast(bit % 8);
    }

    /// Flipping any single bit of a valid checksummed packet makes it fail verification.
    pub fn ipv4HeaderBitFlip(in: zv.Bytes(60), bit: u16) bool {
        var buf: [60]u8 = undefined;
        _ = load(60, in, &buf);
        const ihl: usize = 5 + (buf[0] & 0x0f) % 11;
        buf[0] = 0x40 | @as(u8, @intCast(ihl));
        putU16(buf[10..12], 0);
        putU16(buf[10..12], checksum.internetChecksum(buf[0 .. ihl * 4]));
        if (!ipv4.verifyChecksum(buf[0 .. ihl * 4])) return false;
        var flipped = buf;
        flip(flipped[0 .. ihl * 4], bit);
        return !ipv4.verifyChecksum(flipped[0 .. ihl * 4]);
    }

    pub fn icmpBitFlip(in: zv.Bytes(40), bit: u16) bool {
        var buf: [40]u8 = undefined;
        const n = @max(load(40, in, &buf), icmp.HEADER_LEN);
        putU16(buf[2..4], 0);
        putU16(buf[2..4], checksum.internetChecksum(buf[0..n]));
        if (icmp.parse(buf[0..n])) |_| {} else |_| return false;
        var flipped = buf;
        flip(flipped[0..n], bit);
        if (icmp.parse(flipped[0..n])) |_| return false else |_| return true;
    }

    pub fn icmpv6BitFlip(in: zv.Bytes(40), bit: u16, src: [16]u8, dst: [16]u8) bool {
        var buf: [40]u8 = undefined;
        const n = @max(load(40, in, &buf), icmpv6.HEADER_LEN);
        putU16(buf[2..4], 0);
        const pseudo = checksum.pseudoHeaderChecksumV6(src, dst, @backingInt(ipv6.Protocol.icmpv6), @intCast(n));
        putU16(buf[2..4], checksum.finish(checksum.calculate(buf[0..n], pseudo)));
        if (!icmpv6.verifyChecksum(buf[0..n], src, dst)) return false;
        var flipped = buf;
        flip(flipped[0..n], bit);
        return !icmpv6.verifyChecksum(flipped[0..n], src, dst);
    }

    pub fn tcpBitFlip(in: zv.Bytes(60), bit: u16, src: [4]u8, dst: [4]u8) bool {
        var buf: [60]u8 = undefined;
        const n = @max(load(60, in, &buf), tcp.HEADER_LEN);
        putU16(buf[16..18], 0);
        putU16(buf[16..18], tcp.computeChecksum(src, dst, buf[0..n]));
        if (!tcp.verifyChecksum(src, dst, buf[0..n])) return false;
        var flipped = buf;
        flip(flipped[0..n], bit);
        return !tcp.verifyChecksum(src, dst, flipped[0..n]);
    }

    pub fn udpBitFlip(in: zv.Bytes(60), bit: u16, src: [4]u8, dst: [4]u8) bool {
        var buf: [60]u8 = undefined;
        const n = @max(load(60, in, &buf), udp.HEADER_LEN);
        putU16(buf[4..6], @intCast(n));
        udp.fillChecksum(buf[0..n], src, dst);
        if (!udp.verifyChecksum(buf[0..n], src, dst)) return false;
        var flipped = buf;
        flip(flipped[0..n], bit);
        // a flip that makes the checksum field zero means "no checksum" over IPv4, by design
        if (flipped[6] == 0 and flipped[7] == 0) return true;
        return !udp.verifyChecksum(flipped[0..n], src, dst);
    }
};

test "laws: framing and integrity" {
    try zv.checkLaws(framing, .{ .iterations = iterations, .seed = 12 });
    try zv.checkLaws(integrity, .{ .iterations = iterations, .seed = 13 });
}

// -------------------------------------------------------------------------
// Configuration and classification helpers.
// -------------------------------------------------------------------------

const dhcp_socket = @import("socket/dhcp.zig");

pub const configuration = struct {
    /// RFC 8200 4.2: the two high bits of an option type say what to do with an unrecognized option.
    pub fn optionFailureTypeIsTopTwoBits(opt_type: u8) bool {
        return @backingInt(ipv6option.failureTypeFromOptionType(opt_type)) == opt_type >> 6;
    }

    /// DHCP socket setters take effect, and equal seeds give equal transaction ids.
    pub fn dhcpSettersTakeEffect(hw: [6]u8, seed: u64, other_seed: u64, server: u16, client: u16, ignore: bool, lease_secs: ?u16, retries: u16) bool {
        var a = dhcp_socket.Socket.initWithTransactionSeed(hw, seed);
        const b = dhcp_socket.Socket.initWithTransactionSeed(hw, seed);
        if (a.transaction_id != b.transaction_id) return false;
        var prng_a: std.Random.DefaultPrng = .init(seed);
        var prng_b: std.Random.DefaultPrng = .init(seed);
        const c = dhcp_socket.Socket.initWithRandom(hw, prng_a.random());
        const e = dhcp_socket.Socket.initWithTransactionSeed(hw, prng_b.random().int(u64));
        if (c.transaction_id != e.transaction_id) return false;
        a.setTransactionIdSeed(other_seed);
        var d = dhcp_socket.Socket.initWithTransactionSeed(hw, other_seed);
        d.setTransactionIdSeed(other_seed);
        if (a.transaction_id != d.transaction_id) return false;
        var prng_c: std.Random.DefaultPrng = .init(seed);
        var prng_d: std.Random.DefaultPrng = .init(seed);
        var f = dhcp_socket.Socket.initWithTransactionSeed(hw, other_seed);
        f.setTransactionIdRandom(prng_c.random());
        var g = dhcp_socket.Socket.initWithTransactionSeed(hw, other_seed);
        g.setTransactionIdSeed(prng_d.random().int(u64));
        if (f.transaction_id != g.transaction_id) return false;
        a.setPorts(server, client);
        a.setIgnoreNaks(ignore);
        a.setMaxLeaseDuration(if (lease_secs) |l| time_mod.Duration.fromSecs(l) else null);
        a.setRetryConfig(.{ .request_retries = retries });
        return a.server_port == server and a.client_port == client and a.ignore_naks == ignore and
            a.getRetryConfig().request_retries == retries and
            (a.max_lease_duration == null) == (lease_secs == null);
    }
};

test "laws: configuration" {
    try zv.checkLaws(configuration, .{ .iterations = iterations, .seed = 14 });
}

/// Flip to true to print, per parser, how often laws reach a value versus each error.
const report_reach = false;

test "laws: reach report" {
    if (report_reach) std.debug.print("\nlaw reach (parser result counts)\n", .{});
    for (probes[0..probe_count]) |p| {
        var total: usize = p.ok;
        for (p.err_counts[0..p.err_kinds]) |c| total += c;
        const name = if (std.mem.indexOfScalar(u8, p.name, '!')) |i| p.name[i + 1 ..] else p.name;
        if (report_reach) {
            std.debug.print("  {s: <46} ok {d: >7} of {d: >7}", .{ name[0..@min(name.len, 46)], p.ok, total });
            for (p.err_names[0..p.err_kinds], p.err_counts[0..p.err_kinds]) |n, c| std.debug.print("  {s}={d}", .{ n, c });
            std.debug.print("\n", .{});
        }
        if (std.mem.endsWith(u8, p.name, "*")) try std.testing.expect(p.ok > 0);
    }
}

// -------------------------------------------------------------------------
// Value types, bounded lists and congestion control.
// -------------------------------------------------------------------------

pub const values = struct {
    const Dns = dns_socket.Socket(ipv4);

    /// Instants are ordered by their microsecond count, and every comparison agrees with it.
    pub fn instantsAreTotallyOrdered(a: i64, b: i64) bool {
        const x = time_mod.Instant.fromMicros(a);
        const y = time_mod.Instant.fromMicros(b);
        return x.totalMicros() == a and
            x.lessThan(y) == (a < b) and
            x.greaterThanOrEqual(y) == (a >= b) and
            x.eql(y) == (a == b) and
            x.cmp(y) == std.math.order(a, b) and
            y.cmp(x) == x.cmp(y).invert();
    }

    pub fn durationsAreTotallyOrdered(a: i64, b: i64) bool {
        const x = time_mod.Duration.fromMicros(a);
        const y = time_mod.Duration.fromMicros(b);
        return x.totalMicros() == a and
            x.lessThan(y) == (a < b) and
            x.greaterThanOrEqual(y) == (a >= b) and
            x.eql(y) == (a == b);
    }

    /// A full list drops later entries instead of overwriting earlier ones.
    pub fn boundedListsKeepTheFirstEntries(addrs: [10][4]u8, count: u8) bool {
        const n = count % (addrs.len + 1);
        var servers: dhcp.DnsServers = .{};
        var answers: Dns.Addresses = .{};
        for (addrs[0..n]) |a| {
            servers.push(a);
            answers.push(a);
        }
        if (servers.len != @min(n, dhcp.MAX_DNS_SERVER_COUNT)) return false;
        if (answers.len != @min(n, dns_socket.MAX_RESULT_COUNT)) return false;
        for (0..servers.len) |i| if (!std.mem.eql(u8, &servers.get(i), &addrs[i])) return false;
        for (0..answers.len) |i| if (!std.mem.eql(u8, &answers.get(i), &addrs[i])) return false;
        var other = servers;
        if (other.len > 0) {
            other.addrs[other.len - 1][3] ^= 1;
            if (servers.eql(&other)) return false;
        }
        return servers.eql(&servers);
    }

    /// RFC 1035 3.1: a name is length-prefixed labels ending in a zero byte, and parsing it
    /// gives back each label.
    pub fn nameLabelsDecodeTheWireName(lens: [4]u8, fill: [4]u8, count: u8) bool {
        var wire_name: [40]u8 = undefined;
        const labels = count % 4 + 1;
        var at: usize = 0;
        for (0..labels) |i| {
            const len = lens[i] % 8 + 1;
            wire_name[at] = len;
            @memset(wire_name[at + 1 ..][0..len], fill[i]);
            at += 1 + len;
        }
        wire_name[at] = 0;
        const parsed = dns.parseName(wire_name[0 .. at + 1], 0) catch return false;
        if (parsed.len != labels) return false;
        for (0..labels) |i| {
            const label = parsed.get(i);
            if (label.len != lens[i] % 8 + 1) return false;
            for (label) |c| if (c != fill[i]) return false;
        }
        return true;
    }

    /// Two configurations are equal exactly when every field is.
    pub fn dhcpEventEqualityIsStructural(server: [4]u8, id: [4]u8, addr: [4]u8, prefix: u6, router: ?[4]u8, dns_addr: [4]u8, which: u8) bool {
        var servers: dhcp.DnsServers = .{};
        servers.push(dns_addr);
        const base: dhcp_socket.Config = .{
            .server = .{ .address = server, .identifier = id },
            .address = addr,
            .prefix_len = prefix,
            .router = router,
            .dns_servers = servers,
        };
        var changed = base;
        switch (which % 6) {
            0 => changed.server.address[0] ^= 1,
            1 => changed.server.identifier[0] ^= 1,
            2 => changed.address[3] ^= 1,
            3 => changed.prefix_len ^= 1,
            4 => if (changed.router) |*r| {
                r[0] ^= 1;
            } else {
                changed.router = .{ 0, 0, 0, 0 };
            },
            else => changed.dns_servers.addrs[0][1] ^= 1,
        }
        const a: dhcp_socket.Event = .{ .configured = base };
        const b: dhcp_socket.Event = .{ .configured = changed };
        const gone: dhcp_socket.Event = .deconfigured;
        return a.eql(a) and !a.eql(b) and !b.eql(a) and !a.eql(gone) and !gone.eql(a) and gone.eql(gone);
    }

    /// Both address families satisfy the interface generic code relies on.
    pub fn bothFamiliesAreIpTypes() bool {
        ip_mod.assertIsIp(ipv4);
        ip_mod.assertIsIp(ipv6);
        return true;
    }
};

test "laws: values" {
    try zv.checkLaws(values, .{ .iterations = iterations, .seed = 15 });
}

/// CUBIC (RFC 8312): a loss event cuts the window to BETA (0.7) of its value at the loss,
/// then it grows back, never shrinking until the next loss.
pub const congestion = struct {
    const Cubic = tcp_socket.Cubic;
    const beta = 0.7;

    /// A live connection never has a window below one segment, so that is where laws start.
    fn afterLoss(window: u16, segment: u16, duplicate_ack: bool, now_ms: u16) Cubic {
        const mss = @as(usize, segment) + 1;
        var c: Cubic = .{ .cwnd = @max(window, mss), .w_max = 0 };
        c.setMss(mss);
        c.setRemoteWindow(1 << 20);
        const now = time_mod.Instant.fromMillis(now_ms);
        if (duplicate_ack) c.onDuplicateAck(now) else c.onRetransmit(now);
        return c;
    }

    pub fn lossCutsTheWindowToBeta(window: u16, segment: u16, duplicate_ack: bool, now_ms: u16) bool {
        var c = afterLoss(window, segment, duplicate_ack, now_ms);
        const before = c.cwnd;
        if (c.w_max != before or c.ssthresh != before >> 1) return false;
        const now = time_mod.Instant.fromMillis(now_ms);
        c.preTransmit(now);
        c.postTransmit(now, 1);
        const expected = @max(@as(f64, @floatFromInt(before)) * beta, @as(f64, @floatFromInt(c.min_cwnd)));
        return @abs(@as(f64, @floatFromInt(c.window())) - expected) <= 4;
    }

    pub fn windowNeverShrinksWhileRecovering(window: u16, segment: u16, steps: [12]u16) bool {
        var c = afterLoss(window, segment, false, 0);
        var now_ms: i64 = 0;
        c.preTransmit(time_mod.Instant.fromMillis(now_ms));
        var last = c.window();
        for (steps) |dt| {
            now_ms += dt;
            c.preTransmit(time_mod.Instant.fromMillis(now_ms));
            if (c.window() < last) return false;
            last = c.window();
        }
        return true;
    }
};

test "laws: congestion control" {
    try zv.checkLaws(congestion, .{ .iterations = iterations, .seed = 16 });
}

// -------------------------------------------------------------------------
// Devices, middleware and seeding.
// -------------------------------------------------------------------------

const stack_mod = @import("stack.zig");
const phy_mod = @import("phy.zig");

pub const devices = struct {
    const Loopback = stack_mod.LoopbackDevice(3);

    const Capped = struct {
        pub fn capabilities() iface_mod.DeviceCapabilities {
            return .{ .max_transmission_unit = 1280, .max_burst_size = 4 };
        }
    };

    /// An in-memory device is two bounded FIFOs: a full queue drops the new frame, and
    /// `loopback` moves transmitted frames to the receive side in order.
    pub fn loopbackIsABoundedFifo(ops: [24]Op) bool {
        var dev = Loopback.init();
        var rx: [3]u8 = undefined;
        var tx: [3]u8 = undefined;
        var rx_n: usize = 0;
        var tx_n: usize = 0;
        for (ops) |op| {
            const tag = [1]u8{op.a};
            switch (op.kind % 5) {
                0 => {
                    dev.enqueueRx(&tag);
                    if (rx_n < rx.len) {
                        rx[rx_n] = op.a;
                        rx_n += 1;
                    }
                },
                1 => {
                    dev.transmit(&tag);
                    if (tx_n < tx.len) {
                        tx[tx_n] = op.a;
                        tx_n += 1;
                    }
                },
                2 => {
                    const got = dev.receive();
                    if ((got == null) != (rx_n == 0)) return false;
                    if (got) |frame| {
                        if (frame.len != 1 or frame[0] != rx[0]) return false;
                        std.mem.copyForwards(u8, rx[0 .. rx_n - 1], rx[1..rx_n]);
                        rx_n -= 1;
                    }
                },
                3 => {
                    const got = dev.dequeueTx();
                    if ((got == null) != (tx_n == 0)) return false;
                    if (got) |frame| {
                        if (frame.len != 1 or frame[0] != tx[0]) return false;
                        std.mem.copyForwards(u8, tx[0 .. tx_n - 1], tx[1..tx_n]);
                        tx_n -= 1;
                    }
                },
                else => {
                    dev.loopback();
                    for (tx[0..tx_n]) |t| {
                        if (rx_n < rx.len) {
                            rx[rx_n] = t;
                            rx_n += 1;
                        }
                    }
                    tx_n = 0;
                },
            }
        }
        return true;
    }

    /// Tracing, fault injection and capture are transparent to the layer above: they report
    /// the capabilities of the device they wrap (the defaults when it declares none).
    pub fn middlewareReportsTheWrappedCapabilities() bool {
        inline for (.{ Loopback, Capped }) |Dev| {
            const want = if (@hasDecl(Dev, "capabilities")) Dev.capabilities() else iface_mod.DeviceCapabilities{};
            inline for (.{ phy_mod.Tracer(Dev), phy_mod.FaultInjector(Dev), phy_mod.PcapWriter(Dev) }) |Wrapped| {
                if (!std.meta.eql(Wrapped.capabilities(), want)) return false;
            }
        }
        return true;
    }
};

test "laws: devices" {
    try zv.checkLaws(devices, .{ .iterations = iterations, .seed = 17 });
}

pub const seeding = struct {
    const Dns = dns_socket.Socket(ipv4);

    const FirstQuery = struct { txid: u16, port: u16 };

    fn firstQuery(sock: *Dns) ?FirstQuery {
        _ = sock.startQuery("example.com", .a) catch return null;
        var buf: [512]u8 = undefined;
        const sent = sock.dispatch(time_mod.Instant.fromMillis(0), &buf) orelse return null;
        return .{ .txid = std.mem.readInt(u16, sent.payload[0..2], .big), .port = sent.src_port };
    }

    /// Every way of seeding a DNS socket, from a value or from a `Random`, at construction or
    /// later, gives the same transaction id and source port as seeding with that value.
    pub fn dnsSeedsDecideTheFirstQuery(seed: u64) bool {
        const servers = [_]ipv4.Address{.{ 10, 0, 0, 53 }};
        var slots: [4][1]Dns.QuerySlot = @splat(@splat(.{}));
        var prng: std.Random.DefaultPrng = .init(seed);
        const drawn = prng.random().int(u64);
        var prng_a: std.Random.DefaultPrng = .init(seed);
        var prng_b: std.Random.DefaultPrng = .init(seed);

        var direct = Dns.initWithSeed(&slots[0], &servers, drawn);
        var random = Dns.initWithRandom(&slots[1], &servers, prng_a.random());
        var reseeded = Dns.initWithSeed(&slots[2], &servers, ~drawn);
        reseeded.setQuerySeed(drawn);
        var reseeded_random = Dns.initWithSeed(&slots[3], &servers, ~drawn);
        reseeded_random.setQueryRandom(prng_b.random());

        const want = firstQuery(&direct) orelse return false;
        for ([_]*Dns{ &random, &reseeded, &reseeded_random }) |sock| {
            const got = firstQuery(sock) orelse return false;
            if (!std.meta.eql(want, got)) return false;
        }
        return true;
    }

    /// A TCP socket seeded from a `Random` draws one u64 secret, and a zero secret is never kept
    /// (initial sequence numbers hashed from it would be predictable).
    pub fn tcpSeedsDecideTheSecret(seed: u64) bool {
        const Sock = tcp_socket.Socket(ipv4, 4);
        var rx: [16]u8 = undefined;
        var tx: [16]u8 = undefined;
        var prng: std.Random.DefaultPrng = .init(seed);
        const drawn = prng.random().int(u64);
        var prng_a: std.Random.DefaultPrng = .init(seed);
        var prng_b: std.Random.DefaultPrng = .init(seed);

        const direct = Sock.initWithInitialSequenceSecret(&rx, &tx, drawn);
        const random = Sock.initWithRandom(&rx, &tx, prng_a.random());
        var reseeded = Sock.initWithInitialSequenceSecret(&rx, &tx, ~drawn);
        reseeded.setInitialSequenceRandom(prng_b.random());
        var zeroed = Sock.initWithInitialSequenceSecret(&rx, &tx, 1);
        zeroed.setInitialSequenceSecret(0);
        return direct.isn_secret == random.isn_secret and
            direct.isn_secret == reseeded.isn_secret and
            direct.isn_secret != 0 and zeroed.isn_secret != 0 and
            Sock.initWithInitialSequenceSecret(&rx, &tx, 0).isn_secret != 0;
    }

    /// Closing an ICMP socket unbinds it and discards what it queued, and it can be bound again.
    pub fn icmpCloseDiscardsQueues(len: u8, ident: u16) bool {
        const Sock = icmp_socket.Socket(ipv4);
        var rx_meta: [1]Sock.PacketMeta = .{.{}};
        var rx_payload: [32]u8 = undefined;
        var tx_meta: [1]Sock.PacketMeta = .{.{}};
        var tx_payload: [64]u8 = undefined;
        var sock = Sock.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);
        sock.bind(.{ .ident = ident }) catch return false;
        sock.sendSlice(payload_mem[0 .. len % 16], .{ 10, 0, 0, 9 }) catch return false;
        if (!sock.isOpen()) return false;
        sock.close();
        if (sock.isOpen() or sock.canRecv() or sock.dispatch() != null) return false;
        sock.bind(.{ .ident = ident }) catch return false;
        return sock.canSend() and sock.dispatch() == null;
    }
};

test "laws: seeding" {
    try zv.checkLaws(seeding, .{ .iterations = iterations, .seed = 18 });
}

// -------------------------------------------------------------------------
// RPL routing state (RFC 6550, RFC 6552, RFC 6206).
// -------------------------------------------------------------------------

const rpl_state = @import("rpl.zig");

pub const routing = struct {
    const Seq = rpl_state.SequenceCounter;
    const Rank = rpl_state.Rank;
    const Parents = rpl_state.ParentSet(4);
    const Links = rpl_state.Relations(4);
    const window = rpl_state.SEQUENCE_WINDOW;

    pub const pinned = .{
        .objectiveFunctionRanksChildrenBelowTheirParent = .{ .{ 0, 40000 }, .{ 1000, 65535 }, .{ 65535, 22000 } },
        .trickleToleratesAnyConfiguredExponent = .{ .{ 255, 255, 0, 0, .{ 0, 0, 0, 0 } }, .{ 64, 0, 1, 7, .{ 1, 1, 1, 1 } } },
    };

    fn region(v: u8) bool {
        return v >= 128;
    }

    /// RFC 6550 7.2: counters are comparable when they are in different regions or no more than
    /// SEQUENCE_WINDOW apart in one region, and comparison is antisymmetric.
    pub fn sequenceOrderIsAntisymmetric(a: u8, b: u8) bool {
        const x = Seq{ .value = a };
        const y = Seq{ .value = b };
        const xy = x.order(y);
        const yx = y.order(x);
        if (a == b) return xy == .eq and yx == .eq;
        const comparable = region(a) != region(b) or @abs(@as(i16, a) - @as(i16, b)) <= window;
        if (!comparable) return xy == null and yx == null;
        return xy != null and yx != null and xy.? == yx.?.invert() and xy.? != .eq;
    }

    /// Incrementing makes a counter newer than before (the point of a lollipop counter) for up to
    /// SEQUENCE_WINDOW steps, including the step from the linear region into the circular one.
    /// The circular region stays below 128, and a wrap inside it is the one case left incomparable.
    pub fn incrementingMakesACounterNewer(start: u8, steps: u8) bool {
        const k = steps % (window + 1);
        const before = Seq{ .value = start };
        var c = before;
        for (0..k) |_| c.increment();
        if (!region(start) and region(c.value)) return false;
        if (k == 0) return c.order(before).? == .eq;
        const wrapped_circular = !region(start) and c.value < start;
        if (wrapped_circular) return c.order(before) == null and before.order(c) == null;
        return c.order(before).? == .gt and before.order(c).? == .lt;
    }

    /// Ranks compare by their integer part, DAGRank = rank / MinHopRankIncrease.
    pub fn rankOrderFollowsTheIntegerPart(v1: u16, m1: u16, v2: u16, m2: u16) bool {
        const a = Rank{ .value = v1, .min_hop_rank_increase = @max(m1, 1) };
        const b = Rank{ .value = v2, .min_hop_rank_increase = @max(m2, 1) };
        return a.dagRank() == v1 / @max(m1, 1) and
            a.order(b) == std.math.order(a.dagRank(), b.dagRank()) and
            b.order(a) == a.order(b).invert() and
            Rank.ROOT.dagRank() == 1 and Rank.INFINITE.order(Rank.ROOT) == .gt;
    }

    /// RFC 6552 (OF0): a node ranks itself farther from the root than its parent, by three
    /// hops' worth, saturating at the infinite rank. This must hold for any advertised
    /// MinHopRankIncrease, which arrives as a 16-bit field from the network.
    pub fn objectiveFunctionRanksChildrenBelowTheirParent(value: u16, increase: u16) bool {
        const parent = Rank{ .value = value, .min_hop_rank_increase = @max(increase, 1) };
        const child = rpl_state.ObjectiveFunction0.computeRank(parent);
        if (child.min_hop_rank_increase != parent.min_hop_rank_increase or child.value < parent.value) return false;
        if (child.value == 0xFFFF) return true;
        return parent.order(child) == .lt;
    }

    const SetOp = struct { kind: u8, addr: u8, rank: u8 };

    fn setAddr(sel: u8) [16]u8 {
        var a: [16]u8 = @splat(0);
        a[0] = 0xfd;
        a[15] = sel % 6;
        return a;
    }

    fn setParent(rank: u8) rpl_state.Parent {
        return .{
            .rank = .{ .value = @as(u16, rank % 8) * 256, .min_hop_rank_increase = 256 },
            .preference = 0,
            .version_number = Seq.INIT,
            .dodag_id = @splat(0),
        };
    }

    /// A parent set holds distinct addresses up to its capacity; when full it admits only a parent
    /// strictly better than its worst one, evicting that one. The preferred parent is the first
    /// of the best-ranked entries, the worst parent the last of the worst-ranked.
    pub fn parentSetKeepsTheBestParents(ops: [32]SetOp) bool {
        var set: Parents = .{};
        for (ops) |op| {
            const addr = setAddr(op.addr);
            var before: [6]?u16 = @splat(null);
            for (0..6) |i| if (set.find(setAddr(@intCast(i)))) |p| {
                before[i] = p.rank.dagRank();
            };
            const full = set.count() == 4;
            var worst: u16 = 0;
            for (before) |b| if (b) |d| {
                worst = @max(worst, d);
            };
            const was_present = before[addr[15]] != null;
            switch (op.kind % 3) {
                0, 1 => {
                    const p = setParent(op.rank);
                    const added = set.add(addr, p);
                    const should_add = was_present or !full or p.rank.dagRank() < worst;
                    if (added != should_add) return false;
                    if (added) {
                        const got = set.find(addr) orelse return false;
                        if (got.rank.dagRank() != p.rank.dagRank()) return false;
                    }
                    if (!was_present and full) {
                        var lost: usize = 0;
                        for (0..6) |i| {
                            if (i == addr[15]) continue;
                            if (before[i] != null and set.find(setAddr(@intCast(i))) == null) {
                                if (!added or before[i].? != worst) return false;
                                lost += 1;
                            }
                        }
                        if (lost != @intFromBool(added)) return false;
                    }
                },
                else => {
                    if (set.remove(addr) != was_present or set.find(addr) != null) return false;
                },
            }
            var n: usize = 0;
            for (0..6) |i| {
                if (set.find(setAddr(@intCast(i))) != null) n += 1;
            }
            if (n != set.count() or n > 4) return false;
            const best = rpl_state.ObjectiveFunction0.preferredParent(4, &set);
            const bad = set.worstParent();
            if ((best == null) != (n == 0) or (bad == null) != (n == 0)) return false;
            if (best) |bi| {
                const bd = set.entries[bi].?.parent.rank.dagRank();
                for (set.entries, 0..) |e, i| if (e) |entry| {
                    const d = entry.parent.rank.dagRank();
                    if (d < bd or (d == bd and i < bi)) return false;
                };
            }
            if (bad) |wi| {
                const wd = set.entries[wi].?.parent.rank.dagRank();
                for (set.entries, 0..) |e, i| if (e) |entry| {
                    const d = entry.parent.rank.dagRank();
                    if (d > wd or (d == wd and i > wi)) return false;
                };
            }
        }
        return true;
    }

    const LinkOp = struct { kind: u8, dest: u8, hop: u8, expires: u8 };

    /// A relation table is a bounded map from destination to next hop; purging removes exactly
    /// the relations whose expiration has been reached.
    pub fn relationsAreABoundedMap(ops: [32]LinkOp) bool {
        var table: Links = .{};
        var hop: [6]?u8 = @splat(null);
        var expires: [6]u8 = @splat(0);
        for (ops) |op| {
            const dest = op.dest % 6;
            var d: [16]u8 = @splat(0);
            d[15] = dest;
            var h: [16]u8 = @splat(0);
            h[15] = op.hop;
            var live: usize = 0;
            for (hop) |x| live += @intFromBool(x != null);
            switch (op.kind % 4) {
                0 => {
                    const added = table.addRelation(d, h, time_mod.Instant.fromSecs(op.expires));
                    const should = hop[dest] != null or live < 4;
                    if (added != should) return false;
                    if (added) {
                        hop[dest] = op.hop;
                        expires[dest] = op.expires;
                    }
                },
                1 => {
                    if (table.removeRelation(d) != (hop[dest] != null)) return false;
                    hop[dest] = null;
                },
                2 => {
                    table.purge(time_mod.Instant.fromSecs(op.expires));
                    for (&hop, expires) |*x, e| {
                        if (x.* != null and op.expires >= e) x.* = null;
                    }
                },
                else => {},
            }
            live = 0;
            for (0..6) |i| {
                var probe: [16]u8 = @splat(0);
                probe[15] = @intCast(i);
                const found = table.findNextHop(probe);
                if ((found == null) != (hop[i] == null)) return false;
                if (found) |f| {
                    if (f[15] != hop[i].?) return false;
                    live += 1;
                }
            }
            if (table.count() != live) return false;
        }
        return true;
    }

    const TimerOp = struct { kind: u8, dt: u8, rand: u32 };

    /// RFC 6206: the interval stays within [Imin, Imax] and doubles when it ends, the
    /// transmission point lies in the second half of the interval, a transmission is
    /// suppressed once k consistent messages were heard, and an inconsistency restarts a
    /// grown interval at Imin.
    pub fn trickleFollowsRfc6206(i_min: u8, doublings: u8, k: u8, ops: [32]TimerOp) bool {
        const min_exp: u32 = i_min % 12;
        const max_exp = min_exp + doublings % 8;
        var now_ms: i64 = 0;
        var t = rpl_state.TrickleTimer.init(min_exp, max_exp - min_exp, k % 4, time_mod.Instant.fromMillis(0), ops[0].rand);
        if (!intervalIsWellFormed(&t, now_ms, min_exp, max_exp)) return false;
        for (ops) |op| {
            const now = time_mod.Instant.fromMillis(now_ms);
            switch (op.kind % 4) {
                0 => now_ms += op.dt,
                1 => {
                    const was_expired = now.greaterThanOrEqual(t.i_expiration);
                    const before = t;
                    const send = t.poll(now, op.rand);
                    const expect = now.greaterThanOrEqual(before.t_expiration) and (before.k == 0 or before.counter < before.k);
                    if (send != expect) return false;
                    if (was_expired and (t.i_exp != @min(before.i_exp + 1, max_exp) or t.counter != 0)) return false;
                    if (!was_expired and (t.i_exp != before.i_exp or t.counter != before.counter)) return false;
                    if (was_expired and !intervalIsWellFormed(&t, now_ms, min_exp, max_exp)) return false;
                },
                2 => {
                    const before = t.counter;
                    t.hearConsistent();
                    if (t.counter != before +| 1) return false;
                },
                else => {
                    const grown = t.i_exp > min_exp;
                    t.hearInconsistency(now, op.rand);
                    if (grown and (t.i_exp != min_exp or t.counter != 0 or !intervalIsWellFormed(&t, now_ms, min_exp, max_exp))) return false;
                },
            }
            if (t.i_exp < min_exp or t.i_exp > max_exp) return false;
            const earliest = if (t.t_expiration.lessThan(t.i_expiration)) t.t_expiration else t.i_expiration;
            if (!t.pollAt().eql(earliest)) return false;
        }
        return true;
    }

    /// The interval that started at `start_ms`, if the timer was just (re)started there.
    fn intervalIsWellFormed(t: *const rpl_state.TrickleTimer, start_ms: i64, min_exp: u32, max_exp: u32) bool {
        const interval: i64 = @as(i64, 1) << @intCast(t.i_exp);
        if (t.i_exp < min_exp or t.i_exp > max_exp) return false;
        const i_end = t.i_expiration.totalMillis();
        const t_at = t.t_expiration.totalMillis();
        if (i_end != start_ms + interval) return false;
        if (interval < 2) return t_at == start_ms;
        return t_at >= start_ms + (interval >> 1) and t_at < i_end;
    }

    /// Intervals are configured by 8-bit exponents on the wire; no value may overflow time.
    pub fn trickleToleratesAnyConfiguredExponent(i_min: u8, doublings: u8, k: u8, rand: u32, steps: [4]u16) bool {
        var now_ms: i64 = 0;
        var t = rpl_state.TrickleTimer.init(i_min, doublings, k, time_mod.Instant.fromMillis(0), rand);
        for (steps) |dt| {
            now_ms += dt;
            _ = t.poll(time_mod.Instant.fromMillis(now_ms), rand);
            t.hearInconsistency(time_mod.Instant.fromMillis(now_ms), rand);
        }
        return t.pollAt().greaterThanOrEqual(time_mod.Instant.ZERO);
    }
};

test "laws: rpl routing state" {
    try zv.checkLaws(routing, .{ .iterations = iterations, .seed = 19 });
}

// -------------------------------------------------------------------------
// Fragmentation (RFC 791, RFC 4944) and reassembly keys.
// -------------------------------------------------------------------------

const frag_mod = @import("fragmentation.zig");

pub const fragments = struct {
    const Frag = frag_mod.Fragmenter(300, true);
    const Reasm = frag_mod.Reassembler(frag_mod.FragKey, .{ .buffer_size = 300, .max_segments = 4 });
    const Frag6 = frag_mod.SixlowpanFragmenter(64);

    pub const pinned = .{
        .fragmenterRefusesAnMtuThatCannotCarryData = .{ .{0}, .{19}, .{20}, .{27} },
    };

    fn pattern(buf: []u8, salt: u16) void {
        for (buf, 0..) |*b, i| b.* = @truncate(i *% 31 +% salt);
    }

    /// RFC 791: the fragments of a payload carry it in order at 8-byte aligned offsets, every one
    /// but the last has More Fragments set, and reassembling them gives back the payload.
    pub fn ipv4FragmentsReassembleToTheOriginal(len: u16, mtu_extra: u8, ident: u16) bool {
        var payload: [300]u8 = undefined;
        pattern(&payload, ident);
        const n: usize = len % 301;
        const mtu: usize = 28 + @as(usize, mtu_extra) % 200;
        const hw = ethernet.Address{ 2, 0, 0, 0, 0, 1 };
        const src = ipv4.Address{ 10, 0, 0, 1 };
        const dst = ipv4.Address{ 10, 0, 0, 2 };
        var f = Frag{};
        if (!f.stage(payload[0..n], src, dst, .udp, 64, ident, .{ 2, 0, 0, 0, 0, 2 })) return false;
        if (n == 0) return f.isEmpty() and f.emitNext(&framebuf, hw, mtu) == null;

        var r = Reasm{};
        if (!r.isFree()) return false;
        const key = frag_mod.FragKey{ .id = ident, .src_addr = src, .dst_addr = dst, .protocol = .udp };
        var next_offset: usize = 0;
        var frames: usize = 0;
        while (f.emitNext(&framebuf, hw, mtu)) |total| {
            frames += 1;
            if (frames > 300) return false;
            const eth = ethernet.parse(framebuf[0..total]) catch return false;
            if (eth.ethertype != .ipv4) return false;
            const ip_bytes = framebuf[ethernet.HEADER_LEN..total];
            const repr = ipv4.parse(ip_bytes) catch return false;
            const body = ip_bytes[ipv4.HEADER_LEN..];
            if (repr.identification != ident or repr.protocol != .udp or repr.total_length != ip_bytes.len) return false;
            if (@as(usize, repr.fragment_offset) * 8 != next_offset or ip_bytes.len > mtu) return false;
            if (repr.more_fragments != !f.finished()) return false;
            if (repr.more_fragments and body.len % 8 != 0) return false;
            if (!std.mem.eql(u8, body, payload[next_offset..][0..body.len])) return false;
            if (frag_mod.isFragment(repr) != (!f.finished() or next_offset != 0)) return false;
            r.accept(key, time_mod.Instant.fromSecs(60));
            if (r.isFree() or !r.add(body, next_offset)) return false;
            next_offset += body.len;
        }
        if (next_offset != n or !f.finished()) return false;
        r.setTotalSize(n);
        const whole = r.assemble() orelse return false;
        return std.mem.eql(u8, whole, payload[0..n]) and r.isFree();
    }

    var framebuf: [1514]u8 = undefined;

    /// A link too small for the IP header plus one 8-byte unit cannot carry fragments at all;
    /// asking for one must fail instead of looping on empty fragments or underflowing.
    pub fn fragmenterRefusesAnMtuThatCannotCarryData(mtu: u8) bool {
        var f = Frag{};
        var payload: [64]u8 = undefined;
        pattern(&payload, 7);
        if (!f.stage(&payload, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .udp, 64, 1, .{ 2, 0, 0, 0, 0, 2 })) return false;
        return f.emitNext(&framebuf, .{ 2, 0, 0, 0, 0, 1 }, mtu % 28) == null and !f.finished();
    }

    /// RFC 4944 5.3: a datagram's fragments are keyed by tag, size and link-layer addresses;
    /// the link addresses are compared in EUI-64 form.
    pub fn sixlowpanKeysIdentifyADatagram(tag: u16, size: u16, a: [8]u8, b: [8]u8, short: [2]u8, flip: u8) bool {
        const src = ieee802154.Address{ .extended = a };
        const dst = ieee802154.Address{ .short = short };
        const key = frag_mod.FragKey6LoWPAN.fromAddrs(src, dst, tag, size);
        const same = frag_mod.FragKey6LoWPAN.fromAddrs(src, dst, tag, size);
        if (!key.eql(same) or !same.eql(key)) return false;
        if (key.datagram_tag != tag or key.datagram_size != size) return false;
        if (!std.mem.eql(u8, &key.ll_src_addr, &src.asEui64()) or !std.mem.eql(u8, &key.ll_dst_addr, &dst.asEui64())) return false;
        const other = switch (flip % 4) {
            0 => frag_mod.FragKey6LoWPAN.fromAddrs(src, dst, tag +% 1, size),
            1 => frag_mod.FragKey6LoWPAN.fromAddrs(src, dst, tag, size +% 1),
            2 => frag_mod.FragKey6LoWPAN.fromAddrs(.{ .extended = b }, dst, tag, size),
            else => frag_mod.FragKey6LoWPAN.fromAddrs(src, .{ .short = .{ short[0] ^ 1, short[1] } }, tag, size),
        };
        const expected = flip % 4 == 2 and std.mem.eql(u8, &a, &b);
        return key.eql(other) == expected and other.eql(key) == expected;
    }

    /// RFC 8200 4.5 and RFC 6946: a fragment header with offset zero and no More Fragments is an
    /// atomic fragment, a complete datagram, not a fragment to reassemble.
    pub fn ipv6FragmentKeysAndAtomicFragments(id: u32, offset: u16, more: bool, a: [16]u8, b: [16]u8) bool {
        const repr = ipv6fragment.Repr{ .next_header = 17, .frag_offset = offset, .more_frags = more, .ident = id };
        if (frag_mod.isFragmentV6(repr) != (more or offset != 0)) return false;
        const k1 = frag_mod.FragKeyV6{ .id = id, .src_addr = a, .dst_addr = b };
        const k2 = frag_mod.FragKeyV6{ .id = id +% 1, .src_addr = a, .dst_addr = b };
        const k3 = frag_mod.FragKeyV6{ .id = id, .src_addr = b, .dst_addr = a };
        return k1.eql(k1) and !k1.eql(k2) and !k2.eql(k1) and k1.eql(k3) == std.mem.eql(u8, &a, &b);
    }

    /// The 6LoWPAN fragmenter splits one compressed datagram across 802.15.4 frames that fit the
    /// radio's frame size; the fragment headers carry the datagram's size and tag, and the
    /// payloads, in order, are the staged bytes. Staging too much is refused without harm.
    pub fn sixlowpanFragmenterCoversTheDatagram(len: u8, tag: u16, diff: u8, mac_seq: u8) bool {
        var payload: [65]u8 = undefined;
        pattern(&payload, tag);
        const n: usize = len % 65;
        var f = Frag6{};
        if (!f.isEmpty() or f.finished()) return false;
        const src = ieee802154.Address{ .extended = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
        const dst = ieee802154.Address{ .short = .{ 0xab, 0xcd } };
        const size: u16 = @intCast(ipv6.HEADER_LEN + n + diff);
        if (!f.stage(payload[0..n], size, tag, diff, src, dst, 0x1234)) return false;
        if (f.stage(&payload, size, tag +% 1, diff, src, dst, 0x1234)) return false;
        if (n == 0) return f.isEmpty();
        var sent: usize = 0;
        var frame: [ieee802154.MAX_FRAME_LEN]u8 = undefined;
        var count: usize = 0;
        while (f.emitNext(&frame, mac_seq +% @as(u8, @intCast(count)))) |total| {
            count += 1;
            if (count > 64 or total > ieee802154.MAX_FRAME_LEN) return false;
            const body = ieee802154.payloadSlice(frame[0..total]) catch return false;
            const header = sixlowpan_frag.parse(body) catch return false;
            const hdr_len: usize = switch (header) {
                .first_fragment => |h| blk: {
                    if (sent != 0 or h.datagram_size != size or h.datagram_tag != tag) return false;
                    break :blk sixlowpan_frag.FIRST_FRAGMENT_HEADER_SIZE;
                },
                .next_fragment => |h| blk: {
                    if (sent == 0 or h.datagram_size != size or h.datagram_tag != tag) return false;
                    if (@as(usize, h.datagram_offset) * 8 != sent + diff) return false;
                    break :blk sixlowpan_frag.NEXT_FRAGMENT_HEADER_SIZE;
                },
            };
            const data = body[hdr_len..];
            if (!std.mem.eql(u8, data, payload[sent..][0..data.len])) return false;
            sent += data.len;
            if (sent < n and data.len % 8 != 0) return false;
        }
        const done = sent == n and f.finished() and f.emitNext(&frame, 0) == null;
        f.reset();
        return done and f.isEmpty() and !f.finished();
    }
};

test "laws: fragmentation" {
    try zv.checkLaws(fragments, .{ .iterations = 20_000, .seed = 20 });
}

// -------------------------------------------------------------------------
// Time arithmetic, address classes and text forms.
// -------------------------------------------------------------------------

pub const arithmetic = struct {
    const Instant = time_mod.Instant;
    const Duration = time_mod.Duration;

    pub const pinned = .{
        .clockUnitsAgree = .{ .{ -2147483648, 2147483647 }, .{ -1500000, 0 }, .{ 0, -1500000 } },
    };

    /// Instants and durations decompose into whole seconds and milliseconds, and moving an instant
    /// by a duration and back returns it.
    pub fn clockUnitsAgree(micros: i32, delta: i32) bool {
        const t = Instant.fromMicros(micros);
        const d = Duration.fromMicros(delta);
        const ms: i64 = @divTrunc(@as(i64, micros), 1000);
        if (t.totalMillis() != ms or Instant.fromMillis(ms).totalMicros() != ms * 1000) return false;
        if (t.secs() != @divTrunc(@as(i64, micros), 1_000_000)) return false;
        if (t.secs() * 1000 + t.millis() != ms) return false;
        if (Instant.fromSecs(t.secs()).totalMicros() != t.secs() * 1_000_000) return false;
        if (d.totalMillis() != @divTrunc(@as(i64, delta), 1000) or d.secs() != @divTrunc(@as(i64, delta), 1_000_000)) return false;
        if (d.secs() * 1000 + d.millis() != d.totalMillis()) return false;
        if (Duration.fromMillis(d.totalMillis()).totalMicros() != d.totalMillis() * 1000) return false;
        if (Duration.fromSecs(d.secs()).totalMicros() != d.secs() * 1_000_000) return false;
        return t.add(d).sub(d).eql(t) and t.sub(d).add(d).eql(t) and t.add(d).diff(t).totalMicros() == @abs(@as(i64, delta));
    }

    /// Duration algebra: addition commutes, subtraction saturates at zero, and min, max and clamp
    /// are the lattice operations on the microsecond count.
    pub fn durationAlgebra(a: i32, b: i32, lo: i32, hi: i32, factor: u16, shift: u3, divisor: u16) bool {
        const x = Duration.fromMicros(a);
        const y = Duration.fromMicros(b);
        if (!x.add(y).eql(y.add(x)) or x.add(y).totalMicros() != @as(i64, a) + b) return false;
        if (x.subSaturating(y).totalMicros() != @max(@as(i64, a) - b, 0)) return false;
        if (x.max(y).totalMicros() != @max(a, b) or x.min(y).totalMicros() != @min(a, b)) return false;
        if (x.mul(factor).totalMicros() != @as(i64, a) * factor) return false;
        if (divisor != 0 and x.divFloor(divisor).totalMicros() != @divTrunc(@as(i64, a), divisor)) return false;
        if (x.shl(shift).totalMicros() != @as(i64, a) << shift) return false;
        const l = Duration.fromMicros(@min(lo, hi));
        const h = Duration.fromMicros(@max(lo, hi));
        const c = x.clamp(l, h);
        return !c.lessThan(l) and !h.lessThan(c) and c.clamp(l, h).eql(c) and (x.lessThan(l) or h.lessThan(x) or c.eql(x));
    }
};

test "laws: time arithmetic" {
    try zv.checkLaws(arithmetic, .{ .iterations = iterations, .seed = 21 });
}

fn u128Of(addr: [16]u8) u128 {
    return std.mem.readInt(u128, &addr, .big);
}

pub const addresses = struct {
    /// Shapes the interesting prefixes out of random bytes, which would otherwise almost never
    /// be loopback, link-local or multicast.
    fn shape4(raw: [4]u8, class: u8) [4]u8 {
        var a = raw;
        switch (class % 8) {
            1 => a[0] = 127,
            2 => a[0..2].* = .{ 169, 254 },
            3 => a[0] = 224 + a[0] % 16,
            4 => a = .{ 255, 255, 255, 255 },
            5 => a = .{ 0, 0, 0, 0 },
            else => {},
        }
        return a;
    }

    fn shape6(raw: [16]u8, class: u8) [16]u8 {
        var a = raw;
        switch (class % 10) {
            1 => {
                a = @splat(0);
                a[15] = 1;
            },
            2 => a = @splat(0),
            3 => a[0] = 0xff,
            4 => {
                a[0] = 0xfe;
                a[1] = 0x80 | (a[1] & 0x3f);
            },
            5 => a[0] = 0xfc | (a[0] & 1),
            6 => a[0] = 0x20 | (a[0] & 0x1f),
            7 => a[0..13].* = .{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff },
            else => {},
        }
        return a;
    }

    /// RFC 1122, 3927 and 5771 define the IPv4 classes by prefix.
    pub fn ipv4ClassesFollowTheirPrefixes(raw: [4]u8, class: u8) bool {
        const a = shape4(raw, class);
        const v = std.mem.readInt(u32, &a, .big);
        return ipv4.isLoopback(a) == (v >> 24 == 127) and
            ipv4.isLinkLocal(a) == (v >> 16 == 0xa9fe) and
            ipv4.isMulticast(a) == (v >> 28 == 0xe) and
            ipv4.isBroadcast(a) == (v == 0xffffffff) and
            ipv4.isUnspecified(a) == (v == 0);
    }

    /// RFC 4291 defines the IPv6 classes by prefix; RFC 4291 2.7.1 the solicited-node group.
    pub fn ipv6ClassesFollowTheirPrefixes(raw: [16]u8, class: u8) bool {
        const a = shape6(raw, class);
        const v = u128Of(a);
        if (ipv6.isLoopback(a) != (v == 1) or ipv6.isUnspecified(a) != (v == 0)) return false;
        if (ipv6.isMulticast(a) != (v >> 120 == 0xff) or ipv6.isBroadcast(a)) return false;
        if (ipv6.isLinkLocal(a) != (v >> 118 == 0x3fa)) return false;
        if (ipv6.isUniqueLocal(a) != (v >> 121 == 0x7e)) return false;
        if (ipv6.isGlobalUnicast(a) != (v >> 125 == 1)) return false;
        const sn = ipv6.solicitedNode(a);
        const mask: u128 = (1 << 24) - 1;
        if (!ipv6.isSolicitedNodeMulticast(sn) or u128Of(sn) & mask != v & mask or u128Of(sn) >> 24 != 0xff02_0000_0000_0000_0000_0001_ff) return false;
        return ipv6.isSolicitedNodeMulticast(a) == (v >> 24 == 0xff02_0000_0000_0000_0000_0001_ff);
    }

    fn parseV4(text: []const u8) ?[4]u8 {
        var out: [4]u8 = undefined;
        var it = std.mem.splitScalar(u8, text, '.');
        for (&out) |*b| {
            const part = it.next() orelse return null;
            if (part.len > 1 and part[0] == '0') return null;
            b.* = std.fmt.parseInt(u8, part, 10) catch return null;
        }
        return if (it.next() == null) out else null;
    }

    fn parseGroups(text: []const u8, out: []u16) ?usize {
        if (text.len == 0) return 0;
        var n: usize = 0;
        var it = std.mem.splitScalar(u8, text, ':');
        while (it.next()) |part| {
            if (part.len == 0 or part.len > 4 or n == out.len) return null;
            out[n] = std.fmt.parseInt(u16, part, 16) catch return null;
            n += 1;
        }
        return n;
    }

    fn parseV6(text: []const u8) ?[16]u8 {
        var halves = std.mem.splitSequence(u8, text, "::");
        const head_text = halves.next().?;
        const tail_text = halves.next();
        if (halves.next() != null) return null;
        var groups: [8]u16 = @splat(0);
        const head = parseGroups(head_text, &groups) orelse return null;
        if (tail_text) |t| {
            var tail: [8]u16 = undefined;
            const n = parseGroups(t, &tail) orelse return null;
            if (head + n > 7) return null;
            @memcpy(groups[8 - n ..], tail[0..n]);
        } else if (head != 8) return null;
        var out: [16]u8 = undefined;
        for (groups, 0..) |g, i| std.mem.writeInt(u16, out[i * 2 ..][0..2], g, .big);
        return out;
    }

    /// The text forms read back as the address: dotted decimal, and RFC 5952 for IPv6 (lower
    /// case, no leading zeros, the longest run of zero groups compressed, a single zero group not).
    pub fn textFormsReadBack(raw4: [4]u8, raw6: [16]u8, class: u8, zero_run: u8) bool {
        const a4 = shape4(raw4, class);
        var buf4: [15]u8 = undefined;
        const t4 = ipv4.formatAddr(a4, &buf4);
        const back4 = parseV4(t4) orelse return false;
        if (!std.mem.eql(u8, &a4, &back4)) return false;

        var a6 = shape6(raw6, class);
        const start = zero_run % 8;
        const len = (zero_run >> 3) % 9;
        for (start..@min(8, start + len)) |g| a6[g * 2 ..][0..2].* = .{ 0, 0 };
        var buf6: [39]u8 = undefined;
        const t6 = ipv6.formatAddr(a6, &buf6);
        const back6 = parseV6(t6) orelse return false;
        if (!std.mem.eql(u8, &a6, &back6)) return false;
        for (t6) |c| if (std.ascii.isUpper(c)) return false;
        var run_len: usize = 0;
        var best_len: usize = 0;
        for (0..9) |g| {
            const zero = g < 8 and a6[g * 2] == 0 and a6[g * 2 + 1] == 0;
            if (zero) {
                run_len += 1;
            } else {
                best_len = @max(best_len, run_len);
                run_len = 0;
            }
        }
        const compressed = std.mem.indexOf(u8, t6, "::") != null;
        return compressed == (best_len >= 2);
    }

    /// A CIDR block contains exactly the addresses sharing its network part, and its network
    /// and broadcast addresses are the first and last of those.
    pub fn cidrBlocksAreNetworkPrefixes(raw: [4]u8, other: [4]u8, prefix: u8) bool {
        const Cidr = ip_mod.Cidr(ipv4);
        const len = prefix % 33;
        const block = Cidr{ .address = raw, .prefix_len = len };
        const mask: u32 = if (len == 0) 0 else ~@as(u32, 0) << @intCast(32 - len);
        const net = std.mem.readInt(u32, &raw, .big) & mask;
        const net_addr = block.networkAddr();
        if (std.mem.readInt(u32, &net_addr, .big) != net or !block.contains(raw) or !block.contains(net_addr)) return false;
        if (block.contains(other) != (std.mem.readInt(u32, &other, .big) & mask == net)) return false;
        if (block.broadcast()) |b| {
            if (!block.contains(b) or std.mem.readInt(u32, &b, .big) != net | ~mask) return false;
        } else if (len < 31) return false;
        return true;
    }
};

test "laws: addresses" {
    try zv.checkLaws(addresses, .{ .iterations = iterations, .seed = 22 });
}

// -------------------------------------------------------------------------
// Congestion windows (RFC 5681), TCP byte streams and datagram sockets.
// -------------------------------------------------------------------------

pub const windows = struct {
    const CC = tcp_socket.CongestionController;
    const Host = tcp_socket.Socket(ipv4, 1);

    const CcOp = struct { kind: u8, len: u16 };

    /// A sender that is not controlled may always send; a Reno sender follows RFC 5681: slow
    /// start adds what was acknowledged until the slow-start threshold, after which it adds one
    /// segment per acknowledgment, a timeout halves the window, three duplicate acknowledgments
    /// lower the threshold without touching the window, and the window stays within
    /// [one segment, the peer's window] once an acknowledgment arrives.
    pub fn renoFollowsRfc5681(window: u16, segment: u16, peer: u16, ops: [24]CcOp) bool {
        const mss = @as(usize, segment) + 1;
        var none: CC = .{ .none = .{} };
        var reno: CC = .{ .reno = .{ .cwnd = @max(window, mss), .min_cwnd = mss, .rwnd = @max(peer, mss) } };
        var empty: [0]u8 = .{};
        const host = Host.init(&empty, &empty);
        const rtte = &host.rtte;
        reno.setMss(mss);
        none.setMss(mss);
        var now_ms: i64 = 0;
        for (ops) |op| {
            now_ms += 10;
            const now = time_mod.Instant.fromMillis(now_ms);
            const r = &reno.reno;
            const before = r.*;
            switch (op.kind % 6) {
                0 => {
                    reno.onAck(now, op.len, rtte);
                    const growth: usize = if (before.cwnd < before.ssthresh) op.len else before.min_cwnd;
                    const want = @min(@max(before.cwnd +| growth, before.min_cwnd), before.rwnd);
                    if (reno.window() != want) return false;
                },
                1 => {
                    reno.onRetransmit(now);
                    if (reno.window() != @max(before.cwnd >> 1, before.min_cwnd)) return false;
                },
                2 => {
                    reno.onDuplicateAck(now);
                    if (reno.window() != before.cwnd or r.ssthresh != @max(before.cwnd >> 1, before.min_cwnd)) return false;
                },
                3 => {
                    reno.preTransmit(now);
                    reno.postTransmit(now, op.len);
                    if (reno.window() != before.cwnd) return false;
                },
                4 => {
                    reno.setRemoteWindow(op.len);
                    if (r.rwnd != @max(before.rwnd, op.len)) return false;
                },
                else => {
                    reno.setMss(op.len);
                    if (r.min_cwnd != op.len) return false;
                },
            }
            none.onAck(now, op.len, rtte);
            none.onRetransmit(now);
            none.onDuplicateAck(now);
            none.preTransmit(now);
            none.postTransmit(now, op.len);
            none.setRemoteWindow(op.len);
            if (none.window() != std.math.maxInt(usize)) return false;
        }
        return true;
    }

    /// Cubic grows like Reno in slow start: it adds what was acknowledged, within [one segment,
    /// the peer's window], and the dispatching wrapper reaches it unchanged.
    pub fn cubicSlowStartAddsAcknowledgedBytes(window: u16, segment: u16, acked: u16, dup: bool) bool {
        const mss = @as(usize, segment) + 1;
        var cc: CC = .{ .cubic = .{ .cwnd = @max(window, mss), .min_cwnd = mss, .w_max = @max(window, mss), .rwnd = 1 << 20 } };
        const before = cc.cubic;
        const now = time_mod.Instant.fromMillis(5);
        var empty: [0]u8 = .{};
        const host = Host.init(&empty, &empty);
        cc.onAck(now, acked, &host.rtte);
        if (cc.window() != @min(@max(before.cwnd + acked, before.min_cwnd), before.rwnd)) return false;
        if (!dup) return true;
        const w = cc.window();
        cc.onDuplicateAck(now);
        return cc.cubic.w_max == w and cc.cubic.ssthresh == w >> 1;
    }

    pub const pinned = .{
        .emptySegmentsCarryNoFlagsExceptPush = .{ .{ 3, 0 }, .{ 4, 0 } },
    };

    /// smoltcp (wire/tcp.rs): a segment is empty when it carries no data and no flag but PSH.
    /// Only SYN and FIN take sequence space, but RST is not empty either.
    pub fn emptySegmentsCarryNoFlagsExceptPush(control: u8, len: u8) bool {
        const repr: tcp_socket.TcpRepr = .{
            .src_port = 1,
            .dst_port = 2,
            .control = switch (control % 5) {
                0 => .none,
                1 => .syn,
                2 => .fin,
                3 => .psh,
                else => .rst,
            },
            .payload = payload_mem[0 .. len % 3],
        };
        const bare = repr.payload.len == 0 and (repr.control == .none or repr.control == .psh);
        if (repr.isEmpty() != bare) return false;
        return !repr.isEmpty() or repr.segmentLen() == 0;
    }
};

test "laws: congestion windows" {
    try zv.checkLaws(windows, .{ .iterations = iterations, .seed = 23 });
}

pub const streams = struct {
    const Sock = tcp_socket.Socket(ipv4, 4);
    const server_addr = ipv4.Address{ 10, 0, 0, 1 };
    const client_addr = ipv4.Address{ 10, 0, 0, 2 };

    var client_rx: [3000]u8 = undefined;
    var client_tx: [3000]u8 = undefined;
    var server_rx: [3000]u8 = undefined;
    var server_tx: [3000]u8 = undefined;

    const Settings = struct {
        nagle: bool,
        ack_delay_ms: u8,
        keep_alive: bool,
        cc: u2,
        timestamps: bool,
        hop: u8,
    };

    fn byteAt(offset: usize) u8 {
        return @truncate(offset *% 131 +% 7);
    }

    const Pull = struct { offset: usize = 0, ok: bool = true };

    fn check(pull: *Pull, data: []const u8) usize {
        for (data) |b| {
            if (b != byteAt(pull.offset)) pull.ok = false;
            pull.offset += 1;
        }
        return data.len;
    }

    const Push = struct { offset: usize = 0, limit: usize };

    fn produce(push: *Push, buf: []u8) usize {
        const n = @min(buf.len, push.limit);
        for (buf[0..n]) |*b| {
            b.* = byteAt(push.offset);
            push.offset += 1;
        }
        return n;
    }

    fn configure(s: *Sock, cfg: Settings) !void {
        s.setNagleEnabled(cfg.nagle);
        s.setAckDelay(if (cfg.ack_delay_ms == 0) null else time_mod.Duration.fromMillis(cfg.ack_delay_ms));
        s.setKeepAlive(if (cfg.keep_alive) time_mod.Duration.fromSecs(5) else null);
        s.setTimeout(time_mod.Duration.fromSecs(30));
        s.setCongestionControl(switch (cfg.cc) {
            0 => .{ .none = .{} },
            1 => .{ .reno = .{} },
            else => .{ .cubic = .{} },
        });
        if (cfg.timestamps) s.setTsvalGenerator(&tsGen);
        try s.setHopLimit(if (cfg.hop == 0) null else cfg.hop);
    }

    fn tsGen() u32 {
        return 1000;
    }

    /// Moves every segment both sockets have ready to the other, until the link is quiet.
    fn pump(a: *Sock, b: *Sock, now: time_mod.Instant) void {
        var quiet = false;
        var rounds: usize = 0;
        while (!quiet and rounds < 64) : (rounds += 1) {
            quiet = true;
            if (a.dispatch(now)) |d| {
                quiet = false;
                if (b.accepts(d.src_addr, d.dst_addr, d.repr)) _ = b.process(now, d.src_addr, d.dst_addr, d.repr);
            }
            if (b.dispatch(now)) |d| {
                quiet = false;
                if (a.accepts(d.src_addr, d.dst_addr, d.repr)) _ = a.process(now, d.src_addr, d.dst_addr, d.repr);
            }
        }
    }

    /// Whatever the options, a TCP connection delivers a byte stream intact and in order with
    /// either side's API (copying, zero-copy, peeking), reports its endpoints and queues
    /// consistently, negotiates timestamps only when both sides want them, and closes cleanly.
    pub fn byteStreamsAreDeliveredInOrder(cfg: Settings, other_ts: bool, chunks: [10]u16, reads: [4]u8) bool {
        var client = Sock.init(&client_rx, &client_tx);
        var server = Sock.init(&server_rx, &server_tx);
        configure(&client, cfg) catch return false;
        var server_cfg = cfg;
        server_cfg.timestamps = other_ts;
        configure(&server, server_cfg) catch return false;
        const cc_tag = std.meta.activeTag(client.congestionControl());
        if (cc_tag != @as(@TypeOf(cc_tag), switch (cfg.cc) {
            0 => .none,
            1 => .reno,
            else => .cubic,
        })) return false;
        if (client.sendCapacity() != client_tx.len or client.recvCapacity() != client_rx.len) return false;

        server.listen(.{ .port = 80 }) catch return false;
        var now = time_mod.Instant.fromMillis(0);
        client.connect(server_addr, 80, client_addr, 49152) catch return false;
        for (0..40) |_| {
            now = now.add(time_mod.Duration.fromMillis(10));
            pump(&client, &server, now);
            if (client.mayRecv() and server.maySend()) break;
        }
        if (!client.maySend() or !server.maySend()) return false;
        if (client.timestampEnabled() != (cfg.timestamps and other_ts) or server.timestampEnabled() != client.timestampEnabled()) return false;
        const remote = client.remoteEndpoint() orelse return false;
        const local = client.localEndpoint() orelse return false;
        const peer = server.remoteEndpoint() orelse return false;
        if (remote.port != 80 or local.port != 49152 or peer.port != 49152 or !std.mem.eql(u8, &peer.addr, &client_addr)) return false;

        var total: usize = 0;
        for (chunks) |c| total += c % 1200;
        var push: Push = .{ .limit = 0 };
        var pull: Pull = .{};
        var sent: usize = 0;
        var round: usize = 0;
        var closed = false;
        while (round < 3000) : (round += 1) {
            now = now.add(time_mod.Duration.fromMillis(7));
            if (sent < total) {
                const want = @min(total - sent, chunks[round % chunks.len] % 1200 + 1);
                if (round % 2 == 0) {
                    var bytes: [1200]u8 = undefined;
                    for (bytes[0..want], 0..) |*b, i| b.* = byteAt(sent + i);
                    sent += client.sendSlice(bytes[0..want]) catch return false;
                } else {
                    push.offset = sent;
                    push.limit = want;
                    sent += client.send(&push, &produce) catch return false;
                }
            } else if (!closed and pull.offset == total) {
                client.close();
                closed = true;
            }
            if (client.sendQueue() > client.sendCapacity() or server.recvQueue() > server.recvCapacity()) return false;
            pump(&client, &server, now);

            const step: usize = @as(usize, reads[round % reads.len]) % 300 + 1;
            switch (round % 3) {
                0 => {
                    var bytes: [300]u8 = undefined;
                    const n = server.recvSlice(bytes[0..step]) catch 0;
                    _ = check(&pull, bytes[0..n]);
                },
                1 => {
                    const view = server.peek(step) catch &.{};
                    const before = pull.offset;
                    if (view.len > 0) {
                        var shadow = pull;
                        _ = check(&shadow, view);
                        if (!shadow.ok) return false;
                        const n = server.recv(&pull, &check) catch return false;
                        if (n == 0 or pull.offset != before + n) return false;
                    }
                },
                else => {
                    _ = server.recv(&pull, &check) catch 0;
                },
            }
            if (!pull.ok) return false;
            pump(&client, &server, now);
            if (closed and pull.offset == total and !server.mayRecv() and server.getState() == .close_wait) {
                server.close();
                pump(&client, &server, now);
                break;
            }
        }
        if (pull.offset != total or !pull.ok) return false;
        var tail: [1]u8 = undefined;
        if (server.recvSlice(&tail)) |_| return false else |_| {}
        for (0..40) |_| {
            now = now.add(time_mod.Duration.fromSecs(5));
            pump(&client, &server, now);
        }
        return !server.isOpen() and !client.isActive();
    }
};

test "laws: tcp byte streams" {
    try zv.checkLaws(streams, .{ .iterations = 400, .seed = 24 });
}

pub const datagrams = struct {
    const Udp = udp_socket.Socket(ipv4);
    const Raw = raw_socket.Socket(ipv4, .{ .payload_size = 16 });
    const Icmp = icmp_socket.Socket(ipv4);

    const DatagramOp = struct { kind: u8, tag: u8, len: u8 };

    /// UDP is a FIFO of datagrams: what is accepted comes out in order with its source,
    /// `peek` shows the next one without taking it, the hop limit rides on what is sent, and
    /// closing discards both queues.
    pub fn udpIsAFifoOfDatagrams(hop: ?u8, ops: [32]DatagramOp) bool {
        var rx_meta: [3]Udp.PacketMeta = @splat(.{});
        var rx_payload: [48]u8 = undefined;
        var tx_meta: [3]Udp.PacketMeta = @splat(.{});
        var tx_payload: [48]u8 = undefined;
        var sock = Udp.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);
        sock.bind(.{ .port = 5000 }) catch return false;
        if (sock.setHopLimit(0)) |_| return false else |_| {}
        const limit: ?u8 = if (hop) |h| (if (h == 0) null else h) else null;
        sock.setHopLimit(limit) catch return false;
        var inbox: [8]struct { tag: u8, len: u8 } = undefined;
        var in_n: usize = 0;
        var outbox: [8]struct { tag: u8, len: u8 } = undefined;
        var out_n: usize = 0;
        const peer = ipv4.Address{ 10, 0, 0, 7 };
        const me = ipv4.Address{ 10, 0, 0, 1 };
        for (ops) |op| {
            const len: u8 = op.len % 12;
            switch (op.kind % 7) {
                0 => {
                    @memset(payload_mem[0..len], op.tag);
                    if (!sock.accepts(peer, me, .{ .src_port = 40000 + @as(u16, op.tag), .dst_port = 5000 })) return false;
                    if (sock.accepts(peer, me, .{ .src_port = 40000, .dst_port = 5001 })) return false;
                    const before = sock.canRecv();
                    sock.process(peer, me, .{ .src_port = 40000 + @as(u16, op.tag), .dst_port = 5000 }, payload_mem[0..len]);
                    if (sock.canRecv() and !before) {
                        if (in_n != 0) return false;
                    }
                    if (sock.canRecv()) {
                        // accepted unless the ring was full: learn it from the queue depth
                        var probe = sock;
                        var depth: usize = 0;
                        var scratch: [48]u8 = undefined;
                        while (probe.recvSlice(&scratch)) |_| depth += 1 else |_| {}
                        if (depth == in_n + 1) {
                            inbox[in_n] = .{ .tag = op.tag, .len = len };
                            in_n += 1;
                        } else if (depth != in_n) return false;
                    }
                },
                1, 2 => {
                    var out: [48]u8 = undefined;
                    if (in_n == 0) {
                        if (sock.canRecv()) return false;
                        if (sock.recvSlice(&out)) |_| return false else |e| if (e != error.Exhausted) return false;
                        if (sock.peek()) |_| return false else |_| {}
                        continue;
                    }
                    const want = inbox[0];
                    const peeked = sock.peek() catch return false;
                    if (peeked.payload.len != want.len or peeked.meta.endpoint.port != 40000 + @as(u16, want.tag)) return false;
                    if (!std.mem.eql(u8, &peeked.meta.endpoint.addr, &peer)) return false;
                    const copied = sock.peekSlice(&out) catch return false;
                    if (copied.data_len != want.len or !sock.canRecv()) return false;
                    if (op.kind % 7 == 2) {
                        if (sock.peekSlice(out[0..0])) |_| {
                            if (want.len != 0) return false;
                        } else |e| if (e != error.Truncated or want.len == 0) return false;
                        continue;
                    }
                    const got = sock.recvSlice(&out) catch return false;
                    if (got.data_len != want.len) return false;
                    for (out[0..want.len]) |b| if (b != want.tag) return false;
                    std.mem.copyForwards(@TypeOf(inbox[0]), inbox[0 .. in_n - 1], inbox[1..in_n]);
                    in_n -= 1;
                },
                3 => {
                    @memset(payload_mem[0..len], op.tag);
                    const dest: Udp.Metadata = .{ .endpoint = .{ .addr = peer, .port = 9000 + @as(u16, op.tag) } };
                    if (sock.sendSlice(payload_mem[0..len], dest)) |_| {
                        if (out_n == outbox.len) return false;
                        outbox[out_n] = .{ .tag = op.tag, .len = len };
                        out_n += 1;
                    } else |e| if (e != error.BufferFull or sock.canSend() and out_n == 0) return false;
                },
                4 => {
                    if (sock.dispatch()) |d| {
                        if (out_n == 0) return false;
                        const want = outbox[0];
                        if (d.payload.len != want.len or d.repr.dst_port != 9000 + @as(u16, want.tag) or d.repr.src_port != 5000) return false;
                        if (d.hop_limit != limit) return false;
                        std.mem.copyForwards(@TypeOf(outbox[0]), outbox[0 .. out_n - 1], outbox[1..out_n]);
                        out_n -= 1;
                    } else if (out_n != 0) return false;
                },
                5 => {
                    sock.close();
                    if (sock.isOpen() or sock.canRecv() or sock.dispatch() != null) return false;
                    in_n = 0;
                    out_n = 0;
                    sock.bind(.{ .port = 5000 }) catch return false;
                    if (!sock.canSend()) return false;
                },
                else => {
                    if ((sock.pollAt() != null) != (out_n != 0)) return false;
                },
            }
        }
        return true;
    }

    /// A raw socket queues whole packets of one IP protocol: it refuses to send before it is
    /// bound, fills after its storage does, hands packets out in order, and closing empties it.
    pub fn rawSocketsAreBoundedPacketQueues(hop: ?u8, ops: [32]DatagramOp) bool {
        var rx: [3]Raw.Packet = undefined;
        var tx: [3]Raw.Packet = undefined;
        var sock = Raw.init(&rx, &tx);
        const peer = ipv4.Address{ 10, 0, 0, 7 };
        if (sock.isOpen() or sock.canSend()) return false;
        if (sock.sendSlice("x", peer)) |_| return false else |e| if (e != error.Unbound) return false;
        if (sock.setHopLimit(0)) |_| return false else |_| {}
        const limit: ?u8 = if (hop) |h| (if (h == 0) null else h) else null;
        sock.setHopLimit(limit) catch return false;
        sock.bind(.udp) catch return false;
        if (!sock.isOpen() or !sock.canSend() or !sock.accepts(.udp) or sock.accepts(.tcp)) return false;
        var inbox: [3]u8 = undefined;
        var in_n: usize = 0;
        var outbox: [3]u8 = undefined;
        var out_n: usize = 0;
        for (ops) |op| {
            const len: u8 = op.len % 17;
            switch (op.kind % 6) {
                0 => {
                    @memset(payload_mem[0..len], op.tag);
                    sock.process(peer, .udp, payload_mem[0..len]);
                    if (in_n < inbox.len) {
                        inbox[in_n] = op.tag;
                        in_n += 1;
                    }
                },
                1 => {
                    var out: [16]u8 = undefined;
                    if (in_n == 0) {
                        if (sock.canRecv()) return false;
                        if (sock.peek()) |_| return false else |e| if (e != error.Exhausted) return false;
                        continue;
                    }
                    const peeked = sock.peek() catch return false;
                    if (!std.mem.eql(u8, &peeked.src_addr, &peer) or (peeked.payload.len > 0 and peeked.payload[0] != inbox[0])) return false;
                    const got = sock.recvSlice(&out) catch return false;
                    if (got.data_len != peeked.payload.len) return false;
                    std.mem.copyForwards(u8, inbox[0 .. in_n - 1], inbox[1..in_n]);
                    in_n -= 1;
                },
                2 => {
                    @memset(payload_mem[0..len], op.tag);
                    if (sock.sendSlice(payload_mem[0..len], peer)) |_| {
                        if (out_n == outbox.len) return false;
                        outbox[out_n] = op.tag;
                        out_n += 1;
                    } else |e| {
                        if (e != error.BufferFull or out_n != outbox.len) return false;
                    }
                    if (sock.canSend() != (out_n < outbox.len)) return false;
                },
                3 => {
                    if (sock.peekDstAddr() != null and out_n == 0) return false;
                    if (sock.dispatch()) |d| {
                        if (out_n == 0 or d.ip_protocol != .udp or d.hop_limit != limit or !std.mem.eql(u8, &d.dst_addr, &peer)) return false;
                        if (d.payload.len > 0 and d.payload[0] != outbox[0]) return false;
                        std.mem.copyForwards(u8, outbox[0 .. out_n - 1], outbox[1..out_n]);
                        out_n -= 1;
                    } else if (out_n != 0) return false;
                },
                4 => {
                    sock.close();
                    if (sock.isOpen() or sock.canSend() or sock.canRecv() or sock.dispatch() != null or sock.accepts(.udp)) return false;
                    in_n = 0;
                    out_n = 0;
                    sock.bind(.udp) catch return false;
                },
                else => if ((sock.pollAt() != null) != (out_n != 0)) return false,
            }
            if (sock.canRecv() != (in_n != 0)) return false;
        }
        return true;
    }

    /// The hop limit configured on an ICMP socket is the one its packets leave with, and zero
    /// is refused.
    pub fn icmpSocketsStampTheirHopLimit(hop: u8, len: u8) bool {
        var rx_meta: [1]Icmp.PacketMeta = .{.{}};
        var rx_payload: [16]u8 = undefined;
        var tx_meta: [2]Icmp.PacketMeta = .{ .{}, .{} };
        var tx_payload: [64]u8 = undefined;
        var sock = Icmp.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);
        if (sock.setHopLimit(0)) |_| return false else |_| {}
        sock.setHopLimit(if (hop == 0) null else hop) catch return false;
        sock.sendSlice(payload_mem[0 .. len % 20], .{ 10, 0, 0, 9 }) catch return false;
        const d = sock.dispatch() orelse return false;
        return d.hop_limit == (if (hop == 0) null else hop);
    }
};

test "laws: datagram sockets" {
    try zv.checkLaws(datagrams, .{ .iterations = iterations, .seed = 25 });
}

// -------------------------------------------------------------------------
// Wire formats built from fields: RFC layouts and iterators.
// -------------------------------------------------------------------------

pub const layouts = struct {
    pub const pinned = .{
        .ipsecHeadersFollowTheirRfcs = .{ .{ 0, 0, 51, 254, 0 }, .{ 7, 9, 50, 0, 1 } },
    };

    /// RFC 4303 2 and RFC 4302 2: ESP starts with the SPI and a sequence number; AH adds the
    /// next header, a length in 32-bit words minus two, a reserved zero and an ICV filling the rest.
    pub fn ipsecHeadersFollowTheirRfcs(spi: u32, seq_no: u32, next: u8, icv_words: u8, fill: u8) bool {
        var buf: [1100]u8 = @splat(0xAA);
        const esp_repr: ipsec_esp.Repr = .{ .spi = spi, .sequence_number = seq_no };
        ipsec_esp.emit(esp_repr, &buf) catch return false;
        if (ipsec_esp.bufferLen(esp_repr) != 8 or std.mem.readInt(u32, buf[0..4], .big) != spi or std.mem.readInt(u32, buf[4..8], .big) != seq_no) return false;
        const esp_back = ipsec_esp.parse(buf[0..8]) catch return false;
        if (esp_back.spi != spi or esp_back.sequence_number != seq_no) return false;

        const icv_len = @as(usize, icv_words % 255) * 4;
        var icv: [1024]u8 = undefined;
        @memset(icv[0..icv_len], fill);
        const ah_repr: ipsec_ah.Repr = .{ .next_header = @fromBackingInt(next), .spi = spi, .sequence_number = seq_no, .icv_len = icv_len };
        const total = ipsec_ah.bufferLen(ah_repr);
        if (total != 12 + icv_len or total % 4 != 0) return false;
        ipsec_ah.emit(ah_repr, icv[0..icv_len], &buf) catch return false;
        if (buf[0] != next or buf[1] != total / 4 - 2 or buf[2] != 0 or buf[3] != 0) return false;
        if (std.mem.readInt(u32, buf[4..8], .big) != spi or std.mem.readInt(u32, buf[8..12], .big) != seq_no) return false;
        if (ipsec_ah.headerLen(buf[0..total]) != total) return false;
        const back = ipsec_ah.parse(buf[0..total]) catch return false;
        if (back.spi != spi or back.sequence_number != seq_no or back.icv_len != icv_len or @backingInt(back.next_header) != next) return false;
        const odd: ipsec_ah.Repr = .{ .next_header = @fromBackingInt(next), .spi = spi, .sequence_number = seq_no, .icv_len = icv_len + 1 + fill % 3 };
        const huge: ipsec_ah.Repr = .{ .next_header = @fromBackingInt(next), .spi = spi, .sequence_number = seq_no, .icv_len = ipsec_ah.MAX_ICV_LEN + 4 };
        var big: [1100]u8 = undefined;
        return ipsec_ah.emit(odd, icv[0..odd.icv_len], &big) == error.BadIcvLen and ipsec_ah.emit(huge, big[0..huge.icv_len], &big) == error.BadIcvLen;
    }

    /// Walking IPv6 options yields exactly what parsing at each offset yields, consumes the
    /// whole buffer unless an option is malformed, and stays finished once it is.
    pub fn ipv6OptionIteratorWalksTheBuffer(in: zv.Bytes(40)) bool {
        const data = in.slice();
        var it = ipv6option.iterator(data);
        var at: usize = 0;
        var count: usize = 0;
        while (it.next()) |opt| {
            const want = ipv6option.parse(data[at..]) catch return false;
            if (!std.meta.eql(opt, want)) return false;
            at += opt.bufferLen();
            count += 1;
            if (at > data.len or count > data.len) return false;
        }
        if (it.next() != null) return false;
        return it.hit_error == (at < data.len) and (it.hit_error or at == data.len);
    }

    /// RFC 3810 5.1: an MLDv2 report rides in a hop-by-hop header carrying a Router Alert
    /// option (RFC 2711) with value 0, which survives emit and parse.
    pub fn mldv2ReportsCarryARouterAlert() bool {
        const repr = ipv6hbh.mldv2RouterAlert();
        var buf: [8]u8 = undefined;
        const n = ipv6hbh.emit(repr, &buf) catch return false;
        if (n != 4 or !std.mem.eql(u8, buf[0..4], &.{ 0x05, 0x02, 0x00, 0x00 })) return false;
        const back = ipv6hbh.parse(buf[0..n]) catch return false;
        return back.count == 1 and std.meta.eql(back.options[0], repr.options[0]);
    }

    /// RFC 3810 5.2: a multicast address record is its type, auxiliary data length, number of
    /// sources and the group address, in that order and network byte order.
    pub fn mldAddressRecordsFollowTheirLayout(kind: u8, aux: u8, sources: u16, group: [16]u8) bool {
        const record: mld.AddressRecordRepr = .{ .record_type = @fromBackingInt(kind), .aux_data_len = aux, .num_srcs = sources, .mcast_addr = group };
        var buf: [24]u8 = undefined;
        if (mld.emitAddressRecord(record, buf[0..19])) |_| return false else |_| {}
        const n = mld.emitAddressRecord(record, &buf) catch return false;
        return n == 20 and buf[0] == kind and buf[1] == aux and std.mem.readInt(u16, buf[2..4], .big) == sources and
            std.mem.eql(u8, buf[4..20], &group) and mld.addressRecordLen(record) == 20 + @as(usize, sources) * 16 + @as(usize, aux) * 4;
    }

    /// RFC 4944 6 and RFC 4291 A: a link-local address is fe80::/64 followed by the interface
    /// identifier, which for a 64-bit link address is the address with its universal/local bit
    /// inverted and for a 16-bit one is 0000:00ff:fe00:xxxx. Only 0xffff is the broadcast address.
    pub fn ieee802154LinkAddressesMapToIpv6(ext: [8]u8, short: [2]u8, which: u8) bool {
        const a: ieee802154.Address = switch (which % 3) {
            0 => .absent,
            1 => .{ .short = short },
            else => .{ .extended = ext },
        };
        const ll = a.asLinkLocalAddress();
        if (!std.mem.eql(u8, ll[0..8], &.{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0 }) or !std.mem.eql(u8, ll[8..], &a.asEui64())) return false;
        switch (a) {
            .extended => |e| if (ll[8] != e[0] ^ 0x02 or !std.mem.eql(u8, ll[9..], e[1..])) return false,
            .short => |s| if (!std.mem.eql(u8, ll[8..], &.{ 0, 0, 0, 0xff, 0xfe, 0, s[0], s[1] })) return false,
            .absent => {},
        }
        const short_broadcast = ieee802154.Address{ .short = .{ 0xff, 0xff } };
        const absent: ieee802154.Address = .absent;
        return a.isBroadcast() == (which % 3 == 1 and short[0] == 0xff and short[1] == 0xff) and short_broadcast.isBroadcast() and
            !(ieee802154.Address{ .extended = @splat(0xff) }).isBroadcast() and !absent.isBroadcast();
    }

    /// The payload after a 6LoWPAN fragment header is the rest of the frame.
    pub fn sixlowpanFragmentPayloadFollowsTheHeader(in: zv.Bytes(32)) bool {
        const data = in.slice();
        const header = sixlowpan_frag.parse(data) catch return true;
        const p = sixlowpan_frag.payloadSlice(data) catch return false;
        return within(data, p) and p.len + sixlowpan_frag.bufferLen(header) == data.len;
    }

    /// RFC 1035 4.1.1: the header is six big-endian 16-bit fields, flags carrying the opcode
    /// in bits 11-14 and the response code in bits 0-3.
    pub fn dnsHeaderFieldsAreBigEndianWords(in: zv.Bytes(16)) bool {
        var buf: [16]u8 = @splat(0);
        const n = in.slice().len;
        @memcpy(buf[0..n], in.slice());
        if (n < dns.HEADER_LEN) {
            if (dns.transactionId(buf[0..n])) |_| return false else |_| {}
            if (dns.additionalCount(buf[0..n])) |_| return false else |_| {}
            return true;
        }
        const data = buf[0..n];
        const word = struct {
            fn at(d: []const u8, i: usize) u16 {
                return std.mem.readInt(u16, d[i * 2 ..][0..2], .big);
            }
        }.at;
        const flags = word(data, 1);
        return (dns.transactionId(data) catch return false) == word(data, 0) and
            (dns.flags(data) catch return false) == flags & dns.Flags.MASK and
            @backingInt(dns.opcode(data) catch return false) == (flags >> 11) & 0xf and
            @backingInt(dns.rcode(data) catch return false) == flags & 0xf and
            (dns.questionCount(data) catch return false) == word(data, 2) and
            (dns.answerCount(data) catch return false) == word(data, 3) and
            (dns.authorityCount(data) catch return false) == word(data, 4) and
            (dns.additionalCount(data) catch return false) == word(data, 5) and
            std.mem.eql(u8, dns.payload(data) catch return false, data[dns.HEADER_LEN..]);
    }

    /// Writing parsed labels back gives the wire name, with room for the terminating zero.
    pub fn dnsNamesSurviveBeingCopiedBack(lens: [4]u8, fill: [4]u8, count: u8, room: u8) bool {
        var wire_name: [40]u8 = undefined;
        const labels = count % 4 + 1;
        var at: usize = 0;
        for (0..labels) |i| {
            const len = lens[i] % 8 + 1;
            wire_name[at] = len;
            @memset(wire_name[at + 1 ..][0..len], fill[i]);
            at += 1 + len;
        }
        wire_name[at] = 0;
        const parsed = dns.parseName(wire_name[0 .. at + 1], 0) catch return false;
        var out: [40]u8 = undefined;
        const n = dns.copyName(out[0 .. @as(usize, room) % 41], parsed) catch return room % 41 < at + 1;
        return n == at + 1 and std.mem.eql(u8, out[0..n], wire_name[0..n]) and dns.eqNames(parsed, parsed);
    }

    /// RFC 6550 6.7.6, 6.7.7, 6.7.8 and RFC 6553: each option reads back what was written.
    pub fn rplOptionsReadBackWhatWasEmitted(cfg: rpl.DodagConfigurationOption, prefix_len: u8, prefix: [16]u8, transit: rpl.TransitInformationOption, flags: [3]bool, instance: u8, rank: u16) bool {
        var buf: [32]u8 = undefined;
        var n = cfg.emit(buf[0 .. rpl.DodagConfigurationOption.WIRE_LEN - 1]) catch 0;
        if (n != 0) return false;
        n = cfg.emit(&buf) catch return false;
        const cfg_back = rpl.DodagConfigurationOption.parseOption(buf[0..n]) catch return false;
        if (n != 14 or !std.meta.eql(cfg_back, cfg) or buf[10] != 0) return false;

        const target: rpl.RplTargetOption = .{ .prefix_length = prefix_len, .prefix = prefix };
        n = target.emit(&buf) catch return false;
        const target_back = rpl.RplTargetOption.parseOption(buf[0..n]) catch return false;
        if (n != 18 or !std.meta.eql(target_back, target)) return false;

        n = transit.emit(&buf) catch return false;
        const transit_back = rpl.TransitInformationOption.parseOption(buf[0..n]) catch return false;
        if (n != transit.wireLen() or n != (if (transit.parent_address != null) @as(usize, 20) else 4) or !std.meta.eql(transit_back, transit)) return false;
        if (transit.emit(buf[0 .. n - 1])) |_| return false else |_| {}

        const hop: rpl.HopByHopRepr = .{ .down = flags[0], .rank_error = flags[1], .forwarding_error = flags[2], .instance_id = rpl.InstanceId.fromByte(instance), .sender_rank = rank };
        n = hop.emit(&buf) catch return false;
        const hop_back = rpl.HopByHopRepr.parseOption(buf[0..n]) catch return false;
        return n == 4 and hop_back.instance_id.toByte() == instance and hop_back.down == flags[0] and hop_back.rank_error == flags[1] and
            hop_back.forwarding_error == flags[2] and hop_back.sender_rank == rank and buf[1] == instance;
    }

    /// RPL control message options are type-length-value triples with a one-byte Pad1; walking
    /// them never leaves the buffer, and stops at a truncated option.
    pub fn rplOptionIteratorStaysInTheBuffer(in: zv.Bytes(48)) bool {
        const data = in.slice();
        var it = rpl.OptionIterator.init(data);
        var steps: usize = 0;
        var last_offset: usize = 0;
        while (it.next()) |opt| {
            steps += 1;
            if (steps > data.len or it.offset <= last_offset or it.offset > data.len) return false;
            if (opt.option_type == .pad1 and (opt.value.len != 0 or it.offset != last_offset + 1)) return false;
            if (opt.option_type != .pad1 and it.offset != last_offset + 2 + opt.value.len) return false;
            if (opt.value.len > 0 and !within(data, opt.value)) return false;
            last_offset = it.offset;
        }
        return it.next() == null;
    }

    /// RFC 6282 4.2: a compressed extension header starts with 1110 EID NH and is followed by its
    /// next header (when not compressed), a length and the data. The emitted length is what the
    /// length helper predicted.
    pub fn sixlowpanExtensionHeadersCompressConsistently(eid: u8, payload_len: u8, next: u8, compressed: bool) bool {
        const repr: sixlowpan.ExtHeaderNhcRepr = .{
            .id = @fromBackingInt(@as(u3, @truncate(eid))),
            .next_header = if (compressed) .compressed else .{ .uncompressed = @fromBackingInt(next) },
            .length = payload_len,
        };
        var buf: [8]u8 = undefined;
        const predicted = sixlowpan.extHeaderNhcBufLen(repr);
        if (sixlowpan.emitExtHeaderNhc(repr, buf[0 .. predicted - 1])) |_| return false else |_| {}
        const n = sixlowpan.emitExtHeaderNhc(repr, &buf) catch return false;
        if (n != predicted or buf[0] >> 4 != 0xe or (buf[0] >> 1) & 7 != eid % 8 or (buf[0] & 1 == 1) != compressed) return false;
        const back = sixlowpan.parseExtHeaderNhc(buf[0..n]) catch return false;
        return back.consumed == n and std.meta.eql(back.repr, repr);
    }
};

test "laws: wire layouts" {
    try zv.checkLaws(layouts, .{ .iterations = iterations, .seed = 26 });
}

// -------------------------------------------------------------------------
// Interface: addresses, routes, multicast membership, SLAAC and the answers
// a host gives to frames addressed to it.
// -------------------------------------------------------------------------

pub const addressing = struct {
    const State = iface_mod.IpState(ipv4);
    const Cidr = iface_mod.IpCidr;
    const Routes = iface_mod.RoutesFor(ipv4);

    const AddrOp = struct { kind: u8, host: u8, prefix: u8 };

    fn cidrOf(op: AddrOp) Cidr {
        return .{ .address = .{ 10, op.host % 4, 0, op.host / 4 % 4 + 1 }, .prefix_len = 16 + op.prefix % 3 * 8 };
    }

    /// An interface keeps a bounded list of addresses: adding past the limit is ignored, removing
    /// takes the most recently added match, replacing swaps the whole list, and the source
    /// address for a destination is the one on its network, else the first.
    pub fn addressListsAreBounded(ops: [32]AddrOp, probe: [4]u8) bool {
        var state: State = .{};
        var model: [iface_mod.MAX_ADDR_COUNT]Cidr = undefined;
        var n: usize = 0;
        for (ops) |op| {
            const cidr = cidrOf(op);
            switch (op.kind % 4) {
                0, 1 => {
                    state.addIpAddr(cidr);
                    if (n < model.len) {
                        model[n] = cidr;
                        n += 1;
                    }
                },
                2 => {
                    var at: ?usize = null;
                    for (model[0..n], 0..) |m, i| {
                        if (std.mem.eql(u8, &m.address, &cidr.address)) at = i;
                    }
                    const removed = state.removeIpAddr(cidr.address);
                    if (removed != (at != null)) return false;
                    if (at) |i| {
                        std.mem.copyForwards(Cidr, model[i .. n - 1], model[i + 1 .. n]);
                        n -= 1;
                    }
                },
                else => {
                    const batch = [_]Cidr{ cidr, cidrOf(.{ .kind = 0, .host = op.host +% 1, .prefix = op.prefix }), cidrOf(.{ .kind = 0, .host = op.host +% 2, .prefix = 0 }), cidrOf(.{ .kind = 0, .host = op.host +% 3, .prefix = 0 }), cidrOf(.{ .kind = 0, .host = op.host +% 5, .prefix = 0 }) };
                    const count = op.prefix % batch.len + 1;
                    state.setAddrs(batch[0..count]);
                    n = @min(count, model.len);
                    @memcpy(model[0..n], batch[0..n]);
                },
            }
            const got = state.ipAddrs();
            if (got.len != n) return false;
            for (got, model[0..n]) |g, m| if (!std.meta.eql(g, m)) return false;
            var want_source: ?ipv4.Address = if (n == 0) null else model[0].address;
            var on_net = false;
            for (model[0..n]) |m| {
                if (m.contains(probe)) {
                    want_source = m.address;
                    on_net = true;
                    break;
                }
            }
            const source = state.getSourceAddress(probe);
            if ((source == null) != (want_source == null)) return false;
            if (source) |s| if (!std.mem.eql(u8, &s, &want_source.?)) return false;
            if (state.inSameNetwork(probe) != on_net) return false;
            if (state.hasIpAddr(probe) != for (model[0..n]) |m| {
                if (std.mem.eql(u8, &m.address, &probe)) break true;
            } else false) return false;
        }
        return true;
    }

    const RouteOp = struct { gateway: u8, prefix: u8, host: u8, expires: u8 };

    /// RFC 1812 5.2.4.3: forwarding takes the most specific route that matches the destination
    /// and has not expired, the first one added on a tie, and a full table refuses further routes.
    pub fn routingPrefersTheMostSpecificLiveRoute(ops: [6]RouteOp, dst: [4]u8, now_secs: u8) bool {
        var table: Routes = .{};
        var accepted: [iface_mod.MAX_ROUTE_COUNT]RouteOp = undefined;
        var n: usize = 0;
        for (ops) |op| {
            const route: iface_mod.RouteFor(ipv4) = .{
                .cidr = .{ .address = .{ 10, op.host % 3, 0, 0 }, .prefix_len = op.prefix % 3 * 8 + 8 },
                .via_router = .{ 192, 168, 0, op.gateway },
                .expires_at = if (op.expires < 64) null else time_mod.Instant.fromSecs(op.expires),
            };
            const added = table.add(route);
            if (added != (n < accepted.len)) return false;
            if (added) {
                accepted[n] = op;
                n += 1;
            }
        }
        const now = time_mod.Instant.fromSecs(now_secs);
        var best: ?u8 = null;
        var best_gateway: u8 = 0;
        for (accepted[0..n]) |op| {
            const len = op.prefix % 3 * 8 + 8;
            const net: ipv4.Address = .{ 10, op.host % 3, 0, 0 };
            const live = op.expires < 64 or now_secs <= op.expires;
            const matches = std.mem.eql(u8, net[0 .. len / 8], dst[0 .. len / 8]);
            if (live and matches and (best == null or len > best.?)) {
                best = len;
                best_gateway = op.gateway;
            }
        }
        const got = table.lookup(dst, now);
        if ((got == null) != (best == null)) return false;
        if (got) |g| if (!std.mem.eql(u8, &g, &.{ 192, 168, 0, best_gateway })) return false;
        const gw = iface_mod.RouteFor(ipv4).newDefaultGateway(.{ 1, 2, 3, 4 });
        return gw.cidr.prefix_len == 0 and gw.cidr.contains(dst) and gw.expires_at == null and std.mem.eql(u8, &gw.via_router, &.{ 1, 2, 3, 4 });
    }
};

test "laws: addressing and routes" {
    try zv.checkLaws(addressing, .{ .iterations = iterations, .seed = 27 });
}

pub const membership = struct {
    const Group = ipv6.Address;

    fn group4(id: u8) ipv4.Address {
        return .{ 224, 0, 1, id % 7 };
    }

    fn group6(id: u8) Group {
        var g: Group = @splat(0);
        g[0] = 0xff;
        g[1] = 0x0e;
        g[15] = id % 10 + 1;
        return g;
    }

    const MemberOp = struct { kind: u8, group: u8 };

    /// IPv4 group membership is a bounded set: joining twice is joining once, a full table
    /// refuses a new group, and only a member can be left.
    pub fn ipv4GroupsAreABoundedSet(ops: [32]MemberOp) bool {
        var iface = iface_mod.Interface.init(.{ 2, 0, 0, 0, 0, 1 });
        var members: [7]bool = @splat(false);
        for (ops) |op| {
            const id = op.group % 7;
            var count: usize = 0;
            for (members) |m| count += @intFromBool(m);
            switch (op.kind % 3) {
                0 => {
                    const ok = iface.joinMulticastGroup(group4(id));
                    if (ok != (members[id] or count < iface_mod.MAX_MULTICAST_GROUPS)) return false;
                    members[id] = members[id] or ok;
                },
                1 => {
                    if (iface.leaveMulticastGroup(group4(id)) != members[id]) return false;
                    members[id] = false;
                },
                else => {},
            }
            for (members, 0..) |m, i| if (iface.hasMulticastGroup(group4(@intCast(i))) != m) return false;
        }
        return true;
    }

    const Phase = enum { joining, joined, leaving };
    const MldOp = struct { kind: u8, group: u8, hop: u8 };

    /// RFC 3810 and RFC 4861 on the host side: a group being joined is reported once and then
    /// stays joined; leaving is announced before the group disappears; a general query makes
    /// every joined group report again, a group-specific query only that group, and only a query
    /// with hop limit 1 (so, from the local link) counts.
    pub fn multicastListenersReportAsQueried(ops: [40]MldOp) bool {
        var iface = iface_mod.Interface.init(.{ 2, 0, 0, 0, 0, 1 });
        var phase: [10]?Phase = @splat(null);
        for (ops) |op| {
            const id = op.group % 10;
            const g = group6(id);
            var present: usize = 0;
            for (phase) |p| present += @intFromBool(p != null);
            switch (op.kind % 8) {
                0 => {
                    const ok = iface.joinMulticastGroupV6(g);
                    const should = phase[id] != null or present < iface_mod.MAX_MULTICAST_GROUPS_V6;
                    if (ok != should) return false;
                    if (phase[id]) |p| {
                        if (p == .leaving) phase[id] = .joined;
                    } else if (ok) phase[id] = .joining;
                },
                1 => {
                    const ok = iface.leaveMulticastGroupV6(g);
                    const should = phase[id] != null and phase[id].? != .leaving;
                    if (ok != should) return false;
                    if (ok) phase[id] = .leaving;
                },
                2 => {
                    iface.markMldReported(g);
                    if (phase[id]) |p| switch (p) {
                        .joining => phase[id] = .joined,
                        .leaving => phase[id] = null,
                        .joined => {},
                    };
                },
                3 => {
                    iface.markAllGroupsForReport();
                    for (&phase) |*p| if (p.* != null and p.*.? == .joined) {
                        p.* = .joining;
                    };
                },
                4 => {
                    iface.markGroupForReport(g);
                    if (phase[id] != null and phase[id].? == .joined) phase[id] = .joining;
                },
                else => {
                    const general = op.kind % 8 == 5;
                    const ip: ipv6.Repr = .{ .src_addr = iface_mod.Interface.linkLocalFromMac(.{ 2, 0, 0, 0, 0, 9 }), .dst_addr = ipv6.LINK_LOCAL_ALL_NODES, .next_header = .icmpv6, .payload_len = 24, .hop_limit = if (op.hop % 3 == 0) 1 else op.hop };
                    iface.processMldQuery(ip, .{ .query = .{ .max_resp_code = 1000, .mcast_addr = if (general) ipv6.UNSPECIFIED else g, .s_flag = false, .qrv = 2, .qqic = 125, .num_srcs = 0 } });
                    if (ip.hop_limit == 1) {
                        if (general) {
                            for (&phase) |*p| if (p.* != null and p.*.? == .joined) {
                                p.* = .joining;
                            };
                        } else if (phase[id] != null and phase[id].? != .leaving) {
                            if (phase[id].? == .joined) phase[id] = .joining;
                        }
                    }
                    iface.processMldQuery(ip, .{ .report = .{ .nr_mcast_addr_rcrds = 0 } });
                },
            }
            var pending = false;
            for (phase, 0..) |p, i| {
                const listening = p != null and p.? != .leaving;
                if (iface.hasMulticastGroupV6(group6(@intCast(i))) != listening) return false;
                pending = pending or (p != null and p.? != .joined);
            }
            if (iface.hasPendingMldV6() != pending) return false;
        }
        return true;
    }
};

test "laws: multicast membership" {
    try zv.checkLaws(membership, .{ .iterations = iterations, .seed = 28 });
}

pub const autoconfiguration = struct {
    const mac_of = struct {
        fn f(m: [6]u8) ethernet.Address {
            return m;
        }
    }.f;

    /// RFC 4291 Appendix A: the interface identifier is the MAC with FF FE in the middle and the
    /// universal/local bit inverted; the link-local address is fe80::/64 followed by it.
    pub fn interfaceIdentifiersFollowRfc4291(mac: [6]u8) bool {
        const iid = iface_mod.Interface.eui64InterfaceId(mac);
        const ll = iface_mod.Interface.linkLocalFromMac(mac);
        return iid[0] == mac[0] ^ 0x02 and iid[1] == mac[1] and iid[2] == mac[2] and iid[3] == 0xff and iid[4] == 0xfe and
            std.mem.eql(u8, iid[5..], mac[3..]) and
            std.mem.eql(u8, ll[0..8], &.{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0 }) and std.mem.eql(u8, ll[8..], &iid) and ipv6.isLinkLocal(ll);
    }

    const RaOp = struct { lifetime: u16, valid: u32, preferred: u32, prefix: u8, len_sel: u8, addrconf: bool, advance: u16 };

    /// RFC 4862 5.5: a host configures a link-local address, then for each advertised /64 prefix
    /// flagged for autoconfiguration an address made of the prefix and its interface identifier,
    /// for as long as the prefix is valid; a router lifetime of zero withdraws the default router.
    pub fn routerAdvertisementsConfigureAddresses(mac: [6]u8, ops: [10]RaOp) bool {
        var iface = iface_mod.Interface.init(mac);
        iface.enableSlaac();
        const ll = iface_mod.Interface.linkLocalFromMac(mac);
        if (!std.mem.eql(u8, &(iface.linkLocalIpv6Addr() orelse return false), &ll)) return false;
        if (!std.mem.eql(u8, &(iface.ipv6Addr() orelse return false), &ll) or !iface.hasMulticastGroupV6(ipv6.LINK_LOCAL_ALL_NODES) or !iface.hasSolicitedNode(ipv6.solicitedNode(ll))) return false;
        const router = iface_mod.Interface.linkLocalFromMac(.{ 2, 0, 0, 0, 0, 0xee });
        const iid = iface_mod.Interface.eui64InterfaceId(mac);
        var now_secs: i64 = 0;
        var valid_until: [3]?i64 = @splat(null);
        for (ops) |op| {
            now_secs += op.advance % 600;
            const now = time_mod.Instant.fromSecs(now_secs);
            iface.now = now;
            iface.slaacMaintenance(now);
            for (&valid_until) |*v| if (v.* != null and v.*.? <= now_secs) {
                v.* = null;
            };
            var prefix: ipv6.Address = @splat(0);
            prefix[0] = 0x20;
            prefix[7] = op.prefix % 3;
            const len: u8 = if (op.len_sel % 4 == 0) 48 else 64;
            const ip: ipv6.Repr = .{ .src_addr = router, .dst_addr = ipv6.LINK_LOCAL_ALL_NODES, .next_header = .icmpv6, .payload_len = 64, .hop_limit = 255 };
            iface.processRouterAdvertisement(ip, .{ .router_advert = .{
                .hop_limit = 64,
                .flags = .{ .managed = false, .other = false },
                .router_lifetime = op.lifetime,
                .reachable_time = 0,
                .retrans_time = 0,
                .lladdr = null,
                .mtu = null,
                .prefix_info = .{ .prefix_len = len, .flags = .{ .on_link = true, .addrconf = op.addrconf }, .valid_lifetime = op.valid % 2000, .preferred_lifetime = op.preferred % 2000, .prefix = prefix },
            } });
            const slaac = iface.slaac.?;
            if (op.lifetime > 0 and !std.mem.eql(u8, &(slaac.default_router orelse return false), &router)) return false;
            if (op.lifetime == 0 and slaac.default_router != null) return false;
            const configurable = len == 64 and op.addrconf;
            if (configurable) valid_until[op.prefix % 3] = if (op.valid % 2000 == 0) null else now_secs + op.valid % 2000;
            for (valid_until, 0..) |until, i| {
                var addr = prefix;
                addr[7] = @intCast(i);
                @memcpy(addr[8..], &iid);
                if (iface.v6.hasIpAddr(addr) != (until != null)) return false;
                if (until != null and !iface.hasSolicitedNode(ipv6.solicitedNode(addr))) return false;
            }
            if (!iface.v6.hasIpAddr(ll)) return false;
        }
        now_secs += 100_000;
        iface.slaacMaintenance(time_mod.Instant.fromSecs(now_secs));
        const after = iface.slaac.?;
        return after.default_router == null and after.phase != .configured and iface.v6.ipAddrs().len == 1 and
            (iface.slaacPollAt() == null or !iface.slaacPollAt().?.lessThan(time_mod.Instant.ZERO));
    }
};

test "laws: autoconfiguration" {
    try zv.checkLaws(autoconfiguration, .{ .iterations = iterations, .seed = 29 });
}

pub const hosts = struct {
    const me_mac = ethernet.Address{ 2, 0, 0, 0, 0, 1 };
    const peer_mac = ethernet.Address{ 2, 0, 0, 0, 0, 2 };
    const me4 = ipv4.Address{ 10, 0, 0, 1 };
    const peer4 = ipv4.Address{ 10, 0, 0, 2 };

    fn host() iface_mod.Interface {
        var iface = iface_mod.Interface.init(me_mac);
        iface.setIpAddrs(&.{.{ .address = me4, .prefix_len = 24 }});
        iface.setIpv6Addrs(&.{.{ .address = iface_mod.Interface.linkLocalFromMac(me_mac), .prefix_len = 64 }});
        return iface;
    }

    fn frame(buf: []u8, kind: ethernet.EtherType, len_after: usize) usize {
        const n = ethernet.emit(.{ .dst_addr = me_mac, .src_addr = peer_mac, .ethertype = kind }, buf) catch unreachable;
        return n + len_after;
    }

    /// RFC 826: an ARP request for the interface's address is answered with its hardware
    /// address and teaches it the requester's; a request for another address is ignored.
    pub fn arpRequestsAreAnsweredForOwnAddressesOnly(who: [4]u8, requester: u8) bool {
        var iface = host();
        var buf: [64]u8 = undefined;
        const target: ipv4.Address = if (who[0] % 2 == 0) me4 else who;
        const source: ipv4.Address = .{ 10, 0, 0, 2 + requester % 100 };
        var at = ethernet.emit(.{ .dst_addr = ethernet.BROADCAST, .src_addr = peer_mac, .ethertype = .arp }, &buf) catch return false;
        at += arp.emit(.{ .operation = .request, .source_hardware_addr = peer_mac, .source_protocol_addr = source, .target_hardware_addr = .{ 0, 0, 0, 0, 0, 0 }, .target_protocol_addr = target }, buf[at..]) catch return false;
        const response = iface.processEthernet(buf[0..at]);
        const ours = std.mem.eql(u8, &target, &me4);
        if ((response != null) != ours) return false;
        if (!ours) return !iface.hasNeighbor(source);
        const reply = response.?.arp_reply;
        return reply.operation == .reply and std.mem.eql(u8, &reply.source_hardware_addr, &me_mac) and std.mem.eql(u8, &reply.target_hardware_addr, &peer_mac) and
            std.mem.eql(u8, &reply.source_protocol_addr, &me4) and std.mem.eql(u8, &reply.target_protocol_addr, &source) and iface.hasNeighbor(source);
    }

    /// RFC 1122 3.2.2.1 and RFC 792: a datagram for an unknown IP protocol is answered with an
    /// ICMP "protocol unreachable" quoting the offender, unless it was a broadcast.
    pub fn unknownIpv4ProtocolsAreRefused(protocol: u8, payload_len: u8, broadcast: bool) bool {
        var iface = host();
        var buf: [128]u8 = @splat(0);
        const proto: ipv4.Protocol = @fromBackingInt(protocol);
        if (proto == .icmp or proto == .igmp or proto == .udp or proto == .tcp) return true;
        const len = payload_len % 40;
        const repr: ipv4.Repr = .{
            .version = 4,
            .ihl = 5,
            .dscp_ecn = 0,
            .total_length = @intCast(ipv4.HEADER_LEN + len),
            .identification = 7,
            .dont_fragment = false,
            .more_fragments = false,
            .fragment_offset = 0,
            .ttl = 64,
            .protocol = proto,
            .checksum = 0,
            .src_addr = peer4,
            .dst_addr = if (broadcast) ipv4.BROADCAST else me4,
        };
        var at = frame(&buf, .ipv4, 0);
        _ = ipv4.emit(repr, buf[at..]) catch return false;
        at += ipv4.HEADER_LEN + len;
        const response = iface.processEthernet(buf[0..at]);
        if (broadcast) return response == null;
        const r = (response orelse return false).ipv4;
        const unreachable_ = switch (r.payload) {
            .icmp_dest_unreachable => |d| d,
            else => return false,
        };
        return unreachable_.code == 2 and std.mem.eql(u8, &r.ip.src_addr, &me4) and std.mem.eql(u8, &r.ip.dst_addr, &peer4) and
            unreachable_.invoking_repr.protocol == proto and unreachable_.data.len == len;
    }

    /// RFC 4443 3.4: an IPv6 packet whose next header is unknown is answered with a parameter
    /// problem pointing at the Next Header field (offset 6); multicast packets are not answered.
    pub fn unknownIpv6NextHeadersAreRefused(next: u8, payload_len: u8, multicast: bool) bool {
        var iface = host();
        var buf: [128]u8 = @splat(0);
        const proto: ipv6.Protocol = @fromBackingInt(next);
        switch (proto) {
            .hop_by_hop, .tcp, .udp, .routing, .fragment, .destination, .icmpv6, .no_next_header => return true,
            else => {},
        }
        const len = payload_len % 40;
        const me6 = iface_mod.Interface.linkLocalFromMac(me_mac);
        const repr: ipv6.Repr = .{ .src_addr = iface_mod.Interface.linkLocalFromMac(peer_mac), .dst_addr = if (multicast) ipv6.LINK_LOCAL_ALL_NODES else me6, .next_header = proto, .payload_len = len, .hop_limit = 64 };
        var at = frame(&buf, .ipv6, 0);
        _ = ipv6.emit(repr, buf[at..]) catch return false;
        at += ipv6.HEADER_LEN + len;
        const response = iface.processEthernet(buf[0..at]);
        if (multicast) return response == null or response.?.ipv6.payload == .icmpv6_param_problem;
        const r = (response orelse return false).ipv6;
        const problem = switch (r.payload) {
            .icmpv6_param_problem => |p| p,
            else => return false,
        };
        return problem.reason == .unrecognized_nxt_hdr and problem.pointer == 6 and std.mem.eql(u8, &r.ip.src_addr, &me6) and problem.data.len == len;
    }

    /// RFC 4861 7.2.4 and 7.1.1: a neighbor solicitation for one of the interface's addresses is
    /// answered with an advertisement carrying its link-layer address, and only if it arrived
    /// with hop limit 255; the solicitor is learned unless the solicitation came from `::`.
    pub fn neighborSolicitationsAreAnswered(hop_limit: u8, from_unspecified: bool, other_target: bool) bool {
        var iface = host();
        var buf: [160]u8 = @splat(0);
        const me6 = iface_mod.Interface.linkLocalFromMac(me_mac);
        const peer6 = iface_mod.Interface.linkLocalFromMac(peer_mac);
        const src = if (from_unspecified) ipv6.UNSPECIFIED else peer6;
        const target = if (other_target) iface_mod.Interface.linkLocalFromMac(.{ 2, 0, 0, 0, 0, 9 }) else me6;
        const solicit: ndisc.Repr = .{ .neighbor_solicit = .{ .target_addr = target, .lladdr = if (from_unspecified) null else peer_mac } };
        const dst = ipv6.solicitedNode(target);
        var at = frame(&buf, .ipv6, 0);
        const body_len = icmpv6.bufferLen(.{ .ndisc = solicit });
        const ip: ipv6.Repr = .{ .src_addr = src, .dst_addr = dst, .next_header = .icmpv6, .payload_len = @intCast(body_len), .hop_limit = hop_limit };
        _ = ipv6.emit(ip, buf[at..]) catch return false;
        at += ipv6.HEADER_LEN;
        _ = icmpv6.emit(.{ .ndisc = solicit }, src, dst, buf[at..]) catch return false;
        at += body_len;
        const response = iface.processEthernet(buf[0..at]);
        const answered = hop_limit == 255 and !other_target;
        if ((response != null) != answered) return false;
        if (!answered) return true;
        const r = response.?.ipv6;
        const advert = switch (r.payload) {
            .ndisc => |n| switch (n) {
                .neighbor_advert => |a| a,
                else => return false,
            },
            else => return false,
        };
        return std.mem.eql(u8, &advert.target_addr, &me6) and std.mem.eql(u8, &(advert.lladdr orelse return false), &me_mac) and advert.flags.override_ and
            advert.flags.solicited == !from_unspecified and r.ip.hop_limit == 255 and
            std.mem.eql(u8, &r.ip.dst_addr, if (from_unspecified) &ipv6.LINK_LOCAL_ALL_NODES else &peer6) and
            (iface.neighbor_cache_v6.hasNeighbor(peer6) == !from_unspecified);
    }
};

test "laws: host behavior" {
    try zv.checkLaws(hosts, .{ .iterations = iterations, .seed = 30 });
}

// -------------------------------------------------------------------------
// DHCP client lifecycle (RFC 2131).
// -------------------------------------------------------------------------

pub const leases = struct {
    const Socket = dhcp_socket.Socket;
    const Instant = time_mod.Instant;
    const Duration = time_mod.Duration;

    const mac = [6]u8{ 2, 0, 0, 0, 0, 7 };
    const server = [4]u8{ 10, 0, 0, 254 };
    const lease_ip = [4]u8{ 10, 0, 0, 42 };

    pub const pinned = .{
        .unansweredRequestsBackOffAndGiveUp = .{ .{ 1, 100 }, .{ 7, 199 } },
    };

    fn reply(kind: dhcp.MessageType, xid: u32, lease: ?u32, t1: ?u32, t2: ?u32) dhcp.Repr {
        return .{
            .message_type = kind,
            .transaction_id = xid,
            .secs = 0,
            .client_hardware_address = mac,
            .client_ip = .{ 0, 0, 0, 0 },
            .your_ip = lease_ip,
            .server_ip = server,
            .router = server,
            .subnet_mask = .{ 255, 255, 255, 0 },
            .relay_agent_ip = .{ 0, 0, 0, 0 },
            .broadcast = false,
            .requested_ip = null,
            .client_identifier = null,
            .server_identifier = server,
            .parameter_request_list = null,
            .max_size = null,
            .lease_duration = lease,
            .renew_duration = t1,
            .rebind_duration = t2,
            .dns_servers = null,
        };
    }

    /// Acquire a lease at `at`: discover, offer, request, acknowledgment.
    fn acquire(s: *Socket, at: Instant, lease: ?u32, t1: ?u32, t2: ?u32) bool {
        const discover = s.dispatch(at) orelse return false;
        if (discover.dhcp_repr.message_type != .discover or !std.mem.eql(u8, &discover.dst_ip, &.{ 255, 255, 255, 255 })) return false;
        s.process(at, server, reply(.offer, discover.dhcp_repr.transaction_id, lease, t1, t2));
        const request = s.dispatch(at) orelse return false;
        if (request.dhcp_repr.message_type != .request or !std.mem.eql(u8, &request.dhcp_repr.requested_ip.?, &lease_ip)) return false;
        s.process(at, server, reply(.ack, request.dhcp_repr.transaction_id, lease, t1, t2));
        return true;
    }

    /// RFC 2131 4.4.5: a lease is renewed at T1 (by default half of it), rebound with a
    /// broadcast at T2 (by default 7/8) and lost at its end, with T1 < T2 < lease whatever the
    /// server sent; the client announces its configuration once and its loss once, and `reset`
    /// goes back to discovery at once.
    pub fn leasesRenewRebindAndExpire(seed: u64, lease_secs: u16, t1: ?u16, t2: ?u16) bool {
        const lease: u32 = @as(u32, lease_secs) + 8;
        var s = Socket.initWithTransactionSeed(mac, seed);
        if (!s.pollAt().eql(Instant.ZERO) or s.poll() == null) return false;
        const t0 = Instant.fromSecs(100);
        if (!acquire(&s, t0, lease, if (t1) |v| v else null, if (t2) |v| v else null)) return false;

        const event = s.poll() orelse return false;
        const cfg = switch (event) {
            .configured => |c| c,
            .deconfigured => return false,
        };
        if (!std.mem.eql(u8, &cfg.address, &lease_ip) or cfg.prefix_len != 24 or !std.mem.eql(u8, &cfg.router.?, &server) or s.poll() != null) return false;

        const lease_end = t0.add(Duration.fromSecs(lease));
        const timers = switch (s.state) {
            .renewing => |r| r,
            else => return false,
        };
        if (!timers.expires_at.eql(lease_end) or timers.renew_at.lessThan(t0) or timers.rebind_at.lessThan(timers.renew_at) or lease_end.lessThan(timers.rebind_at)) return false;
        if (t1 == null and t2 == null and (!timers.renew_at.eql(t0.add(Duration.fromSecs(lease).divFloor(2))) or
            timers.rebind_at.totalMicros() != t0.totalMicros() + @divTrunc(Duration.fromSecs(lease).totalMicros() * 7, 8))) return false;
        if (!s.pollAt().eql(timers.renew_at)) return false;

        if (s.dispatch(timers.renew_at.sub(Duration.fromMicros(1))) != null) return false;
        const renew = s.dispatch(timers.renew_at) orelse return false;
        if (renew.dhcp_repr.message_type != .request or !std.mem.eql(u8, &renew.dhcp_repr.client_ip, &lease_ip)) return false;
        const renew_is_unicast = timers.renew_at.lessThan(timers.rebind_at);
        if (std.mem.eql(u8, &renew.dst_ip, &server) != renew_is_unicast) return false;
        const rebind_at = switch (s.state) {
            .renewing => |r| r.rebind_at,
            else => return false,
        };
        if (rebind_at.lessThan(lease_end)) {
            const rebind = s.dispatch(rebind_at) orelse return false;
            if (!std.mem.eql(u8, &rebind.dst_ip, &.{ 255, 255, 255, 255 }) or rebind.dhcp_repr.message_type != .request) return false;
        }

        const lost = s.dispatch(lease_end);
        if (lost != null or s.state != .discovering) return false;
        if (s.poll() == null or !s.pollAt().eql(Instant.ZERO)) return false;

        if (!acquire(&s, lease_end.add(Duration.fromSecs(1)), lease, null, null)) return false;
        if (s.poll() == null) return false;
        s.reset();
        const gone = s.poll() orelse return false;
        return gone == .deconfigured and s.state == .discovering and s.pollAt().eql(Instant.ZERO);
    }

    /// RFC 2131 4.1: unanswered requests back off and then give up; the retry timer never moves
    /// backwards however many retries are configured.
    pub fn unansweredRequestsBackOffAndGiveUp(seed: u64, retries: u16) bool {
        var s = Socket.initWithTransactionSeed(mac, seed);
        s.setRetryConfig(.{ .request_retries = retries % 200 });
        const discover = s.dispatch(Instant.ZERO) orelse return false;
        s.process(Instant.ZERO, server, reply(.offer, discover.dhcp_repr.transaction_id, 3600, null, null));
        var now = Instant.ZERO;
        var sent: usize = 0;
        var last_gap = Duration.ZERO;
        while (sent <= retries % 200) : (sent += 1) {
            const due = s.pollAt();
            if (due.lessThan(now)) return false;
            if (sent > 0 and due.diff(now).lessThan(last_gap)) return false;
            if (sent > 0) last_gap = due.diff(now);
            now = due;
            if (s.dispatch(now)) |request| {
                if (request.dhcp_repr.message_type != .request) return false;
            } else break;
        }
        return sent == retries % 200 and s.state == .discovering and s.pollAt().eql(Instant.ZERO);
    }
};

test "laws: dhcp leases" {
    try zv.checkLaws(leases, .{ .iterations = 3_000, .seed = 31 });
}
