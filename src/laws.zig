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
const RxPick = zv.Ranged(0, rx_sizes.len - 1);
const max_rx = 140_000;

var rx_mem: [max_rx]u8 = undefined;
var tx_mem: [4096]u8 = undefined;
var payload_mem: [2 * max_rx]u8 = @splat(0x5a);

const local_v4 = ipv4.Address{ 10, 0, 0, 1 };
const peer_v4 = ipv4.Address{ 10, 0, 0, 2 };

pub const tcp_state = struct {
    pub const pinned = .{
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

    const Check = enum { rings_in_bounds, window_fits_ring, fin_follows_all_data, dispatch_fits_egress };

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
        const declared = @as(usize, data[2]) << 8 | data[3];
        return within(data, p) and p.len + ihl * 4 == declared;
    }
    pub fn ipv6PayloadInsideInput(in: zv.Bytes(64)) bool {
        var buf: [64]u8 = undefined;
        const n = @max(load(64, in, &buf), ipv6.HEADER_LEN);
        buf[0] = 0x60 | (buf[0] & 0x0f);
        const data = buf[0..n];
        const p = ipv6.payloadSlice(data) catch return true;
        const declared = @as(usize, data[4]) << 8 | data[5];
        return within(data, p) and p.len == declared;
    }
    pub fn udpPayloadInsideInput(in: zv.Bytes(48)) bool {
        var buf: [48]u8 = undefined;
        const n = load(48, in, &buf);
        const data = buf[0..n];
        const p = udp.payloadSlice(data) catch return true;
        const declared = if (n >= 6) @as(usize, data[4]) << 8 | data[5] else 0;
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
