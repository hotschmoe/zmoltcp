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
    _ = result catch {};
    return true;
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
        return roundTrip(tcp, in.slice(), struct {
            fn f(r: *tcp.Repr) void {
                r.data_offset = 0;
            }
        }.f);
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
