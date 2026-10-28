// Executable laws (zirakzigil) for the wire parsers, sequence numbers and
// storage. Imported only from root.zig's test block;
// run by `zig build test`.

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
