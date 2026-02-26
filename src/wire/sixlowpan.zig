// 6LoWPAN IPHC header compression, NHC, and address resolution per RFC 6282.
//
// Reference: smoltcp src/wire/sixlowpan/{mod.rs, iphc.rs, nhc.rs}

const checksum = @import("checksum.zig");
const readU16 = checksum.readU16;
const writeU16 = checksum.writeU16;
const ieee802154 = @import("ieee802154.zig");
const ipv6 = @import("ipv6.zig");
pub const sixlowpan_frag = @import("sixlowpan_frag.zig");

// -------------------------------------------------------------------------
// Dispatch constants
// -------------------------------------------------------------------------

pub const DISPATCH_IPHC: u8 = 0b011;
pub const DISPATCH_EXT_NHC: u8 = 0b1110;
pub const DISPATCH_UDP_NHC: u8 = 0b11110;

// -------------------------------------------------------------------------
// Common types
// -------------------------------------------------------------------------

pub const AddressContext = [8]u8;
pub const LINK_LOCAL_PREFIX = [2]u8{ 0xfe, 0x80 };
pub const EUI64_MIDDLE = [2]u8{ 0xff, 0xfe };

pub const NextHeader = union(enum) {
    compressed,
    uncompressed: ipv6.Protocol,
};

// -------------------------------------------------------------------------
// Dispatch detection
// -------------------------------------------------------------------------

pub const DispatchType = enum {
    iphc,
    first_fragment,
    next_fragment,
    unknown,
};

pub fn dispatchType(first_byte: u8) DispatchType {
    if (first_byte >> 5 == DISPATCH_IPHC) return .iphc;
    if (first_byte >> 3 == sixlowpan_frag.DISPATCH_FIRST_FRAGMENT) return .first_fragment;
    if (first_byte >> 3 == sixlowpan_frag.DISPATCH_NEXT_FRAGMENT) return .next_fragment;
    return .unknown;
}

// -------------------------------------------------------------------------
// Address resolution
// -------------------------------------------------------------------------

fn iidFromLlAddr(ll_addr: ieee802154.Address) error{Malformed}![8]u8 {
    return switch (ll_addr) {
        .extended => ll_addr.asEui64(),
        .short => |s| [8]u8{ 0, 0, 0, 0xff, 0xfe, 0, s[0], s[1] },
        .absent => error.Malformed,
    };
}

pub fn resolveSourceAddress(
    data: []const u8,
    offset: *usize,
    sac: u1,
    sam: u2,
    ll_addr: ieee802154.Address,
    src_ctx_id: ?u4,
    contexts: []const AddressContext,
) error{ Truncated, Malformed }![16]u8 {
    var addr = [_]u8{0} ** 16;

    if (sac == 0) {
        switch (sam) {
            0b00 => {
                if (offset.* + 16 > data.len) return error.Truncated;
                @memcpy(addr[0..16], data[offset.*..][0..16]);
                offset.* += 16;
            },
            0b01 => {
                if (offset.* + 8 > data.len) return error.Truncated;
                @memcpy(addr[0..2], &LINK_LOCAL_PREFIX);
                @memcpy(addr[8..16], data[offset.*..][0..8]);
                offset.* += 8;
            },
            0b10 => {
                if (offset.* + 2 > data.len) return error.Truncated;
                @memcpy(addr[0..2], &LINK_LOCAL_PREFIX);
                @memcpy(addr[11..13], &EUI64_MIDDLE);
                @memcpy(addr[14..16], data[offset.*..][0..2]);
                offset.* += 2;
            },
            0b11 => {
                @memcpy(addr[0..2], &LINK_LOCAL_PREFIX);
                const iid = try iidFromLlAddr(ll_addr);
                @memcpy(addr[8..16], &iid);
            },
        }
    } else {
        // SAC=1: context-based
        switch (sam) {
            0b00 => {
                // Unspecified address (::)
            },
            0b01 => {
                const ctx_idx = src_ctx_id orelse return error.Malformed;
                if (ctx_idx >= contexts.len) return error.Malformed;
                if (offset.* + 8 > data.len) return error.Truncated;
                @memcpy(addr[0..8], &contexts[ctx_idx]);
                @memcpy(addr[8..16], data[offset.*..][0..8]);
                offset.* += 8;
            },
            0b10 => {
                const ctx_idx = src_ctx_id orelse return error.Malformed;
                if (ctx_idx >= contexts.len) return error.Malformed;
                if (offset.* + 2 > data.len) return error.Truncated;
                @memcpy(addr[0..8], &contexts[ctx_idx]);
                @memcpy(addr[14..16], data[offset.*..][0..2]);
                offset.* += 2;
            },
            0b11 => {
                const ctx_idx = src_ctx_id orelse return error.Malformed;
                if (ctx_idx >= contexts.len) return error.Malformed;
                @memcpy(addr[0..8], &contexts[ctx_idx]);
                const iid = try iidFromLlAddr(ll_addr);
                @memcpy(addr[8..16], &iid);
            },
        }
    }

    return addr;
}

pub fn resolveDestAddress(
    data: []const u8,
    offset: *usize,
    m: u1,
    dac: u1,
    dam: u2,
    ll_addr: ieee802154.Address,
    dst_ctx_id: ?u4,
    contexts: []const AddressContext,
) error{ Truncated, Malformed }![16]u8 {
    var addr = [_]u8{0} ** 16;

    if (m == 0) {
        // Unicast
        if (dac == 0) {
            return resolveSourceAddress(data, offset, 0, dam, ll_addr, null, contexts);
        } else {
            return resolveSourceAddress(data, offset, 1, dam, ll_addr, dst_ctx_id, contexts);
        }
    }

    // Multicast (M=1)
    if (dac == 0) {
        switch (dam) {
            0b00 => {
                if (offset.* + 16 > data.len) return error.Truncated;
                @memcpy(addr[0..16], data[offset.*..][0..16]);
                offset.* += 16;
            },
            0b01 => {
                // ffXX::00XX:XXXX:XXXX (6 bytes inline)
                if (offset.* + 6 > data.len) return error.Truncated;
                addr[0] = 0xff;
                addr[1] = data[offset.*];
                @memcpy(addr[11..16], data[offset.* + 1 ..][0..5]);
                offset.* += 6;
            },
            0b10 => {
                // ffXX::00XX:XXXX (4 bytes inline)
                if (offset.* + 4 > data.len) return error.Truncated;
                addr[0] = 0xff;
                addr[1] = data[offset.*];
                @memcpy(addr[13..16], data[offset.* + 1 ..][0..3]);
                offset.* += 4;
            },
            0b11 => {
                // ff02::00XX (1 byte inline)
                if (offset.* + 1 > data.len) return error.Truncated;
                addr[0] = 0xff;
                addr[1] = 0x02;
                addr[15] = data[offset.*];
                offset.* += 1;
            },
        }
    } else {
        return error.Malformed;
    }

    return addr;
}

// -------------------------------------------------------------------------
// IPHC Header Compression
// -------------------------------------------------------------------------

pub const IphcRepr = struct {
    src_addr: [16]u8,
    dst_addr: [16]u8,
    next_header: NextHeader,
    hop_limit: u8,
    ecn: ?u2 = null,
    dscp: ?u6 = null,
    flow_label: ?u20 = null,
};

pub fn parseIphc(
    data: []const u8,
    src_ll: ieee802154.Address,
    dst_ll: ieee802154.Address,
    contexts: []const AddressContext,
) error{ Truncated, Malformed }!struct { repr: IphcRepr, consumed: usize } {
    if (data.len < 2) return error.Truncated;

    const header = readU16(data[0..2]);

    // Validate dispatch
    const dispatch: u3 = @truncate(header >> 13);
    if (dispatch != DISPATCH_IPHC) return error.Malformed;

    const tf: u2 = @truncate(header >> 11);
    const nh_flag: u1 = @truncate(header >> 10);
    const hlim_mode: u2 = @truncate(header >> 8);
    const cid: u1 = @truncate(header >> 7);
    const sac: u1 = @truncate(header >> 6);
    const sam: u2 = @truncate(header >> 4);
    const m: u1 = @truncate(header >> 3);
    const dac: u1 = @truncate(header >> 2);
    const dam: u2 = @truncate(header);

    var offset: usize = 2;

    // Context identifier extension
    var src_ctx_id: ?u4 = null;
    var dst_ctx_id: ?u4 = null;
    if (cid == 1) {
        if (offset >= data.len) return error.Truncated;
        src_ctx_id = @truncate(data[offset] >> 4);
        dst_ctx_id = @truncate(data[offset] & 0x0f);
        offset += 1;
    }

    // Traffic class and flow label
    var ecn: ?u2 = null;
    var dscp: ?u6 = null;
    var flow_label: ?u20 = null;

    switch (tf) {
        0b00 => {
            // 4 bytes: ECN + DSCP + 4-bit pad + 20-bit flow label
            if (offset + 4 > data.len) return error.Truncated;
            ecn = @truncate((data[offset] & 0xC0) >> 6);
            dscp = @truncate(data[offset] & 0x3F);
            const fl_hi: u20 = @as(u20, data[offset + 1] & 0x0F) << 16;
            const fl_lo: u20 = @as(u20, data[offset + 2]) << 8 | @as(u20, data[offset + 3]);
            flow_label = fl_hi | fl_lo;
            offset += 4;
        },
        0b01 => {
            // 3 bytes: ECN + 2-bit pad + 20-bit flow label (DSCP elided)
            if (offset + 3 > data.len) return error.Truncated;
            ecn = @truncate((data[offset] & 0xC0) >> 6);
            const fl_hi: u20 = @as(u20, data[offset] & 0x0F) << 16;
            const fl_lo: u20 = @as(u20, data[offset + 1]) << 8 | @as(u20, data[offset + 2]);
            flow_label = fl_hi | fl_lo;
            offset += 3;
        },
        0b10 => {
            // 1 byte: ECN + DSCP (flow label elided)
            if (offset + 1 > data.len) return error.Truncated;
            ecn = @truncate((data[offset] & 0xC0) >> 6);
            dscp = @truncate(data[offset] & 0x3F);
            offset += 1;
        },
        0b11 => {
            // Fully elided
        },
    }

    // Next header
    var next_header: NextHeader = undefined;
    if (nh_flag == 0) {
        if (offset >= data.len) return error.Truncated;
        next_header = .{ .uncompressed = @enumFromInt(data[offset]) };
        offset += 1;
    } else {
        next_header = .compressed;
    }

    // Hop limit
    var hop_limit: u8 = undefined;
    switch (hlim_mode) {
        0b00 => {
            if (offset >= data.len) return error.Truncated;
            hop_limit = data[offset];
            offset += 1;
        },
        0b01 => hop_limit = 1,
        0b10 => hop_limit = 64,
        0b11 => hop_limit = 255,
    }

    // Source address
    const src_addr = try resolveSourceAddress(data, &offset, sac, sam, src_ll, src_ctx_id, contexts);

    // Destination address
    const dst_addr = try resolveDestAddress(data, &offset, m, dac, dam, dst_ll, dst_ctx_id, contexts);

    return .{
        .repr = .{
            .src_addr = src_addr,
            .dst_addr = dst_addr,
            .next_header = next_header,
            .hop_limit = hop_limit,
            .ecn = ecn,
            .dscp = dscp,
            .flow_label = flow_label,
        },
        .consumed = offset,
    };
}

// Source address compression analysis for emit
const SrcCompression = struct {
    sac: u1,
    sam: u2,
    inline_len: usize,
};

fn srcCompress(addr: [16]u8, ll_addr: ieee802154.Address) SrcCompression {
    if (eql16(addr, ipv6.UNSPECIFIED)) {
        return .{ .sac = 1, .sam = 0b00, .inline_len = 0 };
    }

    if (ipv6.isLinkLocal(addr)) {
        // Check if IID matches EUI-64 of LL address
        const eui = ll_addr.asEui64();
        if (eql8(addr[8..16].*, eui)) {
            return .{ .sac = 0, .sam = 0b11, .inline_len = 0 };
        }

        // Check if IID is 0000:00ff:fe00:XXXX pattern
        if (addr[8] == 0 and addr[9] == 0 and addr[10] == 0 and
            addr[11] == 0xff and addr[12] == 0xfe and addr[13] == 0)
        {
            // Check if short address matches LL
            switch (ll_addr) {
                .short => |s| {
                    if (addr[14] == s[0] and addr[15] == s[1]) {
                        return .{ .sac = 0, .sam = 0b11, .inline_len = 0 };
                    }
                },
                else => {},
            }
            return .{ .sac = 0, .sam = 0b10, .inline_len = 2 };
        }

        return .{ .sac = 0, .sam = 0b01, .inline_len = 8 };
    }

    return .{ .sac = 0, .sam = 0b00, .inline_len = 16 };
}

// Destination address compression analysis for emit
const DstCompression = struct {
    m: u1,
    dac: u1,
    dam: u2,
    inline_len: usize,
};

fn dstCompress(addr: [16]u8, ll_addr: ieee802154.Address) DstCompression {
    if (ipv6.isMulticast(addr)) {
        // ff02::00XX
        if (addr[1] == 0x02 and allZero(addr[2..15])) {
            return .{ .m = 1, .dac = 0, .dam = 0b11, .inline_len = 1 };
        }
        // ffXX::00XX:XXXX (bytes 2..13 all zero)
        if (allZero(addr[2..13])) {
            return .{ .m = 1, .dac = 0, .dam = 0b10, .inline_len = 4 };
        }
        // ffXX::00XX:XXXX:XXXX (bytes 2..11 all zero)
        if (allZero(addr[2..11])) {
            return .{ .m = 1, .dac = 0, .dam = 0b01, .inline_len = 6 };
        }
        return .{ .m = 1, .dac = 0, .dam = 0b00, .inline_len = 16 };
    }

    if (ipv6.isLinkLocal(addr)) {
        const eui = ll_addr.asEui64();
        if (eql8(addr[8..16].*, eui)) {
            return .{ .m = 0, .dac = 0, .dam = 0b11, .inline_len = 0 };
        }

        if (addr[8] == 0 and addr[9] == 0 and addr[10] == 0 and
            addr[11] == 0xff and addr[12] == 0xfe and addr[13] == 0)
        {
            switch (ll_addr) {
                .short => |s| {
                    if (addr[14] == s[0] and addr[15] == s[1]) {
                        return .{ .m = 0, .dac = 0, .dam = 0b11, .inline_len = 0 };
                    }
                },
                else => {},
            }
            return .{ .m = 0, .dac = 0, .dam = 0b10, .inline_len = 2 };
        }

        return .{ .m = 0, .dac = 0, .dam = 0b01, .inline_len = 8 };
    }

    return .{ .m = 0, .dac = 0, .dam = 0b00, .inline_len = 16 };
}

pub fn emitIphc(
    repr: IphcRepr,
    src_ll: ieee802154.Address,
    dst_ll: ieee802154.Address,
    buf: []u8,
) error{BufferTooSmall}!usize {
    const needed = iphcBufferLen(repr, src_ll, dst_ll);
    if (buf.len < needed) return error.BufferTooSmall;

    const sc = srcCompress(repr.src_addr, src_ll);
    const dc = dstCompress(repr.dst_addr, dst_ll);

    // NH flag
    const nh_flag: u1 = switch (repr.next_header) {
        .compressed => 1,
        .uncompressed => 0,
    };

    // HLIM
    const hlim_mode: u2 = switch (repr.hop_limit) {
        1 => 0b01,
        64 => 0b10,
        255 => 0b11,
        else => 0b00,
    };

    // TF = 0b11 (elide all traffic class, matching smoltcp emit)
    const tf: u2 = 0b11;

    // Build 2-byte header
    var header: u16 = 0;
    header |= @as(u16, DISPATCH_IPHC) << 13;
    header |= @as(u16, tf) << 11;
    header |= @as(u16, nh_flag) << 10;
    header |= @as(u16, hlim_mode) << 8;
    // CID = 0 (no context extension for emit)
    header |= @as(u16, sc.sac) << 6;
    header |= @as(u16, sc.sam) << 4;
    header |= @as(u16, dc.m) << 3;
    header |= @as(u16, dc.dac) << 2;
    header |= @as(u16, dc.dam);

    writeU16(buf[0..2], header);

    var offset: usize = 2;

    // Next header inline
    switch (repr.next_header) {
        .uncompressed => |proto| {
            buf[offset] = @intFromEnum(proto);
            offset += 1;
        },
        .compressed => {},
    }

    // Hop limit inline
    if (hlim_mode == 0b00) {
        buf[offset] = repr.hop_limit;
        offset += 1;
    }

    // Source address inline bytes
    switch (sc.sam) {
        0b00 => {
            if (sc.sac == 0) {
                @memcpy(buf[offset..][0..16], &repr.src_addr);
                offset += 16;
            }
            // sac=1, sam=0b00 => unspecified, no inline
        },
        0b01 => {
            @memcpy(buf[offset..][0..8], repr.src_addr[8..16]);
            offset += 8;
        },
        0b10 => {
            @memcpy(buf[offset..][0..2], repr.src_addr[14..16]);
            offset += 2;
        },
        0b11 => {
            // Fully elided
        },
    }

    // Destination address inline bytes
    if (dc.m == 1) {
        switch (dc.dam) {
            0b00 => {
                @memcpy(buf[offset..][0..16], &repr.dst_addr);
                offset += 16;
            },
            0b01 => {
                // 6 bytes: scope + 5 bytes of addr
                buf[offset] = repr.dst_addr[1];
                @memcpy(buf[offset + 1 ..][0..5], repr.dst_addr[11..16]);
                offset += 6;
            },
            0b10 => {
                // 4 bytes: scope + 3 bytes of addr
                buf[offset] = repr.dst_addr[1];
                @memcpy(buf[offset + 1 ..][0..3], repr.dst_addr[13..16]);
                offset += 4;
            },
            0b11 => {
                // 1 byte
                buf[offset] = repr.dst_addr[15];
                offset += 1;
            },
        }
    } else {
        switch (dc.dam) {
            0b00 => {
                @memcpy(buf[offset..][0..16], &repr.dst_addr);
                offset += 16;
            },
            0b01 => {
                @memcpy(buf[offset..][0..8], repr.dst_addr[8..16]);
                offset += 8;
            },
            0b10 => {
                @memcpy(buf[offset..][0..2], repr.dst_addr[14..16]);
                offset += 2;
            },
            0b11 => {},
        }
    }

    return offset;
}

pub fn iphcBufferLen(
    repr: IphcRepr,
    src_ll: ieee802154.Address,
    dst_ll: ieee802154.Address,
) usize {
    var len: usize = 2; // base header

    // TF=0b11, no traffic class bytes
    // Next header
    len += switch (repr.next_header) {
        .compressed => @as(usize, 0),
        .uncompressed => @as(usize, 1),
    };

    // Hop limit
    len += switch (repr.hop_limit) {
        1, 64, 255 => @as(usize, 0),
        else => @as(usize, 1),
    };

    len += srcCompress(repr.src_addr, src_ll).inline_len;
    len += dstCompress(repr.dst_addr, dst_ll).inline_len;

    return len;
}

// -------------------------------------------------------------------------
// NHC: Extension Header Compression
// -------------------------------------------------------------------------

pub const ExtHeaderId = enum(u3) {
    hop_by_hop = 0,
    routing = 1,
    fragment = 2,
    destination = 3,
    mobility = 4,
    _,
};

pub const ExtHeaderNhcRepr = struct {
    id: ExtHeaderId,
    next_header: NextHeader,
    length: u8,
};

pub fn parseExtHeaderNhc(data: []const u8) error{ Truncated, Malformed }!struct { repr: ExtHeaderNhcRepr, consumed: usize } {
    if (data.len < 1) return error.Truncated;

    // Validate dispatch (top 4 bits = 0b1110)
    if (data[0] >> 4 != DISPATCH_EXT_NHC) return error.Malformed;

    const eid: u3 = @truncate((data[0] >> 1) & 0b111);
    const nh_bit: u1 = @truncate(data[0] & 1);

    var offset: usize = 1;

    var next_header: NextHeader = undefined;
    if (nh_bit == 0) {
        if (offset >= data.len) return error.Truncated;
        next_header = .{ .uncompressed = @enumFromInt(data[offset]) };
        offset += 1;
    } else {
        next_header = .compressed;
    }

    if (offset >= data.len) return error.Truncated;
    const length = data[offset];
    offset += 1;

    return .{
        .repr = .{
            .id = @enumFromInt(eid),
            .next_header = next_header,
            .length = length,
        },
        .consumed = offset,
    };
}

pub fn emitExtHeaderNhc(repr: ExtHeaderNhcRepr, buf: []u8) error{BufferTooSmall}!usize {
    const needed = extHeaderNhcBufLen(repr);
    if (buf.len < needed) return error.BufferTooSmall;

    const nh_bit: u1 = switch (repr.next_header) {
        .compressed => 1,
        .uncompressed => 0,
    };

    buf[0] = (@as(u8, DISPATCH_EXT_NHC) << 4) | (@as(u8, @intFromEnum(repr.id)) << 1) | nh_bit;

    var offset: usize = 1;

    switch (repr.next_header) {
        .uncompressed => |proto| {
            buf[offset] = @intFromEnum(proto);
            offset += 1;
        },
        .compressed => {},
    }

    buf[offset] = repr.length;
    offset += 1;

    return offset;
}

pub fn extHeaderNhcBufLen(repr: ExtHeaderNhcRepr) usize {
    var len: usize = 1; // dispatch byte
    len += switch (repr.next_header) {
        .compressed => @as(usize, 0),
        .uncompressed => @as(usize, 1),
    };
    len += 1; // length byte
    return len;
}

// -------------------------------------------------------------------------
// NHC: UDP Compression
// -------------------------------------------------------------------------

pub const UdpNhcRepr = struct {
    src_port: u16,
    dst_port: u16,
    checksum: ?u16,
};

pub fn parseUdpNhc(data: []const u8) error{ Truncated, Malformed }!struct { repr: UdpNhcRepr, consumed: usize } {
    if (data.len < 1) return error.Truncated;

    // Validate dispatch (top 5 bits = 0b11110)
    if (data[0] >> 3 != DISPATCH_UDP_NHC) return error.Malformed;

    const c_bit: u1 = @truncate((data[0] >> 2) & 1);
    const p_bits: u2 = @truncate(data[0] & 0b11);

    var offset: usize = 1;

    var src_port: u16 = undefined;
    var dst_port: u16 = undefined;

    switch (p_bits) {
        0b00 => {
            if (offset + 4 > data.len) return error.Truncated;
            src_port = readU16(data[offset..][0..2]);
            dst_port = readU16(data[offset + 2 ..][0..2]);
            offset += 4;
        },
        0b01 => {
            // src 16-bit inline, dst 8-bit (0xf000 + byte)
            if (offset + 3 > data.len) return error.Truncated;
            src_port = readU16(data[offset..][0..2]);
            dst_port = 0xf000 + @as(u16, data[offset + 2]);
            offset += 3;
        },
        0b10 => {
            // src 8-bit (0xf000 + byte), dst 16-bit inline
            if (offset + 3 > data.len) return error.Truncated;
            src_port = 0xf000 + @as(u16, data[offset]);
            dst_port = readU16(data[offset + 1 ..][0..2]);
            offset += 3;
        },
        0b11 => {
            // Both 4-bit: src = 0xf0b0 + hi nibble, dst = 0xf0b0 + lo nibble
            if (offset + 1 > data.len) return error.Truncated;
            src_port = 0xf0b0 + @as(u16, data[offset] >> 4);
            dst_port = 0xf0b0 + @as(u16, data[offset] & 0x0f);
            offset += 1;
        },
    }

    var chksum: ?u16 = null;
    if (c_bit == 0) {
        if (offset + 2 > data.len) return error.Truncated;
        chksum = readU16(data[offset..][0..2]);
        offset += 2;
    }

    return .{
        .repr = .{
            .src_port = src_port,
            .dst_port = dst_port,
            .checksum = chksum,
        },
        .consumed = offset,
    };
}

fn udpPortCompression(src_port: u16, dst_port: u16) struct { p: u2, size: usize } {
    if (src_port >= 0xf0b0 and src_port <= 0xf0bf and
        dst_port >= 0xf0b0 and dst_port <= 0xf0bf)
    {
        return .{ .p = 0b11, .size = 1 };
    }
    if (src_port >= 0xf000 and src_port <= 0xf0ff) {
        return .{ .p = 0b10, .size = 3 };
    }
    if (dst_port >= 0xf000 and dst_port <= 0xf0ff) {
        return .{ .p = 0b01, .size = 3 };
    }
    return .{ .p = 0b00, .size = 4 };
}

pub fn emitUdpNhc(repr: UdpNhcRepr, buf: []u8) error{BufferTooSmall}!usize {
    const needed = udpNhcBufLen(repr);
    if (buf.len < needed) return error.BufferTooSmall;

    const pc = udpPortCompression(repr.src_port, repr.dst_port);

    const c_bit: u1 = if (repr.checksum == null) 1 else 0;

    buf[0] = (@as(u8, DISPATCH_UDP_NHC) << 3) | (@as(u8, c_bit) << 2) | @as(u8, pc.p);

    var offset: usize = 1;

    switch (pc.p) {
        0b00 => {
            writeU16(buf[offset..][0..2], repr.src_port);
            writeU16(buf[offset + 2 ..][0..2], repr.dst_port);
            offset += 4;
        },
        0b01 => {
            writeU16(buf[offset..][0..2], repr.src_port);
            buf[offset + 2] = @truncate(repr.dst_port - 0xf000);
            offset += 3;
        },
        0b10 => {
            buf[offset] = @truncate(repr.src_port - 0xf000);
            writeU16(buf[offset + 1 ..][0..2], repr.dst_port);
            offset += 3;
        },
        0b11 => {
            const src_nibble: u8 = @truncate(repr.src_port - 0xf0b0);
            const dst_nibble: u8 = @truncate(repr.dst_port - 0xf0b0);
            buf[offset] = (src_nibble << 4) | dst_nibble;
            offset += 1;
        },
    }

    if (repr.checksum) |cksum| {
        writeU16(buf[offset..][0..2], cksum);
        offset += 2;
    }

    return offset;
}

pub fn udpNhcBufLen(repr: UdpNhcRepr) usize {
    var len: usize = 1; // dispatch byte
    len += udpPortCompression(repr.src_port, repr.dst_port).size;
    if (repr.checksum != null) len += 2;
    return len;
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

fn eql16(a: [16]u8, b: [16]u8) bool {
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn eql8(a: [8]u8, b: [8]u8) bool {
    for (a, b) |x, y| {
        if (x != y) return false;
    }
    return true;
}

fn allZero(slice: []const u8) bool {
    for (slice) |b| {
        if (b != 0) return false;
    }
    return true;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

fn extAddr(bytes: [8]u8) ieee802154.Address {
    return .{ .extended = bytes };
}

fn shortAddr(bytes: [2]u8) ieee802154.Address {
    return .{ .short = bytes };
}

// [smoltcp:sixlowpan/iphc.rs:iphc_fields - test vector 1]
test "IPHC parse: TF=11 NH=uncompressed HLIM=64 SAM=11 DAM=11" {
    const src_ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 });
    const dst_ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf });
    const data = [_]u8{ 0x7a, 0x33, 0x3a };
    const result = try parseIphc(&data, src_ll, dst_ll, &.{});
    const repr = result.repr;

    try testing.expectEqual(@as(u8, 64), repr.hop_limit);

    switch (repr.next_header) {
        .uncompressed => |p| try testing.expectEqual(ipv6.Protocol.icmpv6, p),
        .compressed => return error.TestUnexpectedResult,
    }

    // Source: fe80:: + EUI-64 of extended LL addr
    const expected_src = src_ll.asLinkLocalAddress();
    try testing.expectEqualSlices(u8, &expected_src, &repr.src_addr);

    // Destination: fe80:: + EUI-64 of extended LL addr
    const expected_dst = dst_ll.asLinkLocalAddress();
    try testing.expectEqualSlices(u8, &expected_dst, &repr.dst_addr);

    try testing.expectEqual(@as(usize, 3), result.consumed);
}

// [smoltcp:sixlowpan/iphc.rs:iphc_fields - test vector 2]
test "IPHC parse: NH=compressed CID=1 SAC=1 DAC=1 both fully elided with context" {
    const src_ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 });
    const dst_ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf });
    const ctx = [_]AddressContext{.{ 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00 }};
    const data = [_]u8{ 0x7e, 0xf7, 0x00 };
    const result = try parseIphc(&data, src_ll, dst_ll, &ctx);
    const repr = result.repr;

    try testing.expectEqual(@as(u8, 64), repr.hop_limit);

    switch (repr.next_header) {
        .compressed => {},
        .uncompressed => return error.TestUnexpectedResult,
    }

    // Both addresses: context[0..8] + IID from EUI-64
    const src_eui = src_ll.asEui64();
    var expected_src: [16]u8 = undefined;
    @memcpy(expected_src[0..8], &ctx[0]);
    @memcpy(expected_src[8..16], &src_eui);
    try testing.expectEqualSlices(u8, &expected_src, &repr.src_addr);

    const dst_eui = dst_ll.asEui64();
    var expected_dst: [16]u8 = undefined;
    @memcpy(expected_dst[0..8], &ctx[0]);
    @memcpy(expected_dst[8..16], &dst_eui);
    try testing.expectEqualSlices(u8, &expected_dst, &repr.dst_addr);
}

test "address resolution: fully elided from extended LL" {
    const ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 });
    var offset: usize = 0;
    const addr = try resolveSourceAddress(&[_]u8{}, &offset, 0, 0b11, ll, null, &.{});
    const expected = ll.asLinkLocalAddress();
    try testing.expectEqualSlices(u8, &expected, &addr);
    try testing.expectEqual(@as(usize, 0), offset);
}

test "address resolution: fully elided from short LL" {
    const ll = shortAddr(.{ 0xab, 0xcd });
    var offset: usize = 0;
    const addr = try resolveSourceAddress(&[_]u8{}, &offset, 0, 0b11, ll, null, &.{});
    try testing.expectEqual(@as(u8, 0xfe), addr[0]);
    try testing.expectEqual(@as(u8, 0x80), addr[1]);
    // bytes 2..8 zero
    for (addr[2..8]) |b| try testing.expectEqual(@as(u8, 0), b);
    // IID: 00:00:00:ff:fe:00:ab:cd
    try testing.expectEqual(@as(u8, 0x00), addr[8]);
    try testing.expectEqual(@as(u8, 0x00), addr[9]);
    try testing.expectEqual(@as(u8, 0x00), addr[10]);
    try testing.expectEqual(@as(u8, 0xff), addr[11]);
    try testing.expectEqual(@as(u8, 0xfe), addr[12]);
    try testing.expectEqual(@as(u8, 0x00), addr[13]);
    try testing.expectEqual(@as(u8, 0xab), addr[14]);
    try testing.expectEqual(@as(u8, 0xcd), addr[15]);
}

test "address resolution: 16-bit inline" {
    const ll: ieee802154.Address = .absent;
    const inline_data = [_]u8{ 0xab, 0xcd };
    var offset: usize = 0;
    const addr = try resolveSourceAddress(&inline_data, &offset, 0, 0b10, ll, null, &.{});
    try testing.expectEqual(@as(u8, 0xfe), addr[0]);
    try testing.expectEqual(@as(u8, 0x80), addr[1]);
    try testing.expectEqual(@as(u8, 0xff), addr[11]);
    try testing.expectEqual(@as(u8, 0xfe), addr[12]);
    try testing.expectEqual(@as(u8, 0xab), addr[14]);
    try testing.expectEqual(@as(u8, 0xcd), addr[15]);
    try testing.expectEqual(@as(usize, 2), offset);
}

test "address resolution: 64-bit inline" {
    const ll: ieee802154.Address = .absent;
    const inline_data = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    var offset: usize = 0;
    const addr = try resolveSourceAddress(&inline_data, &offset, 0, 0b01, ll, null, &.{});
    try testing.expectEqual(@as(u8, 0xfe), addr[0]);
    try testing.expectEqual(@as(u8, 0x80), addr[1]);
    try testing.expectEqualSlices(u8, &inline_data, addr[8..16]);
    try testing.expectEqual(@as(usize, 8), offset);
}

test "address resolution: unspecified (SAC=1 SAM=00)" {
    const ll: ieee802154.Address = .absent;
    var offset: usize = 0;
    const addr = try resolveSourceAddress(&[_]u8{}, &offset, 1, 0b00, ll, null, &.{});
    try testing.expectEqualSlices(u8, &ipv6.UNSPECIFIED, &addr);
}

test "multicast address decompression: 8-bit (ff02::XX)" {
    const ll: ieee802154.Address = .absent;
    const inline_data = [_]u8{0x42};
    var offset: usize = 0;
    const addr = try resolveDestAddress(&inline_data, &offset, 1, 0, 0b11, ll, null, &.{});
    try testing.expectEqual(@as(u8, 0xff), addr[0]);
    try testing.expectEqual(@as(u8, 0x02), addr[1]);
    for (addr[2..15]) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expectEqual(@as(u8, 0x42), addr[15]);
}

test "multicast address decompression: 32-bit (ffXX::00XX:XXXX)" {
    const ll: ieee802154.Address = .absent;
    const inline_data = [_]u8{ 0x05, 0xAA, 0xBB, 0xCC };
    var offset: usize = 0;
    const addr = try resolveDestAddress(&inline_data, &offset, 1, 0, 0b10, ll, null, &.{});
    try testing.expectEqual(@as(u8, 0xff), addr[0]);
    try testing.expectEqual(@as(u8, 0x05), addr[1]);
    for (addr[2..13]) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expectEqual(@as(u8, 0xAA), addr[13]);
    try testing.expectEqual(@as(u8, 0xBB), addr[14]);
    try testing.expectEqual(@as(u8, 0xCC), addr[15]);
}

test "multicast address decompression: 48-bit (ffXX::00XX:XXXX:XXXX)" {
    const ll: ieee802154.Address = .absent;
    const inline_data = [_]u8{ 0x05, 0x11, 0x22, 0x33, 0x44, 0x55 };
    var offset: usize = 0;
    const addr = try resolveDestAddress(&inline_data, &offset, 1, 0, 0b01, ll, null, &.{});
    try testing.expectEqual(@as(u8, 0xff), addr[0]);
    try testing.expectEqual(@as(u8, 0x05), addr[1]);
    for (addr[2..11]) |b| try testing.expectEqual(@as(u8, 0), b);
    try testing.expectEqual(@as(u8, 0x11), addr[11]);
    try testing.expectEqual(@as(u8, 0x22), addr[12]);
    try testing.expectEqual(@as(u8, 0x33), addr[13]);
    try testing.expectEqual(@as(u8, 0x44), addr[14]);
    try testing.expectEqual(@as(u8, 0x55), addr[15]);
}

test "IPHC emit/parse roundtrip: link-local fully elided" {
    const src_ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 });
    const dst_ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf });

    const repr = IphcRepr{
        .src_addr = src_ll.asLinkLocalAddress(),
        .dst_addr = dst_ll.asLinkLocalAddress(),
        .next_header = .{ .uncompressed = .icmpv6 },
        .hop_limit = 64,
    };

    var buf: [128]u8 = undefined;
    const emitted = try emitIphc(repr, src_ll, dst_ll, &buf);

    const result = try parseIphc(buf[0..emitted], src_ll, dst_ll, &.{});
    try testing.expectEqualSlices(u8, &repr.src_addr, &result.repr.src_addr);
    try testing.expectEqualSlices(u8, &repr.dst_addr, &result.repr.dst_addr);
    try testing.expectEqual(@as(u8, 64), result.repr.hop_limit);

    switch (result.repr.next_header) {
        .uncompressed => |p| try testing.expectEqual(ipv6.Protocol.icmpv6, p),
        .compressed => return error.TestUnexpectedResult,
    }
}

test "IPHC emit/parse roundtrip: global addresses (16-byte inline)" {
    const src_ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 });
    const dst_ll = extAddr(.{ 0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf });

    const repr = IphcRepr{
        .src_addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .dst_addr = .{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 },
        .next_header = .{ .uncompressed = .udp },
        .hop_limit = 255,
    };

    var buf: [128]u8 = undefined;
    const emitted = try emitIphc(repr, src_ll, dst_ll, &buf);
    try testing.expectEqual(iphcBufferLen(repr, src_ll, dst_ll), emitted);

    const result = try parseIphc(buf[0..emitted], src_ll, dst_ll, &.{});
    try testing.expectEqualSlices(u8, &repr.src_addr, &result.repr.src_addr);
    try testing.expectEqualSlices(u8, &repr.dst_addr, &result.repr.dst_addr);
    try testing.expectEqual(@as(u8, 255), result.repr.hop_limit);
}

// [smoltcp:sixlowpan/nhc.rs:ext_header_nh_inlined]
test "NHC ext header parse: routing header, NH inline ICMPv6" {
    const data = [_]u8{ 0xe2, 0x3a, 0x06, 0x03, 0x00, 0xff, 0x00, 0x00, 0x00 };
    const result = try parseExtHeaderNhc(&data);
    try testing.expectEqual(ExtHeaderId.routing, result.repr.id);
    try testing.expectEqual(@as(u8, 6), result.repr.length);

    switch (result.repr.next_header) {
        .uncompressed => |p| try testing.expectEqual(ipv6.Protocol.icmpv6, p),
        .compressed => return error.TestUnexpectedResult,
    }

    try testing.expectEqual(@as(usize, 3), result.consumed);
}

// [smoltcp:sixlowpan/nhc.rs:ext_header_nh_elided]
test "NHC ext header parse: routing header, NH compressed" {
    const data = [_]u8{ 0xe3, 0x06, 0x03, 0x00, 0xff, 0x00, 0x00, 0x00 };
    const result = try parseExtHeaderNhc(&data);
    try testing.expectEqual(ExtHeaderId.routing, result.repr.id);
    try testing.expectEqual(@as(u8, 6), result.repr.length);

    switch (result.repr.next_header) {
        .compressed => {},
        .uncompressed => return error.TestUnexpectedResult,
    }

    try testing.expectEqual(@as(usize, 2), result.consumed);
}

test "NHC ext header emit roundtrip" {
    const repr = ExtHeaderNhcRepr{
        .id = .routing,
        .next_header = .compressed,
        .length = 6,
    };

    var buf: [16]u8 = undefined;
    const emitted = try emitExtHeaderNhc(repr, &buf);
    try testing.expectEqual(extHeaderNhcBufLen(repr), emitted);

    const result = try parseExtHeaderNhc(buf[0..emitted]);
    try testing.expectEqual(repr.id, result.repr.id);
    try testing.expectEqual(repr.length, result.repr.length);

    switch (result.repr.next_header) {
        .compressed => {},
        .uncompressed => return error.TestUnexpectedResult,
    }
}

// [smoltcp:sixlowpan/nhc.rs:udp_nhc_fields]
test "UDP NHC parse: P=00 full ports with checksum" {
    const data = [_]u8{ 0xf0, 0x16, 0x2e, 0x22, 0x3d, 0x28, 0xc4 };
    const result = try parseUdpNhc(&data);
    try testing.expectEqual(@as(u16, 5678), result.repr.src_port);
    try testing.expectEqual(@as(u16, 8765), result.repr.dst_port);
    try testing.expectEqual(@as(?u16, 0x28c4), result.repr.checksum);
    try testing.expectEqual(@as(usize, 7), result.consumed);
}

test "UDP NHC: P=11 (4-bit ports)" {
    // src = 0xf0b1, dst = 0xf0b2 -> nibbles 1,2 -> byte 0x12
    const src_port: u16 = 0xf0b1;
    const dst_port: u16 = 0xf0b2;
    const repr = UdpNhcRepr{
        .src_port = src_port,
        .dst_port = dst_port,
        .checksum = 0x1234,
    };

    var buf: [16]u8 = undefined;
    const emitted = try emitUdpNhc(repr, &buf);

    // Verify P=11 in dispatch byte
    try testing.expectEqual(@as(u2, 0b11), @as(u2, @truncate(buf[0] & 0b11)));

    const result = try parseUdpNhc(buf[0..emitted]);
    try testing.expectEqual(src_port, result.repr.src_port);
    try testing.expectEqual(dst_port, result.repr.dst_port);
    try testing.expectEqual(@as(?u16, 0x1234), result.repr.checksum);
}

test "UDP NHC emit/parse roundtrip" {
    const repr = UdpNhcRepr{
        .src_port = 5678,
        .dst_port = 8765,
        .checksum = 0xabcd,
    };

    var buf: [16]u8 = undefined;
    const emitted = try emitUdpNhc(repr, &buf);
    try testing.expectEqual(udpNhcBufLen(repr), emitted);

    const result = try parseUdpNhc(buf[0..emitted]);
    try testing.expectEqual(repr.src_port, result.repr.src_port);
    try testing.expectEqual(repr.dst_port, result.repr.dst_port);
    try testing.expectEqual(repr.checksum, result.repr.checksum);
}

test "dispatch type detection" {
    // IPHC: top 3 bits = 011 -> byte starts with 0x60..0x7f
    try testing.expectEqual(DispatchType.iphc, dispatchType(0x7a));
    try testing.expectEqual(DispatchType.iphc, dispatchType(0x60));

    // First fragment: top 5 bits = 11000 -> 0xc0..0xc7
    try testing.expectEqual(DispatchType.first_fragment, dispatchType(0xc0));
    try testing.expectEqual(DispatchType.first_fragment, dispatchType(0xc7));

    // Next fragment: top 5 bits = 11100 -> 0xe0..0xe7
    try testing.expectEqual(DispatchType.next_fragment, dispatchType(0xe0));
    try testing.expectEqual(DispatchType.next_fragment, dispatchType(0xe7));

    // Unknown
    try testing.expectEqual(DispatchType.unknown, dispatchType(0x00));
    try testing.expectEqual(DispatchType.unknown, dispatchType(0x40));
}

test "UDP NHC with elided checksum" {
    const repr = UdpNhcRepr{
        .src_port = 5678,
        .dst_port = 8765,
        .checksum = null,
    };

    var buf: [16]u8 = undefined;
    const emitted = try emitUdpNhc(repr, &buf);

    // C bit should be set
    try testing.expectEqual(@as(u1, 1), @as(u1, @truncate((buf[0] >> 2) & 1)));

    const result = try parseUdpNhc(buf[0..emitted]);
    try testing.expectEqual(repr.src_port, result.repr.src_port);
    try testing.expectEqual(repr.dst_port, result.repr.dst_port);
    try testing.expectEqual(@as(?u16, null), result.repr.checksum);

    // Without checksum should be 2 bytes smaller
    const with_cksum = UdpNhcRepr{
        .src_port = 5678,
        .dst_port = 8765,
        .checksum = 0x1234,
    };
    try testing.expectEqual(udpNhcBufLen(with_cksum), udpNhcBufLen(repr) + 2);
}
