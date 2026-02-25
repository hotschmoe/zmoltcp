// ICMPv6 message parsing and serialization.
//
// Reference: RFC 4443, smoltcp src/wire/icmpv6.rs

const ipv6 = @import("ipv6.zig");
const ndisc = @import("ndisc.zig");
const mld = @import("mld.zig");
const checksum = @import("checksum.zig");

const readU16 = checksum.readU16;
const readU32 = checksum.readU32;
const writeU16 = checksum.writeU16;
const writeU32 = checksum.writeU32;

pub const HEADER_LEN: usize = 4;
pub const MAX_ERROR_PACKET_LEN: usize = ipv6.MIN_MTU - ipv6.HEADER_LEN;

pub const Message = enum(u8) {
    dst_unreachable = 1,
    pkt_too_big = 2,
    time_exceeded = 3,
    param_problem = 4,
    echo_request = 0x80,
    echo_reply = 0x81,
    mld_query = 0x82,
    router_solicit = 0x85,
    router_advert = 0x86,
    neighbor_solicit = 0x87,
    neighbor_advert = 0x88,
    redirect = 0x89,
    mld_report = 0x8F,
    _,
};

pub const DstUnreachable = enum(u8) {
    no_route = 0,
    admin_prohibit = 1,
    beyond_scope = 2,
    addr_unreachable = 3,
    port_unreachable = 4,
    failed_policy = 5,
    reject_route = 6,
    _,
};

pub const TimeExceeded = enum(u8) {
    hop_limit_exceeded = 0,
    frag_reassem_exceeded = 1,
    _,
};

pub const ParamProblem = enum(u8) {
    erroneous_hdr_field = 0,
    unrecognized_nxt_hdr = 1,
    unrecognized_option = 2,
    _,
};

pub const Repr = union(enum) {
    dst_unreachable: struct {
        reason: DstUnreachable,
        header: ipv6.Repr,
        data: []const u8,
    },
    pkt_too_big: struct {
        mtu: u32,
        header: ipv6.Repr,
        data: []const u8,
    },
    time_exceeded: struct {
        reason: TimeExceeded,
        header: ipv6.Repr,
        data: []const u8,
    },
    param_problem: struct {
        reason: ParamProblem,
        pointer: u32,
        header: ipv6.Repr,
        data: []const u8,
    },
    echo_request: struct {
        ident: u16,
        seq_no: u16,
        data: []const u8,
    },
    echo_reply: struct {
        ident: u16,
        seq_no: u16,
        data: []const u8,
    },
    ndisc: ndisc.Repr,
    mld: mld.Repr,
};

pub fn bufferLen(repr: Repr) usize {
    const base: usize = HEADER_LEN;
    return base + switch (repr) {
        .echo_request => |e| 4 + e.data.len,
        .echo_reply => |e| 4 + e.data.len,
        .dst_unreachable => |d| clampError(4 + ipv6.HEADER_LEN + d.data.len),
        .pkt_too_big => |p| clampError(4 + ipv6.HEADER_LEN + p.data.len),
        .time_exceeded => |t| clampError(4 + ipv6.HEADER_LEN + t.data.len),
        .param_problem => |pp| clampError(4 + ipv6.HEADER_LEN + pp.data.len),
        .ndisc => |n| ndisc.bufferLen(n),
        .mld => |m| mld.bufferLen(m),
    };
}

fn clampError(body_len: usize) usize {
    return @min(body_len, MAX_ERROR_PACKET_LEN - HEADER_LEN);
}

/// Parse an ICMPv6 message. Verifies checksum via pseudo-header.
pub fn parse(
    data: []const u8,
    src_addr: ipv6.Address,
    dst_addr: ipv6.Address,
) error{ Truncated, BadVersion, BadLength, BadChecksum, Unrecognized }!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;

    if (!verifyChecksum(data, src_addr, dst_addr)) return error.BadChecksum;

    const msg_type: Message = @enumFromInt(data[0]);
    const body = data[HEADER_LEN..];

    switch (msg_type) {
        .echo_request => {
            if (body.len < 4) return error.Truncated;
            return .{ .echo_request = .{
                .ident = readU16(body[0..2]),
                .seq_no = readU16(body[2..4]),
                .data = body[4..],
            } };
        },
        .echo_reply => {
            if (body.len < 4) return error.Truncated;
            return .{ .echo_reply = .{
                .ident = readU16(body[0..2]),
                .seq_no = readU16(body[2..4]),
                .data = body[4..],
            } };
        },
        .dst_unreachable => {
            if (body.len < 4 + ipv6.HEADER_LEN) return error.Truncated;
            const inner = ipv6.parse(body[4..]) catch return error.BadVersion;
            return .{ .dst_unreachable = .{
                .reason = @enumFromInt(data[1]),
                .header = inner,
                .data = body[4 + ipv6.HEADER_LEN ..],
            } };
        },
        .pkt_too_big => {
            if (body.len < 4 + ipv6.HEADER_LEN) return error.Truncated;
            const inner = ipv6.parse(body[4..]) catch return error.BadVersion;
            return .{ .pkt_too_big = .{
                .mtu = readU32(body[0..4]),
                .header = inner,
                .data = body[4 + ipv6.HEADER_LEN ..],
            } };
        },
        .time_exceeded => {
            if (body.len < 4 + ipv6.HEADER_LEN) return error.Truncated;
            const inner = ipv6.parse(body[4..]) catch return error.BadVersion;
            return .{ .time_exceeded = .{
                .reason = @enumFromInt(data[1]),
                .header = inner,
                .data = body[4 + ipv6.HEADER_LEN ..],
            } };
        },
        .param_problem => {
            if (body.len < 4 + ipv6.HEADER_LEN) return error.Truncated;
            const inner = ipv6.parse(body[4..]) catch return error.BadVersion;
            return .{ .param_problem = .{
                .reason = @enumFromInt(data[1]),
                .pointer = readU32(body[0..4]),
                .header = inner,
                .data = body[4 + ipv6.HEADER_LEN ..],
            } };
        },
        .router_solicit, .router_advert, .neighbor_solicit, .neighbor_advert, .redirect => {
            return .{ .ndisc = try ndisc.parse(@intFromEnum(msg_type), body) };
        },
        .mld_query, .mld_report => {
            return .{ .mld = try mld.parse(@intFromEnum(msg_type), body) };
        },
        _ => return error.Unrecognized,
    }
}

/// Emit an ICMPv6 message. Fills in pseudo-header checksum.
pub fn emit(
    repr: Repr,
    src_addr: ipv6.Address,
    dst_addr: ipv6.Address,
    buf: []u8,
) error{BufferTooSmall}!usize {
    const len = bufferLen(repr);
    if (buf.len < len) return error.BufferTooSmall;

    // Type and code
    switch (repr) {
        .echo_request => {
            buf[0] = @intFromEnum(Message.echo_request);
            buf[1] = 0;
        },
        .echo_reply => {
            buf[0] = @intFromEnum(Message.echo_reply);
            buf[1] = 0;
        },
        .dst_unreachable => |d| {
            buf[0] = @intFromEnum(Message.dst_unreachable);
            buf[1] = @intFromEnum(d.reason);
        },
        .pkt_too_big => {
            buf[0] = @intFromEnum(Message.pkt_too_big);
            buf[1] = 0;
        },
        .time_exceeded => |t| {
            buf[0] = @intFromEnum(Message.time_exceeded);
            buf[1] = @intFromEnum(t.reason);
        },
        .param_problem => |pp| {
            buf[0] = @intFromEnum(Message.param_problem);
            buf[1] = @intFromEnum(pp.reason);
        },
        .ndisc => |n| {
            buf[0] = switch (n) {
                .router_solicit => ndisc.ROUTER_SOLICIT,
                .router_advert => ndisc.ROUTER_ADVERT,
                .neighbor_solicit => ndisc.NEIGHBOR_SOLICIT,
                .neighbor_advert => ndisc.NEIGHBOR_ADVERT,
                .redirect => ndisc.REDIRECT,
            };
            buf[1] = 0;
        },
        .mld => |m| {
            buf[0] = switch (m) {
                .query => @intFromEnum(Message.mld_query),
                .report => @intFromEnum(Message.mld_report),
            };
            buf[1] = 0;
        },
    }

    // Body (after the 4-byte ICMPv6 header)
    const body = buf[HEADER_LEN..len];
    switch (repr) {
        .echo_request => |e| {
            writeU16(body[0..2], e.ident);
            writeU16(body[2..4], e.seq_no);
            @memcpy(body[4 .. 4 + e.data.len], e.data);
        },
        .echo_reply => |e| {
            writeU16(body[0..2], e.ident);
            writeU16(body[2..4], e.seq_no);
            @memcpy(body[4 .. 4 + e.data.len], e.data);
        },
        .dst_unreachable => |d| {
            @memset(body[0..4], 0);
            try emitErrorBody(body, d.header, d.data, len);
        },
        .pkt_too_big => |p| {
            writeU32(body[0..4], p.mtu);
            try emitErrorBody(body, p.header, p.data, len);
        },
        .time_exceeded => |t| {
            @memset(body[0..4], 0);
            try emitErrorBody(body, t.header, t.data, len);
        },
        .param_problem => |pp| {
            writeU32(body[0..4], pp.pointer);
            try emitErrorBody(body, pp.header, pp.data, len);
        },
        .ndisc => |n| {
            _ = ndisc.emit(n, body) catch return error.BufferTooSmall;
        },
        .mld => |m| {
            _ = mld.emit(m, body) catch return error.BufferTooSmall;
        },
    }

    // Compute and fill checksum
    fillChecksum(buf[0..len], src_addr, dst_addr);
    return len;
}

pub fn verifyChecksum(data: []const u8, src_addr: ipv6.Address, dst_addr: ipv6.Address) bool {
    const pseudo = checksum.pseudoHeaderChecksumV6(
        src_addr,
        dst_addr,
        @intFromEnum(ipv6.Protocol.icmpv6),
        @intCast(data.len),
    );
    return checksum.finish(checksum.calculate(data, pseudo)) == 0;
}

fn emitErrorBody(body: []u8, header: ipv6.Repr, data: []const u8, total_len: usize) error{BufferTooSmall}!void {
    _ = ipv6.emit(header, body[4..]) catch return error.BufferTooSmall;
    const data_len = @min(data.len, total_len - HEADER_LEN - 4 - ipv6.HEADER_LEN);
    @memcpy(body[4 + ipv6.HEADER_LEN .. 4 + ipv6.HEADER_LEN + data_len], data[0..data_len]);
}

fn fillChecksum(data: []u8, src_addr: ipv6.Address, dst_addr: ipv6.Address) void {
    data[2] = 0;
    data[3] = 0;
    const pseudo = checksum.pseudoHeaderChecksumV6(
        src_addr,
        dst_addr,
        @intFromEnum(ipv6.Protocol.icmpv6),
        @intCast(data.len),
    );
    const cksum = checksum.finish(checksum.calculate(data, pseudo));
    data[2] = @truncate(cksum >> 8);
    data[3] = @truncate(cksum);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

const SRC_ADDR = ipv6.Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const DST_ADDR = ipv6.Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

test "echo request parse" {
    // Build a valid echo request with correct checksum
    const repr: Repr = .{ .echo_request = .{
        .ident = 0x1234,
        .seq_no = 0xABCD,
        .data = &[_]u8{ 0xAA, 0x00, 0x00, 0xFF },
    } };
    var buf: [12]u8 = undefined;
    _ = try emit(repr, SRC_ADDR, DST_ADDR, &buf);

    const parsed = try parse(&buf, SRC_ADDR, DST_ADDR);
    try testing.expectEqual(@as(u16, 0x1234), parsed.echo_request.ident);
    try testing.expectEqual(@as(u16, 0xABCD), parsed.echo_request.seq_no);
    try testing.expectEqual(@as(usize, 4), parsed.echo_request.data.len);
}

test "echo reply roundtrip" {
    const repr: Repr = .{ .echo_reply = .{
        .ident = 0x5678,
        .seq_no = 0x0001,
        .data = &[_]u8{ 0xDE, 0xAD },
    } };
    var buf: [10]u8 = undefined;
    _ = try emit(repr, SRC_ADDR, DST_ADDR, &buf);

    const parsed = try parse(&buf, SRC_ADDR, DST_ADDR);
    try testing.expectEqual(@as(u16, 0x5678), parsed.echo_reply.ident);
    try testing.expectEqual(@as(u16, 0x0001), parsed.echo_reply.seq_no);
}

test "bad checksum rejected" {
    var buf = [_]u8{
        0x80, 0x00, 0x00, 0x00, // type=echo_request, code=0, bad checksum
        0x12, 0x34, 0xAB, 0xCD,
    };
    try testing.expectError(error.BadChecksum, parse(&buf, SRC_ADDR, DST_ADDR));
}

test "pkt_too_big roundtrip" {
    const inner_header: ipv6.Repr = .{
        .src_addr = SRC_ADDR,
        .dst_addr = DST_ADDR,
        .next_header = .udp,
        .payload_len = 12,
        .hop_limit = 64,
    };
    const payload = [_]u8{ 0xBF, 0x00, 0x00, 0x35, 0x00, 0x0C, 0x12, 0x4D, 0xAA, 0x00, 0x00, 0xFF };

    const repr: Repr = .{ .pkt_too_big = .{
        .mtu = 1500,
        .header = inner_header,
        .data = &payload,
    } };
    var buf: [60]u8 = undefined;
    const len = try emit(repr, SRC_ADDR, DST_ADDR, &buf);
    try testing.expectEqual(@as(usize, 60), len);

    const parsed = try parse(buf[0..len], SRC_ADDR, DST_ADDR);
    try testing.expectEqual(@as(u32, 1500), parsed.pkt_too_big.mtu);
    try testing.expectEqual(ipv6.Protocol.udp, parsed.pkt_too_big.header.next_header);
}

test "dst_unreachable roundtrip" {
    const inner_header: ipv6.Repr = .{
        .src_addr = SRC_ADDR,
        .dst_addr = DST_ADDR,
        .next_header = .tcp,
        .payload_len = 0,
        .hop_limit = 64,
    };
    const repr: Repr = .{ .dst_unreachable = .{
        .reason = .port_unreachable,
        .header = inner_header,
        .data = &[_]u8{},
    } };
    var buf: [48]u8 = undefined;
    const len = try emit(repr, SRC_ADDR, DST_ADDR, &buf);
    const parsed = try parse(buf[0..len], SRC_ADDR, DST_ADDR);
    try testing.expectEqual(DstUnreachable.port_unreachable, parsed.dst_unreachable.reason);
}

test "ndisc via icmpv6" {
    // Router advert through ICMPv6 emit/parse
    const nd = ndisc.Repr{ .router_solicit = .{ .lladdr = null } };
    const repr: Repr = .{ .ndisc = nd };
    var buf: [8]u8 = undefined;
    const len = try emit(repr, SRC_ADDR, DST_ADDR, &buf);
    const parsed = try parse(buf[0..len], SRC_ADDR, DST_ADDR);
    try testing.expect(parsed.ndisc == .router_solicit);
}

test "mld query via icmpv6" {
    const m = mld.Repr{ .query = .{
        .max_resp_code = 0x0400,
        .mcast_addr = ipv6.LINK_LOCAL_ALL_NODES,
        .s_flag = true,
        .qrv = 2,
        .qqic = 0x12,
        .num_srcs = 0,
    } };
    const repr: Repr = .{ .mld = m };
    var buf: [28]u8 = undefined;
    const len = try emit(repr, SRC_ADDR, DST_ADDR, &buf);
    const parsed = try parse(buf[0..len], SRC_ADDR, DST_ADDR);
    try testing.expectEqual(@as(u16, 0x0400), parsed.mld.query.max_resp_code);
    try testing.expect(parsed.mld.query.s_flag);
    try testing.expectEqual(@as(u8, 2), parsed.mld.query.qrv);
}

test "truncated message" {
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0x80, 0x00 }, SRC_ADDR, DST_ADDR));
}

test "verifyChecksum" {
    const repr: Repr = .{ .echo_request = .{
        .ident = 1,
        .seq_no = 2,
        .data = &[_]u8{},
    } };
    var buf: [8]u8 = undefined;
    _ = try emit(repr, SRC_ADDR, DST_ADDR, &buf);
    try testing.expect(verifyChecksum(&buf, SRC_ADDR, DST_ADDR));
    buf[4] ^= 0xFF; // corrupt
    try testing.expect(!verifyChecksum(&buf, SRC_ADDR, DST_ADDR));
}
