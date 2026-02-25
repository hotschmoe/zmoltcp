// MLDv2 (Multicast Listener Discovery v2) parsing and serialization.
//
// Reference: RFC 3810, smoltcp src/wire/mld.rs
//
// MLD messages are carried inside ICMPv6. The data parameter to parse/emit
// starts at byte 4 of the ICMPv6 message (after type+code+checksum).

const ipv6 = @import("ipv6.zig");

pub const RecordType = enum(u8) {
    mode_is_include = 1,
    mode_is_exclude = 2,
    change_to_include = 3,
    change_to_exclude = 4,
    allow_new_sources = 5,
    block_old_sources = 6,
    _,
};

pub const AddressRecordRepr = struct {
    record_type: RecordType,
    aux_data_len: u8,
    num_srcs: u16,
    mcast_addr: ipv6.Address,
};

pub const Repr = union(enum) {
    query: struct {
        max_resp_code: u16,
        mcast_addr: ipv6.Address,
        s_flag: bool,
        qrv: u8,
        qqic: u8,
        num_srcs: u16,
    },
    report: struct {
        nr_mcast_addr_rcrds: u16,
    },
};

pub fn bufferLen(repr: Repr) usize {
    return switch (repr) {
        .query => 24, // max_resp(2) + reserved(2) + mcast(16) + sqrv(1) + qqic(1) + numsrc(2)
        .report => 4, // reserved(2) + nr_records(2)
    };
}

/// Parse MLD message body. msg_type is the ICMPv6 type byte, data starts
/// at byte 4 of the ICMPv6 message.
pub fn parse(msg_type: u8, data: []const u8) error{ Truncated, Unrecognized }!Repr {
    switch (msg_type) {
        0x82 => { // MLD Query
            if (data.len < 24) return error.Truncated;
            const sqrv = data[20];
            return .{ .query = .{
                .max_resp_code = readU16(data[0..2]),
                .mcast_addr = data[4..20].*,
                .s_flag = (sqrv & 0x08) != 0,
                .qrv = sqrv & 0x07,
                .qqic = data[21],
                .num_srcs = readU16(data[22..24]),
            } };
        },
        0x8F => { // MLDv2 Report
            if (data.len < 4) return error.Truncated;
            return .{ .report = .{
                .nr_mcast_addr_rcrds = readU16(data[2..4]),
            } };
        },
        else => return error.Unrecognized,
    }
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const len = bufferLen(repr);
    if (buf.len < len) return error.BufferTooSmall;

    switch (repr) {
        .query => |q| {
            writeU16(buf[0..2], q.max_resp_code);
            @memset(buf[2..4], 0); // reserved
            @memcpy(buf[4..20], &q.mcast_addr);
            var sqrv: u8 = q.qrv & 0x07;
            if (q.s_flag) sqrv |= 0x08;
            buf[20] = sqrv;
            buf[21] = q.qqic;
            writeU16(buf[22..24], q.num_srcs);
        },
        .report => |r| {
            @memset(buf[0..2], 0); // reserved
            writeU16(buf[2..4], r.nr_mcast_addr_rcrds);
        },
    }
    return len;
}

pub fn parseAddressRecord(data: []const u8) error{Truncated}!AddressRecordRepr {
    if (data.len < 20) return error.Truncated;
    return .{
        .record_type = @enumFromInt(data[0]),
        .aux_data_len = data[1],
        .num_srcs = readU16(data[2..4]),
        .mcast_addr = data[4..20].*,
    };
}

pub fn addressRecordLen(record: AddressRecordRepr) usize {
    return 20 + @as(usize, record.num_srcs) * 16 + @as(usize, record.aux_data_len) * 4;
}

pub fn emitAddressRecord(record: AddressRecordRepr, buf: []u8) error{BufferTooSmall}!usize {
    if (buf.len < 20) return error.BufferTooSmall;
    buf[0] = @intFromEnum(record.record_type);
    buf[1] = record.aux_data_len;
    writeU16(buf[2..4], record.num_srcs);
    @memcpy(buf[4..20], &record.mcast_addr);
    return 20;
}

fn readU16(data: *const [2]u8) u16 {
    return @as(u16, data[0]) << 8 | @as(u16, data[1]);
}

fn writeU16(buf: *[2]u8, val: u16) void {
    buf[0] = @truncate(val >> 8);
    buf[1] = @truncate(val);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/mld.rs:test_query_deconstruct]
test "parse MLD query" {
    // Data after ICMPv6 type+code+checksum (byte 4 onward of full packet)
    const data = [_]u8{
        0x04, 0x00, // max_resp_code=0x0400
        0x00, 0x00, // reserved
        // mcast_addr = ff02::1
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x0a, // SQRV: s_flag=1(bit3), qrv=2(bits0-2) = 0b00001010
        0x12, // qqic
        0x00, 0x01, // num_srcs=1
    };
    const repr = try parse(0x82, &data);
    const q = repr.query;
    try testing.expectEqual(@as(u16, 0x0400), q.max_resp_code);
    try testing.expect(q.s_flag);
    try testing.expectEqual(@as(u8, 2), q.qrv);
    try testing.expectEqual(@as(u8, 0x12), q.qqic);
    try testing.expectEqual(@as(u16, 1), q.num_srcs);
    try testing.expectEqual(ipv6.LINK_LOCAL_ALL_NODES, q.mcast_addr);
}

// [smoltcp:wire/mld.rs:test_report_deconstruct]
test "parse MLD report" {
    const data = [_]u8{
        0x00, 0x00, // reserved
        0x00, 0x01, // nr_mcast_addr_rcrds=1
    };
    const repr = try parse(0x8F, &data);
    try testing.expectEqual(@as(u16, 1), repr.report.nr_mcast_addr_rcrds);
}

test "parse MLD unrecognized type" {
    try testing.expectError(error.Unrecognized, parse(0x01, &[_]u8{ 0, 0, 0, 0 }));
}

test "MLD query roundtrip" {
    const original = [_]u8{
        0x04, 0x00, 0x00, 0x00,
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x0a, 0x12, 0x00, 0x01,
    };
    const repr = try parse(0x82, &original);
    var buf: [24]u8 = undefined;
    _ = try emit(repr, &buf);
    try testing.expectEqualSlices(u8, &original, &buf);
}

test "parse address record" {
    const data = [_]u8{
        0x01, // record_type=ModeIsInclude
        0x00, // aux_data_len=0
        0x00, 0x01, // num_srcs=1
        // mcast_addr = ff02::1
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    const rec = try parseAddressRecord(&data);
    try testing.expectEqual(RecordType.mode_is_include, rec.record_type);
    try testing.expectEqual(@as(u16, 1), rec.num_srcs);
    try testing.expectEqual(ipv6.LINK_LOCAL_ALL_NODES, rec.mcast_addr);
    try testing.expectEqual(@as(usize, 36), addressRecordLen(rec));
}

test "address record roundtrip" {
    const rec = AddressRecordRepr{
        .record_type = .mode_is_exclude,
        .aux_data_len = 0,
        .num_srcs = 0,
        .mcast_addr = ipv6.LINK_LOCAL_ALL_NODES,
    };
    var buf: [20]u8 = undefined;
    _ = try emitAddressRecord(rec, &buf);
    const parsed = try parseAddressRecord(&buf);
    try testing.expectEqual(RecordType.mode_is_exclude, parsed.record_type);
    try testing.expectEqual(@as(u16, 0), parsed.num_srcs);
    try testing.expectEqual(ipv6.LINK_LOCAL_ALL_NODES, parsed.mcast_addr);
}
