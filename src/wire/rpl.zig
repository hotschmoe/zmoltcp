// RPL (Routing Protocol for Low-Power and Lossy Networks) wire format.
//
// Reference: RFC 6550, RFC 6553, smoltcp src/wire/rpl.rs
//
// RPL control messages are ICMPv6 type 0x9b. The data parameter to
// parse/emit starts at byte 4 of the ICMPv6 message (after type+code+checksum).

const checksum = @import("checksum.zig");

const readU16 = checksum.readU16;
const writeU16 = checksum.writeU16;

pub const InstanceId = union(enum) {
    global: u7,
    local: struct {
        id: u6,
        dodag_is_destination: bool,
    },

    pub fn fromByte(b: u8) InstanceId {
        if (b & 0x80 == 0) {
            return .{ .global = @truncate(b) };
        }
        return .{ .local = .{
            .id = @truncate(b & 0x3F),
            .dodag_is_destination = b & 0x40 != 0,
        } };
    }

    pub fn toByte(self: InstanceId) u8 {
        return switch (self) {
            .global => |v| @as(u8, v),
            .local => |l| 0x80 | (if (l.dodag_is_destination) @as(u8, 0x40) else @as(u8, 0)) | @as(u8, l.id),
        };
    }
};

pub const ModeOfOperation = enum(u2) {
    no_downward_routes = 0,
    non_storing = 1,
    storing_without_multicast = 2,
    storing_with_multicast = 3,
};

pub const RplControlMessage = enum(u8) {
    dis = 0x00,
    dio = 0x01,
    dao = 0x02,
    dao_ack = 0x03,
    _,
};

pub const DisRepr = struct {
    options: []const u8,
};

pub const DioRepr = struct {
    rpl_instance_id: InstanceId,
    version_number: u8,
    rank: u16,
    grounded: bool,
    mode_of_operation: ModeOfOperation,
    dodag_preference: u3,
    dtsn: u8,
    dodag_id: [16]u8,
    options: []const u8,
};

pub const DaoRepr = struct {
    rpl_instance_id: InstanceId,
    expect_ack: bool,
    sequence: u8,
    dodag_id: ?[16]u8,
    options: []const u8,
};

pub const DaoAckRepr = struct {
    rpl_instance_id: InstanceId,
    sequence: u8,
    status: u8,
    dodag_id: ?[16]u8,
};

pub const Repr = union(enum) {
    dis: DisRepr,
    dio: DioRepr,
    dao: DaoRepr,
    dao_ack: DaoAckRepr,
};

/// Parses the optional DODAG ID at byte offset 4 when the D-flag is set.
/// Used by both DAO and DAO-ACK. Returns the DODAG ID and the byte offset
/// where trailing data begins.
fn parseDodagId(flags_byte: u8, d_flag_bit: u8, data: []const u8) error{Truncated}!struct { ?[16]u8, usize } {
    if (flags_byte & d_flag_bit != 0) {
        if (data.len < 20) return error.Truncated;
        return .{ data[4..20].*, 20 };
    }
    return .{ null, 4 };
}

pub fn parse(code: u8, data: []const u8) error{ Truncated, Malformed }!Repr {
    const msg: RplControlMessage = @enumFromInt(code);
    switch (msg) {
        .dis => {
            if (data.len < 2) return error.Truncated;
            return .{ .dis = .{ .options = data[2..] } };
        },
        .dio => {
            if (data.len < 24) return error.Truncated;
            const flags_byte = data[4];
            return .{ .dio = .{
                .rpl_instance_id = InstanceId.fromByte(data[0]),
                .version_number = data[1],
                .rank = readU16(data[2..4]),
                .grounded = flags_byte & 0x80 != 0,
                .mode_of_operation = @enumFromInt(@as(u2, @truncate(flags_byte >> 3))),
                .dodag_preference = @truncate(flags_byte & 0x07),
                .dtsn = data[5],
                .dodag_id = data[8..24].*,
                .options = data[24..],
            } };
        },
        .dao => {
            if (data.len < 4) return error.Truncated;
            const dodag_id, const tail = try parseDodagId(data[1], 0x40, data);
            return .{ .dao = .{
                .rpl_instance_id = InstanceId.fromByte(data[0]),
                .expect_ack = data[1] & 0x80 != 0,
                .sequence = data[3],
                .dodag_id = dodag_id,
                .options = data[tail..],
            } };
        },
        .dao_ack => {
            if (data.len < 4) return error.Truncated;
            const dodag_id, _ = try parseDodagId(data[1], 0x80, data);
            return .{ .dao_ack = .{
                .rpl_instance_id = InstanceId.fromByte(data[0]),
                .sequence = data[2],
                .status = data[3],
                .dodag_id = dodag_id,
            } };
        },
        _ => return error.Malformed,
    }
}

/// Emits the optional DODAG ID at byte offset 4 when present. Returns
/// the byte offset where trailing data should begin.
fn emitDodagId(dodag_id: ?[16]u8, buf: []u8) usize {
    if (dodag_id) |did| {
        @memcpy(buf[4..20], &did);
        return 20;
    }
    return 4;
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const len = bufferLen(repr);
    if (buf.len < len) return error.BufferTooSmall;

    switch (repr) {
        .dis => |d| {
            buf[0] = 0;
            buf[1] = 0;
            @memcpy(buf[2 .. 2 + d.options.len], d.options);
        },
        .dio => |d| {
            buf[0] = d.rpl_instance_id.toByte();
            buf[1] = d.version_number;
            writeU16(buf[2..4], d.rank);
            var flags: u8 = @as(u8, d.dodag_preference);
            if (d.grounded) flags |= 0x80;
            flags |= @as(u8, @intFromEnum(d.mode_of_operation)) << 3;
            buf[4] = flags;
            buf[5] = d.dtsn;
            buf[6] = 0;
            buf[7] = 0;
            @memcpy(buf[8..24], &d.dodag_id);
            @memcpy(buf[24 .. 24 + d.options.len], d.options);
        },
        .dao => |d| {
            buf[0] = d.rpl_instance_id.toByte();
            var flags: u8 = if (d.dodag_id != null) @as(u8, 0x40) else @as(u8, 0);
            if (d.expect_ack) flags |= 0x80;
            buf[1] = flags;
            buf[2] = 0;
            buf[3] = d.sequence;
            const tail = emitDodagId(d.dodag_id, buf);
            @memcpy(buf[tail .. tail + d.options.len], d.options);
        },
        .dao_ack => |d| {
            buf[0] = d.rpl_instance_id.toByte();
            buf[1] = if (d.dodag_id != null) @as(u8, 0x80) else @as(u8, 0);
            buf[2] = d.sequence;
            buf[3] = d.status;
            _ = emitDodagId(d.dodag_id, buf);
        },
    }
    return len;
}

pub fn bufferLen(repr: Repr) usize {
    return switch (repr) {
        .dis => |d| 2 + d.options.len,
        .dio => |d| 24 + d.options.len,
        .dao => |d| (if (d.dodag_id != null) @as(usize, 20) else @as(usize, 4)) + d.options.len,
        .dao_ack => |d| if (d.dodag_id != null) @as(usize, 20) else @as(usize, 4),
    };
}

pub const OptionType = enum(u8) {
    pad1 = 0x00,
    padn = 0x01,
    dag_metric_container = 0x02,
    route_information = 0x03,
    dodag_configuration = 0x04,
    rpl_target = 0x05,
    transit_information = 0x06,
    solicited_information = 0x07,
    prefix_information = 0x08,
    rpl_target_descriptor = 0x09,
    _,
};

pub const OptionIterator = struct {
    data: []const u8,
    offset: usize,

    pub fn init(data: []const u8) OptionIterator {
        return .{ .data = data, .offset = 0 };
    }

    pub fn next(self: *OptionIterator) ?struct { option_type: OptionType, value: []const u8 } {
        if (self.offset >= self.data.len) return null;

        const typ: OptionType = @enumFromInt(self.data[self.offset]);
        if (typ == .pad1) {
            self.offset += 1;
            return .{ .option_type = .pad1, .value = &.{} };
        }

        if (self.offset + 1 >= self.data.len) return null;
        const opt_len = self.data[self.offset + 1];
        const value_start = self.offset + 2;
        const value_end = value_start + @as(usize, opt_len);
        if (value_end > self.data.len) return null;

        const value = self.data[value_start..value_end];
        self.offset = value_end;
        return .{ .option_type = typ, .value = value };
    }
};

pub const DodagConfigurationOption = struct {
    authentication_enabled: bool,
    path_control_size: u3,
    dio_interval_doublings: u8,
    dio_interval_min: u8,
    dio_redundancy_constant: u8,
    max_rank_increase: u16,
    minimum_hop_rank_increase: u16,
    objective_code_point: u16,
    default_lifetime: u8,
    lifetime_unit: u16,

    pub const WIRE_LEN: usize = 14;

    pub fn parseOption(data: []const u8) error{Truncated}!DodagConfigurationOption {
        if (data.len < WIRE_LEN) return error.Truncated;
        const flags_byte = data[0];
        return .{
            .authentication_enabled = flags_byte & 0x08 != 0,
            .path_control_size = @truncate(flags_byte & 0x07),
            .dio_interval_doublings = data[1],
            .dio_interval_min = data[2],
            .dio_redundancy_constant = data[3],
            .max_rank_increase = readU16(data[4..6]),
            .minimum_hop_rank_increase = readU16(data[6..8]),
            .objective_code_point = readU16(data[8..10]),
            .default_lifetime = data[11],
            .lifetime_unit = readU16(data[12..14]),
        };
    }

    pub fn emit(self: DodagConfigurationOption, buf: []u8) error{BufferTooSmall}!usize {
        if (buf.len < WIRE_LEN) return error.BufferTooSmall;
        var flags: u8 = 0;
        if (self.authentication_enabled) flags |= 0x08;
        flags |= @as(u8, self.path_control_size);
        buf[0] = flags;
        buf[1] = self.dio_interval_doublings;
        buf[2] = self.dio_interval_min;
        buf[3] = self.dio_redundancy_constant;
        writeU16(buf[4..6], self.max_rank_increase);
        writeU16(buf[6..8], self.minimum_hop_rank_increase);
        writeU16(buf[8..10], self.objective_code_point);
        buf[10] = 0;
        buf[11] = self.default_lifetime;
        writeU16(buf[12..14], self.lifetime_unit);
        return WIRE_LEN;
    }
};

pub const RplTargetOption = struct {
    prefix_length: u8,
    prefix: [16]u8,

    pub const WIRE_LEN: usize = 18; // flags(1) + prefix_length(1) + prefix(16)

    pub fn parseOption(data: []const u8) error{Truncated}!RplTargetOption {
        if (data.len < 2) return error.Truncated;
        var prefix: [16]u8 = .{0} ** 16;
        const avail = @min(data.len - 2, 16);
        @memcpy(prefix[0..avail], data[2 .. 2 + avail]);
        return .{
            .prefix_length = data[1],
            .prefix = prefix,
        };
    }

    pub fn emit(self: RplTargetOption, buf: []u8) error{BufferTooSmall}!usize {
        if (buf.len < WIRE_LEN) return error.BufferTooSmall;
        buf[0] = 0;
        buf[1] = self.prefix_length;
        @memcpy(buf[2..18], &self.prefix);
        return WIRE_LEN;
    }
};

pub const TransitInformationOption = struct {
    external: bool,
    path_control: u8,
    path_sequence: u8,
    path_lifetime: u8,
    parent_address: ?[16]u8,

    pub fn parseOption(data: []const u8) error{Truncated}!TransitInformationOption {
        if (data.len < 4) return error.Truncated;
        return .{
            .external = data[0] & 0x80 != 0,
            .path_control = data[1],
            .path_sequence = data[2],
            .path_lifetime = data[3],
            .parent_address = if (data.len >= 20) data[4..20].* else null,
        };
    }

    pub fn emit(self: TransitInformationOption, buf: []u8) error{BufferTooSmall}!usize {
        const len = self.wireLen();
        if (buf.len < len) return error.BufferTooSmall;
        buf[0] = if (self.external) @as(u8, 0x80) else @as(u8, 0);
        buf[1] = self.path_control;
        buf[2] = self.path_sequence;
        buf[3] = self.path_lifetime;
        if (self.parent_address) |addr| {
            @memcpy(buf[4..20], &addr);
        }
        return len;
    }

    pub fn wireLen(self: TransitInformationOption) usize {
        return if (self.parent_address != null) 20 else 4;
    }
};

// RFC 6553 -- carried in IPv6 HBH extension header
pub const HopByHopRepr = struct {
    down: bool,
    rank_error: bool,
    forwarding_error: bool,
    instance_id: InstanceId,
    sender_rank: u16,

    pub const WIRE_LEN: usize = 4;

    pub fn parseOption(data: []const u8) error{Truncated}!HopByHopRepr {
        if (data.len < WIRE_LEN) return error.Truncated;
        const flags = data[0];
        return .{
            .down = flags & 0x80 != 0,
            .rank_error = flags & 0x40 != 0,
            .forwarding_error = flags & 0x20 != 0,
            .instance_id = InstanceId.fromByte(data[1]),
            .sender_rank = readU16(data[2..4]),
        };
    }

    pub fn emit(self: HopByHopRepr, buf: []u8) error{BufferTooSmall}!usize {
        if (buf.len < WIRE_LEN) return error.BufferTooSmall;
        var flags: u8 = 0;
        if (self.down) flags |= 0x80;
        if (self.rank_error) flags |= 0x40;
        if (self.forwarding_error) flags |= 0x20;
        buf[0] = flags;
        buf[1] = self.instance_id.toByte();
        writeU16(buf[2..4], self.sender_rank);
        return WIRE_LEN;
    }
};

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

test "InstanceId global encoding" {
    const id = InstanceId.fromByte(0x1E);
    try testing.expect(id == .global);
    try testing.expectEqual(@as(u7, 0x1E), id.global);
    try testing.expectEqual(@as(u8, 0x1E), id.toByte());
}

test "InstanceId local encoding" {
    // bit7=1, bit6=1 (dodag_is_destination), bits[5:0]=0x0A
    const id = InstanceId.fromByte(0xCA); // 1_1_001010
    try testing.expect(id == .local);
    try testing.expectEqual(@as(u6, 0x0A), id.local.id);
    try testing.expect(id.local.dodag_is_destination);
    try testing.expectEqual(@as(u8, 0xCA), id.toByte());
}

test "InstanceId global zero" {
    const id = InstanceId.fromByte(0);
    try testing.expect(id == .global);
    try testing.expectEqual(@as(u7, 0), id.global);
    try testing.expectEqual(@as(u8, 0), id.toByte());
}

test "InstanceId local no dodag_is_destination" {
    // bit7=1, bit6=0, bits[5:0]=0x05
    const id = InstanceId.fromByte(0x85); // 1_0_000101
    try testing.expect(id == .local);
    try testing.expectEqual(@as(u6, 0x05), id.local.id);
    try testing.expect(!id.local.dodag_is_destination);
    try testing.expectEqual(@as(u8, 0x85), id.toByte());
}

test "DIS parse and emit roundtrip" {
    const data = [_]u8{ 0x00, 0x00 };
    const repr = try parse(0x00, &data);
    try testing.expect(repr == .dis);
    try testing.expectEqual(@as(usize, 0), repr.dis.options.len);

    var buf: [2]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 2), len);
    try testing.expectEqualSlices(u8, &data, &buf);
}

test "DIO parse and emit roundtrip" {
    // RPLInstanceID=0, Version=240, Rank=128, G=0|MOP=1(non_storing)|Prf=0, DTSN=240
    var data: [24]u8 = undefined;
    data[0] = 0x00; // instance id = global(0)
    data[1] = 0xF0; // version = 240
    data[2] = 0x00;
    data[3] = 0x80; // rank = 128
    data[4] = 0x08; // G=0, MOP=1 (bits[5:3]=001), Prf=0
    data[5] = 0xF0; // DTSN = 240
    data[6] = 0x00; // flags
    data[7] = 0x00; // reserved
    // DODAG ID = fd00::0201:0001:0001:0001
    const dodag_id = [16]u8{ 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 };
    @memcpy(data[8..24], &dodag_id);

    const repr = try parse(0x01, &data);
    try testing.expect(repr == .dio);
    const dio = repr.dio;
    try testing.expect(dio.rpl_instance_id == .global);
    try testing.expectEqual(@as(u7, 0), dio.rpl_instance_id.global);
    try testing.expectEqual(@as(u8, 240), dio.version_number);
    try testing.expectEqual(@as(u16, 128), dio.rank);
    try testing.expect(!dio.grounded);
    try testing.expectEqual(ModeOfOperation.non_storing, dio.mode_of_operation);
    try testing.expectEqual(@as(u3, 0), dio.dodag_preference);
    try testing.expectEqual(@as(u8, 240), dio.dtsn);
    try testing.expectEqual(dodag_id, dio.dodag_id);

    var buf: [24]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 24), len);
    try testing.expectEqualSlices(u8, &data, &buf);
}

test "DAO parse and emit without DODAG ID" {
    // instance_id=0, K=1, D=0, reserved=0, sequence=0xF1
    const data = [_]u8{ 0x00, 0x80, 0x00, 0xF1 };
    const repr = try parse(0x02, &data);
    try testing.expect(repr == .dao);
    const dao = repr.dao;
    try testing.expect(dao.expect_ack);
    try testing.expect(dao.dodag_id == null);
    try testing.expectEqual(@as(u8, 0xF1), dao.sequence);

    var buf: [4]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 4), len);
    try testing.expectEqualSlices(u8, &data, &buf);
}

test "DAO parse and emit with DODAG ID" {
    var data: [20]u8 = undefined;
    data[0] = 0x00; // instance_id = global(0)
    data[1] = 0xC0; // K=1, D=1
    data[2] = 0x00; // reserved
    data[3] = 0x05; // sequence
    const did = [16]u8{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    @memcpy(data[4..20], &did);

    const repr = try parse(0x02, &data);
    try testing.expect(repr == .dao);
    try testing.expect(repr.dao.dodag_id != null);
    try testing.expectEqual(did, repr.dao.dodag_id.?);
    try testing.expect(repr.dao.expect_ack);

    var buf: [20]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 20), len);
    try testing.expectEqualSlices(u8, &data, &buf);
}

test "DAO-ACK parse and emit without DODAG ID" {
    // From smoltcp test: instance_id=0, D=0, sequence=0xF1, status=0
    const data = [_]u8{ 0x00, 0x00, 0xF1, 0x00 };
    const repr = try parse(0x03, &data);
    try testing.expect(repr == .dao_ack);
    try testing.expect(repr.dao_ack.dodag_id == null);
    try testing.expectEqual(@as(u8, 0xF1), repr.dao_ack.sequence);
    try testing.expectEqual(@as(u8, 0), repr.dao_ack.status);

    var buf: [4]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 4), len);
    try testing.expectEqualSlices(u8, &data, &buf);
}

test "DAO-ACK parse and emit with DODAG ID" {
    // From smoltcp test: instance_id=30, D=1, sequence=0xF0, status=0
    var data: [20]u8 = undefined;
    data[0] = 0x1E; // instance_id = global(30)
    data[1] = 0x80; // D=1
    data[2] = 0xF0; // sequence
    data[3] = 0x00; // status
    const did = [16]u8{ 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
    @memcpy(data[4..20], &did);

    const repr = try parse(0x03, &data);
    try testing.expect(repr == .dao_ack);
    try testing.expect(repr.dao_ack.dodag_id != null);
    try testing.expectEqual(did, repr.dao_ack.dodag_id.?);
    try testing.expectEqual(@as(u8, 0x1E), repr.dao_ack.rpl_instance_id.toByte());

    var buf: [20]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 20), len);
    try testing.expectEqualSlices(u8, &data, &buf);
}

test "DodagConfiguration option parse and emit" {
    // From smoltcp DIO test options at offset 28:
    // Type=0x04, Len=14, then 14 bytes of content
    // Flags|A|PCS=0x00, DIOIntDoubl=8, DIOIntMin=12, DIORedun=0,
    // MaxRankIncrease=0x0400, MinHopRankIncrease=0x0080, OCP=0x0001,
    // Reserved=0, DefLifetime=30, LifetimeUnit=60
    const option_value = [_]u8{
        0x00, 0x08, 0x0C, 0x00,
        0x04, 0x00, 0x00, 0x80,
        0x00, 0x01, 0x00, 0x1E,
        0x00, 0x3C,
    };
    const opt = try DodagConfigurationOption.parseOption(&option_value);
    try testing.expect(!opt.authentication_enabled);
    try testing.expectEqual(@as(u3, 0), opt.path_control_size);
    try testing.expectEqual(@as(u8, 8), opt.dio_interval_doublings);
    try testing.expectEqual(@as(u8, 12), opt.dio_interval_min);
    try testing.expectEqual(@as(u8, 0), opt.dio_redundancy_constant);
    try testing.expectEqual(@as(u16, 0x0400), opt.max_rank_increase);
    try testing.expectEqual(@as(u16, 0x0080), opt.minimum_hop_rank_increase);
    try testing.expectEqual(@as(u16, 1), opt.objective_code_point);
    try testing.expectEqual(@as(u8, 30), opt.default_lifetime);
    try testing.expectEqual(@as(u16, 60), opt.lifetime_unit);

    var buf: [14]u8 = undefined;
    _ = try opt.emit(&buf);
    try testing.expectEqualSlices(u8, &option_value, &buf);
}

test "RplTarget option parse and emit" {
    const prefix = [16]u8{ 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x00, 0x02, 0x00, 0x02, 0x00, 0x02 };
    // value = flags(1) + prefix_length(1) + prefix(16)
    var option_value: [18]u8 = undefined;
    option_value[0] = 0x00; // flags
    option_value[1] = 128; // prefix_length
    @memcpy(option_value[2..18], &prefix);

    const opt = try RplTargetOption.parseOption(&option_value);
    try testing.expectEqual(@as(u8, 128), opt.prefix_length);
    try testing.expectEqual(prefix, opt.prefix);

    var buf: [18]u8 = undefined;
    _ = try opt.emit(&buf);
    try testing.expectEqualSlices(u8, &option_value, &buf);
}

test "TransitInformation option parse and emit without parent" {
    // external=0, path_control=0, path_sequence=0, path_lifetime=30
    const option_value = [_]u8{ 0x00, 0x00, 0x00, 0x1E };
    const opt = try TransitInformationOption.parseOption(&option_value);
    try testing.expect(!opt.external);
    try testing.expectEqual(@as(u8, 0), opt.path_control);
    try testing.expectEqual(@as(u8, 0), opt.path_sequence);
    try testing.expectEqual(@as(u8, 0x1E), opt.path_lifetime);
    try testing.expect(opt.parent_address == null);

    var buf: [4]u8 = undefined;
    _ = try opt.emit(&buf);
    try testing.expectEqualSlices(u8, &option_value, &buf);
}

test "TransitInformation option parse and emit with parent" {
    const parent = [16]u8{ 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01 };
    var option_value: [20]u8 = undefined;
    option_value[0] = 0x00;
    option_value[1] = 0x00;
    option_value[2] = 0x00;
    option_value[3] = 0x1E;
    @memcpy(option_value[4..20], &parent);

    const opt = try TransitInformationOption.parseOption(&option_value);
    try testing.expect(!opt.external);
    try testing.expectEqual(@as(u8, 0x1E), opt.path_lifetime);
    try testing.expect(opt.parent_address != null);
    try testing.expectEqual(parent, opt.parent_address.?);

    var buf: [20]u8 = undefined;
    _ = try opt.emit(&buf);
    try testing.expectEqualSlices(u8, &option_value, &buf);
}

test "HopByHop option parse and emit" {
    // O=1, R=0, F=1, instance_id=global(5), sender_rank=0x0200
    const data = [_]u8{ 0xA0, 0x05, 0x02, 0x00 };
    const hbh = try HopByHopRepr.parseOption(&data);
    try testing.expect(hbh.down);
    try testing.expect(!hbh.rank_error);
    try testing.expect(hbh.forwarding_error);
    try testing.expect(hbh.instance_id == .global);
    try testing.expectEqual(@as(u7, 5), hbh.instance_id.global);
    try testing.expectEqual(@as(u16, 0x0200), hbh.sender_rank);

    var buf: [4]u8 = undefined;
    _ = try hbh.emit(&buf);
    try testing.expectEqualSlices(u8, &data, &buf);
}

test "OptionIterator walks multiple options" {
    // Pad1 + DodagConfiguration(type=0x04, len=14, ...) + Pad1
    var opts: [17]u8 = undefined;
    opts[0] = 0x00; // Pad1
    opts[1] = 0x04; // DodagConfiguration type
    opts[2] = 14; // length
    @memset(opts[3..17], 0x00); // 14 bytes of dodag conf data

    var iter = OptionIterator.init(&opts);

    // First: Pad1
    const first = iter.next();
    try testing.expect(first != null);
    try testing.expectEqual(OptionType.pad1, first.?.option_type);

    // Second: DodagConfiguration
    const second = iter.next();
    try testing.expect(second != null);
    try testing.expectEqual(OptionType.dodag_configuration, second.?.option_type);
    try testing.expectEqual(@as(usize, 14), second.?.value.len);

    // No more
    const third = iter.next();
    try testing.expect(third == null);
}

test "secure message codes rejected as malformed" {
    try testing.expectError(error.Malformed, parse(0x80, &[_]u8{ 0, 0, 0, 0 }));
    try testing.expectError(error.Malformed, parse(0x81, &[_]u8{ 0, 0, 0, 0 }));
    try testing.expectError(error.Malformed, parse(0x82, &[_]u8{ 0, 0, 0, 0 }));
    try testing.expectError(error.Malformed, parse(0x83, &[_]u8{ 0, 0, 0, 0 }));
    try testing.expectError(error.Malformed, parse(0x8a, &[_]u8{ 0, 0, 0, 0 }));
}

test "truncated messages" {
    try testing.expectError(error.Truncated, parse(0x00, &[_]u8{0}));
    try testing.expectError(error.Truncated, parse(0x01, &[_]u8{ 0, 0, 0 }));
    try testing.expectError(error.Truncated, parse(0x02, &[_]u8{ 0, 0 }));
    try testing.expectError(error.Truncated, parse(0x03, &[_]u8{ 0, 0 }));
}

test "DIO with grounded flag and preference" {
    var data: [24]u8 = .{0} ** 24;
    data[0] = 0x00; // instance id
    data[1] = 0x01; // version
    data[2] = 0x01;
    data[3] = 0x00; // rank = 256
    data[4] = 0x80 | (0x02 << 3) | 0x05; // G=1, MOP=2(storing_without_multicast), Prf=5
    data[5] = 0x42; // DTSN

    const repr = try parse(0x01, &data);
    const dio = repr.dio;
    try testing.expect(dio.grounded);
    try testing.expectEqual(ModeOfOperation.storing_without_multicast, dio.mode_of_operation);
    try testing.expectEqual(@as(u3, 5), dio.dodag_preference);
    try testing.expectEqual(@as(u16, 256), dio.rank);
    try testing.expectEqual(@as(u8, 0x42), dio.dtsn);

    var buf: [24]u8 = undefined;
    const len = try emit(repr, &buf);
    try testing.expectEqual(@as(usize, 24), len);
    try testing.expectEqualSlices(u8, &data, &buf);
}
