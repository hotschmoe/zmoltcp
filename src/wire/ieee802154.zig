// IEEE 802.15.4 MAC frame parsing and serialization.
//
// Reference: IEEE 802.15.4-2015, smoltcp src/wire/ieee802154.rs

pub const MAX_FRAME_LEN: usize = 127;

pub const FrameType = enum(u3) {
    beacon = 0,
    data = 1,
    ack = 2,
    mac_command = 3,
    multipurpose = 5,
    frag_or_frak = 6,
    extended = 7,
    _,
};

pub const AddressingMode = enum(u2) {
    absent = 0,
    short = 2,
    extended = 3,
    _,
};

pub const FrameVersion = enum(u2) {
    ieee802154_2003 = 0,
    ieee802154_2006 = 1,
    ieee802154 = 2,
    _,
};

pub const Address = union(enum) {
    absent,
    short: [2]u8,
    extended: [8]u8,

    pub fn isBroadcast(self: Address) bool {
        return switch (self) {
            .short => |s| s[0] == 0xff and s[1] == 0xff,
            else => false,
        };
    }

    /// EUI-64: extended flips U/L bit, short pads with 0xff/0xfe per RFC 4944.
    pub fn asEui64(self: Address) [8]u8 {
        return switch (self) {
            .extended => |e| {
                var bytes = e;
                bytes[0] ^= 0x02;
                return bytes;
            },
            .short => |s| .{ 0, 0, 0, 0xff, 0xfe, 0, s[0], s[1] },
            .absent => .{ 0, 0, 0, 0, 0, 0, 0, 0 },
        };
    }

    pub fn asLinkLocalAddress(self: Address) [16]u8 {
        const eui = self.asEui64();
        return .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, eui[0], eui[1], eui[2], eui[3], eui[4], eui[5], eui[6], eui[7] };
    }

    fn addressingMode(self: Address) AddressingMode {
        return switch (self) {
            .absent => .absent,
            .short => .short,
            .extended => .extended,
        };
    }

    fn size(self: Address) usize {
        return switch (self) {
            .absent => 0,
            .short => 2,
            .extended => 8,
        };
    }
};

pub const Repr = struct {
    frame_type: FrameType,
    frame_version: FrameVersion,
    security: bool,
    frame_pending: bool,
    ack_request: bool,
    pan_id_compression: bool,
    sequence_number: ?u8,
    dst_pan_id: ?u16,
    dst_addr: Address,
    src_pan_id: ?u16,
    src_addr: Address,
};

const AddrPresentFlags = struct {
    dst_pan: bool,
    dst_mode: AddressingMode,
    src_pan: bool,
    src_mode: AddressingMode,
};

/// PAN ID / address presence rules per IEEE 802.15.4-2015 Table 7-2.
fn addrPresentFlags(
    frame_version: FrameVersion,
    dst_mode: AddressingMode,
    src_mode: AddressingMode,
    pan_id_compression: bool,
) error{Malformed}!AddrPresentFlags {
    switch (frame_version) {
        .ieee802154_2003, .ieee802154_2006 => {
            if (dst_mode == .absent and src_mode == .absent and pan_id_compression)
                return error.Malformed;

            const dst_present = dst_mode != .absent;
            const src_present = src_mode != .absent;

            if (!dst_present) {
                return .{ .dst_pan = false, .dst_mode = .absent, .src_pan = src_present, .src_mode = src_mode };
            }
            return .{
                .dst_pan = true,
                .dst_mode = dst_mode,
                .src_pan = src_present and !pan_id_compression,
                .src_mode = src_mode,
            };
        },
        .ieee802154 => {
            const dst_present = dst_mode != .absent;
            const src_present = src_mode != .absent;

            if (!dst_present and !src_present) {
                return .{
                    .dst_pan = pan_id_compression,
                    .dst_mode = .absent,
                    .src_pan = false,
                    .src_mode = .absent,
                };
            }
            if (!dst_present) {
                return .{
                    .dst_pan = false,
                    .dst_mode = .absent,
                    .src_pan = !pan_id_compression,
                    .src_mode = src_mode,
                };
            }
            if (!src_present) {
                return .{
                    .dst_pan = !pan_id_compression,
                    .dst_mode = dst_mode,
                    .src_pan = false,
                    .src_mode = .absent,
                };
            }
            if (dst_mode == .extended and src_mode == .extended) {
                return .{
                    .dst_pan = !pan_id_compression,
                    .dst_mode = .extended,
                    .src_pan = false,
                    .src_mode = .extended,
                };
            }
            if (dst_mode == .short and src_mode == .short) {
                return .{
                    .dst_pan = true,
                    .dst_mode = .short,
                    .src_pan = !pan_id_compression,
                    .src_mode = .short,
                };
            }
            return .{
                .dst_pan = true,
                .dst_mode = dst_mode,
                .src_pan = !pan_id_compression,
                .src_mode = src_mode,
            };
        },
        _ => return error.Malformed,
    }
}

fn readU16Le(data: []const u8) u16 {
    return @as(u16, data[1]) << 8 | @as(u16, data[0]);
}

fn writeU16Le(buf: []u8, val: u16) void {
    buf[0] = @truncate(val & 0xFF);
    buf[1] = @truncate(val >> 8);
}

fn readAddrReversed(data: []const u8, comptime len: usize) [len]u8 {
    var out: [len]u8 = undefined;
    for (0..len) |i| {
        out[i] = data[len - 1 - i];
    }
    return out;
}

fn writeAddrReversed(buf: []u8, comptime len: usize, addr: [len]u8) void {
    for (0..len) |i| {
        buf[i] = addr[len - 1 - i];
    }
}

fn securityHeaderLen(data: []const u8, offset: usize) error{Truncated}!usize {
    if (offset >= data.len) return error.Truncated;

    const security_ctrl = data[offset];
    var len: usize = 1;

    // 4-byte frame counter unless suppressed (bit 5)
    if ((security_ctrl >> 5) & 1 == 0) len += 4;

    // Key identifier length from key_id_mode (bits 4:3)
    len += switch ((security_ctrl >> 3) & 0b11) {
        0 => @as(usize, 0),
        1 => @as(usize, 1),
        2 => @as(usize, 5),
        3 => @as(usize, 9),
        else => unreachable,
    };

    return len;
}

fn micLen(security_level: u8) usize {
    return switch (security_level & 0b111) {
        0, 4 => 0,
        1, 5 => 4,
        2, 6 => 8,
        3, 7 => 16,
        else => unreachable,
    };
}

/// Read an address from wire bytes at the given offset, advancing offset.
fn readAddress(data: []const u8, offset: *usize, mode: AddressingMode) error{ Truncated, Malformed }!Address {
    switch (mode) {
        .absent => return .absent,
        .short => {
            if (offset.* + 2 > data.len) return error.Truncated;
            const addr = readAddrReversed(data[offset.*..], 2);
            offset.* += 2;
            return .{ .short = addr };
        },
        .extended => {
            if (offset.* + 8 > data.len) return error.Truncated;
            const addr = readAddrReversed(data[offset.*..], 8);
            offset.* += 8;
            return .{ .extended = addr };
        },
        _ => return error.Malformed,
    }
}

/// Write an address to wire bytes at the given offset, advancing offset.
fn writeAddress(buf: []u8, offset: *usize, addr: Address) void {
    switch (addr) {
        .absent => {},
        .short => |s| {
            writeAddrReversed(buf[offset.*..], 2, s);
            offset.* += 2;
        },
        .extended => |e| {
            writeAddrReversed(buf[offset.*..], 8, e);
            offset.* += 8;
        },
    }
}

/// Read an optional PAN ID from wire bytes at the given offset, advancing offset.
fn readPanId(data: []const u8, offset: *usize, present: bool) error{Truncated}!?u16 {
    if (!present) return null;
    if (offset.* + 2 > data.len) return error.Truncated;
    const pan = readU16Le(data[offset.* .. offset.* + 2]);
    offset.* += 2;
    return pan;
}

/// Write an optional PAN ID to wire bytes at the given offset, advancing offset.
fn writePanId(buf: []u8, offset: *usize, pan_id: ?u16) void {
    if (pan_id) |pan| {
        writeU16Le(buf[offset.* .. offset.* + 2], pan);
        offset.* += 2;
    }
}

pub fn parse(data: []const u8) error{ Truncated, Malformed }!Repr {
    if (data.len < 3) return error.Truncated;
    if (data.len > MAX_FRAME_LEN) return error.Malformed;

    const fc = readU16Le(data[0..2]);

    const frame_type: FrameType = @enumFromInt(@as(u3, @truncate(fc & 0b111)));
    const security: bool = (fc >> 3) & 1 == 1;
    const frame_pending: bool = (fc >> 4) & 1 == 1;
    const ack_request: bool = (fc >> 5) & 1 == 1;
    const pan_id_compression: bool = (fc >> 6) & 1 == 1;
    const seq_suppressed: bool = (fc >> 8) & 1 == 1;
    const dst_mode: AddressingMode = @enumFromInt(@as(u2, @truncate((fc >> 10) & 0b11)));
    const frame_version: FrameVersion = @enumFromInt(@as(u2, @truncate((fc >> 12) & 0b11)));
    const src_mode: AddressingMode = @enumFromInt(@as(u2, @truncate((fc >> 14) & 0b11)));

    if (@intFromEnum(dst_mode) == 1 or @intFromEnum(src_mode) == 1)
        return error.Malformed;
    if (@intFromEnum(frame_version) == 3)
        return error.Malformed;

    var offset: usize = 2;
    const sequence_number: ?u8 = blk: {
        if (seq_suppressed and frame_version == .ieee802154) break :blk null;
        if (offset >= data.len) return error.Truncated;
        const sn = data[offset];
        offset += 1;
        break :blk sn;
    };

    const flags = try addrPresentFlags(frame_version, dst_mode, src_mode, pan_id_compression);

    const dst_pan_id = try readPanId(data, &offset, flags.dst_pan);
    const dst_addr = try readAddress(data, &offset, flags.dst_mode);
    const src_pan_id = try readPanId(data, &offset, flags.src_pan);
    const src_addr = try readAddress(data, &offset, flags.src_mode);

    if (security) {
        const sec_len = try securityHeaderLen(data, offset);
        if (offset + sec_len > data.len) return error.Truncated;
    }

    return .{
        .frame_type = frame_type,
        .frame_version = frame_version,
        .security = security,
        .frame_pending = frame_pending,
        .ack_request = ack_request,
        .pan_id_compression = pan_id_compression,
        .sequence_number = sequence_number,
        .dst_pan_id = dst_pan_id,
        .dst_addr = dst_addr,
        .src_pan_id = src_pan_id,
        .src_addr = src_addr,
    };
}

pub fn bufferLen(repr: Repr) usize {
    var len: usize = 2;
    if (repr.sequence_number != null) len += 1;
    if (repr.dst_pan_id != null) len += 2;
    len += repr.dst_addr.size();
    if (repr.src_pan_id != null) len += 2;
    len += repr.src_addr.size();
    return len;
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const needed = bufferLen(repr);
    if (buf.len < needed) return error.BufferTooSmall;

    var fc: u16 = 0;
    fc |= @as(u16, @intFromEnum(repr.frame_type));
    if (repr.security) fc |= 1 << 3;
    if (repr.frame_pending) fc |= 1 << 4;
    if (repr.ack_request) fc |= 1 << 5;
    if (repr.pan_id_compression) fc |= 1 << 6;
    if (repr.sequence_number == null) fc |= 1 << 8;
    fc |= @as(u16, @intFromEnum(repr.dst_addr.addressingMode())) << 10;
    fc |= @as(u16, @intFromEnum(repr.frame_version)) << 12;
    fc |= @as(u16, @intFromEnum(repr.src_addr.addressingMode())) << 14;
    writeU16Le(buf[0..2], fc);

    var offset: usize = 2;

    if (repr.sequence_number) |sn| {
        buf[offset] = sn;
        offset += 1;
    }

    writePanId(buf, &offset, repr.dst_pan_id);
    writeAddress(buf, &offset, repr.dst_addr);
    writePanId(buf, &offset, repr.src_pan_id);
    writeAddress(buf, &offset, repr.src_addr);

    return offset;
}

/// Returns the payload portion of a parsed frame (after all headers, including security).
pub fn payloadSlice(data: []const u8) error{ Truncated, Malformed }![]const u8 {
    const repr = try parse(data);

    var offset: usize = bufferLen(repr);

    if (repr.security) {
        const sec_len = try securityHeaderLen(data, offset);
        offset += sec_len;
    }

    if (offset > data.len) return error.Truncated;
    return data[offset..];
}

const testing = @import("std").testing;

// [smoltcp:ieee802154.rs:extended_addr]
test "parse extended addresses" {
    const frame = [_]u8{
        0b0000_0001, 0b1100_1100, // frame control
        0b0, // seq
        0xcd, 0xab, // dst pan id
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, // dst addr (LE on wire)
        0x03, 0x04, // src pan id
        0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, // src addr (LE on wire)
    };
    const repr = try parse(&frame);
    try testing.expectEqual(FrameType.data, repr.frame_type);
    try testing.expectEqual(FrameVersion.ieee802154_2003, repr.frame_version);
    try testing.expect(!repr.security);
    try testing.expect(!repr.pan_id_compression);
    try testing.expectEqual(@as(?u8, 0), repr.sequence_number);
    try testing.expectEqual(@as(?u16, 0xabcd), repr.dst_pan_id);
    try testing.expectEqual(
        Address{ .extended = .{ 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00 } },
        repr.dst_addr,
    );
    try testing.expectEqual(@as(?u16, 0x0403), repr.src_pan_id);
    try testing.expectEqual(
        Address{ .extended = .{ 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00 } },
        repr.src_addr,
    );
}

// [smoltcp:ieee802154.rs:short_addr]
test "parse short addresses" {
    const frame = [_]u8{
        0x01, 0x98, // frame control
        0x00, // sequence number
        0x34, 0x12, 0x78, 0x56, // dst PAN + short addr
        0x34, 0x12, 0xbc, 0x9a, // src PAN + short addr
    };
    const repr = try parse(&frame);
    try testing.expectEqual(FrameType.data, repr.frame_type);
    try testing.expectEqual(FrameVersion.ieee802154_2006, repr.frame_version);
    try testing.expect(!repr.security);
    try testing.expect(!repr.frame_pending);
    try testing.expect(!repr.ack_request);
    try testing.expect(!repr.pan_id_compression);
    try testing.expectEqual(@as(?u8, 0x00), repr.sequence_number);
    try testing.expectEqual(@as(?u16, 0x1234), repr.dst_pan_id);
    try testing.expectEqual(Address{ .short = .{ 0x56, 0x78 } }, repr.dst_addr);
    try testing.expectEqual(@as(?u16, 0x1234), repr.src_pan_id);
    try testing.expectEqual(Address{ .short = .{ 0x9a, 0xbc } }, repr.src_addr);
}

// [smoltcp:ieee802154.rs:zolertia_remote]
test "parse zolertia remote" {
    const frame = [_]u8{
        0x41, 0xd8, // frame control
        0x01, // sequence number
        0xcd, 0xab, // dst PAN id
        0xff, 0xff, // short dst addr
        0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, // extended src addr
        0x2b, 0x00, 0x00, 0x00, // payload
    };
    const repr = try parse(&frame);
    try testing.expectEqual(FrameType.data, repr.frame_type);
    try testing.expectEqual(FrameVersion.ieee802154_2006, repr.frame_version);
    try testing.expect(!repr.security);
    try testing.expect(!repr.frame_pending);
    try testing.expect(!repr.ack_request);
    try testing.expect(repr.pan_id_compression);

    try testing.expectEqual(@as(?u8, 0x01), repr.sequence_number);
    try testing.expectEqual(@as(?u16, 0xabcd), repr.dst_pan_id);
    try testing.expectEqual(Address{ .short = .{ 0xff, 0xff } }, repr.dst_addr);
    try testing.expect(repr.dst_addr.isBroadcast());
    try testing.expectEqual(@as(?u16, null), repr.src_pan_id);
    try testing.expectEqual(
        Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 } },
        repr.src_addr,
    );

    const payload = try payloadSlice(&frame);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x2b, 0x00, 0x00, 0x00 }, payload);
}

// [smoltcp:ieee802154.rs:security]
test "parse frame with security" {
    const frame = [_]u8{
        0x69, 0xdc, // frame control
        0x32, // sequence number
        0xcd, 0xab, // dst PAN id
        0xbf, 0x9b, 0x15, 0x06, 0x00, 0x4b, 0x12, 0x00, // extended dst addr
        0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00, // extended src addr
        0x05, // security control
        0x31, 0x01, 0x00, 0x00, // frame counter
        // encrypted data + MIC follow
        0x3e, 0xe8, 0xfb, 0x85, 0xe4, 0xcc, 0xf4, 0x48,
        0x90, 0xfe, 0x56, 0x66, 0xf7, 0x1c, 0x65, 0x9e,
        0xf9, 0x93, 0xc8, 0x34, 0x2e,
    };
    const repr = try parse(&frame);
    try testing.expectEqual(FrameType.data, repr.frame_type);
    try testing.expectEqual(FrameVersion.ieee802154_2006, repr.frame_version);
    try testing.expect(repr.security);
    try testing.expect(!repr.frame_pending);
    try testing.expect(repr.ack_request);
    try testing.expect(repr.pan_id_compression);
    try testing.expectEqual(@as(?u8, 0x32), repr.sequence_number);
    try testing.expectEqual(@as(?u16, 0xabcd), repr.dst_pan_id);
    try testing.expectEqual(
        Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x06, 0x15, 0x9b, 0xbf } },
        repr.dst_addr,
    );
    try testing.expectEqual(@as(?u16, null), repr.src_pan_id);
    try testing.expectEqual(
        Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 } },
        repr.src_addr,
    );
}

test "short addr roundtrip" {
    const repr = Repr{
        .frame_type = .data,
        .frame_version = .ieee802154_2006,
        .security = false,
        .frame_pending = false,
        .ack_request = false,
        .pan_id_compression = false,
        .sequence_number = 0x00,
        .dst_pan_id = 0x1234,
        .dst_addr = .{ .short = .{ 0x56, 0x78 } },
        .src_pan_id = 0x1234,
        .src_addr = .{ .short = .{ 0x9a, 0xbc } },
    };
    var buf: [128]u8 = undefined;
    const len = try emit(repr, &buf);
    const parsed = try parse(buf[0..len]);
    try testing.expectEqual(repr.frame_type, parsed.frame_type);
    try testing.expectEqual(repr.frame_version, parsed.frame_version);
    try testing.expectEqual(repr.sequence_number, parsed.sequence_number);
    try testing.expectEqual(repr.dst_pan_id, parsed.dst_pan_id);
    try testing.expectEqual(repr.dst_addr, parsed.dst_addr);
    try testing.expectEqual(repr.src_pan_id, parsed.src_pan_id);
    try testing.expectEqual(repr.src_addr, parsed.src_addr);
}

test "extended addr roundtrip with compression" {
    const repr = Repr{
        .frame_type = .data,
        .frame_version = .ieee802154,
        .security = false,
        .frame_pending = false,
        .ack_request = true,
        .pan_id_compression = true,
        .sequence_number = 1,
        .dst_pan_id = 0xabcd,
        .dst_addr = .{ .short = .{ 0xff, 0xff } },
        .src_pan_id = null,
        .src_addr = .{ .extended = .{ 0xc7, 0xd9, 0xb5, 0x14, 0x00, 0x4b, 0x12, 0x00 } },
    };
    var buf: [128]u8 = undefined;
    const len = try emit(repr, &buf);
    const parsed = try parse(buf[0..len]);
    try testing.expectEqual(repr.frame_type, parsed.frame_type);
    try testing.expectEqual(repr.frame_version, parsed.frame_version);
    try testing.expectEqual(repr.ack_request, parsed.ack_request);
    try testing.expectEqual(repr.pan_id_compression, parsed.pan_id_compression);
    try testing.expectEqual(repr.sequence_number, parsed.sequence_number);
    try testing.expectEqual(repr.dst_pan_id, parsed.dst_pan_id);
    try testing.expectEqual(repr.dst_addr, parsed.dst_addr);
    try testing.expectEqual(repr.src_pan_id, parsed.src_pan_id);
    try testing.expectEqual(repr.src_addr, parsed.src_addr);
}

test "broadcast detection" {
    const bcast = Address{ .short = .{ 0xff, 0xff } };
    try testing.expect(bcast.isBroadcast());

    const unicast = Address{ .short = .{ 0x01, 0x02 } };
    try testing.expect(!unicast.isBroadcast());

    const ext = Address{ .extended = .{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } };
    try testing.expect(!ext.isBroadcast());

    const absent: Address = .absent;
    try testing.expect(!absent.isBroadcast());
}

test "EUI-64 conversion" {
    const ext = Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 } };
    const eui = ext.asEui64();
    try testing.expectEqual(@as(u8, 0x02), eui[0]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 }, eui[1..]);

    const shrt = Address{ .short = .{ 0xab, 0xcd } };
    const eui_short = shrt.asEui64();
    try testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xab, 0xcd }, &eui_short);

    const absent_addr: Address = .absent;
    const eui_absent = absent_addr.asEui64();
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, &eui_absent);
}

test "link-local address generation" {
    const ext = Address{ .extended = .{ 0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 } };
    const ll = ext.asLinkLocalAddress();
    try testing.expectEqual(@as(u8, 0xfe), ll[0]);
    try testing.expectEqual(@as(u8, 0x80), ll[1]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0 }, ll[2..8]);
    try testing.expectEqual(@as(u8, 0x02), ll[8]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd9, 0xc7 }, ll[9..16]);
}

test "parse truncated" {
    try testing.expectError(error.Truncated, parse(&[_]u8{ 0x01, 0x00 }));
}

test "bufferLen matches emit output" {
    const repr = Repr{
        .frame_type = .data,
        .frame_version = .ieee802154_2006,
        .security = false,
        .frame_pending = false,
        .ack_request = false,
        .pan_id_compression = true,
        .sequence_number = 5,
        .dst_pan_id = 0x1234,
        .dst_addr = .{ .short = .{ 0x01, 0x02 } },
        .src_pan_id = null,
        .src_addr = .{ .extended = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 } },
    };
    var buf: [128]u8 = undefined;
    const emitted = try emit(repr, &buf);
    try testing.expectEqual(bufferLen(repr), emitted);
}
