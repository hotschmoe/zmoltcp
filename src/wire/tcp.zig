// TCP header parsing and serialization.
//
// Reference: RFC 793, smoltcp src/wire/tcp.rs

const std = @import("std");
const checksum = @import("checksum.zig");

pub const HEADER_LEN = 20; // Minimum (no options)
pub const MAX_HEADER_LEN = 60; // data_offset=15 * 4

// -------------------------------------------------------------------------
// Sequence Number (modular 2^32 arithmetic)
// -------------------------------------------------------------------------

// [smoltcp:wire/tcp.rs:SeqNumber]
pub const SeqNumber = struct {
    value: i32,

    pub const ZERO: SeqNumber = .{ .value = 0 };

    pub fn fromU32(v: u32) SeqNumber {
        return .{ .value = @bitCast(v) };
    }

    pub fn toU32(self: SeqNumber) u32 {
        return @bitCast(self.value);
    }

    pub fn add(self: SeqNumber, n: usize) SeqNumber {
        std.debug.assert(n <= std.math.maxInt(i32));
        return .{ .value = self.value +% @as(i32, @intCast(n)) };
    }

    pub fn sub(self: SeqNumber, n: usize) SeqNumber {
        std.debug.assert(n <= std.math.maxInt(i32));
        return .{ .value = self.value -% @as(i32, @intCast(n)) };
    }

    pub fn diff(self: SeqNumber, other: SeqNumber) usize {
        const result = self.value -% other.value;
        std.debug.assert(result >= 0);
        return @intCast(result);
    }

    pub fn cmp(self: SeqNumber, other: SeqNumber) std.math.Order {
        const d = self.value -% other.value;
        return std.math.order(d, @as(i32, 0));
    }

    pub fn lessThan(self: SeqNumber, other: SeqNumber) bool {
        return self.cmp(other) == .lt;
    }

    pub fn greaterThan(self: SeqNumber, other: SeqNumber) bool {
        return self.cmp(other) == .gt;
    }

    pub fn greaterThanOrEqual(self: SeqNumber, other: SeqNumber) bool {
        return self.cmp(other) != .lt;
    }

    pub fn lessThanOrEqual(self: SeqNumber, other: SeqNumber) bool {
        return self.cmp(other) != .gt;
    }

    pub fn eql(self: SeqNumber, other: SeqNumber) bool {
        return self.value == other.value;
    }

    pub fn max(self: SeqNumber, other: SeqNumber) SeqNumber {
        return if (self.greaterThanOrEqual(other)) self else other;
    }

    pub fn min(self: SeqNumber, other: SeqNumber) SeqNumber {
        return if (self.lessThan(other)) self else other;
    }
};

// -------------------------------------------------------------------------
// Control (abstract single control signal for socket layer)
// -------------------------------------------------------------------------

// [smoltcp:wire/tcp.rs:Control]
pub const Control = enum {
    none,
    psh,
    syn,
    fin,
    rst,

    pub fn seqLen(self: Control) usize {
        return switch (self) {
            .syn, .fin => 1,
            .none, .psh, .rst => 0,
        };
    }

    pub fn quashPsh(self: Control) Control {
        return if (self == .psh) .none else self;
    }

    pub fn fromFlags(flags: Flags) Control {
        if (flags.rst) return .rst;
        if (flags.fin) return .fin;
        if (flags.syn) return .syn;
        if (flags.psh) return .psh;
        return .none;
    }

    pub fn applyToFlags(self: Control, flags: *Flags) void {
        switch (self) {
            .none => {},
            .psh => flags.psh = true,
            .syn => flags.syn = true,
            .fin => flags.fin = true,
            .rst => flags.rst = true,
        }
    }
};

pub const Flags = struct {
    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    ece: bool = false,
    cwr: bool = false,
};

/// TCP option kinds.
pub const OptionKind = enum(u8) {
    end = 0,
    nop = 1,
    mss = 2,
    window_scale = 3,
    sack_permitted = 4,
    sack = 5,
    timestamps = 8,
    _,
};

pub const SackRange = struct { left: u32, right: u32 };
pub const Timestamp = struct { tsval: u32, tsecr: u32 };

/// High-level representation of a TCP segment header.
pub const Repr = struct {
    src_port: u16,
    dst_port: u16,
    seq_number: u32,
    ack_number: u32,
    data_offset: u4,
    flags: Flags,
    window_size: u16,
    checksum: u16,
    urgent_pointer: u16,
    // Parsed options
    max_seg_size: ?u16 = null,
    window_scale: ?u8 = null,
    sack_permitted: bool = false,
    sack_ranges: [3]?SackRange = .{ null, null, null },
    timestamp: ?Timestamp = null,
};

/// Parse a TCP header from raw bytes (after IP header).
pub fn parse(data: []const u8) error{ Truncated, BadDataOffset }!Repr {
    if (data.len < HEADER_LEN) return error.Truncated;

    const data_offset: u4 = @truncate(data[12] >> 4);
    if (data_offset < 5) return error.BadDataOffset;

    const header_len: usize = @as(usize, data_offset) * 4;
    if (data.len < header_len) return error.Truncated;

    const flags_byte = data[13];

    var repr = Repr{
        .src_port = @as(u16, data[0]) << 8 | @as(u16, data[1]),
        .dst_port = @as(u16, data[2]) << 8 | @as(u16, data[3]),
        .seq_number = @as(u32, data[4]) << 24 | @as(u32, data[5]) << 16 |
            @as(u32, data[6]) << 8 | @as(u32, data[7]),
        .ack_number = @as(u32, data[8]) << 24 | @as(u32, data[9]) << 16 |
            @as(u32, data[10]) << 8 | @as(u32, data[11]),
        .data_offset = data_offset,
        .flags = .{
            .fin = (flags_byte & 0x01) != 0,
            .syn = (flags_byte & 0x02) != 0,
            .rst = (flags_byte & 0x04) != 0,
            .psh = (flags_byte & 0x08) != 0,
            .ack = (flags_byte & 0x10) != 0,
            .urg = (flags_byte & 0x20) != 0,
            .ece = (flags_byte & 0x40) != 0,
            .cwr = (flags_byte & 0x80) != 0,
        },
        .window_size = @as(u16, data[14]) << 8 | @as(u16, data[15]),
        .checksum = @as(u16, data[16]) << 8 | @as(u16, data[17]),
        .urgent_pointer = @as(u16, data[18]) << 8 | @as(u16, data[19]),
    };

    // Parse options
    if (header_len > HEADER_LEN) {
        parseOptions(data[HEADER_LEN..header_len], &repr);
    }

    return repr;
}

fn parseOptions(options: []const u8, repr: *Repr) void {
    var i: usize = 0;
    while (i < options.len) {
        const kind: OptionKind = @enumFromInt(options[i]);
        switch (kind) {
            .end => return,
            .nop => {
                i += 1;
                continue;
            },
            .mss => {
                if (i + 4 > options.len) return;
                repr.max_seg_size = @as(u16, options[i + 2]) << 8 | @as(u16, options[i + 3]);
                i += 4;
            },
            .window_scale => {
                if (i + 3 > options.len) return;
                repr.window_scale = options[i + 2];
                i += 3;
            },
            .sack_permitted => {
                if (i + 2 > options.len) return;
                repr.sack_permitted = true;
                i += 2;
            },
            .sack => {
                if (i + 1 >= options.len) return;
                const opt_len = options[i + 1];
                if (opt_len < 2 or i + opt_len > options.len) return;
                const range_count = (@as(usize, opt_len) - 2) / 8;
                var ri: usize = 0;
                while (ri < @min(range_count, 3)) : (ri += 1) {
                    const start = i + 2 + ri * 8;
                    if (start + 8 > i + opt_len) break;
                    repr.sack_ranges[ri] = .{
                        .left = @as(u32, options[start]) << 24 | @as(u32, options[start + 1]) << 16 |
                            @as(u32, options[start + 2]) << 8 | @as(u32, options[start + 3]),
                        .right = @as(u32, options[start + 4]) << 24 | @as(u32, options[start + 5]) << 16 |
                            @as(u32, options[start + 6]) << 8 | @as(u32, options[start + 7]),
                    };
                }
                i += opt_len;
            },
            .timestamps => {
                if (i + 1 >= options.len) return;
                const opt_len = options[i + 1];
                if (opt_len != 10 or i + 10 > options.len) return;
                repr.timestamp = .{
                    .tsval = @as(u32, options[i + 2]) << 24 | @as(u32, options[i + 3]) << 16 |
                        @as(u32, options[i + 4]) << 8 | @as(u32, options[i + 5]),
                    .tsecr = @as(u32, options[i + 6]) << 24 | @as(u32, options[i + 7]) << 16 |
                        @as(u32, options[i + 8]) << 8 | @as(u32, options[i + 9]),
                };
                i += 10;
            },
            _ => {
                if (i + 1 >= options.len) return;
                const opt_len = options[i + 1];
                if (opt_len < 2) return;
                i += opt_len;
            },
        }
    }
}

fn sackCount(ranges: [3]?SackRange) usize {
    var count: usize = 0;
    for (ranges) |range| {
        if (range != null) count += 1;
    }
    return count;
}

/// Compute the header length from populated options, rounded up to 4 bytes.
pub fn headerLen(repr: Repr) usize {
    var length: usize = HEADER_LEN;
    if (repr.max_seg_size != null) length += 4;
    if (repr.window_scale != null) length += 3;
    if (repr.sack_permitted) {
        length += 2;
    } else {
        const count = sackCount(repr.sack_ranges);
        if (count > 0) length += 2 + 8 * count;
    }
    if (repr.timestamp != null) length += 10;
    return (length + 3) & ~@as(usize, 3);
}

/// Serialize a TCP header into a buffer. Does NOT compute checksum
/// (caller must provide pseudo-header context). Returns header length.
/// The data_offset field on repr is ignored; it is computed from options.
pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const header_len = headerLen(repr);
    if (buf.len < header_len) return error.BufferTooSmall;

    const data_offset: u4 = @intCast(header_len / 4);

    buf[0] = @truncate(repr.src_port >> 8);
    buf[1] = @truncate(repr.src_port & 0xFF);
    buf[2] = @truncate(repr.dst_port >> 8);
    buf[3] = @truncate(repr.dst_port & 0xFF);

    buf[4] = @truncate(repr.seq_number >> 24);
    buf[5] = @truncate(repr.seq_number >> 16);
    buf[6] = @truncate(repr.seq_number >> 8);
    buf[7] = @truncate(repr.seq_number & 0xFF);

    buf[8] = @truncate(repr.ack_number >> 24);
    buf[9] = @truncate(repr.ack_number >> 16);
    buf[10] = @truncate(repr.ack_number >> 8);
    buf[11] = @truncate(repr.ack_number & 0xFF);

    buf[12] = @as(u8, data_offset) << 4;

    var flags_byte: u8 = 0;
    if (repr.flags.fin) flags_byte |= 0x01;
    if (repr.flags.syn) flags_byte |= 0x02;
    if (repr.flags.rst) flags_byte |= 0x04;
    if (repr.flags.psh) flags_byte |= 0x08;
    if (repr.flags.ack) flags_byte |= 0x10;
    if (repr.flags.urg) flags_byte |= 0x20;
    if (repr.flags.ece) flags_byte |= 0x40;
    if (repr.flags.cwr) flags_byte |= 0x80;
    buf[13] = flags_byte;

    buf[14] = @truncate(repr.window_size >> 8);
    buf[15] = @truncate(repr.window_size & 0xFF);

    buf[16] = @truncate(repr.checksum >> 8);
    buf[17] = @truncate(repr.checksum & 0xFF);

    buf[18] = @truncate(repr.urgent_pointer >> 8);
    buf[19] = @truncate(repr.urgent_pointer & 0xFF);

    // Serialize options
    if (header_len > HEADER_LEN) {
        var i: usize = HEADER_LEN;

        if (repr.max_seg_size) |mss| {
            buf[i] = @intFromEnum(OptionKind.mss);
            buf[i + 1] = 4;
            buf[i + 2] = @truncate(mss >> 8);
            buf[i + 3] = @truncate(mss);
            i += 4;
        }

        if (repr.window_scale) |ws| {
            buf[i] = @intFromEnum(OptionKind.window_scale);
            buf[i + 1] = 3;
            buf[i + 2] = ws;
            i += 3;
        }

        if (repr.sack_permitted) {
            buf[i] = @intFromEnum(OptionKind.sack_permitted);
            buf[i + 1] = 2;
            i += 2;
        } else {
            const count = sackCount(repr.sack_ranges);
            if (count > 0) {
                buf[i] = @intFromEnum(OptionKind.sack);
                buf[i + 1] = @intCast(2 + 8 * count);
                i += 2;
                for (repr.sack_ranges) |maybe_range| {
                    if (maybe_range) |range| {
                        buf[i] = @truncate(range.left >> 24);
                        buf[i + 1] = @truncate(range.left >> 16);
                        buf[i + 2] = @truncate(range.left >> 8);
                        buf[i + 3] = @truncate(range.left);
                        buf[i + 4] = @truncate(range.right >> 24);
                        buf[i + 5] = @truncate(range.right >> 16);
                        buf[i + 6] = @truncate(range.right >> 8);
                        buf[i + 7] = @truncate(range.right);
                        i += 8;
                    }
                }
            }
        }

        if (repr.timestamp) |ts| {
            buf[i] = @intFromEnum(OptionKind.timestamps);
            buf[i + 1] = 10;
            buf[i + 2] = @truncate(ts.tsval >> 24);
            buf[i + 3] = @truncate(ts.tsval >> 16);
            buf[i + 4] = @truncate(ts.tsval >> 8);
            buf[i + 5] = @truncate(ts.tsval);
            buf[i + 6] = @truncate(ts.tsecr >> 24);
            buf[i + 7] = @truncate(ts.tsecr >> 16);
            buf[i + 8] = @truncate(ts.tsecr >> 8);
            buf[i + 9] = @truncate(ts.tsecr);
            i += 10;
        }

        if (i < header_len) {
            buf[i] = @intFromEnum(OptionKind.end);
            i += 1;
        }
        @memset(buf[i..header_len], 0);
    }

    return header_len;
}

/// Compute TCP checksum with pseudo-header.
pub fn computeChecksum(src_ip: [4]u8, dst_ip: [4]u8, tcp_data: []const u8) u16 {
    var sum: u32 = 0;

    // Pseudo-header: src IP, dst IP, zero, protocol (6), TCP length
    sum = checksum.calculate(&src_ip, sum);
    sum = checksum.calculate(&dst_ip, sum);
    const proto_len = [_]u8{ 0, 6, @truncate(tcp_data.len >> 8), @truncate(tcp_data.len & 0xFF) };
    sum = checksum.calculate(&proto_len, sum);

    // TCP header + data
    sum = checksum.calculate(tcp_data, sum);

    return checksum.finish(sum);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

// [smoltcp:wire/tcp.rs:test_parse - SYN segment]
test "parse TCP SYN" {
    const data = [_]u8{
        0xC0, 0x02, // src_port = 49154
        0x1F, 0x90, // dst_port = 8080
        0x00, 0x00, 0x03, 0xEA, // seq = 1002
        0x00, 0x00, 0x00, 0x00, // ack = 0
        0x50, 0x02, // data_offset=5, flags=SYN
        0x10, 0x00, // window = 4096
        0x00, 0x00, // checksum (not verified here)
        0x00, 0x00, // urgent = 0
    };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u16, 49154), repr.src_port);
    try testing.expectEqual(@as(u16, 8080), repr.dst_port);
    try testing.expectEqual(@as(u32, 1002), repr.seq_number);
    try testing.expectEqual(@as(u32, 0), repr.ack_number);
    try testing.expect(repr.flags.syn);
    try testing.expect(!repr.flags.ack);
    try testing.expect(!repr.flags.fin);
    try testing.expectEqual(@as(u16, 4096), repr.window_size);
}

test "parse TCP truncated" {
    const short = [_]u8{ 0xC0, 0x02, 0x1F, 0x90 };
    try testing.expectError(error.Truncated, parse(&short));
}

test "parse TCP bad data offset" {
    var data = [_]u8{
        0xC0, 0x02, 0x1F, 0x90,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x30, 0x02, // data_offset=3 (invalid, minimum is 5)
        0x10, 0x00, 0x00, 0x00,
        0x00, 0x00,
    };
    _ = &data;
    try testing.expectError(error.BadDataOffset, parse(&data));
}

// [smoltcp:wire/tcp.rs:test_parse_options - MSS option]
test "parse TCP with MSS option" {
    const data = [_]u8{
        0x00, 0x50, 0x1F, 0x90, // ports
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x60, 0x02, // data_offset=6 (24 bytes), SYN
        0x10, 0x00, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
        // Options:
        0x02, 0x04, 0x05, 0xB4, // MSS = 1460
    };
    const repr = try parse(&data);
    try testing.expectEqual(@as(u4, 6), repr.data_offset);
    try testing.expect(repr.flags.syn);
    try testing.expectEqual(@as(u16, 1460), repr.max_seg_size.?);
}

// [smoltcp:wire/tcp.rs:roundtrip]
test "TCP SYN roundtrip" {
    const original = [_]u8{
        0xC0, 0x02, 0x1F, 0x90,
        0x00, 0x00, 0x03, 0xEA,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02,
        0x10, 0x00,
        0x6E, 0x89,
        0x00, 0x00,
    };
    const repr = try parse(&original);
    var emitted: [HEADER_LEN]u8 = undefined;
    _ = try emit(repr, &emitted);
    try testing.expectEqualSlices(u8, &original, &emitted);
}

test "TCP checksum computation" {
    const src_ip = [4]u8{ 0x0A, 0x00, 0x02, 0x0F };
    const dst_ip = [4]u8{ 0x0A, 0x00, 0x02, 0x02 };
    // SYN segment (header only, checksum field zeroed)
    var tcp_bytes = [_]u8{
        0xC0, 0x02, 0x1F, 0x90,
        0x00, 0x00, 0x03, 0xEA,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02,
        0x10, 0x00,
        0x00, 0x00, // checksum = 0
        0x00, 0x00,
    };
    const cksum = computeChecksum(src_ip, dst_ip, &tcp_bytes);
    try testing.expect(cksum != 0);

    // Fill in checksum and verify
    tcp_bytes[16] = @truncate(cksum >> 8);
    tcp_bytes[17] = @truncate(cksum & 0xFF);
    try testing.expectEqual(@as(u16, 0), computeChecksum(src_ip, dst_ip, &tcp_bytes));
}

// [smoltcp:wire/tcp.rs:SeqNumber - wrapping arithmetic]
test "SeqNumber wrapping add and sub" {
    const s = SeqNumber.fromU32(0xFFFF_FFFE);
    const s2 = s.add(5);
    try testing.expectEqual(@as(u32, 3), s2.toU32());
    const s3 = s2.sub(5);
    try testing.expect(s3.eql(s));
}

test "SeqNumber signed comparison across wrap boundary" {
    // smoltcp uses REMOTE_SEQ = TcpSeqNumber(-10001)
    const remote_seq = SeqNumber{ .value = -10001 };
    const remote_seq_plus1 = remote_seq.add(1);

    // -10001 < -10000 in sequence space (adjacent)
    try testing.expect(remote_seq.lessThan(remote_seq_plus1));

    // Wrapping across 2^31 boundary
    const a = SeqNumber{ .value = @as(i32, std.math.maxInt(i32)) };
    const b = a.add(1);
    try testing.expect(a.lessThan(b));
    try testing.expect(b.greaterThan(a));
}

test "SeqNumber diff" {
    const a = SeqNumber{ .value = 100 };
    const b = SeqNumber{ .value = 90 };
    try testing.expectEqual(@as(usize, 10), a.diff(b));

    // Wrapping diff
    const c = SeqNumber.fromU32(5);
    const d = SeqNumber.fromU32(0xFFFF_FFFC);
    try testing.expectEqual(@as(usize, 9), c.diff(d));
}

test "SeqNumber max and min" {
    const a = SeqNumber{ .value = 100 };
    const b = SeqNumber{ .value = 200 };
    try testing.expect(a.max(b).eql(b));
    try testing.expect(a.min(b).eql(a));
}

test "Control seqLen" {
    try testing.expectEqual(@as(usize, 1), Control.syn.seqLen());
    try testing.expectEqual(@as(usize, 1), Control.fin.seqLen());
    try testing.expectEqual(@as(usize, 0), Control.none.seqLen());
    try testing.expectEqual(@as(usize, 0), Control.psh.seqLen());
    try testing.expectEqual(@as(usize, 0), Control.rst.seqLen());
}

test "Control from and to Flags" {
    var flags = Flags{ .syn = true };
    try testing.expectEqual(Control.syn, Control.fromFlags(flags));

    flags = Flags{ .fin = true };
    try testing.expectEqual(Control.fin, Control.fromFlags(flags));

    flags = Flags{ .rst = true, .fin = true };
    try testing.expectEqual(Control.rst, Control.fromFlags(flags));

    flags = Flags{ .psh = true };
    try testing.expectEqual(Control.psh, Control.fromFlags(flags));

    flags = Flags{};
    try testing.expectEqual(Control.none, Control.fromFlags(flags));

    // applyToFlags roundtrip
    var out_flags = Flags{};
    Control.syn.applyToFlags(&out_flags);
    try testing.expect(out_flags.syn);
}

test "Control quashPsh" {
    try testing.expectEqual(Control.none, Control.psh.quashPsh());
    try testing.expectEqual(Control.syn, Control.syn.quashPsh());
    try testing.expectEqual(Control.fin, Control.fin.quashPsh());
}

test "headerLen no options" {
    const repr = Repr{
        .src_port = 80,
        .dst_port = 8080,
        .seq_number = 0,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{},
        .window_size = 0,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    try testing.expectEqual(@as(usize, 20), headerLen(repr));
}

test "headerLen MSS only" {
    var repr = Repr{
        .src_port = 80,
        .dst_port = 8080,
        .seq_number = 0,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{},
        .window_size = 0,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    repr.max_seg_size = 1460;
    // 20 + 4 = 24, already aligned
    try testing.expectEqual(@as(usize, 24), headerLen(repr));
}

test "headerLen SYN with MSS + WindowScale + SackPermitted" {
    var repr = Repr{
        .src_port = 80,
        .dst_port = 8080,
        .seq_number = 0,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .syn = true },
        .window_size = 0,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    repr.max_seg_size = 1460;
    repr.window_scale = 7;
    repr.sack_permitted = true;
    // 20 + 4 + 3 + 2 = 29, rounds to 32
    try testing.expectEqual(@as(usize, 32), headerLen(repr));
}

test "headerLen timestamp" {
    var repr = Repr{
        .src_port = 80,
        .dst_port = 8080,
        .seq_number = 0,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{},
        .window_size = 0,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    repr.timestamp = .{ .tsval = 1, .tsecr = 0 };
    // 20 + 10 = 30, rounds to 32
    try testing.expectEqual(@as(usize, 32), headerLen(repr));
}

test "headerLen SACK range" {
    var repr = Repr{
        .src_port = 80,
        .dst_port = 8080,
        .seq_number = 0,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{},
        .window_size = 0,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    repr.sack_ranges[0] = .{ .left = 1000, .right = 2000 };
    // 20 + 2 + 8 = 30, rounds to 32
    try testing.expectEqual(@as(usize, 32), headerLen(repr));

    repr.sack_ranges[1] = .{ .left = 3000, .right = 4000 };
    // 20 + 2 + 16 = 38, rounds to 40
    try testing.expectEqual(@as(usize, 40), headerLen(repr));
}

test "timestamp option parse and emit roundtrip" {
    // Build a SYN with timestamp: MSS(1460) + Timestamp(tsval=0x01020304, tsecr=0x05060708)
    var repr = Repr{
        .src_port = 49154,
        .dst_port = 8080,
        .seq_number = 1002,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .syn = true },
        .window_size = 4096,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    repr.max_seg_size = 1460;
    repr.timestamp = .{ .tsval = 0x01020304, .tsecr = 0x05060708 };

    // headerLen: 20 + 4(MSS) + 10(TS) = 34, rounds to 36
    const hdr_len = headerLen(repr);
    try testing.expectEqual(@as(usize, 36), hdr_len);

    var buf: [60]u8 = undefined;
    const emitted_len = try emit(repr, &buf);
    try testing.expectEqual(hdr_len, emitted_len);

    // Parse back
    const parsed = try parse(buf[0..emitted_len]);
    try testing.expectEqual(@as(u16, 49154), parsed.src_port);
    try testing.expectEqual(@as(u16, 8080), parsed.dst_port);
    try testing.expectEqual(@as(u16, 1460), parsed.max_seg_size.?);
    try testing.expectEqual(@as(u32, 0x01020304), parsed.timestamp.?.tsval);
    try testing.expectEqual(@as(u32, 0x05060708), parsed.timestamp.?.tsecr);
}

test "SACK range parse and emit roundtrip" {
    // ACK with one SACK block
    var repr = Repr{
        .src_port = 80,
        .dst_port = 49500,
        .seq_number = 10001,
        .ack_number = 5000,
        .data_offset = 5,
        .flags = .{ .ack = true },
        .window_size = 4000,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    repr.sack_ranges[0] = .{ .left = 5500, .right = 6000 };

    const hdr_len = headerLen(repr);
    // 20 + 2 + 8 = 30, rounds to 32
    try testing.expectEqual(@as(usize, 32), hdr_len);

    var buf: [60]u8 = undefined;
    const emitted_len = try emit(repr, &buf);
    try testing.expectEqual(hdr_len, emitted_len);

    const parsed = try parse(buf[0..emitted_len]);
    try testing.expectEqual(@as(u32, 5500), parsed.sack_ranges[0].?.left);
    try testing.expectEqual(@as(u32, 6000), parsed.sack_ranges[0].?.right);
    try testing.expect(parsed.sack_ranges[1] == null);
    try testing.expect(parsed.sack_ranges[2] == null);
}

test "SYN options MSS + WindowScale + SackPermitted roundtrip" {
    var repr = Repr{
        .src_port = 80,
        .dst_port = 49500,
        .seq_number = 10000,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .syn = true },
        .window_size = 64,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    repr.max_seg_size = 1460;
    repr.window_scale = 0;
    repr.sack_permitted = true;

    const hdr_len = headerLen(repr);
    // 20 + 4 + 3 + 2 = 29, rounds to 32
    try testing.expectEqual(@as(usize, 32), hdr_len);

    var buf: [60]u8 = undefined;
    const emitted_len = try emit(repr, &buf);
    try testing.expectEqual(hdr_len, emitted_len);

    const parsed = try parse(buf[0..emitted_len]);
    try testing.expectEqual(@as(u16, 1460), parsed.max_seg_size.?);
    try testing.expectEqual(@as(u8, 0), parsed.window_scale.?);
    try testing.expect(parsed.sack_permitted);
    try testing.expect(parsed.timestamp == null);
    try testing.expect(parsed.sack_ranges[0] == null);
}

// [smoltcp:wire/tcp.rs:test_malformed_tcp_options]
test "malformed TCP options parsed without error" {
    // zmoltcp's parseOptions silently returns on malformed input.
    // Each case builds a TCP header with malformed options. parse() succeeds
    // but option fields stay at defaults.

    // Helper: build a minimal TCP header with data_offset and option bytes.
    const base = [HEADER_LEN]u8{
        0x00, 0x50, 0x1F, 0x90, // ports
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x00, 0x00, // data_offset + flags (filled per case)
        0x10, 0x00, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    };

    // Case 1: MSS kind=2 truncated (need 4 bytes, only 3 remain after NOP)
    {
        var buf: [24]u8 = undefined;
        @memcpy(buf[0..HEADER_LEN], &base);
        buf[12] = 0x60; // data_offset=6 (24 bytes)
        buf[20] = 0x01; // NOP
        buf[21] = 0x02; // MSS kind
        buf[22] = 0x04; // MSS length (needs i+4, but only 3 bytes from kind)
        buf[23] = 0x00;
        const repr = try parse(&buf);
        try testing.expect(repr.max_seg_size == null);
    }

    // Case 2: WindowScale kind=3 truncated (need 3 bytes, only 2 remain)
    {
        var buf: [24]u8 = undefined;
        @memcpy(buf[0..HEADER_LEN], &base);
        buf[12] = 0x60; // data_offset=6
        buf[20] = 0x01; // NOP
        buf[21] = 0x01; // NOP
        buf[22] = 0x03; // WS kind at position 2, only 1 byte left
        buf[23] = 0x00;
        const repr = try parse(&buf);
        try testing.expect(repr.window_scale == null);
    }

    // Case 3: Unknown kind with length < 2 (illegal minimum)
    {
        var buf: [24]u8 = undefined;
        @memcpy(buf[0..HEADER_LEN], &base);
        buf[12] = 0x60;
        buf[20] = 0x0C; // unknown kind
        buf[21] = 0x01; // length=1 (illegal, minimum is 2)
        buf[22] = 0x00;
        buf[23] = 0x00;
        const repr = try parse(&buf);
        try testing.expect(repr.max_seg_size == null);
        try testing.expect(repr.window_scale == null);
        try testing.expect(repr.timestamp == null);
    }

    // Case 4: Unknown kind at end of options (no length byte available)
    {
        var buf: [24]u8 = undefined;
        @memcpy(buf[0..HEADER_LEN], &base);
        buf[12] = 0x60;
        buf[20] = 0x01; // NOP
        buf[21] = 0x01; // NOP
        buf[22] = 0x01; // NOP
        buf[23] = 0x0C; // unknown kind at last byte, no length byte
        const repr = try parse(&buf);
        try testing.expect(repr.max_seg_size == null);
    }

    // Case 5: Timestamps kind with wrong length (!=10)
    {
        var buf: [28]u8 = undefined;
        @memcpy(buf[0..HEADER_LEN], &base);
        buf[12] = 0x70; // data_offset=7 (28 bytes)
        buf[20] = 0x08; // timestamps kind
        buf[21] = 0x08; // length=8 (should be 10)
        @memset(buf[22..28], 0);
        const repr = try parse(&buf);
        try testing.expect(repr.timestamp == null);
    }

    // Case 6: SACK kind with length < 2
    {
        var buf: [24]u8 = undefined;
        @memcpy(buf[0..HEADER_LEN], &base);
        buf[12] = 0x60;
        buf[20] = 0x05; // SACK kind
        buf[21] = 0x01; // length=1 (illegal)
        buf[22] = 0x00;
        buf[23] = 0x00;
        const repr = try parse(&buf);
        try testing.expect(repr.sack_ranges[0] == null);
    }
}
