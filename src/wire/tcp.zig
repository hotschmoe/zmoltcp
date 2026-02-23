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
            _ => {
                // Unknown option: skip using length field
                if (i + 1 >= options.len) return;
                const opt_len = options[i + 1];
                if (opt_len < 2) return;
                i += opt_len;
            },
        }
    }
}

/// Serialize a TCP header into a buffer. Does NOT compute checksum
/// (caller must provide pseudo-header context). Returns header length.
pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const header_len: usize = @as(usize, repr.data_offset) * 4;
    if (buf.len < header_len) return error.BufferTooSmall;

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

    buf[12] = @as(u8, repr.data_offset) << 4;

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

    // Zero option bytes
    if (header_len > HEADER_LEN) {
        @memset(buf[HEADER_LEN..header_len], 0);
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
