// DNS packet parsing and serialization.
//
// Reference: RFC 1035, smoltcp src/wire/dns.rs

const std = @import("std");

pub const HEADER_LEN: usize = 12;
pub const CLASS_IN: u16 = 1;
pub const MAX_NAME_SIZE: usize = 255;
const MAX_LABELS: usize = 16;

pub const Opcode = enum(u8) {
    query = 0x00,
    status = 0x01,
    _,
};

pub const Rcode = enum(u8) {
    no_error = 0x00,
    form_err = 0x01,
    serv_fail = 0x02,
    nx_domain = 0x03,
    not_imp = 0x04,
    refused = 0x05,
    _,
};

pub const Type = enum(u16) {
    a = 0x0001,
    ns = 0x0002,
    cname = 0x0005,
    soa = 0x0006,
    aaaa = 0x001c,
    _,
};

pub const Flags = struct {
    pub const RESPONSE: u16 = 0x8000;
    pub const AUTHORITATIVE: u16 = 0x0400;
    pub const TRUNCATED: u16 = 0x0200;
    pub const RECURSION_DESIRED: u16 = 0x0100;
    pub const RECURSION_AVAILABLE: u16 = 0x0080;
    pub const AUTHENTIC_DATA: u16 = 0x0020;
    pub const CHECK_DISABLED: u16 = 0x0010;
};

pub const ParseError = error{Truncated};

fn readU16Be(data: []const u8, off: usize) u16 {
    return @as(u16, data[off]) << 8 | @as(u16, data[off + 1]);
}

fn readU32Be(data: []const u8, off: usize) u32 {
    return @as(u32, data[off]) << 24 | @as(u32, data[off + 1]) << 16 |
        @as(u32, data[off + 2]) << 8 | @as(u32, data[off + 3]);
}

// Header accessors -- free functions on raw packet bytes.

pub fn transactionId(data: []const u8) ParseError!u16 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return readU16Be(data, 0);
}

pub fn flags(data: []const u8) ParseError!u16 {
    if (data.len < HEADER_LEN) return error.Truncated;
    const all_flags = Flags.RESPONSE | Flags.AUTHORITATIVE | Flags.TRUNCATED |
        Flags.RECURSION_DESIRED | Flags.RECURSION_AVAILABLE |
        Flags.AUTHENTIC_DATA | Flags.CHECK_DISABLED;
    return readU16Be(data, 2) & all_flags;
}

pub fn opcode(data: []const u8) ParseError!Opcode {
    if (data.len < HEADER_LEN) return error.Truncated;
    const f = readU16Be(data, 2);
    return @enumFromInt(@as(u8, @truncate((f >> 11) & 0xF)));
}

pub fn rcode(data: []const u8) ParseError!Rcode {
    if (data.len < HEADER_LEN) return error.Truncated;
    const f = readU16Be(data, 2);
    return @enumFromInt(@as(u8, @truncate(f & 0xF)));
}

pub fn questionCount(data: []const u8) ParseError!u16 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return readU16Be(data, 4);
}

pub fn answerCount(data: []const u8) ParseError!u16 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return readU16Be(data, 6);
}

pub fn authorityCount(data: []const u8) ParseError!u16 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return readU16Be(data, 8);
}

pub fn additionalCount(data: []const u8) ParseError!u16 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return readU16Be(data, 10);
}

pub fn payload(data: []const u8) ParseError![]const u8 {
    if (data.len < HEADER_LEN) return error.Truncated;
    return data[HEADER_LEN..];
}

// Name parsing.
//
// DNS names use label-length encoding with optional pointer compression
// (RFC 1035 sec 4.1.4). Pointers use the top 2 bits of the length byte
// set to 0xC0, with the remaining 14 bits as an offset into the packet.

pub const NameLabels = struct {
    labels: [MAX_LABELS][]const u8 = undefined,
    len: usize = 0,

    pub fn get(self: *const NameLabels, i: usize) []const u8 {
        return self.labels[i];
    }
};

/// Walk a name without following pointers. Returns how far we consumed in
/// `bytes` (the "rest" after the name ends) and the end-of-name position
/// within `bytes`. Used by parseQuestion/parseRecord to find where the
/// name bytes end in the sequential payload.
pub fn parseNamePart(bytes: []const u8) ParseError!struct { rest: []const u8, name_end: usize } {
    var pos: usize = 0;
    while (pos < bytes.len) {
        const x = bytes[pos];
        if (x == 0x00) {
            // Terminator
            return .{ .rest = bytes[pos + 1 ..], .name_end = pos + 1 };
        } else if (x & 0xC0 == 0x00) {
            const label_len = @as(usize, x & 0x3F);
            if (pos + 1 + label_len > bytes.len) return error.Truncated;
            pos += 1 + label_len;
        } else if (x & 0xC0 == 0xC0) {
            if (pos + 2 > bytes.len) return error.Truncated;
            // Pointer: 2 bytes consumed, name continues elsewhere
            return .{ .rest = bytes[pos + 2 ..], .name_end = pos + 2 };
        } else {
            return error.Truncated;
        }
    }
    return error.Truncated;
}

/// Parse a DNS name following pointer compression. `packet_data` is the
/// full packet (needed for pointer targets). `name_start` is the offset
/// within `packet_data` where the name begins.
///
/// Anti-loop: on each pointer follow, we shrink the visible packet so we
/// never visit the same byte twice (same technique as smoltcp).
pub fn parseName(packet_data: []const u8, name_start: usize) ParseError!NameLabels {
    var result = NameLabels{};
    var packet = packet_data;
    var bytes = packet[name_start..];

    while (true) {
        if (bytes.len == 0) return error.Truncated;
        const x = bytes[0];
        if (x == 0x00) {
            return result;
        } else if (x & 0xC0 == 0x00) {
            const label_len = @as(usize, x & 0x3F);
            if (bytes.len < 1 + label_len) return error.Truncated;
            if (result.len >= MAX_LABELS) return error.Truncated;
            result.labels[result.len] = bytes[1 .. 1 + label_len];
            result.len += 1;
            bytes = bytes[1 + label_len ..];
        } else if (x & 0xC0 == 0xC0) {
            if (bytes.len < 2) return error.Truncated;
            const ptr = (@as(usize, x & 0x3F) << 8) | @as(usize, bytes[1]);
            if (packet.len <= ptr) return error.Truncated;
            // Anti-loop: shrink visible packet, continue from pointer target
            bytes = packet[ptr..];
            packet = packet[0..ptr];
        } else {
            return error.Truncated;
        }
    }
}

pub fn eqNames(a: NameLabels, b: NameLabels) bool {
    if (a.len != b.len) return false;
    for (0..a.len) |i| {
        if (!std.mem.eql(u8, a.labels[i], b.labels[i])) return false;
    }
    return true;
}

/// Flatten parsed name labels back into wire format (length-prefixed labels + 0x00).
pub fn copyName(dest: []u8, labels: NameLabels) ParseError!usize {
    var pos: usize = 0;
    for (0..labels.len) |i| {
        const label = labels.labels[i];
        if (pos + 1 + label.len > dest.len) return error.Truncated;
        dest[pos] = @truncate(label.len);
        @memcpy(dest[pos + 1 ..][0..label.len], label);
        pos += 1 + label.len;
    }
    if (pos >= dest.len) return error.Truncated;
    dest[pos] = 0x00;
    return pos + 1;
}

// Question and Record parsing.

pub const Question = struct {
    name: []const u8,
    type_: Type,
};

pub fn parseQuestion(bytes: []const u8) ParseError!struct { rest: []const u8, question: Question } {
    const np = try parseNamePart(bytes);
    const name = bytes[0..np.name_end];
    const rest = np.rest;

    if (rest.len < 4) return error.Truncated;
    const type_val = readU16Be(rest, 0);
    const class = readU16Be(rest, 2);
    if (class != CLASS_IN) return error.Truncated;

    return .{
        .rest = rest[4..],
        .question = .{
            .name = name,
            .type_ = @enumFromInt(type_val),
        },
    };
}

pub const RecordData = union(enum) {
    a: [4]u8,
    cname: []const u8,
    other: struct { type_: Type, data: []const u8 },
};

pub const Record = struct {
    name: []const u8,
    ttl: u32,
    data: RecordData,
};

pub fn parseRecord(bytes: []const u8) ParseError!struct { rest: []const u8, record: Record } {
    const np = try parseNamePart(bytes);
    const name = bytes[0..np.name_end];
    const rest = np.rest;

    if (rest.len < 10) return error.Truncated;
    const type_val = readU16Be(rest, 0);
    const class = readU16Be(rest, 2);
    const ttl = readU32Be(rest, 4);
    const rdlength = @as(usize, readU16Be(rest, 8));
    const after_fixed = rest[10..];

    if (class != CLASS_IN) return error.Truncated;
    if (after_fixed.len < rdlength) return error.Truncated;

    const rdata = after_fixed[0..rdlength];
    const type_: Type = @enumFromInt(type_val);

    const record_data: RecordData = switch (type_) {
        .a => blk: {
            if (rdata.len != 4) return error.Truncated;
            break :blk .{ .a = rdata[0..4].* };
        },
        .cname => .{ .cname = rdata },
        else => .{ .other = .{ .type_ = type_, .data = rdata } },
    };

    return .{
        .rest = after_fixed[rdlength..],
        .record = .{
            .name = name,
            .ttl = ttl,
            .data = record_data,
        },
    };
}

// Repr and emit (query-only).

pub const Repr = struct {
    transaction_id: u16,
    opcode: Opcode,
    flags: u16,
    question: Question,
};

pub fn bufferLen(repr: Repr) usize {
    return HEADER_LEN + repr.question.name.len + 4;
}

pub fn emit(repr: Repr, buf: []u8) ParseError!usize {
    const required = bufferLen(repr);
    if (buf.len < required) return error.Truncated;

    // Transaction ID
    buf[0] = @truncate(repr.transaction_id >> 8);
    buf[1] = @truncate(repr.transaction_id);

    // Flags + opcode
    const opcode_bits = @as(u16, @intFromEnum(repr.opcode)) << 11;
    const flags_val = repr.flags | opcode_bits;
    buf[2] = @truncate(flags_val >> 8);
    buf[3] = @truncate(flags_val);

    // QDCOUNT = 1
    buf[4] = 0;
    buf[5] = 1;
    // ANCOUNT = 0
    buf[6] = 0;
    buf[7] = 0;
    // NSCOUNT = 0
    buf[8] = 0;
    buf[9] = 0;
    // ARCOUNT = 0
    buf[10] = 0;
    buf[11] = 0;

    // Question section: name + type + class
    const name_len = repr.question.name.len;
    @memcpy(buf[HEADER_LEN..][0..name_len], repr.question.name);
    const qoff = HEADER_LEN + name_len;
    const type_val = @intFromEnum(repr.question.type_);
    buf[qoff] = @truncate(type_val >> 8);
    buf[qoff + 1] = @truncate(type_val);
    buf[qoff + 2] = @truncate(CLASS_IN >> 8);
    buf[qoff + 3] = @truncate(CLASS_IN);

    return required;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;

// [smoltcp:wire/dns.rs:test_parse_name]
test "parse name with pointer compression" {
    const bytes = [_]u8{
        0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
        0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f,
        0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
        0x05, 0xf3, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69,
        0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x05, 0x00, 0x04, 0x1f, 0x0d, 0x53, 0x24,
    };

    // Name at 0x0c: www.facebook.com
    const n1 = try parseName(&bytes, 0x0c);
    try testing.expectEqual(@as(usize, 3), n1.len);
    try testing.expectEqualSlices(u8, "www", n1.labels[0]);
    try testing.expectEqualSlices(u8, "facebook", n1.labels[1]);
    try testing.expectEqualSlices(u8, "com", n1.labels[2]);

    // Pointer at 0x22 -> 0x0c: www.facebook.com
    const n2 = try parseName(&bytes, 0x22);
    try testing.expectEqual(@as(usize, 3), n2.len);
    try testing.expectEqualSlices(u8, "www", n2.labels[0]);
    try testing.expectEqualSlices(u8, "facebook", n2.labels[1]);
    try testing.expectEqualSlices(u8, "com", n2.labels[2]);

    // Name at 0x2e: star-mini.c10r.facebook.com (partial pointer)
    const n3 = try parseName(&bytes, 0x2e);
    try testing.expectEqual(@as(usize, 4), n3.len);
    try testing.expectEqualSlices(u8, "star-mini", n3.labels[0]);
    try testing.expectEqualSlices(u8, "c10r", n3.labels[1]);
    try testing.expectEqualSlices(u8, "facebook", n3.labels[2]);
    try testing.expectEqualSlices(u8, "com", n3.labels[3]);

    // Pointer at 0x3f -> 0x2e: star-mini.c10r.facebook.com
    const n4 = try parseName(&bytes, 0x3f);
    try testing.expectEqual(@as(usize, 4), n4.len);
    try testing.expectEqualSlices(u8, "star-mini", n4.labels[0]);
    try testing.expectEqualSlices(u8, "c10r", n4.labels[1]);
    try testing.expectEqualSlices(u8, "facebook", n4.labels[2]);
    try testing.expectEqualSlices(u8, "com", n4.labels[3]);
}

// [smoltcp:wire/dns.rs:test_parse_request]
test "parse request" {
    const bytes = [_]u8{
        0x51, 0x84, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
    };

    try testing.expectEqual(@as(u16, 0x5184), try transactionId(&bytes));
    try testing.expectEqual(
        Flags.RECURSION_DESIRED | Flags.AUTHENTIC_DATA,
        try flags(&bytes),
    );
    try testing.expectEqual(Opcode.query, try opcode(&bytes));
    try testing.expectEqual(@as(u16, 1), try questionCount(&bytes));
    try testing.expectEqual(@as(u16, 0), try answerCount(&bytes));
    try testing.expectEqual(@as(u16, 0), try authorityCount(&bytes));
    try testing.expectEqual(@as(u16, 0), try additionalCount(&bytes));

    const pld = try payload(&bytes);
    const qr = try parseQuestion(pld);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    }, qr.question.name);
    try testing.expectEqual(Type.a, qr.question.type_);
    try testing.expectEqual(@as(usize, 0), qr.rest.len);
}

// [smoltcp:wire/dns.rs:test_parse_response]
test "parse response single A" {
    const bytes = [_]u8{
        0x51, 0x84, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0xca, 0x00, 0x04, 0xac, 0xd9,
        0xa8, 0xae,
    };

    try testing.expectEqual(@as(u16, 0x5184), try transactionId(&bytes));
    try testing.expectEqual(
        Flags.RESPONSE | Flags.RECURSION_DESIRED | Flags.RECURSION_AVAILABLE,
        try flags(&bytes),
    );
    try testing.expectEqual(Opcode.query, try opcode(&bytes));
    try testing.expectEqual(Rcode.no_error, try rcode(&bytes));
    try testing.expectEqual(@as(u16, 1), try questionCount(&bytes));
    try testing.expectEqual(@as(u16, 1), try answerCount(&bytes));

    const pld = try payload(&bytes);
    const qr = try parseQuestion(pld);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
    }, qr.question.name);
    try testing.expectEqual(Type.a, qr.question.type_);

    const ar = try parseRecord(qr.rest);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xc0, 0x0c }, ar.record.name);
    try testing.expectEqual(@as(u32, 202), ar.record.ttl);
    switch (ar.record.data) {
        .a => |addr| try testing.expectEqualSlices(u8, &[_]u8{ 0xac, 0xd9, 0xa8, 0xae }, &addr),
        else => return error.TestExpectedEqual,
    }
    try testing.expectEqual(@as(usize, 0), ar.rest.len);
}

// [smoltcp:wire/dns.rs:test_parse_response_multiple_a]
test "parse response multiple A" {
    const bytes = [_]u8{
        0x4b, 0x9e, 0x81, 0x80, 0x00, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x09, 0x72,
        0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00,
        0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00,
        0x04, 0x0d, 0xe0, 0x77, 0x35, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x28, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x43, 0xc0, 0x0c, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x04, 0x0d, 0xe0, 0x77, 0x62,
    };

    try testing.expectEqual(@as(u16, 0x4b9e), try transactionId(&bytes));
    try testing.expectEqual(@as(u16, 4), try answerCount(&bytes));

    const pld = try payload(&bytes);
    const qr = try parseQuestion(pld);
    try testing.expectEqual(Type.a, qr.question.type_);

    const expected_addrs = [4][4]u8{
        .{ 0x0d, 0xe0, 0x77, 0x35 },
        .{ 0x0d, 0xe0, 0x77, 0x28 },
        .{ 0x0d, 0xe0, 0x77, 0x43 },
        .{ 0x0d, 0xe0, 0x77, 0x62 },
    };

    var rest = qr.rest;
    for (0..4) |i| {
        const ar = try parseRecord(rest);
        try testing.expectEqualSlices(u8, &[_]u8{ 0xc0, 0x0c }, ar.record.name);
        try testing.expectEqual(@as(u32, 9), ar.record.ttl);
        switch (ar.record.data) {
            .a => |addr| try testing.expectEqualSlices(u8, &expected_addrs[i], &addr),
            else => return error.TestExpectedEqual,
        }
        rest = ar.rest;
    }
    try testing.expectEqual(@as(usize, 0), rest.len);
}

// [smoltcp:wire/dns.rs:test_parse_response_cname]
test "parse response CNAME" {
    const bytes = [_]u8{
        0x78, 0x6c, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
        0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03, 0x63, 0x6f,
        0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
        0x05, 0xf3, 0x00, 0x11, 0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69,
        0x04, 0x63, 0x31, 0x30, 0x72, 0xc0, 0x10, 0xc0, 0x2e, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x05, 0x00, 0x04, 0x1f, 0x0d, 0x53, 0x24,
    };

    try testing.expectEqual(@as(u16, 0x786c), try transactionId(&bytes));
    try testing.expectEqual(
        Flags.RESPONSE | Flags.RECURSION_DESIRED | Flags.RECURSION_AVAILABLE,
        try flags(&bytes),
    );
    try testing.expectEqual(@as(u16, 2), try answerCount(&bytes));

    const pld = try payload(&bytes);
    const qr = try parseQuestion(pld);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x03, 0x77, 0x77, 0x77, 0x08, 0x66, 0x61, 0x63, 0x65, 0x62, 0x6f, 0x6f, 0x6b, 0x03,
        0x63, 0x6f, 0x6d, 0x00,
    }, qr.question.name);

    // CNAME record
    const ar1 = try parseRecord(qr.rest);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xc0, 0x0c }, ar1.record.name);
    try testing.expectEqual(@as(u32, 1523), ar1.record.ttl);
    switch (ar1.record.data) {
        .cname => |cname_data| try testing.expectEqualSlices(u8, &[_]u8{
            0x09, 0x73, 0x74, 0x61, 0x72, 0x2d, 0x6d, 0x69, 0x6e, 0x69, 0x04, 0x63, 0x31, 0x30,
            0x72, 0xc0, 0x10,
        }, cname_data),
        else => return error.TestExpectedEqual,
    }

    // A record
    const ar2 = try parseRecord(ar1.rest);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xc0, 0x2e }, ar2.record.name);
    try testing.expectEqual(@as(u32, 5), ar2.record.ttl);
    switch (ar2.record.data) {
        .a => |addr| try testing.expectEqualSlices(u8, &[_]u8{ 0x1f, 0x0d, 0x53, 0x24 }, &addr),
        else => return error.TestExpectedEqual,
    }
    try testing.expectEqual(@as(usize, 0), ar2.rest.len);
}

// [smoltcp:wire/dns.rs:test_parse_response_nxdomain]
test "parse response NXDomain" {
    const bytes = [_]u8{
        0x63, 0xc4, 0x81, 0x83, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x13, 0x61,
        0x68, 0x61, 0x73, 0x64, 0x67, 0x68, 0x6c, 0x61, 0x6b, 0x73, 0x6a, 0x68, 0x62, 0x61,
        0x61, 0x73, 0x6c, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x20, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x03, 0x83, 0x00, 0x3d, 0x01, 0x61, 0x0c,
        0x67, 0x74, 0x6c, 0x64, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e,
        0x65, 0x74, 0x00, 0x05, 0x6e, 0x73, 0x74, 0x6c, 0x64, 0x0c, 0x76, 0x65, 0x72, 0x69,
        0x73, 0x69, 0x67, 0x6e, 0x2d, 0x67, 0x72, 0x73, 0xc0, 0x20, 0x5f, 0xce, 0x8b, 0x85,
        0x00, 0x00, 0x07, 0x08, 0x00, 0x00, 0x03, 0x84, 0x00, 0x09, 0x3a, 0x80, 0x00, 0x01,
        0x51, 0x80,
    };

    try testing.expectEqual(@as(u16, 0x63c4), try transactionId(&bytes));
    try testing.expectEqual(
        Flags.RESPONSE | Flags.RECURSION_DESIRED | Flags.RECURSION_AVAILABLE,
        try flags(&bytes),
    );
    try testing.expectEqual(Rcode.nx_domain, try rcode(&bytes));
    try testing.expectEqual(@as(u16, 1), try questionCount(&bytes));
    try testing.expectEqual(@as(u16, 0), try answerCount(&bytes));
    try testing.expectEqual(@as(u16, 1), try authorityCount(&bytes));

    const pld = try payload(&bytes);
    const qr = try parseQuestion(pld);
    try testing.expectEqual(Type.a, qr.question.type_);

    // SOA authority record
    const ar = try parseRecord(qr.rest);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xc0, 0x20 }, ar.record.name);
    try testing.expectEqual(@as(u32, 899), ar.record.ttl);
    switch (ar.record.data) {
        .other => |o| try testing.expectEqual(Type.soa, o.type_),
        else => return error.TestExpectedEqual,
    }
}

// [smoltcp:wire/dns.rs:test_emit]
test "emit query" {
    const name = [_]u8{
        0x09, 0x72, 0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67,
        0x00,
    };

    const repr = Repr{
        .transaction_id = 0x1234,
        .flags = Flags.RECURSION_DESIRED,
        .opcode = .query,
        .question = .{
            .name = &name,
            .type_ = .a,
        },
    };

    var buf: [bufferLen(repr)]u8 = undefined;
    _ = try emit(repr, &buf);

    const want = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x72,
        0x75, 0x73, 0x74, 0x2d, 0x6c, 0x61, 0x6e, 0x67, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00,
        0x01, 0x00, 0x01,
    };
    try testing.expectEqualSlices(u8, &want, &buf);
}
