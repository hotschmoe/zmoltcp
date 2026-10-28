//! A wrapping sequence number, as in a TCP header.

const std = @import("std");
const zv = @import("zv");

pub const assurance = .{
    .SeqNumber = .{ .fromU32 = .tested, .add = .checked, .lt = .tested },
    .laws = .{ .addThenLess = .tested },
    .Random = .external, // a std type re-exported for convenience
};

comptime {
    zv.requireAssurance(@This(), .tested);
}

pub const Random = std.Random;

pub const SeqNumber = struct {
    value: u32,

    pub fn fromU32(v: u32) SeqNumber {
        return .{ .value = v };
    }

    pub fn add(a: SeqNumber, n: u16) SeqNumber {
        return .{ .value = a.value +% n };
    }

    /// Serial-number comparison (RFC 1982 style).
    pub fn lt(a: SeqNumber, b: SeqNumber) bool {
        return @as(i32, @bitCast(a.value -% b.value)) < 0;
    }
};

pub const laws = struct {
    pub fn addThenLess(start: u32, n: u16) bool {
        const a: SeqNumber = .fromU32(start);
        return n == 0 or a.lt(a.add(n));
    }
};

test "laws hold, deterministic and fuzz entry" {
    try zv.checkLaws(laws, .{ .iterations = 2000, .seed = 7 });
    try zv.fuzzLaws(laws, &.{});
}
