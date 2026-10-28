//! Functions written as ordinary Zig with zv contracts.
//! - `zig build test` runs them with runtime contract checks.
//! - `python3 tools/zvc.py examples/search.zig` proves the `.verified` ones
//!   statically: contracts, absence of overflow panics, and in-bounds indexing.

const std = @import("std");
const zv = @import("zv");

/// Every pub fn must appear here (enforced at compile time below).
pub const assurance = .{
    .midpointNaive = .verified, // zvc is expected to REJECT this one
    .midpoint = .verified,
    .lowerBound = .verified,
    .withdrawNaive = .verified, // zvc is expected to REJECT this one
    .withdraw = .verified,
    .clampedAdd = .verified,
    .scale = .checked,
};

comptime {
    zv.requireAssurance(@This(), .checked);
}

/// The classic binary-search bug (Bloch, 2006): lo + hi overflows.
/// Every unit test with small numbers passes.
pub fn midpointNaive(lo: u32, hi: u32) u32 {
    zv.requires(lo <= hi);
    const mid = (lo + hi) / 2;
    return zv.ensures(mid, lo <= mid and mid <= hi);
}

pub fn midpoint(lo: u32, hi: u32) u32 {
    zv.requires(lo <= hi);
    const mid = lo + (hi - lo) / 2;
    return zv.ensures(mid, lo <= mid and mid <= hi);
}

/// First index whose element is >= key. zvc proves every `xs[mid]` is in bounds,
/// so the bounds check can never fire, and the result is a valid insert point.
pub fn lowerBound(xs: []const u32, key: u32) usize {
    var lo: usize = 0;
    var hi: usize = xs.len;
    while (lo < hi) {
        zv.invariant(lo <= hi and hi <= xs.len);
        const mid = lo + (hi - lo) / 2;
        if (xs[mid] < key) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return zv.ensures(lo, lo <= xs.len);
}

/// Forgot the precondition: underflow when amount > balance.
pub fn withdrawNaive(balance: u64, amount: u64) u64 {
    const rest = balance - amount;
    return zv.ensures(rest, rest <= balance);
}

pub fn withdraw(balance: u64, amount: u64) u64 {
    zv.requires(amount <= balance);
    const rest = balance - amount;
    return zv.ensures(rest, rest + amount == balance);
}

/// Saturating add with a cap; branches, no overflow possible.
pub fn clampedAdd(a: u32, b: u32, cap: u32) u32 {
    var r: u32 = cap;
    if (a <= cap) {
        if (b <= cap - a) {
            r = a + b;
        }
    }
    return zv.ensures(r, r <= cap);
}

/// Runtime-checked only (not in zvc's subset: it uses a Ranged type).
pub fn scale(x: zv.Ranged(0, 1000), k: zv.Ranged(0, 50)) zv.MulResult(zv.Ranged(0, 1000), zv.Ranged(0, 50)) {
    return zv.mul(x, k); // result type is Ranged(0, 50000): no overflow by construction
}

test "small cases pass for both midpoints (tests cannot see the bug)" {
    try std.testing.expectEqual(@as(u32, 5), midpointNaive(0, 10));
    try std.testing.expectEqual(@as(u32, 5), midpoint(0, 10));
    try std.testing.expectEqual(@as(u32, 7), midpointNaive(4, 10));
}

test "lowerBound" {
    const xs = [_]u32{ 1, 3, 3, 7, 9 };
    try std.testing.expectEqual(@as(usize, 1), lowerBound(&xs, 3));
    try std.testing.expectEqual(@as(usize, 5), lowerBound(&xs, 10));
    try std.testing.expectEqual(@as(usize, 0), lowerBound(&xs, 0));
    try std.testing.expectEqual(@as(usize, 0), lowerBound(&[_]u32{}, 4));
}

test "withdraw / clampedAdd / scale" {
    try std.testing.expectEqual(@as(u64, 3), withdraw(10, 7));
    try std.testing.expectEqual(@as(u32, 100), clampedAdd(90, 20, 100));
    try std.testing.expectEqual(@as(u32, 30), clampedAdd(10, 20, 100));
    const s = scale(.lit(1000), .lit(50));
    try std.testing.expectEqual(@as(u16, 50000), s.get());
    try std.testing.expect(@TypeOf(s.get()) == u16); // storage chosen at comptime
}
