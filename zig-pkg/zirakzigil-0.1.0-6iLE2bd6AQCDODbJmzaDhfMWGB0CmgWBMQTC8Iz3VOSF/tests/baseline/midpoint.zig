//! Plain-Zig control for zvc's midpointNaive result.
//! Safe builds panic only if some test happens to use a huge input; the unit
//! test below passes. zvc finds the counterexample without running anything.
//! expect: Debug=panic ReleaseSafe=panic ReleaseFast=ub
const std = @import("std");

fn mid(lo: u32, hi: u32) u32 {
    return (lo + hi) / 2;
}

test "small inputs cannot see the bug" {
    try std.testing.expectEqual(@as(u32, 5), mid(0, 10));
}

pub fn main() void {
    var lo: u32 = 1;
    var hi: u32 = 4294967295; // zvc's counterexample
    _ = .{ &lo, &hi };
    const m = mid(lo, hi);
    if (m < lo) std.debug.print("WRONG: mid={d}, below lo\n", .{m});
}
