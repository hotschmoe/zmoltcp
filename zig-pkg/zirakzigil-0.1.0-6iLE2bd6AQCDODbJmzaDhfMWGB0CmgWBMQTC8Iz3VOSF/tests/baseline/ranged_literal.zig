//! Plain-Zig control for compile_fail ranged_literal.
//! A percentage stored in a u8 accepts 101.
//! expect: Debug=silent ReleaseSafe=silent ReleaseFast=silent
const std = @import("std");

pub fn main() void {
    const pct: u8 = 101;
    if (pct > 100) std.debug.print("WRONG: pct={d}\n", .{pct});
}
