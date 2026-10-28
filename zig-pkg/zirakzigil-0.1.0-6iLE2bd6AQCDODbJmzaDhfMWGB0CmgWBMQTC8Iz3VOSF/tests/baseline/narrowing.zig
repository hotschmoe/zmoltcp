//! Plain-Zig control for compile_fail ranged_as_too_small.
//! @intCast compiles whenever the types differ; whether it fits is a runtime question.
//! expect: Debug=panic ReleaseSafe=panic ReleaseFast=ub
const std = @import("std");

pub fn main() void {
    var x: u16 = 1000; // a value in [0, 1000]
    _ = &x;
    const y: u8 = @intCast(x);
    std.debug.print("WRONG: y={d}\n", .{y});
}
