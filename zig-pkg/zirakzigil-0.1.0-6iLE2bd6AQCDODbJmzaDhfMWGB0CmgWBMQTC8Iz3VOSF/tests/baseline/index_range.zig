//! Plain-Zig control for compile_fail index_range.
//! A runtime index into a too-short array compiles; safe builds panic only on
//! the path that runs, and ReleaseFast reads out of bounds.
//! expect: Debug=panic ReleaseSafe=panic ReleaseFast=ub
const std = @import("std");

pub fn main() void {
    const arr = [_]u8{ 1, 2, 3, 4 };
    var i: usize = 5; // an index meant for an 8-element table
    _ = &i;
    std.debug.print("WRONG: read {d}\n", .{arr[i]});
}
