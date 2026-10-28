//! Plain-Zig control for should_panic/double_consume.zig.
//! A withdrawal is an ordinary struct; copying it and depositing twice prints money.
//! expect: Debug=silent ReleaseSafe=silent ReleaseFast=silent
const std = @import("std");

const Withdrawal = struct { amount: u64 };

pub fn main() void {
    var a: u64 = 100;
    var b: u64 = 0;
    a -= 60;
    const w: Withdrawal = .{ .amount = 60 };
    const copy = w; // silent by-value copy
    b += w.amount;
    b += copy.amount;
    if (a + b != 100) std.debug.print("WRONG: total={d}, started with 100\n", .{a + b});
}
