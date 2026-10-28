//! Plain-Zig control for should_panic/precondition.zig.
//! Safe builds already catch the underflow, but blame the callee, not the caller.
//! In ReleaseFast it is unchecked illegal behavior (zv's contract is off there too).
//! expect: Debug=panic ReleaseSafe=panic ReleaseFast=ub
const std = @import("std");

fn withdraw(balance: u64, amount: u64) u64 {
    return balance - amount;
}

pub fn main() void {
    var amount: u64 = 70;
    _ = &amount;
    const rest = withdraw(50, amount);
    if (rest > 50) std.debug.print("WRONG: rest={d}\n", .{rest});
}
