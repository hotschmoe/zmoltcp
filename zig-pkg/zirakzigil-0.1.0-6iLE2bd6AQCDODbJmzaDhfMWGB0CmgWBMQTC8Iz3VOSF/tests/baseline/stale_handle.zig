//! Plain-Zig control for should_panic/stale_handle.zig.
//! Accounts addressed by bare index; a closed account's index now points at bob.
//! expect: Debug=silent ReleaseSafe=silent ReleaseFast=silent
const std = @import("std");

pub fn main() void {
    var balances: [4]u64 = @splat(0);
    const alice: u32 = 0;
    balances[alice] = 100;
    // alice closes; bob is allocated into the same slot
    const bob: u32 = 0;
    balances[bob] = 5000;
    balances[alice] -= 50; // stale index debits bob
    if (balances[bob] != 5000) std.debug.print("WRONG: bob={d}, expected 5000\n", .{balances[bob]});
}
