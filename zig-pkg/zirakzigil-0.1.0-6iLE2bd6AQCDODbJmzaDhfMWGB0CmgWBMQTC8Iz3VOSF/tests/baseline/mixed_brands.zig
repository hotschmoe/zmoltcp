//! Plain-Zig control for compile_fail mixed_brands.
//! Handles are bare u32s, so a user id indexes the orders table without complaint.
//! expect: Debug=silent ReleaseSafe=silent ReleaseFast=silent
const std = @import("std");

pub fn main() void {
    const orders = [_]u32{ 900, 901 };
    const user_id: u32 = 1; // a handle into the *users* pool
    const order = orders[user_id];
    std.debug.print("WRONG: user handle {d} read order {d}\n", .{ user_id, order });
}
