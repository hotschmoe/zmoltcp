//! Plain-Zig control for should_panic/pin_copy.zig.
//! A self-referential struct copied by value keeps pointing at the original.
//! expect: Debug=silent ReleaseSafe=silent ReleaseFast=silent
const std = @import("std");

const Node = struct { val: u32 = 0, self_ref: ?*Node = null };

pub fn main() void {
    var original: Node = .{ .val = 1 };
    original.self_ref = &original;
    var moved = original; // innocent-looking copy
    moved.self_ref.?.val = 99; // writes through to `original`
    if (moved.val != 99) std.debug.print("WRONG: moved.val={d}, expected 99\n", .{moved.val});
}
