//! `zig build assurance`: one line per module opts it into the Phase 0 gate.

const std = @import("std");
const zv = @import("zv");
const lib = @import("consumer");

pub fn main(init: std.process.Init) !void {
    try zv.report.run(init.io, .{
        .{ "ring_buffer", lib.ring_buffer },
        .{ "seq", lib.seq },
    }, .tested);
}
