//! `zig build assurance`: the per-module assurance table for the examples.
//! A consumer opts a module in by adding one line to the tuple below.

const std = @import("std");
const zv = @import("zv");

pub fn main(init: std.process.Init) !void {
    try zv.report.run(init.io, .{
        .{ "examples/search", @import("search") },
        .{ "examples/ledger", @import("ledger") },
    }, .tested);
}
