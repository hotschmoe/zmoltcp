//! `zig build assurance`: the Phase 0 gate. The walk starts at the library root, so every
//! module is covered; the build supplies the evidence (see `addAssuranceGate` in build.zig).

const std = @import("std");
const zv = @import("zv");

pub fn main(init: std.process.Init) !void {
    try zv.report.run(init, @import("zmoltcp"), .tested);
}
