//! The Phase 0 gate measurement: a per-module table of assurance levels.
//!
//! Host-side tooling (it prints), not part of the freestanding library path.
//! A consumer lists its modules once and wires the result to `zig build assurance`:
//!
//!     // tools/assurance.zig
//!     const std = @import("std");
//!     const zv = @import("zv");
//!     const lib = @import("mylib");
//!
//!     pub fn main(init: std.process.Init) !void {
//!         try zv.report.run(init.io, .{
//!             .{ "tcp", lib.wire.tcp },                // one line per module
//!             .{ "ring_buffer", lib.storage.ring_buffer, .checked },  // optional own floor
//!         }, .tested);
//!     }
//!
//! `run` exits non-zero if any module has no manifest, has an unclassified
//! public function, or sits below its floor.

const std = @import("std");
const manifest = @import("manifest.zig");
const Level = manifest.Level;
const Counts = manifest.Counts;

const header = "{s:<24} {s:>4} {s:>8} {s:>7} {s:>6} {s:>7} {s:>8} {s:>9} {s:>8}  {s:<8} {s}\n";
const row = "{s:<24} {d:>4} {d:>8} {d:>7} {d:>6} {d:>7} {d:>8} {d:>9} {d:>8}  {s:<8} {s}\n";

/// Write the table for `modules` (a tuple of `.{ name, Module }` or
/// `.{ name, Module, floor }`). Returns true when every module passes.
pub fn write(w: *std.Io.Writer, comptime modules: anytype, comptime default_floor: Level) std.Io.Writer.Error!bool {
    var total: Counts = .{};
    var ok = true;
    try w.print(header, .{ "module", "fns", "verified", "checked", "tested", "trusted", "governed", "unwitness", "external", "floor", "status" });
    inline for (modules) |entry| {
        const floor: Level = comptime if (entry.len > 2) entry[2] else default_floor;
        const a = comptime manifest.audit(entry[1], floor);
        total = total.add(a.counts);
        const pass = a.problem.len == 0;
        ok = ok and pass;
        const c = a.counts;
        try w.print(row, .{ entry[0], c.fns(), c.verified, c.checked, c.tested, c.trusted, c.governed, c.unwitnessed, c.external, @tagName(floor), if (pass) "ok" else "FAIL" });
    }
    try w.print(row, .{ "TOTAL", total.fns(), total.verified, total.checked, total.tested, total.trusted, total.governed, total.unwitnessed, total.external, "", if (ok) "ok" else "FAIL" });
    inline for (modules) |entry| {
        const floor: Level = comptime if (entry.len > 2) entry[2] else default_floor;
        const a = comptime manifest.audit(entry[1], floor);
        if (a.problem.len != 0) try w.print("\n{s}: {s}\n", .{ entry[0], a.problem });
    }
    return ok;
}

/// Print the table to stdout and exit with status 1 if any module fails.
pub fn run(io: std.Io, comptime modules: anytype, comptime default_floor: Level) !void {
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writer(io, &buffer);
    const ok = try write(&stdout.interface, modules, default_floor);
    try stdout.interface.flush();
    if (!ok) std.process.exit(1);
}

test "table lists modules and flags failures" {
    const Good = struct {
        pub const assurance = .{ .f = .verified, .g = .tested };
        pub fn f() void {}
        pub fn g() void {}
    };
    const Bad = struct {
        pub const assurance = .{ .h = .trusted };
        pub fn h() void {}
    };
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    const ok = try write(&w, .{ .{ "good", Good }, .{ "bad", Bad, .tested } }, .tested);
    try std.testing.expect(!ok);
    const out = w.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out, "good") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "below this module's floor") != null);
}
