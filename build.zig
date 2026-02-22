const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Expose zmoltcp as a module for downstream consumers.
    // Downstream build.zig uses: b.dependency("zmoltcp", .{}).module("zmoltcp")
    _ = b.addModule("zmoltcp", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Unit tests -- run on host (native target by default).
    // `zig build test` runs all conformance + unit tests.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run zmoltcp unit and conformance tests");
    test_step.dependOn(&run_unit_tests.step);
}
