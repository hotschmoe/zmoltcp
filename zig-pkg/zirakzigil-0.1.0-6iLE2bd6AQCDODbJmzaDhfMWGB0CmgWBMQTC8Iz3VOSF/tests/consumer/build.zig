//! A downstream project consuming zirakzigil the way zmoltcp will.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const ghost = b.option(bool, "ghost", "Compile zv ghost code") orelse false;

    const zv = b.dependency("zirakzigil", .{ .ghost = ghost }).module("zv");

    // The library's own module: no target, so it adopts its importer's.
    const lib = b.addModule("consumer", .{
        .root_source_file = b.path("src/root.zig"),
        .imports = &.{.{ .name = "zv", .module = zv }},
    });

    const tests = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zv", .module = zv }},
    }) });
    b.step("test", "Run library tests (laws, contracts, manifests)").dependOn(&b.addRunArtifact(tests).step);

    const report = b.addExecutable(.{ .name = "assurance", .root_module = b.createModule(.{
        .root_source_file = b.path("tools/assurance.zig"),
        .target = b.graph.host,
        .imports = &.{
            .{ .name = "zv", .module = zv },
            .{ .name = "consumer", .module = lib },
        },
    }) });
    b.step("assurance", "Print the per-module assurance table").dependOn(&b.addRunArtifact(report).step);
}
