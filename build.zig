const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const ghost = b.option(bool, "ghost", "Compile zv ghost code") orelse false;
    const zv = b.dependency("zirakzigil", .{ .ghost = ghost }).module("zv");

    // Expose zmoltcp as a module for downstream consumers.
    // Downstream build.zig uses: b.dependency("zmoltcp", .{}).module("zmoltcp")
    const zmoltcp_mod = b.addModule("zmoltcp", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "zv", .module = zv }},
    });

    // Unit tests -- run on host (native target by default).
    // `zig build test` runs all conformance + unit tests.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = true,
        .imports = &.{.{ .name = "zv", .module = zv }},
    });
    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run zmoltcp unit and conformance tests");
    test_step.dependOn(&run_unit_tests.step);

    // Native fuzzing needs a threaded test binary.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .single_threaded = false,
        .imports = &.{.{ .name = "zv", .module = zv }},
    });
    const fuzz_tests = b.addTest(.{
        .name = "fuzz",
        .root_module = fuzz_mod,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run zmoltcp fuzz targets");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // Integration demos -- `zig build demo`
    const demo_step = b.step("demo", "Run zmoltcp integration demos");
    for ([_][]const u8{
        "examples/loopback_echo.zig",
        "examples/back_to_back.zig",
        "examples/udp_icmp.zig",
        "examples/ipv6_echo.zig",
        "examples/fault_tolerant.zig",
        "examples/ip_medium.zig",
        "examples/fragmentation.zig",
        "examples/multi_socket.zig",
        "examples/raw_socket.zig",
        "examples/dual_stack.zig",
        "examples/dns_resolve.zig",
        "examples/phy_middleware.zig",
        "examples/dhcp_client.zig",
        "examples/sixlowpan.zig",
    }) |path| {
        const demo_mod = b.createModule(.{
            .root_source_file = b.path(path),
            .target = target,
            .optimize = optimize,
            .single_threaded = true,
            .imports = &.{.{ .name = "zmoltcp", .module = zmoltcp_mod }},
        });
        const demo_test = b.addTest(.{ .root_module = demo_mod });
        demo_step.dependOn(&b.addRunArtifact(demo_test).step);
    }
}
