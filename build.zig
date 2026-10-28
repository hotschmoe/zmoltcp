const std = @import("std");
const zirakzigil = @import("zirakzigil");

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

    // `zig build matrix`: every optimize mode, ghost off and on, plus cross checks.
    _ = zirakzigil.addTestMatrix(b, .{
        .root_source_file = b.path("src/root.zig"),
        .ghost = true,
        .cross = &.{ "aarch64-freestanding-none", "riscv64-freestanding-none" },
    });

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

    const report = b.addExecutable(.{ .name = "assurance", .root_module = b.createModule(.{
        .root_source_file = b.path("tools/assurance.zig"),
        .target = b.graph.host,
        .imports = &.{
            .{ .name = "zv", .module = zv },
            .{ .name = "zmoltcp", .module = zmoltcp_mod },
        },
    }) });
    b.step("assurance", "Print the per-module assurance table").dependOn(&b.addRunArtifact(report).step);

    addInterop(b, zmoltcp_mod, zv, optimize);
}

/// `zig build interop`: zmoltcp against real smoltcp (tests/interop/README.md). Needs cargo.
/// Deliberately not a dependency of `test` or `matrix`: the core suite stays Rust-free.
fn addInterop(b: *std.Build, zmoltcp_mod: *std.Build.Module, zv: *std.Build.Module, optimize: std.builtin.OptimizeMode) void {
    const host = b.graph.host;
    const interop_step = b.step("interop", "Run the zmoltcp <-> smoltcp interop scenarios (requires cargo)");
    const manifest = b.path("tests/interop/peer/Cargo.toml");
    const target_dir = "tests/interop/peer/target"; // relative to the build root, where the runs are pinned
    const exe_name = b.fmt("peer{s}", .{host.result.exeFileExt()});

    const tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/interop/main.zig"),
        .target = host,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "zmoltcp", .module = zmoltcp_mod },
            .{ .name = "zv", .module = zv },
        },
    });
    const interop_tests = b.addTest(.{ .root_module = tests_mod });

    // Two peer builds: plain release, and release with debug assertions and overflow checks so
    // smoltcp's own debug_assert!s fire. cargo is incremental, so the step always runs it and
    // the test runs declare the produced binary as an input.
    for ([_][]const u8{ "release", "release-assert" }) |profile| {
        const cargo = b.addSystemCommand(&.{ "cargo", "build", "--locked", "--manifest-path" });
        cargo.addFileArg(manifest);
        cargo.addArgs(&.{ "--target-dir", target_dir, "--profile", profile });
        cargo.has_side_effects = true;

        const peer_path = b.pathJoin(&.{ target_dir, profile, exe_name });
        const run = b.addRunArtifact(interop_tests);
        run.setName(b.fmt("run interop ({s} peer)", .{profile}));
        run.setCwd(b.path("."));
        run.setEnvironmentVariable("ZMOLTCP_PEER", peer_path);
        run.setEnvironmentVariable("ZMOLTCP_PEER_PROFILE", profile);
        run.step.dependOn(&cargo.step);
        run.addFileInput(.{ .cwd_relative = peer_path });
        interop_step.dependOn(&run.step);
    }
}
