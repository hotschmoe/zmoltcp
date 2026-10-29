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
    const manifest = b.path("tests/interop/peer/Cargo.toml");
    const filter = b.option([]const u8, "interop-filter", "Run only interop tests whose name contains this");
    const imports: []const std.Build.Module.Import = &.{
        .{ .name = "zmoltcp", .module = zmoltcp_mod },
        .{ .name = "zv", .module = zv },
    };
    const scenarios = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/interop/main.zig"),
            .target = host,
            .optimize = optimize,
            .imports = imports,
        }),
        .filters = if (filter) |f| &.{f} else &.{},
    });
    const upstream = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/interop/upstream_main.zig"),
            .target = host,
            .optimize = optimize,
            .imports = imports,
        }),
    });

    // The scenarios run against upstream main, in a plain release build and in a release build
    // with debug assertions and overflow checks (so smoltcp's own debug_assert!s fire). cargo is
    // incremental, so its step always runs, and each test run declares the binary as an input.
    const interop_step = b.step("interop", "Run the zmoltcp <-> smoltcp interop scenarios (requires cargo)");
    for ([_][]const u8{ "release", "release-assert" }) |profile| {
        addPeerRun(b, interop_step, scenarios, manifest, host, "master", profile);
    }

    // The upstream-bug probes run against both smoltcp revisions in all three build flavors.
    const upstream_step = b.step("interop-upstream", "Probe smoltcp (08bacc9 and main) with the segments behind the zmoltcp TCP fixes");
    for ([_][]const u8{ "ref", "master" }) |variant| {
        for ([_][]const u8{ "release", "release-assert", "dev" }) |profile| {
            addPeerRun(b, upstream_step, upstream, manifest, host, variant, profile);
        }
    }
}

fn addPeerRun(
    b: *std.Build,
    step: *std.Build.Step,
    tests: *std.Build.Step.Compile,
    manifest: std.Build.LazyPath,
    host: std.Build.ResolvedTarget,
    variant: []const u8,
    profile: []const u8,
) void {
    const peer = addPeerBuild(b, manifest, variant, profile, host);
    const run = b.addRunArtifact(tests);
    run.setName(b.fmt("run {s} (smoltcp {s}, {s})", .{ step.name, variant, profile }));
    run.setCwd(b.path("."));
    run.setEnvironmentVariable("ZMOLTCP_PEER", peer.path);
    run.setEnvironmentVariable("ZMOLTCP_PEER_VARIANT", variant);
    run.setEnvironmentVariable("ZMOLTCP_PEER_PROFILE", profile);
    run.step.dependOn(peer.step);
    run.addFileInput(.{ .cwd_relative = peer.path });
    step.dependOn(&run.step);
}

const PeerBuild = struct { step: *std.Build.Step, path: []const u8 };

/// Build the smoltcp peer for one smoltcp variant (cargo feature `master` or `ref`) and cargo
/// profile into its own target directory, so variants never overwrite each other.
fn addPeerBuild(
    b: *std.Build,
    manifest: std.Build.LazyPath,
    variant: []const u8,
    profile: []const u8,
    host: std.Build.ResolvedTarget,
) PeerBuild {
    const target_dir = b.fmt("tests/interop/peer/target/{s}", .{variant}); // relative to the build root
    const cargo = b.addSystemCommand(&.{ "cargo", "build", "--locked", "--no-default-features", "--manifest-path" });
    cargo.addFileArg(manifest);
    cargo.addArgs(&.{ "--features", variant, "--target-dir", target_dir, "--profile", profile });
    cargo.has_side_effects = true;
    return .{
        .step = &cargo.step,
        .path = b.pathJoin(&.{ target_dir, if (std.mem.eql(u8, profile, "dev")) "debug" else profile, b.fmt("peer{s}", .{host.result.exeFileExt()}) }),
    };
}
