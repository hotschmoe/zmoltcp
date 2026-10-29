const std = @import("std");
const zirakzigil = @import("zirakzigil");

const FuzzPriority = enum { p0, p1, p2 };

const FuzzTarget = struct {
    step: []const u8,
    path: []const u8,
    description: []const u8,
    priority: FuzzPriority,
};

const fuzz_targets = [_]FuzzTarget{
    .{
        .step = "fuzz-dns",
        .path = "src/fuzz/dns.zig",
        .description = "Run the DNS parser fuzz target",
        .priority = .p0,
    },
    .{
        .step = "fuzz-tcp-header",
        .path = "src/fuzz/tcp_header.zig",
        .description = "Run the TCP header parser fuzz target",
        .priority = .p0,
    },
    .{
        .step = "fuzz-ip-header",
        .path = "src/fuzz/ip_header.zig",
        .description = "Run the IP header parser fuzz target",
        .priority = .p0,
    },
    .{
        .step = "fuzz-ipv6-extension",
        .path = "src/fuzz/ipv6_extension.zig",
        .description = "Run the IPv6 extension parser fuzz target",
        .priority = .p0,
    },
    .{
        .step = "fuzz-stack-ingress",
        .path = "src/fuzz/stack_ingress.zig",
        .description = "Run the stack ingress fuzz target",
        .priority = .p0,
    },
    .{
        .step = "fuzz-reassembly",
        .path = "src/fuzz/reassembly.zig",
        .description = "Run the fragment reassembly fuzz target",
        .priority = .p0,
    },
    .{
        .step = "fuzz-protocol-parsers",
        .path = "src/fuzz/protocol_parsers.zig",
        .description = "Run the protocol parser fuzz target",
        .priority = .p1,
    },
    .{
        .step = "fuzz-rpl-state",
        .path = "src/fuzz/rpl_state.zig",
        .description = "Run the RPL state fuzz target",
        .priority = .p1,
    },
    .{
        .step = "fuzz-storage-streams",
        .path = "src/fuzz/storage_streams.zig",
        .description = "Run the storage operation stream fuzz target",
        .priority = .p2,
    },
    .{
        .step = "fuzz-socket-state",
        .path = "src/fuzz/socket_state.zig",
        .description = "Run the socket state machine fuzz target",
        .priority = .p2,
    },
    .{
        .step = "fuzz-phy-middleware",
        .path = "src/fuzz/phy_middleware.zig",
        .description = "Run the PHY middleware fuzz target",
        .priority = .p2,
    },
};

const demos = [_][]const u8{
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
};

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

    // Native fuzzing needs threaded binaries. Each fuzz root holds exactly one
    // testing.fuzz call so the active fuzz target is deterministic.
    const fuzz_step = b.step("fuzz", "Run all zmoltcp fuzz targets");
    const fuzz_p0_step = b.step("fuzz-p0", "Run P0 fuzz targets");
    const fuzz_p1_step = b.step("fuzz-p1", "Run P1 fuzz targets");
    const fuzz_p2_step = b.step("fuzz-p2", "Run P2 fuzz targets");
    for (fuzz_targets) |fuzz_target| {
        const fuzz_common_mod = b.createModule(.{
            .root_source_file = b.path("src/fuzz.zig"),
            .target = target,
            .optimize = optimize,
            .single_threaded = false,
            .imports = &.{.{ .name = "zv", .module = zv }},
        });
        const fuzz_mod = b.createModule(.{
            .root_source_file = b.path(fuzz_target.path),
            .target = target,
            .optimize = optimize,
            .single_threaded = false,
            .imports = &.{.{ .name = "fuzz_common", .module = fuzz_common_mod }},
        });
        const fuzz_tests = b.addTest(.{
            .name = fuzz_target.step,
            .root_module = fuzz_mod,
        });
        const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
        const target_step = b.step(fuzz_target.step, fuzz_target.description);
        target_step.dependOn(&run_fuzz_tests.step);
        test_step.dependOn(&run_fuzz_tests.step);
        fuzz_step.dependOn(&run_fuzz_tests.step);
        switch (fuzz_target.priority) {
            .p0 => fuzz_p0_step.dependOn(&run_fuzz_tests.step),
            .p1 => fuzz_p1_step.dependOn(&run_fuzz_tests.step),
            .p2 => fuzz_p2_step.dependOn(&run_fuzz_tests.step),
        }
    }

    // Integration demos -- `zig build demo`
    const demo_step = b.step("demo", "Run zmoltcp integration demos");
    for (demos) |path| {
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
    var demo_roots: [demos.len]std.Build.LazyPath = undefined;
    for (demos, &demo_roots) |path, *root| root.* = b.path(path);
    _ = zirakzigil.addAssuranceGate(b, .{
        .report = report,
        .src = b.path("src"),
        .lib_name = "zmoltcp",
        .laws = &.{"laws.zig"},
        .scenarios = &demo_roots,
    });

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
