const std = @import("std");

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

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Expose zmoltcp as a module for downstream consumers.
    // Downstream build.zig uses: b.dependency("zmoltcp", .{}).module("zmoltcp")
    const zmoltcp_mod = b.addModule("zmoltcp", .{
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
        .single_threaded = true,
    });
    const unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run zmoltcp unit and conformance tests");
    test_step.dependOn(&run_unit_tests.step);

    // Native fuzzing needs threaded test binaries, and Zig 0.16.0's fuzz
    // runner fails to compile with error traces enabled. Each fuzz build root
    // contains exactly one testing.fuzz call so active fuzzing is deterministic.
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
            .error_tracing = false,
        });
        const fuzz_mod = b.createModule(.{
            .root_source_file = b.path(fuzz_target.path),
            .target = target,
            .optimize = optimize,
            .single_threaded = false,
            .error_tracing = false,
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
