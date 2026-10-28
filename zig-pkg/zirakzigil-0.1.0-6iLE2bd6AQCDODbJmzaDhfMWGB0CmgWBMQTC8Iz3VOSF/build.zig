const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const ghost = b.option(bool, "ghost", "Compile ghost (verification-only) code") orelse false;
    const options = b.addOptions();
    options.addOption(bool, "ghost", ghost);

    // The module dependents import. It carries no target or optimize mode, so
    // it is compiled for whatever the importing artifact targets.
    const zv = b.addModule("zv", .{ .root_source_file = b.path("src/zv.zig") });
    zv.addOptions("zv_options", options);

    // Same source, pinned to this build's target: used by everything below.
    const local = b.createModule(.{ .root_source_file = b.path("src/zv.zig"), .target = target, .optimize = optimize });
    local.addOptions("zv_options", options);

    const test_step = b.step("test", "Run unit tests, example tests and the downstream-consumer check");

    const zv_tests = b.addTest(.{ .root_module = local });
    test_step.dependOn(&b.addRunArtifact(zv_tests).step);

    const examples = [_][]const u8{ "search", "ledger" };
    var example_modules: [examples.len]*std.Build.Module = undefined;
    for (examples, &example_modules) |name, *module| {
        module.* = b.createModule(.{
            .root_source_file = b.path(b.fmt("examples/{s}.zig", .{name})),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "zv", .module = local }},
        });
        const t = b.addTest(.{ .root_module = module.* });
        test_step.dependOn(&b.addRunArtifact(t).step);
    }

    // Programs that must PANIC at runtime (run by tools/run_negative.sh).
    const neg = b.step("negative", "Build should-panic programs");
    for ([_][]const u8{ "double_consume", "stale_handle", "pin_copy", "precondition", "law_oob" }) |name| {
        const exe = b.addExecutable(.{ .name = name, .root_module = b.createModule(.{
            .root_source_file = b.path(b.fmt("tests/should_panic/{s}.zig", .{name})),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zv", .module = local },
                .{ .name = "ledger", .module = example_modules[1] },
            },
        }) });
        neg.dependOn(&b.addInstallArtifact(exe, .{}).step);
    }

    // The Phase 0 gate measurement, demonstrated on the examples.
    const assurance = b.step("assurance", "Print the per-module assurance table for the examples");
    const report = b.addExecutable(.{ .name = "assurance", .root_module = b.createModule(.{
        .root_source_file = b.path("examples/assurance.zig"),
        .target = b.graph.host,
        .imports = &.{
            .{ .name = "zv", .module = local },
            .{ .name = "search", .module = example_modules[0] },
            .{ .name = "ledger", .module = example_modules[1] },
        },
    }) });
    assurance.dependOn(&b.addRunArtifact(report).step);

    // Freestanding gate: zv must not grow an OS dependency.
    const freestanding = b.step("freestanding", "Cross-compile zv for freestanding aarch64 and riscv64");
    for ([_][]const u8{ "aarch64-freestanding-none", "riscv64-freestanding-none" }) |triple| {
        const query = std.Target.Query.parse(.{ .arch_os_abi = triple }) catch unreachable;
        for ([_]std.builtin.OptimizeMode{ .Debug, .ReleaseSafe }) |mode| {
            const obj = b.addObject(.{ .name = "freestanding_smoke", .root_module = b.createModule(.{
                .root_source_file = b.path("tests/freestanding/smoke.zig"),
                .target = b.resolveTargetQuery(query),
                .optimize = mode,
                .imports = &.{.{ .name = "zv", .module = zv }},
            }) });
            freestanding.dependOn(&obj.step);
        }
    }
    test_step.dependOn(freestanding);

    // Downstream-consumer check: a separate project that depends on this one by path.
    const consumer = b.addSystemCommand(&.{ b.graph.zig_exe, "build", "test", "assurance", b.fmt("-Dghost={}", .{ghost}), b.fmt("-Doptimize={t}", .{optimize}) });
    consumer.setCwd(b.path("tests/consumer"));
    consumer.has_side_effects = true;
    const consumer_step = b.step("consumer", "Build and test tests/consumer against this package");
    consumer_step.dependOn(&consumer.step);
    test_step.dependOn(consumer_step);
}
