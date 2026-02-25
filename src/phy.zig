// PHY middleware: device wrappers for debugging and testing.
//
// Tracer(Device) logs every frame through a caller-provided callback.
// FaultInjector(Device) drops or corrupts frames at configurable rates.
//
// Both wrap any Device type and forward the Device interface, so they
// compose: `FaultInjector(Tracer(LoopbackDevice(8)))` is valid.
//
// Reference: smoltcp src/phy/tracer.rs, src/phy/fault_injector.rs

const iface_mod = @import("iface.zig");

const MAX_FRAME_LEN = 1514;

fn delegateCapabilities(comptime Device: type) iface_mod.DeviceCapabilities {
    if (@hasDecl(Device, "capabilities")) return Device.capabilities();
    return .{};
}

fn hitPercent(r: u32, comptime shift: u5, threshold: u8) bool {
    return @as(u8, @truncate(r >> shift)) % 100 < threshold;
}

/// Wraps a Device and calls `trace_fn` with every frame that passes
/// through receive() or transmit(). The callback receives the raw
/// Ethernet frame bytes.
pub fn Tracer(comptime Device: type) type {
    return struct {
        const Self = @This();

        inner: Device,
        trace_fn: *const fn (direction: Direction, frame: []const u8) void,

        pub const Direction = enum { rx, tx };

        pub fn init(inner: Device, trace_fn: *const fn (Direction, []const u8) void) Self {
            return .{ .inner = inner, .trace_fn = trace_fn };
        }

        pub fn receive(self: *Self) ?[]const u8 {
            const frame = self.inner.receive() orelse return null;
            self.trace_fn(.rx, frame);
            return frame;
        }

        pub fn transmit(self: *Self, frame: []const u8) void {
            self.trace_fn(.tx, frame);
            self.inner.transmit(frame);
        }

        pub fn capabilities() iface_mod.DeviceCapabilities {
            return delegateCapabilities(Device);
        }
    };
}

/// Wraps a Device and randomly drops or corrupts frames based on
/// configurable per-direction percentages. Uses a caller-provided
/// RNG function (returns u32) for all randomness.
pub fn FaultInjector(comptime Device: type) type {
    return struct {
        const Self = @This();

        inner: Device,
        config: Config,
        rng_fn: *const fn () u32,
        scratch: [MAX_FRAME_LEN]u8 = undefined,

        pub const Config = struct {
            rx_drop_pct: u8 = 0,
            tx_drop_pct: u8 = 0,
            rx_corrupt_pct: u8 = 0,
            tx_corrupt_pct: u8 = 0,
        };

        pub fn init(inner: Device, config: Config, rng_fn: *const fn () u32) Self {
            return .{ .inner = inner, .config = config, .rng_fn = rng_fn };
        }

        pub fn receive(self: *Self) ?[]const u8 {
            const frame = self.inner.receive() orelse return null;
            const r = self.rng_fn();
            if (hitPercent(r, 0, self.config.rx_drop_pct)) return null;
            if (hitPercent(r, 8, self.config.rx_corrupt_pct)) return self.corrupt(frame, r);
            return frame;
        }

        pub fn transmit(self: *Self, frame: []const u8) void {
            const r = self.rng_fn();
            if (hitPercent(r, 0, self.config.tx_drop_pct)) return;
            if (hitPercent(r, 8, self.config.tx_corrupt_pct)) {
                self.inner.transmit(self.corrupt(frame, r));
                return;
            }
            self.inner.transmit(frame);
        }

        pub fn capabilities() iface_mod.DeviceCapabilities {
            return delegateCapabilities(Device);
        }

        fn corrupt(self: *Self, frame: []const u8, r: u32) []const u8 {
            if (frame.len == 0) return frame;
            @memcpy(self.scratch[0..frame.len], frame);
            const pos = @as(usize, r >> 16) % frame.len;
            self.scratch[pos] ^= 0xFF;
            return self.scratch[0..frame.len];
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;
const stack_mod = @import("stack.zig");
const TestDevice = stack_mod.LoopbackDevice(8);

test "Tracer forwards receive and transmit" {
    const S = struct {
        var rx_count: usize = 0;
        var tx_count: usize = 0;

        fn trace(dir: Tracer(TestDevice).Direction, _: []const u8) void {
            switch (dir) {
                .rx => rx_count += 1,
                .tx => tx_count += 1,
            }
        }
    };
    S.rx_count = 0;
    S.tx_count = 0;

    var traced = Tracer(TestDevice).init(TestDevice.init(), &S.trace);
    traced.inner.enqueueRx(&[_]u8{ 1, 2, 3 });

    const frame = traced.receive();
    try testing.expect(frame != null);
    try testing.expectEqual(@as(usize, 1), S.rx_count);

    traced.transmit(&[_]u8{ 4, 5, 6 });
    try testing.expectEqual(@as(usize, 1), S.tx_count);

    const tx_frame = traced.inner.dequeueTx();
    try testing.expect(tx_frame != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 4, 5, 6 }, tx_frame.?);
}

test "Tracer returns null when inner has no frames" {
    var traced = Tracer(TestDevice).init(TestDevice.init(), &struct {
        fn trace(_: Tracer(TestDevice).Direction, _: []const u8) void {}
    }.trace);
    try testing.expectEqual(@as(?[]const u8, null), traced.receive());
}

test "FaultInjector drops rx frames at configured rate" {
    const S = struct {
        fn alwaysDrop() u32 {
            return 0; // 0 % 100 == 0 < any positive drop_pct
        }
    };
    var fi = FaultInjector(TestDevice).init(
        TestDevice.init(),
        .{ .rx_drop_pct = 50 },
        &S.alwaysDrop,
    );
    fi.inner.enqueueRx(&[_]u8{ 1, 2, 3 });

    // RNG returns 0, so 0 % 100 == 0 < 50 => dropped.
    try testing.expectEqual(@as(?[]const u8, null), fi.receive());
}

test "FaultInjector passes rx frames when rng above threshold" {
    const S = struct {
        fn neverDrop() u32 {
            return 99; // 99 % 100 == 99 >= any pct < 100
        }
    };
    var fi = FaultInjector(TestDevice).init(
        TestDevice.init(),
        .{ .rx_drop_pct = 50 },
        &S.neverDrop,
    );
    fi.inner.enqueueRx(&[_]u8{ 1, 2, 3 });

    const frame = fi.receive();
    try testing.expect(frame != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, frame.?);
}

test "FaultInjector drops tx frames at configured rate" {
    const S = struct {
        fn alwaysDrop() u32 {
            return 0;
        }
    };
    var fi = FaultInjector(TestDevice).init(
        TestDevice.init(),
        .{ .tx_drop_pct = 50 },
        &S.alwaysDrop,
    );
    fi.transmit(&[_]u8{ 1, 2, 3 });

    // Frame should be dropped, inner device should have no TX frames.
    try testing.expectEqual(@as(?[]const u8, null), fi.inner.dequeueTx());
}

test "FaultInjector corrupts rx frame" {
    const S = struct {
        fn triggerCorrupt() u32 {
            // low byte: 99 (99 % 100 = 99 >= 0 drop_pct, no drop)
            // second byte: 0 (0 % 100 = 0 < 50 corrupt_pct, corrupt)
            // third+fourth bytes: position and flip
            return 0x0100_0063;
        }
    };
    var fi = FaultInjector(TestDevice).init(
        TestDevice.init(),
        .{ .rx_corrupt_pct = 50 },
        &S.triggerCorrupt,
    );
    fi.inner.enqueueRx(&[_]u8{ 0xAA, 0xBB, 0xCC });

    const frame = fi.receive() orelse return error.ExpectedFrame;
    try testing.expectEqual(@as(usize, 3), frame.len);

    // At least one byte should differ from original.
    const differs = frame[0] != 0xAA or frame[1] != 0xBB or frame[2] != 0xCC;
    try testing.expect(differs);
}

test "FaultInjector corrupts tx frame" {
    const S = struct {
        fn triggerCorrupt() u32 {
            return 0x0100_0063; // same logic as rx corrupt test
        }
    };
    var fi = FaultInjector(TestDevice).init(
        TestDevice.init(),
        .{ .tx_corrupt_pct = 50 },
        &S.triggerCorrupt,
    );
    fi.transmit(&[_]u8{ 0xAA, 0xBB, 0xCC });

    const tx_frame = fi.inner.dequeueTx() orelse return error.ExpectedFrame;
    try testing.expectEqual(@as(usize, 3), tx_frame.len);

    const differs = tx_frame[0] != 0xAA or tx_frame[1] != 0xBB or tx_frame[2] != 0xCC;
    try testing.expect(differs);
}

test "FaultInjector zero config passes everything through" {
    const S = struct {
        fn anyRng() u32 {
            return 42;
        }
    };
    var fi = FaultInjector(TestDevice).init(
        TestDevice.init(),
        .{},
        &S.anyRng,
    );
    fi.inner.enqueueRx(&[_]u8{ 1, 2, 3 });

    const frame = fi.receive();
    try testing.expect(frame != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3 }, frame.?);

    fi.transmit(&[_]u8{ 4, 5, 6 });
    const tx = fi.inner.dequeueTx();
    try testing.expect(tx != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 4, 5, 6 }, tx.?);
}

test "Tracer and FaultInjector compose" {
    const noop_trace = struct {
        fn trace(_: Tracer(TestDevice).Direction, _: []const u8) void {}
    }.trace;
    const noop_rng = struct {
        fn rng() u32 {
            return 99;
        }
    }.rng;

    // FaultInjector wrapping Tracer wrapping TestDevice.
    const TracedDevice = Tracer(TestDevice);
    var fi = FaultInjector(TracedDevice).init(
        TracedDevice.init(TestDevice.init(), &noop_trace),
        .{},
        &noop_rng,
    );
    fi.inner.inner.enqueueRx(&[_]u8{ 7, 8, 9 });

    const frame = fi.receive();
    try testing.expect(frame != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 7, 8, 9 }, frame.?);
}
