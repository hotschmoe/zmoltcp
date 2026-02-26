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

        pub const medium: iface_mod.Medium = if (@hasDecl(Device, "medium")) Device.medium else .ethernet;

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

        pub const medium: iface_mod.Medium = if (@hasDecl(Device, "medium")) Device.medium else .ethernet;

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

pub const PcapMode = enum { both, rx_only, tx_only };

/// Wraps a Device and writes pcap-format packet captures via a caller-provided
/// write function. The global pcap header is written lazily on first capture.
/// Timestamps are zero (no clock source available at this layer).
pub fn PcapWriter(comptime Device: type) type {
    return struct {
        const Self = @This();

        pub const medium: iface_mod.Medium = if (@hasDecl(Device, "medium")) Device.medium else .ethernet;

        // Pcap link types
        const LINKTYPE_ETHERNET: u32 = 1;
        const LINKTYPE_RAW: u32 = 101;

        inner: Device,
        write_fn: *const fn ([]const u8) void,
        mode: PcapMode,
        header_written: bool = false,

        pub fn init(inner: Device, write_fn: *const fn ([]const u8) void, mode: PcapMode) Self {
            return .{ .inner = inner, .write_fn = write_fn, .mode = mode };
        }

        pub fn receive(self: *Self) ?[]const u8 {
            const frame = self.inner.receive() orelse return null;
            if (self.mode == .both or self.mode == .rx_only) {
                self.writeGlobalHeader();
                self.writeRecordHeader(frame.len);
                self.write_fn(frame);
            }
            return frame;
        }

        pub fn transmit(self: *Self, frame: []const u8) void {
            if (self.mode == .both or self.mode == .tx_only) {
                self.writeGlobalHeader();
                self.writeRecordHeader(frame.len);
                self.write_fn(frame);
            }
            self.inner.transmit(frame);
        }

        pub fn capabilities() iface_mod.DeviceCapabilities {
            return delegateCapabilities(Device);
        }

        fn writeGlobalHeader(self: *Self) void {
            if (self.header_written) return;
            self.header_written = true;
            var hdr: [24]u8 = undefined;
            writeLeU32(hdr[0..4], 0xa1b2c3d4); // magic
            writeLeU16(hdr[4..6], 2); // version major
            writeLeU16(hdr[6..8], 4); // version minor
            writeLeU32(hdr[8..12], 0); // thiszone
            writeLeU32(hdr[12..16], 0); // sigfigs
            writeLeU32(hdr[16..20], 65535); // snaplen
            const linktype: u32 = if (medium == .ethernet) LINKTYPE_ETHERNET else LINKTYPE_RAW;
            writeLeU32(hdr[20..24], linktype);
            self.write_fn(&hdr);
        }

        fn writeRecordHeader(self: *Self, frame_len: usize) void {
            var rec: [16]u8 = undefined;
            writeLeU32(rec[0..4], 0); // ts_sec
            writeLeU32(rec[4..8], 0); // ts_usec
            const len: u32 = @intCast(frame_len);
            writeLeU32(rec[8..12], len); // incl_len
            writeLeU32(rec[12..16], len); // orig_len
            self.write_fn(&rec);
        }
    };
}

fn writeLeU32(b: *[4]u8, v: u32) void {
    b[0] = @truncate(v);
    b[1] = @truncate(v >> 8);
    b[2] = @truncate(v >> 16);
    b[3] = @truncate(v >> 24);
}

fn writeLeU16(b: *[2]u8, v: u16) void {
    b[0] = @truncate(v);
    b[1] = @truncate(v >> 8);
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

// PcapWriter test helpers
const PcapTestState = struct {
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    fn reset() void {
        pos = 0;
    }

    fn write(data: []const u8) void {
        @memcpy(buf[pos..][0..data.len], data);
        pos += data.len;
    }

    fn written() []const u8 {
        return buf[0..pos];
    }
};

fn readLeU32(b: []const u8) u32 {
    return @as(u32, b[0]) | @as(u32, b[1]) << 8 | @as(u32, b[2]) << 16 | @as(u32, b[3]) << 24;
}

fn readLeU16(b: []const u8) u16 {
    return @as(u16, b[0]) | @as(u16, b[1]) << 8;
}

test "PcapWriter writes global header on first receive" {
    PcapTestState.reset();
    var pcap = PcapWriter(TestDevice).init(TestDevice.init(), &PcapTestState.write, .both);
    pcap.inner.enqueueRx(&[_]u8{ 1, 2, 3 });
    _ = pcap.receive();

    const out = PcapTestState.written();
    // global header (24) + record header (16) + frame (3) = 43
    try testing.expectEqual(@as(usize, 43), out.len);
    try testing.expectEqual(@as(u32, 0xa1b2c3d4), readLeU32(out[0..4]));
    try testing.expectEqual(@as(u16, 2), readLeU16(out[4..6]));
    try testing.expectEqual(@as(u16, 4), readLeU16(out[6..8]));
    try testing.expectEqual(@as(u32, 65535), readLeU32(out[16..20]));
    // Ethernet linktype
    try testing.expectEqual(@as(u32, 1), readLeU32(out[20..24]));
}

test "PcapWriter global header written only once" {
    PcapTestState.reset();
    var pcap = PcapWriter(TestDevice).init(TestDevice.init(), &PcapTestState.write, .both);
    pcap.inner.enqueueRx(&[_]u8{ 1, 2, 3 });
    _ = pcap.receive();
    pcap.inner.enqueueRx(&[_]u8{ 4, 5 });
    _ = pcap.receive();

    const out = PcapTestState.written();
    // 24 (global) + 16+3 (first) + 16+2 (second) = 61
    try testing.expectEqual(@as(usize, 61), out.len);
}

test "PcapWriter captures rx frame data" {
    PcapTestState.reset();
    var pcap = PcapWriter(TestDevice).init(TestDevice.init(), &PcapTestState.write, .both);
    pcap.inner.enqueueRx(&[_]u8{ 0xAA, 0xBB, 0xCC });
    const frame = pcap.receive();
    try testing.expect(frame != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, frame.?);

    const out = PcapTestState.written();
    // record header at offset 24, frame at offset 40
    try testing.expectEqual(@as(u32, 3), readLeU32(out[32..36])); // incl_len
    try testing.expectEqual(@as(u32, 3), readLeU32(out[36..40])); // orig_len
    try testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, out[40..43]);
}

test "PcapWriter captures tx frame" {
    PcapTestState.reset();
    var pcap = PcapWriter(TestDevice).init(TestDevice.init(), &PcapTestState.write, .both);
    pcap.transmit(&[_]u8{ 0xDE, 0xAD });

    const out = PcapTestState.written();
    // 24 (global) + 16 (record) + 2 (frame) = 42
    try testing.expectEqual(@as(usize, 42), out.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, out[40..42]);

    // Inner device should have received the frame
    const inner_frame = pcap.inner.dequeueTx();
    try testing.expect(inner_frame != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD }, inner_frame.?);
}

test "PcapWriter rx_only mode ignores tx" {
    PcapTestState.reset();
    var pcap = PcapWriter(TestDevice).init(TestDevice.init(), &PcapTestState.write, .rx_only);
    pcap.transmit(&[_]u8{ 1, 2, 3 });
    try testing.expectEqual(@as(usize, 0), PcapTestState.pos);

    pcap.inner.enqueueRx(&[_]u8{ 4, 5, 6 });
    _ = pcap.receive();
    try testing.expect(PcapTestState.pos > 0);
}

test "PcapWriter tx_only mode ignores rx" {
    PcapTestState.reset();
    var pcap = PcapWriter(TestDevice).init(TestDevice.init(), &PcapTestState.write, .tx_only);
    pcap.inner.enqueueRx(&[_]u8{ 1, 2, 3 });
    _ = pcap.receive();
    try testing.expectEqual(@as(usize, 0), PcapTestState.pos);

    pcap.transmit(&[_]u8{ 4, 5, 6 });
    try testing.expect(PcapTestState.pos > 0);
}

test "PcapWriter composes with Tracer" {
    PcapTestState.reset();
    const noop_trace = struct {
        fn trace(_: Tracer(TestDevice).Direction, _: []const u8) void {}
    }.trace;
    const TracedDevice = Tracer(TestDevice);
    var pcap = PcapWriter(TracedDevice).init(
        TracedDevice.init(TestDevice.init(), &noop_trace),
        &PcapTestState.write,
        .both,
    );
    pcap.inner.inner.enqueueRx(&[_]u8{ 7, 8, 9 });
    const frame = pcap.receive();
    try testing.expect(frame != null);
    try testing.expectEqualSlices(u8, &[_]u8{ 7, 8, 9 }, frame.?);
    try testing.expect(PcapTestState.pos > 0);
}
