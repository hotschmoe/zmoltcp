// Time structures for TCP timers and scheduling.
//
// Instant represents absolute time, Duration represents relative time.
// Both wrap i64 microseconds, matching smoltcp's time module.
//
// [smoltcp:time.rs]

const std = @import("std");

pub const Instant = struct {
    micros: i64,

    pub const ZERO: Instant = .{ .micros = 0 };

    pub fn fromMicros(micros: i64) Instant {
        return .{ .micros = micros };
    }

    pub fn fromMillis(ms: i64) Instant {
        return .{ .micros = ms * 1000 };
    }

    pub fn fromSecs(s: i64) Instant {
        return .{ .micros = s * 1_000_000 };
    }

    pub fn totalMicros(self: Instant) i64 {
        return self.micros;
    }

    pub fn totalMillis(self: Instant) i64 {
        return @divTrunc(self.micros, 1000);
    }

    pub fn secs(self: Instant) i64 {
        return @divTrunc(self.micros, 1_000_000);
    }

    pub fn millis(self: Instant) i64 {
        return @mod(@divTrunc(self.micros, 1000), 1000);
    }

    pub fn add(self: Instant, d: Duration) Instant {
        return .{ .micros = self.micros + d.micros };
    }

    pub fn sub(self: Instant, d: Duration) Instant {
        return .{ .micros = self.micros - d.micros };
    }

    pub fn diff(self: Instant, other: Instant) Duration {
        const delta = self.micros - other.micros;
        return .{ .micros = if (delta >= 0) delta else -delta };
    }

    pub fn cmp(self: Instant, other: Instant) std.math.Order {
        return std.math.order(self.micros, other.micros);
    }

    pub fn lessThan(self: Instant, other: Instant) bool {
        return self.micros < other.micros;
    }

    pub fn greaterThanOrEqual(self: Instant, other: Instant) bool {
        return self.micros >= other.micros;
    }

    pub fn eql(self: Instant, other: Instant) bool {
        return self.micros == other.micros;
    }
};

pub const Duration = struct {
    micros: i64,

    pub const ZERO: Duration = .{ .micros = 0 };

    pub fn fromMicros(micros: i64) Duration {
        return .{ .micros = micros };
    }

    pub fn fromMillis(ms: i64) Duration {
        return .{ .micros = ms * 1000 };
    }

    pub fn fromSecs(s: i64) Duration {
        return .{ .micros = s * 1_000_000 };
    }

    pub fn totalMicros(self: Duration) i64 {
        return self.micros;
    }

    pub fn totalMillis(self: Duration) i64 {
        return @divTrunc(self.micros, 1000);
    }

    pub fn secs(self: Duration) i64 {
        return @divTrunc(self.micros, 1_000_000);
    }

    pub fn millis(self: Duration) i64 {
        return @mod(@divTrunc(self.micros, 1000), 1000);
    }

    pub fn add(self: Duration, other: Duration) Duration {
        return .{ .micros = self.micros + other.micros };
    }

    pub fn subSaturating(self: Duration, other: Duration) Duration {
        const result = self.micros - other.micros;
        return .{ .micros = if (result >= 0) result else 0 };
    }

    pub fn mul(self: Duration, factor: u32) Duration {
        return .{ .micros = self.micros * @as(i64, factor) };
    }

    pub fn divFloor(self: Duration, divisor: u32) Duration {
        return .{ .micros = @divTrunc(self.micros, @as(i64, divisor)) };
    }

    pub fn shl(self: Duration, shift: u5) Duration {
        return .{ .micros = self.micros << shift };
    }

    pub fn min(self: Duration, other: Duration) Duration {
        return if (self.micros <= other.micros) self else other;
    }

    pub fn max(self: Duration, other: Duration) Duration {
        return if (self.micros >= other.micros) self else other;
    }

    pub fn clamp(self: Duration, lower: Duration, upper: Duration) Duration {
        return self.max(lower).min(upper);
    }

    pub fn lessThan(self: Duration, other: Duration) bool {
        return self.micros < other.micros;
    }

    pub fn greaterThanOrEqual(self: Duration, other: Duration) bool {
        return self.micros >= other.micros;
    }

    pub fn eql(self: Duration, other: Duration) bool {
        return self.micros == other.micros;
    }
};

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;

// [smoltcp:time.rs:test_instant_ops]
test "instant arithmetic" {
    const a = Instant.fromMillis(4);
    const b = a.add(Duration.fromMillis(6));
    try testing.expectEqual(@as(i64, 10), b.totalMillis());

    const c = Instant.fromMillis(7);
    const d = c.sub(Duration.fromMillis(5));
    try testing.expectEqual(@as(i64, 2), d.totalMillis());
}

// [smoltcp:time.rs:test_instant_getters]
test "instant getters" {
    const instant = Instant.fromMillis(5674);
    try testing.expectEqual(@as(i64, 5), instant.secs());
    try testing.expectEqual(@as(i64, 674), instant.millis());
    try testing.expectEqual(@as(i64, 5674), instant.totalMillis());
}

// [smoltcp:time.rs:test_duration_ops]
test "duration arithmetic" {
    const d1 = Duration.fromMillis(40).add(Duration.fromMillis(2));
    try testing.expectEqual(@as(i64, 42), d1.totalMillis());

    const d2 = Duration.fromMillis(555).subSaturating(Duration.fromMillis(42));
    try testing.expectEqual(@as(i64, 513), d2.totalMillis());

    const d3 = Duration.fromMillis(13).mul(22);
    try testing.expectEqual(@as(i64, 286), d3.totalMillis());

    const d4 = Duration.fromMillis(53).divFloor(4);
    try testing.expectEqual(@as(i64, 13250), d4.totalMicros());
}

// [smoltcp:time.rs:test_duration_getters]
test "duration getters" {
    const d = Duration.fromMillis(4934);
    try testing.expectEqual(@as(i64, 4), d.secs());
    try testing.expectEqual(@as(i64, 934), d.millis());
    try testing.expectEqual(@as(i64, 4934), d.totalMillis());
}

test "instant diff" {
    const a = Instant.fromMillis(10);
    const b = Instant.fromMillis(3);
    const d = a.diff(b);
    try testing.expectEqual(@as(i64, 7), d.totalMillis());
    const d2 = b.diff(a);
    try testing.expectEqual(@as(i64, 7), d2.totalMillis());
}

test "instant comparison" {
    const a = Instant.fromMillis(5);
    const b = Instant.fromMillis(10);
    try testing.expect(a.lessThan(b));
    try testing.expect(!b.lessThan(a));
    try testing.expect(b.greaterThanOrEqual(a));
    try testing.expect(a.eql(a));
}

test "duration clamp" {
    const d = Duration.fromMillis(50);
    const clamped = d.clamp(Duration.fromMillis(100), Duration.fromMillis(200));
    try testing.expectEqual(@as(i64, 100), clamped.totalMillis());

    const d2 = Duration.fromMillis(300);
    const clamped2 = d2.clamp(Duration.fromMillis(100), Duration.fromMillis(200));
    try testing.expectEqual(@as(i64, 200), clamped2.totalMillis());

    const d3 = Duration.fromMillis(150);
    const clamped3 = d3.clamp(Duration.fromMillis(100), Duration.fromMillis(200));
    try testing.expectEqual(@as(i64, 150), clamped3.totalMillis());
}

test "duration saturating subtract" {
    const d = Duration.fromMillis(0).subSaturating(Duration.fromMillis(1));
    try testing.expectEqual(@as(i64, 0), d.totalMillis());
}
