// RPL state machine components (RFC 6550, RFC 6552, RFC 6206).
//
// Contains: SequenceCounter (lollipop), Rank, ObjectiveFunction0,
// ParentSet, Relations routing table, TrickleTimer.
//
// Reference: smoltcp src/iface/rpl/

const std = @import("std");
const time = @import("time.zig");

// ---------------------------------------------------------------------------
// Constants (RFC 6550)
// ---------------------------------------------------------------------------

pub const SEQUENCE_WINDOW: u8 = 16;
pub const DEFAULT_MIN_HOP_RANK_INCREASE: u16 = 256;
pub const DEFAULT_DIO_INTERVAL_MIN: u32 = 12;
pub const DEFAULT_DIO_REDUNDANCY_CONSTANT: u8 = 10;
pub const DEFAULT_DIO_INTERVAL_DOUBLINGS: u32 = 8;

// ---------------------------------------------------------------------------
// SequenceCounter (RFC 6550 S7.2 -- Lollipop Counter)
// ---------------------------------------------------------------------------

pub const SequenceCounter = struct {
    value: u8,

    pub const INIT = SequenceCounter{ .value = 240 };

    pub fn increment(self: *SequenceCounter) void {
        const max_val: u8 = if (self.value >= 128) 255 else 127;
        self.value = if (self.value >= max_val) 0 else self.value + 1;
    }

    /// Partial ordering per RFC 6550 S7.2.
    /// Returns null when values are uncomparable (too far apart in same region).
    pub fn order(a: SequenceCounter, b: SequenceCounter) ?std.math.Order {
        if (a.value == b.value) return .eq;

        const a_linear = a.value >= 128;
        const b_linear = b.value >= 128;

        if (a_linear and !b_linear) {
            const gap = @as(u16, 256) + @as(u16, b.value) - @as(u16, a.value);
            if (gap <= SEQUENCE_WINDOW) return .lt;
            return .gt;
        }
        if (!a_linear and b_linear) {
            const gap = @as(u16, 256) + @as(u16, a.value) - @as(u16, b.value);
            if (gap <= SEQUENCE_WINDOW) return .gt;
            return .lt;
        }

        // Same region
        const diff = if (a.value > b.value) a.value - b.value else b.value - a.value;
        if (diff > SEQUENCE_WINDOW) return null;
        if (a.value > b.value) return .gt;
        return .lt;
    }
};

// ---------------------------------------------------------------------------
// Rank (RFC 6550 S3.5.1)
// ---------------------------------------------------------------------------

pub const Rank = struct {
    value: u16,
    min_hop_rank_increase: u16,

    pub const ROOT = Rank{ .value = DEFAULT_MIN_HOP_RANK_INCREASE, .min_hop_rank_increase = DEFAULT_MIN_HOP_RANK_INCREASE };
    pub const INFINITE = Rank{ .value = 0xFFFF, .min_hop_rank_increase = DEFAULT_MIN_HOP_RANK_INCREASE };

    pub fn dagRank(self: Rank) u16 {
        return self.value / self.min_hop_rank_increase;
    }

    pub fn order(a: Rank, b: Rank) std.math.Order {
        return std.math.order(a.dagRank(), b.dagRank());
    }
};

// ---------------------------------------------------------------------------
// Objective Function 0 (RFC 6552)
// ---------------------------------------------------------------------------

pub const ObjectiveFunction0 = struct {
    pub const OCP: u16 = 0;
    const RANK_STEP: u16 = 3;
    const RANK_FACTOR: u16 = 1;
    const RANK_STRETCH: u16 = 0;

    pub fn computeRank(parent_rank: Rank) Rank {
        const increase = (RANK_FACTOR * RANK_STEP + RANK_STRETCH) * parent_rank.min_hop_rank_increase;
        return .{
            .value = parent_rank.value +| increase,
            .min_hop_rank_increase = parent_rank.min_hop_rank_increase,
        };
    }

    pub fn preferredParent(comptime max: usize, set: *const ParentSet(max)) ?usize {
        var best_idx: ?usize = null;
        var best_dag_rank: u16 = 0xFFFF;
        for (set.entries, 0..) |entry, i| {
            if (entry) |e| {
                const dr = e.parent.rank.dagRank();
                if (dr < best_dag_rank) {
                    best_dag_rank = dr;
                    best_idx = i;
                }
            }
        }
        return best_idx;
    }
};

// ---------------------------------------------------------------------------
// ParentSet
// ---------------------------------------------------------------------------

pub const Parent = struct {
    rank: Rank,
    preference: u8,
    version_number: SequenceCounter,
    dodag_id: [16]u8,
};

pub fn ParentSet(comptime max_parents: usize) type {
    return struct {
        const Self = @This();
        pub const Entry = struct { addr: [16]u8, parent: Parent };

        entries: [max_parents]?Entry = .{null} ** max_parents,

        pub fn add(self: *Self, addr: [16]u8, parent: Parent) bool {
            for (&self.entries) |*slot| {
                if (slot.*) |*e| {
                    if (std.mem.eql(u8, &e.addr, &addr)) {
                        e.parent = parent;
                        return true;
                    }
                }
            }
            for (&self.entries) |*slot| {
                if (slot.* == null) {
                    slot.* = .{ .addr = addr, .parent = parent };
                    return true;
                }
            }
            const worst = self.worstParent() orelse return false;
            if (parent.rank.dagRank() < self.entries[worst].?.parent.rank.dagRank()) {
                self.entries[worst] = .{ .addr = addr, .parent = parent };
                return true;
            }
            return false;
        }

        pub fn find(self: *const Self, addr: [16]u8) ?*const Parent {
            for (&self.entries) |*slot| {
                if (slot.*) |*e| {
                    if (std.mem.eql(u8, &e.addr, &addr)) return &e.parent;
                }
            }
            return null;
        }

        pub fn remove(self: *Self, addr: [16]u8) bool {
            for (&self.entries) |*slot| {
                if (slot.*) |e| {
                    if (std.mem.eql(u8, &e.addr, &addr)) {
                        slot.* = null;
                        return true;
                    }
                }
            }
            return false;
        }

        pub fn worstParent(self: *const Self) ?usize {
            var worst_idx: ?usize = null;
            var worst_dag_rank: u16 = 0;
            for (self.entries, 0..) |entry, i| {
                if (entry) |e| {
                    const dr = e.parent.rank.dagRank();
                    if (dr >= worst_dag_rank) {
                        worst_dag_rank = dr;
                        worst_idx = i;
                    }
                }
            }
            return worst_idx;
        }

        pub fn count(self: *const Self) usize {
            var n: usize = 0;
            for (self.entries) |e| {
                if (e != null) n += 1;
            }
            return n;
        }
    };
}

// ---------------------------------------------------------------------------
// Relations (Routing Table)
// ---------------------------------------------------------------------------

pub const Relation = struct {
    destination: [16]u8,
    next_hop: [16]u8,
    expiration: time.Instant,
};

pub fn Relations(comptime max_relations: usize) type {
    return struct {
        const Self = @This();

        entries: [max_relations]?Relation = .{null} ** max_relations,

        pub fn addRelation(self: *Self, dest: [16]u8, next_hop: [16]u8, exp: time.Instant) bool {
            for (&self.entries) |*slot| {
                if (slot.*) |*r| {
                    if (std.mem.eql(u8, &r.destination, &dest)) {
                        r.next_hop = next_hop;
                        r.expiration = exp;
                        return true;
                    }
                }
            }
            for (&self.entries) |*slot| {
                if (slot.* == null) {
                    slot.* = .{ .destination = dest, .next_hop = next_hop, .expiration = exp };
                    return true;
                }
            }
            return false;
        }

        pub fn removeRelation(self: *Self, dest: [16]u8) bool {
            for (&self.entries) |*slot| {
                if (slot.*) |r| {
                    if (std.mem.eql(u8, &r.destination, &dest)) {
                        slot.* = null;
                        return true;
                    }
                }
            }
            return false;
        }

        pub fn findNextHop(self: *const Self, dest: [16]u8) ?[16]u8 {
            for (self.entries) |entry| {
                if (entry) |r| {
                    if (std.mem.eql(u8, &r.destination, &dest)) return r.next_hop;
                }
            }
            return null;
        }

        pub fn purge(self: *Self, now: time.Instant) void {
            for (&self.entries) |*slot| {
                if (slot.*) |r| {
                    if (r.expiration.lessThan(now) or r.expiration.eql(now)) {
                        slot.* = null;
                    }
                }
            }
        }

        pub fn count(self: *const Self) usize {
            var n: usize = 0;
            for (self.entries) |e| {
                if (e != null) n += 1;
            }
            return n;
        }
    };
}

// ---------------------------------------------------------------------------
// TrickleTimer (RFC 6206)
// ---------------------------------------------------------------------------

pub const TrickleTimer = struct {
    i_min_exp: u32,
    i_max_exp: u32,
    k: u8,
    i_exp: u32,
    counter: u8,
    t_expiration: time.Instant,
    i_expiration: time.Instant,

    pub fn init(i_min: u32, i_doublings: u32, k: u8, now: time.Instant, rand: u32) TrickleTimer {
        const i_max = i_min + i_doublings;
        var timer = TrickleTimer{
            .i_min_exp = i_min,
            .i_max_exp = i_max,
            .k = k,
            .i_exp = i_min,
            .counter = 0,
            .t_expiration = now,
            .i_expiration = now,
        };
        timer.resetInterval(now, rand);
        return timer;
    }

    pub fn poll(self: *TrickleTimer, now: time.Instant, rand: u32) bool {
        var should_tx = false;

        if (self.t_expiration.lessThan(now) or self.t_expiration.eql(now)) {
            if (self.k == 0 or self.counter < self.k) {
                should_tx = true;
            }
        }

        if (self.i_expiration.lessThan(now) or self.i_expiration.eql(now)) {
            if (self.i_exp < self.i_max_exp) {
                self.i_exp += 1;
            }
            self.counter = 0;
            self.resetInterval(now, rand);
        }

        return should_tx;
    }

    pub fn hearConsistent(self: *TrickleTimer) void {
        self.counter +|= 1;
    }

    pub fn hearInconsistency(self: *TrickleTimer, now: time.Instant, rand: u32) void {
        if (self.i_exp > self.i_min_exp) {
            self.i_exp = self.i_min_exp;
            self.counter = 0;
            self.resetInterval(now, rand);
        }
    }

    pub fn pollAt(self: *const TrickleTimer) time.Instant {
        if (self.t_expiration.lessThan(self.i_expiration))
            return self.t_expiration
        else
            return self.i_expiration;
    }

    fn resetInterval(self: *TrickleTimer, now: time.Instant, rand: u32) void {
        const i_ms = intervalMs(self.i_exp);
        const half = i_ms / 2;
        const t_offset = if (half > 0) half + (rand % half) else 0;
        self.t_expiration = now.add(time.Duration.fromMillis(@intCast(t_offset)));
        self.i_expiration = now.add(time.Duration.fromMillis(@intCast(i_ms)));
    }

    fn intervalMs(exp: u32) u64 {
        if (exp >= 64) return std.math.maxInt(u64);
        return @as(u64, 1) << @intCast(exp);
    }
};

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;

fn testAddr(last_byte: u8) [16]u8 {
    return .{ 0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last_byte };
}

fn testParent(rank_value: u16) Parent {
    return .{
        .rank = .{ .value = rank_value, .min_hop_rank_increase = DEFAULT_MIN_HOP_RANK_INCREASE },
        .preference = 0,
        .version_number = SequenceCounter.INIT,
        .dodag_id = .{0} ** 16,
    };
}

// -- SequenceCounter tests --

// [smoltcp:lollipop.rs:sequence_counter_increment]
test "sequence counter increment wraps linear 255 to 0" {
    var seq = SequenceCounter{ .value = 253 };
    seq.increment();
    try testing.expectEqual(@as(u8, 254), seq.value);
    seq.increment();
    try testing.expectEqual(@as(u8, 255), seq.value);
    seq.increment();
    try testing.expectEqual(@as(u8, 0), seq.value);
}

// [smoltcp:lollipop.rs:sequence_counter_increment]
test "sequence counter increment wraps circular 127 to 0" {
    var seq = SequenceCounter{ .value = 126 };
    seq.increment();
    try testing.expectEqual(@as(u8, 127), seq.value);
    seq.increment();
    try testing.expectEqual(@as(u8, 0), seq.value);
}

test "sequence counter increment in linear region" {
    var seq = SequenceCounter{ .value = 240 };
    seq.increment();
    try testing.expectEqual(@as(u8, 241), seq.value);
}

test "sequence counter increment in circular region" {
    var seq = SequenceCounter{ .value = 5 };
    seq.increment();
    try testing.expectEqual(@as(u8, 6), seq.value);
}

// [smoltcp:lollipop.rs:sequence_counter_comparison]
test "sequence counter ordering same region" {
    try testing.expectEqual(@as(?std.math.Order, .gt), SequenceCounter.order(.{ .value = 121 }, .{ .value = 120 }));
    try testing.expectEqual(@as(?std.math.Order, .lt), SequenceCounter.order(.{ .value = 120 }, .{ .value = 121 }));
    try testing.expectEqual(@as(?std.math.Order, .eq), SequenceCounter.order(.{ .value = 120 }, .{ .value = 120 }));
    try testing.expectEqual(@as(?std.math.Order, .lt), SequenceCounter.order(.{ .value = 240 }, .{ .value = 241 }));
    try testing.expectEqual(@as(?std.math.Order, .gt), SequenceCounter.order(.{ .value = 241 }, .{ .value = 240 }));
    try testing.expectEqual(@as(?std.math.Order, .eq), SequenceCounter.order(.{ .value = 240 }, .{ .value = 240 }));
}

// [smoltcp:lollipop.rs:sequence_counter_comparison]
test "sequence counter ordering cross-region" {
    // 240 is far from 5 in wrap distance: 256+5-240=21 > 16, so 240 > 5
    try testing.expectEqual(@as(?std.math.Order, .gt), SequenceCounter.order(.{ .value = 240 }, .{ .value = 5 }));
    // 250 is close to 5 in wrap distance: 256+5-250=11 <= 16, so 250 < 5
    try testing.expectEqual(@as(?std.math.Order, .lt), SequenceCounter.order(.{ .value = 250 }, .{ .value = 5 }));
    // Reverse of above
    try testing.expectEqual(@as(?std.math.Order, .gt), SequenceCounter.order(.{ .value = 5 }, .{ .value = 250 }));
    // Cross-region: circular 127, linear 129: 256+127-129=254 > 16 => 127 < 129
    try testing.expectEqual(@as(?std.math.Order, .lt), SequenceCounter.order(.{ .value = 127 }, .{ .value = 129 }));
}

// [smoltcp:lollipop.rs:sequence_counter_comparison]
test "sequence counter ordering uncomparable" {
    // 130 and 241 are both in linear region, diff=111 > 16
    try testing.expectEqual(@as(?std.math.Order, null), SequenceCounter.order(.{ .value = 130 }, .{ .value = 241 }));
}

// -- Rank tests --

// [smoltcp:rank.rs:calculate_rank]
test "rank dagRank" {
    const r = Rank{ .value = 27, .min_hop_rank_increase = 16 };
    try testing.expectEqual(@as(u16, 1), r.dagRank());
    try testing.expectEqual(@as(u16, 1), Rank.ROOT.dagRank());
    try testing.expectEqual(@as(u16, 255), Rank.INFINITE.dagRank());
}

// [smoltcp:rank.rs:comparison]
test "rank ordering" {
    try testing.expectEqual(std.math.Order.lt, Rank.order(Rank.ROOT, Rank.INFINITE));
    try testing.expectEqual(std.math.Order.gt, Rank.order(Rank.INFINITE, Rank.ROOT));
    try testing.expectEqual(std.math.Order.eq, Rank.order(Rank.ROOT, Rank.ROOT));

    const r1 = Rank{ .value = 16, .min_hop_rank_increase = 16 };
    const r2 = Rank{ .value = 32, .min_hop_rank_increase = 16 };
    try testing.expectEqual(std.math.Order.lt, Rank.order(r1, r2));
}

// -- ObjectiveFunction0 tests --

// [smoltcp:of0.rs:rank_increase]
test "OF0 computeRank from root" {
    const result = ObjectiveFunction0.computeRank(Rank.ROOT);
    // 256 + 3*256 = 1024
    try testing.expectEqual(@as(u16, 1024), result.value);
    try testing.expectEqual(@as(u16, 4), result.dagRank());
    try testing.expectEqual(DEFAULT_MIN_HOP_RANK_INCREASE, result.min_hop_rank_increase);
}

// [smoltcp:of0.rs:rank_increase]
test "OF0 computeRank from non-root" {
    const parent = Rank{ .value = 1024, .min_hop_rank_increase = DEFAULT_MIN_HOP_RANK_INCREASE };
    const result = ObjectiveFunction0.computeRank(parent);
    // 1024 + 3*256 = 1792
    try testing.expectEqual(@as(u16, 1792), result.value);
}

// [smoltcp:of0.rs:non_empty_set]
test "OF0 preferredParent selects lowest dagRank" {
    var set: ParentSet(4) = .{};
    _ = set.add(testAddr(1), testParent(Rank.ROOT.value));
    _ = set.add(testAddr(2), testParent(1024));

    const idx = ObjectiveFunction0.preferredParent(4, &set);
    try testing.expect(idx != null);
    const entry = set.entries[idx.?].?;
    try testing.expectEqual(Rank.ROOT.value, entry.parent.rank.value);
}

// [smoltcp:of0.rs:empty_set]
test "OF0 preferredParent empty set" {
    const set: ParentSet(4) = .{};
    try testing.expectEqual(@as(?usize, null), ObjectiveFunction0.preferredParent(4, &set));
}

// -- ParentSet tests --

// [smoltcp:parents.rs:add_parent]
test "parent set add find remove" {
    var set: ParentSet(4) = .{};
    const addr = testAddr(1);
    const p = testParent(256);
    try testing.expect(set.add(addr, p));
    try testing.expectEqual(@as(usize, 1), set.count());

    const found = set.find(addr);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u16, 256), found.?.rank.value);

    try testing.expect(set.remove(addr));
    try testing.expectEqual(@as(usize, 0), set.count());
    try testing.expect(set.find(addr) == null);
}

test "parent set update in place" {
    var set: ParentSet(4) = .{};
    const addr = testAddr(1);
    _ = set.add(addr, testParent(256));
    _ = set.add(addr, testParent(512));
    try testing.expectEqual(@as(usize, 1), set.count());
    try testing.expectEqual(@as(u16, 512), set.find(addr).?.rank.value);
}

// [smoltcp:parents.rs:add_more_parents]
test "parent set eviction when full" {
    var set: ParentSet(4) = .{};
    _ = set.add(testAddr(1), testParent(256));
    _ = set.add(testAddr(2), testParent(512));
    _ = set.add(testAddr(3), testParent(768));
    _ = set.add(testAddr(4), testParent(1024));
    try testing.expectEqual(@as(usize, 4), set.count());

    // Worse than worst -- should not be added
    try testing.expect(!set.add(testAddr(5), testParent(2048)));
    try testing.expectEqual(@as(usize, 4), set.count());
    try testing.expect(set.find(testAddr(5)) == null);

    // Better than worst (1024) -- should evict it
    try testing.expect(set.add(testAddr(6), testParent(128)));
    try testing.expectEqual(@as(usize, 4), set.count());
    try testing.expect(set.find(testAddr(6)) != null);
    try testing.expect(set.find(testAddr(4)) == null);
}

// -- Relations tests --

// [smoltcp:relations.rs:add_relation]
test "relations add and find" {
    var rel: Relations(8) = .{};
    const dest = testAddr(1);
    const hop = testAddr(2);
    const exp = time.Instant.fromSecs(100);
    try testing.expect(rel.addRelation(dest, hop, exp));
    try testing.expectEqual(@as(usize, 1), rel.count());

    const found = rel.findNextHop(dest);
    try testing.expect(found != null);
    try testing.expect(std.mem.eql(u8, &hop, &found.?));
}

// [smoltcp:relations.rs:find_next_hop]
test "relations find missing" {
    var rel: Relations(8) = .{};
    try testing.expect(rel.findNextHop(testAddr(99)) == null);
}

// [smoltcp:relations.rs:remove_relation]
test "relations remove" {
    var rel: Relations(8) = .{};
    const dest = testAddr(1);
    _ = rel.addRelation(dest, testAddr(2), time.Instant.fromSecs(100));
    try testing.expect(rel.removeRelation(dest));
    try testing.expectEqual(@as(usize, 0), rel.count());
    try testing.expect(!rel.removeRelation(dest));
}

// [smoltcp:relations.rs:purge_relation]
test "relations purge expired" {
    var rel: Relations(8) = .{};
    _ = rel.addRelation(testAddr(1), testAddr(2), time.Instant.fromSecs(5));
    _ = rel.addRelation(testAddr(3), testAddr(4), time.Instant.fromSecs(20));
    try testing.expectEqual(@as(usize, 2), rel.count());

    rel.purge(time.Instant.fromSecs(10));
    try testing.expectEqual(@as(usize, 1), rel.count());
    try testing.expect(rel.findNextHop(testAddr(1)) == null);
    try testing.expect(rel.findNextHop(testAddr(3)) != null);
}

// [smoltcp:relations.rs:update_relation]
test "relations upsert updates next hop" {
    var rel: Relations(8) = .{};
    const dest = testAddr(1);
    _ = rel.addRelation(dest, testAddr(2), time.Instant.fromSecs(100));
    _ = rel.addRelation(dest, testAddr(3), time.Instant.fromSecs(200));
    try testing.expectEqual(@as(usize, 1), rel.count());

    const hop = rel.findNextHop(dest).?;
    try testing.expect(std.mem.eql(u8, &testAddr(3), &hop));
}

// -- TrickleTimer tests --

// [smoltcp:trickle.rs:trickle_timer_intervals]
test "trickle timer fires at t_expiration" {
    const now = time.Instant.ZERO;
    var timer = TrickleTimer.init(
        DEFAULT_DIO_INTERVAL_MIN,
        DEFAULT_DIO_INTERVAL_DOUBLINGS,
        DEFAULT_DIO_REDUNDANCY_CONSTANT,
        now,
        42,
    );

    // Timer should not have fired yet at t=0 (t_expiration is in the future)
    try testing.expect(!timer.poll(now, 42));

    // Advance to just past t_expiration
    const fire_time = timer.t_expiration;
    const fired = timer.poll(fire_time, 42);
    try testing.expect(fired);
}

// [smoltcp:trickle.rs:trickle_timer_hear_consistency]
test "trickle timer consistency suppresses transmission" {
    const now = time.Instant.ZERO;
    var timer = TrickleTimer.init(12, 8, 1, now, 42);

    // Hear enough consistent messages to suppress
    timer.hearConsistent();
    try testing.expectEqual(@as(u8, 1), timer.counter);

    // Even at t_expiration, should not fire because counter >= k
    const fired = timer.poll(timer.t_expiration, 42);
    try testing.expect(!fired);
}

// [smoltcp:trickle.rs:trickle_timer_hear_inconsistency]
test "trickle timer inconsistency resets to i_min" {
    const now = time.Instant.ZERO;
    var timer = TrickleTimer.init(12, 8, 10, now, 42);

    // Manually double the interval a few times
    const far_future = now.add(time.Duration.fromSecs(1000));
    _ = timer.poll(far_future, 42);
    const after_first = timer.i_exp;
    try testing.expect(after_first > 12);

    // Hear inconsistency -- should reset
    timer.hearInconsistency(far_future, 99);
    try testing.expectEqual(@as(u32, 12), timer.i_exp);
    try testing.expectEqual(@as(u8, 0), timer.counter);
}

// [smoltcp:trickle.rs:trickle_timer_intervals]
test "trickle timer interval doubling" {
    const now = time.Instant.ZERO;
    var timer = TrickleTimer.init(2, 4, 10, now, 0);
    // i_min_exp=2, i_max_exp=6, so interval starts at 2^2=4ms
    try testing.expectEqual(@as(u32, 2), timer.i_exp);

    // Expire the first interval
    _ = timer.poll(timer.i_expiration, 0);
    try testing.expectEqual(@as(u32, 3), timer.i_exp);

    // Expire again
    _ = timer.poll(timer.i_expiration, 0);
    try testing.expectEqual(@as(u32, 4), timer.i_exp);

    // Keep expiring to reach max
    _ = timer.poll(timer.i_expiration, 0);
    try testing.expectEqual(@as(u32, 5), timer.i_exp);
    _ = timer.poll(timer.i_expiration, 0);
    try testing.expectEqual(@as(u32, 6), timer.i_exp);

    // Should cap at i_max_exp
    _ = timer.poll(timer.i_expiration, 0);
    try testing.expectEqual(@as(u32, 6), timer.i_exp);
}

test "trickle timer pollAt returns earliest expiration" {
    const now = time.Instant.ZERO;
    const timer = TrickleTimer.init(12, 8, 10, now, 42);
    const pa = timer.pollAt();
    // pollAt should return the earlier of t_expiration and i_expiration
    if (timer.t_expiration.lessThan(timer.i_expiration)) {
        try testing.expect(pa.eql(timer.t_expiration));
    } else {
        try testing.expect(pa.eql(timer.i_expiration));
    }
}
