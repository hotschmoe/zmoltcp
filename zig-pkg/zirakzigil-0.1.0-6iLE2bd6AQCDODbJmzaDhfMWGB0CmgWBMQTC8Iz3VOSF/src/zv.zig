//! zv — the comptime layer of "Zirakzigil", a verification stack for Zig.
//!
//! Everything in this file is plain Zig 0.17. No compiler fork, no plugin.
//! It gives a team four things the language does not:
//!
//!   1. Contracts      requires / ensures / invariant / assume, written in Zig,
//!                     checked at runtime in safe builds and read by `zvc`
//!                     (the static verifier) as proof obligations.
//!   2. Refinements    Ranged(lo, hi): integers whose bounds live in the type and
//!                     whose arithmetic is proven overflow-free at comptime.
//!   3. Ownership      Pool / Handle (branded + generational), Linear(T) affine
//!                     tokens, PinCheck for do-not-copy structs.
//!   4. Governance     an assurance manifest every module must carry, enforced
//!                     at compile time, plus executable laws (property tests).

const std = @import("std");
const builtin = @import("builtin");
const opts = @import("zv_options");

/// Runtime contract checks run in Debug and ReleaseSafe, never in ReleaseFast/Small.
pub const checks: bool = switch (builtin.mode) {
    .Debug, .ReleaseSafe => true,
    .ReleaseFast, .ReleaseSmall => false,
};

/// Ghost code. `if (zv.ghost) { ... }` is compiled only in verification builds
/// (`zig build -Dghost=true`). In normal builds the branch is comptime-false and
/// vanishes, so ghost state costs nothing in production.
pub const ghost: bool = opts.ghost;

// ─────────────────────────────────────────────────────────────────────────────
// 1. Contracts
// ─────────────────────────────────────────────────────────────────────────────

/// Precondition. The caller's obligation.
pub inline fn requires(ok: bool) void {
    if (checks and !ok) @panic("zv: precondition violated");
}

/// Postcondition. Returns `value` so it composes with `return`:
///     return zv.ensures(r, lo <= r and r <= hi);
pub inline fn ensures(value: anytype, ok: bool) @TypeOf(value) {
    if (checks and !ok) @panic("zv: postcondition violated");
    return value;
}

/// Loop invariant. Place it as the first statement of a loop body.
pub inline fn invariant(ok: bool) void {
    if (checks and !ok) @panic("zv: loop invariant violated");
}

/// A fact the verifier may take for granted (trusted). Checked at runtime anyway.
pub inline fn assume(ok: bool) void {
    if (checks and !ok) @panic("zv: assumption violated");
}

/// Runtime check over [lo, hi): spec helper for quantified properties.
pub fn forallRange(lo: usize, hi: usize, ctx: anytype, comptime pred: fn (@TypeOf(ctx), usize) bool) bool {
    var i = lo;
    while (i < hi) : (i += 1) if (!pred(ctx, i)) return false;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Refinement integers: the range is part of the type
// ─────────────────────────────────────────────────────────────────────────────

/// An integer known to lie in [lo, hi]. Storage is the smallest fitting int.
pub fn Ranged(comptime lo: comptime_int, comptime hi: comptime_int) type {
    if (lo > hi) @compileError(std.fmt.comptimePrint("zv.Ranged: empty range [{d}, {d}]", .{ lo, hi }));
    return struct {
        raw: T,

        pub const T = std.math.IntFittingRange(lo, hi);
        pub const min: comptime_int = lo;
        pub const max: comptime_int = hi;
        pub const is_ranged = true;
        const Self = @This();

        pub const assurance = .{ .lit = .checked, .from = .tested, .get = .checked, .as = .checked };
        comptime {
            manifest.requireAssurance(Self, .tested);
        }

        /// Comptime literal: out-of-range is a compile error, not a runtime one.
        pub fn lit(comptime x: comptime_int) Self {
            if (x < lo or x > hi) @compileError(std.fmt.comptimePrint("zv.Ranged: literal {d} outside [{d}, {d}]", .{ x, lo, hi }));
            return .{ .raw = x };
        }

        /// Runtime entry point: the only place a range is *checked*.
        pub fn from(x: anytype) error{OutOfRange}!Self {
            if (x < lo or x > hi) return error.OutOfRange;
            return .{ .raw = @intCast(x) };
        }

        pub fn get(self: Self) T {
            if (checks) std.debug.assert(self.raw >= lo and self.raw <= hi);
            return self.raw;
        }

        /// Convert to a plain int type. Compile error unless every value fits.
        pub fn as(self: Self, comptime U: type) U {
            if (lo < std.math.minInt(U) or hi > std.math.maxInt(U))
                @compileError("zv.Ranged.as: range [" ++ std.fmt.comptimePrint("{d}, {d}", .{ lo, hi }) ++ "] does not fit " ++ @typeName(U));
            return self.raw;
        }
    };
}

/// Index into an array of comptime-known length `n`.
pub fn Index(comptime n: comptime_int) type {
    return Ranged(0, n - 1);
}

fn Wide(comptime a: comptime_int, comptime b: comptime_int, comptime c: comptime_int, comptime d: comptime_int) type {
    return std.math.IntFittingRange(@min(@min(a, b), @min(c, d)), @max(@max(a, b), @max(c, d)));
}

pub fn AddResult(comptime A: type, comptime B: type) type {
    return Ranged(A.min + B.min, A.max + B.max);
}
pub fn SubResult(comptime A: type, comptime B: type) type {
    return Ranged(A.min - B.max, A.max - B.min);
}
pub fn MulResult(comptime A: type, comptime B: type) type {
    const p = [_]comptime_int{ A.min * B.min, A.min * B.max, A.max * B.min, A.max * B.max };
    return Ranged(@min(@min(p[0], p[1]), @min(p[2], p[3])), @max(@max(p[0], p[1]), @max(p[2], p[3])));
}

/// Interval arithmetic computed at comptime: the result type is wide enough by
/// construction, so overflow is impossible and no runtime check is emitted.
pub fn add(a: anytype, b: anytype) AddResult(@TypeOf(a), @TypeOf(b)) {
    const A = @TypeOf(a);
    const B = @TypeOf(b);
    const R = AddResult(A, B);
    const W = Wide(A.min, B.max, R.min, R.max);
    return .{ .raw = @intCast(@as(W, a.raw) + @as(W, b.raw)) };
}
pub fn sub(a: anytype, b: anytype) SubResult(@TypeOf(a), @TypeOf(b)) {
    const A = @TypeOf(a);
    const B = @TypeOf(b);
    const R = SubResult(A, B);
    const W = Wide(@min(A.min, B.min), @max(A.max, B.max), R.min, R.max);
    return .{ .raw = @intCast(@as(W, a.raw) - @as(W, b.raw)) };
}
pub fn mul(a: anytype, b: anytype) MulResult(@TypeOf(a), @TypeOf(b)) {
    const A = @TypeOf(a);
    const B = @TypeOf(b);
    const R = MulResult(A, B);
    const W = Wide(@min(A.min, B.min), @max(A.max, B.max), R.min, R.max);
    return .{ .raw = @intCast(@as(W, a.raw) * @as(W, b.raw)) };
}

/// Shrink a range with a runtime check (the explicit, greppable trust point).
pub fn narrow(comptime lo: comptime_int, comptime hi: comptime_int, x: anytype) error{OutOfRange}!Ranged(lo, hi) {
    return Ranged(lo, hi).from(x.raw);
}

/// Index an array with a proven-in-bounds index. Length mismatch is a compile error.
pub fn at(arr: anytype, idx: anytype) @TypeOf(arr[0]) {
    const n = arr.len;
    const I = @TypeOf(idx);
    if (I.min < 0 or I.max >= n) @compileError("zv.at: index range does not fit the array length");
    return arr[idx.raw];
}

// ─────────────────────────────────────────────────────────────────────────────
// 3a. Pool + branded, generational handles
// ─────────────────────────────────────────────────────────────────────────────

/// A fixed-capacity pool. `Brand` is any unique type (pass `struct {}` at the
/// declaration site); handles from one pool are a *different type* from handles
/// of another, so mixing them is a compile error. Each slot carries a generation,
/// so a stale handle (use-after-free, ABA) is caught at runtime in safe builds.
pub fn Pool(comptime T: type, comptime capacity: u32, comptime Brand: type) type {
    return struct {
        items: [capacity]T = undefined,
        gens: [capacity]u32 = @splat(0), // even = free, odd = live
        free_list: [capacity]u32 = undefined,
        free_len: u32 = 0,
        high: u32 = 0,

        pub const brand = Brand;
        pub const Handle = struct {
            index: u32,
            gen: u32,
            pub const Pool = Self;
        };
        const Self = @This();

        pub const assurance = .{ .alloc = .tested, .get = .checked, .isLive = .tested, .free = .checked };
        comptime {
            manifest.requireAssurance(Self, .tested);
        }

        pub fn alloc(self: *Self, value: T) error{PoolFull}!Handle {
            const i: u32 = if (self.free_len > 0) blk: {
                self.free_len -= 1;
                break :blk self.free_list[self.free_len];
            } else if (self.high < capacity) blk: {
                self.high += 1;
                break :blk self.high - 1;
            } else return error.PoolFull;
            self.gens[i] +%= 1; // free(even) -> live(odd)
            self.items[i] = value;
            return .{ .index = i, .gen = self.gens[i] };
        }

        fn check(self: *const Self, h: Handle) void {
            if (checks and (h.index >= self.high or self.gens[h.index] != h.gen))
                @panic("zv.Pool: stale or foreign handle (use-after-free?)");
        }

        pub fn get(self: *Self, h: Handle) *T {
            self.check(h);
            return &self.items[h.index];
        }

        pub fn isLive(self: *const Self, h: Handle) bool {
            return h.index < self.high and self.gens[h.index] == h.gen;
        }

        pub fn free(self: *Self, h: Handle) void {
            self.check(h);
            self.gens[h.index] +%= 1; // live(odd) -> free(even); old handles now stale
            self.free_list[self.free_len] = h.index;
            self.free_len += 1;
        }
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// 3b. Linear(T): affine ownership tokens, enforced at runtime
// ─────────────────────────────────────────────────────────────────────────────
//
// Zig copies structs silently, so a flag *inside* the token cannot detect a
// double consume (the copy carries its own flag). The liveness bit lives
// out-of-line in a ledger keyed by ticket, so every copy shares it.
// The static analyzer (`zv-own`, designed in the doc) enforces the same rule
// at compile time; this is the backstop that works today.

const ledger_capacity = 1 << 14;
var ledger: std.StaticBitSet(ledger_capacity) = .empty;
var ledger_next: u32 = 0;

pub fn Linear(comptime T: type) type {
    return struct {
        value: T,
        ticket: u32,
        const Self = @This();

        pub const assurance = .{ .init = .tested, .borrow = .checked, .consume = .checked };
        comptime {
            manifest.requireAssurance(Self, .tested);
        }

        pub fn init(value: T) Self {
            const t = ledger_next % ledger_capacity;
            ledger_next +%= 1;
            if (checks) ledger.set(t);
            return .{ .value = value, .ticket = t };
        }

        /// Read access while the token is still owned.
        pub fn borrow(self: *const Self) *const T {
            if (checks and !ledger.isSet(self.ticket)) @panic("zv.Linear: borrow after consume");
            return &self.value;
        }

        /// Move the value out. A second consume (via any copy) panics.
        pub fn consume(self: Self) T {
            if (checks) {
                if (!ledger.isSet(self.ticket)) @panic("zv.Linear: consumed twice (copied token?)");
                ledger.unset(self.ticket);
            }
            return self.value;
        }
    };
}

/// Tokens created but never consumed. Call at the end of a test: must be 0.
pub fn leakedTokens() usize {
    return ledger.count();
}
pub fn resetLedger() void {
    ledger = .empty;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3c. PinCheck: catch accidental by-value copies of self-referential structs
// ─────────────────────────────────────────────────────────────────────────────

pub const PinCheck = struct {
    addr: usize = 0,

    pub const assurance = .{ .pin = .tested, .check = .checked };
    comptime {
        manifest.requireAssurance(PinCheck, .tested);
    }

    pub fn pin(self: *PinCheck) void {
        self.addr = @intFromPtr(self);
    }
    pub fn check(self: *const PinCheck) void {
        if (checks and self.addr != @intFromPtr(self)) @panic("zv.PinCheck: pinned struct was copied or moved");
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// 4. Governance: assurance manifest + laws
// ─────────────────────────────────────────────────────────────────────────────

pub const manifest = @import("manifest.zig");
pub const Level = manifest.Level;
pub const Counts = manifest.Counts;
pub const requireAssurance = manifest.requireAssurance;
pub const governed = manifest.governed;
pub const assuranceCounts = manifest.assuranceCounts;

/// Test-time property drivers (see `laws.zig`). Not analyzed unless used.
pub const laws = @import("laws.zig");
pub const checkLaws = laws.checkLaws;
pub const LawOptions = laws.Options;
pub const fuzzLaws = laws.fuzzLaws;
pub const Bytes = laws.Bytes;

/// Host-side assurance table for `zig build assurance` (see `report.zig`).
pub const report = @import("report.zig");

test {
    _ = manifest;
    _ = laws;
    _ = report;
}
