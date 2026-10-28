//! A tiny account ledger written the "Zirakzigil way":
//!   - accounts live in a branded, generational Pool (no raw pointers escape)
//!   - money moves as Linear tokens that must be consumed exactly once
//!   - amounts are Ranged so their arithmetic cannot overflow
//!   - LAWS are executable properties maintained by code owners

const std = @import("std");
const zv = @import("zv");

pub const Cents = zv.Ranged(0, 1_000_000_000_00); // up to $1B per account
pub const Account = struct { balance: u64, frozen: bool = false };

/// Brand: this `struct {}` is a unique type. No other pool's handles fit here.
pub const Accounts = zv.Pool(Account, 1024, struct {});
pub const AccountId = Accounts.Handle;

/// Money in flight. Must be deposited (consumed) exactly once.
pub const Withdrawal = zv.Linear(u64);

pub const assurance = .{
    .open = .checked,
    .withdraw = .checked,
    .deposit = .checked,
    .total = .tested,
    .laws = .{ .conservation = .tested, .ranged_sum_in_range = .tested },
};

comptime {
    zv.requireAssurance(@This(), .tested);
}

pub fn open(pool: *Accounts, initial: u64) !AccountId {
    return pool.alloc(.{ .balance = initial });
}

pub fn withdraw(pool: *Accounts, from: AccountId, amount: u64) error{Insufficient}!Withdrawal {
    const acct = pool.get(from); // stale handle => panic in safe builds
    if (acct.balance < amount) return error.Insufficient;
    acct.balance -= amount;
    return Withdrawal.init(amount);
}

pub fn deposit(pool: *Accounts, to: AccountId, w: Withdrawal) void {
    const amount = w.consume(); // a second deposit of the same token panics
    const acct = pool.get(to);
    acct.balance = zv.ensures(acct.balance + amount, acct.balance + amount >= amount);
}

pub fn total(pool: *Accounts, ids: []const AccountId) u64 {
    var sum: u64 = 0;
    for (ids) |id| sum += pool.get(id).balance;
    return sum;
}

/// LAWS: owned by maintainers (CODEOWNERS), checked as properties in CI,
/// and the obligations a future zvc proof must discharge.
pub const laws = struct {
    /// Transfers conserve money.
    pub fn conservation(a0: u32, b0: u32, amt: u32) bool {
        var pool: Accounts = .{};
        const a = open(&pool, a0) catch return false;
        const b = open(&pool, b0) catch return false;
        const before = total(&pool, &.{ a, b });
        if (withdraw(&pool, a, amt)) |w| {
            deposit(&pool, b, w);
        } else |_| {}
        return total(&pool, &.{ a, b }) == before;
    }

    /// Interval arithmetic on Cents never escapes its declared range.
    pub fn ranged_sum_in_range(x: Cents, y: Cents) bool {
        const s = zv.add(x, y);
        return s.get() >= 0 and s.get() <= 2 * Cents.max;
    }
};

test "laws hold on 20k random edge-biased inputs" {
    zv.resetLedger();
    try zv.checkLaws(laws, .{ .iterations = 10_000, .seed = 0xC0FFEE });
    try std.testing.expectEqual(@as(usize, 0), zv.leakedTokens());
}

test "generational handles detect use-after-free without crashing the test" {
    var pool: Accounts = .{};
    const a = try open(&pool, 100);
    pool.free(a);
    const b = try open(&pool, 5); // reuses the slot
    try std.testing.expect(a.index == b.index); // same slot...
    try std.testing.expect(!pool.isLive(a)); // ...but the old handle is dead
    try std.testing.expect(pool.isLive(b));
}

test "brands make handle types distinct" {
    const Other = zv.Pool(Account, 1024, struct {});
    try std.testing.expect(Other.Handle != AccountId);
}

test "Ranged types pick storage and grow through arithmetic at comptime" {
    const A = zv.Ranged(0, 200);
    const B = zv.Ranged(0, 100);
    try std.testing.expect(A.T == u8);
    const s = zv.add(A.lit(200), B.lit(100));
    try std.testing.expect(@TypeOf(s).T == u9);
    try std.testing.expectEqual(@as(u9, 300), s.get());
    const d = zv.sub(B.lit(10), A.lit(200));
    try std.testing.expect(@TypeOf(d).min == -200);
    try std.testing.expectEqual(@as(@TypeOf(d).T, -190), d.get());
    const arr = [_]u8{ 10, 20, 30, 40 };
    try std.testing.expectEqual(@as(u8, 40), zv.at(arr, zv.Index(4).lit(3)));
}

const Node = struct {
    pin: zv.PinCheck = .{},
    self_ref: ?*Node = null,
    fn init(n: *Node) void {
        n.pin.pin();
        n.self_ref = n;
    }
    fn touch(n: *Node) void {
        n.pin.check();
    }
};

test "PinCheck accepts the original" {
    var n: Node = .{};
    n.init();
    n.touch();
}

test "ghost code compiles away unless -Dghost=true" {
    var ghost_counter: usize = 0;
    if (zv.ghost) ghost_counter += 1;
    try std.testing.expectEqual(@as(usize, if (zv.ghost) 1 else 0), ghost_counter);
}

test "laws under the fuzzer (corpus replay without --fuzz)" {
    try zv.fuzzLaws(laws, &.{ &@as([32]u8, @splat(0)), &@as([32]u8, @splat(0xff)) });
}
