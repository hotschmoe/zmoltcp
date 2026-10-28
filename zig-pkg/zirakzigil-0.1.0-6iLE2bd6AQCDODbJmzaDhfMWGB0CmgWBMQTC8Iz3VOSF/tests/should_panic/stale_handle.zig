// Module A closes an account; module B still holds its handle and the slot has
// been reused for someone else. Without generations this silently debits the
// wrong customer.
const ledger = @import("ledger");

pub fn main() !void {
    var pool: ledger.Accounts = .{};
    const alice = try ledger.open(&pool, 100);
    pool.free(alice);
    _ = try ledger.open(&pool, 5_000); // bob reuses alice's slot
    _ = try ledger.withdraw(&pool, alice, 50); // stale handle -> must panic
}
