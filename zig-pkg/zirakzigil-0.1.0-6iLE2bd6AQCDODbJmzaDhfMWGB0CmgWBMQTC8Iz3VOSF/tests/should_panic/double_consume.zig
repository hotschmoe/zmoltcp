// A contributor copies a Withdrawal token and deposits it twice.
// Zig happily copies the struct; the out-of-line ledger catches the second use.
const ledger = @import("ledger");

pub fn main() !void {
    var pool: ledger.Accounts = .{};
    const a = try ledger.open(&pool, 100);
    const b = try ledger.open(&pool, 0);
    const w = try ledger.withdraw(&pool, a, 60);
    const copy = w; // silent by-value copy
    ledger.deposit(&pool, b, w);
    ledger.deposit(&pool, b, copy); // money printed from nothing -> must panic
}
