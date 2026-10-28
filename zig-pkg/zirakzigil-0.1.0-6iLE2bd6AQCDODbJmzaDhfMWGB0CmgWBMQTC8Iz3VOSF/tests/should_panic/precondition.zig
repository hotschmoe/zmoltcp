// A caller ignores a documented precondition. The contract fires at the call
// boundary (blaming the caller), not deep inside the callee.
const zv = @import("zv");

fn withdraw(balance: u64, amount: u64) u64 {
    zv.requires(amount <= balance);
    return balance - amount;
}

pub fn main() void {
    var amount: u64 = 70;
    _ = &amount;
    _ = withdraw(50, amount); // must panic with "precondition violated"
}
