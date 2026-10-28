// A parser with an unguarded read panics inside a law. The panic cannot be
// caught, so `.trace = true` prints the case before each call: the last
// `zv: law ...` line on stderr names the failing iteration for `zv.laws.replay`.
const zv = @import("zv");

fn headerLast(b: []const u8) u8 {
    if (b.len < 7) return 0; // BUG: needs 8 bytes
    return b[7];
}

const laws = struct {
    pub fn readsHeader(input: zv.Bytes(64)) bool {
        _ = headerLast(input.slice());
        return true;
    }
};

pub fn main() !void {
    try zv.checkLaws(laws, .{ .iterations = 2000, .seed = 1, .trace = true });
}
