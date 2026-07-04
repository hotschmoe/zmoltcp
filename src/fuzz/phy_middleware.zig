const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P2 PHY middleware" {
    try testing.fuzz({}, fuzz.fuzzPhyMiddleware, .{});
}
