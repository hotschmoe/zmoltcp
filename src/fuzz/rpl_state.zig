const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P1 RPL state" {
    try testing.fuzz({}, fuzz.fuzzRplState, .{});
}
