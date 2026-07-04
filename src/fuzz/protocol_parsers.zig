const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P1 protocol parsers" {
    try testing.fuzz({}, fuzz.fuzzProtocolParsers, .{});
}
