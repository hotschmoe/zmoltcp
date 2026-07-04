const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P0 DNS parsing" {
    try testing.fuzz({}, fuzz.fuzzDnsParsing, .{});
}
