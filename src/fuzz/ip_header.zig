const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P0 IP header parsing" {
    try testing.fuzz({}, fuzz.fuzzIpHeaderParsing, .{});
}
