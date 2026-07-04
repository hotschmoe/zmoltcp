const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P0 TCP header parsing" {
    try testing.fuzz({}, fuzz.fuzzTcpHeaderParsing, .{});
}
