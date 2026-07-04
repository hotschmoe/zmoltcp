const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P0 IPv6 extension parsing" {
    try testing.fuzz({}, fuzz.fuzzIpv6ExtensionParsing, .{});
}
