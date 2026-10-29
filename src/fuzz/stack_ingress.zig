const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P0 stack ingress" {
    try testing.fuzz({}, fuzz.fuzzStackIngress, .{});
}
