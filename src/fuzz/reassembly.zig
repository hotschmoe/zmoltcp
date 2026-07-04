const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P0 fragment reassembly" {
    try testing.fuzz({}, fuzz.fuzzReassembly, .{});
}
