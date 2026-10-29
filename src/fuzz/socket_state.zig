const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P2 socket state machines" {
    try testing.fuzz({}, fuzz.fuzzSocketStateMachines, .{});
}
