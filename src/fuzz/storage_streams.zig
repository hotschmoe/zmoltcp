const testing = @import("std").testing;
const fuzz = @import("fuzz_common");

test "fuzz P2 storage operation streams" {
    try testing.fuzz({}, fuzz.fuzzStorageStreams, .{});
}
