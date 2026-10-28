//! A generic circular buffer over caller-provided storage.

const std = @import("std");
const zv = @import("zv");

pub const assurance = .{
    .RingBuffer = zv.governed(RingBuffer(u8)), // audited through a witness instantiation
    .capacityOf = .tested,
};

comptime {
    zv.requireAssurance(@This(), .tested);
}

pub fn RingBuffer(comptime T: type) type {
    return struct {
        storage: []T,
        read_at: usize = 0,
        length: usize = 0,

        const Self = @This();

        pub const assurance = .{ .init = .tested, .enqueue = .checked, .len = .tested };
        comptime {
            zv.requireAssurance(Self, .tested);
        }

        pub fn init(storage: []T) Self {
            return .{ .storage = storage };
        }

        pub fn len(self: Self) usize {
            return self.length;
        }

        pub fn enqueue(self: *Self, item: T) error{Full}!void {
            if (self.length == self.storage.len) return error.Full;
            self.storage[(self.read_at + self.length) % self.storage.len] = item;
            self.length += 1;
            zv.ensures({}, self.length <= self.storage.len);
        }
    };
}

/// Generic function with a comptime parameter: an ordinary classified fn.
pub fn capacityOf(comptime T: type, ring: RingBuffer(T)) usize {
    return ring.storage.len;
}

/// A pub instantiation is checked through the returned type's own manifest.
pub const ByteRing = RingBuffer(u8);

test "enqueue until full" {
    var backing: [2]u8 = undefined;
    var ring: ByteRing = .init(&backing);
    try ring.enqueue(1);
    try ring.enqueue(2);
    try std.testing.expectError(error.Full, ring.enqueue(3));
    try std.testing.expectEqual(@as(usize, 2), capacityOf(u8, ring));
}
