// Ring buffer for TCP send/receive windows
//
// Generic circular buffer operating on caller-provided storage. Supports
// discrete (single-element), continuous (contiguous-slice), slice-copy
// (wrap-around), and random-access (offset-based) interfaces.
//
// Design note: smoltcp uses enqueue_many_with(closure) to work around Rust's
// borrow checker. Zig doesn't need closures -- we return mutable slices
// directly and the caller writes into them.
//
// [smoltcp:storage/ring_buffer.rs]

const std = @import("std");

pub fn RingBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        storage: []T,
        read_at: usize,
        length: usize,

        pub fn init(storage: []T) Self {
            return .{
                .storage = storage,
                .read_at = 0,
                .length = 0,
            };
        }

        pub fn clear(self: *Self) void {
            self.read_at = 0;
            self.length = 0;
        }

        pub fn capacity(self: Self) usize {
            return self.storage.len;
        }

        pub fn len(self: Self) usize {
            return self.length;
        }

        pub fn window(self: Self) usize {
            return self.capacity() - self.length;
        }

        pub fn contiguousWindow(self: Self) usize {
            return @min(self.window(), self.capacity() - self.getIdx(self.length));
        }

        pub fn isEmpty(self: Self) bool {
            return self.length == 0;
        }

        pub fn isFull(self: Self) bool {
            return self.window() == 0;
        }

        fn getIdx(self: Self, idx: usize) usize {
            const cap = self.capacity();
            if (cap > 0) {
                return (self.read_at + idx) % cap;
            } else {
                return 0;
            }
        }

        // -- Discrete (single element) --

        pub fn enqueueOne(self: *Self) error{Full}!*T {
            if (self.isFull()) return error.Full;
            const index = (self.read_at + self.length) % self.capacity();
            self.length += 1;
            return &self.storage[index];
        }

        pub fn dequeueOne(self: *Self) error{Empty}!*T {
            if (self.isEmpty()) return error.Empty;
            const index = self.read_at;
            self.read_at = (self.read_at + 1) % self.capacity();
            self.length -= 1;
            return &self.storage[index];
        }

        // -- Continuous (contiguous slices) --

        pub fn enqueueMany(self: *Self, max: usize) []T {
            if (self.length == 0) {
                self.read_at = 0;
            }
            const write_at = self.getIdx(self.length);
            const contig = self.contiguousWindow();
            const size = @min(max, contig);
            self.length += size;
            return self.storage[write_at..][0..size];
        }

        pub fn dequeueMany(self: *Self, max: usize) []T {
            const cap = self.capacity();
            const contig = @min(self.length, cap - self.read_at);
            const size = @min(max, contig);
            const start = self.read_at;
            if (cap > 0) {
                self.read_at = (self.read_at + size) % cap;
            }
            self.length -= size;
            return self.storage[start..][0..size];
        }

        // -- Slice Copy (handles wrap-around via two calls) --

        pub fn enqueueSlice(self: *Self, data: []const T) usize {
            const size_1 = blk: {
                const buf = self.enqueueMany(data.len);
                @memcpy(buf, data[0..buf.len]);
                break :blk buf.len;
            };
            const size_2 = blk: {
                const remaining = data[size_1..];
                const buf = self.enqueueMany(remaining.len);
                @memcpy(buf, remaining[0..buf.len]);
                break :blk buf.len;
            };
            return size_1 + size_2;
        }

        pub fn dequeueSlice(self: *Self, data: []T) usize {
            const size_1 = blk: {
                const buf = self.dequeueMany(data.len);
                @memcpy(data[0..buf.len], buf);
                break :blk buf.len;
            };
            const size_2 = blk: {
                const remaining = data[size_1..];
                const buf = self.dequeueMany(remaining.len);
                @memcpy(remaining[0..buf.len], buf);
                break :blk buf.len;
            };
            return size_1 + size_2;
        }

        // -- Random Access (for TCP out-of-order segments) --

        pub fn getUnallocated(self: *Self, offset: usize, max: usize) []T {
            const start_at = self.getIdx(self.length + offset);
            if (offset > self.window()) return self.storage[0..0];
            const clamped = self.window() - offset;
            var size = @min(max, clamped);
            const until_end = self.capacity() - start_at;
            size = @min(size, until_end);
            return self.storage[start_at..][0..size];
        }

        pub fn writeUnallocated(self: *Self, offset: usize, data: []const T) usize {
            const size_1 = blk: {
                const slice = self.getUnallocated(offset, data.len);
                @memcpy(slice, data[0..slice.len]);
                break :blk slice.len;
            };
            const size_2 = blk: {
                const slice = self.getUnallocated(offset + size_1, data[size_1..].len);
                @memcpy(slice, data[size_1..][0..slice.len]);
                break :blk slice.len;
            };
            return size_1 + size_2;
        }

        pub fn enqueueUnallocated(self: *Self, count: usize) void {
            std.debug.assert(count <= self.window());
            self.length += count;
        }

        pub fn getAllocated(self: Self, offset: usize, max: usize) []const T {
            const start_at = self.getIdx(offset);
            if (offset > self.length) return self.storage[0..0];
            const clamped = self.length - offset;
            var size = @min(max, clamped);
            const until_end = self.capacity() - start_at;
            size = @min(size, until_end);
            return self.storage[start_at..][0..size];
        }

        pub fn readAllocated(self: *Self, offset: usize, data: []T) usize {
            const size_1 = blk: {
                const slice = self.getAllocated(offset, data.len);
                @memcpy(data[0..slice.len], slice);
                break :blk slice.len;
            };
            const size_2 = blk: {
                const slice = self.getAllocated(offset + size_1, data[size_1..].len);
                @memcpy(data[size_1..][0..slice.len], slice);
                break :blk slice.len;
            };
            return size_1 + size_2;
        }

        pub fn dequeueAllocated(self: *Self, count: usize) void {
            std.debug.assert(count <= self.length);
            self.length -= count;
            self.read_at = self.getIdx(count);
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;
const RingBufU8 = RingBuffer(u8);

fn storageAsStr(ring: *const RingBufU8) []const u8 {
    return ring.storage;
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_length_changes]
test "buffer length and capacity tracking" {
    var backing = [_]u8{ 0, 0 };
    var ring = RingBufU8.init(&backing);
    try testing.expect(ring.isEmpty());
    try testing.expect(!ring.isFull());
    try testing.expectEqual(@as(usize, 0), ring.len());
    try testing.expectEqual(@as(usize, 2), ring.capacity());
    try testing.expectEqual(@as(usize, 2), ring.window());

    ring.length = 1;
    try testing.expect(!ring.isEmpty());
    try testing.expect(!ring.isFull());
    try testing.expectEqual(@as(usize, 1), ring.len());
    try testing.expectEqual(@as(usize, 2), ring.capacity());
    try testing.expectEqual(@as(usize, 1), ring.window());

    ring.length = 2;
    try testing.expect(!ring.isEmpty());
    try testing.expect(ring.isFull());
    try testing.expectEqual(@as(usize, 2), ring.len());
    try testing.expectEqual(@as(usize, 2), ring.capacity());
    try testing.expectEqual(@as(usize, 0), ring.window());
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_enqueue_dequeue_one_with]
// [smoltcp:storage/ring_buffer.rs:test_buffer_enqueue_dequeue_one]
// (merged: smoltcp had separate _with(closure) and non-_with APIs; we have one API)
test "enqueue and dequeue one" {
    var backing = [_]u8{ 0, 0, 0, 0, 0 };
    var ring = RingBufU8.init(&backing);

    try testing.expectError(error.Empty, ring.dequeueOne());

    _ = try ring.enqueueOne();
    try testing.expect(!ring.isEmpty());
    try testing.expect(!ring.isFull());

    for (1..5) |i| {
        const e = try ring.enqueueOne();
        e.* = @intCast(i);
        try testing.expect(!ring.isEmpty());
    }
    try testing.expect(ring.isFull());
    try testing.expectError(error.Full, ring.enqueueOne());

    for (0..5) |i| {
        const e = try ring.dequeueOne();
        try testing.expectEqual(@as(u8, @intCast(i)), e.*);
        try testing.expect(!ring.isFull());
    }
    try testing.expectError(error.Empty, ring.dequeueOne());
    try testing.expect(ring.isEmpty());
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_enqueue_many_with]
test "enqueue many with wrap-around" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);

    // First enqueue: buffer empty, read_at resets to 0, full 12 contiguous
    {
        const buf = ring.enqueueMany(12);
        try testing.expectEqual(@as(usize, 12), buf.len);
        @memcpy(buf[0..2], "ab");
        // enqueueMany committed 12, but we only wrote 2 -- adjust
        ring.length = 2;
    }
    // Redo: use enqueueMany properly
    ring.clear();
    @memset(ring.storage, '.');

    {
        const buf = ring.enqueueMany(2);
        @memcpy(buf, "ab");
    }
    try testing.expectEqual(@as(usize, 2), ring.len());
    try testing.expectEqualStrings("ab..........", storageAsStr(&ring));

    {
        const buf = ring.enqueueMany(2);
        @memcpy(buf, "cd");
    }
    try testing.expectEqual(@as(usize, 4), ring.len());
    try testing.expectEqualStrings("abcd........", storageAsStr(&ring));

    {
        const buf = ring.enqueueMany(4);
        @memcpy(buf, "efgh");
    }
    try testing.expectEqual(@as(usize, 8), ring.len());
    try testing.expectEqualStrings("abcdefgh....", storageAsStr(&ring));

    // Dequeue 4 from front
    for (0..4) |_| {
        const e = try ring.dequeueOne();
        e.* = '.';
    }
    try testing.expectEqual(@as(usize, 4), ring.len());
    try testing.expectEqualStrings("....efgh....", storageAsStr(&ring));

    // Enqueue 4 at tail (positions 8..12)
    {
        const buf = ring.enqueueMany(4);
        try testing.expectEqual(@as(usize, 4), buf.len);
        @memcpy(buf, "ijkl");
    }
    try testing.expectEqual(@as(usize, 8), ring.len());
    try testing.expectEqualStrings("....efghijkl", storageAsStr(&ring));

    // Enqueue 4 more -- wraps to positions 0..4
    {
        const buf = ring.enqueueMany(4);
        try testing.expectEqual(@as(usize, 4), buf.len);
        @memcpy(buf, "abcd");
    }
    try testing.expectEqual(@as(usize, 12), ring.len());
    try testing.expectEqualStrings("abcdefghijkl", storageAsStr(&ring));

    // Dequeue 4 again
    for (0..4) |_| {
        const e = try ring.dequeueOne();
        e.* = '.';
    }
    try testing.expectEqual(@as(usize, 8), ring.len());
    try testing.expectEqualStrings("abcd....ijkl", storageAsStr(&ring));
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_enqueue_many]
test "enqueue many contiguous" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);

    {
        const buf = ring.enqueueMany(8);
        @memcpy(buf, "abcdefgh");
    }
    try testing.expectEqual(@as(usize, 8), ring.len());
    try testing.expectEqualStrings("abcdefgh....", storageAsStr(&ring));

    // Request 8 but only 4 contiguous remain at end
    {
        const buf = ring.enqueueMany(8);
        try testing.expectEqual(@as(usize, 4), buf.len);
        @memcpy(buf, "ijkl");
    }
    try testing.expectEqual(@as(usize, 12), ring.len());
    try testing.expectEqualStrings("abcdefghijkl", storageAsStr(&ring));
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_enqueue_slice]
test "enqueue slice with wrap-around" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);

    try testing.expectEqual(@as(usize, 8), ring.enqueueSlice("abcdefgh"));
    try testing.expectEqual(@as(usize, 8), ring.len());
    try testing.expectEqualStrings("abcdefgh....", storageAsStr(&ring));

    for (0..4) |_| {
        const e = try ring.dequeueOne();
        e.* = '.';
    }
    try testing.expectEqual(@as(usize, 4), ring.len());
    try testing.expectEqualStrings("....efgh....", storageAsStr(&ring));

    try testing.expectEqual(@as(usize, 8), ring.enqueueSlice("ijklabcd"));
    try testing.expectEqual(@as(usize, 12), ring.len());
    try testing.expectEqualStrings("abcdefghijkl", storageAsStr(&ring));
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_dequeue_many_with]
test "dequeue many with wrap-around" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);

    try testing.expectEqual(@as(usize, 12), ring.enqueueSlice("abcdefghijkl"));

    // Dequeue first 4
    {
        const buf = ring.dequeueMany(12);
        try testing.expectEqual(@as(usize, 12), buf.len);
        try testing.expectEqualStrings("abcdefghijkl", buf);
        @memcpy(buf[0..4], "....");
        // dequeueMany committed 12 but we want only 4 consumed -- adjust
    }
    // Redo: proper step-by-step
    ring.clear();
    @memset(ring.storage, '.');
    _ = ring.enqueueSlice("abcdefghijkl");

    {
        const buf = ring.dequeueMany(4);
        try testing.expectEqualStrings("abcd", buf);
        @memset(buf, '.');
    }
    try testing.expectEqual(@as(usize, 8), ring.len());
    try testing.expectEqualStrings("....efghijkl", storageAsStr(&ring));

    {
        const buf = ring.dequeueMany(4);
        try testing.expectEqualStrings("efgh", buf);
        @memset(buf, '.');
    }
    try testing.expectEqual(@as(usize, 4), ring.len());
    try testing.expectEqualStrings("........ijkl", storageAsStr(&ring));

    _ = ring.enqueueSlice("abcd");
    try testing.expectEqual(@as(usize, 8), ring.len());

    // Dequeue wraps: first gets ijkl (end of storage), then abcd (start)
    {
        const buf = ring.dequeueMany(4);
        try testing.expectEqualStrings("ijkl", buf);
        @memset(buf, '.');
    }
    {
        const buf = ring.dequeueMany(4);
        try testing.expectEqualStrings("abcd", buf);
        @memset(buf, '.');
    }
    try testing.expectEqual(@as(usize, 0), ring.len());
    try testing.expectEqualStrings("............", storageAsStr(&ring));
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_dequeue_many]
test "dequeue many contiguous" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);

    _ = ring.enqueueSlice("abcdefghijkl");

    {
        const buf = ring.dequeueMany(8);
        try testing.expectEqualStrings("abcdefgh", buf);
        @memset(buf, '.');
    }
    try testing.expectEqual(@as(usize, 4), ring.len());
    try testing.expectEqualStrings("........ijkl", storageAsStr(&ring));

    {
        const buf = ring.dequeueMany(8);
        try testing.expectEqualStrings("ijkl", buf);
        @memset(buf, '.');
    }
    try testing.expectEqual(@as(usize, 0), ring.len());
    try testing.expectEqualStrings("............", storageAsStr(&ring));
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_dequeue_slice]
test "dequeue slice with wrap-around" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);

    _ = ring.enqueueSlice("abcdefghijkl");

    {
        var buf: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 8), ring.dequeueSlice(&buf));
        try testing.expectEqualStrings("abcdefgh", &buf);
        try testing.expectEqual(@as(usize, 4), ring.len());
    }

    _ = ring.enqueueSlice("abcd");

    {
        var buf: [8]u8 = undefined;
        try testing.expectEqual(@as(usize, 8), ring.dequeueSlice(&buf));
        try testing.expectEqualStrings("ijklabcd", &buf);
        try testing.expectEqual(@as(usize, 0), ring.len());
    }
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_get_unallocated]
test "get unallocated with offset and wrap" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);

    // Offset past window returns empty
    try testing.expectEqual(@as(usize, 0), ring.getUnallocated(16, 4).len);

    // Write at offset 0
    {
        const buf = ring.getUnallocated(0, 4);
        @memcpy(buf, "abcd");
    }
    try testing.expectEqualStrings("abcd........", storageAsStr(&ring));

    // Commit 4 via enqueueMany
    {
        const buf_enqueued = ring.enqueueMany(4);
        try testing.expectEqual(@as(usize, 4), buf_enqueued.len);
    }
    try testing.expectEqual(@as(usize, 4), ring.len());

    // Write at offset 4 past allocated (position 8..12)
    {
        const buf = ring.getUnallocated(4, 8);
        @memcpy(buf, "ijkl");
    }
    try testing.expectEqualStrings("abcd....ijkl", storageAsStr(&ring));

    // Fill 8 more, dequeue 4
    @memcpy(ring.enqueueMany(8), "EFGHIJKL");
    @memset(ring.dequeueMany(4), '.');
    try testing.expectEqual(@as(usize, 8), ring.len());
    try testing.expectEqualStrings("....EFGHIJKL", storageAsStr(&ring));

    // Write at offset 0 past allocated (wraps to position 0..4)
    {
        const buf = ring.getUnallocated(0, 8);
        @memcpy(buf, "ABCD");
    }
    try testing.expectEqualStrings("ABCDEFGHIJKL", storageAsStr(&ring));
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_write_unallocated]
test "write unallocated with wrap" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);
    @memcpy(ring.enqueueMany(6), "abcdef");
    @memset(ring.dequeueMany(6), '.');

    // read_at=6, length=0. Write at offset 0 -> positions 6..9
    try testing.expectEqual(@as(usize, 3), ring.writeUnallocated(0, "ghi"));
    try testing.expectEqualStrings("ghi", ring.getUnallocated(0, 3));

    // Write at offset 3 -> positions 9..12 + wrap 0..3
    try testing.expectEqual(@as(usize, 6), ring.writeUnallocated(3, "jklmno"));
    try testing.expectEqualStrings("jkl", ring.getUnallocated(3, 3));

    // Write at offset 9 -> positions 3..6 (only 3 left)
    try testing.expectEqual(@as(usize, 3), ring.writeUnallocated(9, "pqrstu"));
    try testing.expectEqualStrings("pqr", ring.getUnallocated(9, 3));
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_get_allocated]
test "get allocated with offset and wrap" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);

    // Empty: offset past length returns empty
    try testing.expectEqual(@as(usize, 0), ring.getAllocated(16, 4).len);
    try testing.expectEqual(@as(usize, 0), ring.getAllocated(0, 4).len);

    _ = ring.enqueueSlice("abcd");
    try testing.expectEqualStrings("abcd", ring.getAllocated(0, 8));

    _ = ring.enqueueSlice("efghijkl");
    @memset(ring.dequeueMany(4), '.');
    // read_at=4, length=8: efghijkl with read starting at e
    try testing.expectEqualStrings("ijkl", ring.getAllocated(4, 8));

    _ = ring.enqueueSlice("abcd");
    // read_at=4, length=12: full buffer
    try testing.expectEqualStrings("ijkl", ring.getAllocated(4, 8));
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_read_allocated]
test "read allocated with wrap" {
    var backing = [_]u8{'.'} ** 12;
    var ring = RingBufU8.init(&backing);
    @memcpy(ring.enqueueMany(12), "abcdefghijkl");

    {
        var data: [6]u8 = undefined;
        try testing.expectEqual(@as(usize, 6), ring.readAllocated(0, &data));
        try testing.expectEqualStrings("abcdef", &data);
    }

    @memset(ring.dequeueMany(6), '.');
    @memcpy(ring.enqueueMany(3), "mno");
    // read_at=6, length=9: ghijklmno (wraps)

    {
        var data: [6]u8 = undefined;
        try testing.expectEqual(@as(usize, 6), ring.readAllocated(3, &data));
        try testing.expectEqualStrings("jklmno", &data);
    }

    {
        var data = [_]u8{0} ** 6;
        try testing.expectEqual(@as(usize, 3), ring.readAllocated(6, &data));
        try testing.expectEqualStrings("mno", data[0..3]);
    }
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_with_no_capacity]
test "zero capacity buffer" {
    var no_storage: [0]u8 = .{};
    var ring = RingBufU8.init(&no_storage);

    try testing.expectEqual(@as(usize, 0), ring.getUnallocated(0, 0).len);
    try testing.expectEqual(@as(usize, 0), ring.getAllocated(0, 0).len);
    ring.dequeueAllocated(0);
    try testing.expectEqual(@as(usize, 0), ring.enqueueMany(0).len);
    try testing.expectError(error.Full, ring.enqueueOne());
    try testing.expectEqual(@as(usize, 0), ring.contiguousWindow());
}

// [smoltcp:storage/ring_buffer.rs:test_buffer_write_wholly]
test "empty buffer resets position for full write" {
    var backing = [_]u8{'.'} ** 8;
    var ring = RingBufU8.init(&backing);
    @memcpy(ring.enqueueMany(2), "ab");
    @memcpy(ring.enqueueMany(2), "cd");
    try testing.expectEqual(@as(usize, 4), ring.len());
    const buf_dequeued = ring.dequeueMany(4);
    try testing.expectEqualStrings("abcd", buf_dequeued);
    try testing.expectEqual(@as(usize, 0), ring.len());

    // After draining, enqueueMany resets read_at=0, giving full contiguous space
    const large = ring.enqueueMany(8);
    try testing.expectEqual(@as(usize, 8), large.len);
}
