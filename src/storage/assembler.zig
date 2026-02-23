// TCP segment reassembler
//
// Tracks which byte ranges have been received, enabling out-of-order segment
// buffering. The assembler records holes (missing data) and contiguous data
// regions, coalescing adjacent ranges as gaps are filled.
//
// The contig array is comptime-sized. Each entry represents a hole followed
// by a data region. The invariant: all contigs before some index i have data,
// all after are empty. All contigs with data have hole_size != 0, except
// possibly the first (which represents data starting at offset 0).
//
// [smoltcp:storage/assembler.rs]

const std = @import("std");

pub fn Assembler(comptime max_segment_count: usize) type {
    return struct {
        const Self = @This();

        const Contig = struct {
            hole_size: usize = 0,
            data_size: usize = 0,

            const empty: Contig = .{};

            fn hasHole(self: Contig) bool {
                return self.hole_size != 0;
            }

            fn hasData(self: Contig) bool {
                return self.data_size != 0;
            }

            fn totalSize(self: Contig) usize {
                return self.hole_size + self.data_size;
            }

            fn shrinkHoleTo(self: *Contig, size: usize) void {
                std.debug.assert(self.hole_size >= size);
                const total = self.totalSize();
                self.hole_size = size;
                self.data_size = total - size;
            }
        };

        contigs: [max_segment_count]Contig,

        pub fn init() Self {
            return .{
                .contigs = [_]Contig{Contig.empty} ** max_segment_count,
            };
        }

        pub fn clear(self: *Self) void {
            self.contigs = [_]Contig{Contig.empty} ** max_segment_count;
        }

        pub fn isEmpty(self: Self) bool {
            return !self.contigs[0].hasData();
        }

        pub fn peekFront(self: Self) usize {
            const front = self.contigs[0];
            if (front.hasHole()) return 0;
            return front.data_size;
        }

        fn removeContigAt(self: *Self, at: usize) void {
            std.debug.assert(self.contigs[at].hasData());
            for (at..max_segment_count - 1) |i| {
                if (!self.contigs[i].hasData()) return;
                self.contigs[i] = self.contigs[i + 1];
            }
            self.contigs[max_segment_count - 1] = Contig.empty;
        }

        fn addContigAt(self: *Self, at: usize) error{TooManyHoles}!*Contig {
            if (self.contigs[max_segment_count - 1].hasData()) {
                return error.TooManyHoles;
            }
            var i: usize = max_segment_count - 1;
            while (i > at) : (i -= 1) {
                self.contigs[i] = self.contigs[i - 1];
            }
            self.contigs[at] = Contig.empty;
            return &self.contigs[at];
        }

        pub fn add(self: *Self, offset_arg: usize, size: usize) error{TooManyHoles}!void {
            if (size == 0) return;

            var offset = offset_arg;
            var i: usize = 0;

            // Find index of the contig containing the start of the range.
            while (true) {
                if (i == max_segment_count) {
                    return error.TooManyHoles;
                }
                const contig = &self.contigs[i];
                if (!contig.hasData()) {
                    contig.* = .{ .hole_size = offset, .data_size = size };
                    return;
                }
                if (offset <= contig.totalSize()) {
                    break;
                }
                offset -= contig.totalSize();
                i += 1;
            }

            const contig = &self.contigs[i];
            if (offset < contig.hole_size) {
                if (offset + size < contig.hole_size) {
                    // Range starts and ends within the hole.
                    const new_contig = try self.addContigAt(i);
                    new_contig.hole_size = offset;
                    new_contig.data_size = size;
                    self.contigs[i + 1].hole_size -= offset + size;
                    return;
                }
                // Range covers part of hole and part of data.
                contig.shrinkHoleTo(offset);
            }

            // Coalesce contigs to the right.
            var j: usize = i + 1;
            while (j < max_segment_count and
                self.contigs[j].hasData() and
                offset + size >= self.contigs[i].totalSize() + self.contigs[j].hole_size)
            {
                self.contigs[i].data_size += self.contigs[j].totalSize();
                j += 1;
            }

            const shift = j - i - 1;
            if (shift != 0) {
                for (i + 1..max_segment_count) |x| {
                    if (!self.contigs[x].hasData()) break;
                    if (x + shift < max_segment_count) {
                        self.contigs[x] = self.contigs[x + shift];
                    } else {
                        self.contigs[x] = Contig.empty;
                    }
                }
            }

            if (offset + size > self.contigs[i].totalSize()) {
                const left = offset + size - self.contigs[i].totalSize();
                self.contigs[i].data_size += left;

                if (i + 1 < max_segment_count and self.contigs[i + 1].hasData()) {
                    self.contigs[i + 1].hole_size -= left;
                }
            }
        }

        pub fn removeFront(self: *Self) usize {
            const front = self.contigs[0];
            if (front.hasHole() or !front.hasData()) {
                return 0;
            }
            self.removeContigAt(0);
            return front.data_size;
        }

        pub fn addThenRemoveFront(self: *Self, offset: usize, size: usize) error{TooManyHoles}!usize {
            // Special case: segment at offset=0 that partially fills the front
            // hole. Handle without add() to guarantee no TooManyHoles.
            if (offset == 0 and size < self.contigs[0].hole_size) {
                self.contigs[0].hole_size -= size;
                return size;
            }
            try self.add(offset, size);
            return self.removeFront();
        }

        pub const Iterator = struct {
            contigs: []const Contig,
            offset: usize,
            index: usize,
            left: usize,
            right: usize,

            pub fn next(self: *Iterator) ?struct { usize, usize } {
                while (self.index < self.contigs.len) {
                    const contig = self.contigs[self.index];
                    self.left += contig.hole_size;
                    self.right = self.left + contig.data_size;
                    self.index += 1;
                    if (self.left < self.right) {
                        const result = .{ self.left + self.offset, self.right + self.offset };
                        self.left = self.right;
                        return result;
                    }
                }
                return null;
            }
        };

        pub fn iterData(self: *const Self, first_offset: usize) Iterator {
            return .{
                .contigs = &self.contigs,
                .offset = first_offset,
                .index = 0,
                .left = 0,
                .right = 0,
            };
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;
const TestAssembler = Assembler(4);

fn expectContigs(expected: []const [2]usize, asmb: *const TestAssembler) !void {
    for (expected, 0..) |pair, i| {
        try testing.expectEqual(pair[0], asmb.contigs[i].hole_size);
        try testing.expectEqual(pair[1], asmb.contigs[i].data_size);
    }
    // Remaining contigs must be empty.
    for (expected.len..4) |i| {
        try testing.expectEqual(@as(usize, 0), asmb.contigs[i].hole_size);
        try testing.expectEqual(@as(usize, 0), asmb.contigs[i].data_size);
    }
}

fn collectIter(asmb: *const TestAssembler, offset: usize) [4][2]usize {
    var iter = asmb.iterData(offset);
    var result: [4][2]usize = .{.{ 0, 0 }} ** 4;
    var i: usize = 0;
    while (iter.next()) |pair| {
        if (i < 4) {
            result[i] = .{ pair[0], pair[1] };
            i += 1;
        }
    }
    return result;
}

fn iterCount(asmb: *const TestAssembler, offset: usize) usize {
    var iter = asmb.iterData(offset);
    var count: usize = 0;
    while (iter.next()) |_| count += 1;
    return count;
}

// [smoltcp:storage/assembler.rs:test_new]
test "new assembler is empty" {
    const asmb = TestAssembler.init();
    try expectContigs(&.{}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_empty_add_full]
test "add full range to empty" {
    var asmb = TestAssembler.init();
    try asmb.add(0, 16);
    try expectContigs(&.{.{ 0, 16 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_empty_add_front]
test "add front range to empty" {
    var asmb = TestAssembler.init();
    try asmb.add(0, 4);
    try expectContigs(&.{.{ 0, 4 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_empty_add_back]
test "add back range to empty" {
    var asmb = TestAssembler.init();
    try asmb.add(12, 4);
    try expectContigs(&.{.{ 12, 4 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_empty_add_mid]
test "add middle range to empty" {
    var asmb = TestAssembler.init();
    try asmb.add(4, 8);
    try expectContigs(&.{.{ 4, 8 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_partial_add_front]
test "add adjacent front range" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    try asmb.add(0, 4);
    try expectContigs(&.{.{ 0, 12 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_partial_add_back]
test "add adjacent back range" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    try asmb.add(12, 4);
    try expectContigs(&.{.{ 4, 12 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_partial_add_front_overlap]
test "add overlapping front range" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    try asmb.add(0, 8);
    try expectContigs(&.{.{ 0, 12 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_partial_add_front_overlap_split]
test "add partially overlapping front range" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    try asmb.add(2, 6);
    try expectContigs(&.{.{ 2, 10 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_partial_add_back_overlap]
test "add overlapping back range" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    try asmb.add(8, 8);
    try expectContigs(&.{.{ 4, 12 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_partial_add_back_overlap_split]
test "add partially overlapping back range" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    try asmb.add(10, 4);
    try expectContigs(&.{.{ 4, 10 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_partial_add_both_overlap]
test "add range covering entire contig" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    try asmb.add(0, 16);
    try expectContigs(&.{.{ 0, 16 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_partial_add_both_overlap_split]
test "add range covering most of contig" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    try asmb.add(2, 12);
    try expectContigs(&.{.{ 2, 12 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_rejected_add_keeps_state]
test "rejected add preserves state" {
    var asmb = TestAssembler.init();
    for (1..5) |c| {
        try asmb.add(c * 10, 3);
    }
    // Maximum holes reached -- save state
    const saved = asmb;
    try testing.expectError(error.TooManyHoles, asmb.add(1, 3));
    // State must be unchanged after failed add
    for (0..4) |i| {
        try testing.expectEqual(saved.contigs[i].hole_size, asmb.contigs[i].hole_size);
        try testing.expectEqual(saved.contigs[i].data_size, asmb.contigs[i].data_size);
    }
}

// [smoltcp:storage/assembler.rs:test_empty_remove_front]
test "remove front from empty" {
    var asmb = TestAssembler.init();
    try testing.expectEqual(@as(usize, 0), asmb.removeFront());
}

// [smoltcp:storage/assembler.rs:test_trailing_hole_remove_front]
test "remove front with no trailing data" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 0, .data_size = 4 };
    try testing.expectEqual(@as(usize, 4), asmb.removeFront());
    try expectContigs(&.{}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_trailing_data_remove_front]
test "remove front with trailing data" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 0, .data_size = 4 };
    asmb.contigs[1] = .{ .hole_size = 4, .data_size = 4 };
    try testing.expectEqual(@as(usize, 4), asmb.removeFront());
    try expectContigs(&.{.{ 4, 4 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_boundary_case_remove_front]
test "remove front boundary case max contigs" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 0, .data_size = 2 };
    for (1..4) |i| {
        asmb.contigs[i] = .{ .hole_size = 1, .data_size = 1 };
    }
    try testing.expectEqual(@as(usize, 2), asmb.removeFront());
    try expectContigs(&.{ .{ 1, 1 }, .{ 1, 1 }, .{ 1, 1 } }, &asmb);
}

// [smoltcp:storage/assembler.rs:test_shrink_next_hole]
test "add shrinks next hole" {
    var asmb = TestAssembler.init();
    try asmb.add(100, 10);
    try asmb.add(50, 10);
    try asmb.add(40, 30);
    try expectContigs(&.{ .{ 40, 30 }, .{ 30, 10 } }, &asmb);
}

// [smoltcp:storage/assembler.rs:test_join_two]
test "add joins two separate ranges" {
    var asmb = TestAssembler.init();
    try asmb.add(10, 10);
    try asmb.add(50, 10);
    try asmb.add(15, 40);
    try expectContigs(&.{.{ 10, 50 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_join_two_reversed]
test "add joins two ranges reversed order" {
    var asmb = TestAssembler.init();
    try asmb.add(50, 10);
    try asmb.add(10, 10);
    try asmb.add(15, 40);
    try expectContigs(&.{.{ 10, 50 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_join_two_overlong]
test "add joins and extends beyond" {
    var asmb = TestAssembler.init();
    try asmb.add(50, 10);
    try asmb.add(10, 10);
    try asmb.add(15, 60);
    try expectContigs(&.{.{ 10, 65 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_iter_empty]
test "iter empty assembler" {
    const asmb = TestAssembler.init();
    try testing.expectEqual(@as(usize, 0), iterCount(&asmb, 10));
}

// [smoltcp:storage/assembler.rs:test_iter_full]
test "iter full assembler" {
    var asmb = TestAssembler.init();
    try asmb.add(0, 16);
    const result = collectIter(&asmb, 10);
    try testing.expectEqual(@as(usize, 1), iterCount(&asmb, 10));
    try testing.expectEqual(@as(usize, 10), result[0][0]);
    try testing.expectEqual(@as(usize, 26), result[0][1]);
}

// [smoltcp:storage/assembler.rs:test_iter_offset]
test "iter with offset" {
    var asmb = TestAssembler.init();
    try asmb.add(0, 16);
    const result = collectIter(&asmb, 100);
    try testing.expectEqual(@as(usize, 1), iterCount(&asmb, 100));
    try testing.expectEqual(@as(usize, 100), result[0][0]);
    try testing.expectEqual(@as(usize, 116), result[0][1]);
}

// [smoltcp:storage/assembler.rs:test_iter_one_front]
test "iter one front range" {
    var asmb = TestAssembler.init();
    try asmb.add(0, 4);
    const result = collectIter(&asmb, 10);
    try testing.expectEqual(@as(usize, 1), iterCount(&asmb, 10));
    try testing.expectEqual(@as(usize, 10), result[0][0]);
    try testing.expectEqual(@as(usize, 14), result[0][1]);
}

// [smoltcp:storage/assembler.rs:test_iter_one_back]
test "iter one back range" {
    var asmb = TestAssembler.init();
    try asmb.add(12, 4);
    const result = collectIter(&asmb, 10);
    try testing.expectEqual(@as(usize, 1), iterCount(&asmb, 10));
    try testing.expectEqual(@as(usize, 22), result[0][0]);
    try testing.expectEqual(@as(usize, 26), result[0][1]);
}

// [smoltcp:storage/assembler.rs:test_iter_one_mid]
test "iter one middle range" {
    var asmb = TestAssembler.init();
    try asmb.add(4, 8);
    const result = collectIter(&asmb, 10);
    try testing.expectEqual(@as(usize, 1), iterCount(&asmb, 10));
    try testing.expectEqual(@as(usize, 14), result[0][0]);
    try testing.expectEqual(@as(usize, 22), result[0][1]);
}

// [smoltcp:storage/assembler.rs:test_iter_one_trailing_gap]
test "iter one range with trailing gap" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 4, .data_size = 8 };
    const result = collectIter(&asmb, 100);
    try testing.expectEqual(@as(usize, 1), iterCount(&asmb, 100));
    try testing.expectEqual(@as(usize, 104), result[0][0]);
    try testing.expectEqual(@as(usize, 112), result[0][1]);
}

// [smoltcp:storage/assembler.rs:test_iter_two_split]
test "iter two split ranges" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 2, .data_size = 6 };
    asmb.contigs[1] = .{ .hole_size = 4, .data_size = 1 };
    const result = collectIter(&asmb, 100);
    try testing.expectEqual(@as(usize, 2), iterCount(&asmb, 100));
    try testing.expectEqual(@as(usize, 102), result[0][0]);
    try testing.expectEqual(@as(usize, 108), result[0][1]);
    try testing.expectEqual(@as(usize, 112), result[1][0]);
    try testing.expectEqual(@as(usize, 113), result[1][1]);
}

// [smoltcp:storage/assembler.rs:test_iter_three_split]
test "iter three split ranges" {
    var asmb = TestAssembler.init();
    asmb.contigs[0] = .{ .hole_size = 2, .data_size = 6 };
    asmb.contigs[1] = .{ .hole_size = 2, .data_size = 1 };
    asmb.contigs[2] = .{ .hole_size = 2, .data_size = 2 };
    const result = collectIter(&asmb, 100);
    try testing.expectEqual(@as(usize, 3), iterCount(&asmb, 100));
    try testing.expectEqual(@as(usize, 102), result[0][0]);
    try testing.expectEqual(@as(usize, 108), result[0][1]);
    try testing.expectEqual(@as(usize, 110), result[1][0]);
    try testing.expectEqual(@as(usize, 111), result[1][1]);
    try testing.expectEqual(@as(usize, 113), result[2][0]);
    try testing.expectEqual(@as(usize, 115), result[2][1]);
}

// [smoltcp:storage/assembler.rs:test_issue_694]
test "adjacent segments coalesce regression" {
    var asmb = TestAssembler.init();
    try asmb.add(0, 1);
    try asmb.add(2, 1);
    try asmb.add(1, 1);
    try expectContigs(&.{.{ 0, 3 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_add_then_remove_front]
test "add then remove front non-contiguous" {
    var asmb = TestAssembler.init();
    try asmb.add(50, 10);
    try testing.expectEqual(@as(usize, 0), try asmb.addThenRemoveFront(10, 10));
    try expectContigs(&.{ .{ 10, 10 }, .{ 30, 10 } }, &asmb);
}

// [smoltcp:storage/assembler.rs:test_add_then_remove_front_at_front]
test "add then remove front at front" {
    var asmb = TestAssembler.init();
    try asmb.add(50, 10);
    try testing.expectEqual(@as(usize, 10), try asmb.addThenRemoveFront(0, 10));
    try expectContigs(&.{.{ 40, 10 }}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_add_then_remove_front_at_front_touch]
test "add then remove front touching" {
    var asmb = TestAssembler.init();
    try asmb.add(50, 10);
    try testing.expectEqual(@as(usize, 60), try asmb.addThenRemoveFront(0, 50));
    try expectContigs(&.{}, &asmb);
}

// [smoltcp:storage/assembler.rs:test_add_then_remove_front_at_front_full]
test "add then remove front when full" {
    var asmb = TestAssembler.init();
    for (1..5) |c| {
        try asmb.add(c * 10, 3);
    }
    const saved = asmb;
    try testing.expectError(error.TooManyHoles, asmb.addThenRemoveFront(1, 3));
    for (0..4) |i| {
        try testing.expectEqual(saved.contigs[i].hole_size, asmb.contigs[i].hole_size);
        try testing.expectEqual(saved.contigs[i].data_size, asmb.contigs[i].data_size);
    }
}

// [smoltcp:storage/assembler.rs:test_add_then_remove_front_at_front_full_offset_0]
test "add then remove front offset 0 when full" {
    var asmb = TestAssembler.init();
    for (1..5) |c| {
        try asmb.add(c * 10, 3);
    }
    try testing.expectEqual(@as(usize, 3), try asmb.addThenRemoveFront(0, 3));
}
