// Dual-ring packet buffer for variable-length datagram storage.
//
// Pairs a metadata ring (PacketMeta(H)) with a payload ring (u8) to store
// variable-length packets without per-packet size limits. Padding entries
// are inserted when contiguous tail space is insufficient.
//
// Reference: smoltcp src/storage/packet_buffer.rs

const ring_buffer_mod = @import("ring_buffer.zig");

pub fn PacketMeta(comptime H: type) type {
    return struct {
        size: usize = 0,
        header: ?H = null,

        pub fn isPadding(self: @This()) bool {
            return self.header == null;
        }
    };
}

pub fn PacketBuffer(comptime H: type) type {
    const Meta = PacketMeta(H);
    const MetaRing = ring_buffer_mod.RingBuffer(Meta);
    const PayloadRing = ring_buffer_mod.RingBuffer(u8);

    return struct {
        const Self = @This();

        metadata: MetaRing,
        payload: PayloadRing,

        pub fn init(meta_storage: []Meta, payload_storage: []u8) Self {
            return .{
                .metadata = MetaRing.init(meta_storage),
                .payload = PayloadRing.init(payload_storage),
            };
        }

        pub fn isEmpty(self: Self) bool {
            return self.metadata.isEmpty();
        }

        pub fn isFull(self: Self) bool {
            return self.metadata.isFull();
        }

        pub fn packetCapacity(self: Self) usize {
            return self.metadata.capacity();
        }

        pub fn payloadCapacity(self: Self) usize {
            return self.payload.capacity();
        }

        pub fn reset(self: *Self) void {
            self.metadata.clear();
            self.payload.clear();
        }

        pub fn enqueue(self: *Self, size: usize, header: H) error{Full}![]u8 {
            if (size > self.payload.capacity()) return error.Full;
            if (self.payload.window() < size) return error.Full;

            var contig = if (self.payload.isEmpty())
                self.payload.capacity()
            else
                self.payload.contiguousWindow();
            if (contig < size) {
                if (self.metadata.window() < 2) return error.Full;
                if (self.payload.window() - contig < size) return error.Full;

                const pad = self.metadata.enqueueOne() catch return error.Full;
                pad.* = .{ .size = contig, .header = null };
                _ = self.payload.enqueueMany(contig);
                contig = self.payload.contiguousWindow();
            }

            if (self.metadata.isFull()) return error.Full;
            const meta = self.metadata.enqueueOne() catch return error.Full;
            meta.* = .{ .size = size, .header = header };
            return self.payload.enqueueMany(size);
        }

        pub fn dequeue(self: *Self) error{Empty}!struct { header: H, payload: []u8 } {
            self.dequeuePadding();
            if (self.metadata.isEmpty()) return error.Empty;
            const meta = self.metadata.dequeueOne() catch return error.Empty;
            const buf = self.payload.dequeueMany(meta.size);
            return .{
                .header = meta.header.?,
                .payload = buf,
            };
        }

        pub fn peek(self: *Self) error{Empty}!struct { header: *const H, payload: []const u8 } {
            self.dequeuePadding();
            if (self.metadata.isEmpty()) return error.Empty;
            const meta_slice = self.metadata.getAllocated(0, 1);
            if (meta_slice.len == 0) return error.Empty;
            const meta = &meta_slice[0];
            const payload_slice = self.payload.getAllocated(0, meta.size);
            return .{
                .header = &meta.header.?,
                .payload = payload_slice,
            };
        }

        fn dequeuePadding(self: *Self) void {
            while (!self.metadata.isEmpty()) {
                const slice = self.metadata.getAllocated(0, 1);
                if (slice.len == 0) break;
                if (!slice[0].isPadding()) break;
                const pad = self.metadata.dequeueOne() catch break;
                _ = self.payload.dequeueMany(pad.size);
            }
        }
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = @import("std").testing;

const TestBuffer = PacketBuffer(void);
const TestMeta = PacketMeta(void);

fn buffer() struct { buf: TestBuffer, meta: *[4]TestMeta, payload: *[16]u8 } {
    const S = struct {
        var meta: [4]TestMeta = .{TestMeta{}} ** 4;
        var payload: [16]u8 = .{0} ** 16;
    };
    S.meta = .{TestMeta{}} ** 4;
    S.payload = .{0} ** 16;
    return .{
        .buf = TestBuffer.init(&S.meta, &S.payload),
        .meta = &S.meta,
        .payload = &S.payload,
    };
}

// [smoltcp:storage/packet_buffer.rs:test_simple]
test "enqueue dequeue simple" {
    var ctx = buffer();
    var b = &ctx.buf;

    const slice = try b.enqueue(6, {});
    try testing.expectEqual(@as(usize, 6), slice.len);
    @memcpy(slice[0..6], "abcdef");

    const result = try b.dequeue();
    try testing.expectEqualSlices(u8, "abcdef", result.payload);

    try testing.expectError(error.Empty, b.dequeue());
}

// [smoltcp:storage/packet_buffer.rs:test_peek]
test "peek does not consume" {
    var ctx = buffer();
    var b = &ctx.buf;

    try testing.expectError(error.Empty, b.peek());

    const slice = try b.enqueue(4, {});
    @memcpy(slice[0..4], "test");

    const peeked = try b.peek();
    try testing.expectEqualSlices(u8, "test", peeked.payload);

    const result = try b.dequeue();
    try testing.expectEqualSlices(u8, "test", result.payload);

    try testing.expectError(error.Empty, b.peek());
}

// [smoltcp:storage/packet_buffer.rs:test_padding]
test "padding inserted when contiguous tail too small" {
    var ctx = buffer();
    var b = &ctx.buf;

    // Enqueue 6 + 8 = 14 of 16 bytes
    _ = try b.enqueue(6, {});
    _ = try b.enqueue(8, {});

    // Dequeue first (frees 6 bytes at head)
    _ = try b.dequeue();

    // Enqueue 4 -- only 2 bytes at tail, needs padding
    const slice = try b.enqueue(4, {});
    try testing.expectEqual(@as(usize, 4), slice.len);

    // Drain remaining
    _ = try b.dequeue(); // the 8-byte entry
    _ = try b.dequeue(); // the 4-byte entry
    try testing.expectError(error.Empty, b.dequeue());
}

// [smoltcp:storage/packet_buffer.rs:test_padding_with_large_payload]
test "padding with large payload wraps around" {
    var ctx = buffer();
    var b = &ctx.buf;

    _ = try b.enqueue(12, {});
    _ = try b.dequeue();
    // 12 bytes free starting at offset 12, only 4 contiguous at tail
    _ = try b.enqueue(12, {});
    _ = try b.dequeue();
}

// [smoltcp:storage/packet_buffer.rs:test_metadata_full_empty]
test "metadata ring limits packet count" {
    var ctx = buffer();
    var b = &ctx.buf;

    try testing.expect(b.isEmpty());
    try testing.expect(!b.isFull());

    _ = try b.enqueue(1, {});
    _ = try b.enqueue(1, {});
    _ = try b.enqueue(1, {});
    _ = try b.enqueue(1, {});

    try testing.expect(b.isFull());
    try testing.expect(!b.isEmpty());
    try testing.expectError(error.Full, b.enqueue(1, {}));

    _ = try b.dequeue();
    try testing.expect(!b.isFull());
}

// [smoltcp:storage/packet_buffer.rs:test_window_too_small]
test "enqueue fails when total window insufficient" {
    var ctx = buffer();
    var b = &ctx.buf;

    _ = try b.enqueue(4, {});
    _ = try b.enqueue(8, {});
    _ = try b.dequeue();
    // 4 bytes free at head + 4 at tail = 8 total
    // But 16 requested
    try testing.expectError(error.Full, b.enqueue(16, {}));
}

// [smoltcp:storage/packet_buffer.rs:test_contiguous_window_too_small]
test "enqueue fails when wrap would exhaust metadata" {
    var ctx = buffer();
    var b = &ctx.buf;

    // Fill: 4 + 8 = 12 bytes, using 2 of 4 metadata slots
    _ = try b.enqueue(4, {});
    _ = try b.enqueue(8, {});
    // Dequeue first: 4 bytes free at head, 4 at tail
    _ = try b.dequeue();
    // Enqueue 8: needs padding (4 tail) + entry (8). Padding takes 1 meta slot,
    // entry takes 1 meta slot. We have 2 meta slots free (of 4, 1 used by 8-byte).
    // BUT 4 (freed at head) < 8 needed for payload after padding.
    try testing.expectError(error.Full, b.enqueue(8, {}));
}

// [smoltcp:storage/packet_buffer.rs:test_contiguous_window_wrap]
test "successful wrap around with padding" {
    var ctx = buffer();
    var b = &ctx.buf;

    const s1 = try b.enqueue(15, {});
    try testing.expectEqual(@as(usize, 15), s1.len);
    _ = try b.dequeue();

    // 1 byte at tail, 15 at head after wrap (with padding eating 1 byte)
    const s2 = try b.enqueue(16, {});
    try testing.expectEqual(@as(usize, 16), s2.len);
    _ = try b.dequeue();
}

// [smoltcp:storage/packet_buffer.rs:test_capacity_too_small]
test "enqueue larger than capacity fails immediately" {
    var ctx = buffer();
    var b = &ctx.buf;
    try testing.expectError(error.Full, b.enqueue(32, {}));
}

// [smoltcp:storage/packet_buffer.rs:test_contig_window_prioritized]
test "contiguous window prioritized over wrap" {
    var ctx = buffer();
    var b = &ctx.buf;

    _ = try b.enqueue(4, {});
    _ = try b.dequeue();
    // Contiguous window starts at offset 4, goes to 16 = 12 bytes
    const slice = try b.enqueue(5, {});
    try testing.expectEqual(@as(usize, 5), slice.len);
    _ = try b.dequeue();
}

// [smoltcp:storage/packet_buffer.rs:clear]
test "reset clears buffer" {
    var ctx = buffer();
    var b = &ctx.buf;

    _ = try b.enqueue(6, {});
    try testing.expect(!b.isEmpty());
    b.reset();
    try testing.expect(b.isEmpty());
    try testing.expectError(error.Empty, b.dequeue());
}

// (original)
test "PacketBuffer with typed header" {
    const Hdr = struct { port: u16 };
    const PB = PacketBuffer(Hdr);
    const PM = PacketMeta(Hdr);

    const S = struct {
        var meta: [4]PM = .{PM{}} ** 4;
        var payload: [32]u8 = .{0} ** 32;
    };
    S.meta = .{PM{}} ** 4;
    S.payload = .{0} ** 32;

    var b = PB.init(&S.meta, &S.payload);
    const slice = try b.enqueue(5, .{ .port = 1234 });
    @memcpy(slice[0..5], "hello");

    const result = try b.dequeue();
    try testing.expectEqual(@as(u16, 1234), result.header.port);
    try testing.expectEqualSlices(u8, "hello", result.payload);
}
