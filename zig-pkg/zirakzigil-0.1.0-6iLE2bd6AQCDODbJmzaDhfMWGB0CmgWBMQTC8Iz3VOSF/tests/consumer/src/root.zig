//! Root of the consumer library: re-exports modules, as zmoltcp's root.zig does.

const zv = @import("zv");

pub const ring_buffer = @import("ring_buffer.zig");
pub const seq = @import("seq.zig");

/// Namespaces nest, like `zmoltcp.wire.tcp`.
pub const storage = struct {
    pub const ring = @import("ring_buffer.zig");
};

pub const assurance = .{};

comptime {
    zv.requireAssurance(@This(), .tested); // walks every re-exported module
}

test {
    _ = ring_buffer;
    _ = seq;
}
