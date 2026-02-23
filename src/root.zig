// zmoltcp - Pure Zig TCP/IP stack for freestanding targets
//
// Architecturally inspired by smoltcp (Rust no_std).
// See SPEC.md for conformance testing methodology.

pub const wire = struct {
    pub const checksum = @import("wire/checksum.zig");
    pub const ethernet = @import("wire/ethernet.zig");
    pub const arp = @import("wire/arp.zig");
    pub const ipv4 = @import("wire/ipv4.zig");
    pub const tcp = @import("wire/tcp.zig");
    pub const udp = @import("wire/udp.zig");
    pub const icmp = @import("wire/icmp.zig");
};

pub const storage = struct {
    pub const ring_buffer = @import("storage/ring_buffer.zig");
    pub const assembler = @import("storage/assembler.zig");
};

pub const time = @import("time.zig");

pub const socket = struct {
    pub const tcp = @import("socket/tcp.zig");
    pub const udp = @import("socket/udp.zig");
};

test {
    @import("std").testing.refAllDecls(@This());
}
