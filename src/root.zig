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
    pub const dhcp = @import("wire/dhcp.zig");
    pub const dns = @import("wire/dns.zig");
};

pub const storage = struct {
    pub const ring_buffer = @import("storage/ring_buffer.zig");
    pub const assembler = @import("storage/assembler.zig");
};

pub const time = @import("time.zig");

pub const socket = struct {
    pub const tcp = @import("socket/tcp.zig");
    pub const udp = @import("socket/udp.zig");
    pub const icmp = @import("socket/icmp.zig");
    pub const dhcp = @import("socket/dhcp.zig");
    pub const dns = @import("socket/dns.zig");
};

test {
    // refAllDecls ensures all declarations compile but does NOT discover
    // tests inside modules imported within struct namespaces. Explicit
    // imports below make the test runner collect every module's tests.
    @import("std").testing.refAllDecls(@This());

    _ = @import("wire/checksum.zig");
    _ = @import("wire/ethernet.zig");
    _ = @import("wire/arp.zig");
    _ = @import("wire/ipv4.zig");
    _ = @import("wire/udp.zig");
    _ = @import("wire/icmp.zig");
    _ = @import("storage/ring_buffer.zig");
    _ = @import("storage/assembler.zig");
    _ = @import("socket/udp.zig");
    _ = @import("socket/icmp.zig");
    _ = @import("wire/tcp.zig");
    _ = @import("wire/dhcp.zig");
    _ = @import("socket/dhcp.zig");
    _ = @import("socket/tcp.zig");
    _ = @import("wire/dns.zig");
    _ = @import("socket/dns.zig");
}
