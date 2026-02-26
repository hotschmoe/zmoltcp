// zmoltcp - Pure Zig TCP/IP stack for freestanding targets
//
// Architecturally inspired by smoltcp (Rust no_std).
// See SPEC.md for conformance testing methodology.

pub const wire = struct {
    pub const checksum = @import("wire/checksum.zig");
    pub const ethernet = @import("wire/ethernet.zig");
    pub const arp = @import("wire/arp.zig");
    pub const ip = @import("wire/ip.zig");
    pub const ipv4 = @import("wire/ipv4.zig");
    pub const tcp = @import("wire/tcp.zig");
    pub const udp = @import("wire/udp.zig");
    pub const icmp = @import("wire/icmp.zig");
    pub const dhcp = @import("wire/dhcp.zig");
    pub const dns = @import("wire/dns.zig");
    pub const igmp = @import("wire/igmp.zig");
    pub const ipv6 = @import("wire/ipv6.zig");
    pub const ipv6option = @import("wire/ipv6option.zig");
    pub const ipv6ext_header = @import("wire/ipv6ext_header.zig");
    pub const ipv6fragment = @import("wire/ipv6fragment.zig");
    pub const ipv6routing = @import("wire/ipv6routing.zig");
    pub const ipv6hbh = @import("wire/ipv6hbh.zig");
    pub const icmpv6 = @import("wire/icmpv6.zig");
    pub const ndiscoption = @import("wire/ndiscoption.zig");
    pub const ndisc = @import("wire/ndisc.zig");
    pub const mld = @import("wire/mld.zig");
    pub const ipsec_esp = @import("wire/ipsec_esp.zig");
    pub const ipsec_ah = @import("wire/ipsec_ah.zig");
    pub const rpl = @import("wire/rpl.zig");
    pub const ieee802154 = @import("wire/ieee802154.zig");
    pub const sixlowpan = @import("wire/sixlowpan.zig");
    pub const sixlowpan_frag = @import("wire/sixlowpan_frag.zig");
};

pub const storage = struct {
    pub const ring_buffer = @import("storage/ring_buffer.zig");
    pub const assembler = @import("storage/assembler.zig");
    pub const packet_buffer = @import("storage/packet_buffer.zig");
};

pub const time = @import("time.zig");

pub const socket = struct {
    pub const tcp = @import("socket/tcp.zig");
    pub const udp = @import("socket/udp.zig");
    pub const icmp = @import("socket/icmp.zig");
    pub const dhcp = @import("socket/dhcp.zig");
    pub const dns = @import("socket/dns.zig");
    pub const raw = @import("socket/raw.zig");
};

pub const iface = @import("iface.zig");
pub const fragmentation = @import("fragmentation.zig");
pub const stack = @import("stack.zig");
pub const phy = @import("phy.zig");
pub const rpl_state = @import("rpl.zig");

test {
    // refAllDecls ensures all declarations compile but does NOT discover
    // tests inside modules imported within struct namespaces. Explicit
    // imports below make the test runner collect every module's tests.
    @import("std").testing.refAllDecls(@This());

    _ = @import("wire/checksum.zig");
    _ = @import("wire/ethernet.zig");
    _ = @import("wire/arp.zig");
    _ = @import("wire/ip.zig");
    _ = @import("wire/ipv4.zig");
    _ = @import("wire/udp.zig");
    _ = @import("wire/icmp.zig");
    _ = @import("storage/ring_buffer.zig");
    _ = @import("storage/assembler.zig");
    _ = @import("storage/packet_buffer.zig");
    _ = @import("socket/udp.zig");
    _ = @import("socket/icmp.zig");
    _ = @import("wire/tcp.zig");
    _ = @import("wire/dhcp.zig");
    _ = @import("socket/dhcp.zig");
    _ = @import("socket/tcp.zig");
    _ = @import("wire/dns.zig");
    _ = @import("socket/dns.zig");
    _ = @import("socket/raw.zig");
    _ = @import("wire/igmp.zig");
    _ = @import("wire/ipv6.zig");
    _ = @import("wire/ipv6option.zig");
    _ = @import("wire/ipv6ext_header.zig");
    _ = @import("wire/ipv6fragment.zig");
    _ = @import("wire/ipv6routing.zig");
    _ = @import("wire/ipv6hbh.zig");
    _ = @import("wire/icmpv6.zig");
    _ = @import("wire/ndiscoption.zig");
    _ = @import("wire/ndisc.zig");
    _ = @import("wire/mld.zig");
    _ = @import("wire/ipsec_esp.zig");
    _ = @import("wire/ipsec_ah.zig");
    _ = @import("wire/rpl.zig");
    _ = @import("wire/ieee802154.zig");
    _ = @import("wire/sixlowpan.zig");
    _ = @import("wire/sixlowpan_frag.zig");
    _ = @import("iface.zig");
    _ = @import("fragmentation.zig");
    _ = @import("stack.zig");
    _ = @import("phy.zig");
    _ = @import("rpl.zig");
}
