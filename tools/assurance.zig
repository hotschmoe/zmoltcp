//! `zig build assurance`: per-module assurance table. Every module must carry a
//! manifest at or above the floor; the root is not listed because its own
//! gate already walks the whole tree.

const std = @import("std");
const zv = @import("zv");
const lib = @import("zmoltcp");

pub fn main(init: std.process.Init) !void {
    try zv.report.run(init.io, .{
        .{ "wire.checksum", lib.wire.checksum },
        .{ "wire.ethernet", lib.wire.ethernet },
        .{ "wire.arp", lib.wire.arp },
        .{ "wire.ip", lib.wire.ip },
        .{ "wire.ipv4", lib.wire.ipv4 },
        .{ "wire.tcp", lib.wire.tcp },
        .{ "wire.udp", lib.wire.udp },
        .{ "wire.icmp", lib.wire.icmp },
        .{ "wire.dhcp", lib.wire.dhcp },
        .{ "wire.dns", lib.wire.dns },
        .{ "wire.igmp", lib.wire.igmp },
        .{ "wire.ipv6", lib.wire.ipv6 },
        .{ "wire.ipv6option", lib.wire.ipv6option },
        .{ "wire.ipv6ext_header", lib.wire.ipv6ext_header },
        .{ "wire.ipv6fragment", lib.wire.ipv6fragment },
        .{ "wire.ipv6routing", lib.wire.ipv6routing },
        .{ "wire.ipv6hbh", lib.wire.ipv6hbh },
        .{ "wire.icmpv6", lib.wire.icmpv6 },
        .{ "wire.ndiscoption", lib.wire.ndiscoption },
        .{ "wire.ndisc", lib.wire.ndisc },
        .{ "wire.mld", lib.wire.mld },
        .{ "wire.ipsec_esp", lib.wire.ipsec_esp },
        .{ "wire.ipsec_ah", lib.wire.ipsec_ah },
        .{ "wire.rpl", lib.wire.rpl },
        .{ "wire.ieee802154", lib.wire.ieee802154 },
        .{ "wire.sixlowpan", lib.wire.sixlowpan },
        .{ "wire.sixlowpan_frag", lib.wire.sixlowpan_frag },
        .{ "storage.ring_buffer", lib.storage.ring_buffer },
        .{ "storage.assembler", lib.storage.assembler },
        .{ "storage.packet_buffer", lib.storage.packet_buffer },
        .{ "socket.tcp", lib.socket.tcp },
        .{ "socket.udp", lib.socket.udp },
        .{ "socket.icmp", lib.socket.icmp },
        .{ "socket.dhcp", lib.socket.dhcp },
        .{ "socket.dns", lib.socket.dns },
        .{ "socket.raw", lib.socket.raw },
        .{ "time", lib.time },
        .{ "iface", lib.iface },
        .{ "fragmentation", lib.fragmentation },
        .{ "stack", lib.stack },
        .{ "phy", lib.phy },
        .{ "rpl_state", lib.rpl_state },
    }, .tested);
}
