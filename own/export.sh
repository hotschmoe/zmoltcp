#!/bin/sh
# Exports the AIR packs behind `zig build own` / `zig build own-seeded` again, and pins the sources they come from.
#   own/export.sh ZIRAKZIGIL_CHECKOUT
# The checkout is a zirakzigil tree at the version build.zig.zon pins, with zig-zv built (tools/build_zig_zv.sh there,
# or ZIG_ZV pointing at one). Run it after editing a pinned source (own/PINS names them).
set -eu

[ $# -eq 1 ] || { echo "usage: $0 ZIRAKZIGIL_CHECKOUT" >&2; exit 2; }
here=$(cd "$(dirname "$0")/.." && { pwd -W 2>/dev/null || pwd; })
zk=$(cd "$1" && { pwd -W 2>/dev/null || pwd; })
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The generics are instantiated the way the assurance manifests witness them (every address family for ipv4 and ipv6).
(cd "$zk" && ZVC_DEEP=1 sh tools/zvc_export.sh "$work" "$here/src/root.zig" \
    --only wire --only storage --only time --only iface --only fragmentation --only phy --only rpl_state --only stack --only socket \
    --only 'fragmentation.Fragmenter(64, true)' --only 'fragmentation.SixlowpanFragmenter(64)' \
    --only 'fragmentation.Reassembler(target.fragmentation.FragKey, .{ .buffer_size = 64, .max_segments = 4 })' \
    --only 'iface.RouteFor(target.wire.ipv4)' --only 'iface.RoutesFor(target.wire.ipv4)' --only 'iface.NeighborCache(target.wire.ipv4)' \
    --only 'iface.IpMetaFor(target.wire.ipv4)' --only 'iface.IpState(target.wire.ipv4)' \
    --only 'iface.NeighborCache(target.wire.ipv6)' --only 'iface.IpState(target.wire.ipv6)' \
    --only 'phy.Tracer(target.stack.LoopbackDevice(4))' --only 'phy.FaultInjector(target.stack.LoopbackDevice(4))' \
    --only 'phy.PcapWriter(target.stack.LoopbackDevice(4))' \
    --only 'rpl_state.ParentSet(4)' --only 'rpl_state.Relations(4)' \
    --only 'socket.dns.Socket(target.wire.ipv4)' --only 'socket.icmp.Socket(target.wire.ipv4)' \
    --only 'socket.raw.Socket(target.wire.ipv4, .{ .payload_size = 64 })' \
    --only 'socket.tcp.Socket(target.wire.ipv4, 4)' --only 'socket.udp.Socket(target.wire.ipv4)' \
    --only 'socket.tcp.Socket(target.wire.ipv6, 4)' --only 'socket.udp.Socket(target.wire.ipv6)' \
    --only 'socket.dns.Socket(target.wire.ipv6)' --only 'socket.icmp.Socket(target.wire.ipv6)' \
    --only 'stack.Stack(target.stack.LoopbackDevice(4), void)' --only 'stack.LoopbackDevice(4)' \
    --only 'storage.assembler.Assembler(4)' --only 'storage.packet_buffer.PacketBuffer(void)' \
    --only 'storage.packet_buffer.PacketMeta(void)' --only 'storage.ring_buffer.RingBuffer(u8)' \
    --only 'wire.ip.Cidr(target.wire.ipv4)' --only 'wire.ip.Endpoint(target.wire.ipv4)' --only 'wire.ip.ListenEndpoint(target.wire.ipv4)')
cp "$work/root.zvp" "$here/own/zmoltcp.zvp"

(cd "$zk" && sh tools/zvc_export.sh "$work" "$here/own/seeded.zig" --dep zmoltcp="$here/src/root.zig")
cp "$work/seeded.zvp" "$here/own/seeded.zvp"

(cd "$zk" && zig build zv-air)
"$zk/zig-out/bin/zv-air" dump "$here/own/zmoltcp.zvp" >"$work/lib.json"
"$zk/zig-out/bin/zv-air" dump "$here/own/seeded.zvp" >"$work/seeded.json"
{
    grep -o '{"module":"target","path":"[^"]*"}' "$work/lib.json" | sed 's/.*"path":"\([^"]*\)".*/src\/\1/' | grep -v air_deep.zig
    grep -o '{"module":"zmoltcp","path":"[^"]*"}' "$work/seeded.json" | sed 's/.*"path":"\([^"]*\)".*/src\/\1/'
    echo own/seeded.zig
} | sort -u >"$work/files.txt"

{
    echo "# The sources behind own/zmoltcp.zvp and own/seeded.zvp, as sha256sum writes them (line ends do not count)."
    echo "# After editing one: own/export.sh ZIRAKZIGIL_CHECKOUT (a zirakzigil tree with zig-zv built), then commit the packs and this file."
    while read -r file; do
        printf '%s  %s\n' "$(tr -d '\r' <"$here/$file" | sha256sum | cut -d' ' -f1)" "$file"
    done <"$work/files.txt"
} >"$here/own/PINS"
echo "exported own/zmoltcp.zvp and own/seeded.zvp, pinned $(grep -vc '^#' "$here/own/PINS") sources"
