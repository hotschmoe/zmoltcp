# zmoltcp

A pure Zig dual-stack (IPv4/IPv6) TCP/IP stack for freestanding targets,
architecturally inspired by [smoltcp](https://github.com/smoltcp-rs/smoltcp)
(Rust no_std).

## What This Is

zmoltcp is a standalone, zero-allocation network stack designed for bare-metal
and custom OS use. It implements full dual-stack IPv4/IPv6 networking with
comptime-parameterized generics -- zero runtime branching on address type,
dead code elimination for single-stack builds, and type safety that prevents
accidentally passing a v6 address to a v4 socket.

Supported protocols: TCP (full state machine, SACK, timestamps, Reno/Cubic),
UDP, ICMPv4/v6, ARP, NDP, IGMP, MLD, SLAAC, DHCPv4, DNS (including mDNS),
raw sockets, IPv4/IPv6 fragmentation/reassembly, IEEE 802.15.4, 6LoWPAN,
RPL, IPsec ESP/AH wire formats.

Supported mediums: Ethernet (Layer 2), raw IP (Layer 3, TUN/PPP),
IEEE 802.15.4 (constrained IoT).

Primary consumer: [Laminae](https://github.com/hotschmoe/laminae), a
container-native research kernel for ARM64. But zmoltcp has no kernel
dependencies -- it is a pure protocol library that any freestanding Zig
project can use.

## Development Philosophy

**Make it work, make it right, make it fast** -- in that order.

**This codebase will outlive you** -- every shortcut becomes someone else's
burden. Patterns you establish will be copied. Corners you cut will be cut
again.

**Fight entropy** -- leave the codebase better than you found it.

**Inspiration vs. Recreation** -- we take inspiration from well-established
patterns (smoltcp, RFCs) and make them our own in idiomatic Zig. We do not
reinvent the wheel for the sake of it, but we also do not shy away from
unconventional approaches when they serve the design better.

## Design Principles

- **Comptime dual-stack**: Each socket, endpoint, and routing type is
  parameterized over an `Ip` type (ipv4 or ipv6). The compiler generates
  fully specialized code per IP version. No enum tag checks in the hot path.

- **Explicit poll model**: No background timers or callbacks. Call `poll()`
  with a timestamp, it tells you what to do. Your event loop owns the
  scheduling.

- **Zero allocation**: All buffers are caller-provided slices. No allocator
  interface, no hidden heap usage. Packet buffers are `[]u8` pointing into
  your DMA pool or wherever you want.

- **Stateless layers**: Wire parsing is pure: bytes in, structured data out.
  Socket state machines are explicit tagged unions -- the compiler enforces
  exhaustive handling of every TCP state.

- **Clean layer separation**: `wire/` handles parsing and serialization.
  `socket/` handles protocol state machines. `iface` routes packets. Each
  layer is independently testable.

## Architecture

```
src/
  wire/                  Protocol wire formats (parse + serialize)
    checksum.zig         IP/TCP/UDP internet checksum (RFC 1071)
    ethernet.zig         Ethernet II frame
    ip.zig               Generic Ip comptime contract, Cidr(Ip), Endpoint(Ip)
    arp.zig              ARP request/reply (Ethernet+IPv4)
    ipv4.zig             IPv4 header, Address, Protocol enum
    ipv6.zig             IPv6 header, Address, Protocol enum
    ipv6option.zig       IPv6 extension header TLV options
    ipv6ext_header.zig   Generic extension header base (next_header + length)
    ipv6fragment.zig     Fragment extension header (RFC 8200)
    ipv6routing.zig      Routing extension header (Type 2, RPL)
    ipv6hbh.zig          Hop-by-Hop options header
    tcp.zig              TCP header + options (MSS, window scale, SACK, timestamps)
    udp.zig              UDP datagram
    icmp.zig             ICMPv4 (echo, unreachable, time exceeded)
    icmpv6.zig           ICMPv6 (echo, NDP, MLD, RPL dispatch)
    ndisc.zig            NDP (RFC 4861): RS/RA/NS/NA/Redirect
    ndiscoption.zig      NDP options (SLLA, TLLA, PrefixInfo, MTU)
    mld.zig              MLDv2 (RFC 3810): multicast listener query/report
    igmp.zig             IGMPv1/v2 multicast group management
    dhcp.zig             DHCPv4 packet format
    dns.zig              DNS query/response (RFC 1035)
    ipsec_esp.zig        IPsec ESP header (RFC 4303)
    ipsec_ah.zig         IPsec AH header (RFC 4302)
    ieee802154.zig       IEEE 802.15.4 MAC frame
    sixlowpan.zig        6LoWPAN IPHC/NHC compression (RFC 6282)
    sixlowpan_frag.zig   6LoWPAN fragmentation (FRAG1/FRAGN)
    rpl.zig              RPL wire format (RFC 6550): DIS/DIO/DAO

  socket/                Protocol state machines
    tcp.zig              TCP FSM (RFC 793), congestion control (Reno/Cubic)
    udp.zig              UDP datagram send/recv
    icmp.zig             ICMP/ICMPv6 echo request/response tracking
    raw.zig              Raw IP socket (bind to protocol number)
    dhcp.zig             DHCPv4 client (DISCOVER/OFFER/REQUEST/ACK)
    dns.zig              DNS/mDNS resolver client

  storage/               Data structures
    ring_buffer.zig      Generic ring buffer (TX/RX queues)
    assembler.zig        TCP/IP out-of-order segment reassembly
    packet_buffer.zig    Dual-ring datagram store (UDP/ICMP/DNS)

  iface.zig              Network interface: ARP/NDP cache, ICMP auto-reply,
                         MLD/IGMP multicast, SLAAC, medium dispatch
  stack.zig              Top-level poll loop: protocol demux, socket dispatch,
                         fragmentation, 6LoWPAN, egress serialization
  fragmentation.zig      IPv4/IPv6/6LoWPAN fragmentation and reassembly
  phy.zig                PHY middleware: Tracer, FaultInjector, PcapWriter
  rpl.zig                RPL state machine (RFC 6550/6552/6206)
  time.zig               Timestamp/Duration types (i64 microseconds)
  root.zig               Library entry point (public API)
```

examples/
  loopback_echo.zig    TCP echo on single stack (loopback device)
  back_to_back.zig     TCP transfer between two stacks (simulated wire)
  udp_icmp.zig         UDP exchange + ICMP ping (two stacks)
```

## Building

```bash
# Run all tests (on host -- no VM, no hardware needed)
zig build test

# Cross-compile check for freestanding ARM64
zig build -Dtarget=aarch64-freestanding-none

# Build as static library (native)
zig build
```

Zig version: 0.15.2

## Testing

818 tests passing across all modules. Tests are transliterated from smoltcp's
test suite where applicable (see SPEC.md for the conformance testing
methodology and tests/CONFORMANCE.md for per-test tracking). The smoltcp
source is included as a git submodule under `ref/smoltcp/` for reference.

**Tests are diagnostic tools, not success criteria.** A passing suite does not
mean the code is good. A failing test does not mean the code is wrong. Tests
are valuable for regression detection, sanity checks, and documenting current
behavior -- but they are not a definition of correctness. The real metric is
whether the code furthers the project's vision.

```bash
# Run all unit tests
zig build test

# Run with verbose output
zig build test -- --summary all
```

## Integration Demos

Three end-to-end demos exercise the full stack API (sockets -> Stack poll
loop -> LoopbackDevice) with no manual packet construction. They serve as
both functional validation and usage documentation.

```bash
# Run all demos
zig build demo

# Run with verbose output
zig build demo -- --summary all
```

| Demo | File | What it proves |
|------|------|----------------|
| TCP loopback echo | `examples/loopback_echo.zig` | Full TCP lifecycle on a single stack: ARP, handshake, data echo, close |
| TCP back-to-back | `examples/back_to_back.zig` | Two stacks communicate over a simulated wire: ARP discovery, 1KB transfer |
| UDP + ICMP | `examples/udp_icmp.zig` | UDP datagram exchange and ICMP ping with auto-reply |

## Using in Your Project

Add zmoltcp as a Zig dependency in your `build.zig.zon`:

```zig
.dependencies = .{
    .zmoltcp = .{
        .url = "https://github.com/hotschmoe/zmoltcp/archive/<commit>.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const zmoltcp_dep = b.dependency("zmoltcp", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zmoltcp", zmoltcp_dep.module("zmoltcp"));
```

## Integration with Laminae

In Laminae, zmoltcp is consumed as a package. The kernel-specific glue
(ICC message dispatch, shared memory with the NIC driver, event loop) lives
in `laminae/user/programs/zmoltcp/` and is roughly 200 lines of code. The
protocol logic -- TCP state machines, checksums, neighbor tables, everything
that makes networking work -- lives here.

```
Laminae container (main.zig, netif.zig)    <-- kernel-specific, ~200 LOC
  |
  imports zmoltcp                          <-- this repo, ~31,000 LOC
  |
  zmoltcp.stack.poll(timestamp)
  |
  +-- wire/ parse incoming packets
  +-- socket/ drive state machines
  +-- iface route to correct socket
  +-- return next poll time
```

## Binary Size

zmoltcp's comptime generics produce smaller binaries than smoltcp's runtime
dispatch as feature count grows. Measured on `aarch64-freestanding-none` with
size-optimized settings (Zig `-OReleaseSmall`, Rust `opt-level=z` + LTO):

```
Scenario            zmoltcp   smoltcp   Ratio    .text bytes
A: TCP/IPv4          14,405    11,332    1.27x   (zmoltcp slightly larger)
B: TCP+UDP+ICMP      16,917    15,243    1.11x   (near parity)
C: Full IPv4         20,317    24,872    0.82x   (zmoltcp 18% smaller)
D: Dual-stack        27,721    43,380    0.64x   (zmoltcp 36% smaller)
E: Wire-only          1,145     5,276    0.22x   (zmoltcp 78% smaller)
TOTAL                80,505   100,103    0.80x   (zmoltcp 20% smaller overall)
```

Comptime generics break even at ~3 socket types and then progressively win.
Dual-stack is where the advantage is most pronounced: zmoltcp generates
fully specialized code per IP version, while smoltcp dispatches through
`IpRepr` enums at runtime.

Run `bash bench/size/measure.sh` to reproduce. Requires `zig`, `cargo`,
`rustup target add aarch64-unknown-none`, and `llvm-size` on PATH.

## Status

Feature-complete dual-stack IPv4/IPv6 TCP/IP stack with full smoltcp feature
parity. See `docs/20260224_plan.md` for the development plan and phase history.

## License

MIT
