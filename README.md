# zmoltcp

A pure Zig TCP/IP stack for freestanding targets, architecturally inspired by
[smoltcp](https://github.com/smoltcp-rs/smoltcp) (Rust no_std).

## What This Is

zmoltcp is a standalone, zero-allocation network stack designed for bare-metal
and custom OS use. It implements IPv4, TCP, UDP, DHCP, DNS, ARP, and ICMP with
no runtime dependencies beyond caller-provided buffers.

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
  wire/              Protocol wire formats (parse + serialize)
    checksum.zig     IP/TCP/UDP internet checksum (RFC 1071)
    ethernet.zig     Ethernet II frame
    arp.zig          ARP request/reply
    ipv4.zig         IPv4 header + options
    tcp.zig          TCP header + options (MSS, window scale, SACK)
    udp.zig          UDP datagram
    icmp.zig         ICMPv4 (echo, unreachable, time exceeded)
    dhcp.zig         DHCPv4 packet format
    dns.zig          DNS query/response

  socket/            Protocol state machines
    tcp.zig          TCP FSM (RFC 793), congestion control, retransmit
    udp.zig          Stateless datagram send/recv
    icmp.zig         Ping request/response tracking
    dhcp.zig         DHCP client (DISCOVER/OFFER/REQUEST/ACK)
    dns.zig          DNS resolver client

  storage/           Data structures
    ring_buffer.zig  Generic ring buffer (TX/RX queues)
    assembler.zig    TCP out-of-order segment reassembly

  iface.zig          Network interface (packet routing, neighbor cache)
  stack.zig          Top-level poll loop, socket set management
  buf.zig            Packet buffer descriptor
  time.zig           Timestamp/duration types
  root.zig           Library entry point (public API)
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

## Testing

Tests are transliterated from smoltcp's test suite (see SPEC.md for the full
conformance testing methodology). The smoltcp source is included as a git
submodule under `ref/smoltcp/` for reference.

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
protocol logic -- TCP state machines, checksums, ARP tables, everything
that makes networking work -- lives here.

```
Laminae container (main.zig, netif.zig)    <-- kernel-specific, ~200 LOC
  |
  imports zmoltcp                          <-- this repo, ~3000+ LOC
  |
  zmoltcp.stack.poll(timestamp)
  |
  +-- wire/ parse incoming packets
  +-- socket/ drive state machines
  +-- iface route to correct socket
  +-- return next poll time
```

## Status

Early development. See SPEC.md for the implementation plan and conformance
testing methodology.

## License

MIT
