# zmoltcp Conformance Testing Specification

## Overview

zmoltcp uses smoltcp (Rust no_std TCP/IP stack) as its architectural reference
and correctness baseline. This document specifies how we validate zmoltcp
against smoltcp's test suite to ensure protocol conformance.

**Current status: 818 tests passing** across all modules. Full dual-stack
IPv4/IPv6 feature parity with smoltcp, plus IoT (802.15.4, 6LoWPAN, RPL)
and additional features (IPsec wire formats, PcapWriter, mDNS, PacketBuffer).

## Reference Material

smoltcp is included as a git submodule at `ref/smoltcp/`. This provides:

1. **Test vectors**: Byte arrays and expected behaviors embedded in smoltcp's
   inline Rust tests
2. **Protocol specifications**: The Rust implementations serve as readable
   RFC interpretations
3. **Behavioral baseline**: When in doubt about edge cases, smoltcp's behavior
   is the reference

```
ref/smoltcp/                          (git submodule, read-only reference)
  src/
    wire/*.rs                         Wire format tests (parse + serialize)
    socket/tcp.rs                     175 TCP state machine tests
    socket/udp.rs                     UDP socket tests
    socket/icmp.rs                    ICMP socket tests
    socket/dhcpv4.rs                  DHCP client tests
    socket/dns.rs                     DNS resolver tests
    storage/ring_buffer.rs            Ring buffer tests
    storage/assembler.rs              Segment assembler tests
    iface/interface/tests/ipv4.rs     IPv4 interface tests
    iface/interface/tests/ipv6.rs     IPv6 interface tests
    iface/interface/tests/sixlowpan.rs  6LoWPAN interface tests
```

## Test Architecture

```
                    +---------------------------+
                    |   zig build test           |
                    |   (runs on host, native)   |
                    +---------------------------+
                               |
        +----------+-----------+-----------+----------+
        |          |           |           |          |
   wire/*_test  socket/*   storage/*   iface_test  stack_test
   (parse/      (state     (data       (interface  (end-to-end
    serialize)   machines)  structures)  routing)   integration)
        |          |           |           |          |
        v          v           v           v          v
   Known byte   State       Ring buffer  ARP/NDP    Full packet
   arrays from  transition  invariants   cache,     pipeline:
   RFCs and     sequences               ICMP,      RX -> parse ->
   smoltcp      from smoltcp            multicast  route -> socket
```

All tests run on the host machine. No QEMU, no VM, no hardware. A test
failure is always a zmoltcp bug, never a kernel/driver/timing issue.

## Conformance Test Methodology

### Step 1: Identify smoltcp Test Functions

Each smoltcp test function follows a pattern:

```rust
// From smoltcp src/socket/tcp.rs
#[test]
fn test_connect() {
    let mut s = socket_syn_sent();           // setup: socket in SYN_SENT state
    recv!(s, [TcpRepr {                      // verify: expect SYN packet out
        control: TcpControl::Syn,
        seq_number: LOCAL_SEQ,
        ack_number: None,
        max_seg_size: Some(BASE_MSS),
        ..RECV_TEMPL
    }]);
}
```

### Step 2: Extract Test Vectors

From each smoltcp test, extract:

1. **Initial state**: What socket/protocol state to set up
2. **Input**: Bytes or structured data fed into the module
3. **Expected output**: Bytes produced, state transitions, side effects
4. **Edge conditions**: What error handling is tested

Document these as structured comments in the Zig test:

```zig
// Transliterated from: smoltcp src/socket/tcp.rs test_connect()
// Setup: socket transitions to SYN_SENT via connect()
// Expect: SYN segment emitted with correct seq, MSS option
// Edge: verify no ACK number in initial SYN
test "tcp connect emits SYN" {
    var sock = TcpSocket.init(&rx_buf, &tx_buf);
    sock.connect(local_ep, remote_ep, timestamp) catch unreachable;

    const seg = sock.dispatch() orelse unreachable;
    try expect(seg.control == .syn);
    try expect(seg.seq_number == local_seq);
    try expect(seg.ack_number == null);
    try expect(seg.max_seg_size != null);
}
```

### Step 3: Conformance Tracking

Each transliterated test is tagged with its smoltcp origin:

```zig
// [smoltcp:socket/tcp.rs:test_connect]
test "tcp connect emits SYN" { ... }

// [smoltcp:socket/tcp.rs:test_connect_syn_sent_rst]
test "tcp SYN_SENT receives RST" { ... }
```

The tag format is: `[smoltcp:<file>:<test_function_name>]`

A tracking file `tests/CONFORMANCE.md` maps each smoltcp test to its zmoltcp
equivalent and tracks implementation status.

## Test Categories

### Category 1: Wire Format Tests (207 tests)

Source: `ref/smoltcp/src/wire/*.rs`

These test pure parsing and serialization. Each test provides raw bytes and
verifies that parsing produces the correct structured representation, and
that serializing produces the original bytes (roundtrip).

```
wire/checksum.zig (6 tests)
  - RFC 1071 test vectors
  - Incremental checksum update
  - Odd-length data handling
  - IPv6 pseudo-header checksum
  - IPv4 header checksum known value

wire/ethernet.zig (5 tests)
  - Parse Ethernet II frame
  - Serialize frame with correct EtherType
  - Reject truncated frames
  - Roundtrip: parse -> repr -> emit -> compare

wire/arp.zig (5 tests)
  - Parse ARP request/reply for Ethernet+IPv4
  - Serialize ARP with correct hw/proto lengths
  - Reject truncated and unsupported hardware types
  - Roundtrip: parse -> repr -> emit -> compare

wire/ip.zig (7 tests)
  - Cidr(ipv4) containment, prefix_len 0, broadcast/networkAddr
  - Cidr(ipv6) containment, prefix_len 0
  - Endpoint and ListenEndpoint for both address families

wire/ipv4.zig (16 tests)
  - Parse IPv4 header (version, IHL, total length, TTL, protocol)
  - Validate header checksum
  - Handle options (IHL > 5)
  - Fragment offset and flags (DF, MF, fragment_offset)
  - Reject invalid version, bad IHL, truncated packets
  - checkLen: validate total_length vs buffer consistency
  - payloadSliceClamped: payload clamped to total_length
  - CIDR contains/broadcast/networkAddr

wire/ipv6.zig (12 tests)
  - Parse IPv6 header (version, traffic class, flow label, hop limit)
  - Next header / protocol field
  - Address classification (multicast, link-local, loopback, unspecified)
  - Solicited-node multicast address computation
  - Roundtrip: parse -> repr -> emit -> compare

wire/ipv6option.zig (7 tests)
  - TLV option parsing (pad1, padN, router alert, RPL)
  - Failure type semantics (skip, discard, send ICMP)
  - Roundtrip for option types

wire/ipv6ext_header.zig (5 tests)
  - Generic extension header parse/emit
  - Header length decoding ((length+1)*8)

wire/ipv6fragment.zig (4 tests)
  - Fragment header parse/emit
  - Fragment offset and M-bit extraction
  - Identification field

wire/ipv6routing.zig (4 tests)
  - Routing header Type 2 (Mobile IPv6)
  - Routing header Type 3 (RPL source routing)

wire/ipv6hbh.zig (3 tests)
  - Hop-by-Hop options header with embedded TLV options

wire/tcp.zig (22 tests)
  - Parse TCP header with data offset
  - Parse TCP options: MSS, window scale, SACK permitted, SACK blocks, timestamps
  - Serialize SYN with options
  - Serialize ACK with payload
  - Roundtrip for all flag combinations (SYN, ACK, FIN, RST, PSH, URG)
  - Pseudo-header checksum (v4 and v6)

wire/udp.zig (11 tests)
  - Parse UDP datagram
  - Verify length field consistency
  - Optional checksum (0 = disabled per RFC 768)
  - fillChecksum and verifyChecksum helpers
  - Roundtrip: parse -> repr -> emit -> compare

wire/icmp.zig (5 tests)
  - Parse echo request/reply
  - Parse destination unreachable (with embedded IP header)
  - Parse time exceeded
  - Checksum validation
  - Minimum length validation (HEADER_LEN = 8)

wire/icmpv6.zig (9 tests)
  - Echo request/reply parse/emit
  - Destination unreachable, packet too big, time exceeded
  - Parameter problem
  - NDP and MLD message dispatch
  - Pseudo-header checksum validation

wire/ndisc.zig (4 tests)
  - Neighbor Solicitation/Advertisement parse/emit
  - Router Solicitation/Advertisement parse/emit
  - NDP option extraction (SLLA, TLLA, prefix info)

wire/ndiscoption.zig (8 tests)
  - Source/Target Link-Layer Address options
  - Prefix Information option (SLAAC)
  - MTU option
  - 8-byte-unit length encoding

wire/mld.zig (6 tests)
  - MLDv2 multicast listener query/report
  - Record types (include, exclude, change, allow, block)
  - Multiple multicast address records

wire/igmp.zig (8 tests)
  - IGMPv1/v2 parse/emit
  - Membership query and report
  - Leave group message
  - Version detection

wire/dhcp.zig (9 tests)
  - Parse DHCP DISCOVER/OFFER/REQUEST/ACK
  - Option parsing: message type, server ID, lease time, subnet, router, DNS
  - Serialize DISCOVER with client MAC and requested options

wire/dns.zig (7 tests)
  - Parse DNS query (A record)
  - Parse DNS response with answer section
  - Handle CNAME chains
  - Name compression (pointer labels)
  - Multiple answers

wire/ipsec_esp.zig (6 tests)
  - ESP header parse/emit (RFC 4303)
  - SPI and sequence number extraction
  - Truncation rejection

wire/ipsec_ah.zig (6 tests)
  - AH header parse/emit (RFC 4302)
  - Variable-length ICV support
  - Next header and SPI extraction

wire/ieee802154.zig (11 tests)
  - IEEE 802.15.4 MAC frame parse/emit
  - Addressing modes: absent, short (2 bytes), extended (8 bytes)
  - PAN ID compression
  - Frame type and version handling

wire/sixlowpan.zig (20 tests)
  - IPHC header compression/decompression (RFC 6282)
  - Address compression modes (inline, elided, context-based)
  - Traffic class and flow label encoding
  - NHC (Next Header Compression) for UDP
  - Dispatch type identification

wire/sixlowpan_frag.zig (8 tests)
  - FRAG1 and FRAGN header parse/emit (RFC 4944)
  - Datagram size and tag fields
  - Fragment offset encoding

wire/rpl.zig (19 tests)
  - DIS/DIO/DAO/DAO-ACK message parse/emit (RFC 6550)
  - RPL options (DODAG info, prefix, transit, target)
  - RPL HopByHop extension header (RFC 6553)
  - Instance ID and DODAG ID handling
```

### Category 2: Storage/Data Structure Tests (63 tests)

Source: `ref/smoltcp/src/storage/*.rs`

```
storage/ring_buffer.zig (14 tests)
  - Empty/full detection
  - Wrap-around write and read
  - Contiguous window access
  - Capacity and length invariants
  - Offset-based random access

storage/assembler.zig (37 tests)
  - In-order segment addition
  - Out-of-order segments with gaps
  - Overlapping segments (deduplication)
  - Front contiguous range extraction
  - Full assembler (no more space for holes)
  - Coalescing adjacent ranges

storage/packet_buffer.zig (12 tests)
  - Dual-ring enqueue/dequeue (metadata + payload)
  - Padding entries for wrap-around alignment
  - Full buffer rejection
  - Peek without consume
```

### Category 3: Socket State Machine Tests (279 tests)

Source: `ref/smoltcp/src/socket/*.rs`

The largest and most important category. smoltcp's socket/tcp.rs alone has
175 tests; zmoltcp has 217 TCP tests (original + additional edge cases).

```
socket/tcp.zig (217 tests) -- TCP State Machine
  Connect sequence:
    CLOSED -> SYN_SENT, emit SYN
    SYN_SENT + RST -> CLOSED
    SYN retransmit, then give up
    SYN_SENT + SYN-ACK -> ESTABLISHED

  Data transfer:
    Send data, advance snd_nxt
    Recv data, advance rcv_nxt, send ACK
    Out-of-order segments, buffered
    Backpressure when recv buffer full
    Window opens after application reads

  Retransmission:
    RTO fires, segment resent
    Exponential backoff on repeated timeout
    RTT sample updates SRTT/RTTVAR

  Congestion control (Reno/Cubic):
    Slow start: cwnd grows by MSS per ACK
    Congestion avoidance: cwnd grows by MSS^2/cwnd per ACK
    Fast retransmit: triple duplicate ACK triggers retransmit

  Close sequences:
    Active close: ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT
    Passive close: ESTABLISHED -> CLOSE_WAIT -> LAST_ACK -> CLOSED
    Simultaneous close: both FIN -> CLOSING -> TIME_WAIT
    TIME_WAIT expiry -> CLOSED

  Edge cases:
    RST handling in every state
    Zero window probe (persist timer)
    Nagle algorithm (small segment coalescing)
    Delayed ACK batching
    Keepalive probes after idle
    Window scaling option negotiation
    SACK option handling
    Timestamp option (RFC 7323)

socket/udp.zig (17 tests) -- UDP
    Basic datagram send/recv roundtrip
    Buffer full rejection
    Checksum mandatory over IPv6
    Port binding and metadata extraction

socket/icmp.zig (7 tests) -- ICMP/ICMPv6
    Echo request send, track ID/sequence
    Echo reply matching
    TTL exceeded / destination unreachable handling
    Ident and UDP binding modes

socket/raw.zig (11 tests) -- Raw IP
    Bind to protocol number
    Receive raw IP payloads
    Suppress ICMP proto-unreachable when bound
    IPv4 and IPv6 variants

socket/dhcp.zig (11 tests) -- DHCPv4 Client
    Emit DISCOVER on start
    OFFER -> emit REQUEST
    ACK -> interface configured
    NAK -> restart discovery
    Lease renewal: T1/T2 timers, RENEWING state

socket/dns.zig (16 tests) -- DNS/mDNS Resolver
    Emit A-record query
    Parse response, return address
    Follow CNAME -> A chain
    Retry on timeout, try next server
    Handle NXDOMAIN error
    mDNS multicast queries (port 5353)
```

### Category 4: Interface Tests (62 tests)

Source: `ref/smoltcp/src/iface/interface/tests/*.rs`

Interface-level processing: Ethernet/IP/802.15.4 frame parsing, ARP/NDP
neighbor cache, ICMPv4/v6 auto-reply, TCP RST generation, MLD/IGMP
multicast, SLAAC, address management. Returns structured Response values
without serialization.

```
iface.zig (62 tests)
  IPv4 interface:
    IpCidr broadcast detection (/24, /16, /8)
    Source IP selection by subnet match
    ARP request handling (valid, wrong IP, any_ip mode)
    ARP cache flush on IP address change
    ICMP echo to broadcast: reply from our IP
    ICMP error generation (proto unreachable, port unreachable)
    ICMP error clamped to IPV4_MIN_MTU (576)
    UDP broadcast delivery to bound socket
    ICMP socket delivery + auto-reply coexistence
    TCP SYN with no listener produces RST
    IGMP multicast group join/leave
    Raw socket delivery and proto-unreachable suppression
    Configurable auto_icmp_echo_reply

  IPv6 interface:
    NDP neighbor solicitation/advertisement
    NDP router solicitation/advertisement
    SLAAC address autoconfiguration
    ICMPv6 echo request/reply
    MLD multicast group management
    IPv6 source address selection
    Solicited-node multicast address handling

  IP medium (Layer 3):
    Version nibble dispatch (IPv4/IPv6)
    No MAC resolution, no ARP/NDP
    Point-to-point egress (no Ethernet framing)

  IEEE 802.15.4 medium:
    6LoWPAN IPHC decompression on ingress
    6LoWPAN compression on egress
    Direct addressing (no NDP)
    IPv6-only (IPv4 rejected at comptime)
```

### Category 5: Fragmentation Tests (16 tests)

```
fragmentation.zig (16 tests)
  IPv4 fragmentation:
    Fragment payload 8-byte alignment for all header sizes
    Stage oversized payload, emit multiple fragments
    Fragment lifecycle (stage -> emitNext -> done)

  IPv6 fragmentation:
    Extension header-based fragment identification
    FragKeyV6 (src + dst + id)

  6LoWPAN fragmentation:
    FRAG1/FRAGN header generation
    FragKey6LoWPAN (EUI-64 normalized addresses)
    Reassembly from fragment stream
```

### Category 6: PHY Middleware Tests (16 tests)

```
phy.zig (16 tests)
  Tracer:
    Per-frame callback invocation on RX/TX

  FaultInjector:
    Configurable drop and corrupt rates
    Pass-through when rates are zero

  PcapWriter:
    Pcap global header emission
    Per-packet record headers with timestamps
    RX-only, TX-only, and bidirectional modes
    Ethernet and raw IP link types
```

### Category 7: RPL State Machine Tests (26 tests)

```
rpl.zig (26 tests)
  SequenceCounter:
    Lollipop counter (RFC 6550 S7.2)
    Linear and circular region transitions

  Rank / OF0:
    Objective Function 0 (RFC 6552)
    Rank computation from step and stretch

  ParentSet:
    Parent selection and eviction
    Preferred parent by rank

  Relations:
    Downward routing table
    Child registration and timeout

  TrickleTimer:
    RFC 6206 algorithm (Imin, Imax, k)
    Consistent/inconsistent event handling
    Timer reset on inconsistency
```

### Category 8: Stack Integration Tests (114 tests)

Source: full end-to-end integration

`Stack(Device, SocketConfig)` wraps an Interface, drains RX frames from a
Device, routes packets to sockets (TCP, UDP, ICMP, Raw, DHCP, DNS), processes
iface-level responses (ARP, NDP, ICMP auto-reply, TCP RST, port unreachable),
serializes, and transmits via Device.

Test devices: `LoopbackDevice(max_frames)` for Ethernet,
`IpLoopbackDevice` for IP medium,
`Ieee802154LoopbackDevice(max_frames)` for 802.15.4.

```
stack.zig (114 tests)
  Ethernet medium (IPv4):
    ARP request -> serialized reply via Device
    ICMP echo -> serialized reply with neighbor lookup
    Empty RX returns false from poll()
    TX -> RX loopback, re-poll processes
    TCP SYN no listener -> RST with correct seq/ack/checksum
    UDP bound socket delivery, no ICMP error
    ICMP socket + auto-reply coexistence
    TCP egress (SYN on connect, handshake via listen)
    UDP egress datagram dispatch
    ICMP egress echo dispatch
    Egress cached neighbor MAC
    DHCP discover/offer/request/ack lifecycle
    DNS query/response/pollAt
    IPv4 fragmentation (MTU, alignment)
    IGMP join/leave reports
    Raw socket ingress/egress

  Ethernet medium (IPv6):
    NDP neighbor resolution pipeline
    ICMPv6 echo request/reply
    TCP6/UDP6/ICMPv6 socket dispatch
    IPv6 fragmentation and reassembly
    MLD multicast reports
    SLAAC address configuration

  IP medium (TUN/PPP):
    Version nibble dispatch
    IPv4 and IPv6 over IP medium
    No ARP/NDP, no Ethernet framing
    DHCP rejected at comptime for IP medium

  IEEE 802.15.4 medium:
    6LoWPAN compression/decompression pipeline
    UDP over 6LoWPAN
    6LoWPAN fragmentation egress
    RPL HopByHop processing
    IPv4 sockets rejected at comptime

  pollAt:
    Returns null for no socket timers
    Returns ZERO for pending TCP SYN-SENT
    Returns retransmit deadline after SYN dispatch
    Returns DHCP/DNS socket deadlines
    Returns null for idle sockets

  General:
    poll() returns true for egress-only activity
    poll() returns false for empty RX
```

## Test Summary

| Category | Module | Tests |
|----------|--------|-------|
| Wire formats | wire/* | 207 |
| Storage | storage/* | 63 |
| Sockets | socket/* | 279 |
| Interface | iface | 62 |
| Fragmentation | fragmentation | 16 |
| PHY middleware | phy | 16 |
| RPL state machine | rpl | 26 |
| Stack integration | stack | 114 |
| Time | time | 8 |
| Root | root | 1 |
| | **Total** | **818** | -- Note: Includes 26 RPL tests in rpl.zig count

## CI/CD Pipeline

### On Every Push

```yaml
- zig build test              # All unit + conformance tests
- zig build -Dtarget=aarch64-freestanding-none  # Cross-compile check
```

### Downstream Notification

When zmoltcp tags a release, the laminae repo CI can pull the new version
and run its integration tests (QEMU + VirtIO + mock server) to validate
the full stack.

## smoltcp Version Tracking

Current reference: smoltcp `main` branch (pin to specific commit via submodule).

When smoltcp updates:
1. Update submodule to new commit
2. Diff test changes: `git diff HEAD~1 -- ref/smoltcp/src/`
3. Identify new tests, modified tests, removed tests
4. Update zmoltcp tests accordingly
5. Update CONFORMANCE.md

## Definitions

- **Wire test**: Validates byte-level parsing and serialization of a protocol
  header. Input is raw bytes, output is structured data (and vice versa).

- **Socket test**: Validates protocol state machine behavior. Input is a
  sequence of events (segment received, timer expired, application call),
  output is state transitions and emitted segments.

- **Conformance test**: A zmoltcp test that is directly transliterated from
  a specific smoltcp test function, tagged with its origin.

- **Roundtrip test**: Parse raw bytes into a Repr, serialize the Repr back
  to bytes, verify the output matches the input. Validates that
  parse and serialize are inverses.
