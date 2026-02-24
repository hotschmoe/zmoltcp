# zmoltcp Conformance Testing Specification

## Overview

zmoltcp uses smoltcp (Rust no_std TCP/IP stack) as its architectural reference
and correctness baseline. This document specifies how we validate zmoltcp
against smoltcp's test suite to ensure protocol conformance.

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
```

## Test Architecture

```
                    +---------------------------+
                    |   zig build test           |
                    |   (runs on host, native)   |
                    +---------------------------+
                               |
              +----------------+----------------+
              |                |                |
      src/wire/*_test     src/socket/*_test   src/storage/*_test
      (parse/serialize)   (state machines)    (data structures)
              |                |                |
              v                v                v
      Known byte arrays   State transition   Ring buffer
      from RFCs and       sequences from     invariants
      smoltcp tests       smoltcp tests
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
equivalent and tracks implementation status:

```
| smoltcp test | zmoltcp test | status |
|---|---|---|
| socket/tcp.rs:test_connect | socket/tcp.zig:"tcp connect emits SYN" | PASS |
| socket/tcp.rs:test_connect_syn_sent_rst | socket/tcp.zig:"tcp SYN_SENT receives RST" | TODO |
```

### Step 4: CI Conformance Gate

CI runs `zig build test` on every push. The test suite includes all
transliterated smoltcp tests. A conformance percentage is tracked:

```
zmoltcp conformance: 47/175 TCP tests passing (26.8%)
```

This percentage is updated in CONFORMANCE.md and optionally in a CI badge.

## Test Categories

### Category 1: Wire Format Tests

Source: `ref/smoltcp/src/wire/*.rs`

These test pure parsing and serialization. Each test provides raw bytes and
verifies that parsing produces the correct structured representation, and
that serializing produces the original bytes (roundtrip).

```
wire/checksum.zig
  - RFC 1071 test vectors
  - Incremental checksum update
  - Odd-length data handling

wire/ethernet.zig
  - Parse Ethernet II frame
  - Serialize frame with correct EtherType
  - Reject truncated frames

wire/arp.zig
  - Parse ARP request/reply for Ethernet+IPv4
  - Serialize ARP with correct hw/proto lengths
  - Roundtrip: parse -> repr -> emit -> compare

wire/ipv4.zig
  - Parse IPv4 header (version, IHL, total length, TTL, protocol)
  - Validate header checksum
  - Handle options (IHL > 5)
  - Fragment offset and flags (DF, MF, fragment_offset)
  - Reject invalid version, bad IHL, truncated packets
  - checkLen: validate total_length vs buffer consistency
  - payloadSliceClamped: payload clamped to total_length (overlong buffers)
  - CIDR contains/broadcast/networkAddr via IpCidr

wire/tcp.zig
  - Parse TCP header with data offset
  - Parse TCP options: MSS, window scale, SACK permitted, SACK blocks, timestamps
  - Serialize SYN with options
  - Serialize ACK with payload
  - Roundtrip for all flag combinations (SYN, ACK, FIN, RST, PSH, URG)

wire/udp.zig
  - Parse UDP datagram
  - Verify length field consistency
  - Optional checksum (0 = disabled per RFC 768)
  - fillChecksum: write computed checksum (0xFFFF if zero per RFC 768)
  - verifyChecksum: validate or accept disabled (0x0000)

wire/icmp.zig
  - Parse echo request/reply
  - Parse destination unreachable (with embedded IP header)
  - Parse time exceeded
  - Checksum validation
  - Minimum length validation (HEADER_LEN = 8)

wire/dhcp.zig
  - Parse DHCP DISCOVER/OFFER/REQUEST/ACK
  - Option parsing: message type, server ID, lease time, subnet, router, DNS
  - Serialize DISCOVER with client MAC and requested options

wire/dns.zig
  - Parse DNS query (A record)
  - Parse DNS response with answer section
  - Handle CNAME chains
  - Name compression (pointer labels)
  - Multiple answers
```

### Category 2: Storage/Data Structure Tests

Source: `ref/smoltcp/src/storage/*.rs`

```
storage/ring_buffer.zig
  - Empty/full detection
  - Wrap-around write and read
  - Contiguous window access
  - Capacity and length invariants

storage/assembler.zig
  - In-order segment addition
  - Out-of-order segments with gaps
  - Overlapping segments (deduplication)
  - Front contiguous range extraction
  - Full assembler (no more space for holes)
```

### Category 3: Socket State Machine Tests

Source: `ref/smoltcp/src/socket/*.rs`

The largest and most important category. smoltcp's socket/tcp.rs alone has
175 tests covering every TCP state transition.

```
socket/tcp.zig -- TCP State Machine
  Connect sequence:
    test_connect                      CLOSED -> SYN_SENT, emit SYN
    test_connect_syn_sent_rst         SYN_SENT + RST -> CLOSED
    test_connect_syn_sent_timeout     SYN retransmit, then give up
    test_connect_syn_ack              SYN_SENT + SYN-ACK -> ESTABLISHED

  Data transfer:
    test_established_send             Send data, advance snd_nxt
    test_established_recv             Recv data, advance rcv_nxt, send ACK
    test_established_recv_ooo         Out-of-order segments, buffered
    test_established_window_full      Backpressure when recv buffer full
    test_established_window_update    Window opens after application reads

  Retransmission:
    test_retransmit_timeout           RTO fires, segment resent
    test_retransmit_backoff           Exponential backoff on repeated timeout
    test_rtt_estimation               RTT sample updates SRTT/RTTVAR

  Congestion control:
    test_slow_start                   cwnd grows by MSS per ACK
    test_congestion_avoidance         cwnd grows by MSS^2/cwnd per ACK
    test_fast_retransmit              Triple duplicate ACK triggers retransmit

  Close sequences:
    test_active_close                 ESTABLISHED -> FIN_WAIT_1 -> FIN_WAIT_2 -> TIME_WAIT
    test_passive_close                ESTABLISHED -> CLOSE_WAIT -> LAST_ACK -> CLOSED
    test_simultaneous_close           Both sides FIN -> CLOSING -> TIME_WAIT
    test_time_wait_timeout            TIME_WAIT expires -> CLOSED

  Edge cases:
    test_rst_handling                 RST in every state
    test_zero_window_probe            Persist timer for zero-window
    test_nagle                        Small segment coalescing
    test_delayed_ack                  ACK batching
    test_keepalive                    Keepalive probes after idle

  Dispatch/options:
    test_set_hop_limit                hop_limit propagates to DispatchResult
    test_set_hop_limit_zero           null hop_limit uses default (64)
    test_listen_syn_win_scale_buffers windowShiftFor for various buffer sizes
    test_syn_sent_no_window_scaling   SYN-ACK without window_scale clears shift

socket/udp.zig -- UDP
    test_send_recv                    Basic datagram roundtrip
    test_buffer_full                  Drop when buffer exhausted
    test_port_unreachable             ICMP unreachable on closed port

socket/dhcp.zig -- DHCP Client
    test_discover                     Emit DISCOVER on start
    test_offer_request                OFFER -> emit REQUEST
    test_ack_configured               ACK -> interface configured
    test_nak_restart                  NAK -> restart discovery
    test_lease_renewal                T1/T2 timers, RENEWING state

socket/dns.zig -- DNS Resolver
    test_query                        Emit A-record query
    test_response                     Parse response, return address
    test_cname                        Follow CNAME -> A chain
    test_timeout_retry                Retry on timeout, try next server
    test_nxdomain                     Handle NXDOMAIN error

socket/icmp.zig -- ICMP
    test_echo_request                 Send echo, track ID/sequence
    test_echo_reply                   Match reply to pending request
    test_ttl_exceeded                 Handle TTL exceeded response
```

### Category 4: Interface/Integration Tests

Source: `ref/smoltcp/src/iface/interface/tests/ipv4.rs`

These test the packet processing pipeline at two levels:

- **iface.zig**: Interface-level processing (Ethernet frame parsing, ARP
  neighbor cache, ICMP auto-reply, address management). Returns structured
  Response values without serialization.
- **stack.zig**: Full end-to-end integration. Stack(Device) wraps an
  Interface, drains RX frames from a Device, processes them, serializes
  responses (ARP replies, IPv4/ICMP), and transmits via Device. The
  LoopbackDevice provides an in-memory ring buffer device for testing.

```
iface.zig (13 tests implemented)
  local_subnet_broadcasts             IpCidr broadcast detection /24, /16, /8
  get_source_address                  Source IP selection by subnet match
  get_source_address_empty            No addresses -> null
  handle_valid_arp_request            ARP request for our IP: reply + cache fill
  handle_other_arp_request            ARP for wrong IP: no reply, no cache
  arp_flush_after_update_ip           Cache flushed on IP address change
  handle_ipv4_broadcast               ICMP echo to broadcast: reply from our IP
  no_icmp_no_unicast                  Unknown protocol to broadcast: no ICMP
  icmp_error_no_payload               Unknown protocol to unicast: proto unreachable
  icmp_error_port_unreachable         UDP closed port: port unreachable / null for broadcast
  handle_udp_broadcast                UDP broadcast delivered to bound socket
  icmp_reply_size                     ICMP error clamped to IPV4_MIN_MTU (576)
  any_ip_accept_arp                   any_ip mode: reply to ARP for any IP

stack.zig (5 tests implemented)
  stack_arp_request_produces_reply    End-to-end ARP request -> serialized reply via Device
  stack_icmp_echo_produces_reply      End-to-end ICMP echo -> serialized reply with neighbor lookup
  stack_empty_rx_returns_false        Empty RX queue returns false from poll()
  stack_loopback_round_trip           TX -> RX loopback, re-poll processes without new response
  stack_pollAt_returns_null           No socket timers -> null

Deferred (require features not yet in zmoltcp):
  test_handle_igmp                    IGMP/multicast
  test_packet_len, fragment_size      IP fragmentation
  test_raw_socket_*                   Raw sockets (4 tests)
  test_icmpv4_socket                  ICMP socket + auto-reply integration
```

## Extracting Test Vectors from smoltcp

### Automated Extraction (Future)

A script `tools/extract_vectors.py` (or Zig) can parse smoltcp's Rust test
source files and extract:

1. Byte literal arrays (`[0x45, 0x00, 0x00, 0x28, ...]`)
2. Expected field values from assertions
3. Test function names and descriptions

Output: JSON files in `tests/vectors/` that both Rust and Zig can consume.

```json
{
  "source": "smoltcp/src/wire/ipv4.rs:test_parse",
  "input_bytes": "450000280001000040060000c0a80001c0a80002",
  "expected": {
    "version": 4,
    "ihl": 5,
    "total_length": 40,
    "ttl": 64,
    "protocol": 6,
    "src_addr": "192.168.0.1",
    "dst_addr": "192.168.0.2"
  }
}
```

### Manual Transliteration (Initial Approach)

For the first pass, manually read each smoltcp test and write the Zig
equivalent. This is slower but produces idiomatic Zig tests and builds
deep understanding of the protocol logic.

Priority order:
1. wire/ tests (foundation, fast to write, high confidence)
2. storage/ tests (ring buffer and assembler are prerequisites for sockets)
3. socket/tcp.rs tests (the bulk of the work, highest value)
4. socket/ other tests (UDP, DHCP, DNS, ICMP)
5. iface/ tests (integration, do last)

## CI/CD Pipeline

### On Every Push

```yaml
- zig build test              # All unit + conformance tests
- zig build -Dtarget=aarch64-freestanding-none  # Cross-compile check
```

### Conformance Report (Weekly or on Tag)

```
Generate tests/CONFORMANCE.md with:
- Total smoltcp tests identified
- Total zmoltcp tests passing
- Per-module breakdown
- List of TODO tests
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
