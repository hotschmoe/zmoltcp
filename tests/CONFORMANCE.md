# zmoltcp Conformance Tracking

Tracks zmoltcp tests against their smoltcp reference implementations.

## Summary

| Module | smoltcp Tests | zmoltcp Tests | Passing | Status |
|--------|--------------|---------------|---------|--------|
| wire/checksum | ~5 | 5 | TBD | Initial |
| wire/ethernet | ~8 | 4 | TBD | Initial |
| wire/arp | ~6 | 5 | TBD | Initial |
| wire/ipv4 | ~15 | 6 | TBD | Initial |
| wire/tcp | ~20 | 6 | TBD | Initial |
| wire/udp | ~8 | 4 | TBD | Initial |
| wire/icmp | ~10 | 4 | TBD | Initial |
| socket/tcp | 175 | 0 | -- | TODO |
| socket/udp | ~15 | 0 | -- | TODO |
| socket/dhcp | ~12 | 0 | -- | TODO |
| socket/dns | ~10 | 0 | -- | TODO |
| socket/icmp | ~8 | 0 | -- | TODO |
| storage/ring_buffer | ~12 | 0 | -- | TODO |
| storage/assembler | ~15 | 0 | -- | TODO |
| iface | ~25 | 0 | -- | TODO |

## Wire Layer Tests

### wire/checksum.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/mod.rs (checksum) | "checksum of all zeros" | INITIAL |
| wire/mod.rs (checksum) | "checksum of 0xFF bytes" | INITIAL |
| wire/mod.rs (checksum) | "checksum odd length" | INITIAL |
| wire/mod.rs (checksum) | "checksum accumulate non-contiguous" | INITIAL |
| (RFC 1071 vector) | "IPv4 header checksum known value" | INITIAL |

### wire/ethernet.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ethernet.rs:test_parse | "parse ethernet frame" | INITIAL |
| wire/ethernet.rs:test_emit | "emit ethernet frame" | INITIAL |
| wire/ethernet.rs:roundtrip | "ethernet roundtrip" | INITIAL |
| (original) | "payload extraction" | INITIAL |

### wire/arp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/arp.rs:test_parse | "parse ARP request" | INITIAL |
| (original) | "parse ARP truncated" | INITIAL |
| (original) | "parse ARP unsupported hardware" | INITIAL |
| wire/arp.rs:roundtrip | "ARP roundtrip" | INITIAL |
| (original) | "emit ARP reply" | INITIAL |

### wire/ipv4.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ipv4.rs:test_parse | "parse IPv4 header" | INITIAL |
| (original) | "parse IPv4 truncated" | INITIAL |
| (original) | "parse IPv4 bad version" | INITIAL |
| (original) | "parse IPv4 bad IHL" | INITIAL |
| wire/ipv4.rs:roundtrip | "IPv4 roundtrip" | INITIAL |
| (original) | "IPv4 emit produces valid checksum" | INITIAL |

### wire/tcp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/tcp.rs:test_parse | "parse TCP SYN" | INITIAL |
| (original) | "parse TCP truncated" | INITIAL |
| (original) | "parse TCP bad data offset" | INITIAL |
| wire/tcp.rs:test_parse_options | "parse TCP with MSS option" | INITIAL |
| wire/tcp.rs:roundtrip | "TCP SYN roundtrip" | INITIAL |
| (original) | "TCP checksum computation" | INITIAL |

### wire/udp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/udp.rs:test_parse | "parse UDP datagram" | INITIAL |
| (original) | "parse UDP truncated" | INITIAL |
| wire/udp.rs:roundtrip | "UDP roundtrip" | INITIAL |
| (original) | "UDP payload extraction" | INITIAL |

### wire/icmp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/icmpv4.rs:test_parse_echo | "parse ICMP echo request" | INITIAL |
| (original) | "parse ICMP dest unreachable" | INITIAL |
| (original) | "ICMP echo emit with valid checksum" | INITIAL |
| (original) | "ICMP echo roundtrip" | INITIAL |
