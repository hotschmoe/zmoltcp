# zmoltcp Conformance Tracking

Tracks zmoltcp tests against their smoltcp reference implementations.

## Summary

| Module | smoltcp Tests | zmoltcp Tests | Passing | Status |
|--------|--------------|---------------|---------|--------|
| wire/checksum | ~5 | 5 | 5 | PASS |
| wire/ethernet | ~8 | 4 | 4 | PASS |
| wire/arp | ~6 | 5 | 5 | PASS |
| wire/ipv4 | ~15 | 6 | 6 | PASS |
| wire/tcp | ~20 | 6 | 6 | PASS |
| wire/udp | ~8 | 4 | 4 | PASS |
| wire/icmp | ~10 | 4 | 4 | PASS |
| storage/ring_buffer | 15 | 14 | 14 | PASS |
| storage/assembler | 38 | 37 | 37 | PASS |
| socket/tcp | 175 | 0 | -- | TODO |
| socket/udp | ~15 | 0 | -- | TODO |
| socket/dhcp | ~12 | 0 | -- | TODO |
| socket/dns | ~10 | 0 | -- | TODO |
| socket/icmp | ~8 | 0 | -- | TODO |
| iface | ~25 | 0 | -- | TODO |

## Wire Layer Tests

### wire/checksum.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/mod.rs (checksum) | "checksum of all zeros" | PASS |
| wire/mod.rs (checksum) | "checksum of 0xFF bytes" | PASS |
| wire/mod.rs (checksum) | "checksum odd length" | PASS |
| wire/mod.rs (checksum) | "checksum accumulate non-contiguous" | PASS |
| (RFC 1071 vector) | "IPv4 header checksum known value" | PASS |

### wire/ethernet.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ethernet.rs:test_parse | "parse ethernet frame" | PASS |
| wire/ethernet.rs:test_emit | "emit ethernet frame" | PASS |
| wire/ethernet.rs:roundtrip | "ethernet roundtrip" | PASS |
| (original) | "payload extraction" | PASS |

### wire/arp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/arp.rs:test_parse | "parse ARP request" | PASS |
| (original) | "parse ARP truncated" | PASS |
| (original) | "parse ARP unsupported hardware" | PASS |
| wire/arp.rs:roundtrip | "ARP roundtrip" | PASS |
| (original) | "emit ARP reply" | PASS |

### wire/ipv4.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ipv4.rs:test_parse | "parse IPv4 header" | PASS |
| (original) | "parse IPv4 truncated" | PASS |
| (original) | "parse IPv4 bad version" | PASS |
| (original) | "parse IPv4 bad IHL" | PASS |
| wire/ipv4.rs:roundtrip | "IPv4 roundtrip" | PASS |
| (original) | "IPv4 emit produces valid checksum" | PASS |

### wire/tcp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/tcp.rs:test_parse | "parse TCP SYN" | PASS |
| (original) | "parse TCP truncated" | PASS |
| (original) | "parse TCP bad data offset" | PASS |
| wire/tcp.rs:test_parse_options | "parse TCP with MSS option" | PASS |
| wire/tcp.rs:roundtrip | "TCP SYN roundtrip" | PASS |
| (original) | "TCP checksum computation" | PASS |

### wire/udp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/udp.rs:test_parse | "parse UDP datagram" | PASS |
| (original) | "parse UDP truncated" | PASS |
| wire/udp.rs:roundtrip | "UDP roundtrip" | PASS |
| (original) | "UDP payload extraction" | PASS |

### wire/icmp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/icmpv4.rs:test_parse_echo | "parse ICMP echo request" | PASS |
| (original) | "parse ICMP dest unreachable" | PASS |
| (original) | "ICMP echo emit with valid checksum" | PASS |
| (original) | "ICMP echo roundtrip" | PASS |

## Storage Layer Tests

### storage/ring_buffer.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| storage/ring_buffer.rs:test_buffer_length_changes | "buffer length and capacity tracking" | PASS |
| storage/ring_buffer.rs:test_buffer_enqueue_dequeue_one{,_with} | "enqueue and dequeue one" | PASS |
| storage/ring_buffer.rs:test_buffer_enqueue_many_with | "enqueue many with wrap-around" | PASS |
| storage/ring_buffer.rs:test_buffer_enqueue_many | "enqueue many contiguous" | PASS |
| storage/ring_buffer.rs:test_buffer_enqueue_slice | "enqueue slice with wrap-around" | PASS |
| storage/ring_buffer.rs:test_buffer_dequeue_many_with | "dequeue many with wrap-around" | PASS |
| storage/ring_buffer.rs:test_buffer_dequeue_many | "dequeue many contiguous" | PASS |
| storage/ring_buffer.rs:test_buffer_dequeue_slice | "dequeue slice with wrap-around" | PASS |
| storage/ring_buffer.rs:test_buffer_get_unallocated | "get unallocated with offset and wrap" | PASS |
| storage/ring_buffer.rs:test_buffer_write_unallocated | "write unallocated with wrap" | PASS |
| storage/ring_buffer.rs:test_buffer_get_allocated | "get allocated with offset and wrap" | PASS |
| storage/ring_buffer.rs:test_buffer_read_allocated | "read allocated with wrap" | PASS |
| storage/ring_buffer.rs:test_buffer_with_no_capacity | "zero capacity buffer" | PASS |
| storage/ring_buffer.rs:test_buffer_write_wholly | "empty buffer resets position for full write" | PASS |

### storage/assembler.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| storage/assembler.rs:test_new | "new assembler is empty" | PASS |
| storage/assembler.rs:test_empty_add_full | "add full range to empty" | PASS |
| storage/assembler.rs:test_empty_add_front | "add front range to empty" | PASS |
| storage/assembler.rs:test_empty_add_back | "add back range to empty" | PASS |
| storage/assembler.rs:test_empty_add_mid | "add middle range to empty" | PASS |
| storage/assembler.rs:test_partial_add_front | "add adjacent front range" | PASS |
| storage/assembler.rs:test_partial_add_back | "add adjacent back range" | PASS |
| storage/assembler.rs:test_partial_add_front_overlap | "add overlapping front range" | PASS |
| storage/assembler.rs:test_partial_add_front_overlap_split | "add partially overlapping front range" | PASS |
| storage/assembler.rs:test_partial_add_back_overlap | "add overlapping back range" | PASS |
| storage/assembler.rs:test_partial_add_back_overlap_split | "add partially overlapping back range" | PASS |
| storage/assembler.rs:test_partial_add_both_overlap | "add range covering entire contig" | PASS |
| storage/assembler.rs:test_partial_add_both_overlap_split | "add range covering most of contig" | PASS |
| storage/assembler.rs:test_rejected_add_keeps_state | "rejected add preserves state" | PASS |
| storage/assembler.rs:test_empty_remove_front | "remove front from empty" | PASS |
| storage/assembler.rs:test_trailing_hole_remove_front | "remove front with no trailing data" | PASS |
| storage/assembler.rs:test_trailing_data_remove_front | "remove front with trailing data" | PASS |
| storage/assembler.rs:test_boundary_case_remove_front | "remove front boundary case max contigs" | PASS |
| storage/assembler.rs:test_shrink_next_hole | "add shrinks next hole" | PASS |
| storage/assembler.rs:test_join_two | "add joins two separate ranges" | PASS |
| storage/assembler.rs:test_join_two_reversed | "add joins two ranges reversed order" | PASS |
| storage/assembler.rs:test_join_two_overlong | "add joins and extends beyond" | PASS |
| storage/assembler.rs:test_iter_empty | "iter empty assembler" | PASS |
| storage/assembler.rs:test_iter_full | "iter full assembler" | PASS |
| storage/assembler.rs:test_iter_offset | "iter with offset" | PASS |
| storage/assembler.rs:test_iter_one_front | "iter one front range" | PASS |
| storage/assembler.rs:test_iter_one_back | "iter one back range" | PASS |
| storage/assembler.rs:test_iter_one_mid | "iter one middle range" | PASS |
| storage/assembler.rs:test_iter_one_trailing_gap | "iter one range with trailing gap" | PASS |
| storage/assembler.rs:test_iter_two_split | "iter two split ranges" | PASS |
| storage/assembler.rs:test_iter_three_split | "iter three split ranges" | PASS |
| storage/assembler.rs:test_issue_694 | "adjacent segments coalesce regression" | PASS |
| storage/assembler.rs:test_add_then_remove_front | "add then remove front non-contiguous" | PASS |
| storage/assembler.rs:test_add_then_remove_front_at_front | "add then remove front at front" | PASS |
| storage/assembler.rs:test_add_then_remove_front_at_front_touch | "add then remove front touching" | PASS |
| storage/assembler.rs:test_add_then_remove_front_at_front_full | "add then remove front when full" | PASS |
| storage/assembler.rs:test_add_then_remove_front_at_front_full_offset_0 | "add then remove front offset 0 when full" | PASS |
