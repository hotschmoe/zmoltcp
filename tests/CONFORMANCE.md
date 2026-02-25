# zmoltcp Conformance Tracking

Tracks zmoltcp tests against their smoltcp reference implementations.

**Total: 592 tests passing** (591 named + 1 root import test)

## Summary

| Module | smoltcp Tests | zmoltcp Tests | N/A | Passing | Status |
|--------|--------------|---------------|-----|---------|--------|
| wire/checksum | 5 | 6 | 0 | 6 | PASS |
| wire/ethernet | 5 | 5 | 0 | 5 | PASS |
| wire/arp | 4 | 5 | 0 | 5 | PASS |
| wire/ip | 0 | 7 | 0 | 7 | PASS |
| wire/ipv4 | 15 | 16 | 0 | 16 | PASS |
| wire/tcp | 9 | 22 | 0 | 22 | PASS |
| wire/udp | 8 | 8 | 0 | 8 | PASS |
| wire/icmp | 5 | 5 | 0 | 5 | PASS |
| storage/ring_buffer | 15 | 14 | 1 | 14 | PASS |
| storage/assembler | 38 | 37 | 1 | 37 | PASS |
| time | 10 | 8 | 2 | 8 | PASS |
| socket/tcp | 175 | 217 | 3 | 217 | PASS |
| socket/udp | 16 | 17 | 0 | 17 | PASS |
| wire/dhcp | 9 | 9 | 0 | 9 | PASS |
| socket/dhcp | 11 | 11 | 0 | 11 | PASS |
| wire/dns | 7 | 7 | 0 | 7 | PASS |
| socket/dns | 0 | 12 | 0 | 12 | PASS |
| socket/icmp | 6 | 7 | 0 | 7 | PASS |
| socket/raw | 5 | 11 | 0 | 11 | PASS |
| wire/igmp | 4 | 8 | 0 | 8 | PASS |
| wire/ipv6 | 12 | 12 | 0 | 12 | PASS |
| wire/ipv6option | 7 | 7 | 0 | 7 | PASS |
| wire/ipv6ext_header | 3 | 5 | 0 | 5 | PASS |
| wire/ipv6fragment | 3 | 4 | 0 | 4 | PASS |
| wire/ipv6routing | 3 | 4 | 0 | 4 | PASS |
| wire/ipv6hbh | 2 | 3 | 0 | 3 | PASS |
| wire/ndiscoption | 5 | 8 | 0 | 8 | PASS |
| wire/ndisc | 2 | 4 | 0 | 4 | PASS |
| wire/mld | 2 | 6 | 0 | 6 | PASS |
| wire/icmpv6 | 6 | 9 | 0 | 9 | PASS |
| iface | 24 | 33 | 1 | 33 | PASS |
| phy | 0 | 9 | 0 | 9 | PASS |
| fragmentation | 3 | 8 | 0 | 8 | PASS |
| stack | 2 | 47 | 0 | 47 | PASS |
| **Total** | | **591** | **8** | **591** | **PASS** |

## Wire Layer Tests

### wire/checksum.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/mod.rs (checksum) | "checksum of all zeros" | PASS |
| wire/mod.rs (checksum) | "checksum of 0xFF bytes" | PASS |
| wire/mod.rs (checksum) | "checksum odd length" | PASS |
| wire/mod.rs (checksum) | "checksum accumulate non-contiguous" | PASS |
| (RFC 8200 vector) | "IPv6 pseudo-header checksum" | PASS |
| (RFC 1071 vector) | "IPv4 header checksum known value" | PASS |

### wire/ethernet.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ethernet.rs:test_parse | "parse ethernet frame" | PASS |
| (original) | "parse ethernet truncated" | PASS |
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

### wire/ip.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| (original) | "Cidr(ipv4) basic containment" | PASS |
| (original) | "Cidr(ipv4) prefix_len 0 contains all" | PASS |
| (original) | "Cidr(ipv4) broadcast and networkAddr" | PASS |
| (original) | "Endpoint and ListenEndpoint basic usage" | PASS |
| (original) | "Cidr(ipv6) basic containment" | PASS |
| (original) | "Cidr(ipv6) prefix_len 0 contains all" | PASS |
| (original) | "Endpoint(ipv6) and ListenEndpoint(ipv6)" | PASS |

### wire/ipv4.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ipv4.rs:test_parse | "parse IPv4 header" | PASS |
| (original) | "parse IPv4 truncated" | PASS |
| (original) | "parse IPv4 bad version" | PASS |
| (original) | "parse IPv4 bad IHL" | PASS |
| wire/ipv4.rs:roundtrip | "IPv4 roundtrip" | PASS |
| (original) | "IPv4 emit produces valid checksum" | PASS |
| (original) | "IPv4 payload extraction" | PASS |
| wire/ipv4.rs:test_deconstruct | "IPv4 deconstruct raw fields" | PASS |
| wire/ipv4.rs:test_construct | "IPv4 construct with flags and frag offset" | PASS |
| wire/ipv4.rs:test_overlong | "IPv4 overlong buffer clamped to total_len" | PASS |
| wire/ipv4.rs:test_total_len_overflow | "IPv4 total_len overflow" | PASS |
| wire/ipv4.rs:test_emit | "IPv4 emit repr to exact bytes" | PASS |
| wire/ipv4.rs:test_cidr | "IPv4 CIDR contains" | PASS |
| wire/ipv4.rs:test_unspecified | "IPv4 address classification: unspecified" | PASS |
| wire/ipv4.rs:test_broadcast | "IPv4 address classification: broadcast" | PASS |
| (original) | "IPv4 formatAddr" | PASS |

### wire/tcp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/tcp.rs:test_parse | "parse TCP SYN" | PASS |
| (original) | "parse TCP truncated" | PASS |
| (original) | "parse TCP bad data offset" | PASS |
| wire/tcp.rs:test_parse_options | "parse TCP with MSS option" | PASS |
| wire/tcp.rs:roundtrip | "TCP SYN roundtrip" | PASS |
| (original) | "TCP checksum computation" | PASS |
| (original) | "SeqNumber wrapping add and sub" | PASS |
| (original) | "SeqNumber signed comparison across wrap boundary" | PASS |
| (original) | "SeqNumber diff" | PASS |
| (original) | "SeqNumber max and min" | PASS |
| (original) | "Control seqLen" | PASS |
| (original) | "Control from and to Flags" | PASS |
| (original) | "Control quashPsh" | PASS |
| (original) | "headerLen no options" | PASS |
| (original) | "headerLen MSS only" | PASS |
| (original) | "headerLen SYN with MSS + WindowScale + SackPermitted" | PASS |
| (original) | "headerLen timestamp" | PASS |
| (original) | "headerLen SACK range" | PASS |
| (original) | "timestamp option parse and emit roundtrip" | PASS |
| (original) | "SACK range parse and emit roundtrip" | PASS |
| (original) | "SYN options MSS + WindowScale + SackPermitted roundtrip" | PASS |
| wire/tcp.rs:test_malformed_tcp_options | "malformed TCP options parsed without error" | PASS |

### wire/udp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/udp.rs:test_parse | "parse UDP datagram" | PASS |
| (original) | "parse UDP truncated" | PASS |
| wire/udp.rs:roundtrip | "UDP roundtrip" | PASS |
| (original) | "UDP payload extraction" | PASS |
| wire/udp.rs:test_deconstruct | "UDP deconstruct raw fields" | PASS |
| wire/udp.rs:test_construct | "UDP construct with checksum" | PASS |
| wire/udp.rs:test_zero_checksum | "UDP zero checksum becomes 0xFFFF" | PASS |
| wire/udp.rs:test_no_checksum | "UDP disabled checksum passes verify" | PASS |

### wire/icmp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/icmpv4.rs:test_parse_echo | "parse ICMP echo request" | PASS |
| (original) | "parse ICMP dest unreachable" | PASS |
| (original) | "ICMP echo emit with valid checksum" | PASS |
| (original) | "ICMP echo roundtrip" | PASS |
| wire/icmpv4.rs:test_check_len | "ICMP check length" | PASS |

### wire/dhcp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/dhcpv4.rs:test_deconstruct_discover | "deconstruct discover raw fields" | PASS |
| wire/dhcpv4.rs:test_parse_discover | "parse discover" | PASS |
| wire/dhcpv4.rs:test_emit_discover | "emit discover" | PASS |
| wire/dhcpv4.rs:test_emit_offer | "emit offer" | PASS |
| wire/dhcpv4.rs:test_emit_offer_dns | "emit offer with dns servers roundtrip" | PASS |
| wire/dhcpv4.rs:test_emit_dhcp_option | "emit dhcp option TLV" | PASS |
| wire/dhcpv4.rs:test_parse_ack_dns_servers | "parse ack with dns servers capped at 3" | PASS |
| wire/dhcpv4.rs:test_parse_ack_lease_duration | "parse ack with lease duration" | PASS |
| wire/dhcpv4.rs:test_construct_discover | "construct discover from bytes" | PASS |

### wire/dns.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/dns.rs:test_parse_name | "parse name with pointer compression" | PASS |
| wire/dns.rs:test_parse_request | "parse request" | PASS |
| wire/dns.rs:test_parse_response | "parse response single A" | PASS |
| wire/dns.rs:test_parse_response_multiple_a | "parse response multiple A" | PASS |
| wire/dns.rs:test_parse_response_cname | "parse response CNAME" | PASS |
| wire/dns.rs:test_parse_response_nxdomain | "parse response NXDomain" | PASS |
| wire/dns.rs:test_emit | "emit query" | PASS |

### wire/igmp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/igmp.rs:test_leave_group_deconstruct | "IGMP leave group parse" | PASS |
| wire/igmp.rs:test_report_deconstruct | "IGMP membership report v2 parse" | PASS |
| wire/igmp.rs:test_leave_construct | "IGMP leave group emit and checksum" | PASS |
| wire/igmp.rs:test_report_construct | "IGMP report v2 emit and checksum" | PASS |
| (original) | "IGMP parse rejects too short" | PASS |
| (original) | "IGMP parse rejects non-multicast group" | PASS |
| (original) | "IGMP emit roundtrip" | PASS |
| (original) | "IGMP v1 query detected by zero max_resp_code" | PASS |

### wire/ipv6.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ipv6.rs:test_repr_parse | "parse IPv6 header" | PASS |
| (original) | "parse IPv6 truncated" | PASS |
| (original) | "parse IPv6 bad version" | PASS |
| wire/ipv6.rs:test_repr_emit | "IPv6 roundtrip" | PASS |
| (original) | "IPv6 emit buffer too small" | PASS |
| (original) | "IPv6 payload extraction" | PASS |
| (original) | "IPv6 payload clamped" | PASS |
| (original) | "IPv6 checkLen valid" | PASS |
| (original) | "IPv6 checkLen truncated payload" | PASS |
| wire/ipv6.rs:test_address | "IPv6 address classification" | PASS |
| wire/ipv6.rs:test_solicited_node | "IPv6 solicited-node multicast" | PASS |
| (original) | "IPv6 formatAddr compressed" | PASS |

### wire/ipv6option.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ipv6option.rs:test_check_len | "parse Pad1" | PASS |
| wire/ipv6option.rs:test_option_deconstruct | "parse PadN" | PASS |
| wire/ipv6option.rs:test_option_deconstruct | "parse RouterAlert MLD" | PASS |
| wire/ipv6option.rs:test_option_deconstruct | "parse RouterAlert RSVP" | PASS |
| wire/ipv6option.rs:test_option_deconstruct | "parse unknown option" | PASS |
| wire/ipv6option.rs:test_option_construct | "option roundtrip" | PASS |
| wire/ipv6option.rs:test_option_iterator | "iterator with mixed options" | PASS |

### wire/ipv6ext_header.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| (original) | "headerLen encoding" | PASS |
| wire/ipv6ext_header.rs:test_ext_header_deconstruct | "parse extension header with PadN(4)" | PASS |
| wire/ipv6ext_header.rs:test_ext_header_deconstruct | "parse extension header with PadN(12)" | PASS |
| wire/ipv6ext_header.rs:test_ext_header_construct | "extension header roundtrip" | PASS |
| (original) | "parse truncated" | PASS |

### wire/ipv6fragment.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ipv6fragment.rs:test_frag_header_deconstruct | "parse fragment header more_frags" | PASS |
| wire/ipv6fragment.rs:test_frag_header_deconstruct | "parse fragment header last frag" | PASS |
| wire/ipv6fragment.rs:test_frag_header_construct | "fragment header roundtrip" | PASS |
| (original) | "parse fragment truncated" | PASS |

### wire/ipv6routing.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ipv6routing.rs:test_deconstruct_type2 | "parse Type2 routing header" | PASS |
| wire/ipv6routing.rs:test_construct_type2 | "Type2 roundtrip" | PASS |
| wire/ipv6routing.rs:test_deconstruct_rpl_elided | "parse RPL elided" | PASS |
| (original) | "unrecognized routing type" | PASS |

### wire/ipv6hbh.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ipv6hopbyhop.rs:test_hbh_deconstruct | "parse HBH with PadN(4)" | PASS |
| (original) | "parse HBH with multiple options" | PASS |
| (original) | "mldv2RouterAlert preset" | PASS |

### wire/ndiscoption.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ndiscoption.rs:test_parse_source_lladdr | "parse source link-layer address" | PASS |
| (original) | "parse target link-layer address" | PASS |
| wire/ndiscoption.rs:test_parse_prefix_info | "parse prefix information" | PASS |
| wire/ndiscoption.rs:test_parse_mtu | "parse MTU option" | PASS |
| (original) | "parse unknown option" | PASS |
| (original) | "parse length zero is error" | PASS |
| (original) | "optionLen basic" | PASS |
| wire/ndiscoption.rs:test_construct_prefix_info | "prefix information roundtrip" | PASS |

### wire/ndisc.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/ndisc.rs:test_router_advert_parse | "parse router advertisement" | PASS |
| (original) | "parse neighbor solicit" | PASS |
| wire/ndisc.rs:test_router_advert_emit | "router advertisement roundtrip" | PASS |
| (original) | "parse unrecognized NDP type" | PASS |

### wire/mld.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/mld.rs:test_query_deconstruct | "parse MLD query" | PASS |
| wire/mld.rs:test_report_deconstruct | "parse MLD report" | PASS |
| (original) | "parse MLD unrecognized type" | PASS |
| wire/mld.rs:test_query_construct | "MLD query roundtrip" | PASS |
| wire/mld.rs:test_record_deconstruct | "parse address record" | PASS |
| (original) | "address record roundtrip" | PASS |

### wire/icmpv6.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| wire/icmpv6.rs:test_echo_parse | "echo request parse" | PASS |
| wire/icmpv6.rs:test_echo_emit | "echo reply roundtrip" | PASS |
| (original) | "bad checksum rejected" | PASS |
| wire/icmpv6.rs:test_pkt_too_big | "pkt_too_big roundtrip" | PASS |
| wire/icmpv6.rs:test_dst_unreachable | "dst_unreachable roundtrip" | PASS |
| (original) | "ndisc via icmpv6" | PASS |
| (original) | "mld query via icmpv6" | PASS |
| (original) | "truncated message" | PASS |
| (original) | "verifyChecksum" | PASS |

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

## Time Tests

### time.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| time.rs:test_instant_ops | "instant arithmetic" | PASS |
| time.rs:test_instant_getters | "instant getters" | PASS |
| time.rs:test_duration_ops | "duration arithmetic" | PASS |
| time.rs:test_duration_getters | "duration getters" | PASS |
| (original) | "instant diff" | PASS |
| (original) | "instant comparison" | PASS |
| (original) | "duration clamp" | PASS |
| time.rs:test_sub_from_zero_overflow | "duration saturating subtract" | PASS |

## Socket Layer Tests

### socket/tcp.zig

Note: TCP tests are now included in the root test runner (`src/root.zig`) and
execute in CI. Prior to this, the TCP imports were commented out and these tests
were never actually run despite being listed here. The test module runs with
`.single_threaded = true` to avoid shared-buffer races between tests.
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| (original) | "rtt estimator first sample" | PASS |
| (original) | "rtt estimator subsequent sample" | PASS |
| (original) | "rtt estimator backoff" | PASS |
| (original) | "timer idle and retransmit" | PASS |
| (original) | "timer close" | PASS |
| (original) | "socket init" | PASS |
| test_listen | "listen sanity" | PASS |
| test_listen_validation | "listen validation rejects port 0" | PASS |
| test_listen_twice | "listen twice on same port is ok" | PASS |
| test_listen_syn | "listen receives SYN -> SYN-RECEIVED" | PASS |
| test_listen_rst | "listen rejects RST" | PASS |
| test_listen_syn_reject_ack | "listen rejects SYN with ACK" | PASS |
| test_listen_close | "listen close goes to closed" | PASS |
| test_listen_timeout | "listen never times out" | PASS |
| test_listen_sack_option | "listen sack option enabled" | PASS |
| test_listen_sack_option | "listen sack option disabled" | PASS |
| test_syn_received_ack | "SYN-RECEIVED receives ACK -> ESTABLISHED" | PASS |
| test_syn_received_close | "SYN-RECEIVED close -> FIN-WAIT-1" | PASS |
| test_syn_received_rst | "SYN-RECEIVED RST returns to LISTEN" | PASS |
| test_syn_received_ack_too_high | "SYN-RECEIVED rejects ACK too high" | PASS |
| test_syn_received_ack_too_low | "SYN-RECEIVED rejects ACK too low" | PASS |
| test_syn_received_fin | "SYN-RECEIVED recv FIN -> CLOSE-WAIT" | PASS |
| test_syn_received_no_window_scaling | "SYN-RECEIVED no window scaling" | PASS |
| test_syn_received_window_scaling | "SYN-RECEIVED window scaling" | PASS |
| test_syn_sent_sanity | "SYN-SENT sanity" | PASS |
| test_syn_sent_dispatch | "SYN-SENT dispatch emits SYN" | PASS |
| test_syn_sent_syn_ack | "SYN-SENT receives SYN\|ACK -> ESTABLISHED" | PASS |
| test_syn_sent_rst | "SYN-SENT receives RST\|ACK -> CLOSED" | PASS |
| test_syn_sent_close | "SYN-SENT close goes to CLOSED" | PASS |
| test_syn_sent_bad_ack_seq_1 | "SYN-SENT sends RST for bad ACK seq too high" | PASS |
| test_syn_sent_bad_ack_seq_2 | "SYN-SENT sends RST for bad ACK seq too low" | PASS |
| test_syn_sent_rst_no_ack | "SYN-SENT ignores RST without ACK" | PASS |
| test_syn_sent_rst_bad_ack | "SYN-SENT ignores RST with wrong ACK" | PASS |
| test_syn_sent_bad_ack | "SYN-SENT ignores bare ACK with correct seq" | PASS |
| test_syn_sent_syn_received_ack | "SYN-SENT receives SYN (simultaneous open) -> SYN-RECEIVED" | PASS |
| test_syn_sent_syn_received_rst | "SYN-SENT simultaneous open then RST" | PASS |
| test_syn_sent_sack_option | "SYN-SENT sack option" | PASS |
| test_syn_sent_syn_ack_window_scaling | "SYN-SENT syn ack window scaling" | PASS |
| test_syn_sent_syn_ack_not_incremented | "SYN-SENT rejects SYN\|ACK with un-incremented ACK" | PASS |
| test_connect_twice | "connect twice fails" | PASS |
| test_connect_validation | "connect validation" | PASS |
| test_established_recv | "ESTABLISHED recv data" | PASS |
| test_established_send | "ESTABLISHED send data" | PASS |
| test_established_send_recv | "ESTABLISHED send and receive" | PASS |
| test_established_fin | "ESTABLISHED recv FIN -> CLOSE-WAIT" | PASS |
| test_established_fin | "ESTABLISHED recv FIN with ACK" | PASS |
| test_established_close | "ESTABLISHED close sets FIN-WAIT-1 state" | PASS |
| test_established_abort | "ESTABLISHED abort sends RST" | PASS |
| test_established_rst | "ESTABLISHED recv RST -> CLOSED" | PASS |
| test_established_rst | "ESTABLISHED recv RST without ACK -> CLOSED" | PASS |
| test_established_send_fin | "ESTABLISHED recv FIN while send data queued" | PASS |
| test_established_send_buf_gt_win | "ESTABLISHED send more data than window" | PASS |
| test_established_send_no_ack_send | "ESTABLISHED send two segments without ACK (nagle off)" | PASS |
| test_established_no_ack | "ESTABLISHED rejects packet without ACK and stays established" | PASS |
| test_established_bad_ack | "ESTABLISHED ignores ACK too low" | PASS |
| test_established_bad_seq | "ESTABLISHED bad seq gets challenge ACK" | PASS |
| test_established_rst_bad_seq | "ESTABLISHED RST bad seq gets challenge ACK" | PASS |
| test_established_fin_after_missing | "ESTABLISHED FIN after missing segment stays established" | PASS |
| test_established_receive_partially_outside_window | "ESTABLISHED receive partially outside window" | PASS |
| test_established_receive_partially_outside_window_fin | "ESTABLISHED receive partially outside window with FIN" | PASS |
| test_established_send_wrap | "ESTABLISHED send wrap around seq boundary" | PASS |
| test_established_send_window_shrink | "ESTABLISHED send window shrink" | PASS |
| (original) | "FIN-WAIT-1 recv FIN+ACK -> TIME-WAIT" | PASS |
| test_fin_wait_1_fin_ack | "FIN-WAIT-1 recv ACK of FIN -> FIN-WAIT-2" | PASS |
| test_fin_wait_1_fin_fin | "FIN-WAIT-1 recv FIN without ACK of our FIN -> CLOSING" | PASS |
| test_fin_wait_1_fin_fin | "FIN-WAIT-1 recv FIN without data and no ack of our FIN -> CLOSING" | PASS |
| test_fin_wait_1_close | "FIN-WAIT-1 close is noop" | PASS |
| test_fin_wait_1_recv | "FIN-WAIT-1 recv data" | PASS |
| test_fin_wait_1_fin_with_data_queued | "FIN-WAIT-1 with data queued waits for ack" | PASS |
| test_fin_wait_2_fin | "FIN-WAIT-2 recv FIN -> TIME-WAIT" | PASS |
| test_fin_wait_2_close | "FIN-WAIT-2 close is noop" | PASS |
| test_fin_wait_2_recv | "FIN-WAIT-2 recv data" | PASS |
| (original) | "CLOSING recv ACK -> TIME-WAIT" | PASS |
| test_closing_ack_fin | "CLOSING recv ACK of FIN -> TIME-WAIT via ack_fin" | PASS |
| test_closing_close | "CLOSING close is noop" | PASS |
| test_time_wait_from_fin_wait_2_ack | "TIME-WAIT from FIN-WAIT-2 dispatches ACK" | PASS |
| test_time_wait_from_closing_no_ack | "TIME-WAIT from CLOSING dispatches nothing" | PASS |
| (original) | "TIME-WAIT expires to CLOSED" | PASS |
| test_time_wait_timeout | "TIME-WAIT timeout expires to CLOSED" | PASS |
| test_time_wait_close | "TIME-WAIT close is noop" | PASS |
| test_time_wait_retransmit | "time wait retransmit" | PASS |
| test_time_wait_no_window_update | "TIME-WAIT no window update" | PASS |
| test_close_wait_ack | "CLOSE-WAIT send data and receive ACK" | PASS |
| test_close_wait_close | "CLOSE-WAIT close sets LAST-ACK state" | PASS |
| test_close_wait_no_window_update | "close wait no window update" | PASS |
| test_last_ack_fin_ack | "LAST-ACK dispatches FIN then ACK -> CLOSED" | PASS |
| test_last_ack_ack_not_of_fin | "LAST-ACK stays until FIN is acked" | PASS |
| test_last_ack_close | "LAST-ACK close is noop" | PASS |
| (original) | "full three-way handshake via listen" | PASS |
| (original) | "full handshake via connect" | PASS |
| (original) | "local close full sequence" | PASS |
| (original) | "remote close full sequence" | PASS |
| (original) | "simultaneous close" | PASS |
| (original) | "simultaneous close combined FIN+ACK" | PASS |
| test_simultaneous_close_raced | "simultaneous close raced" | PASS |
| test_simultaneous_close_raced_with_data | "simultaneous close raced with data" | PASS |
| test_mutual_close_with_data_1 | "mutual close with data 1" | PASS |
| test_mutual_close_with_data_2 | "mutual close with data 2" | PASS |
| test_data_retransmit | "data retransmit on RTO" | PASS |
| test_data_retransmit | "retransmission after timeout" | PASS |
| test_data_retransmit_bursts | "data retransmit bursts" | PASS |
| test_data_retransmit_bursts_half_ack | "data retransmit bursts half ack" | PASS |
| test_retransmit_timer_restart_on_partial_ack | "retransmit timer restart on partial ack" | PASS |
| test_data_retransmit_bursts_half_ack_close | "data retransmit bursts half ack close" | PASS |
| test_retransmit_exponential_backoff | "retransmit exponential backoff" | PASS |
| test_retransmit_fin | "retransmit FIN" | PASS |
| test_retransmit_fin_wait | "retransmit in CLOSING state" | PASS |
| test_established_retransmit_for_dup_ack | "dup ack does not replace retransmit timer" | PASS |
| test_established_retransmit_reset_after_ack | "retransmit reset after ack windowed" | PASS |
| test_established_queue_during_retransmission | "queue during retransmission" | PASS |
| test_fast_retransmit_after_triple_duplicate_ack | "fast retransmit after triple dup ack" | PASS |
| test_fast_retransmit_dup_acks_counter | "dup ack counter saturates" | PASS |
| test_fast_retransmit_duplicate_detection_with_data | "dup ack counter reset on data" | PASS |
| test_fast_retransmit_duplicate_detection_with_window_update | "dup ack counter reset on window update" | PASS |
| test_fast_retransmit_duplicate_detection | "fast retransmit duplicate detection with no data" | PASS |
| test_fast_retransmit_zero_window | "fast retransmit zero window" | PASS |
| test_data_retransmit_ack_more_than_expected | "retransmit ack more than expected" | PASS |
| test_close_wait_retransmit_reset | "close wait retransmit reset after ack" | PASS |
| test_fin_wait_1_retransmit_reset | "fin wait 1 retransmit reset after ack" | PASS |
| test_send_data_after_syn_ack_retransmit | "send data after SYN-ACK retransmit" | PASS |
| test_connect_timeout | "connect timeout" | PASS |
| test_established_timeout | "established timeout" | PASS |
| test_fin_wait_1_timeout | "fin wait 1 timeout" | PASS |
| test_last_ack_timeout | "last ack timeout" | PASS |
| test_closed_timeout | "closed timeout" | PASS |
| test_established_keep_alive_timeout | "established keep alive timeout" | PASS |
| test_send_keep_alive | "sends keep alive probes" | PASS |
| test_send_keep_alive | "keep alive sends probes" | PASS |
| test_respond_to_keep_alive | "responds to keep alive probe" | PASS |
| test_maximum_segment_size | "maximum segment size from SYN" | PASS |
| test_out_of_order | "out of order reassembly" | PASS |
| test_buffer_wraparound_rx | "buffer wraparound rx" | PASS |
| test_buffer_wraparound_tx | "buffer wraparound tx" | PASS |
| test_rx_close_fin | "rx close FIN with data" | PASS |
| test_rx_close_fin_in_fin_wait_1 | "rx close FIN in FIN-WAIT-1" | PASS |
| test_rx_close_fin_in_fin_wait_2 | "rx close FIN in FIN-WAIT-2" | PASS |
| test_rx_close_fin_with_hole | "rx close FIN with hole" | PASS |
| test_rx_close_rst | "rx close RST" | PASS |
| test_rx_close_rst_with_hole | "rx close RST with hole" | PASS |
| test_delayed_ack | "delayed ack" | PASS |
| test_delayed_ack_reply | "delayed ack piggybacks on outgoing data" | PASS |
| test_delayed_ack_win | "delayed ack window update" | PASS |
| test_window_update_with_delay_ack | "window update with delay ack" | PASS |
| test_delayed_ack_every_rmss | "delayed ack every rmss" | PASS |
| test_delayed_ack_every_rmss_or_more | "delayed ack every rmss or more" | PASS |
| test_nagle | "nagle algorithm" | PASS |
| test_final_packet_in_stream_doesnt_wait_for_nagle | "FIN bypasses Nagle" | PASS |
| test_fill_peer_window | "fill peer window" | PASS |
| test_psh_receive | "PSH on receive is treated as normal data" | PASS |
| test_psh_transmit | "PSH set on last segment in burst" | PASS |
| test_zero_window_probe | "zero window probe enters on send" | PASS |
| test_zero_window_probe | "zero window probe enters on window update" | PASS |
| test_zero_window_probe | "zero window probe exits on window open" | PASS |
| test_zero_window_probe | "zero window probe sends 1 byte and exits on ack" | PASS |
| test_zero_window_probe_backoff_no_reply | "zero window probe backs off" | PASS |
| test_zero_window_probe_backoff_nack_reply | "zero window probe backoff with nack reply" | PASS |
| test_zero_window_probe_shift | "zero window probe shift" | PASS |
| test_zero_window_ack | "zero window ack rejects data" | PASS |
| test_zero_window_fin | "zero window accepts FIN" | PASS |
| test_zero_window_ack_on_window_growth | "zero window ack on window growth" | PASS |
| test_announce_window_after_read | "announce window after read" | PASS |
| test_duplicate_seq_ack | "duplicate seq ack (remote retransmission)" | PASS |
| test_doesnt_accept_wrong_ip | "doesnt accept wrong ip" | PASS |
| test_doesnt_accept_wrong_port | "doesnt accept wrong port" | PASS |
| test_closed_reject | "closed rejects SYN" | PASS |
| test_closed_reject_after_listen | "closed rejects after listen+close" | PASS |
| test_closed_close | "close on closed is noop" | PASS |
| test_peek_slice | "peek slice" | PASS |
| test_peek_slice_buffer_wrap | "peek slice buffer wrap" | PASS |
| test_send_error | "send error when not established" | PASS |
| test_recv_error | "recv error when not established" | PASS |
| test_syn_sent_syn_received_ack | "SYN-SENT simultaneous open SYN then ACK -> ESTABLISHED" | PASS |
| test_fin_with_data | "FIN with data queued" | PASS |
| test_set_hop_limit | "set hop limit propagates to dispatch" | PASS |
| test_set_hop_limit_zero | "set hop limit zero rejected" | PASS |
| test_listen_syn_win_scale_buffers | "listen syn window scale for various buffer sizes" | PASS |
| test_syn_sent_syn_ack_no_window_scaling | "SYN-SENT syn ack no window scaling clears shift" | PASS |
| test_connect | "connect full active open roundtrip" | PASS |
| test_syn_sent_win_scale_buffers | "SYN-SENT window scale for various rx buffer sizes" | PASS |
| test_established_sliding_window_recv | "established sliding window recv with scaling" | PASS |
| test_recv_out_of_recv_win | "recv data beyond advertised receive window" | PASS |
| (original) | "pollAt SYN-SENT returns ZERO" | PASS |
| (original) | "pollAt LISTEN returns null" | PASS |
| (original) | "pollAt established with keep-alive returns timer deadline" | PASS |
| test_tsval_established_connection | "tsval established connection" | PASS |
| test_tsval_disabled_in_remote_client | "tsval disabled in remote client" | PASS |
| test_tsval_disabled_in_local_server | "tsval disabled in local server" | PASS |
| test_tsval_disabled_in_remote_server | "tsval disabled in remote server" | PASS |
| test_tsval_disabled_in_local_client | "tsval disabled in local client" | PASS |
| test_established_rfc2018_cases | "established rfc2018 cases" | PASS |
| (original) | "localEndpoint and remoteEndpoint" | PASS |
| (original) | "setTimeout and setKeepAlive" | PASS |
| (original) | "setAckDelay" | PASS |
| (original) | "setNagleEnabled" | PASS |
| (original) | "sendQueue and recvQueue" | PASS |
| (original) | "sendCapacity and recvCapacity" | PASS |
| (original) | "setHopLimit validation" | PASS |
| (original) | "NoControl window is maxInt" | PASS |
| (original) | "Reno slow start doubles cwnd" | PASS |
| (original) | "Reno congestion avoidance linear growth" | PASS |
| (original) | "Reno onRetransmit halves cwnd" | PASS |
| (original) | "Reno onDuplicateAck sets ssthresh" | PASS |
| (original) | "Reno cwnd capped by rwnd" | PASS |
| (original) | "Reno setMss updates min_cwnd" | PASS |
| (original) | "Cubic cubeRoot correctness" | PASS |
| (original) | "Cubic onRetransmit records w_max and halves ssthresh" | PASS |
| (original) | "Cubic slow start grows like Reno" | PASS |
| (original) | "Cubic preTransmit sets recovery_start on first call" | PASS |
| (original) | "CongestionController dispatch to Reno variant" | PASS |
| test_set_get_congestion_control | "setCongestionControl and congestionControl roundtrip" | PASS |
| (original) | "Reno cwnd limits send window in established" | PASS |
| (original) | "Reno onAck grows cwnd via process" | PASS |
| (original) | "Reno onRetransmit via dispatch retransmit path" | PASS |
| (original) | "congestion controller survives socket reset" | PASS |
| (original) | "closure send enqueues data and dispatches" | PASS |
| (original) | "closure recv consumes data from rx buffer" | PASS |
| (original) | "closure send returns zero when tx buffer full" | PASS |

### socket/udp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| socket/udp.rs:test_bind_unaddressable | "bind rejects port 0" | PASS |
| socket/udp.rs:test_bind_twice | "bind twice fails" | PASS |
| socket/udp.rs:test_set_hop_limit_zero | "set hop limit zero rejected" | PASS |
| socket/udp.rs:test_send_unaddressable | "send before bind and with bad addresses" | PASS |
| socket/udp.rs:test_send_with_source | "send with explicit local address" | PASS |
| socket/udp.rs:test_send_dispatch | "send and dispatch outbound packet" | PASS |
| socket/udp.rs:test_recv_process | "process inbound and recv" | PASS |
| socket/udp.rs:test_peek_process | "peek returns data without consuming" | PASS |
| socket/udp.rs:test_recv_truncated_slice | "recv_slice truncated with small buffer" | PASS |
| socket/udp.rs:test_peek_truncated_slice | "peek_slice non-destructive, recv_slice destructive" | PASS |
| socket/udp.rs:test_set_hop_limit | "hop limit propagates to dispatch" | PASS |
| socket/udp.rs:test_doesnt_accept_wrong_port | "rejects packet with wrong destination port" | PASS |
| socket/udp.rs:test_doesnt_accept_wrong_ip | "port-only bind accepts any addr; addr+port rejects wrong" | PASS |
| socket/udp.rs:test_send_large_packet | "payload exceeding capacity returns BufferFull" | PASS |
| socket/udp.rs:test_process_empty_payload | "zero-length datagram is valid" | PASS |
| socket/udp.rs:test_closing | "close resets socket" | PASS |
| (original) | "pollAt returns ZERO when tx queued, null when empty" | PASS |

### socket/icmp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| socket/icmp.rs:test_send_unaddressable | "send rejects unaddressable destination" | PASS |
| socket/icmp.rs:test_send_dispatch | "send and dispatch outbound packet" | PASS |
| socket/icmp.rs:test_set_hop_limit_v4 | "hop limit propagates to dispatch" | PASS |
| socket/icmp.rs:test_recv_process | "process inbound and recv" | PASS |
| socket/icmp.rs:test_accept_bad_id | "rejects packet with wrong identifier" | PASS |
| socket/icmp.rs:test_accepts_udp | "accepts ICMP error for bound UDP port" | PASS |
| (original) | "pollAt returns ZERO when tx queued, null when empty" | PASS |

### socket/raw.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| socket/raw.rs:test_send_truncated | "raw send truncation" | PASS |
| socket/raw.rs:test_send_dispatch | "raw send dispatch roundtrip" | PASS |
| socket/raw.rs:test_recv_process | "raw recv process roundtrip" | PASS |
| socket/raw.rs:test_peek | "raw peek returns data without consuming" | PASS |
| socket/raw.rs:test_recv_truncated | "raw recv truncated" | PASS |
| (original) | "raw accepts filters by protocol" | PASS |
| (original) | "raw unbound socket rejects all" | PASS |
| (original) | "raw close resets state" | PASS |
| (original) | "raw pollAt returns ZERO when tx pending" | PASS |
| (original) | "raw setHopLimit validation" | PASS |
| (original) | "raw process truncates oversized payload" | PASS |

### socket/dhcp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| socket/dhcpv4.rs:test_bind | "bind" | PASS |
| socket/dhcpv4.rs:test_bind_different_ports | "bind different ports" | PASS |
| socket/dhcpv4.rs:test_discover_retransmit | "discover retransmit" | PASS |
| socket/dhcpv4.rs:test_request_retransmit | "request retransmit" | PASS |
| socket/dhcpv4.rs:test_request_timeout | "request timeout" | PASS |
| socket/dhcpv4.rs:test_request_nak | "request nak" | PASS |
| socket/dhcpv4.rs:test_renew | "renew" | PASS |
| socket/dhcpv4.rs:test_renew_rebind_retransmit | "renew rebind retransmit" | PASS |
| socket/dhcpv4.rs:test_renew_rebind_timeout | "renew rebind timeout" | PASS |
| socket/dhcpv4.rs:test_min_max_renew_timeout | "min max renew timeout" | PASS |
| socket/dhcpv4.rs:test_renew_nak | "renew nak" | PASS |

### socket/dns.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| (original) | "start query encodes name" | PASS |
| (original) | "start query rejects empty name" | PASS |
| (original) | "start query rejects too-long label" | PASS |
| (original) | "start query no free slot" | PASS |
| (original) | "dispatch emits query packet" | PASS |
| (original) | "dispatch retransmit with backoff" | PASS |
| (original) | "dispatch timeout tries next server" | PASS |
| (original) | "dispatch all servers exhausted" | PASS |
| (original) | "process A response" | PASS |
| (original) | "process NXDomain" | PASS |
| (original) | "process CNAME then A" | PASS |
| (original) | "cancel query frees slot" | PASS |

## Interface Layer Tests

### iface.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| iface/interface/tests/ipv4.rs:test_local_subnet_broadcasts | "local subnet broadcasts" | PASS |
| iface/interface/tests/ipv4.rs:get_source_address | "get source address" | PASS |
| iface/interface/tests/ipv4.rs:get_source_address_empty_interface | "get source address empty interface" | PASS |
| iface/interface/tests/ipv4.rs:test_handle_valid_arp_request | "handle valid ARP request" | PASS |
| iface/interface/tests/ipv4.rs:test_handle_other_arp_request | "handle other ARP request" | PASS |
| iface/interface/tests/ipv4.rs:test_arp_flush_after_update_ip | "ARP flush after update IP" | PASS |
| iface/interface/tests/ipv4.rs:test_handle_ipv4_broadcast | "handle IPv4 broadcast" | PASS |
| iface/interface/tests/ipv4.rs:test_no_icmp_no_unicast | "no ICMP for unknown protocol to broadcast" | PASS |
| iface/interface/tests/ipv4.rs:test_icmp_error_no_payload | "ICMP error no payload" | PASS |
| iface/interface/tests/ipv4.rs:test_icmp_error_port_unreachable | "ICMP error port unreachable" | PASS |
| iface/interface/tests/mod.rs:test_handle_udp_broadcast | "handle UDP broadcast" | PASS |
| iface/interface/tests/ipv4.rs:test_icmp_reply_size | "ICMP reply size" | PASS |
| iface/interface/tests/ipv4.rs:test_any_ip_accept_arp | "any_ip accepts ARP for unknown address" | PASS |
| iface/interface/tests/ipv4.rs:test_icmpv4_socket | "ICMP socket receives echo request and auto-reply" | PASS |
| (original) | "TCP SYN with no listener produces RST" | PASS |

### iface/neighbor -- NeighborCache unit tests
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| iface/neighbor.rs:test_fill | "neighbor cache fill and lookup" | PASS |
| iface/neighbor.rs:test_expire | "neighbor cache entry expires" | PASS |
| iface/neighbor.rs:test_replace | "neighbor cache replace entry" | PASS |
| iface/neighbor.rs:test_evict | "neighbor cache evicts oldest entry" | PASS |
| iface/neighbor.rs:test_flush | "neighbor cache flush" | PASS |
| iface/neighbor.rs:test_hush (adapted) | "neighbor cache lookupFull found" | PASS |
| iface/neighbor.rs:test_hush (adapted) | "neighbor cache lookupFull not found" | PASS |
| iface/neighbor.rs:test_hush (adapted) | "neighbor cache lookupFull rate limited" | PASS |
| (original) | "neighbor cache rate limit expires" | PASS |

### iface/route -- Routing table unit tests
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| iface/route.rs:test_fill (adapted) | "route lookup empty table" | PASS |
| iface/route.rs:test_fill (adapted) | "route lookup match and no match" | PASS |
| (original) | "route lookup longest prefix match" | PASS |
| iface/route.rs:test_fill (adapted) | "route lookup expiry" | PASS |
| (original) | "route default gateway" | PASS |
| (original) | "interface route direct delivery vs gateway" | PASS |
| (original) | "interface hasNeighbor with routing" | PASS |
| (original) | "multicast group join leave has" | PASS |
| (original) | "multicast group full capacity" | PASS |

## Stack Layer Tests

### stack.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| (original) | "stack ARP request produces reply" | PASS |
| (original) | "stack ICMP echo request produces reply" | PASS |
| (original) | "stack empty RX returns false" | PASS |
| (original) | "stack loopback device round-trip" | PASS |
| (original) | "stack pollAt returns null with no sockets" | PASS |
| (original) | "stack TCP SYN no listener produces RST" | PASS |
| (original) | "stack UDP to bound socket delivers data" | PASS |
| (original) | "stack ICMP echo with bound socket delivers and auto-replies" | PASS |
| (original) | "stack TCP egress dispatches SYN on connect" | PASS |
| (original) | "stack TCP handshake completes via listen" | PASS |
| (original) | "stack UDP egress dispatches datagram" | PASS |
| (original) | "stack ICMP egress dispatches echo request" | PASS |
| (original) | "stack poll returns true for egress-only activity" | PASS |
| (original) | "stack pollAt returns ZERO for pending TCP SYN-SENT" | PASS |
| (original) | "stack pollAt returns null for idle sockets" | PASS |
| (original) | "stack egress uses cached neighbor MAC" | PASS |
| (original) | "stack pollAt returns retransmit deadline after SYN dispatch" | PASS |
| (original) | "stack DHCP discover dispatches via UDP broadcast" | PASS |
| (original) | "stack DHCP ingress processes offer" | PASS |
| (original) | "stack DHCP pollAt returns socket deadline" | PASS |
| (original) | "stack DNS query dispatches via UDP" | PASS |
| (original) | "stack DNS ingress delivers response" | PASS |
| (original) | "stack DNS pollAt returns retransmit deadline" | PASS |
| iface/interface/tests/ipv4.rs:test_packet_len | "stack IPv4 fragmentation never exceeds MTU" | PASS |
| iface/interface/tests/ipv4.rs:test_ipv4_fragment_size | "stack IPv4 fragment payload is 8-byte aligned" | PASS |
| (original) | "stack emits ARP request for unknown neighbor on TCP egress" | PASS |
| (original) | "stack TCP SYN sent after ARP resolution" | PASS |
| (original) | "stack ARP request rate limited" | PASS |
| (original) | "stack UDP does not lose packet during ARP resolution" | PASS |
| (original) | "stack ICMP echo reply uses cached neighbor from ingress" | PASS |
| (original) | "stack pollAt accounts for neighbor resolution delay" | PASS |
| (original) | "stack broadcast destination skips ARP resolution" | PASS |
| (original) | "stack reassembles two-fragment ICMP echo" | PASS |
| (original) | "stack reassembles out-of-order UDP fragments" | PASS |
| (original) | "stack non-fragmented packets bypass reassembly" | PASS |
| (original) | "stack rejects IPv4 with broadcast source address" | PASS |
| (original) | "stack rejects IPv4 with multicast source address" | PASS |
| (original) | "stack neighbor cache refresh gated by same network" | PASS |
| (original) | "stack egress routes via gateway for off-subnet destination" | PASS |
| (original) | "stack raw socket receives IP payload" | PASS |
| (original) | "stack raw socket suppresses ICMP proto unreachable" | PASS |
| (original) | "stack IGMP query triggers report for joined group" | PASS |
| (original) | "stack multicast destination accepted for joined group" | PASS |
| (original) | "TCP checksum offload skips computation" | PASS |
| (original) | "burst size limits frames per poll cycle" | PASS |
| (original) | "DeviceCapabilities defaults enable all checksums" | PASS |
| (original) | "ChecksumMode shouldVerifyRx and shouldComputeTx" | PASS |

### phy.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| (original) | "Tracer forwards receive and transmit" | PASS |
| (original) | "Tracer returns null when inner has no frames" | PASS |
| (original) | "FaultInjector drops rx frames at configured rate" | PASS |
| (original) | "FaultInjector passes rx frames when rng above threshold" | PASS |
| (original) | "FaultInjector drops tx frames at configured rate" | PASS |
| (original) | "FaultInjector corrupts rx frame" | PASS |
| (original) | "FaultInjector corrupts tx frame" | PASS |
| (original) | "FaultInjector zero config passes everything through" | PASS |
| (original) | "Tracer and FaultInjector compose" | PASS |

### fragmentation.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| (original) | "maxIpv4FragmentPayload alignment" | PASS |
| (original) | "fragmenter stage and emit" | PASS |
| iface/fragmentation.rs:packet_assembler_assemble | "reassembler two-part assembly" | PASS |
| iface/fragmentation.rs:packet_assembler_out_of_order_assemble | "reassembler out-of-order assembly" | PASS |
| iface/fragmentation.rs:packet_assembler_overlap | "reassembler overlapping fragments" | PASS |
| (original) | "reassembler expiry" | PASS |
| (original) | "reassembler eviction on new key" | PASS |
| (original) | "reassembler buffer overflow" | PASS |

## Not Applicable (N/A) Tests

Tests from smoltcp that are intentionally not implemented in zmoltcp due to
language differences, API design choices, or out-of-scope features.

### time.zig (2 N/A)

| smoltcp Test | Reason |
|---|---|
| test_instant_display | Zig has no Display trait; getters cover the same data |
| test_duration_assign_ops | Zig has no operator overloading; explicit methods tested instead |

### storage/ring_buffer.zig (1 N/A)

| smoltcp Test | Reason |
|---|---|
| test_buffer_enqueue_dequeue_one_with | Merged into "enqueue and dequeue one" (Zig test covers both) |

### storage/assembler.zig (1 N/A)

| smoltcp Test | Reason |
|---|---|
| test_fuzz_* | Fuzz-only test; not a deterministic conformance test |

### socket/tcp.zig (~3 N/A)

| smoltcp Test | Reason |
|---|---|
| test_syn_paused_ack | pause_synack API not in zmoltcp |
| test_established_close_on_src_ip_change | No socket-level IP tracking |
| test_connect_unspecified_local / test_connect_specified_local | API design: zmoltcp always takes explicit 4 params |

### iface.zig (1 N/A)

| smoltcp Test | Reason |
|---|---|
| test_new_panic | Alloc-dependent behavior (zmoltcp is zero-alloc) |

### Out-of-scope protocol families

The following smoltcp modules are 802.15.4 link layers or split-file patterns
outside zmoltcp's scope:

| smoltcp Module | Reason |
|---|---|
| wire/sixlowpan.rs, wire/ieee802154.rs | 802.15.4 / 6LoWPAN link layer |
| wire/rpl.rs | RPL routing (6LoWPAN) |
| iface/interface/sixlowpan.rs | 6LoWPAN interface |
| socket/tcp/congestion/no_control.rs | Split files in smoltcp; unified in zmoltcp |
