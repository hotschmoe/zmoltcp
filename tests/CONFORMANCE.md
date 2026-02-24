# zmoltcp Conformance Tracking

Tracks zmoltcp tests against their smoltcp reference implementations.

## Summary

| Module | smoltcp Tests | zmoltcp Tests | N/A | Passing | Status |
|--------|--------------|---------------|-----|---------|--------|
| wire/checksum | 5 | 5 | 0 | 5 | PASS |
| wire/ethernet | 5 | 5 | 0 | 5 | PASS |
| wire/arp | 4 | 5 | 0 | 5 | PASS |
| wire/ipv4 | 15 | 15 | 0 | 15 | PASS |
| wire/tcp | 9 | 13 | 0 | 13 | PASS |
| wire/udp | 8 | 8 | 0 | 8 | PASS |
| wire/icmp | 5 | 5 | 0 | 5 | PASS |
| storage/ring_buffer | 15 | 14 | 1 | 14 | PASS |
| storage/assembler | 38 | 37 | 1 | 37 | PASS |
| time | 10 | 8 | 2 | 8 | PASS |
| socket/tcp | 186 | 183 | ~10 | 183 | PASS |
| socket/udp | 16 | 17 | 0 | 17 | PASS |
| wire/dhcp | 9 | 9 | 0 | 9 | PASS |
| socket/dhcp | 11 | 11 | 0 | 11 | PASS |
| wire/dns | 7 | 7 | 0 | 7 | PASS |
| socket/dns | 0 | 12 | 0 | 12 | PASS |
| socket/icmp | 6 | 7 | 0 | 7 | PASS |
| iface | ~25 | 15 | 9 | 15 | PASS |
| stack | 0 | 16 | 0 | 16 | PASS |

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
| test_listen_syn_ack | "listen rejects SYN with ACK" | PASS |
| test_listen_close | "listen close goes to closed" | PASS |
| test_listen_timeout | "listen never times out" | PASS |
| test_listen_sack_option | "listen sack option enabled" | PASS |
| test_listen_sack_option | "listen sack option disabled" | PASS |
| test_syn_received_ack | "SYN-RECEIVED receives ACK -> ESTABLISHED" | PASS |
| test_syn_received_close | "SYN-RECEIVED close -> FIN-WAIT-1" | PASS |
| test_syn_received_rst | "SYN-RECEIVED RST returns to LISTEN" | PASS |
| test_syn_received_bad_ack | "SYN-RECEIVED rejects ACK too high" | PASS |
| test_syn_received_bad_ack | "SYN-RECEIVED rejects ACK too low" | PASS |
| test_syn_received_fin | "SYN-RECEIVED recv FIN -> CLOSE-WAIT" | PASS |
| test_syn_received_no_window_scaling | "SYN-RECEIVED no window scaling" | PASS |
| test_syn_received_window_scaling | "SYN-RECEIVED window scaling" | PASS |
| test_syn_sent_sanity | "SYN-SENT sanity" | PASS |
| test_syn_sent_dispatch | "SYN-SENT dispatch emits SYN" | PASS |
| test_syn_sent_syn_ack | "SYN-SENT receives SYN\|ACK -> ESTABLISHED" | PASS |
| test_syn_sent_rst_ack | "SYN-SENT receives RST\|ACK -> CLOSED" | PASS |
| test_syn_sent_close | "SYN-SENT close goes to CLOSED" | PASS |
| test_syn_sent_rst_bad_ack | "SYN-SENT sends RST for bad ACK seq too high" | PASS |
| test_syn_sent_rst_bad_ack | "SYN-SENT sends RST for bad ACK seq too low" | PASS |
| test_syn_sent_rst_no_ack | "SYN-SENT ignores RST without ACK" | PASS |
| test_syn_sent_ignore_bare_ack | "SYN-SENT ignores bare ACK with correct seq" | PASS |
| test_syn_sent_syn | "SYN-SENT receives SYN (simultaneous open) -> SYN-RECEIVED" | PASS |
| test_syn_sent_simultaneous_rst | "SYN-SENT simultaneous open then RST" | PASS |
| test_syn_sent_sack_option | "SYN-SENT sack option" | PASS |
| test_syn_sent_syn_ack_window_scaling | "SYN-SENT syn ack window scaling" | PASS |
| test_syn_sent_syn_ack_not_incremented | "SYN-SENT rejects SYN\|ACK with un-incremented ACK" | PASS |
| test_connect_twice | "connect twice fails" | PASS |
| test_connect_validation | "connect validation" | PASS |
| test_established_recv | "ESTABLISHED recv data" | PASS |
| test_established_send | "ESTABLISHED send data" | PASS |
| test_established_send_recv | "ESTABLISHED send and receive" | PASS |
| test_established_recv_fin | "ESTABLISHED recv FIN -> CLOSE-WAIT" | PASS |
| test_established_recv_fin | "ESTABLISHED recv FIN with ACK" | PASS |
| test_established_close | "ESTABLISHED close sets FIN-WAIT-1 state" | PASS |
| test_established_abort | "ESTABLISHED abort sends RST" | PASS |
| test_established_rst | "ESTABLISHED recv RST -> CLOSED" | PASS |
| test_established_rst | "ESTABLISHED recv RST without ACK -> CLOSED" | PASS |
| test_established_recv_fin_data | "ESTABLISHED recv FIN while send data queued" | PASS |
| test_established_send_buf_gt_win | "ESTABLISHED send more data than window" | PASS |
| test_established_send_no_ack_send | "ESTABLISHED send two segments without ACK (nagle off)" | PASS |
| test_established_no_ack | "ESTABLISHED rejects packet without ACK and stays established" | PASS |
| test_established_bad_ack | "ESTABLISHED ignores ACK too low" | PASS |
| test_established_bad_seq | "ESTABLISHED bad seq gets challenge ACK" | PASS |
| test_established_bad_seq | "ESTABLISHED RST bad seq gets challenge ACK" | PASS |
| test_established_bad_seq | "ESTABLISHED FIN after missing segment stays established" | PASS |
| test_established_receive_partially_outside_window | "ESTABLISHED receive partially outside window" | PASS |
| test_established_receive_partially_outside_window_fin | "ESTABLISHED receive partially outside window with FIN" | PASS |
| test_established_send_wrap | "ESTABLISHED send wrap around seq boundary" | PASS |
| test_established_send_window_shrink | "ESTABLISHED send window shrink" | PASS |
| test_fin_wait_1_fin_ack | "FIN-WAIT-1 recv FIN+ACK -> TIME-WAIT" | PASS |
| test_fin_wait_1_ack | "FIN-WAIT-1 recv ACK of FIN -> FIN-WAIT-2" | PASS |
| test_fin_wait_1_fin_no_ack | "FIN-WAIT-1 recv FIN without ACK of our FIN -> CLOSING" | PASS |
| test_fin_wait_1_fin_fin | "FIN-WAIT-1 recv FIN without data and no ack of our FIN -> CLOSING" | PASS |
| test_fin_wait_1_close | "FIN-WAIT-1 close is noop" | PASS |
| test_fin_wait_1_recv | "FIN-WAIT-1 recv data" | PASS |
| test_fin_wait_1_fin_with_data_queued | "FIN-WAIT-1 with data queued waits for ack" | PASS |
| test_fin_wait_2_fin | "FIN-WAIT-2 recv FIN -> TIME-WAIT" | PASS |
| test_fin_wait_2_close | "FIN-WAIT-2 close is noop" | PASS |
| test_fin_wait_2_recv | "FIN-WAIT-2 recv data" | PASS |
| test_closing_ack | "CLOSING recv ACK -> TIME-WAIT" | PASS |
| test_closing_ack_fin | "CLOSING recv ACK of FIN -> TIME-WAIT via ack_fin" | PASS |
| test_closing_close | "CLOSING close is noop" | PASS |
| test_time_wait_from_fin_wait_2_ack | "TIME-WAIT from FIN-WAIT-2 dispatches ACK" | PASS |
| test_time_wait_from_closing_ack | "TIME-WAIT from CLOSING dispatches nothing" | PASS |
| test_time_wait_expire | "TIME-WAIT expires to CLOSED" | PASS |
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
| test_close_raced | "simultaneous close raced" | PASS |
| test_close_raced_with_data | "simultaneous close raced with data" | PASS |
| test_mutual_close_with_data_1 | "mutual close with data 1" | PASS |
| test_mutual_close_with_data_2 | "mutual close with data 2" | PASS |
| test_retransmit | "data retransmit on RTO" | PASS |
| test_retransmit | "retransmission after timeout" | PASS |
| test_data_retransmit_bursts | "data retransmit bursts" | PASS |
| test_data_retransmit_bursts_half_ack | "data retransmit bursts half ack" | PASS |
| test_retransmit_timer_restart_on_partial_ack | "retransmit timer restart on partial ack" | PASS |
| test_data_retransmit_bursts_half_ack_close | "data retransmit bursts half ack close" | PASS |
| test_retransmit_exponential_backoff | "retransmit exponential backoff" | PASS |
| test_retransmit_fin | "retransmit FIN" | PASS |
| test_retransmit_fin_wait | "retransmit in CLOSING state" | PASS |
| test_dup_ack_replace_timer | "dup ack does not replace retransmit timer" | PASS |
| test_dup_ack_reset_after_ack_windowed | "retransmit reset after ack windowed" | PASS |
| test_dup_ack_queue_during_retransmission | "queue during retransmission" | PASS |
| test_fast_retransmit | "fast retransmit after triple dup ack" | PASS |
| test_fast_retransmit_dup_acks_counter | "dup ack counter saturates" | PASS |
| test_fast_retransmit_dup_acks_reset | "dup ack counter reset on data" | PASS |
| test_fast_retransmit_dup_acks_reset | "dup ack counter reset on window update" | PASS |
| test_fast_retransmit_duplicate_detection | "fast retransmit duplicate detection with no data" | PASS |
| test_fast_retransmit_zero_window | "fast retransmit zero window" | PASS |
| test_retransmit_ack_more_than_expected | "retransmit ack more than expected" | PASS |
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
| test_delayed_ack_every_rmss | "delayed ack every rmss" | PASS |
| test_delayed_ack_every_rmss_or_more | "delayed ack every rmss or more" | PASS |
| test_nagle | "nagle algorithm" | PASS |
| test_nagle_fin | "FIN bypasses Nagle" | PASS |
| test_fill_peer_window | "fill peer window" | PASS |
| test_psh_on_recv | "PSH on receive is treated as normal data" | PASS |
| test_psh_on_send | "PSH set on last segment in burst" | PASS |
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
| test_closed_rejects_syn | "closed rejects SYN" | PASS |
| test_closed_rejects_after_listen_close | "closed rejects after listen+close" | PASS |
| test_close_on_closed | "close on closed is noop" | PASS |
| test_peek_slice | "peek slice" | PASS |
| test_peek_slice_buffer_wrap | "peek slice buffer wrap" | PASS |
| test_send_error | "send error when not established" | PASS |
| test_recv_error | "recv error when not established" | PASS |
| test_syn_sent_syn_received_ack | "SYN-SENT simultaneous open SYN then ACK -> ESTABLISHED" | PASS |
| test_fin_with_data_queued | "FIN with data queued" | PASS |
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
| iface/interface/tests/mod.rs:test_tcp_not_accepted | "TCP SYN with no listener produces RST" | PASS |

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
| (original) | "stack UDP egress dispatches datagram" | PASS |
| (original) | "stack ICMP egress dispatches echo request" | PASS |
| (original) | "stack poll returns true for egress-only activity" | PASS |
| (original) | "stack pollAt returns ZERO for pending TCP SYN-SENT" | PASS |
| (original) | "stack pollAt returns null for idle sockets" | PASS |
| (original) | "stack egress uses cached neighbor MAC" | PASS |
| (original) | "stack pollAt returns retransmit deadline after SYN dispatch" | PASS |

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

### socket/tcp.zig (~10 N/A)

| smoltcp Test | Reason |
|---|---|
| test_syn_paused_ack | pause_synack API not in zmoltcp |
| test_established_rfc2018_cases | SACK blocks not implemented |
| test_set_get_congestion_control | No congestion control abstraction |
| test_tsval_established_connection | TCP timestamps not implemented |
| test_tsval_disabled_in_remote_client | TCP timestamps not implemented |
| test_tsval_disabled_in_local_server | TCP timestamps not implemented |
| test_tsval_disabled_in_remote_server | TCP timestamps not implemented |
| test_tsval_disabled_in_local_client | TCP timestamps not implemented |
| test_established_close_on_src_ip_change | No socket-level IP tracking |
| test_connect_unspecified_local / test_connect_specified_local | API design: zmoltcp always takes explicit 4 params |

### iface.zig (9 N/A)

| smoltcp Test | Reason |
|---|---|
| test_new_panic | Alloc-dependent behavior (zmoltcp is zero-alloc) |
| test_handle_igmp | IGMP/multicast not implemented |
| test_packet_len | IPv4 fragmentation not implemented |
| test_ipv4_fragment_size | IPv4 fragmentation not implemented |
| test_raw_socket_no_accept | Raw sockets not implemented |
| test_raw_socket_with_udp | Raw sockets not implemented |
| test_raw_socket_recv | Raw sockets not implemented |
| test_raw_socket_send | Raw sockets not implemented |
| test_raw_socket_no_double | Raw sockets not implemented |
