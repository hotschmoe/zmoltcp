# zmoltcp Conformance Tracking

Tracks zmoltcp tests against their smoltcp reference implementations.

## Summary

| Module | smoltcp Tests | zmoltcp Tests | Passing | Status |
|--------|--------------|---------------|---------|--------|
| wire/checksum | 5 | 5 | 5 | PASS |
| wire/ethernet | 5 | 5 | 5 | PASS |
| wire/arp | 4 | 5 | 5 | PASS |
| wire/ipv4 | 15 | 7 | 7 | PASS |
| wire/tcp | 9 | 13 | 13 | PASS |
| wire/udp | 8 | 4 | 4 | PASS |
| wire/icmp | 5 | 4 | 4 | PASS |
| storage/ring_buffer | 15 | 14 | 14 | PASS |
| storage/assembler | 38 | 37 | 37 | PASS |
| time | 10 | 8 | 8 | PASS |
| socket/tcp | 175 | 172 | 172 | PASS |
| socket/udp | 16 | 16 | 16 | PASS |
| socket/dhcp | ~12 | 0 | -- | TODO |
| socket/dns | ~10 | 0 | -- | TODO |
| socket/icmp | 6 | 6 | 6 | PASS |
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
| test_zero_window_probe_backoff | "zero window probe backs off" | PASS |
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

### socket/icmp.zig
| smoltcp Reference | zmoltcp Test | Status |
|---|---|---|
| socket/icmp.rs:test_send_unaddressable | "send rejects unaddressable destination" | PASS |
| socket/icmp.rs:test_send_dispatch | "send and dispatch outbound packet" | PASS |
| socket/icmp.rs:test_set_hop_limit_v4 | "hop limit propagates to dispatch" | PASS |
| socket/icmp.rs:test_recv_process | "process inbound and recv" | PASS |
| socket/icmp.rs:test_accept_bad_id | "rejects packet with wrong identifier" | PASS |
| socket/icmp.rs:test_accepts_udp | "accepts ICMP error for bound UDP port" | PASS |
