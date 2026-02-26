// Scenario E: Wire-only (parse/emit, no sockets)
//
// Direct calls to wire format parse and emit functions.
// No Stack instantiation. Measures the cost of the wire layer alone.

const zmoltcp = @import("zmoltcp");
const ethernet = zmoltcp.wire.ethernet;
const ipv4 = zmoltcp.wire.ipv4;
const ipv6 = zmoltcp.wire.ipv6;
const tcp = zmoltcp.wire.tcp;
const udp = zmoltcp.wire.udp;

var emit_buf: [1514]u8 = undefined;

export fn bench_scenario_e(input: [*]const u8, input_len: usize) u32 {
    const frame = input[0..input_len];
    var result: u32 = 0;

    const eth_repr = ethernet.parse(frame) catch return 0;
    result +%= @intFromEnum(eth_repr.ethertype);

    const ip_payload = ethernet.payload(frame) catch return result;
    const ip_repr = ipv4.parse(ip_payload) catch return result;
    result +%= @as(u32, ip_repr.total_length);

    const transport = ipv4.payloadSlice(ip_payload) catch return result;
    switch (ip_repr.protocol) {
        .tcp => {
            const tcp_repr = tcp.parse(transport) catch return result;
            result +%= @as(u32, tcp_repr.src_port) +% @as(u32, tcp_repr.dst_port);
        },
        .udp => {
            const udp_repr = udp.parse(transport) catch return result;
            result +%= @as(u32, udp_repr.src_port) +% @as(u32, udp_repr.dst_port);
        },
        else => {},
    }

    _ = ethernet.emit(eth_repr, &emit_buf) catch return result;
    _ = ipv4.emit(ip_repr, emit_buf[ethernet.HEADER_LEN..]) catch return result;

    const tcp_hdr_end = ethernet.HEADER_LEN + ipv4.HEADER_LEN;

    _ = tcp.emit(.{
        .src_port = 1234,
        .dst_port = 80,
        .seq_number = 0x01020304,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .syn = true },
        .window_size = 65535,
        .checksum = 0,
        .urgent_pointer = 0,
    }, emit_buf[tcp_hdr_end..]) catch return result;

    _ = udp.emit(.{
        .src_port = 5000,
        .dst_port = 53,
        .length = udp.HEADER_LEN,
        .checksum = 0,
    }, emit_buf[tcp_hdr_end..]) catch return result;

    const ipv6_repr = ipv6.parse(ip_payload) catch return result;
    result +%= @as(u32, ipv6_repr.payload_len);

    return result;
}
