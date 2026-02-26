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

var parse_buf: [1514]u8 = undefined;
var emit_buf: [1514]u8 = undefined;

export fn bench_scenario_e(input: [*]const u8, input_len: usize) u32 {
    const frame = input[0..input_len];
    var result: u32 = 0;

    // Parse Ethernet
    const eth_repr = ethernet.parse(frame) catch return 0;
    result +%= @intFromEnum(eth_repr.ethertype);

    // Parse IPv4
    const ip_payload = ethernet.payload(frame) catch return result;
    const ip_repr = ipv4.parse(ip_payload) catch return result;
    result +%= @as(u32, ip_repr.total_length);

    // Parse transport based on protocol
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

    // Emit Ethernet
    _ = ethernet.emit(.{
        .dst_addr = eth_repr.dst_addr,
        .src_addr = eth_repr.src_addr,
        .ethertype = eth_repr.ethertype,
    }, &emit_buf) catch return result;

    // Emit IPv4
    _ = ipv4.emit(ip_repr, emit_buf[ethernet.HEADER_LEN..]) catch return result;

    // Emit TCP
    const tcp_repr_out: tcp.Repr = .{
        .src_port = 1234,
        .dst_port = 80,
        .seq_number = 0x01020304,
        .ack_number = 0,
        .data_offset = 5,
        .flags = .{ .syn = true },
        .window_size = 65535,
        .checksum = 0,
        .urgent_pointer = 0,
    };
    const tcp_hdr_end = ethernet.HEADER_LEN + ipv4.HEADER_LEN;
    _ = tcp.emit(tcp_repr_out, emit_buf[tcp_hdr_end..]) catch return result;

    // Emit UDP
    const udp_repr_out: udp.Repr = .{
        .src_port = 5000,
        .dst_port = 53,
        .length = udp.HEADER_LEN,
        .checksum = 0,
    };
    _ = udp.emit(udp_repr_out, emit_buf[tcp_hdr_end..]) catch return result;

    // Parse IPv6 header (pull in v6 wire code)
    const ipv6_repr = ipv6.parse(ip_payload) catch return result;
    result +%= @as(u32, ipv6_repr.payload_len);

    return result;
}
