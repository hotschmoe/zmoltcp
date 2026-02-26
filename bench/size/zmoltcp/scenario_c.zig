// Scenario C: Full IPv4 (all socket types)
//
// TCP + UDP + ICMP + DHCP + DNS + Raw over Ethernet.
// Measures the full IPv4 feature set.

const zmoltcp = @import("zmoltcp");
const ipv4 = zmoltcp.wire.ipv4;
const tcp_socket = zmoltcp.socket.tcp;
const udp_socket = zmoltcp.socket.udp;
const icmp_socket = zmoltcp.socket.icmp;
const dhcp_socket = zmoltcp.socket.dhcp;
const dns_socket = zmoltcp.socket.dns;
const raw_socket = zmoltcp.socket.raw;
const BenchDevice = @import("device.zig").BenchDevice;

const TcpSock = tcp_socket.Socket(ipv4, 4);
const UdpSock = udp_socket.Socket(ipv4);
const IcmpSock = icmp_socket.Socket(ipv4);
const DhcpSock = dhcp_socket.Socket;
const DnsSock = dns_socket.Socket(ipv4);
const RawSock = raw_socket.Socket(ipv4, .{ .payload_size = 512 });

const Config = struct {
    tcp4_sockets: []*TcpSock,
    udp4_sockets: []*UdpSock,
    icmp4_sockets: []*IcmpSock,
    dhcp_sockets: []*DhcpSock,
    dns4_sockets: []*DnsSock,
    raw4_sockets: []*RawSock,
};
const BenchStack = zmoltcp.stack.Stack(BenchDevice, Config);

var tcp_rx: [4096]u8 = undefined;
var tcp_tx: [4096]u8 = undefined;
var tcp_sock: TcpSock = undefined;
var tcp_arr: [1]*TcpSock = undefined;

var udp_rx_meta: [4]UdpSock.PacketMeta = undefined;
var udp_rx_payload: [512]u8 = undefined;
var udp_tx_meta: [4]UdpSock.PacketMeta = undefined;
var udp_tx_payload: [512]u8 = undefined;
var udp_sock: UdpSock = undefined;
var udp_arr: [1]*UdpSock = undefined;

var icmp_rx_meta: [4]IcmpSock.PacketMeta = undefined;
var icmp_rx_payload: [512]u8 = undefined;
var icmp_tx_meta: [4]IcmpSock.PacketMeta = undefined;
var icmp_tx_payload: [512]u8 = undefined;
var icmp_sock: IcmpSock = undefined;
var icmp_arr: [1]*IcmpSock = undefined;

var dhcp_sock: DhcpSock = undefined;
var dhcp_arr: [1]*DhcpSock = undefined;

var dns_queries: [1]DnsSock.QuerySlot = undefined;
var dns_servers: [1]ipv4.Address = .{.{ 8, 8, 8, 8 }};
var dns_sock: DnsSock = undefined;
var dns_arr: [1]*DnsSock = undefined;

var raw_rx: [4]RawSock.Packet = undefined;
var raw_tx: [4]RawSock.Packet = undefined;
var raw_sock: RawSock = undefined;
var raw_arr: [1]*RawSock = undefined;

var device: BenchDevice = .{};
var stack_inst: BenchStack = undefined;

export fn bench_scenario_c() bool {
    tcp_sock = TcpSock.init(&tcp_rx, &tcp_tx);
    tcp_arr = .{&tcp_sock};

    udp_sock = UdpSock.init(&udp_rx_meta, &udp_rx_payload, &udp_tx_meta, &udp_tx_payload);
    udp_arr = .{&udp_sock};

    icmp_sock = IcmpSock.init(&icmp_rx_meta, &icmp_rx_payload, &icmp_tx_meta, &icmp_tx_payload);
    icmp_arr = .{&icmp_sock};

    dhcp_sock = DhcpSock.init(.{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 });
    dhcp_arr = .{&dhcp_sock};

    dns_sock = DnsSock.init(&dns_queries, &dns_servers);
    dns_arr = .{&dns_sock};

    raw_sock = RawSock.init(&raw_rx, &raw_tx);
    raw_arr = .{&raw_sock};

    stack_inst = BenchStack.init(
        .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .{
            .tcp4_sockets = &tcp_arr,
            .udp4_sockets = &udp_arr,
            .icmp4_sockets = &icmp_arr,
            .dhcp_sockets = &dhcp_arr,
            .dns4_sockets = &dns_arr,
            .raw4_sockets = &raw_arr,
        },
    );
    return stack_inst.poll(zmoltcp.time.Instant.ZERO, &device);
}
