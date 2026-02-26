// Scenario B: TCP + UDP + ICMP / IPv4
//
// Three socket types over Ethernet. Measures incremental cost of adding
// UDP and ICMP on top of TCP.

const zmoltcp = @import("zmoltcp");
const ipv4 = zmoltcp.wire.ipv4;
const tcp_socket = zmoltcp.socket.tcp;
const udp_socket = zmoltcp.socket.udp;
const icmp_socket = zmoltcp.socket.icmp;
const BenchDevice = @import("device.zig").BenchDevice;

const TcpSock = tcp_socket.Socket(ipv4, 4);
const UdpSock = udp_socket.Socket(ipv4);
const IcmpSock = icmp_socket.Socket(ipv4);

const Config = struct {
    tcp4_sockets: []*TcpSock,
    udp4_sockets: []*UdpSock,
    icmp4_sockets: []*IcmpSock,
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

var device: BenchDevice = .{};
var stack_inst: BenchStack = undefined;

export fn bench_scenario_b() bool {
    tcp_sock = TcpSock.init(&tcp_rx, &tcp_tx);
    tcp_arr = .{&tcp_sock};

    udp_sock = UdpSock.init(&udp_rx_meta, &udp_rx_payload, &udp_tx_meta, &udp_tx_payload);
    udp_arr = .{&udp_sock};

    icmp_sock = IcmpSock.init(&icmp_rx_meta, &icmp_rx_payload, &icmp_tx_meta, &icmp_tx_payload);
    icmp_arr = .{&icmp_sock};

    stack_inst = BenchStack.init(
        .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .{ .tcp4_sockets = &tcp_arr, .udp4_sockets = &udp_arr, .icmp4_sockets = &icmp_arr },
    );
    return stack_inst.poll(zmoltcp.time.Instant.ZERO, &device);
}
