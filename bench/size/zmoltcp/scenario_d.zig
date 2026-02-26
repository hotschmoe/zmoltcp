// Scenario D: Dual-stack IPv4 + IPv6
//
// TCP + UDP + ICMP for both IPv4 and IPv6 over Ethernet.
// Measures the cost of enabling dual-stack support.

const zmoltcp = @import("zmoltcp");
const ipv4 = zmoltcp.wire.ipv4;
const ipv6 = zmoltcp.wire.ipv6;
const tcp_socket = zmoltcp.socket.tcp;
const udp_socket = zmoltcp.socket.udp;
const icmp_socket = zmoltcp.socket.icmp;
const BenchDevice = @import("device.zig").BenchDevice;

const Tcp4Sock = tcp_socket.Socket(ipv4, 4);
const Udp4Sock = udp_socket.Socket(ipv4);
const Icmp4Sock = icmp_socket.Socket(ipv4);
const Tcp6Sock = tcp_socket.Socket(ipv6, 4);
const Udp6Sock = udp_socket.Socket(ipv6);
const Icmp6Sock = icmp_socket.Socket(ipv6);

const Config = struct {
    tcp4_sockets: []*Tcp4Sock,
    udp4_sockets: []*Udp4Sock,
    icmp4_sockets: []*Icmp4Sock,
    tcp6_sockets: []*Tcp6Sock,
    udp6_sockets: []*Udp6Sock,
    icmp6_sockets: []*Icmp6Sock,
};
const BenchStack = zmoltcp.stack.Stack(BenchDevice, Config);

var tcp4_rx: [4096]u8 = undefined;
var tcp4_tx: [4096]u8 = undefined;
var tcp4_sock: Tcp4Sock = undefined;
var tcp4_arr: [1]*Tcp4Sock = undefined;

var udp4_rx_meta: [4]Udp4Sock.PacketMeta = undefined;
var udp4_rx_payload: [512]u8 = undefined;
var udp4_tx_meta: [4]Udp4Sock.PacketMeta = undefined;
var udp4_tx_payload: [512]u8 = undefined;
var udp4_sock: Udp4Sock = undefined;
var udp4_arr: [1]*Udp4Sock = undefined;

var icmp4_rx_meta: [4]Icmp4Sock.PacketMeta = undefined;
var icmp4_rx_payload: [512]u8 = undefined;
var icmp4_tx_meta: [4]Icmp4Sock.PacketMeta = undefined;
var icmp4_tx_payload: [512]u8 = undefined;
var icmp4_sock: Icmp4Sock = undefined;
var icmp4_arr: [1]*Icmp4Sock = undefined;

var tcp6_rx: [4096]u8 = undefined;
var tcp6_tx: [4096]u8 = undefined;
var tcp6_sock: Tcp6Sock = undefined;
var tcp6_arr: [1]*Tcp6Sock = undefined;

var udp6_rx_meta: [4]Udp6Sock.PacketMeta = undefined;
var udp6_rx_payload: [512]u8 = undefined;
var udp6_tx_meta: [4]Udp6Sock.PacketMeta = undefined;
var udp6_tx_payload: [512]u8 = undefined;
var udp6_sock: Udp6Sock = undefined;
var udp6_arr: [1]*Udp6Sock = undefined;

var icmp6_rx_meta: [4]Icmp6Sock.PacketMeta = undefined;
var icmp6_rx_payload: [512]u8 = undefined;
var icmp6_tx_meta: [4]Icmp6Sock.PacketMeta = undefined;
var icmp6_tx_payload: [512]u8 = undefined;
var icmp6_sock: Icmp6Sock = undefined;
var icmp6_arr: [1]*Icmp6Sock = undefined;

var device: BenchDevice = .{};
var stack_inst: BenchStack = undefined;

export fn bench_scenario_d() bool {
    tcp4_sock = Tcp4Sock.init(&tcp4_rx, &tcp4_tx);
    tcp4_arr = .{&tcp4_sock};
    udp4_sock = Udp4Sock.init(&udp4_rx_meta, &udp4_rx_payload, &udp4_tx_meta, &udp4_tx_payload);
    udp4_arr = .{&udp4_sock};
    icmp4_sock = Icmp4Sock.init(&icmp4_rx_meta, &icmp4_rx_payload, &icmp4_tx_meta, &icmp4_tx_payload);
    icmp4_arr = .{&icmp4_sock};

    tcp6_sock = Tcp6Sock.init(&tcp6_rx, &tcp6_tx);
    tcp6_arr = .{&tcp6_sock};
    udp6_sock = Udp6Sock.init(&udp6_rx_meta, &udp6_rx_payload, &udp6_tx_meta, &udp6_tx_payload);
    udp6_arr = .{&udp6_sock};
    icmp6_sock = Icmp6Sock.init(&icmp6_rx_meta, &icmp6_rx_payload, &icmp6_tx_meta, &icmp6_tx_payload);
    icmp6_arr = .{&icmp6_sock};

    stack_inst = BenchStack.init(
        .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
        .{
            .tcp4_sockets = &tcp4_arr,
            .udp4_sockets = &udp4_arr,
            .icmp4_sockets = &icmp4_arr,
            .tcp6_sockets = &tcp6_arr,
            .udp6_sockets = &udp6_arr,
            .icmp6_sockets = &icmp6_arr,
        },
    );
    return stack_inst.poll(zmoltcp.time.Instant.ZERO, &device);
}
