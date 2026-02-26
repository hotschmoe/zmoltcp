// Scenario A: Minimal TCP/IPv4
//
// Single TCP socket over Ethernet. Measures the baseline cost of the
// zmoltcp stack with one protocol enabled.

const zmoltcp = @import("zmoltcp");
const ipv4 = zmoltcp.wire.ipv4;
const tcp_socket = zmoltcp.socket.tcp;
const BenchDevice = @import("device.zig").BenchDevice;

const TcpSock = tcp_socket.Socket(ipv4, 4);
const Config = struct { tcp4_sockets: []*TcpSock };
const BenchStack = zmoltcp.stack.Stack(BenchDevice, Config);

var rx_buf: [4096]u8 = undefined;
var tx_buf: [4096]u8 = undefined;
var sock: TcpSock = undefined;
var sock_arr: [1]*TcpSock = undefined;
var device: BenchDevice = .{};
var stack_inst: BenchStack = undefined;

export fn bench_scenario_a() bool {
    sock = TcpSock.init(&rx_buf, &tx_buf);
    sock_arr = .{&sock};
    stack_inst = BenchStack.init(.{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 }, .{ .tcp4_sockets = &sock_arr });
    return stack_inst.poll(zmoltcp.time.Instant.ZERO, &device);
}
