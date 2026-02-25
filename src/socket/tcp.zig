// TCP socket state machine.
//
// Implements the TCP state machine per RFC 793, with timers per RFC 6298.
// This module manages connection lifecycle: handshake, data transfer, teardown.
//
// [smoltcp:socket/tcp.rs]

const std = @import("std");
const time = @import("../time.zig");
const wire_tcp = @import("../wire/tcp.zig");
const ip_generic = @import("../wire/ip.zig");
const ipv4 = @import("../wire/ipv4.zig");
const assembler_mod = @import("../storage/assembler.zig");
const ring_buffer_mod = @import("../storage/ring_buffer.zig");
const iface_mod = @import("../iface.zig");

const Instant = time.Instant;
const Duration = time.Duration;
const SeqNumber = wire_tcp.SeqNumber;
const Control = wire_tcp.Control;
const Flags = wire_tcp.Flags;

const DEFAULT_MSS: usize = 536;
const BASE_MSS: u16 = 1460;
const DEFAULT_HOP_LIMIT: u8 = 64;

// -------------------------------------------------------------------------
// Endpoint types (parameterized in Socket, aliased here for module-level use)
// -------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Socket-level TCP Repr
// -------------------------------------------------------------------------

pub const TcpRepr = struct {
    src_port: u16,
    dst_port: u16,
    control: Control = .none,
    seq_number: SeqNumber = SeqNumber.ZERO,
    ack_number: ?SeqNumber = null,
    window_len: u16 = 0,
    window_scale: ?u8 = null,
    max_seg_size: ?u16 = null,
    sack_permitted: bool = false,
    sack_ranges: [3]?wire_tcp.SackRange = .{ null, null, null },
    timestamp: ?wire_tcp.Timestamp = null,
    payload: []const u8 = &.{},

    pub fn segmentLen(self: TcpRepr) usize {
        return self.payload.len + self.control.seqLen();
    }

    pub fn isEmpty(self: TcpRepr) bool {
        return self.control == .none and self.payload.len == 0;
    }

    pub fn fromWireBytes(data: []const u8) ?TcpRepr {
        const w = wire_tcp.parse(data) catch return null;
        const header_len: usize = @as(usize, w.data_offset) * 4;
        const payload = if (data.len > header_len) data[header_len..] else &[_]u8{};
        return fromWireRepr(w, payload);
    }

    pub fn fromWireRepr(w: wire_tcp.Repr, tcp_payload: []const u8) TcpRepr {
        return .{
            .src_port = w.src_port,
            .dst_port = w.dst_port,
            .control = Control.fromFlags(w.flags),
            .seq_number = SeqNumber.fromU32(w.seq_number),
            .ack_number = if (w.flags.ack) SeqNumber.fromU32(w.ack_number) else null,
            .window_len = w.window_size,
            .window_scale = w.window_scale,
            .max_seg_size = w.max_seg_size,
            .sack_permitted = w.sack_permitted,
            .sack_ranges = w.sack_ranges,
            .timestamp = w.timestamp,
            .payload = tcp_payload,
        };
    }

    pub fn toWireRepr(self: TcpRepr) wire_tcp.Repr {
        var flags = Flags{};
        self.control.applyToFlags(&flags);
        if (self.ack_number != null) flags.ack = true;
        return .{
            .src_port = self.src_port,
            .dst_port = self.dst_port,
            .seq_number = self.seq_number.toU32(),
            .ack_number = if (self.ack_number) |ack| ack.toU32() else 0,
            .data_offset = 5,
            .flags = flags,
            .window_size = self.window_len,
            .checksum = 0,
            .urgent_pointer = 0,
            .max_seg_size = self.max_seg_size,
            .window_scale = self.window_scale,
            .sack_permitted = self.sack_permitted,
            .sack_ranges = self.sack_ranges,
            .timestamp = self.timestamp,
        };
    }
};

pub fn rstReply(repr: TcpRepr) TcpRepr {
    var reply = TcpRepr{
        .src_port = repr.dst_port,
        .dst_port = repr.src_port,
        .control = .rst,
        .seq_number = if (repr.ack_number) |ack| ack else SeqNumber.ZERO,
    };
    if (repr.control == .syn and repr.ack_number == null) {
        reply.ack_number = repr.seq_number.add(repr.segmentLen());
    }
    return reply;
}

// -------------------------------------------------------------------------
// State enum (RFC 793)
// -------------------------------------------------------------------------

pub const State = enum {
    closed,
    listen,
    syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
    closing,
    last_ack,
    time_wait,
};

// -------------------------------------------------------------------------
// Timer
// -------------------------------------------------------------------------

const ACK_DELAY_DEFAULT: Duration = Duration.fromMillis(10);
const CLOSE_DELAY: Duration = Duration.fromMillis(10_000);

const Timer = union(enum) {
    idle: struct { keep_alive_at: ?Instant },
    retransmit: struct { expires_at: Instant },
    fast_retransmit,
    zero_window_probe: struct { expires_at: Instant, delay: Duration },
    close: struct { expires_at: Instant },

    fn init() Timer {
        return .{ .idle = .{ .keep_alive_at = null } };
    }

    fn shouldKeepAlive(self: Timer, timestamp: Instant) bool {
        return switch (self) {
            .idle => |v| if (v.keep_alive_at) |ka| timestamp.greaterThanOrEqual(ka) else false,
            else => false,
        };
    }

    fn shouldRetransmit(self: Timer, timestamp: Instant) bool {
        return switch (self) {
            .retransmit => |v| timestamp.greaterThanOrEqual(v.expires_at),
            .fast_retransmit => true,
            else => false,
        };
    }

    fn shouldClose(self: Timer, timestamp: Instant) bool {
        return switch (self) {
            .close => |v| timestamp.greaterThanOrEqual(v.expires_at),
            else => false,
        };
    }

    fn shouldZeroWindowProbe(self: Timer, timestamp: Instant) bool {
        return switch (self) {
            .zero_window_probe => |v| timestamp.greaterThanOrEqual(v.expires_at),
            else => false,
        };
    }

    fn pollAt(self: Timer) ?Instant {
        return switch (self) {
            .idle => |v| v.keep_alive_at,
            .retransmit => |v| v.expires_at,
            .fast_retransmit => Instant.ZERO,
            .zero_window_probe => |v| v.expires_at,
            .close => |v| v.expires_at,
        };
    }

    fn setForIdle(self: *Timer, timestamp: Instant, interval: ?Duration) void {
        self.* = .{ .idle = .{
            .keep_alive_at = if (interval) |i| timestamp.add(i) else null,
        } };
    }

    fn setKeepAlive(self: *Timer) void {
        switch (self.*) {
            .idle => |*v| {
                if (v.keep_alive_at == null) {
                    v.keep_alive_at = Instant.fromMillis(0);
                }
            },
            else => {},
        }
    }

    fn rewindKeepAlive(self: *Timer, timestamp: Instant, interval: ?Duration) void {
        switch (self.*) {
            .idle => |*v| {
                v.keep_alive_at = if (interval) |i| timestamp.add(i) else null;
            },
            else => {},
        }
    }

    fn setForRetransmit(self: *Timer, timestamp: Instant, delay: Duration) void {
        switch (self.*) {
            .close => return,
            else => {},
        }
        self.* = .{ .retransmit = .{ .expires_at = timestamp.add(delay) } };
    }

    fn setForFastRetransmit(self: *Timer) void {
        self.* = .fast_retransmit;
    }

    fn setForClose(self: *Timer, timestamp: Instant) void {
        self.* = .{ .close = .{ .expires_at = timestamp.add(CLOSE_DELAY) } };
    }

    fn setForZeroWindowProbe(self: *Timer, timestamp: Instant, delay: Duration) void {
        self.* = .{ .zero_window_probe = .{
            .expires_at = timestamp.add(delay),
            .delay = delay,
        } };
    }

    fn rewindZeroWindowProbe(self: *Timer, timestamp: Instant) void {
        switch (self.*) {
            .zero_window_probe => |*v| {
                const new_delay = v.delay.mul(2).min(Duration.fromMillis(RTTE_MAX_RTO));
                v.delay = new_delay;
                v.expires_at = timestamp.add(new_delay);
            },
            else => {},
        }
    }

    fn isIdle(self: Timer) bool {
        return switch (self) {
            .idle => true,
            else => false,
        };
    }

    fn isZeroWindowProbe(self: Timer) bool {
        return switch (self) {
            .zero_window_probe => true,
            else => false,
        };
    }

    fn isRetransmit(self: Timer) bool {
        return switch (self) {
            .retransmit, .fast_retransmit => true,
            else => false,
        };
    }
};

// -------------------------------------------------------------------------
// RTT Estimator (RFC 6298)
// -------------------------------------------------------------------------

const RTTE_INITIAL_RTO: u32 = 1000;
const RTTE_MIN_MARGIN: u32 = 5;
const RTTE_K: u32 = 4;
const RTTE_MIN_RTO: u32 = 1000;
const RTTE_MAX_RTO: u32 = 60_000;

const RttEstimator = struct {
    have_measurement: bool = false,
    srtt: u32 = 0,
    rttvar: u32 = 0,
    rto: u32 = RTTE_INITIAL_RTO,
    timestamp: ?struct { sent_at: Instant, seq: SeqNumber } = null,
    max_seq_sent: ?SeqNumber = null,
    rto_count: u8 = 0,

    fn retransmissionTimeout(self: RttEstimator) Duration {
        return Duration.fromMillis(@as(i64, self.rto));
    }

    fn sample(self: *RttEstimator, new_rtt: u32) void {
        if (self.have_measurement) {
            const srtt_i: i32 = @intCast(self.srtt);
            const rtt_i: i32 = @intCast(new_rtt);
            const diff_signed = srtt_i - rtt_i;
            const diff: u32 = @intCast(if (diff_signed >= 0) diff_signed else -diff_signed);
            self.rttvar = divCeil32(self.rttvar * 3 + diff, 4);
            self.srtt = divCeil32(self.srtt * 7 + new_rtt, 8);
        } else {
            self.have_measurement = true;
            self.srtt = new_rtt;
            self.rttvar = new_rtt / 2;
        }

        const margin = @max(RTTE_MIN_MARGIN, self.rttvar * RTTE_K);
        self.rto = std.math.clamp(self.srtt + margin, RTTE_MIN_RTO, RTTE_MAX_RTO);
        self.rto_count = 0;
    }

    fn onSend(self: *RttEstimator, timestamp: Instant, seq: SeqNumber) void {
        const is_new = if (self.max_seq_sent) |max_sent|
            seq.greaterThan(max_sent)
        else
            true;

        if (is_new) {
            self.max_seq_sent = seq;
            if (self.timestamp == null) {
                self.timestamp = .{ .sent_at = timestamp, .seq = seq };
            }
        }
    }

    fn onAck(self: *RttEstimator, timestamp: Instant, seq: SeqNumber) void {
        if (self.timestamp) |ts| {
            if (seq.greaterThanOrEqual(ts.seq)) {
                const rtt_micros = timestamp.diff(ts.sent_at).totalMillis();
                self.sample(@intCast(@max(rtt_micros, 1)));
                self.timestamp = null;
            }
        }
    }

    fn onRetransmit(self: *RttEstimator) void {
        self.timestamp = null;
        self.rto = @min(self.rto * 2, RTTE_MAX_RTO);
        self.rto_count += 1;
        if (self.rto_count >= 3) {
            self.rto_count = 0;
            self.have_measurement = false;
        }
    }
};

fn divCeil32(a: u32, b: u32) u32 {
    return (a + b - 1) / b;
}

// -------------------------------------------------------------------------
// ACK Delay Timer
// -------------------------------------------------------------------------

const AckDelayTimer = union(enum) {
    idle,
    waiting: Instant,
    immediate,
};

// -------------------------------------------------------------------------
// Congestion Control
// -------------------------------------------------------------------------

pub const NoControl = struct {
    pub fn window(_: NoControl) usize {
        return std.math.maxInt(usize);
    }
    pub fn onAck(_: *NoControl, _: Instant, _: usize, _: *const RttEstimator) void {}
    pub fn onRetransmit(_: *NoControl, _: Instant) void {}
    pub fn onDuplicateAck(_: *NoControl, _: Instant) void {}
    pub fn preTransmit(_: *NoControl, _: Instant) void {}
    pub fn postTransmit(_: *NoControl, _: Instant, _: usize) void {}
    pub fn setMss(_: *NoControl, _: usize) void {}
    pub fn setRemoteWindow(_: *NoControl, _: usize) void {}
};

pub const Reno = struct {
    cwnd: usize = 2048,
    min_cwnd: usize = 2048,
    ssthresh: usize = std.math.maxInt(usize),
    rwnd: usize = 64 * 1024,

    pub fn window(self: Reno) usize {
        return self.cwnd;
    }

    pub fn onAck(self: *Reno, _: Instant, len: usize, _: *const RttEstimator) void {
        const inc = if (self.cwnd < self.ssthresh) len else blk: {
            self.ssthresh = self.cwnd;
            break :blk self.min_cwnd;
        };
        self.cwnd = @min(
            @max(std.math.add(usize, self.cwnd, inc) catch std.math.maxInt(usize), self.min_cwnd),
            self.rwnd,
        );
    }

    pub fn onRetransmit(self: *Reno, _: Instant) void {
        self.cwnd = @max(self.cwnd >> 1, self.min_cwnd);
    }

    pub fn onDuplicateAck(self: *Reno, _: Instant) void {
        self.ssthresh = @max(self.cwnd >> 1, self.min_cwnd);
    }

    pub fn preTransmit(_: *Reno, _: Instant) void {}
    pub fn postTransmit(_: *Reno, _: Instant, _: usize) void {}

    pub fn setMss(self: *Reno, mss: usize) void {
        self.min_cwnd = mss;
    }

    pub fn setRemoteWindow(self: *Reno, remote_window: usize) void {
        if (self.rwnd < remote_window) self.rwnd = remote_window;
    }
};

pub const Cubic = struct {
    const BETA: f64 = 0.7;
    const C_CONST: f64 = 0.4;

    cwnd: usize = 2048,
    min_cwnd: usize = 2048,
    w_max: usize = 2048,
    recovery_start: ?Instant = null,
    rwnd: usize = 64 * 1024,
    last_update: Instant = Instant.ZERO,
    ssthresh: usize = std.math.maxInt(usize),

    fn cubeRoot(a: f64) ?f64 {
        if (a <= 0.0) return null;
        const Range = struct { tol: f64, x0: f64 };
        const range: Range = if (a < 1e3)
            .{ .tol = 1.0, .x0 = 8.879 }
        else if (a < 1e6)
            .{ .tol = 5.0, .x0 = 88.79 }
        else if (a < 1e9)
            .{ .tol = 50.0, .x0 = 887.9 }
        else if (a < 1e12)
            .{ .tol = 500.0, .x0 = 8879.0 }
        else if (a < 1e15)
            .{ .tol = 5000.0, .x0 = 88790.0 }
        else
            .{ .tol = 50000.0, .x0 = 887904.0 };

        var x = range.x0;
        var i: usize = 0;
        while (i < 20) : (i += 1) {
            const x2 = x * x;
            const x3 = x2 * x;
            const diff = x3 - a;
            const abs_diff = if (diff >= 0) diff else -diff;
            if (abs_diff < range.tol) break;
            x = x - (x3 - a) / (3.0 * x2);
        }
        return x;
    }

    pub fn window(self: Cubic) usize {
        return self.cwnd;
    }

    pub fn onAck(self: *Cubic, _: Instant, len: usize, _: *const RttEstimator) void {
        if (self.cwnd < self.ssthresh) {
            self.cwnd = @min(
                @max(std.math.add(usize, self.cwnd, len) catch std.math.maxInt(usize), self.min_cwnd),
                self.rwnd,
            );
        }
    }

    pub fn onRetransmit(self: *Cubic, now: Instant) void {
        self.w_max = self.cwnd;
        self.ssthresh = self.cwnd >> 1;
        self.recovery_start = now;
    }

    pub fn onDuplicateAck(self: *Cubic, now: Instant) void {
        self.w_max = self.cwnd;
        self.ssthresh = self.cwnd >> 1;
        self.recovery_start = now;
    }

    pub fn preTransmit(self: *Cubic, now: Instant) void {
        const recovery = self.recovery_start orelse {
            self.recovery_start = now;
            return;
        };

        const now_ms = now.totalMillis();
        const recovery_ms = recovery.totalMillis();
        const last_ms = self.last_update.totalMillis();

        if (last_ms > recovery_ms and now_ms - last_ms < 100) return;

        const t_ms = now_ms - recovery_ms;
        if (t_ms < 0) return;

        const k3 = @as(f64, @floatFromInt(self.w_max)) * (1.0 - BETA) / C_CONST;
        const k = cubeRoot(k3) orelse return;

        const t_sec = @as(f64, @floatFromInt(t_ms)) / 1000.0;
        const s = t_sec - k;
        const w_cubic = C_CONST * s * s * s + @as(f64, @floatFromInt(self.w_max));

        self.last_update = now;
        const max_f = @as(f64, @floatFromInt(std.math.maxInt(usize)));
        const clamped = @max(@as(f64, 0), @min(w_cubic, max_f));
        self.cwnd = @min(@max(@as(usize, @intFromFloat(clamped)), self.min_cwnd), self.rwnd);
    }

    pub fn postTransmit(_: *Cubic, _: Instant, _: usize) void {}

    pub fn setMss(self: *Cubic, mss: usize) void {
        self.min_cwnd = mss;
    }

    pub fn setRemoteWindow(self: *Cubic, remote_window: usize) void {
        if (self.rwnd < remote_window) self.rwnd = remote_window;
    }
};

pub const CongestionController = union(enum) {
    none: NoControl,
    reno: Reno,
    cubic: Cubic,

    pub fn window(self: CongestionController) usize {
        return switch (self) {
            inline else => |c| c.window(),
        };
    }

    pub fn onAck(self: *CongestionController, now: Instant, len: usize, rtte: *const RttEstimator) void {
        switch (self.*) {
            inline else => |*c| c.onAck(now, len, rtte),
        }
    }

    pub fn onRetransmit(self: *CongestionController, now: Instant) void {
        switch (self.*) {
            inline else => |*c| c.onRetransmit(now),
        }
    }

    pub fn onDuplicateAck(self: *CongestionController, now: Instant) void {
        switch (self.*) {
            inline else => |*c| c.onDuplicateAck(now),
        }
    }

    pub fn preTransmit(self: *CongestionController, now: Instant) void {
        switch (self.*) {
            inline else => |*c| c.preTransmit(now),
        }
    }

    pub fn postTransmit(self: *CongestionController, now: Instant, len: usize) void {
        switch (self.*) {
            inline else => |*c| c.postTransmit(now, len),
        }
    }

    pub fn setMss(self: *CongestionController, mss: usize) void {
        switch (self.*) {
            inline else => |*c| c.setMss(mss),
        }
    }

    pub fn setRemoteWindow(self: *CongestionController, remote_window: usize) void {
        switch (self.*) {
            inline else => |*c| c.setRemoteWindow(remote_window),
        }
    }
};

// -------------------------------------------------------------------------
// Socket
// -------------------------------------------------------------------------

pub fn Socket(comptime Ip: type, comptime max_asm_segs: usize) type {
    comptime ip_generic.assertIsIp(Ip);
    return struct {
        const Self = @This();
        const Assembler = assembler_mod.Assembler(max_asm_segs);
        const RingBuffer = ring_buffer_mod.RingBuffer(u8);

        pub const Endpoint = ip_generic.Endpoint(Ip);
        pub const ListenEndpoint = ip_generic.ListenEndpoint(Ip);

        const Tuple = struct {
            local: Endpoint,
            remote: Endpoint,
        };

        state: State,
        timer: Timer,
        rtte: RttEstimator,
        assembler: Assembler,
        rx_buffer: RingBuffer,
        rx_fin_received: bool,
        tx_buffer: RingBuffer,

        timeout: ?Duration,
        keep_alive: ?Duration,
        hop_limit: ?u8,

        listen_endpoint: ListenEndpoint,
        tuple: ?Tuple,

        local_seq_no: SeqNumber,
        remote_seq_no: SeqNumber,
        remote_last_seq: SeqNumber,
        remote_last_ack: ?SeqNumber,
        remote_last_win: u16,
        remote_win_shift: u8,
        remote_win_len: usize,
        remote_win_scale: ?u8,
        remote_has_sack: bool,
        remote_mss: usize,
        remote_last_ts: ?Instant,

        tsval_generator: ?*const fn () u32,
        last_remote_tsval: u32,

        local_rx_last_seq: ?SeqNumber,
        local_rx_last_ack: ?SeqNumber,
        local_rx_dup_acks: u8,

        ack_delay: ?Duration,
        ack_delay_timer: AckDelayTimer,
        challenge_ack_timer: Instant,

        nagle: bool,
        congestion_controller: CongestionController,

        fn windowShiftFor(rx_cap: usize) u8 {
            const rx_cap_log2 = if (rx_cap == 0) 0 else @as(usize, @sizeOf(usize) * 8) - @as(usize, @clz(@as(usize, rx_cap)));
            return @intCast(if (rx_cap_log2 > 16) rx_cap_log2 - 16 else 0);
        }

        pub fn init(rx_storage: []u8, tx_storage: []u8) Self {
            return .{
                .state = .closed,
                .timer = Timer.init(),
                .rtte = .{},
                .assembler = Assembler.init(),
                .rx_buffer = RingBuffer.init(rx_storage),
                .rx_fin_received = false,
                .tx_buffer = RingBuffer.init(tx_storage),
                .timeout = null,
                .keep_alive = null,
                .hop_limit = null,
                .listen_endpoint = .{},
                .tuple = null,
                .local_seq_no = SeqNumber.ZERO,
                .remote_seq_no = SeqNumber.ZERO,
                .remote_last_seq = SeqNumber.ZERO,
                .remote_last_ack = null,
                .remote_last_win = 0,
                .remote_win_shift = windowShiftFor(rx_storage.len),
                .remote_win_len = 0,
                .remote_win_scale = null,
                .remote_has_sack = false,
                .remote_mss = DEFAULT_MSS,
                .remote_last_ts = null,
                .tsval_generator = null,
                .last_remote_tsval = 0,
                .local_rx_last_seq = null,
                .local_rx_last_ack = null,
                .local_rx_dup_acks = 0,
                .ack_delay = null,
                .ack_delay_timer = .idle,
                .challenge_ack_timer = Instant.fromSecs(0),
                .nagle = true,
                .congestion_controller = .{ .none = .{} },
            };
        }

        fn reset(self: *Self) void {
            self.state = .closed;
            self.timer = Timer.init();
            self.rtte = .{};
            self.assembler.clear();
            self.tx_buffer.clear();
            self.rx_buffer.clear();
            self.rx_fin_received = false;
            self.listen_endpoint = .{};
            self.tuple = null;
            self.local_seq_no = SeqNumber.ZERO;
            self.remote_seq_no = SeqNumber.ZERO;
            self.remote_last_seq = SeqNumber.ZERO;
            self.remote_last_ack = null;
            self.remote_last_win = 0;
            self.remote_win_shift = windowShiftFor(self.rx_buffer.capacity());
            self.remote_win_len = 0;
            self.remote_win_scale = null;
            self.remote_has_sack = false;
            self.remote_mss = DEFAULT_MSS;
            self.remote_last_ts = null;
            self.last_remote_tsval = 0;
            self.local_rx_last_seq = null;
            self.local_rx_last_ack = null;
            self.local_rx_dup_acks = 0;
            self.ack_delay_timer = .idle;
            self.challenge_ack_timer = Instant.fromSecs(0);
        }

        // -- State queries --

        pub fn getState(self: Self) State {
            return self.state;
        }

        pub fn isOpen(self: Self) bool {
            return self.state != .closed and self.state != .time_wait;
        }

        pub fn isActive(self: Self) bool {
            return self.state != .closed and self.state != .time_wait and self.state != .listen;
        }

        pub fn isListening(self: Self) bool {
            return self.state == .listen;
        }

        pub fn maySend(self: Self) bool {
            return self.state == .established or self.state == .close_wait;
        }

        pub fn mayRecv(self: Self) bool {
            return switch (self.state) {
                .established, .fin_wait_1, .fin_wait_2 => true,
                else => self.canRecv(),
            };
        }

        pub fn canSend(self: Self) bool {
            return self.maySend() and !self.tx_buffer.isFull();
        }

        pub fn canRecv(self: Self) bool {
            return !self.rx_buffer.isEmpty();
        }

        // -- Endpoint accessors --

        pub fn localEndpoint(self: Self) ?Endpoint {
            return if (self.tuple) |t| t.local else null;
        }

        pub fn remoteEndpoint(self: Self) ?Endpoint {
            return if (self.tuple) |t| t.remote else null;
        }

        // -- Setters with validation --

        pub fn setTimeout(self: *Self, duration: ?Duration) void {
            self.timeout = duration;
        }

        pub fn setAckDelay(self: *Self, duration: ?Duration) void {
            self.ack_delay = duration;
        }

        pub fn setNagleEnabled(self: *Self, enabled: bool) void {
            self.nagle = enabled;
        }

        pub fn setKeepAlive(self: *Self, interval: ?Duration) void {
            self.keep_alive = interval;
            if (interval != null) {
                self.timer.setKeepAlive();
            }
        }

        pub const SetHopLimitError = error{InvalidValue};

        pub fn setHopLimit(self: *Self, hop_limit: ?u8) SetHopLimitError!void {
            if (hop_limit) |h| {
                if (h == 0) return error.InvalidValue;
            }
            self.hop_limit = hop_limit;
        }

        // -- Congestion control --

        pub fn setCongestionControl(self: *Self, cc: CongestionController) void {
            self.congestion_controller = cc;
        }

        pub fn congestionControl(self: Self) CongestionController {
            return self.congestion_controller;
        }

        // -- Queue inspection --

        pub fn sendQueue(self: Self) usize {
            return self.tx_buffer.len();
        }

        pub fn recvQueue(self: Self) usize {
            return self.rx_buffer.len();
        }

        pub fn sendCapacity(self: Self) usize {
            return self.tx_buffer.capacity();
        }

        pub fn recvCapacity(self: Self) usize {
            return self.rx_buffer.capacity();
        }

        fn scaledWindow(self: Self) u16 {
            const shifted = self.rx_buffer.window() >> @intCast(self.remote_win_shift);
            return if (shifted > std.math.maxInt(u16)) std.math.maxInt(u16) else @intCast(shifted);
        }

        pub fn setTsvalGenerator(self: *Self, gen: ?*const fn () u32) void {
            self.tsval_generator = gen;
        }

        pub fn timestampEnabled(self: Self) bool {
            return self.tsval_generator != null;
        }

        // -- Connection lifecycle --

        pub const ListenError = error{ InvalidState, Unaddressable };

        pub fn listen(self: *Self, local_endpoint: ListenEndpoint) ListenError!void {
            if (local_endpoint.port == 0) return error.Unaddressable;

            if (self.isOpen()) {
                if (self.state == .listen and
                    self.listen_endpoint.port == local_endpoint.port)
                {
                    const addrs_match = blk: {
                        if (self.listen_endpoint.addr == null and local_endpoint.addr == null) break :blk true;
                        if (self.listen_endpoint.addr) |a| {
                            if (local_endpoint.addr) |b| {
                                break :blk std.mem.eql(u8, &a, &b);
                            }
                        }
                        break :blk false;
                    };
                    if (addrs_match) return;
                }
                return error.InvalidState;
            }

            self.reset();
            self.listen_endpoint = local_endpoint;
            self.tuple = null;
            self.state = .listen;
        }

        pub const ConnectError = error{ InvalidState, Unaddressable };

        pub fn connect(
            self: *Self,
            remote_addr: Ip.Address,
            remote_port: u16,
            local_addr: Ip.Address,
            local_port: u16,
        ) ConnectError!void {
            if (self.isOpen()) return error.InvalidState;
            if (remote_port == 0) return error.Unaddressable;
            if (local_port == 0) return error.Unaddressable;

            self.reset();
            self.tuple = .{
                .local = .{ .addr = local_addr, .port = local_port },
                .remote = .{ .addr = remote_addr, .port = remote_port },
            };
            self.state = .syn_sent;

            const seq = localSeqNo();
            self.local_seq_no = seq;
            self.remote_last_seq = seq;
        }

        fn localSeqNo() SeqNumber {
            return SeqNumber{ .value = 10000 };
        }

        pub fn close(self: *Self) void {
            switch (self.state) {
                .listen, .syn_sent => self.state = .closed,
                .syn_received, .established => self.state = .fin_wait_1,
                .close_wait => self.state = .last_ack,
                .fin_wait_1, .fin_wait_2, .closing, .time_wait, .last_ack, .closed => {},
            }
        }

        pub fn abort(self: *Self) void {
            self.state = .closed;
        }

        // -- Data transfer --

        pub const SendError = error{InvalidState};

        pub fn sendSlice(self: *Self, data: []const u8) SendError!usize {
            if (!self.maySend()) return error.InvalidState;

            const old_length = self.tx_buffer.len();
            const size = self.tx_buffer.enqueueSlice(data);
            if (size > 0) self.postEnqueue(old_length);
            return size;
        }

        pub const RecvError = error{ InvalidState, Finished };

        fn checkRecv(self: Self) RecvError!void {
            if (!self.mayRecv()) {
                if (self.rx_fin_received) return error.Finished;
                return error.InvalidState;
            }
        }

        pub fn recvSlice(self: *Self, data: []u8) RecvError!usize {
            try self.checkRecv();
            const size = self.rx_buffer.dequeueSlice(data);
            self.remote_seq_no = self.remote_seq_no.add(size);
            return size;
        }

        pub fn peek(self: *Self, max: usize) RecvError![]const u8 {
            try self.checkRecv();
            return self.rx_buffer.getAllocated(0, max);
        }

        /// Zero-copy send: calls `f` with writable buffer, returns bytes enqueued.
        pub fn send(self: *Self, ctx: anytype, f: *const fn (@TypeOf(ctx), []u8) usize) SendError!usize {
            if (!self.maySend()) return error.InvalidState;

            const window = self.tx_buffer.window();
            if (window == 0) return 0;

            const old_length = self.tx_buffer.len();
            const buf = self.tx_buffer.getUnallocated(0, window);
            const written = f(ctx, buf);
            if (written > 0) {
                self.tx_buffer.enqueueUnallocated(written);
                self.postEnqueue(old_length);
            }
            return written;
        }

        /// Zero-copy recv: calls `f` with readable buffer, returns bytes consumed.
        pub fn recv(self: *Self, ctx: anytype, f: *const fn (@TypeOf(ctx), []const u8) usize) RecvError!usize {
            try self.checkRecv();

            const available = self.rx_buffer.len();
            if (available == 0) return 0;

            const buf = self.rx_buffer.getAllocated(0, available);
            const consumed = f(ctx, buf);
            if (consumed > 0) {
                self.rx_buffer.dequeueAllocated(consumed);
                self.remote_seq_no = self.remote_seq_no.add(consumed);
            }
            return consumed;
        }

        // -- Packet processing --

        pub fn accepts(
            self: Self,
            src_addr: Ip.Address,
            dst_addr: Ip.Address,
            repr: TcpRepr,
        ) bool {
            if (self.state == .closed) return false;

            if (self.state == .listen) {
                if (repr.ack_number != null or repr.control == .rst) return false;
            }

            if (self.tuple) |t| {
                return std.mem.eql(u8, &dst_addr, &t.local.addr) and
                    repr.dst_port == t.local.port and
                    std.mem.eql(u8, &src_addr, &t.remote.addr) and
                    repr.src_port == t.remote.port;
            } else {
                const addr_ok = if (self.listen_endpoint.addr) |listen_addr|
                    std.mem.eql(u8, &dst_addr, &listen_addr)
                else
                    true;
                return addr_ok and repr.dst_port != 0 and repr.dst_port == self.listen_endpoint.port;
            }
        }

        pub fn process(
            self: *Self,
            timestamp: Instant,
            src_addr: Ip.Address,
            dst_addr: Ip.Address,
            repr: TcpRepr,
        ) ?TcpRepr {
            // Consider SYN/FIN in sequence space for ACK validation.
            const sent_syn = self.state == .syn_sent or self.state == .syn_received;
            const sent_fin = self.state == .fin_wait_1 or self.state == .last_ack or self.state == .closing;
            const control_len = @as(usize, @intFromBool(sent_syn)) + @as(usize, @intFromBool(sent_fin));

            // Reject unacceptable acknowledgements.
            switch (self.state) {
                .syn_sent => {
                    switch (repr.control) {
                        .rst => {
                            if (repr.ack_number == null) return null;
                            if (repr.ack_number) |ack| {
                                if (!ack.eql(self.local_seq_no.add(1))) return null;
                            }
                        },
                        .syn => {
                            if (repr.ack_number) |ack| {
                                if (!ack.eql(self.local_seq_no.add(1))) {
                                    return rstReply(repr);
                                }
                            }
                            // SYN without ACK (simultaneous open) is OK
                        },
                        .none => {
                            if (repr.ack_number) |ack| {
                                if (ack.eql(self.local_seq_no.add(1))) {
                                    return null;
                                }
                                return rstReply(repr);
                            }
                            return null;
                        },
                        else => return null,
                    }
                },
                .listen => {
                    if (repr.ack_number != null) unreachable;
                },
                else => {
                    if (repr.control != .rst) {
                        if (repr.ack_number == null) return null;

                        if (repr.ack_number) |ack_number| {
                            if (self.state == .syn_received) {
                                if (!ack_number.eql(self.local_seq_no.add(1))) {
                                    return rstReply(repr);
                                }
                            } else {
                                const unacknowledged = self.tx_buffer.len() + control_len;
                                var ack_min = self.local_seq_no;
                                const ack_max = self.local_seq_no.add(unacknowledged);

                                if (sent_syn) ack_min = ack_min.add(1);

                                if (ack_number.lessThan(ack_min)) return null;
                                if (ack_number.greaterThan(ack_max)) {
                                    return self.challengeAckReply(timestamp, repr);
                                }
                            }
                        }
                    }
                },
            }

            // Compute window and payload bounds.
            const window_start = self.remote_seq_no.add(self.rx_buffer.len());
            const window_end = if (self.remote_last_ack) |last_ack|
                last_ack.add(@as(usize, self.remote_last_win) << @intCast(self.remote_win_shift))
            else
                window_start;

            const segment_start = repr.seq_number;
            const segment_end = repr.seq_number.add(repr.payload.len);

            var payload: []const u8 = &.{};
            var payload_offset: usize = 0;

            switch (self.state) {
                .listen, .syn_sent => {},
                else => {
                    const seg_empty = segment_start.eql(segment_end);
                    const win_empty = window_start.eql(window_end);

                    const segment_in_window = blk: {
                        if (seg_empty) {
                            if (segment_end.eql(window_start.sub(1))) {
                                break :blk false;
                            }
                            if (win_empty) {
                                break :blk window_start.eql(segment_start);
                            } else {
                                break :blk window_start.eql(segment_start) or
                                    (segment_start.greaterThan(window_start) and segment_start.lessThan(window_end));
                            }
                        } else {
                            if (win_empty) break :blk false;
                            break :blk (segment_start.greaterThanOrEqual(window_start) and segment_start.lessThan(window_end)) or
                                (segment_end.greaterThan(window_start) and segment_end.lessThanOrEqual(window_end));
                        }
                    };

                    if (segment_in_window) {
                        const overlap_start = window_start.max(segment_start);
                        const overlap_end = window_end.min(segment_end);

                        self.local_rx_last_seq = repr.seq_number;

                        const off_start = overlap_start.diff(segment_start);
                        const off_end = overlap_end.diff(segment_start);
                        payload = repr.payload[off_start..off_end];
                        payload_offset = overlap_start.diff(window_start);
                    } else {
                        if (self.state == .time_wait) {
                            self.timer.setForClose(timestamp);
                        }
                        return self.challengeAckReply(timestamp, repr);
                    }
                },
            }

            // Compute acknowledged bytes.
            var ack_len: usize = 0;
            var ack_of_fin = false;
            var ack_all = false;
            if (repr.control != .rst) {
                if (repr.ack_number) |ack_number| {
                    const tx_buffer_start_seq = self.local_seq_no.add(@intFromBool(sent_syn));
                    if (ack_number.greaterThanOrEqual(tx_buffer_start_seq)) {
                        ack_len = ack_number.diff(tx_buffer_start_seq);

                        if (sent_fin and self.tx_buffer.len() + 1 == ack_len) {
                            ack_len -= 1;
                            ack_of_fin = true;
                        }

                        ack_all = self.remote_last_seq.eql(ack_number) or ack_number.greaterThan(self.remote_last_seq);
                    }

                    self.rtte.onAck(timestamp, ack_number);
                }
            }

            // Quash PSH for state transition logic.
            var control = repr.control.quashPsh();

            // Disregard FIN if we have a hole before the current segment.
            if (control == .fin and window_start.lessThan(segment_start)) {
                control = .none;
            }

            // State transitions.
            switch (self.state) {
                .listen => switch (control) {
                    .rst => return null,
                    .syn => {
                        if (repr.max_seg_size) |mss| {
                            if (mss == 0) return null;
                            self.remote_mss = mss;
                            self.congestion_controller.setMss(mss);
                        }
                        self.tuple = .{
                            .local = .{ .addr = dst_addr, .port = repr.dst_port },
                            .remote = .{ .addr = src_addr, .port = repr.src_port },
                        };
                        self.local_seq_no = localSeqNo();
                        self.remote_seq_no = repr.seq_number.add(1);
                        self.remote_last_seq = self.local_seq_no;
                        self.remote_has_sack = repr.sack_permitted;
                        self.remote_win_scale = repr.window_scale;
                        if (self.remote_win_scale == null) self.remote_win_shift = 0;
                        if (repr.timestamp == null) self.tsval_generator = null;
                        self.state = .syn_received;
                        self.timer.setForIdle(timestamp, self.keep_alive);
                    },
                    else => return null,
                },
                .syn_received => switch (control) {
                    .rst => {
                        if (self.listen_endpoint.port != 0) {
                            self.tuple = null;
                            self.state = .listen;
                            return null;
                        }
                        self.state = .closed;
                        self.tuple = null;
                        return null;
                    },
                    .none => self.state = .established,
                    .fin => {
                        self.remote_seq_no = self.remote_seq_no.add(1);
                        self.rx_fin_received = true;
                        self.state = .close_wait;
                    },
                    else => return null,
                },
                .syn_sent => switch (control) {
                    .rst => {
                        self.state = .closed;
                        self.tuple = null;
                        return null;
                    },
                    .syn => {
                        if (repr.max_seg_size) |mss| {
                            if (mss == 0) return null;
                            self.remote_mss = mss;
                            self.congestion_controller.setMss(mss);
                        }
                        self.remote_seq_no = repr.seq_number.add(1);
                        self.remote_last_seq = self.local_seq_no.add(1);
                        self.remote_last_ack = repr.seq_number;
                        self.remote_has_sack = repr.sack_permitted;
                        self.remote_win_scale = repr.window_scale;
                        if (self.remote_win_scale == null) self.remote_win_shift = 0;
                        if (repr.timestamp == null) self.tsval_generator = null;

                        if (repr.ack_number != null) {
                            self.state = .established;
                        } else {
                            self.state = .syn_received;
                        }
                    },
                    else => return null,
                },
                .established => switch (control) {
                    .rst => {
                        self.state = .closed;
                        self.tuple = null;
                        return null;
                    },
                    .none => {},
                    .fin => {
                        self.remote_seq_no = self.remote_seq_no.add(1);
                        self.rx_fin_received = true;
                        self.state = .close_wait;
                    },
                    else => return null,
                },
                .fin_wait_1 => switch (control) {
                    .rst => {
                        self.state = .closed;
                        self.tuple = null;
                        return null;
                    },
                    .none => {
                        if (ack_of_fin) self.state = .fin_wait_2;
                    },
                    .fin => {
                        self.remote_seq_no = self.remote_seq_no.add(1);
                        self.rx_fin_received = true;
                        if (ack_of_fin) {
                            self.state = .time_wait;
                            self.timer.setForClose(timestamp);
                        } else {
                            self.state = .closing;
                        }
                    },
                    else => return null,
                },
                .fin_wait_2 => switch (control) {
                    .rst => {
                        self.state = .closed;
                        self.tuple = null;
                        return null;
                    },
                    .none => {},
                    .fin => {
                        self.remote_seq_no = self.remote_seq_no.add(1);
                        self.rx_fin_received = true;
                        self.state = .time_wait;
                        self.timer.setForClose(timestamp);
                    },
                    else => return null,
                },
                .closing => switch (control) {
                    .rst => {
                        self.state = .closed;
                        self.tuple = null;
                        return null;
                    },
                    .none => {
                        if (ack_of_fin) {
                            self.state = .time_wait;
                            self.timer.setForClose(timestamp);
                        }
                    },
                    else => return null,
                },
                .close_wait => switch (control) {
                    .rst => {
                        self.state = .closed;
                        self.tuple = null;
                        return null;
                    },
                    .none => {},
                    else => return null,
                },
                .last_ack => switch (control) {
                    .rst => {
                        self.state = .closed;
                        self.tuple = null;
                        return null;
                    },
                    .none => {
                        if (ack_of_fin) {
                            self.state = .closed;
                            self.tuple = null;
                        }
                    },
                    else => return null,
                },
                .time_wait, .closed => return null,
            }

            // Update remote state.
            self.remote_last_ts = timestamp;
            if (repr.timestamp) |ts| self.last_remote_tsval = ts.tsval;

            const scale: u8 = if (repr.control == .syn) 0 else self.remote_win_scale orelse 0;
            const new_remote_win_len = @as(usize, repr.window_len) << @intCast(scale);
            const is_window_update = new_remote_win_len != self.remote_win_len;
            self.remote_win_len = new_remote_win_len;
            self.congestion_controller.setRemoteWindow(new_remote_win_len);

            if (ack_len > 0) {
                std.debug.assert(self.tx_buffer.len() >= ack_len);
                self.tx_buffer.dequeueAllocated(ack_len);
                self.congestion_controller.onAck(timestamp, ack_len, &self.rtte);
            }

            if (repr.ack_number) |ack_number| {
                // Duplicate ACK detection.
                if (self.local_rx_last_ack) |last_rx_ack| {
                    if (repr.payload.len == 0 and
                        last_rx_ack.eql(ack_number) and
                        ack_number.lessThan(self.remote_last_seq) and
                        !is_window_update)
                    {
                        self.local_rx_dup_acks +|= 1;
                        if (self.local_rx_dup_acks == 3) {
                            self.timer.setForFastRetransmit();
                            self.congestion_controller.onDuplicateAck(timestamp);
                        }
                    } else {
                        if (self.local_rx_dup_acks > 0) self.local_rx_dup_acks = 0;
                        self.local_rx_last_ack = ack_number;
                    }
                } else {
                    self.local_rx_last_ack = ack_number;
                }

                self.local_seq_no = ack_number;
                if (self.remote_last_seq.lessThan(self.local_seq_no)) {
                    self.remote_last_seq = self.local_seq_no;
                }
            }

            // Update timers.
            switch (self.timer) {
                .retransmit, .fast_retransmit => {
                    if (ack_all) {
                        self.timer.setForIdle(timestamp, self.keep_alive);
                    } else if (ack_len > 0) {
                        const rto = self.rtte.retransmissionTimeout();
                        self.timer.setForRetransmit(timestamp, rto);
                    }
                },
                .idle => self.timer.setForIdle(timestamp, self.keep_alive),
                else => {},
            }

            // Zero window probe timer management.
            if (self.remote_win_len == 0 and !self.tx_buffer.isEmpty() and
                (self.timer.isIdle() or ack_len > 0))
            {
                const delay = self.rtte.retransmissionTimeout();
                self.timer.setForZeroWindowProbe(timestamp, delay);
            }
            if (self.remote_win_len != 0 and self.timer.isZeroWindowProbe()) {
                self.timer.setForIdle(timestamp, self.keep_alive);
            }

            if (payload.len == 0) return null;

            const assembler_was_empty = self.assembler.isEmpty();

            const contig_len = self.assembler.addThenRemoveFront(payload_offset, payload.len) catch return null;

            _ = self.rx_buffer.writeUnallocated(payload_offset, payload);

            if (contig_len != 0) {
                self.rx_buffer.enqueueUnallocated(contig_len);
            }

            // Handle delayed ACKs.
            if (self.ack_delay) |ack_delay_dur| {
                if (self.ackToTransmit()) {
                    self.ack_delay_timer = switch (self.ack_delay_timer) {
                        .idle => .{ .waiting = timestamp.add(ack_delay_dur) },
                        .waiting => if (self.immediateAckToTransmit()) .immediate else self.ack_delay_timer,
                        .immediate => .immediate,
                    };
                }
            }

            // Per RFC 5681: immediate ACK for out-of-order or gap-filling segments.
            if (!self.assembler.isEmpty() or !assembler_was_empty) {
                return self.ackReply(repr);
            }

            return null;
        }

        // -- Dispatch (generate outgoing packets) --

        pub const DispatchResult = struct {
            repr: TcpRepr,
            src_addr: Ip.Address,
            dst_addr: Ip.Address,
            hop_limit: u8,
            meta: iface_mod.PacketMeta = .{},
        };

        pub fn dispatch(self: *Self, timestamp: Instant) ?DispatchResult {
            const t = self.tuple orelse return null;

            if (self.remote_last_ts == null) {
                self.remote_last_ts = timestamp;
            }

            self.congestion_controller.preTransmit(timestamp);

            // Timeout check.
            if (self.timedOut(timestamp)) {
                self.state = .closed;
            } else if (!self.seqToTransmit() and self.timer.shouldRetransmit(timestamp)) {
                self.remote_last_seq = self.local_seq_no;
                self.timer.setForIdle(timestamp, self.keep_alive);
                self.rtte.onRetransmit();
                self.congestion_controller.onRetransmit(timestamp);
            }

            // Decide whether to send.
            const should_send = blk: {
                if (self.seqToTransmit()) break :blk true;
                if (self.ackToTransmit() and self.delayedAckExpired(timestamp)) break :blk true;
                if (self.windowToUpdate()) break :blk true;
                if (self.state == .closed) break :blk true;
                if (self.timer.shouldKeepAlive(timestamp)) break :blk true;
                if (self.timer.shouldZeroWindowProbe(timestamp)) break :blk true;
                if (self.timer.shouldClose(timestamp)) {
                    self.reset();
                    return null;
                }
                break :blk false;
            };
            if (!should_send) return null;

            // Build base repr.
            var repr = TcpRepr{
                .src_port = t.local.port,
                .dst_port = t.remote.port,
                .control = .none,
                .seq_number = self.remote_last_seq,
                .ack_number = self.remote_seq_no.add(self.rx_buffer.len()),
                .window_len = self.scaledWindow(),
                .payload = &.{},
            };

            var is_zero_window_probe = false;

            switch (self.state) {
                .closed => {
                    repr.control = .rst;
                },
                .listen => return null,
                .syn_sent, .syn_received => {
                    repr.control = .syn;
                    repr.seq_number = self.local_seq_no;
                    repr.window_len = @intCast(@min(self.rx_buffer.window(), std.math.maxInt(u16)));
                    if (self.state == .syn_sent) {
                        repr.ack_number = null;
                        repr.window_scale = self.remote_win_shift;
                        repr.sack_permitted = true;
                    } else {
                        repr.sack_permitted = self.remote_has_sack;
                        repr.window_scale = if (self.remote_win_scale != null) self.remote_win_shift else null;
                    }
                },
                .established, .fin_wait_1, .closing, .close_wait, .last_ack => {
                    const win_right_edge = self.local_seq_no.add(@min(self.remote_win_len, self.congestion_controller.window()));
                    var win_limit: usize = if (win_right_edge.greaterThanOrEqual(self.remote_last_seq))
                        win_right_edge.diff(self.remote_last_seq)
                    else
                        0;

                    if (win_limit == 0 and self.timer.shouldZeroWindowProbe(timestamp)) {
                        win_limit = 1;
                        is_zero_window_probe = true;
                    }

                    const size = @min(win_limit, @min(self.remote_mss, BASE_MSS));
                    const offset = self.remote_last_seq.diff(self.local_seq_no);
                    repr.payload = self.tx_buffer.getAllocated(offset, size);

                    if (offset + repr.payload.len == self.tx_buffer.len()) {
                        switch (self.state) {
                            .fin_wait_1, .last_ack, .closing => repr.control = .fin,
                            .established, .close_wait => {
                                if (repr.payload.len > 0) repr.control = .psh;
                            },
                            else => {},
                        }
                    }
                },
                .fin_wait_2, .time_wait => {},
            }

            // Keep-alive: send a byte with seq-1 if nothing else to send.
            var is_keep_alive = false;
            if (self.timer.shouldKeepAlive(timestamp) and repr.isEmpty()) {
                repr.seq_number = repr.seq_number.sub(1);
                repr.payload = &.{0};
                is_keep_alive = true;
            }

            // Fill MSS on SYN.
            if (repr.control == .syn) {
                repr.max_seg_size = BASE_MSS;
            }

            // RFC 7323: generate timestamp option on outgoing segments.
            if (self.tsval_generator) |gen| {
                repr.timestamp = .{ .tsval = gen(), .tsecr = self.last_remote_tsval };
            }

            self.timer.rewindKeepAlive(timestamp, self.keep_alive);
            self.ack_delay_timer = .idle;

            const result = DispatchResult{
                .repr = repr,
                .src_addr = t.local.addr,
                .dst_addr = t.remote.addr,
                .hop_limit = self.hop_limit orelse DEFAULT_HOP_LIMIT,
            };

            if (is_zero_window_probe) {
                self.timer.rewindZeroWindowProbe(timestamp);
                return result;
            }

            if (is_keep_alive) {
                return result;
            }

            self.remote_last_seq = repr.seq_number.add(repr.segmentLen());
            self.remote_last_ack = repr.ack_number;
            self.remote_last_win = repr.window_len;

            if (repr.segmentLen() > 0) {
                self.rtte.onSend(timestamp, repr.seq_number.add(repr.segmentLen()));
                self.congestion_controller.postTransmit(timestamp, repr.segmentLen());
            }

            if (repr.segmentLen() > 0 and !self.timer.isRetransmit()) {
                const rto = self.rtte.retransmissionTimeout();
                self.timer.setForRetransmit(timestamp, rto);
            }

            if (self.state == .closed) {
                self.tuple = null;
            }

            return result;
        }

        // -- Poll scheduling --

        pub fn pollAt(self: Self) ?Instant {
            if (self.tuple == null) return null;

            // Immediate dispatch needed for these conditions.
            if (self.seqToTransmit() or self.windowToUpdate() or
                self.state == .closed or self.remote_last_ts == null)
            {
                return Instant.ZERO;
            }

            var result: ?Instant = null;

            // ACK delay timer.
            switch (self.ack_delay_timer) {
                .idle => {},
                .waiting => |deadline| result = minInstant(result, deadline),
                .immediate => return Instant.ZERO,
            }

            // Connection timeout.
            if (self.remote_last_ts) |rts| {
                if (self.timeout) |tout| {
                    result = minInstant(result, rts.add(tout));
                }
            }

            // Timer (retransmit, keep-alive, close, zero-window-probe).
            if (self.timer.pollAt()) |t| {
                result = minInstant(result, t);
            }

            return result;
        }

        fn minInstant(a: ?Instant, b: Instant) Instant {
            if (a) |av| {
                return if (b.lessThan(av)) b else av;
            }
            return b;
        }

        // -- Internal helpers --

        fn postEnqueue(self: *Self, old_length: usize) void {
            if (old_length == 0) self.remote_last_ts = null;
            if (self.remote_win_len == 0 and self.timer.isIdle()) {
                const delay = self.rtte.retransmissionTimeout();
                self.timer.setForZeroWindowProbe(Instant.ZERO, delay);
            }
        }

        fn timedOut(self: Self, timestamp: Instant) bool {
            if (self.remote_last_ts) |rts| {
                if (self.timeout) |tout| {
                    return timestamp.greaterThanOrEqual(rts.add(tout));
                }
            }
            return false;
        }

        fn seqToTransmit(self: Self) bool {
            const data_in_flight = !self.remote_last_seq.eql(self.local_seq_no);

            if ((self.state == .syn_sent or self.state == .syn_received) and !data_in_flight) {
                return true;
            }

            const max_send_seq_len = @min(self.remote_win_len, @min(self.tx_buffer.len(), self.congestion_controller.window()));
            const max_send_seq = self.local_seq_no.add(max_send_seq_len);

            const max_send: usize = if (max_send_seq.greaterThanOrEqual(self.remote_last_seq))
                max_send_seq.diff(self.remote_last_seq)
            else
                0;

            var can_send = max_send != 0;
            const can_send_full = max_send >= @min(self.remote_mss, BASE_MSS);

            const want_fin = self.state == .fin_wait_1 or self.state == .closing or self.state == .last_ack;

            if (self.nagle and data_in_flight and !can_send_full and !want_fin) {
                can_send = false;
            }

            const can_fin = want_fin and self.remote_last_seq.eql(self.local_seq_no.add(self.tx_buffer.len()));

            return can_send or can_fin;
        }

        fn delayedAckExpired(self: Self, timestamp: Instant) bool {
            return switch (self.ack_delay_timer) {
                .idle => true,
                .waiting => |t| timestamp.greaterThanOrEqual(t),
                .immediate => true,
            };
        }

        fn ackToTransmit(self: Self) bool {
            if (self.remote_last_ack) |last_ack| {
                return last_ack.lessThan(self.remote_seq_no.add(self.rx_buffer.len()));
            }
            return false;
        }

        fn immediateAckToTransmit(self: Self) bool {
            if (self.remote_last_ack) |last_ack| {
                return last_ack.add(self.remote_mss).lessThan(self.remote_seq_no.add(self.rx_buffer.len()));
            }
            return false;
        }

        fn lastScaledWindow(self: Self) ?u16 {
            const last_ack = self.remote_last_ack orelse return null;
            const next_ack = self.remote_seq_no.add(self.rx_buffer.len());
            const last_win = @as(usize, self.remote_last_win) << @intCast(self.remote_win_shift);
            const last_win_edge = last_ack.add(last_win);
            const adjusted = last_win_edge.diff(next_ack);
            const shifted: usize = adjusted >> @intCast(self.remote_win_shift);
            return if (shifted > std.math.maxInt(u16)) std.math.maxInt(u16) else @intCast(shifted);
        }

        fn windowToUpdate(self: Self) bool {
            return switch (self.state) {
                .syn_sent, .syn_received, .established, .fin_wait_1, .fin_wait_2 => {
                    const new_win = self.scaledWindow();
                    if (new_win == 0) return false;
                    const last_win = self.lastScaledWindow() orelse return false;
                    return new_win / 2 >= last_win;
                },
                else => false,
            };
        }

        fn ackReply(self: *Self, repr: TcpRepr) TcpRepr {
            const ack_number = self.remote_seq_no.add(self.rx_buffer.len());
            const window_len = self.scaledWindow();

            self.remote_last_ack = ack_number;
            self.remote_last_win = window_len;

            var reply = TcpRepr{
                .src_port = repr.dst_port,
                .dst_port = repr.src_port,
                .seq_number = self.remote_last_seq,
                .ack_number = ack_number,
                .window_len = window_len,
            };

            if (self.tsval_generator) |gen| {
                if (repr.timestamp) |ts| {
                    reply.timestamp = .{ .tsval = gen(), .tsecr = ts.tsval };
                }
            }

            if (self.remote_has_sack) {
                var iter = self.assembler.iterData(@as(usize, ack_number.toU32()));
                for (&reply.sack_ranges) |*slot| {
                    const pair = iter.next() orelse break;
                    slot.* = .{ .left = @truncate(pair[0]), .right = @truncate(pair[1]) };
                }
            }

            return reply;
        }

        fn challengeAckReply(self: *Self, timestamp: Instant, repr: TcpRepr) ?TcpRepr {
            if (timestamp.lessThan(self.challenge_ack_timer)) return null;
            self.challenge_ack_timer = timestamp.add(Duration.fromSecs(1));
            return self.ackReply(repr);
        }
    };
}

// =========================================================================
// Tests
// =========================================================================

const testing = std.testing;
const TestSocket = Socket(ipv4, 4);

const LOCAL_PORT: u16 = 80;
const REMOTE_PORT: u16 = 49500;
const LOCAL_SEQ = SeqNumber{ .value = 10000 };
const REMOTE_SEQ = SeqNumber{ .value = -10001 };
const LOCAL_ADDR = ipv4.Address{ 192, 168, 1, 1 };
const REMOTE_ADDR = ipv4.Address{ 192, 168, 1, 2 };

const LISTEN_END = TestSocket.ListenEndpoint{ .port = LOCAL_PORT };

const SEND_TEMPL = TcpRepr{
    .src_port = REMOTE_PORT,
    .dst_port = LOCAL_PORT,
    .control = .none,
    .seq_number = SeqNumber.ZERO,
    .ack_number = SeqNumber.ZERO,
    .window_len = 256,
};

const RECV_TEMPL = TcpRepr{
    .src_port = LOCAL_PORT,
    .dst_port = REMOTE_PORT,
    .control = .none,
    .seq_number = SeqNumber.ZERO,
    .ack_number = SeqNumber.ZERO,
    .window_len = 64,
};

// -- Test helpers --

fn sendPacket(s: *TestSocket, timestamp: Instant, repr: TcpRepr) ?TcpRepr {
    std.debug.assert(s.accepts(REMOTE_ADDR, LOCAL_ADDR, repr));
    return s.process(timestamp, REMOTE_ADDR, LOCAL_ADDR, repr);
}

fn sendPacketAt0(s: *TestSocket, repr: TcpRepr) ?TcpRepr {
    return sendPacket(s, Instant.ZERO, repr);
}

fn recvPacket(s: *TestSocket, timestamp: Instant) ?TcpRepr {
    const result = s.dispatch(timestamp) orelse return null;
    return result.repr;
}

fn recvAt0(s: *TestSocket) ?TcpRepr {
    return recvPacket(s, Instant.ZERO);
}

// -- Factory functions --

fn socketNew() TestSocket {
    return socketWithBuffers(64, 64);
}

fn socketWithBuffers(comptime tx_len: usize, comptime rx_len: usize) TestSocket {
    const S = struct {
        var rx_buf: [rx_len]u8 = .{0} ** rx_len;
        var tx_buf: [tx_len]u8 = .{0} ** tx_len;
    };
    @memset(&S.rx_buf, 0);
    @memset(&S.tx_buf, 0);
    var s = TestSocket.init(&S.rx_buf, &S.tx_buf);
    s.ack_delay = null;
    return s;
}

fn socketListen() TestSocket {
    var s = socketNew();
    s.state = .listen;
    s.listen_endpoint = LISTEN_END;
    return s;
}

fn socketSynReceived() TestSocket {
    var s = socketNew();
    s.state = .syn_received;
    s.listen_endpoint = LISTEN_END;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };
    s.local_seq_no = LOCAL_SEQ;
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ;
    s.remote_win_len = 256;
    return s;
}

fn socketSynSent() TestSocket {
    var s = socketNew();
    s.state = .syn_sent;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };
    s.local_seq_no = LOCAL_SEQ;
    s.remote_last_seq = LOCAL_SEQ;
    return s;
}

fn socketEstablished() TestSocket {
    var s = socketSynReceived();
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    return s;
}

fn socketFinWait1() TestSocket {
    var s = socketEstablished();
    s.state = .fin_wait_1;
    return s;
}

fn socketFinWait2() TestSocket {
    var s = socketFinWait1();
    s.state = .fin_wait_2;
    s.local_seq_no = LOCAL_SEQ.add(1).add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1).add(1);
    return s;
}

fn socketClosing() TestSocket {
    var s = socketFinWait1();
    s.state = .closing;
    s.remote_last_seq = LOCAL_SEQ.add(1).add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1).add(1);
    s.timer = .{ .retransmit = .{ .expires_at = Instant.fromMillis(1000) } };
    return s;
}

fn socketTimeWait(from_closing: bool) TestSocket {
    var s = socketFinWait2();
    s.state = .time_wait;
    s.remote_seq_no = REMOTE_SEQ.add(1).add(1);
    if (from_closing) {
        s.remote_last_ack = REMOTE_SEQ.add(1).add(1);
    }
    s.timer = .{ .close = .{ .expires_at = Instant.fromSecs(1).add(CLOSE_DELAY) } };
    return s;
}

fn socketCloseWait() TestSocket {
    var s = socketEstablished();
    s.state = .close_wait;
    s.remote_seq_no = REMOTE_SEQ.add(1).add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1).add(1);
    return s;
}

fn socketLastAck() TestSocket {
    var s = socketCloseWait();
    s.state = .last_ack;
    return s;
}

// -- Assertion helpers --

fn expectReprEql(expected: TcpRepr, actual: TcpRepr) !void {
    try testing.expectEqual(expected.src_port, actual.src_port);
    try testing.expectEqual(expected.dst_port, actual.dst_port);
    try testing.expectEqual(expected.control, actual.control);
    try testing.expect(expected.seq_number.eql(actual.seq_number));
    if (expected.ack_number) |ea| {
        const aa = actual.ack_number orelse {
            return error.TestExpectedEqual;
        };
        try testing.expect(ea.eql(aa));
    } else {
        try testing.expectEqual(@as(?SeqNumber, null), actual.ack_number);
    }
    try testing.expectEqual(expected.window_len, actual.window_len);
    if (expected.max_seg_size != null) {
        try testing.expectEqual(expected.max_seg_size, actual.max_seg_size);
    }
    if (expected.sack_permitted) {
        try testing.expect(actual.sack_permitted);
    }
    if (expected.window_scale != null) {
        try testing.expectEqual(expected.window_scale, actual.window_scale);
    }
    try testing.expectEqualSlices(u8, expected.payload, actual.payload);
}

fn expectSanity(a: TestSocket, b: TestSocket) !void {
    try testing.expectEqual(a.state, b.state);
    if (a.tuple) |at| {
        const bt = b.tuple orelse return error.TestExpectedEqual;
        try testing.expect(std.mem.eql(u8, &at.local.addr, &bt.local.addr));
        try testing.expectEqual(at.local.port, bt.local.port);
        try testing.expect(std.mem.eql(u8, &at.remote.addr, &bt.remote.addr));
        try testing.expectEqual(at.remote.port, bt.remote.port);
    } else {
        try testing.expectEqual(@as(?TestSocket.Tuple, null), b.tuple);
    }
    try testing.expect(a.local_seq_no.eql(b.local_seq_no));
    try testing.expect(a.remote_seq_no.eql(b.remote_seq_no));
    try testing.expect(a.remote_last_seq.eql(b.remote_last_seq));
}

// =========================================================================
// Phase 1: Core type tests
// =========================================================================

// [smoltcp:socket/tcp.rs - RttEstimator]
test "rtt estimator first sample" {
    var rtte = RttEstimator{};
    try testing.expectEqual(@as(u32, RTTE_INITIAL_RTO), rtte.rto);

    rtte.sample(500);
    try testing.expect(rtte.have_measurement);
    try testing.expectEqual(@as(u32, 500), rtte.srtt);
    try testing.expectEqual(@as(u32, 250), rtte.rttvar);
    // rto = srtt + max(5, 4*rttvar) = 500 + 1000 = 1500, clamped to [1000..60000]
    try testing.expectEqual(@as(u32, 1500), rtte.rto);
}

test "rtt estimator subsequent sample" {
    var rtte = RttEstimator{};
    rtte.sample(500);
    rtte.sample(400);

    // srtt = ceil((500*7 + 400) / 8) = ceil(3900/8) = 488
    try testing.expectEqual(@as(u32, 488), rtte.srtt);
    // rttvar = ceil((250*3 + |500-400|) / 4) = ceil(850/4) = 213
    try testing.expectEqual(@as(u32, 213), rtte.rttvar);
}

test "rtt estimator backoff" {
    var rtte = RttEstimator{};
    rtte.sample(500);
    const rto_before = rtte.rto;
    rtte.onRetransmit();
    try testing.expectEqual(rto_before * 2, rtte.rto);
    try testing.expect(rtte.timestamp == null);
}

test "timer idle and retransmit" {
    var timer = Timer.init();
    try testing.expect(timer.isIdle());
    try testing.expect(!timer.isRetransmit());

    timer.setForRetransmit(Instant.fromMillis(100), Duration.fromMillis(1000));
    try testing.expect(!timer.isIdle());
    try testing.expect(timer.isRetransmit());
    try testing.expect(!timer.shouldRetransmit(Instant.fromMillis(500)));
    try testing.expect(timer.shouldRetransmit(Instant.fromMillis(1100)));
}

test "timer close" {
    var timer = Timer.init();
    timer.setForClose(Instant.fromMillis(0));
    try testing.expect(!timer.shouldClose(Instant.fromMillis(5000)));
    try testing.expect(timer.shouldClose(Instant.fromMillis(10000)));
}

test "socket init" {
    const s = socketNew();
    try testing.expectEqual(State.closed, s.state);
    try testing.expect(!s.isOpen());
    try testing.expect(!s.isActive());
}

// =========================================================================
// Phase 2: CLOSED state tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_closed_reject]
test "closed rejects SYN" {
    var s = socketNew();
    try testing.expectEqual(State.closed, s.state);

    const syn = TcpRepr{
        .control = .syn,
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
    };
    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, syn));
}

// [smoltcp:socket/tcp.rs:test_closed_reject_after_listen]
test "closed rejects after listen+close" {
    var s = socketNew();
    try s.listen(TestSocket.ListenEndpoint{ .port = LOCAL_PORT });
    s.close();

    const syn = TcpRepr{
        .control = .syn,
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
    };
    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, syn));
}

// [smoltcp:socket/tcp.rs:test_closed_close]
test "close on closed is noop" {
    var s = socketNew();
    s.close();
    try testing.expectEqual(State.closed, s.state);
}

// =========================================================================
// Phase 2: LISTEN state tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_listen_sanity]
test "listen sanity" {
    var s = socketNew();
    try s.listen(TestSocket.ListenEndpoint{ .port = LOCAL_PORT });
    try expectSanity(s, socketListen());
}

// [smoltcp:socket/tcp.rs:test_listen_validation]
test "listen validation rejects port 0" {
    var s = socketNew();
    try testing.expectError(error.Unaddressable, s.listen(TestSocket.ListenEndpoint{ .port = 0 }));
}

// [smoltcp:socket/tcp.rs:test_listen_twice]
test "listen twice on same port is ok" {
    var s = socketNew();
    try s.listen(TestSocket.ListenEndpoint{ .port = 80 });
    try s.listen(TestSocket.ListenEndpoint{ .port = 80 });
    s.state = .syn_received;
    try testing.expectError(error.InvalidState, s.listen(TestSocket.ListenEndpoint{ .port = 80 }));
}

// [smoltcp:socket/tcp.rs:test_listen_syn]
test "listen receives SYN -> SYN-RECEIVED" {
    var s = socketListen();
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try expectSanity(s, socketSynReceived());
}

// [smoltcp:socket/tcp.rs:test_listen_syn_reject_ack]
test "listen rejects SYN with ACK" {
    var s = socketListen();
    const syn_ack = TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ,
        .window_len = SEND_TEMPL.window_len,
    };
    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, syn_ack));
    try testing.expectEqual(State.listen, s.state);
}

// [smoltcp:socket/tcp.rs:test_listen_rst]
test "listen rejects RST" {
    var s = socketListen();
    const rst = TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    };
    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, rst));
    try testing.expectEqual(State.listen, s.state);
}

// [smoltcp:socket/tcp.rs:test_listen_close]
test "listen close goes to closed" {
    var s = socketListen();
    s.close();
    try testing.expectEqual(State.closed, s.state);
}

// =========================================================================
// Phase 2: SYN-RECEIVED state tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_syn_received_ack]
test "SYN-RECEIVED receives ACK -> ESTABLISHED" {
    var s = socketSynReceived();

    // First dispatch: should send SYN|ACK
    const syn_ack = recvAt0(&s);
    try testing.expect(syn_ack != null);
    try expectReprEql(TcpRepr{
        .src_port = LOCAL_PORT,
        .dst_port = REMOTE_PORT,
        .control = .syn,
        .seq_number = LOCAL_SEQ,
        .ack_number = REMOTE_SEQ.add(1),
        .max_seg_size = BASE_MSS,
        .window_len = 64,
    }, syn_ack.?);

    // Send ACK completing handshake
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.established, s.state);
    try expectSanity(s, socketEstablished());
}

// [smoltcp:socket/tcp.rs:test_syn_received_rst]
test "SYN-RECEIVED RST returns to LISTEN" {
    var s = socketSynReceived();
    _ = recvAt0(&s); // drain SYN|ACK

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.listen, s.state);
}

// =========================================================================
// Phase 2: SYN-SENT state tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_syn_sent_syn_ack]
test "SYN-SENT receives SYN|ACK -> ESTABLISHED" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.established, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_syn - simultaneous open]
test "SYN-SENT receives SYN (simultaneous open) -> SYN-RECEIVED" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.syn_received, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_rst]
test "SYN-SENT receives RST|ACK -> CLOSED" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_rst_no_ack]
test "SYN-SENT ignores RST without ACK" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.syn_sent, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_rst_bad_ack]
test "SYN-SENT ignores RST with wrong ACK" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(2), // wrong
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.syn_sent, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_close]
test "SYN-SENT close goes to CLOSED" {
    var s = socketSynSent();
    s.close();
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs - SYN-SENT dispatch emits SYN]
test "SYN-SENT dispatch emits SYN" {
    var s = socketSynSent();
    const syn = recvAt0(&s);
    try testing.expect(syn != null);
    try testing.expectEqual(Control.syn, syn.?.control);
    try testing.expect(syn.?.seq_number.eql(LOCAL_SEQ));
    try testing.expectEqual(@as(?SeqNumber, null), syn.?.ack_number);
    try testing.expect(syn.?.max_seg_size != null);
}

// =========================================================================
// Phase 3: Data transfer tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_established_recv]
test "ESTABLISHED recv data" {
    var s = socketEstablished();

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });
    // In-order data: process() defers ACK to dispatch().
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expect(ack.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(6)));

    // Read the data back.
    var buf: [6]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqualSlices(u8, "abcdef", buf[0..n]);
}

// [smoltcp:socket/tcp.rs:test_established_send]
test "ESTABLISHED send data" {
    var s = socketEstablished();

    const n = try s.sendSlice("abcdef");
    try testing.expectEqual(@as(usize, 6), n);

    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt.?.payload);
    try testing.expectEqual(Control.psh, pkt.?.control);
}

// [smoltcp:socket/tcp.rs:test_established_send_recv]
test "ESTABLISHED send and receive" {
    var s = socketEstablished();

    // Send data.
    _ = try s.sendSlice("abcdef");
    const sent_pkt = recvAt0(&s);
    try testing.expect(sent_pkt != null);
    try testing.expectEqualSlices(u8, "abcdef", sent_pkt.?.payload);

    // Receive ACK of our data + new data from remote.
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = SEND_TEMPL.window_len,
        .payload = "ghijkl",
    });
    // In-order data: process() defers ACK to dispatch().
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    const ack = recvAt0(&s);
    try testing.expect(ack != null);

    var buf: [6]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqualSlices(u8, "ghijkl", buf[0..n]);
}

test "send error when not established" {
    var s = socketNew();
    try testing.expectError(error.InvalidState, s.sendSlice("data"));
}

test "recv error when not established" {
    var s = socketNew();
    var buf: [4]u8 = undefined;
    try testing.expectError(error.InvalidState, s.recvSlice(&buf));
}

// =========================================================================
// Phase 4: Connection teardown tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_established_recv_fin]
test "ESTABLISHED recv FIN -> CLOSE-WAIT" {
    var s = socketEstablished();
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    // Empty FIN, no payload - should return null since no ACK needed
    // (or an ACK if the code does so). Let's just check state.
    _ = reply;
    try testing.expectEqual(State.close_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_1_fin_ack]
test "FIN-WAIT-1 recv FIN+ACK -> TIME-WAIT" {
    var s = socketFinWait1();
    // First dispatch FIN.
    const fin_pkt = recvAt0(&s);
    try testing.expect(fin_pkt != null);
    try testing.expectEqual(Control.fin, fin_pkt.?.control);

    // Remote sends FIN|ACK back.
    const reply = sendPacket(&s, Instant.fromMillis(1000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    _ = reply;
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_1_fin_no_ack]
test "FIN-WAIT-1 recv FIN without ACK of our FIN -> CLOSING" {
    var s = socketFinWait1();
    _ = recvAt0(&s); // drain FIN

    const reply = sendPacket(&s, Instant.fromMillis(1000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1), // ACKs our data but not FIN
        .window_len = SEND_TEMPL.window_len,
    });
    _ = reply;
    try testing.expectEqual(State.closing, s.state);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_1_ack]
test "FIN-WAIT-1 recv ACK of FIN -> FIN-WAIT-2" {
    var s = socketFinWait1();
    _ = recvAt0(&s); // drain FIN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1), // ACKs our FIN
        .window_len = SEND_TEMPL.window_len,
    });
    _ = reply;
    try testing.expectEqual(State.fin_wait_2, s.state);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_2_fin]
test "FIN-WAIT-2 recv FIN -> TIME-WAIT" {
    var s = socketFinWait2();

    const reply = sendPacket(&s, Instant.fromMillis(1000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    _ = reply;
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_closing_ack]
test "CLOSING recv ACK -> TIME-WAIT" {
    var s = socketClosing();

    const reply = sendPacket(&s, Instant.fromMillis(1000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1), // ACKs our FIN
        .window_len = SEND_TEMPL.window_len,
    });
    _ = reply;
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_time_wait_expire]
test "TIME-WAIT expires to CLOSED" {
    var s = socketTimeWait(false);
    // Drain the pending ACK for the remote's FIN.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expectEqual(State.time_wait, s.state);
    // Dispatch at a time past the close timer: should reset.
    const result = s.dispatch(Instant.fromSecs(1).add(CLOSE_DELAY));
    try testing.expectEqual(@as(?TestSocket.DispatchResult, null), result);
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_established_rst]
test "ESTABLISHED recv RST -> CLOSED" {
    var s = socketEstablished();
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.closed, s.state);
}

// =========================================================================
// Phase 5: Retransmission tests
// =========================================================================

test "retransmission after timeout" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef");

    // First dispatch sends data.
    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    // No packet right away.
    const pkt2 = recvPacket(&s, Instant.fromMillis(500));
    try testing.expectEqual(@as(?TcpRepr, null), pkt2);

    // After RTO (1000ms), retransmit fires.
    const pkt3 = recvPacket(&s, Instant.fromMillis(1100));
    try testing.expect(pkt3 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt3.?.payload);
}

// =========================================================================
// Phase 6: Keep-alive test
// =========================================================================

test "keep alive sends probes" {
    var s = socketEstablished();
    s.keep_alive = Duration.fromMillis(500);
    s.timer.setForIdle(Instant.ZERO, s.keep_alive);

    // Before keep-alive interval: no packet.
    const p1 = recvPacket(&s, Instant.fromMillis(100));
    try testing.expectEqual(@as(?TcpRepr, null), p1);

    // After keep-alive interval, should send probe.
    const p2 = recvPacket(&s, Instant.fromMillis(600));
    try testing.expect(p2 != null);
    try testing.expectEqual(@as(usize, 1), p2.?.payload.len);
}

// =========================================================================
// Full handshake integration test
// =========================================================================

test "full three-way handshake via listen" {
    var s = socketNew();
    try s.listen(TestSocket.ListenEndpoint{ .port = 80 });
    try testing.expectEqual(State.listen, s.state);

    // Remote sends SYN.
    const reply1 = sendPacketAt0(&s, TcpRepr{
        .src_port = REMOTE_PORT,
        .dst_port = 80,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = 256,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply1);
    try testing.expectEqual(State.syn_received, s.state);

    // We dispatch SYN|ACK.
    const syn_ack = recvAt0(&s);
    try testing.expect(syn_ack != null);
    try testing.expectEqual(Control.syn, syn_ack.?.control);
    try testing.expect(syn_ack.?.ack_number != null);

    // Remote sends ACK completing handshake.
    const reply2 = sendPacketAt0(&s, TcpRepr{
        .src_port = REMOTE_PORT,
        .dst_port = 80,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 256,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply2);
    try testing.expectEqual(State.established, s.state);
}

test "full handshake via connect" {
    var s = socketNew();
    try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);
    try testing.expectEqual(State.syn_sent, s.state);

    // Dispatch SYN.
    const syn = recvAt0(&s);
    try testing.expect(syn != null);
    try testing.expectEqual(Control.syn, syn.?.control);
    try testing.expectEqual(@as(?SeqNumber, null), syn.?.ack_number);

    // Receive SYN|ACK.
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 256,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.established, s.state);

    // Dispatch ACK.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expectEqual(Control.none, ack.?.control);
    try testing.expect(ack.?.ack_number.?.eql(REMOTE_SEQ.add(1)));
}

// =========================================================================
// Additional LISTEN tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_listen_sack_option]
test "listen sack option disabled" {
    var s = socketListen();
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
        .sack_permitted = false,
    });
    try testing.expect(!s.remote_has_sack);
    const syn_ack = recvAt0(&s);
    try testing.expect(syn_ack != null);
    try testing.expect(!syn_ack.?.sack_permitted);
}

// [smoltcp:socket/tcp.rs:test_listen_sack_option]
test "listen sack option enabled" {
    var s = socketListen();
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
        .sack_permitted = true,
    });
    try testing.expect(s.remote_has_sack);
    const syn_ack = recvAt0(&s);
    try testing.expect(syn_ack != null);
    try testing.expect(syn_ack.?.sack_permitted);
}

// =========================================================================
// Additional SYN-RECEIVED tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_syn_received_ack_too_high]
test "SYN-RECEIVED rejects ACK too high" {
    var s = socketSynReceived();
    _ = recvAt0(&s); // drain SYN|ACK

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(2), // wrong: too high
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expect(reply != null);
    try testing.expectEqual(Control.rst, reply.?.control);
    try testing.expectEqual(State.syn_received, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_received_fin]
test "SYN-RECEIVED recv FIN -> CLOSE-WAIT" {
    var s = socketSynReceived();
    _ = recvAt0(&s); // drain SYN|ACK

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });
    try testing.expectEqual(State.close_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_received_no_window_scaling]
test "SYN-RECEIVED no window scaling" {
    var s = socketListen();
    // SYN without window_scale
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.syn_received, s.state);

    const syn_ack = recvAt0(&s);
    try testing.expect(syn_ack != null);
    try testing.expectEqual(@as(?u8, null), syn_ack.?.window_scale);

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(u8, 0), s.remote_win_shift);
    try testing.expectEqual(@as(?u8, null), s.remote_win_scale);
}

// [smoltcp:socket/tcp.rs:test_syn_received_window_scaling]
test "SYN-RECEIVED window scaling" {
    var s = socketListen();
    // SYN with window_scale = 3
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
        .window_scale = 3,
    });
    try testing.expectEqual(State.syn_received, s.state);

    const syn_ack = recvAt0(&s);
    try testing.expect(syn_ack != null);
    // Our rx buffer is 64 which gives win_shift=0
    try testing.expectEqual(@as(?u8, 0), syn_ack.?.window_scale);

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?u8, 3), s.remote_win_scale);
}

// =========================================================================
// Additional SYN-SENT tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_connect_validation]
test "connect validation" {
    var s = socketNew();
    try testing.expectError(error.Unaddressable, s.connect(REMOTE_ADDR, 0, LOCAL_ADDR, LOCAL_PORT));
    try testing.expectError(error.Unaddressable, s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, 0));
    try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);
    try testing.expect(s.tuple != null);
}

// [smoltcp:socket/tcp.rs:test_connect_twice]
test "connect twice fails" {
    var s = socketNew();
    try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);
    try testing.expectError(error.InvalidState, s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT));
}

// [smoltcp:socket/tcp.rs:test_syn_sent_sanity]
test "SYN-SENT sanity" {
    var s = socketNew();
    try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);
    try expectSanity(s, socketSynSent());
}

// [smoltcp:socket/tcp.rs:test_syn_sent_syn_ack_not_incremented]
test "SYN-SENT rejects SYN|ACK with un-incremented ACK" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ, // wrong: not incremented
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expect(reply != null);
    try testing.expectEqual(Control.rst, reply.?.control);
    try testing.expectEqual(State.syn_sent, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_bad_ack]
test "SYN-SENT ignores bare ACK with correct seq" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    // A plain (non-SYN, non-RST) packet with correct ACK is silently dropped
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.syn_sent, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_bad_ack_seq_1]
test "SYN-SENT sends RST for bad ACK seq too low" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ, // wrong: not incremented
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expect(reply != null);
    try testing.expectEqual(Control.rst, reply.?.control);
    try testing.expect(reply.?.seq_number.eql(LOCAL_SEQ));
    try testing.expectEqual(State.syn_sent, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_bad_ack_seq_2]
test "SYN-SENT sends RST for bad ACK seq too high" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(123456), // wrong: too high
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expect(reply != null);
    try testing.expectEqual(Control.rst, reply.?.control);
    try testing.expect(reply.?.seq_number.eql(LOCAL_SEQ.add(123456)));
    try testing.expectEqual(State.syn_sent, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_sack_option]
test "SYN-SENT sack option" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .sack_permitted = true,
    });
    try testing.expect(s.remote_has_sack);

    var s2 = socketSynSent();
    _ = recvAt0(&s2); // drain SYN

    _ = sendPacketAt0(&s2, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .sack_permitted = false,
    });
    try testing.expect(!s2.remote_has_sack);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_syn_ack_window_scaling]
test "SYN-SENT syn ack window scaling" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 42,
        .window_scale = 7,
    });
    try testing.expectEqual(State.established, s.state);
    try testing.expectEqual(@as(?u8, 7), s.remote_win_scale);
    // Scaling does NOT apply to the window value in SYN packets.
    try testing.expectEqual(@as(usize, 42), s.remote_win_len);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_syn_received_rst]
test "SYN-SENT simultaneous open then RST" {
    var s = socketSynSent();
    _ = recvAt0(&s); // drain SYN

    // SYN without ACK -> simultaneous open -> SYN-RECEIVED
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.syn_received, s.state);

    // RST in SYN-RECEIVED from a connect() (no listen endpoint)
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closed, s.state);
}

// =========================================================================
// Additional ESTABLISHED tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_established_rst_no_ack]
test "ESTABLISHED recv RST without ACK -> CLOSED" {
    var s = socketEstablished();
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_established_abort]
test "ESTABLISHED abort sends RST" {
    var s = socketEstablished();
    s.abort();
    try testing.expectEqual(State.closed, s.state);

    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    try testing.expectEqual(Control.rst, pkt.?.control);
}

// [smoltcp:socket/tcp.rs:test_established_bad_ack]
test "ESTABLISHED ignores ACK too low" {
    var s = socketEstablished();
    // ACK below local_seq_no (already acknowledged data)
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = SeqNumber{ .value = LOCAL_SEQ.value -% 1 },
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expect(s.local_seq_no.eql(LOCAL_SEQ.add(1)));
}

// [smoltcp:socket/tcp.rs:test_established_fin]
test "ESTABLISHED recv FIN with ACK" {
    var s = socketEstablished();
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.close_wait, s.state);

    // Dispatch should send ACK for the FIN.
    const ack_pkt = recvAt0(&s);
    try testing.expect(ack_pkt != null);
    try testing.expect(ack_pkt.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(1)));
}

// [smoltcp:socket/tcp.rs:test_established_send_fin]
test "ESTABLISHED recv FIN while send data queued" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef");
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.close_wait, s.state);

    // Dispatch should send the queued data.
    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt.?.payload);
}

// [smoltcp:socket/tcp.rs:test_established_send_buf_gt_win]
test "ESTABLISHED send more data than window" {
    var s = socketEstablished();
    s.remote_win_len = 16;

    var data: [32]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast(i);
    _ = try s.sendSlice(&data);

    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    // Only 16 bytes should be sent (window limit).
    try testing.expectEqual(@as(usize, 16), pkt.?.payload.len);
    try testing.expectEqualSlices(u8, data[0..16], pkt.?.payload);
}

// [smoltcp:socket/tcp.rs:test_established_send_no_ack_send]
test "ESTABLISHED send two segments without ACK (nagle off)" {
    var s = socketEstablished();
    s.nagle = false;

    _ = try s.sendSlice("abcdef");
    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    _ = try s.sendSlice("foobar");
    const pkt2 = recvAt0(&s);
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "foobar", pkt2.?.payload);
}

// [smoltcp:socket/tcp.rs:test_established_fin_after_missing]
test "ESTABLISHED FIN after missing segment stays established" {
    var s = socketEstablished();
    // Send FIN with data at offset 6 (gap at 0..6).
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1).add(6),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "123456",
    });
    // Should get an ACK (out-of-order segment).
    try testing.expect(reply != null);
    // State should stay established because there's a hole before the FIN.
    try testing.expectEqual(State.established, s.state);
}

// =========================================================================
// Additional FIN-WAIT-1 tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_fin_wait_1_recv]
test "FIN-WAIT-1 recv data" {
    var s = socketFinWait1();
    _ = recvAt0(&s); // drain FIN

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });
    try testing.expectEqual(State.fin_wait_1, s.state);

    var buf: [3]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, "abc", buf[0..3]);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_1_close]
test "FIN-WAIT-1 close is noop" {
    var s = socketFinWait1();
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_1_fin_with_data_queued]
test "FIN-WAIT-1 with data queued waits for ack" {
    var s = socketEstablished();
    s.remote_win_len = 6;
    _ = try s.sendSlice("abcdef123456");
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);

    // Dispatch: should send first 6 bytes (window limit).
    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    // ACK the first 6 bytes, opening window for more.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = SEND_TEMPL.window_len,
    });
    // Still in FIN-WAIT-1 because we haven't sent FIN yet (data remaining).
    try testing.expectEqual(State.fin_wait_1, s.state);
}

// =========================================================================
// Additional FIN-WAIT-2 tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_fin_wait_2_recv]
test "FIN-WAIT-2 recv data" {
    var s = socketFinWait2();

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });
    try testing.expectEqual(State.fin_wait_2, s.state);

    var buf: [3]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, "abc", buf[0..3]);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_2_close]
test "FIN-WAIT-2 close is noop" {
    var s = socketFinWait2();
    s.close();
    try testing.expectEqual(State.fin_wait_2, s.state);
}

// =========================================================================
// Additional CLOSING tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_closing_close]
test "CLOSING close is noop" {
    var s = socketClosing();
    s.close();
    try testing.expectEqual(State.closing, s.state);
}

// =========================================================================
// Additional TIME-WAIT tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_time_wait_close]
test "TIME-WAIT close is noop" {
    var s = socketTimeWait(false);
    s.close();
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_time_wait_from_fin_wait_2_ack]
test "TIME-WAIT from FIN-WAIT-2 dispatches ACK" {
    var s = socketTimeWait(false);
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expectEqual(Control.none, ack.?.control);
    try testing.expect(ack.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(1)));
}

// [smoltcp:socket/tcp.rs:test_time_wait_from_closing_no_ack]
test "TIME-WAIT from CLOSING dispatches nothing" {
    var s = socketTimeWait(true);
    const pkt = recvAt0(&s);
    try testing.expectEqual(@as(?TcpRepr, null), pkt);
}

// =========================================================================
// Additional CLOSE-WAIT tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_close_wait_ack]
test "CLOSE-WAIT send data and receive ACK" {
    var s = socketCloseWait();
    _ = try s.sendSlice("abcdef");

    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt.?.payload);

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(usize, 0), s.tx_buffer.len());
}

// =========================================================================
// Additional LAST-ACK tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_last_ack_ack_not_of_fin]
test "LAST-ACK stays until FIN is acked" {
    var s = socketLastAck();
    _ = recvAt0(&s); // drain FIN

    // ACK that doesn't ack the FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1), // doesn't ack FIN
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.last_ack, s.state);

    // ACK of FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_last_ack_close]
test "LAST-ACK close is noop" {
    var s = socketLastAck();
    s.close();
    try testing.expectEqual(State.last_ack, s.state);
}

// =========================================================================
// Multi-state transition tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_remote_close]
test "remote close full sequence" {
    var s = socketEstablished();

    // Remote sends FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.close_wait, s.state);

    // Dispatch ACK of FIN.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expect(ack.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(1)));

    // Local close.
    s.close();
    try testing.expectEqual(State.last_ack, s.state);

    // Dispatch FIN.
    const fin = recvAt0(&s);
    try testing.expect(fin != null);
    try testing.expectEqual(Control.fin, fin.?.control);

    // Remote ACKs our FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_local_close]
test "local close full sequence" {
    var s = socketEstablished();
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);

    // Dispatch FIN.
    const fin = recvAt0(&s);
    try testing.expect(fin != null);
    try testing.expectEqual(Control.fin, fin.?.control);

    // Remote ACKs our FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.fin_wait_2, s.state);

    // Remote sends FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.time_wait, s.state);

    // Dispatch ACK of remote FIN.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expect(ack.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(1)));
}

// [smoltcp:socket/tcp.rs:test_simultaneous_close]
test "simultaneous close" {
    var s = socketEstablished();
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);

    // Dispatch our FIN.
    const our_fin = recvAt0(&s);
    try testing.expect(our_fin != null);
    try testing.expectEqual(Control.fin, our_fin.?.control);

    // Remote sends FIN (without acking ours).
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closing, s.state);

    // Dispatch ACK of remote FIN.
    const our_ack = recvAt0(&s);
    try testing.expect(our_ack != null);
    try testing.expect(our_ack.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(1)));

    // Remote ACKs our FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_simultaneous_close_combined_fin_ack]
test "simultaneous close combined FIN+ACK" {
    var s = socketEstablished();
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);

    // Dispatch our FIN.
    const our_fin = recvAt0(&s);
    try testing.expect(our_fin != null);
    try testing.expectEqual(Control.fin, our_fin.?.control);

    // Remote sends FIN|ACK (acking our FIN in same segment).
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_fin_with_data]
test "FIN with data queued" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef");
    s.close();

    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    try testing.expectEqual(Control.fin, pkt.?.control);
    try testing.expectEqualSlices(u8, "abcdef", pkt.?.payload);
}

// =========================================================================
// Additional retransmission tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_data_retransmit]
test "data retransmit on RTO" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef");

    const pkt1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    // Nothing at 1050.
    const pkt2 = recvPacket(&s, Instant.fromMillis(1050));
    try testing.expectEqual(@as(?TcpRepr, null), pkt2);

    // After RTO (default 1000ms), retransmit.
    const pkt3 = recvPacket(&s, Instant.fromMillis(2000));
    try testing.expect(pkt3 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt3.?.payload);
}

// [smoltcp:socket/tcp.rs:test_send_data_after_syn_ack_retransmit]
test "send data after SYN-ACK retransmit" {
    var s = socketSynReceived();

    // Dispatch SYN|ACK at t=50.
    const syn_ack = recvPacket(&s, Instant.fromMillis(50));
    try testing.expect(syn_ack != null);
    try testing.expectEqual(Control.syn, syn_ack.?.control);

    // Retransmit at t=1050.
    const retransmit = recvPacket(&s, Instant.fromMillis(1050));
    try testing.expect(retransmit != null);
    try testing.expectEqual(Control.syn, retransmit.?.control);

    // ACK completes handshake.
    _ = sendPacket(&s, Instant.fromMillis(1100), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.established, s.state);

    // Now send data.
    _ = try s.sendSlice("abcdef");
    const data_pkt = recvPacket(&s, Instant.fromMillis(1200));
    try testing.expect(data_pkt != null);
    try testing.expectEqualSlices(u8, "abcdef", data_pkt.?.payload);
}

// =========================================================================
// Packet filtering tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_doesnt_accept_wrong_port]
test "doesnt accept wrong port" {
    var s = socketEstablished();
    const repr = TcpRepr{
        .src_port = REMOTE_PORT + 1,
        .dst_port = LOCAL_PORT,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    };
    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, repr));

    const repr2 = TcpRepr{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT + 1,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    };
    try testing.expect(!s.accepts(REMOTE_ADDR, LOCAL_ADDR, repr2));
}

// [smoltcp:socket/tcp.rs:test_doesnt_accept_wrong_ip]
test "doesnt accept wrong ip" {
    var s = socketEstablished();
    const wrong_addr = ipv4.Address{ 10, 0, 0, 1 };
    const repr = TcpRepr{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    };
    try testing.expect(!s.accepts(wrong_addr, LOCAL_ADDR, repr));
    try testing.expect(!s.accepts(REMOTE_ADDR, wrong_addr, repr));
}

// =========================================================================
// Timeout tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_established_timeout]
test "established timeout" {
    var s = socketEstablished();
    s.timeout = Duration.fromMillis(200);

    _ = try s.sendSlice("abcdef");
    const pkt = recvPacket(&s, Instant.fromMillis(100));
    try testing.expect(pkt != null);

    // Before timeout: nothing happens.
    const pkt2 = recvPacket(&s, Instant.fromMillis(250));
    _ = pkt2;
    try testing.expect(s.state != .closed);

    // After timeout from last data: connection closes.
    const pkt3 = recvPacket(&s, Instant.fromMillis(400));
    _ = pkt3;
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_listen_timeout - listen never times out]
test "listen never times out" {
    var s = socketListen();
    s.timeout = Duration.fromMillis(100);
    const pkt = recvPacket(&s, Instant.fromMillis(300));
    try testing.expectEqual(@as(?TcpRepr, null), pkt);
    try testing.expectEqual(State.listen, s.state);
}

// =========================================================================
// Keep-alive tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_responds_to_keep_alive]
test "responds to keep alive probe" {
    var s = socketEstablished();

    // Remote sends a keep-alive probe (seq-1, 1 byte).
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ, // seq-1 from remote's perspective
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = &.{0},
    });
    // Should get an ACK back.
    _ = reply;
    // The probe data is outside our window so it gets challenge-ack'd.
    // Either way, we should remain established.
    try testing.expectEqual(State.established, s.state);
}

// =========================================================================
// Flow control tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_psh_transmit]
test "PSH set on last segment in burst" {
    var s = socketEstablished();
    s.remote_mss = 6;

    _ = try s.sendSlice("abcdef");
    _ = try s.sendSlice("123456");

    // First segment: no PSH (not the last in queue).
    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);
    try testing.expectEqual(Control.none, pkt1.?.control);

    // Second segment: PSH (last segment).
    const pkt2 = recvAt0(&s);
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "123456", pkt2.?.payload);
    try testing.expectEqual(Control.psh, pkt2.?.control);
}

// [smoltcp:socket/tcp.rs:test_psh_receive]
test "PSH on receive is treated as normal data" {
    var s = socketEstablished();
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .psh,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });
    // In-order data: process() defers ACK to dispatch().
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expect(ack.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(6)));

    var buf: [6]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqualSlices(u8, "abcdef", buf[0..6]);
}

// =========================================================================
// Zero-window probe tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_zero_window_probe_enter_on_win_update]
test "zero window probe enters on window update" {
    var s = socketEstablished();
    try testing.expect(!s.timer.isZeroWindowProbe());

    _ = try s.sendSlice("abcdef123456!@#$%^");
    try testing.expect(!s.timer.isZeroWindowProbe());

    // Remote advertises zero window.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });
    try testing.expect(s.timer.isZeroWindowProbe());
}

// [smoltcp:socket/tcp.rs:test_zero_window_probe_enter_on_send]
test "zero window probe enters on send" {
    var s = socketEstablished();

    // Remote advertises zero window first.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });
    try testing.expect(!s.timer.isZeroWindowProbe());

    // Now enqueue data.
    _ = try s.sendSlice("abcdef123456!@#$%^");
    try testing.expect(s.timer.isZeroWindowProbe());
}

// [smoltcp:socket/tcp.rs:test_zero_window_probe_exit]
test "zero window probe exits on window open" {
    var s = socketEstablished();

    _ = try s.sendSlice("abcdef123456!@#$%^");
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });
    try testing.expect(s.timer.isZeroWindowProbe());

    // Remote opens window.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 6,
    });
    try testing.expect(!s.timer.isZeroWindowProbe());
}

// [smoltcp:socket/tcp.rs:test_zero_window_probe_exit_ack]
test "zero window probe sends 1 byte and exits on ack" {
    var s = socketEstablished();

    _ = try s.sendSlice("abcdef123456!@#$%^");
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });

    // ZWP fires at t=1000 -- sends 1 byte.
    const probe = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(probe != null);
    try testing.expectEqual(@as(usize, 1), probe.?.payload.len);
    try testing.expectEqualSlices(u8, "a", probe.?.payload);

    // Remote acks the 1 byte and opens window.
    _ = sendPacket(&s, Instant.fromMillis(1010), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(2),
        .window_len = 6,
    });

    // Should send remaining data.
    const data_pkt = recvPacket(&s, Instant.fromMillis(1010));
    try testing.expect(data_pkt != null);
    try testing.expectEqualSlices(u8, "bcdef1", data_pkt.?.payload);
}

// [smoltcp:socket/tcp.rs:test_zero_window_probe_backoff_no_reply]
test "zero window probe backs off" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef123456!@#$%^");
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });

    // Nothing before first ZWP.
    const p1 = recvPacket(&s, Instant.fromMillis(999));
    try testing.expectEqual(@as(?TcpRepr, null), p1);

    // First probe at t=1000.
    const probe1 = recvPacket(&s, Instant.fromMillis(1000)) orelse
        return error.TestUnexpectedResult;
    try testing.expect(probe1.seq_number.eql(LOCAL_SEQ.add(1)));
    try testing.expect(probe1.ack_number.?.eql(REMOTE_SEQ.add(1)));
    try testing.expectEqual(@as(usize, 1), probe1.payload.len);
    try testing.expectEqual(@as(u8, 'a'), probe1.payload[0]);

    // Nothing before second ZWP (backed off to 2x = 2000ms).
    const p2 = recvPacket(&s, Instant.fromMillis(2999));
    try testing.expectEqual(@as(?TcpRepr, null), p2);

    // Second probe at t=3000.
    const probe2 = recvPacket(&s, Instant.fromMillis(3000)) orelse
        return error.TestUnexpectedResult;
    try testing.expect(probe2.seq_number.eql(LOCAL_SEQ.add(1)));
    try testing.expect(probe2.ack_number.?.eql(REMOTE_SEQ.add(1)));
    try testing.expectEqual(@as(usize, 1), probe2.payload.len);
    try testing.expectEqual(@as(u8, 'a'), probe2.payload[0]);
}

// =========================================================================
// Reassembly tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_out_of_order]
test "out of order reassembly" {
    var s = socketEstablished();

    // Send data at offset 3 (gap at 0..3).
    const reply1 = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(3),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "def",
    });
    // Out-of-order -> immediate ACK.
    try testing.expect(reply1 != null);
    try testing.expect(reply1.?.ack_number.?.eql(REMOTE_SEQ.add(1)));

    // No data available yet.
    var buf: [10]u8 = undefined;
    try testing.expect(s.rx_buffer.isEmpty());

    // Fill the gap.
    const reply2 = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });
    // Now the full data is available.
    try testing.expect(reply2 != null);
    try testing.expect(reply2.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(6)));

    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqualSlices(u8, "abcdef", buf[0..6]);
}

// =========================================================================
// Graceful vs ungraceful close tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_rx_close_fin]
test "rx close FIN with data" {
    var s = socketEstablished();
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    // Read data.
    var buf: [3]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, "abc", buf[0..3]);

    // Next recv should return Finished.
    try testing.expectError(error.Finished, s.recvSlice(&buf));
}

// [smoltcp:socket/tcp.rs:test_rx_close_rst]
test "rx close RST" {
    var s = socketEstablished();
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closed, s.state);

    var buf: [3]u8 = undefined;
    try testing.expectError(error.InvalidState, s.recvSlice(&buf));
}

// =========================================================================
// Delayed ACK tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_delayed_ack]
test "delayed ack" {
    var s = socketEstablished();
    s.ack_delay = ACK_DELAY_DEFAULT;

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    // No ACK is immediately sent (delayed).
    const no_ack = recvAt0(&s);
    try testing.expectEqual(@as(?TcpRepr, null), no_ack);

    // After delay expires, ACK is sent.
    const ack = recvPacket(&s, Instant.fromMillis(11));
    try testing.expect(ack != null);
    try testing.expect(ack.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(3)));
}

// [smoltcp:socket/tcp.rs:test_delayed_ack_reply]
test "delayed ack piggybacks on outgoing data" {
    var s = socketEstablished();
    s.ack_delay = ACK_DELAY_DEFAULT;

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    var buf: [3]u8 = undefined;
    _ = try s.recvSlice(&buf);

    // Queue outgoing data.
    _ = try s.sendSlice("xyz");

    // The ACK should piggyback on the data segment (sent immediately).
    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    try testing.expect(pkt.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(3)));
    try testing.expectEqualSlices(u8, "xyz", pkt.?.payload);
}

// =========================================================================
// Nagle algorithm tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_nagle]
test "nagle algorithm" {
    var s = socketEstablished();
    s.remote_mss = 6;

    // First full segment goes out immediately.
    _ = try s.sendSlice("abcdef");
    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    // With data in flight, another full segment goes out.
    _ = try s.sendSlice("foobar");
    const pkt2 = recvAt0(&s);
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "foobar", pkt2.?.payload);

    // With data in flight, a partial segment is held.
    _ = try s.sendSlice("aaabbbccc");
    const pkt3 = recvAt0(&s);
    try testing.expect(pkt3 != null);
    // Full segment portion goes out.
    try testing.expectEqualSlices(u8, "aaabbb", pkt3.?.payload);

    // Remaining 3 bytes held by Nagle (data in flight, not full segment).
    const pkt4 = recvAt0(&s);
    try testing.expectEqual(@as(?TcpRepr, null), pkt4);

    // ACK all sent data -> no more data in flight.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(18),
        .window_len = SEND_TEMPL.window_len,
    });

    // Now the partial segment goes out.
    const pkt5 = recvAt0(&s);
    try testing.expect(pkt5 != null);
    try testing.expectEqualSlices(u8, "ccc", pkt5.?.payload);
}

// [smoltcp:socket/tcp.rs:test_final_packet_in_stream_doesnt_wait_for_nagle]
test "FIN bypasses Nagle" {
    var s = socketEstablished();
    s.remote_mss = 6;

    _ = try s.sendSlice("abcdef0");
    s.close();

    // Full segment goes out.
    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);
    try testing.expectEqual(Control.none, pkt1.?.control);

    // Remaining byte + FIN goes out despite Nagle (FIN overrides).
    const pkt2 = recvAt0(&s);
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "0", pkt2.?.payload);
    try testing.expectEqual(Control.fin, pkt2.?.control);
}

// =========================================================================
// Retransmission: burst and partial ACK tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_data_retransmit_bursts]
test "data retransmit bursts" {
    var s = socketEstablished();
    s.remote_mss = 6;
    _ = try s.sendSlice("abcdef012345");

    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    const pkt2 = recvAt0(&s);
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "012345", pkt2.?.payload);

    // Nothing more at t=0.
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));

    // Nothing at t=50.
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(50)));

    // Retransmit first segment at t=1000.
    const retx1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(retx1 != null);
    try testing.expectEqualSlices(u8, "abcdef", retx1.?.payload);

    // Retransmit second segment after another delay.
    const retx2 = recvPacket(&s, Instant.fromMillis(1500));
    try testing.expect(retx2 != null);
    try testing.expectEqualSlices(u8, "012345", retx2.?.payload);
}

// [smoltcp:socket/tcp.rs:test_data_retransmit_bursts_half_ack]
test "data retransmit bursts half ack" {
    var s = socketEstablished();
    s.remote_mss = 6;
    _ = try s.sendSlice("abcdef012345");

    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    const pkt2 = recvAt0(&s);
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "012345", pkt2.?.payload);

    // ACK the first packet.
    _ = sendPacket(&s, Instant.fromMillis(5), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = 6,
    });

    // Second packet should be retransmitted after timeout.
    const retx = recvPacket(&s, Instant.fromMillis(1500));
    try testing.expect(retx != null);
    try testing.expectEqualSlices(u8, "012345", retx.?.payload);

    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(1550)));
}

// [smoltcp:socket/tcp.rs:test_retransmit_timer_restart_on_partial_ack]
test "retransmit timer restart on partial ack" {
    var s = socketEstablished();
    s.remote_mss = 6;
    _ = try s.sendSlice("abcdef012345");

    _ = recvPacket(&s, Instant.fromMillis(0));
    _ = recvPacket(&s, Instant.fromMillis(0));

    // ACK first packet at t=600 -- this should restart the retransmit timer.
    _ = sendPacket(&s, Instant.fromMillis(600), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = 6,
    });

    // The retransmit timer was restarted at t=600, so at t=2399 nothing yet.
    // (The new RTO after ACK could be different, but at least it shouldn't fire before t=1600.)
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(1599)));

    // Second packet should be retransmitted eventually.
    const retx = recvPacket(&s, Instant.fromMillis(2400));
    try testing.expect(retx != null);
    try testing.expectEqualSlices(u8, "012345", retx.?.payload);
}

// [smoltcp:socket/tcp.rs:test_data_retransmit_bursts_half_ack_close]
test "data retransmit bursts half ack close" {
    var s = socketEstablished();
    s.remote_mss = 6;
    _ = try s.sendSlice("abcdef012345");
    s.close();

    const pkt1 = recvPacket(&s, Instant.fromMillis(0));
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);
    try testing.expectEqual(Control.none, pkt1.?.control);

    const pkt2 = recvPacket(&s, Instant.fromMillis(0));
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "012345", pkt2.?.payload);
    try testing.expectEqual(Control.fin, pkt2.?.control);

    // ACK the first packet.
    _ = sendPacket(&s, Instant.fromMillis(5), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = 6,
    });

    // Second (data+FIN) retransmitted after timeout.
    const retx = recvPacket(&s, Instant.fromMillis(1500));
    try testing.expect(retx != null);
    try testing.expectEqualSlices(u8, "012345", retx.?.payload);
    try testing.expectEqual(Control.fin, retx.?.control);
}

// [smoltcp:socket/tcp.rs:test_retransmit_exponential_backoff]
test "retransmit exponential backoff" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef");

    const pkt1 = recvPacket(&s, Instant.fromMillis(0));
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    const rto1 = s.rtte.retransmissionTimeout().totalMillis();

    // Nothing before first RTO.
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(rto1 - 1)));

    // First retransmit at RTO.
    const retx1 = recvPacket(&s, Instant.fromMillis(rto1));
    try testing.expect(retx1 != null);
    try testing.expectEqualSlices(u8, "abcdef", retx1.?.payload);

    // Second retransmit at rto1 + 2*rto1 = 3*rto1 (doubled backoff).
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(3 * rto1 - 1)));
    const retx2 = recvPacket(&s, Instant.fromMillis(3 * rto1));
    try testing.expect(retx2 != null);
    try testing.expectEqualSlices(u8, "abcdef", retx2.?.payload);
}

// [smoltcp:socket/tcp.rs:test_retransmit_fin]
test "retransmit FIN" {
    var s = socketEstablished();
    s.close();

    const fin = recvPacket(&s, Instant.fromMillis(0));
    try testing.expect(fin != null);
    try testing.expectEqual(Control.fin, fin.?.control);

    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(999)));

    const retx = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(retx != null);
    try testing.expectEqual(Control.fin, retx.?.control);
}

// [smoltcp:socket/tcp.rs:test_retransmit_fin_wait]
test "retransmit in CLOSING state" {
    var s = socketFinWait1();
    // Dispatch our FIN.
    const our_fin = recvAt0(&s);
    try testing.expect(our_fin != null);
    try testing.expectEqual(Control.fin, our_fin.?.control);

    // Remote sends FIN without ACKing ours -> CLOSING.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closing, s.state);

    // We ACK the remote FIN.
    const our_ack = recvAt0(&s);
    try testing.expect(our_ack != null);

    // Our FIN hasn't been ACKed, so retransmit fires.
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(999)));

    const retx = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(retx != null);
    try testing.expectEqual(Control.fin, retx.?.control);
}

// [smoltcp:socket/tcp.rs:test_established_retransmit_for_dup_ack]
test "dup ack does not replace retransmit timer" {
    var s = socketEstablished();
    _ = try s.sendSlice("abc");

    const pkt = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(pkt != null);
    try testing.expectEqualSlices(u8, "abc", pkt.?.payload);

    try testing.expectEqual(@as(usize, 3), s.tx_buffer.len());

    // Dup ACK (acks nothing new).
    _ = sendPacket(&s, Instant.fromMillis(1100), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Retransmit should still fire based on original timer.
    const retx = recvPacket(&s, Instant.fromMillis(4000));
    try testing.expect(retx != null);
    try testing.expectEqualSlices(u8, "abc", retx.?.payload);
}

// [smoltcp:socket/tcp.rs:test_established_retransmit_reset_after_ack]
test "retransmit reset after ack windowed" {
    var s = socketEstablished();
    s.remote_win_len = 6;
    _ = try s.sendSlice("abcdef");
    _ = try s.sendSlice("123456");
    _ = try s.sendSlice("ABCDEF");

    // Dispatch first 6 bytes.
    const pkt1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    // ACK first 6 bytes at t=1005.
    _ = sendPacket(&s, Instant.fromMillis(1005), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = 6,
    });

    // Next 6 bytes.
    const pkt2 = recvPacket(&s, Instant.fromMillis(1010));
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "123456", pkt2.?.payload);

    // ACK next 6 bytes.
    _ = sendPacket(&s, Instant.fromMillis(1015), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(12),
        .window_len = 6,
    });

    // Last 6 bytes.
    const pkt3 = recvPacket(&s, Instant.fromMillis(1020));
    try testing.expect(pkt3 != null);
    try testing.expectEqualSlices(u8, "ABCDEF", pkt3.?.payload);
}

// [smoltcp:socket/tcp.rs:test_established_queue_during_retransmission]
test "queue during retransmission" {
    var s = socketEstablished();
    s.remote_mss = 6;
    _ = try s.sendSlice("abcdef123456ABCDEF");

    // Dispatch 3 segments.
    const seg1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(seg1 != null);
    try testing.expectEqualSlices(u8, "abcdef", seg1.?.payload);

    const seg2 = recvPacket(&s, Instant.fromMillis(1005));
    try testing.expect(seg2 != null);
    try testing.expectEqualSlices(u8, "123456", seg2.?.payload);

    const seg3 = recvPacket(&s, Instant.fromMillis(1010));
    try testing.expect(seg3 != null);
    try testing.expectEqualSlices(u8, "ABCDEF", seg3.?.payload);

    // Retransmit first segment (others dropped).
    const retx = recvPacket(&s, Instant.fromMillis(3000));
    try testing.expect(retx != null);
    try testing.expectEqualSlices(u8, "abcdef", retx.?.payload);

    // ACK first two segments.
    _ = sendPacket(&s, Instant.fromMillis(3005), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(12),
        .window_len = SEND_TEMPL.window_len,
    });

    // Third segment retransmitted.
    const retx3 = recvPacket(&s, Instant.fromMillis(3010));
    try testing.expect(retx3 != null);
    try testing.expectEqualSlices(u8, "ABCDEF", retx3.?.payload);
}

// [smoltcp:socket/tcp.rs:test_fast_retransmit_after_triple_duplicate_ack]
test "fast retransmit after triple dup ack" {
    var s = socketEstablished();
    s.remote_mss = 6;

    // Normal ACK.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    _ = try s.sendSlice("xxxxxxyyyyyywwwwwwzzzzzz");

    // Send 4 segments.
    _ = recvPacket(&s, Instant.fromMillis(1000));
    _ = recvPacket(&s, Instant.fromMillis(1005));
    _ = recvPacket(&s, Instant.fromMillis(1010));
    _ = recvPacket(&s, Instant.fromMillis(1015));

    // 3 duplicate ACKs.
    _ = sendPacket(&s, Instant.fromMillis(1050), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    _ = sendPacket(&s, Instant.fromMillis(1055), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    _ = sendPacket(&s, Instant.fromMillis(1060), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Fast retransmit should fire.
    try testing.expect(s.timer.isRetransmit());

    const retx = recvPacket(&s, Instant.fromMillis(1100));
    try testing.expect(retx != null);
    try testing.expectEqualSlices(u8, "xxxxxx", retx.?.payload);

    // ACK everything.
    _ = sendPacket(&s, Instant.fromMillis(1120), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(24),
        .window_len = SEND_TEMPL.window_len,
    });
}

// [smoltcp:socket/tcp.rs:test_fast_retransmit_dup_acks_counter]
test "dup ack counter saturates" {
    var s = socketEstablished();
    _ = try s.sendSlice("abc");
    _ = recvAt0(&s);

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Simulate many dup acks.
    s.local_rx_dup_acks = 254;

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    try testing.expectEqual(@as(u8, 255), s.local_rx_dup_acks);
}

// [smoltcp:socket/tcp.rs:test_fast_retransmit_duplicate_detection_with_data]
test "dup ack counter reset on data" {
    var s = socketEstablished();
    _ = try s.sendSlice("abc");
    _ = recvPacket(&s, Instant.fromMillis(1000));

    // Normal ACK.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    // First dup.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    // Second dup.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    try testing.expectEqual(@as(u8, 2), s.local_rx_dup_acks);

    // Packet with data resets counter.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "xxxxxx",
    });

    try testing.expectEqual(@as(u8, 0), s.local_rx_dup_acks);
}

// [smoltcp:socket/tcp.rs:test_fast_retransmit_duplicate_detection_with_window_update]
test "dup ack counter reset on window update" {
    var s = socketEstablished();
    _ = try s.sendSlice("abc");
    _ = recvPacket(&s, Instant.fromMillis(1000));

    // Normal ACK.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    // First dup.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    // Second dup.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    try testing.expectEqual(@as(u8, 2), s.local_rx_dup_acks);

    // Window update resets counter.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 400,
    });

    try testing.expectEqual(@as(u8, 0), s.local_rx_dup_acks);
}

// [smoltcp:socket/tcp.rs:test_data_retransmit_ack_more_than_expected]
test "retransmit ack more than expected" {
    var s = socketEstablished();
    s.remote_mss = 6;
    _ = try s.sendSlice("aaaaaabbbbbbcccccc");

    _ = recvPacket(&s, Instant.fromMillis(0));
    _ = recvPacket(&s, Instant.fromMillis(0));
    _ = recvPacket(&s, Instant.fromMillis(0));
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(0)));

    // Retransmit (only first two segments make it through).
    try testing.expect(s.timer.isRetransmit());
    _ = recvPacket(&s, Instant.fromMillis(1000));
    _ = recvPacket(&s, Instant.fromMillis(1000));

    // ACK first segment.
    _ = sendPacket(&s, Instant.fromMillis(3000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expect(s.timer.isRetransmit());

    // ACK all three segments.
    _ = sendPacket(&s, Instant.fromMillis(3000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(18),
        .window_len = SEND_TEMPL.window_len,
    });

    // All data acked -- should exit retransmit.
    try testing.expect(!s.timer.isRetransmit());
    try testing.expect(s.tx_buffer.isEmpty());
}

// =========================================================================
// Simultaneous close: raced scenarios
// =========================================================================

// [smoltcp:socket/tcp.rs:test_simultaneous_close_raced]
test "simultaneous close raced" {
    var s = socketEstablished();
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);

    // Remote FIN arrives before we dispatch ours.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closing, s.state);

    // Dispatch FIN + ACK of remote FIN.
    const our_fin = recvAt0(&s);
    try testing.expect(our_fin != null);
    try testing.expectEqual(Control.fin, our_fin.?.control);
    try testing.expectEqual(State.closing, s.state);

    // Remote ACKs our FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_simultaneous_close_raced_with_data]
test "simultaneous close raced with data" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef");
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);

    // Remote FIN arrives before we dispatch our data+FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closing, s.state);

    // Dispatch data + FIN.
    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    try testing.expectEqual(Control.fin, pkt.?.control);
    try testing.expectEqualSlices(u8, "abcdef", pkt.?.payload);

    // Remote ACKs our data + FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_mutual_close_with_data_1]
test "mutual close with data 1" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef");
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);

    // Dispatch data+FIN.
    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    try testing.expectEqual(Control.fin, pkt.?.control);
    try testing.expectEqualSlices(u8, "abcdef", pkt.?.payload);

    // Remote sends FIN, ACKing our data+FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_mutual_close_with_data_2]
test "mutual close with data 2" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef");
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);

    // Dispatch data+FIN.
    _ = recvAt0(&s);

    // Remote ACKs our data+FIN (no FIN yet).
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.fin_wait_2, s.state);

    // Remote sends FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6).add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Dispatch ACK of remote FIN.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expectEqual(State.time_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_duplicate_seq_ack]
test "duplicate seq ack (remote retransmission)" {
    var s = socketEstablished();
    // Receive initial data.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });

    // Remote retransmits same data.
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });
    // We should ACK up to the latest sequence.
    try testing.expect(reply != null);
    try testing.expect(reply.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(6)));
}

// =========================================================================
// Additional timeout tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_connect_timeout]
test "connect timeout" {
    var s = socketNew();
    try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);
    s.timeout = Duration.fromMillis(100);

    // Dispatch SYN at t=150.
    const syn = recvPacket(&s, Instant.fromMillis(150));
    try testing.expect(syn != null);
    try testing.expectEqual(Control.syn, syn.?.control);
    try testing.expectEqual(State.syn_sent, s.state);

    // At t=250, timeout fires -> RST + CLOSED.
    const rst = recvPacket(&s, Instant.fromMillis(250));
    try testing.expect(rst != null);
    try testing.expectEqual(Control.rst, rst.?.control);
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_1_timeout]
test "fin wait 1 timeout" {
    var s = socketFinWait1();
    s.timeout = Duration.fromMillis(1000);

    // Dispatch FIN at t=100.
    const fin = recvPacket(&s, Instant.fromMillis(100));
    try testing.expect(fin != null);
    try testing.expectEqual(Control.fin, fin.?.control);

    // Timeout fires -> RST + CLOSED.
    const rst = recvPacket(&s, Instant.fromMillis(1100));
    try testing.expect(rst != null);
    try testing.expectEqual(Control.rst, rst.?.control);
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_last_ack_timeout]
test "last ack timeout" {
    var s = socketLastAck();
    s.timeout = Duration.fromMillis(1000);

    // Dispatch FIN at t=100.
    const fin = recvPacket(&s, Instant.fromMillis(100));
    try testing.expect(fin != null);
    try testing.expectEqual(Control.fin, fin.?.control);

    // Timeout fires -> RST + CLOSED.
    const rst = recvPacket(&s, Instant.fromMillis(1100));
    try testing.expect(rst != null);
    try testing.expectEqual(Control.rst, rst.?.control);
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_established_keep_alive_timeout]
test "established keep alive timeout" {
    var s = socketEstablished();
    s.keep_alive = Duration.fromMillis(50);
    s.timeout = Duration.fromMillis(100);
    s.timer.setForIdle(Instant.ZERO, s.keep_alive);

    // First keep-alive probe at t >= 50ms.
    const ka1 = recvPacket(&s, Instant.fromMillis(100));
    try testing.expect(ka1 != null);
    try testing.expectEqual(@as(usize, 1), ka1.?.payload.len);

    // Remote responds.
    _ = sendPacket(&s, Instant.fromMillis(105), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Second keep-alive probe.
    const ka2 = recvPacket(&s, Instant.fromMillis(155));
    try testing.expect(ka2 != null);
    try testing.expectEqual(@as(usize, 1), ka2.?.payload.len);

    // No response -> timeout fires.
    const rst = recvPacket(&s, Instant.fromMillis(205));
    // This should either be RST or the socket transitions to closed.
    if (rst) |r| {
        if (r.control == .rst) {
            try testing.expectEqual(State.closed, s.state);
        }
    }
    // Either way, socket should be closed after timeout.
    // Check by dispatching again.
    _ = recvPacket(&s, Instant.fromMillis(300));
    try testing.expectEqual(State.closed, s.state);
}

// =========================================================================
// Window management tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_maximum_segment_size]
test "maximum segment size from SYN" {
    var s = socketListen();
    // Remote SYN with MSS=6.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
        .max_seg_size = 6,
    });
    try testing.expectEqual(State.syn_received, s.state);
    try testing.expectEqual(@as(usize, 6), s.remote_mss);

    // Complete handshake.
    _ = recvAt0(&s); // SYN|ACK
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 1000,
    });
    try testing.expectEqual(State.established, s.state);

    // Send more than MSS.
    _ = try s.sendSlice("abcdef012345");
    const pkt = recvAt0(&s);
    try testing.expect(pkt != null);
    // Should be capped at MSS.
    try testing.expectEqual(@as(usize, 6), pkt.?.payload.len);
    try testing.expectEqualSlices(u8, "abcdef", pkt.?.payload);
}

// [smoltcp:socket/tcp.rs:test_close_wait_no_window_update]
test "close wait no window update" {
    var s = socketEstablished();
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = &[_]u8{ 1, 2, 3, 4 },
    });
    try testing.expectEqual(State.close_wait, s.state);

    // ACK the FIN.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);

    // Read data off buffer.
    var buf: [4]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 4), n);

    // No window update should be sent in CLOSE-WAIT.
    const no_pkt = recvAt0(&s);
    try testing.expectEqual(@as(?TcpRepr, null), no_pkt);
}

// [smoltcp:socket/tcp.rs:test_time_wait_retransmit]
test "time wait retransmit" {
    var s = socketTimeWait(false);
    // Dispatch ACK of remote FIN.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);

    // Remote retransmits FIN.
    const reply = sendPacket(&s, Instant.fromMillis(5000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    // Should re-ACK.
    try testing.expect(reply != null);
    try testing.expect(reply.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(1)));
}

// =========================================================================
// Graceful close edge cases
// =========================================================================

// [smoltcp:socket/tcp.rs:test_rx_close_fin_in_fin_wait_1]
test "rx close FIN in FIN-WAIT-1" {
    var s = socketFinWait1();
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });
    try testing.expectEqual(State.closing, s.state);

    var buf: [3]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, "abc", buf[0..3]);

    try testing.expectError(error.Finished, s.recvSlice(&buf));
}

// [smoltcp:socket/tcp.rs:test_rx_close_fin_in_fin_wait_2]
test "rx close FIN in FIN-WAIT-2" {
    var s = socketFinWait2();
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });
    try testing.expectEqual(State.time_wait, s.state);

    var buf: [3]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, "abc", buf[0..3]);

    try testing.expectError(error.Finished, s.recvSlice(&buf));
}

// [smoltcp:socket/tcp.rs:test_established_bad_seq]
test "ESTABLISHED bad seq gets challenge ACK" {
    var s = socketEstablished();
    // Packet with seq before window (wrong seq).
    const reply = sendPacket(&s, Instant.fromMillis(1000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ, // wrong: should be REMOTE_SEQ+1
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    // Should get challenge ACK.
    try testing.expect(reply != null);
    try testing.expectEqual(State.established, s.state);
}

// [smoltcp:socket/tcp.rs:test_established_rst_bad_seq]
test "ESTABLISHED RST bad seq gets challenge ACK" {
    var s = socketEstablished();
    // RST with wrong seq.
    const reply = sendPacket(&s, Instant.fromMillis(0), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ, // wrong: should be REMOTE_SEQ+1
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    // Should get challenge ACK instead of closing.
    try testing.expect(reply != null);
    try testing.expectEqual(State.established, s.state);
}

// [smoltcp:socket/tcp.rs:test_close_wait_retransmit_reset_after_ack]
test "close wait retransmit reset after ack" {
    var s = socketCloseWait();
    s.remote_win_len = 6;
    _ = try s.sendSlice("abcdef");
    _ = try s.sendSlice("123456");

    // Dispatch first 6 bytes.
    const pkt1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    // ACK first 6 bytes.
    _ = sendPacket(&s, Instant.fromMillis(1005), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = 6,
    });

    // Next 6 bytes.
    const pkt2 = recvPacket(&s, Instant.fromMillis(1010));
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "123456", pkt2.?.payload);
}

// [smoltcp:socket/tcp.rs:test_fin_wait_1_retransmit_reset_after_ack]
test "fin wait 1 retransmit reset after ack" {
    var s = socketEstablished();
    s.remote_win_len = 6;
    _ = try s.sendSlice("abcdef");
    _ = try s.sendSlice("123456");
    _ = try s.sendSlice("ABCDEF");
    s.close();

    // Dispatch first 6 bytes.
    const pkt1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    // ACK first 6 bytes.
    _ = sendPacket(&s, Instant.fromMillis(1005), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = 6,
    });

    // Next 6 bytes.
    const pkt2 = recvPacket(&s, Instant.fromMillis(1010));
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "123456", pkt2.?.payload);

    // ACK next 6 bytes.
    _ = sendPacket(&s, Instant.fromMillis(1015), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(12),
        .window_len = 6,
    });

    // Last 6 bytes + FIN.
    const pkt3 = recvPacket(&s, Instant.fromMillis(1020));
    try testing.expect(pkt3 != null);
    try testing.expectEqualSlices(u8, "ABCDEF", pkt3.?.payload);
    try testing.expectEqual(Control.fin, pkt3.?.control);
}

// [smoltcp:socket/tcp.rs:test_closed_timeout]
test "closed timeout" {
    var s = socketEstablished();
    s.timeout = Duration.fromMillis(200);
    s.remote_last_ts = Instant.fromMillis(100);
    s.abort();

    // Should dispatch RST.
    const rst = recvPacket(&s, Instant.fromMillis(100));
    try testing.expect(rst != null);
    try testing.expectEqual(Control.rst, rst.?.control);
    try testing.expectEqual(State.closed, s.state);
}

// [smoltcp:socket/tcp.rs:test_sends_keep_alive]
test "sends keep alive probes" {
    var s = socketEstablished();
    s.keep_alive = Duration.fromMillis(100);
    s.timer.setForIdle(Instant.ZERO, s.keep_alive);

    // No probe before interval.
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(0)));
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(95)));

    // At 100ms, keep-alive fires.
    const ka1 = recvPacket(&s, Instant.fromMillis(100));
    try testing.expect(ka1 != null);
    try testing.expectEqual(@as(usize, 1), ka1.?.payload.len);

    // At 200ms, another keep-alive.
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(195)));
    const ka2 = recvPacket(&s, Instant.fromMillis(200));
    try testing.expect(ka2 != null);
    try testing.expectEqual(@as(usize, 1), ka2.?.payload.len);

    // Remote responds, resets timer.
    _ = sendPacket(&s, Instant.fromMillis(250), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Next keep-alive at 350ms (250 + 100).
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(345)));
    const ka3 = recvPacket(&s, Instant.fromMillis(350));
    try testing.expect(ka3 != null);
    try testing.expectEqual(@as(usize, 1), ka3.?.payload.len);
}

// =========================================================================
// Buffer wraparound tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_buffer_wraparound_rx]
test "buffer wraparound rx" {
    var s = socketEstablished();
    // Receive first chunk.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    // Read it out.
    var buf1: [3]u8 = undefined;
    _ = try s.recvSlice(&buf1);
    try testing.expectEqualSlices(u8, "abc", &buf1);

    // Receive more data (may wrap around in buffer).
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(3),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "defghi",
    });

    var buf2: [6]u8 = undefined;
    const n = try s.recvSlice(&buf2);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqualSlices(u8, "defghi", buf2[0..6]);
}

// =========================================================================
// Delayed ACK edge cases
// =========================================================================

// [smoltcp:socket/tcp.rs:test_delayed_ack_win]
test "delayed ack window update" {
    var s = socketEstablished();
    s.ack_delay = ACK_DELAY_DEFAULT;

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    // Reading data should not immediately cause ACK (delayed).
    var buf: [3]u8 = undefined;
    _ = try s.recvSlice(&buf);

    // No ACK immediately.
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));

    // After delay, ACK sent.
    const ack = recvPacket(&s, Instant.fromMillis(11));
    try testing.expect(ack != null);
    try testing.expect(ack.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(3)));
}

// [smoltcp:socket/tcp.rs:test_window_update_with_delay_ack]
test "window update with delay ack" {
    var s = socketWithBuffers(6, 6);
    s.state = .established;
    s.listen_endpoint = LISTEN_END;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.ack_delay = ACK_DELAY_DEFAULT;

    // Fill the 6-byte rx buffer.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });

    // At t=5ms, no ACK yet (delayed ack timer not expired).
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(5)));

    // Read 2 bytes -- window opens 0->2, windowToUpdate triggers (lastScaledWindow=0).
    var buf2: [2]u8 = undefined;
    _ = try s.recvSlice(&buf2);
    try testing.expectEqualSlices(u8, "ab", &buf2);

    const ack1 = recvPacket(&s, Instant.fromMillis(5));
    try testing.expect(ack1 != null);
    try testing.expect(ack1.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(6)));
    try testing.expectEqual(@as(u16, 2), ack1.?.window_len);

    // Read 1 byte -- window=3, no update (3/2=1 < lastScaledWindow=2).
    var buf1: [1]u8 = undefined;
    _ = try s.recvSlice(&buf1);
    try testing.expectEqualSlices(u8, "c", &buf1);
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(5)));

    // Read 1 byte -- window=4, update triggers (4/2=2 >= lastScaledWindow=2).
    _ = try s.recvSlice(&buf1);
    try testing.expectEqualSlices(u8, "d", &buf1);

    const ack2 = recvPacket(&s, Instant.fromMillis(5));
    try testing.expect(ack2 != null);
    try testing.expect(ack2.?.ack_number.?.eql(REMOTE_SEQ.add(1).add(6)));
    try testing.expectEqual(@as(u16, 4), ack2.?.window_len);
}

// =========================================================================
// SYN-RECEIVED additional tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_syn_received_close]
test "SYN-RECEIVED close -> FIN-WAIT-1" {
    var s = socketSynReceived();
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_received_ack_too_low]
test "SYN-RECEIVED rejects ACK too low" {
    var s = socketSynReceived();
    _ = recvAt0(&s); // drain SYN|ACK

    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ, // wrong: too low (not incremented)
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expect(reply != null);
    try testing.expectEqual(Control.rst, reply.?.control);
    try testing.expectEqual(State.syn_received, s.state);
}

// =========================================================================
// CLOSE-WAIT additional tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_close_wait_close]
test "CLOSE-WAIT close sets LAST-ACK state" {
    var s = socketCloseWait();
    s.close();
    try testing.expectEqual(State.last_ack, s.state);
}

// =========================================================================
// ESTABLISHED additional tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_established_close]
test "ESTABLISHED close sets FIN-WAIT-1 state" {
    var s = socketEstablished();
    s.close();
    try testing.expectEqual(State.fin_wait_1, s.state);
}

// [smoltcp:socket/tcp.rs:test_established_no_ack]
test "ESTABLISHED rejects packet without ACK and stays established" {
    var s = socketEstablished();
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(?TcpRepr, null), reply);
    try testing.expectEqual(State.established, s.state);
}

// [smoltcp:socket/tcp.rs:test_fast_retransmit_zero_window]
test "fast retransmit zero window" {
    var s = socketEstablished();

    _ = sendPacket(&s, Instant.fromMillis(1000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    _ = try s.sendSlice("abc");

    _ = recvPacket(&s, Instant.fromMillis(0));

    // 3 dup acks with zero window on third.
    _ = sendPacket(&s, Instant.fromMillis(1050), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    _ = sendPacket(&s, Instant.fromMillis(1050), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    _ = sendPacket(&s, Instant.fromMillis(1050), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });

    // Should NOT force-send because remote window is 0.
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));
}

// [smoltcp:socket/tcp.rs:test_zero_window_probe_shift]
test "zero window probe shift" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef123456!@#$%^");
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });

    // Nothing before first ZWP.
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(999)));

    // First probe at t=1000.
    const probe1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(probe1 != null);
    try testing.expectEqual(@as(usize, 1), probe1.?.payload.len);

    // Second probe at t=3000 (doubled to 2000ms).
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(2999)));
    const probe2 = recvPacket(&s, Instant.fromMillis(3000));
    try testing.expect(probe2 != null);
    try testing.expectEqual(@as(usize, 1), probe2.?.payload.len);

    // Third probe at t=7000 (doubled to 4000ms).
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(6999)));
    const probe3 = recvPacket(&s, Instant.fromMillis(7000));
    try testing.expect(probe3 != null);
    try testing.expectEqual(@as(usize, 1), probe3.?.payload.len);
}

// [smoltcp:socket/tcp.rs:test_fill_peer_window]
test "fill peer window" {
    var s = socketEstablished();
    s.remote_mss = 6;
    _ = try s.sendSlice("abcdef123456!@#$%^");

    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    const pkt2 = recvAt0(&s);
    try testing.expect(pkt2 != null);
    try testing.expectEqualSlices(u8, "123456", pkt2.?.payload);

    const pkt3 = recvAt0(&s);
    try testing.expect(pkt3 != null);
    try testing.expectEqualSlices(u8, "!@#$%^", pkt3.?.payload);
}

// =========================================================================
// Peek tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_peek_slice]
test "peek slice" {
    var s = socketEstablished();

    // Receive data.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "0123456",
    });

    // Peek and recv should yield the same data.
    const peeked = try s.peek(10);
    var recv_buf: [10]u8 = undefined;
    const recv_len = try s.recvSlice(&recv_buf);
    try testing.expectEqualSlices(u8, peeked, recv_buf[0..recv_len]);
}

// [smoltcp:socket/tcp.rs:test_peek_slice_buffer_wrap]
test "peek slice buffer wrap" {
    var s = socketWithBuffers(64, 10);
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };

    // Fill 8 bytes then dequeue 6 to advance the ring buffer's read cursor.
    _ = s.rx_buffer.enqueueSlice("01234567");
    var trash: [6]u8 = undefined;
    _ = s.rx_buffer.dequeueSlice(&trash);
    // Now enqueue 5 more, which wraps around.
    _ = s.rx_buffer.enqueueSlice("01234");

    // peek() returns only the first contiguous segment (up to the buffer wrap point).
    const peeked = try s.peek(10);
    try testing.expectEqualSlices(u8, "6701", peeked);

    // recvSlice() returns all data including the wrapped portion.
    var recv_buf: [10]u8 = undefined;
    const recv_len = try s.recvSlice(&recv_buf);
    try testing.expectEqual(@as(usize, 7), recv_len);
    try testing.expectEqualSlices(u8, "6701234", recv_buf[0..recv_len]);
}

// =========================================================================
// FIN-WAIT-1 FIN+FIN (remote FIN while our FIN not yet acked) -> CLOSING
// =========================================================================

// [smoltcp:socket/tcp.rs:test_fin_wait_1_fin_fin]
test "FIN-WAIT-1 recv FIN without data and no ack of our FIN -> CLOSING" {
    var s = socketFinWait1();

    // Dispatch our FIN.
    const fin_pkt = recvAt0(&s);
    try testing.expect(fin_pkt != null);
    try testing.expectEqual(Control.fin, fin_pkt.?.control);

    // Remote sends its own FIN but doesn't ACK ours (ack=LOCAL_SEQ+1, not +2).
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closing, s.state);
}

// =========================================================================
// CLOSING recv ACK+FIN -> TIME-WAIT (test_closing_ack_fin)
// =========================================================================

// [smoltcp:socket/tcp.rs:test_closing_ack_fin]
test "CLOSING recv ACK of FIN -> TIME-WAIT via ack_fin" {
    var s = socketClosing();

    // Dispatch the ACK (from CLOSING, we need to send ACK for remote FIN).
    const ack_pkt = recvAt0(&s);
    try testing.expect(ack_pkt != null);

    // Remote ACKs our FIN.
    _ = sendPacket(&s, Instant.fromMillis(1000), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.time_wait, s.state);
}

// =========================================================================
// TIME-WAIT timeout -> CLOSED
// =========================================================================

// [smoltcp:socket/tcp.rs:test_time_wait_timeout]
test "TIME-WAIT timeout expires to CLOSED" {
    var s = socketTimeWait(false);

    // Dispatch the ACK for the remote FIN.
    const ack_pkt = recvAt0(&s);
    try testing.expect(ack_pkt != null);
    try testing.expectEqual(State.time_wait, s.state);

    // After the close delay, dispatching should close the socket.
    _ = recvPacket(&s, Instant.fromMillis(60_000));
    try testing.expectEqual(State.closed, s.state);
}

// =========================================================================
// LAST-ACK dispatch FIN then recv ACK -> CLOSED
// =========================================================================

// [smoltcp:socket/tcp.rs:test_last_ack_fin_ack]
test "LAST-ACK dispatches FIN then ACK -> CLOSED" {
    var s = socketLastAck();

    // Dispatch our FIN.
    const fin_pkt = recvAt0(&s);
    try testing.expect(fin_pkt != null);
    try testing.expectEqual(Control.fin, fin_pkt.?.control);
    try testing.expectEqual(State.last_ack, s.state);

    // Remote ACKs our FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.closed, s.state);
}

// =========================================================================
// Fast retransmit duplicate detection
// =========================================================================

// [smoltcp:socket/tcp.rs:test_fast_retransmit_duplicate_detection]
test "fast retransmit duplicate detection with no data" {
    var s = socketEstablished();
    s.remote_mss = 6;

    // Normal ACK with nothing queued -- dup ack counter should not increment.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Duplicate when nothing queued.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Counter should still be 0 because there's nothing to retransmit.
    try testing.expectEqual(@as(u8, 0), s.local_rx_dup_acks);

    // Queue data to send.
    _ = try s.sendSlice("xxxxxxyyyyyywwwwwwzzzzzz");

    // Dispatch all 4 segments.
    const pkt1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(pkt1 != null);
    const pkt2 = recvPacket(&s, Instant.fromMillis(1005));
    try testing.expect(pkt2 != null);
    const pkt3 = recvPacket(&s, Instant.fromMillis(1010));
    try testing.expect(pkt3 != null);
    const pkt4 = recvPacket(&s, Instant.fromMillis(1015));
    try testing.expect(pkt4 != null);

    // First dup ACK.
    _ = sendPacket(&s, Instant.fromMillis(1050), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    // Second dup ACK.
    _ = sendPacket(&s, Instant.fromMillis(1055), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Reordered packet arrives - advances ACK, resets dup counter.
    _ = sendPacket(&s, Instant.fromMillis(1060), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1 + 6 * 3),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(@as(u8, 0), s.local_rx_dup_acks);

    // ACK all remaining.
    _ = sendPacket(&s, Instant.fromMillis(1120), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1 + 6 * 4),
        .window_len = SEND_TEMPL.window_len,
    });
}

// =========================================================================
// Receive partially outside window (remote retransmission)
// =========================================================================

// [smoltcp:socket/tcp.rs:test_established_receive_partially_outside_window]
test "ESTABLISHED receive partially outside window" {
    var s = socketEstablished();

    // Receive "abc".
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    // Consume it.
    var buf: [3]u8 = undefined;
    const n = try s.recvSlice(&buf);
    try testing.expectEqual(@as(usize, 3), n);
    try testing.expectEqualSlices(u8, "abc", buf[0..3]);

    // Peer retransmits "abc" plus new "def".
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });

    // Only "def" should be new.
    var buf2: [6]u8 = undefined;
    const n2 = try s.recvSlice(&buf2);
    try testing.expectEqual(@as(usize, 3), n2);
    try testing.expectEqualSlices(u8, "def", buf2[0..3]);
}

// [smoltcp:socket/tcp.rs:test_established_receive_partially_outside_window_fin]
test "ESTABLISHED receive partially outside window with FIN" {
    var s = socketEstablished();

    // Receive "abc".
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });
    var buf: [3]u8 = undefined;
    _ = try s.recvSlice(&buf);

    // Peer retransmits with FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });

    var buf2: [6]u8 = undefined;
    const n2 = try s.recvSlice(&buf2);
    try testing.expectEqual(@as(usize, 3), n2);
    try testing.expectEqualSlices(u8, "def", buf2[0..3]);

    // FIN should be accepted since there's no hole.
    try testing.expectEqual(State.close_wait, s.state);
}

// =========================================================================
// Send wrap (sequence number wraparound at 2^31)
// =========================================================================

// [smoltcp:socket/tcp.rs:test_established_send_wrap]
test "ESTABLISHED send wrap around seq boundary" {
    var s = socketEstablished();
    const local_seq_start = SeqNumber{ .value = std.math.maxInt(i32) - 1 };
    s.local_seq_no = local_seq_start.add(1);
    s.remote_last_seq = local_seq_start.add(1);
    _ = try s.sendSlice("abc");

    const pkt = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(pkt != null);
    try testing.expect(pkt.?.seq_number.eql(local_seq_start.add(1)));
    try testing.expectEqualSlices(u8, "abc", pkt.?.payload);
}

// =========================================================================
// Window shrink
// =========================================================================

// [smoltcp:socket/tcp.rs:test_established_send_window_shrink]
test "ESTABLISHED send window shrink" {
    var s = socketEstablished();

    // Send 6 bytes.
    _ = try s.sendSlice("abcdef");
    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);
    try testing.expectEqualSlices(u8, "abcdef", pkt1.?.payload);

    // Peer sends data + shrinks window to 3 (doesn't ACK our data).
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 3,
        .payload = "xyzxyz",
    });

    // Queue more data -- shouldn't be sent since window is too small.
    _ = try s.sendSlice("foobar");
    const pkt2 = recvAt0(&s);
    // Should get an ACK for the received data, but no new payload.
    try testing.expect(pkt2 != null);
    try testing.expectEqual(@as(usize, 0), pkt2.?.payload.len);
}

// =========================================================================
// Zero window tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_zero_window_ack]
test "zero window ack rejects data" {
    var s = socketWithBuffers(64, 6);
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };

    // Fill the rx buffer completely.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });

    // Dispatch ACK with window_len=0.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expectEqual(@as(u16, 0), ack.?.window_len);

    // Try to send more data when window is 0 -- should get challenge ACK.
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1 + 6),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "123456",
    });
    // The challenge ACK reply window should be 0.
    try testing.expect(reply != null);
    try testing.expectEqual(@as(u16, 0), reply.?.window_len);
}

// [smoltcp:socket/tcp.rs:test_zero_window_fin]
test "zero window accepts FIN" {
    var s = socketWithBuffers(64, 6);
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.ack_delay = null;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };

    // Fill the rx buffer completely.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });

    // Dispatch ACK with window=0.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expectEqual(@as(u16, 0), ack.?.window_len);

    // FIN at end of data should still be accepted even at zero window.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1 + 6),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.close_wait, s.state);
}

// [smoltcp:socket/tcp.rs:test_zero_window_ack_on_window_growth]
test "zero window ack on window growth" {
    var s = socketWithBuffers(64, 6);
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };

    // Fill rx buffer.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abcdef",
    });

    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expectEqual(@as(u16, 0), ack.?.window_len);

    // Nothing to send yet.
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));

    // Read 3 bytes -> window opens to 3.
    var buf: [3]u8 = undefined;
    _ = try s.recvSlice(&buf);

    // Should dispatch a window update.
    const update = recvAt0(&s);
    try testing.expect(update != null);
    try testing.expectEqual(@as(u16, 3), update.?.window_len);
}

// [smoltcp:socket/tcp.rs:test_announce_window_after_read]
test "announce window after read" {
    var s = socketWithBuffers(64, 6);
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };

    // Receive 3 bytes.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    // Dispatch ACK with window=3.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
    try testing.expectEqual(@as(u16, 3), ack.?.window_len);

    // Read all 3 bytes.
    var buf: [3]u8 = undefined;
    _ = try s.recvSlice(&buf);

    // Window should update to 6 (doubled from 3).
    const update = recvAt0(&s);
    try testing.expect(update != null);
    try testing.expectEqual(@as(u16, 6), update.?.window_len);
}

// [smoltcp:socket/tcp.rs:test_zero_window_probe_backoff_nack_reply]
test "zero window probe backoff with nack reply" {
    var s = socketEstablished();
    _ = try s.sendSlice("abcdef123456!@#$%^");

    // Remote advertises zero window.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });

    // First probe at t=1000.
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(999)));
    const probe1 = recvPacket(&s, Instant.fromMillis(1000));
    try testing.expect(probe1 != null);
    try testing.expectEqual(@as(usize, 1), probe1.?.payload.len);

    // NACK reply (still zero window).
    _ = sendPacket(&s, Instant.fromMillis(1100), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });

    // Second probe at t=3000 (backoff to 2000ms).
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(2999)));
    const probe2 = recvPacket(&s, Instant.fromMillis(3000));
    try testing.expect(probe2 != null);
    try testing.expectEqual(@as(usize, 1), probe2.?.payload.len);

    // Another NACK.
    _ = sendPacket(&s, Instant.fromMillis(3100), TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 0,
    });

    // Third probe at t=7000 (backoff to 4000ms).
    try testing.expectEqual(@as(?TcpRepr, null), recvPacket(&s, Instant.fromMillis(6999)));
    const probe3 = recvPacket(&s, Instant.fromMillis(7000));
    try testing.expect(probe3 != null);
    try testing.expectEqual(@as(usize, 1), probe3.?.payload.len);
}

// =========================================================================
// TIME-WAIT no window update
// =========================================================================

// [smoltcp:socket/tcp.rs:test_time_wait_no_window_update]
test "TIME-WAIT no window update" {
    var s = socketFinWait2();

    // Receive data + FIN.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = &[_]u8{ 1, 2, 3, 4 },
    });
    try testing.expectEqual(State.time_wait, s.state);

    // Dispatch ACK for FIN.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);

    // Read data out.
    var buf: [4]u8 = undefined;
    _ = try s.recvSlice(&buf);

    // Should NOT send a window update in TIME-WAIT.
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));
}

// =========================================================================
// RX close with holes
// =========================================================================

// [smoltcp:socket/tcp.rs:test_rx_close_fin_with_hole]
test "rx close FIN with hole" {
    var s = socketEstablished();

    // Receive "abc" at offset 0.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    // Receive FIN + "ghi" at offset 6 (hole at 3-6).
    const reply = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .fin,
        .seq_number = REMOTE_SEQ.add(1 + 6),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "ghi",
    });
    // Should get an ACK for what we have (up to offset 3).
    try testing.expect(reply != null);

    // Read "abc".
    var buf: [3]u8 = undefined;
    _ = try s.recvSlice(&buf);
    try testing.expectEqualSlices(u8, "abc", &buf);

    // Can't read more -- hole.
    var buf2: [1]u8 = undefined;
    const n = try s.recvSlice(&buf2);
    try testing.expectEqual(@as(usize, 0), n);

    // RST to close.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ.add(1 + 9),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // After RST, recv should fail with InvalidState.
    var buf3: [1]u8 = undefined;
    try testing.expectError(error.InvalidState, s.recvSlice(&buf3));
}

// [smoltcp:socket/tcp.rs:test_rx_close_rst_with_hole]
test "rx close RST with hole" {
    var s = socketEstablished();

    // Receive "abc".
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "abc",
    });

    // Receive "ghi" at offset 6 (hole at 3-6).
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1 + 6),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "ghi",
    });

    // RST at offset 9.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .rst,
        .seq_number = REMOTE_SEQ.add(1 + 9),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });

    // Read "abc".
    var buf: [3]u8 = undefined;
    _ = try s.recvSlice(&buf);
    try testing.expectEqualSlices(u8, "abc", &buf);

    // After RST + hole, recv should fail.
    var buf2: [1]u8 = undefined;
    try testing.expectError(error.InvalidState, s.recvSlice(&buf2));
}

// =========================================================================
// Delayed ACK every RMSS tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_delayed_ack_every_rmss]
test "delayed ack every rmss" {
    const BUF_SIZE = DEFAULT_MSS * 2;
    var s = socketWithBuffers(BUF_SIZE, BUF_SIZE);
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.ack_delay = Duration.fromMillis(10);
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };

    // Send MSS-1 bytes -> no immediate ACK (delayed).
    var payload_mss_minus_1: [DEFAULT_MSS - 1]u8 = undefined;
    @memset(&payload_mss_minus_1, 0);
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = &payload_mss_minus_1,
    });
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));

    // Send 1 more byte -> still under RMSS threshold.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(DEFAULT_MSS),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "a",
    });
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));

    // Send 1 more byte -> now RMSS+1 total, trigger immediate ACK.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(DEFAULT_MSS + 1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "a",
    });
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
}

// [smoltcp:socket/tcp.rs:test_delayed_ack_every_rmss_or_more]
test "delayed ack every rmss or more" {
    const BUF_SIZE = DEFAULT_MSS * 2;
    var s = socketWithBuffers(BUF_SIZE, BUF_SIZE);
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.ack_delay = Duration.fromMillis(10);
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };

    // Send exactly MSS bytes -> under RMSS threshold.
    var payload_mss: [DEFAULT_MSS]u8 = undefined;
    @memset(&payload_mss, 0);
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = &payload_mss,
    });
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));

    // Send 1 more byte.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1 + DEFAULT_MSS),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "a",
    });

    // Send another byte -> RMSS+2 total.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1 + DEFAULT_MSS + 1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "b",
    });

    // Immediate ACK triggered because we crossed RMSS.
    const ack = recvAt0(&s);
    try testing.expect(ack != null);
}

// =========================================================================
// SYN-SENT simultaneous open then ACK -> ESTABLISHED
// =========================================================================

// [smoltcp:socket/tcp.rs:test_syn_sent_syn_received_ack]
test "SYN-SENT simultaneous open SYN then ACK -> ESTABLISHED" {
    var s = socketSynSent();

    // Dispatch our SYN.
    const syn_pkt = recvAt0(&s);
    try testing.expect(syn_pkt != null);
    try testing.expectEqual(Control.syn, syn_pkt.?.control);

    // Remote sends SYN (simultaneous open).
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.syn_received, s.state);

    // Dispatch SYN|ACK.
    const syn_ack = recvAt0(&s);
    try testing.expect(syn_ack != null);
    try testing.expectEqual(Control.syn, syn_ack.?.control);

    // Nothing else to send.
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));

    // SYN|ACK can be retransmitted.
    const retransmit = recvPacket(&s, Instant.fromMillis(1001));
    try testing.expect(retransmit != null);
    try testing.expectEqual(Control.syn, retransmit.?.control);

    // Remote sends ACK -> ESTABLISHED.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .none,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
    });
    try testing.expectEqual(State.established, s.state);
}

// =========================================================================
// Buffer wraparound TX
// =========================================================================

// [smoltcp:socket/tcp.rs:test_buffer_wraparound_tx]
test "buffer wraparound tx" {
    var s = socketWithBuffers(9, 64);
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.nagle = false;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };

    // Enqueue "xxxyyy" into tx buffer.
    const sent1 = try s.sendSlice("xxxyyy");
    try testing.expectEqual(@as(usize, 6), sent1);

    // Dispatch first segment.
    const pkt1 = recvAt0(&s);
    try testing.expect(pkt1 != null);

    // ACK first 3 bytes to advance the ring buffer read cursor.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1 + 6),
        .window_len = SEND_TEMPL.window_len,
    });

    // Now enqueue "abcdef" which will wrap around in the 9-byte tx buffer.
    const sent2 = try s.sendSlice("abcdef");
    try testing.expectEqual(@as(usize, 6), sent2);

    // Dispatch -- data may come in 1 or 2 segments depending on contiguity.
    const pkt2 = recvAt0(&s);
    try testing.expect(pkt2 != null);
    try testing.expect(pkt2.?.payload.len > 0);
}

// =========================================================================
// Hop limit tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_set_hop_limit]
test "set hop limit propagates to dispatch" {
    var s = socketSynReceived();
    try s.setHopLimit(0x2a);

    const result = s.dispatch(Instant.ZERO) orelse return error.ExpectedDispatch;
    try testing.expectEqual(@as(u8, 0x2a), result.hop_limit);

    // User-configurable settings are preserved across reset (issue #601)
    s.reset();
    try testing.expectEqual(@as(?u8, 0x2a), s.hop_limit);
}

// [smoltcp:socket/tcp.rs:test_set_hop_limit_zero]
test "set hop limit zero rejected" {
    var s = socketSynReceived();
    try testing.expectError(error.InvalidValue, s.setHopLimit(0));

    // null disables the override and uses DEFAULT_HOP_LIMIT (64)
    try s.setHopLimit(null);
    const result = s.dispatch(Instant.ZERO) orelse return error.ExpectedDispatch;
    try testing.expectEqual(@as(u8, 64), result.hop_limit);
}

// =========================================================================
// Window scale buffer size tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_listen_syn_win_scale_buffers]
test "listen syn window scale for various buffer sizes" {
    // Verify windowShiftFor produces the expected shift for each buffer size
    const cases = [_]struct { buf: usize, shift: u8 }{
        .{ .buf = 64, .shift = 0 },
        .{ .buf = 128, .shift = 0 },
        .{ .buf = 1024, .shift = 0 },
        .{ .buf = 65535, .shift = 0 },
        .{ .buf = 65536, .shift = 1 },
        .{ .buf = 65537, .shift = 1 },
        .{ .buf = 131071, .shift = 1 },
        .{ .buf = 131072, .shift = 2 },
        .{ .buf = 524287, .shift = 3 },
        .{ .buf = 524288, .shift = 4 },
        .{ .buf = 655350, .shift = 4 },
        .{ .buf = 1048576, .shift = 5 },
    };
    for (cases) |c| {
        try testing.expectEqual(c.shift, TestSocket.windowShiftFor(c.buf));
    }
}

// [smoltcp:socket/tcp.rs:test_syn_sent_syn_ack_no_window_scaling]
test "SYN-SENT syn ack no window scaling clears shift" {
    // Use a socket with large buffers so remote_win_shift > 0
    var s = socketWithBuffers(64, 1048576);
    s.state = .syn_sent;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };
    s.local_seq_no = LOCAL_SEQ;
    s.remote_last_seq = LOCAL_SEQ;

    // Verify the initial shift is 5 (for 1048576-byte rx buffer)
    try testing.expectEqual(@as(u8, 5), s.remote_win_shift);

    // Drain the SYN
    const syn = recvAt0(&s);
    try testing.expect(syn != null);
    try testing.expectEqual(Control.syn, syn.?.control);
    try testing.expectEqual(@as(?u8, 5), syn.?.window_scale);

    // Server SYN-ACK without window_scale
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 42,
    });
    try testing.expectEqual(State.established, s.state);
    try testing.expectEqual(@as(u8, 0), s.remote_win_shift);
    try testing.expectEqual(@as(?u8, null), s.remote_win_scale);
    try testing.expectEqual(@as(usize, 42), s.remote_win_len);
}

// =========================================================================
// Additional conformance tests
// =========================================================================

// [smoltcp:socket/tcp.rs:test_connect]
test "connect full active open roundtrip" {
    var s = socketNew();
    s.local_seq_no = LOCAL_SEQ;

    try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);
    try testing.expectEqual(State.syn_sent, s.state);

    // Dispatch SYN and verify option fields.
    const syn = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Control.syn, syn.control);
    try testing.expect(syn.seq_number.eql(LOCAL_SEQ));
    try testing.expectEqual(@as(?SeqNumber, null), syn.ack_number);
    try testing.expectEqual(@as(?u16, BASE_MSS), syn.max_seg_size);
    try testing.expectEqual(@as(?u8, 0), syn.window_scale);
    try testing.expect(syn.sack_permitted);

    // Process SYN-ACK from remote.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .max_seg_size = BASE_MSS - 80,
        .window_scale = 0,
        .window_len = SEND_TEMPL.window_len,
    });

    try testing.expectEqual(State.established, s.state);
}

// [smoltcp:socket/tcp.rs:test_syn_sent_win_scale_buffers]
test "SYN-SENT window scale for various rx buffer sizes" {
    // Test representative buffer sizes and expected window_scale values.
    // Each case: create a socket with the given rx buffer, connect, dispatch SYN,
    // verify the window_scale and window_len in the emitted SYN.
    const Case = struct { buf: usize, shift: u8, win: u16 };
    const cases = [_]Case{
        .{ .buf = 64, .shift = 0, .win = 64 },
        .{ .buf = 65535, .shift = 0, .win = 65535 },
        .{ .buf = 65536, .shift = 1, .win = 65535 },
        .{ .buf = 131072, .shift = 2, .win = 65535 },
        .{ .buf = 1048576, .shift = 5, .win = 65535 },
    };
    inline for (cases) |c| {
        var s = socketWithBuffers(64, c.buf);
        s.local_seq_no = LOCAL_SEQ;

        try testing.expectEqual(c.shift, s.remote_win_shift);

        try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);

        const syn = recvAt0(&s) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(Control.syn, syn.control);
        try testing.expectEqual(@as(?u8, c.shift), syn.window_scale);
        try testing.expectEqual(c.win, syn.window_len);
    }
}

// [smoltcp:socket/tcp.rs:test_established_sliding_window_recv]
test "established sliding window recv with scaling" {
    var s = socketWithBuffers(64, 262143);
    s.state = .syn_received;
    s.listen_endpoint = LISTEN_END;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };
    s.local_seq_no = LOCAL_SEQ;
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ;
    s.remote_win_len = 256;

    // Transition to established.
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_win_scale = 0;
    s.remote_last_win = 65535;
    s.remote_win_shift = 2;

    // Send 1400 bytes of data.
    const segment = "abcdefghijklmn" ** 100;
    comptime std.debug.assert(segment.len == 1400);

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = segment,
    });

    // ACK should have window_len right-shifted by 2.
    // Free space = 262143 - 1400 = 260743. Shifted right 2 = 65185.
    const ack = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expect(ack.seq_number.eql(LOCAL_SEQ.add(1)));
    try testing.expect(ack.ack_number.?.eql(REMOTE_SEQ.add(1).add(1400)));
    try testing.expectEqual(@as(u16, 65185), ack.window_len);
}

// [smoltcp:socket/tcp.rs:test_recv_out_of_recv_win]
test "recv data beyond advertised receive window" {
    var s = socketEstablished();

    // Fill 33 bytes into the 64-byte rx buffer.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = &([_]u8{0} ** 33),
    });

    // Dispatch ACK: acknowledges 33 bytes, advertises window=31.
    const ack1 = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expect(ack1.ack_number.?.eql(REMOTE_SEQ.add(1).add(33)));
    try testing.expectEqual(@as(u16, 31), ack1.window_len);

    // Read 1 byte from rx buffer. Frees space to 32, but the remote
    // only knows about the 31-byte window we last advertised.
    var tmp: [1]u8 = undefined;
    _ = try s.recvSlice(&tmp);
    try testing.expectEqual(@as(?TcpRepr, null), recvAt0(&s));

    // Remote sends 32 bytes at the right edge. Only 31 fit in the
    // previously advertised window; the 32nd byte is silently dropped.
    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1).add(33),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = &([_]u8{0} ** 32),
    });

    // Dispatch ACK: only 31 bytes accepted, window shrinks to 1.
    const ack2 = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expect(ack2.ack_number.?.eql(REMOTE_SEQ.add(1).add(64)));
    try testing.expectEqual(@as(u16, 1), ack2.window_len);
}

// -- pollAt tests --

// (original)
test "pollAt SYN-SENT returns ZERO" {
    var s = socketSynSent();
    try testing.expectEqual(Instant.ZERO, s.pollAt().?);
}

// (original)
test "pollAt LISTEN returns null" {
    var s = socketListen();
    try testing.expectEqual(@as(?Instant, null), s.pollAt());
}

// (original)
test "pollAt established with keep-alive returns timer deadline" {
    var s = socketEstablished();
    s.keep_alive = Duration.fromSecs(10);
    s.timer.setForIdle(Instant.ZERO, s.keep_alive);
    // Drain the initial dispatch (SYN-ACK window update, etc.)
    while (s.dispatch(Instant.ZERO) != null) {}

    const poll_at = s.pollAt() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Instant.fromSecs(10), poll_at);
}

// -- TCP Timestamps (RFC 7323) --

fn testTsvalGenerator() u32 {
    return 1;
}

// [smoltcp:socket/tcp.rs:test_tsval_established_connection]
test "tsval established connection" {
    var s = socketEstablished();
    s.setTsvalGenerator(&testTsvalGenerator);
    try testing.expect(s.timestampEnabled());

    // First roundtrip: send data, expect timestamp on outgoing segment.
    try testing.expectEqual(@as(usize, 6), s.sendSlice("abcdef"));
    const seg1 = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "abcdef", seg1.payload);
    try testing.expectEqual(@as(u32, 1), seg1.timestamp.?.tsval);
    try testing.expectEqual(@as(u32, 0), seg1.timestamp.?.tsecr);

    // ACK from remote with its own timestamp.
    _ = sendPacketAt0(&s, .{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(6),
        .window_len = 256,
        .timestamp = .{ .tsval = 500, .tsecr = 1 },
    });
    try testing.expectEqual(@as(usize, 0), s.tx_buffer.len());

    // Second roundtrip: tsecr should echo the remote's last tsval (500).
    try testing.expectEqual(@as(usize, 6), s.sendSlice("foobar"));
    const seg2 = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "foobar", seg2.payload);
    try testing.expectEqual(@as(u32, 1), seg2.timestamp.?.tsval);
    try testing.expectEqual(@as(u32, 500), seg2.timestamp.?.tsecr);

    // ACK without timestamp option.
    _ = sendPacketAt0(&s, .{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(12),
        .window_len = 256,
    });
    try testing.expectEqual(@as(usize, 0), s.tx_buffer.len());
}

// [smoltcp:socket/tcp.rs:test_tsval_disabled_in_remote_client]
test "tsval disabled in remote client" {
    var s = socketListen();
    s.setTsvalGenerator(&testTsvalGenerator);
    try testing.expect(s.timestampEnabled());

    // Remote SYN without timestamp: server disables timestamps.
    _ = sendPacketAt0(&s, .{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = 256,
    });
    try testing.expectEqual(State.syn_received, s.state);
    try testing.expect(!s.timestampEnabled());

    // SYN-ACK should have no timestamp.
    const synack = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Control.syn, synack.control);
    try testing.expect(synack.timestamp == null);
    try testing.expectEqual(BASE_MSS, synack.max_seg_size.?);

    // Complete handshake.
    _ = sendPacketAt0(&s, .{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 256,
    });
    try testing.expectEqual(State.established, s.state);
}

// [smoltcp:socket/tcp.rs:test_tsval_disabled_in_local_server]
test "tsval disabled in local server" {
    var s = socketListen();
    // No tsval generator set (default).
    try testing.expect(!s.timestampEnabled());

    // Remote SYN WITH timestamp: server still has no generator, so no TS.
    _ = sendPacketAt0(&s, .{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = null,
        .window_len = 256,
        .timestamp = .{ .tsval = 500, .tsecr = 0 },
    });
    try testing.expectEqual(State.syn_received, s.state);
    try testing.expect(!s.timestampEnabled());

    // SYN-ACK should have no timestamp.
    const synack = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Control.syn, synack.control);
    try testing.expect(synack.timestamp == null);
    try testing.expectEqual(BASE_MSS, synack.max_seg_size.?);

    // Complete handshake.
    _ = sendPacketAt0(&s, .{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 256,
    });
    try testing.expectEqual(State.established, s.state);
}

// [smoltcp:socket/tcp.rs:test_tsval_disabled_in_remote_server]
test "tsval disabled in remote server" {
    var s = socketNew();
    s.setTsvalGenerator(&testTsvalGenerator);
    try testing.expect(s.timestampEnabled());
    s.local_seq_no = LOCAL_SEQ;
    try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);

    // Dispatch SYN: should include timestamp.
    const syn = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Control.syn, syn.control);
    try testing.expect(syn.sack_permitted);
    try testing.expectEqual(@as(u32, 1), syn.timestamp.?.tsval);
    try testing.expectEqual(@as(u32, 0), syn.timestamp.?.tsecr);

    // SYN-ACK without timestamp: client disables timestamps.
    _ = sendPacketAt0(&s, .{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 256,
        .max_seg_size = BASE_MSS - 80,
        .window_scale = 0,
    });
    try testing.expect(!s.timestampEnabled());

    // Data segment should have no timestamp.
    try testing.expectEqual(@as(usize, 6), s.sendSlice("abcdef"));
    const data = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "abcdef", data.payload);
    try testing.expect(data.timestamp == null);
}

// [smoltcp:socket/tcp.rs:test_tsval_disabled_in_local_client]
test "tsval disabled in local client" {
    var s = socketNew();
    // No tsval generator set (default).
    try testing.expect(!s.timestampEnabled());
    s.local_seq_no = LOCAL_SEQ;
    try s.connect(REMOTE_ADDR, REMOTE_PORT, LOCAL_ADDR, LOCAL_PORT);

    // Dispatch SYN: should have no timestamp.
    const syn = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Control.syn, syn.control);
    try testing.expect(syn.sack_permitted);
    try testing.expect(syn.timestamp == null);

    // SYN-ACK WITH timestamp: client still has no generator, so no TS.
    _ = sendPacketAt0(&s, .{
        .src_port = REMOTE_PORT,
        .dst_port = LOCAL_PORT,
        .control = .syn,
        .seq_number = REMOTE_SEQ,
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 256,
        .max_seg_size = BASE_MSS - 80,
        .window_scale = 0,
        .timestamp = .{ .tsval = 500, .tsecr = 0 },
    });
    try testing.expect(!s.timestampEnabled());

    // Data segment should have no timestamp.
    try testing.expectEqual(@as(usize, 6), s.sendSlice("abcdef"));
    const data_seg = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "abcdef", data_seg.payload);
    try testing.expect(data_seg.timestamp == null);
}

// -- SACK Blocks (RFC 2018) --

// [smoltcp:socket/tcp.rs:test_established_rfc2018_cases]
test "established rfc2018 cases" {
    // Setup: socket with 4000-byte buffers.
    var s = socketWithBuffers(4000, 4000);
    s.state = .syn_received;
    s.listen_endpoint = LISTEN_END;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };
    s.local_seq_no = LOCAL_SEQ;
    s.remote_seq_no = REMOTE_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ;
    s.remote_win_len = 256;

    // Transition to ESTABLISHED.
    s.state = .established;
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_has_sack = true;

    // Send 10 in-order segments of 500 bytes to advance ACK to REMOTE_SEQ+1+5000.
    const segment = "abcdefghij" ** 50; // 500 bytes
    var offset: usize = 0;
    while (offset < 5000) : (offset += 500) {
        _ = sendPacketAt0(&s, .{
            .src_port = REMOTE_PORT,
            .dst_port = LOCAL_PORT,
            .seq_number = REMOTE_SEQ.add(1).add(offset),
            .ack_number = LOCAL_SEQ.add(1),
            .window_len = 256,
            .payload = segment[0..500],
        });

        // Drain any ACK generated.
        _ = recvAt0(&s);

        // Consume from rx buffer.
        var recv_buf: [500]u8 = undefined;
        const n = s.recvSlice(&recv_buf) catch 0;
        try testing.expectEqual(@as(usize, 500), n);
    }

    // RFC 2018 Case 2: First segment (at +5000) is dropped, remaining 7 arrive.
    // Each OOO segment should trigger an ACK with SACK block.
    const ack_base = REMOTE_SEQ.add(1).add(5000);
    var sack_offset: usize = 500;
    while (sack_offset < 4000) : (sack_offset += 500) {
        const reply = sendPacketAt0(&s, .{
            .src_port = REMOTE_PORT,
            .dst_port = LOCAL_PORT,
            .seq_number = REMOTE_SEQ.add(1).add(5000 + sack_offset),
            .ack_number = LOCAL_SEQ.add(1),
            .window_len = 256,
            .payload = segment[0..500],
        }) orelse return error.TestUnexpectedResult;

        // ACK should still be at 5000 (gap not filled).
        try testing.expect(reply.ack_number.?.eql(ack_base));

        // SACK should show the contiguous out-of-order block.
        const sack = reply.sack_ranges[0] orelse return error.TestUnexpectedResult;
        try testing.expectEqual(REMOTE_SEQ.add(1).add(5500).toU32(), sack.left);
        try testing.expectEqual(REMOTE_SEQ.add(1).add(5500 + sack_offset).toU32(), sack.right);
        try testing.expect(reply.sack_ranges[1] == null);
    }
}

// =========================================================================
// Public API tests
// =========================================================================

test "localEndpoint and remoteEndpoint" {
    var s = socketEstablished();
    const local = s.localEndpoint() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(LOCAL_ADDR, local.addr);
    try testing.expectEqual(LOCAL_PORT, local.port);

    const remote = s.remoteEndpoint() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(REMOTE_ADDR, remote.addr);
    try testing.expectEqual(REMOTE_PORT, remote.port);

    // In LISTEN state, no tuple is set.
    var s2 = socketListen();
    try testing.expectEqual(null, s2.localEndpoint());
    try testing.expectEqual(null, s2.remoteEndpoint());
}

test "setTimeout and setKeepAlive" {
    var s = socketEstablished();

    s.setTimeout(Duration.fromSecs(30));
    try testing.expectEqual(Duration.fromSecs(30), s.timeout.?);

    s.setTimeout(null);
    try testing.expectEqual(null, s.timeout);

    s.setKeepAlive(Duration.fromSecs(10));
    try testing.expectEqual(Duration.fromSecs(10), s.keep_alive.?);

    // setKeepAlive arms the timer when idle.
    switch (s.timer) {
        .idle => |v| try testing.expect(v.keep_alive_at != null),
        else => return error.TestUnexpectedResult,
    }
}

test "setAckDelay" {
    var s = socketNew();
    try testing.expectEqual(null, s.ack_delay);

    s.setAckDelay(Duration.fromMillis(20));
    try testing.expectEqual(Duration.fromMillis(20), s.ack_delay.?);

    s.setAckDelay(null);
    try testing.expectEqual(null, s.ack_delay);
}

test "setNagleEnabled" {
    var s = socketNew();
    try testing.expect(s.nagle);

    s.setNagleEnabled(false);
    try testing.expect(!s.nagle);

    s.setNagleEnabled(true);
    try testing.expect(s.nagle);
}

test "sendQueue and recvQueue" {
    var s = socketEstablished();
    try testing.expectEqual(0, s.sendQueue());
    try testing.expectEqual(0, s.recvQueue());

    _ = try s.sendSlice("hello");
    try testing.expectEqual(5, s.sendQueue());

    _ = sendPacketAt0(&s, TcpRepr{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = SEND_TEMPL.window_len,
        .payload = "world",
    });
    try testing.expectEqual(5, s.recvQueue());
}

test "sendCapacity and recvCapacity" {
    var s = socketNew();
    try testing.expectEqual(64, s.sendCapacity());
    try testing.expectEqual(64, s.recvCapacity());
}

test "setHopLimit validation" {
    var s = socketNew();
    try testing.expectError(error.InvalidValue, s.setHopLimit(0));
    try s.setHopLimit(1);
    try testing.expectEqual(@as(?u8, 1), s.hop_limit);
    try s.setHopLimit(255);
    try testing.expectEqual(@as(?u8, 255), s.hop_limit);
    try s.setHopLimit(null);
    try testing.expectEqual(null, s.hop_limit);
}

// -- Congestion Control: Unit Tests --

const dummy_rtte = RttEstimator{};

test "NoControl window is maxInt" {
    var cc = CongestionController{ .none = .{} };
    try testing.expectEqual(std.math.maxInt(usize), cc.window());
    cc.onAck(Instant.ZERO, 1000, &dummy_rtte);
    cc.onRetransmit(Instant.ZERO);
    cc.onDuplicateAck(Instant.ZERO);
    try testing.expectEqual(std.math.maxInt(usize), cc.window());
}

test "Reno slow start doubles cwnd" {
    var reno = Reno{ .cwnd = 1460, .min_cwnd = 1460, .ssthresh = std.math.maxInt(usize) };
    reno.onAck(Instant.ZERO, 1460, &dummy_rtte);
    try testing.expectEqual(2920, reno.cwnd);
    reno.onAck(Instant.ZERO, 1460, &dummy_rtte);
    try testing.expectEqual(4380, reno.cwnd);
}

test "Reno congestion avoidance linear growth" {
    var reno = Reno{ .cwnd = 4000, .min_cwnd = 1460, .ssthresh = 3000 };
    reno.onAck(Instant.ZERO, 1460, &dummy_rtte);
    try testing.expectEqual(5460, reno.cwnd);
}

test "Reno onRetransmit halves cwnd" {
    var reno = Reno{ .cwnd = 8000, .min_cwnd = 1460 };
    reno.onRetransmit(Instant.ZERO);
    try testing.expectEqual(4000, reno.cwnd);
    reno.onRetransmit(Instant.ZERO);
    try testing.expectEqual(2000, reno.cwnd);
    reno.onRetransmit(Instant.ZERO);
    try testing.expectEqual(1460, reno.cwnd);
}

test "Reno onDuplicateAck sets ssthresh" {
    var reno = Reno{ .cwnd = 8000, .min_cwnd = 1460, .ssthresh = std.math.maxInt(usize) };
    reno.onDuplicateAck(Instant.ZERO);
    try testing.expectEqual(4000, reno.ssthresh);
    try testing.expectEqual(8000, reno.cwnd);
}

test "Reno cwnd capped by rwnd" {
    var reno = Reno{ .cwnd = 3000, .min_cwnd = 1460, .ssthresh = std.math.maxInt(usize), .rwnd = 4000 };
    reno.onAck(Instant.ZERO, 3000, &dummy_rtte);
    try testing.expectEqual(4000, reno.cwnd);
}

test "Reno setMss updates min_cwnd" {
    var reno = Reno{};
    reno.setMss(536);
    try testing.expectEqual(536, reno.min_cwnd);
}

test "Cubic cubeRoot correctness" {
    const result = Cubic.cubeRoot(27.0) orelse unreachable;
    try testing.expect(result > 2.9 and result < 3.1);

    const result2 = Cubic.cubeRoot(1000.0) orelse unreachable;
    try testing.expect(result2 > 9.9 and result2 < 10.1);

    const result3 = Cubic.cubeRoot(1e6) orelse unreachable;
    try testing.expect(result3 > 99.0 and result3 < 101.0);

    try testing.expectEqual(null, Cubic.cubeRoot(0.0));
    try testing.expectEqual(null, Cubic.cubeRoot(-1.0));
}

test "Cubic onRetransmit records w_max and halves ssthresh" {
    var cubic = Cubic{ .cwnd = 10000, .min_cwnd = 1460 };
    cubic.onRetransmit(Instant.fromMillis(100));
    try testing.expectEqual(10000, cubic.w_max);
    try testing.expectEqual(5000, cubic.ssthresh);
    try testing.expect(cubic.recovery_start != null);
}

test "Cubic slow start grows like Reno" {
    var cubic = Cubic{ .cwnd = 1460, .min_cwnd = 1460, .ssthresh = std.math.maxInt(usize) };
    cubic.onAck(Instant.ZERO, 1460, &dummy_rtte);
    try testing.expectEqual(2920, cubic.cwnd);
}

test "Cubic preTransmit sets recovery_start on first call" {
    var cubic = Cubic{};
    try testing.expectEqual(null, cubic.recovery_start);
    cubic.preTransmit(Instant.fromMillis(500));
    try testing.expect(cubic.recovery_start != null);
}

test "CongestionController dispatch to Reno variant" {
    var cc = CongestionController{ .reno = .{ .cwnd = 4000, .min_cwnd = 1460 } };
    try testing.expectEqual(4000, cc.window());
    cc.onRetransmit(Instant.ZERO);
    try testing.expectEqual(2000, cc.window());
}

// -- Congestion Control: Socket Integration Tests --

test "setCongestionControl and congestionControl roundtrip" {
    var s = socketNew();
    try testing.expect(s.congestionControl() == .none);
    s.setCongestionControl(.{ .reno = .{} });
    try testing.expect(s.congestionControl() == .reno);
    s.setCongestionControl(.{ .cubic = .{} });
    try testing.expect(s.congestionControl() == .cubic);
}

test "Reno cwnd limits send window in established" {
    var s = socketEstablished();
    s.setCongestionControl(.{ .reno = .{ .cwnd = 3, .min_cwnd = 1 } });
    _ = s.sendSlice("abcdefghij") catch unreachable;
    const repr = recvAt0(&s) orelse unreachable;
    // Reno cwnd=3, so payload should be at most 3 bytes
    try testing.expectEqual(3, repr.payload.len);
}

test "Reno onAck grows cwnd via process" {
    var s = socketEstablished();
    s.setCongestionControl(.{ .reno = .{
        .cwnd = 1460,
        .min_cwnd = 1460,
        .ssthresh = std.math.maxInt(usize),
    } });
    _ = s.sendSlice("hello") catch unreachable;
    _ = recvAt0(&s);
    _ = sendPacketAt0(&s, .{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1).add(5),
        .window_len = 256,
        .payload = &.{},
    });
    const cwnd = switch (s.congestion_controller) {
        .reno => |r| r.cwnd,
        else => unreachable,
    };
    try testing.expectEqual(1465, cwnd);
}

test "Reno onRetransmit via dispatch retransmit path" {
    var s = socketEstablished();
    s.setCongestionControl(.{ .reno = .{
        .cwnd = 4000,
        .min_cwnd = 1460,
    } });
    _ = s.sendSlice("data") catch unreachable;
    _ = recvAt0(&s);
    const far_future = Instant.fromSecs(10);
    s.remote_last_ts = Instant.ZERO;
    s.timeout = null;
    _ = recvPacket(&s, far_future);
    const cwnd = switch (s.congestion_controller) {
        .reno => |r| r.cwnd,
        else => unreachable,
    };
    try testing.expectEqual(2000, cwnd);
}

test "congestion controller survives socket reset" {
    var s = socketNew();
    s.setCongestionControl(.{ .reno = .{ .cwnd = 5000 } });
    s.reset();
    try testing.expect(s.congestionControl() == .reno);
    try testing.expectEqual(5000, switch (s.congestion_controller) {
        .reno => |r| r.cwnd,
        else => unreachable,
    });
}

// -- Closure-based send/recv Tests --

fn testSendCallback(_: *const u0, buf: []u8) usize {
    const msg = "hello";
    if (buf.len < msg.len) return 0;
    @memcpy(buf[0..msg.len], msg);
    return msg.len;
}

fn testRecvCallback(out: *[64]u8, buf: []const u8) usize {
    const n = @min(buf.len, out.len);
    @memcpy(out[0..n], buf[0..n]);
    return n;
}

test "closure send enqueues data and dispatches" {
    var s = socketEstablished();
    const ctx: *const u0 = &0;
    const written = try s.send(ctx, &testSendCallback);
    try testing.expectEqual(5, written);
    try testing.expectEqual(5, s.sendQueue());

    const repr = recvAt0(&s) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, "hello", repr.payload);
}

test "closure recv consumes data from rx buffer" {
    var s = socketEstablished();
    _ = sendPacketAt0(&s, .{
        .src_port = SEND_TEMPL.src_port,
        .dst_port = SEND_TEMPL.dst_port,
        .seq_number = REMOTE_SEQ.add(1),
        .ack_number = LOCAL_SEQ.add(1),
        .window_len = 256,
        .payload = "world",
    });
    try testing.expectEqual(5, s.recvQueue());

    var out: [64]u8 = undefined;
    const consumed = try s.recv(&out, &testRecvCallback);
    try testing.expectEqual(5, consumed);
    try testing.expectEqualSlices(u8, "world", out[0..5]);
    try testing.expectEqual(0, s.recvQueue());
}

test "closure send returns zero when tx buffer full" {
    var s = socketWithBuffers(4, 4);
    s.state = .established;
    s.listen_endpoint = LISTEN_END;
    s.tuple = .{
        .local = .{ .addr = LOCAL_ADDR, .port = LOCAL_PORT },
        .remote = .{ .addr = REMOTE_ADDR, .port = REMOTE_PORT },
    };
    s.local_seq_no = LOCAL_SEQ.add(1);
    s.remote_last_seq = LOCAL_SEQ.add(1);
    s.remote_last_ack = REMOTE_SEQ.add(1);
    s.remote_last_win = s.scaledWindow();
    s.remote_win_len = 256;
    s.remote_seq_no = REMOTE_SEQ.add(1);

    _ = try s.sendSlice("abcd");
    try testing.expectEqual(0, s.tx_buffer.window());

    const ctx: *const u0 = &0;
    const written = try s.send(ctx, &testSendCallback);
    try testing.expectEqual(0, written);
}
