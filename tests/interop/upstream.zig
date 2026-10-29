//! Probes for suspected upstream smoltcp bugs: the exact segment sequences behind the zmoltcp
//! fixes 33f8ac7, c9fc1fc, 644e024 and 626d8da, injected as raw frames at a real smoltcp peer.
//!
//! No zmoltcp stack is involved: the harness plays the remote end by hand. Each probe records
//! what the peer did (panic message and location, or the observable protocol behavior) and
//! checks it against the characterized behavior for the smoltcp revision and cargo profile the
//! peer was built as (ZMOLTCP_PEER_VARIANT, ZMOLTCP_PEER_PROFILE). A change in upstream
//! behavior, in either direction, fails the probe so the verdict gets revisited.
//!
//! Verdicts (smoltcp 08bacc9 = ref/smoltcp, 24bda3b = upstream main on 2026-10-28):
//!
//!   c9fc1fc unscaled SYN window shifted   CONFIRMED on both. A peer that offers window scaling
//!                                         against a receive ring over 64 KiB makes smoltcp
//!                                         accept bytes up to twice the ring (tcp.rs:1675 on
//!                                         08bacc9, 1784 on main, shifts the unscaled 65535 that
//!                                         tcp.rs:2643 / 2915 stored): panics in
//!                                         ring_buffer.rs:345 (release) or at the debug_assert in
//!                                         tcp.rs:2152 / 2312 (assertions on). Not reported upstream.
//!   644e024 lastScaledWindow underflow    FIXED-UPSTREAM. Panics on 08bacc9 (wire/tcp.rs:73 via
//!                                         last_scaled_window, tcp.rs:766) when poll_at runs between
//!                                         ingress and egress after a simultaneous open; fixed by
//!                                         336a1dd (PR 1223, 2026-10-22). Same family as issues
//!                                         1048 and 1051 (closed by PR 1079).
//!   33f8ac7 FIN at zero window edge       NOT REPRODUCED. smoltcp's RFC 9293 acceptability arms
//!                                         (tcp.rs:1688-1735) reject the segment zmoltcp sliced;
//!                                         the arithmetic hazard in last_scaled_window was only
//!                                         reachable through simultaneous open (above).
//!   626d8da FIN after window truncation   CONFIRMED on both: the FIN of a segment whose payload
//!                                         the window cut is acknowledged and ends the stream
//!                                         (tcp.rs:1804 / 1946 only guards a hole in front; payload
//!                                         is trimmed at 1742 / 1851). Silent truncation.
//!   audit 12 RST in SYN_RECEIVED          NOT REPRODUCED. The stale last_ack is masked because the
//!                                         pending SYN-ACK keeps seq_to_transmit true.

const std = @import("std");
const h = @import("harness.zig");

const Z_PORT: u16 = 50000;
const P_PORT: u16 = 4000;
const Z_ISN: u32 = 1000;

const Outcome = struct {
    /// First line of the panic message, when the peer died.
    panic: ?[]const u8 = null,
    state: ?h.State = null,
    ack: ?u32 = null,
    rx_total: ?u64 = null,
    rx_hash_ok: ?bool = null,
    rx_finished: ?bool = null,
    recv_queue: ?u32 = null,
    note: []const u8 = "",
};

const Raw = struct {
    gpa: std.mem.Allocator,
    peer: *h.PeerProc,
    now: u64 = 0,
    inbox: std.ArrayList(h.Frame) = .empty,
    peer_isn: u32 = 0,
    dead: bool = false,

    fn start(gpa: std.mem.Allocator, io: std.Io, exe: []const u8, cfg_in: h.PeerConfig) !*Raw {
        var cfg = cfg_in;
        cfg.v6 = false;
        cfg.ack_delay_off = true;
        const self = try gpa.create(Raw);
        errdefer gpa.destroy(self);
        self.* = .{ .gpa = gpa, .peer = try h.PeerProc.start(gpa, io, exe, cfg) };
        try self.arpRequest();
        try self.tick(1000);
        return self;
    }

    fn deinit(self: *Raw) void {
        self.peer.deinit();
        self.inbox.deinit(self.gpa);
        self.gpa.destroy(self);
    }

    fn arpRequest(self: *Raw) !void {
        var f: [42]u8 = undefined;
        @memset(f[0..6], 0xff);
        @memcpy(f[6..12], &h.Z_MAC);
        f[12] = 0x08;
        f[13] = 0x06;
        @memcpy(f[14..22], &[_]u8{ 0, 1, 8, 0, 6, 4, 0, 1 });
        @memcpy(f[22..28], &h.Z_MAC);
        @memcpy(f[28..32], &h.Z_V4);
        @memset(f[32..38], 0);
        @memcpy(f[38..42], &h.P_V4);
        try self.peer.deliver(&f);
    }

    fn tick(self: *Raw, advance_us: u64) !void {
        self.now += advance_us;
        self.inbox.clearRetainingCapacity();
        _ = self.peer.tick(self.now, &self.inbox) catch |e| {
            self.dead = true;
            return e;
        };
    }

    const Seg = struct {
        seq: u32,
        ack: ?u32 = null,
        flags: u8 = 0,
        win: u16 = 1000,
        opts: []const u8 = &.{},
        payload: []const u8 = &.{},
        sport: u16 = Z_PORT,
        dport: u16 = P_PORT,
    };

    fn send(self: *Raw, s: Seg) !void {
        var buf: [70000]u8 = undefined;
        const f = h.buildTcp(&buf, .{
            .src_port = s.sport,
            .dst_port = s.dport,
            .seq = s.seq,
            .ack = s.ack,
            .flags = s.flags,
            .window = s.win,
            .options = s.opts,
            .payload = s.payload,
        });
        self.peer.deliver(f) catch |e| {
            self.dead = true;
            return e;
        };
    }

    /// Deliver a segment and let the peer run one millisecond.
    fn sendTick(self: *Raw, s: Seg) !void {
        try self.send(s);
        try self.tick(1000);
    }

    fn lastTcp(self: *Raw) ?h.TcpInfo {
        var last: ?h.TcpInfo = null;
        for (self.inbox.items) |*f| {
            if (h.parseTcp(f.slice())) |i| last = i;
        }
        return last;
    }

    fn handshake(self: *Raw, syn_opts: []const u8, syn_win: u16) !void {
        try self.sendTick(.{ .seq = Z_ISN, .flags = h.SYN, .win = syn_win, .opts = syn_opts });
        const sa = self.lastTcp() orelse return error.NoSynAck;
        if (!sa.has(h.SYN)) return error.NoSynAck;
        self.peer_isn = sa.seq;
        try self.sendTick(.{ .seq = Z_ISN + 1, .ack = self.peer_isn +% 1, .win = syn_win });
    }

    fn status(self: *Raw) ?h.PeerStatus {
        if (self.dead) return null;
        return self.peer.query() catch null;
    }
};

const NOP_WS0 = [_]u8{ 1, 3, 3, 0 };

fn firstLine(raw: *Raw, buf: []u8) []const u8 {
    const msg = raw.peer.deathMessage();
    var it = std.mem.splitScalar(u8, msg, '\n');
    var out: usize = 0;
    // "thread 'main' (id) panicked at <file:line:col>:" then the message line
    while (it.next()) |line| {
        if (line.len == 0 or std.mem.startsWith(u8, line, "note:")) continue;
        const trimmed = std.mem.trim(u8, line, "\r ");
        if (out + trimmed.len + 3 > buf.len) break;
        if (out > 0) {
            @memcpy(buf[out..][0..3], " | ");
            out += 3;
        }
        @memcpy(buf[out..][0..trimmed.len], trimmed);
        out += trimmed.len;
        if (out > 0 and std.mem.indexOf(u8, buf[0..out], " | ") != null) break;
    }
    return buf[0..out];
}

// ---------------------------------------------------------------------------
// Hand-written probes: the minimal wire sequence for each suspected bug.
// ---------------------------------------------------------------------------

/// 33f8ac7: a FIN arrives at the edge of a zero window, then more segments in the same ingress
/// batch (no egress in between, as in the law), and the socket is asked for its poll time.
fn probeFinAtZeroWindowEdge(raw: *Raw, out: *Outcome) !void {
    try raw.peer.setRecv(false);
    _ = try raw.peer.listen(P_PORT);
    try raw.handshake(&.{}, 1000);
    var data: [64]u8 = undefined;
    h.fillStream(7, 0, &data);
    try raw.sendTick(.{ .seq = Z_ISN + 1, .ack = raw.peer_isn +% 1, .payload = &data });
    out.note = if (raw.lastTcp()) |f| (if (f.window == 0) "full buffer, window 0 advertised" else "window not zero") else "no ack";
    const ack = raw.peer_isn +% 1;
    try raw.send(.{ .seq = Z_ISN + 1 + 64, .ack = ack, .flags = h.FIN });
    try raw.send(.{ .seq = Z_ISN + 1 + 64 + 1, .ack = ack });
    try raw.send(.{ .seq = Z_ISN + 1 + 64, .ack = ack });
    try raw.send(.{ .seq = Z_ISN + 1 + 64 + 1, .ack = ack, .payload = "x" });
    try raw.peer.ingress(raw.now);
    _ = try raw.peer.pollAtOnly(raw.now);
    try raw.tick(1000);
    if (raw.lastTcp()) |f| out.ack = f.ack;
}

/// The same edge reached through FIN_WAIT_2: we close first, the remote acks, then its FIN lands on a zero window.
fn probeFinAtZeroWindowEdgeFinWait(raw: *Raw, out: *Outcome) !void {
    _ = out;
    try raw.peer.setRecv(false);
    _ = try raw.peer.listen(P_PORT);
    try raw.handshake(&.{}, 1000);
    var data: [64]u8 = undefined;
    h.fillStream(7, 0, &data);
    try raw.sendTick(.{ .seq = Z_ISN + 1, .ack = raw.peer_isn +% 1, .payload = &data });
    try raw.peer.close();
    try raw.tick(1000);
    const fin_ack = if (raw.lastTcp()) |f| f.seq +% 1 else raw.peer_isn +% 2;
    try raw.send(.{ .seq = Z_ISN + 1 + 64, .ack = fin_ack });
    try raw.peer.ingress(raw.now);
    _ = try raw.peer.pollAtOnly(raw.now);
    try raw.send(.{ .seq = Z_ISN + 1 + 64, .ack = fin_ack, .flags = h.FIN });
    try raw.send(.{ .seq = Z_ISN + 1 + 64 + 1, .ack = fin_ack });
    try raw.peer.ingress(raw.now);
    _ = try raw.peer.pollAtOnly(raw.now);
    try raw.tick(1000);
}

/// c9fc1fc: a remote that offers window scale 0 against a 65536-byte receive ring (shift 1). The
/// SYN-ACK carries the unscaled 65535, which smoltcp shifts again when it computes its window edge.
fn probeUnscaledSynWindow(raw: *Raw, out: *Outcome) !void {
    _ = try raw.peer.listen(P_PORT);
    try raw.handshake(&NOP_WS0, 1000);
    var big: [60000]u8 = undefined;
    var small: [6000]u8 = undefined;
    h.fillStream(3, 0, &big);
    h.fillStream(3, 60000, &small);
    try raw.sendTick(.{ .seq = Z_ISN + 1 + 60000, .ack = raw.peer_isn +% 1, .payload = &small });
    try raw.sendTick(.{ .seq = Z_ISN + 1, .ack = raw.peer_isn +% 1, .payload = &big });
    try raw.peer.setRecv(true);
    try raw.tick(1000);
    if (raw.status()) |s| {
        out.rx_total = s.rx_total;
        out.recv_queue = s.recv_queue;
        out.rx_hash_ok = s.rx_hash == h.streamHash(3, @min(s.rx_total, 66000));
    }
}

/// The same overshoot with a single out-of-order segment and no filling one.
fn probeUnscaledSynWindowSingle(raw: *Raw, out: *Outcome) !void {
    _ = try raw.peer.listen(P_PORT);
    try raw.handshake(&NOP_WS0, 1000);
    var seg: [1400]u8 = undefined;
    h.fillStream(3, 0, &seg);
    // starts inside the real window (65535) and ends past the ring: 65000 + 1400 > 65536
    try raw.sendTick(.{ .seq = Z_ISN + 1 + 65000, .ack = raw.peer_isn +% 1, .payload = &seg });
    if (raw.status()) |s| out.recv_queue = s.recv_queue;
}

/// 644e024, our SYN already sent: a bare SYN (simultaneous open) while the peer is in SYN-SENT.
fn probeSimultaneousOpenDispatched(raw: *Raw, out: *Outcome) !void {
    if (!try raw.peer.connect(Z_PORT, P_PORT)) return error.ConnectRefused;
    try raw.tick(1000);
    try raw.send(.{ .seq = Z_ISN, .flags = h.SYN, .win = 100, .sport = Z_PORT, .dport = P_PORT });
    try raw.peer.ingress(raw.now);
    _ = try raw.peer.pollAtOnly(raw.now);
    try raw.tick(1000);
    if (raw.lastTcp()) |f| out.ack = f.ack;
}

/// 644e024, our SYN still undispatched: the remote's SYN is processed before any egress, and the
/// socket is asked for its poll time before it ever transmitted.
fn probeSimultaneousOpenUndispatched(raw: *Raw, out: *Outcome) !void {
    if (!try raw.peer.connect(Z_PORT, P_PORT)) return error.ConnectRefused;
    try raw.send(.{ .seq = Z_ISN, .flags = h.SYN, .win = 100, .sport = Z_PORT, .dport = P_PORT });
    try raw.peer.ingress(raw.now);
    _ = try raw.peer.pollAtOnly(raw.now);
    try raw.tick(1000);
    if (raw.lastTcp()) |f| out.ack = f.ack;
}

/// Audit finding 12: RST in SYN_RECEIVED returns a listener to LISTEN with its old last-ack, then a
/// distant SYN arrives and the socket is asked for its poll time before it transmits.
fn probeRstThenSyn(raw: *Raw, out: *Outcome) !void {
    _ = try raw.peer.listen(P_PORT);
    try raw.sendTick(.{ .seq = Z_ISN, .flags = h.SYN, .win = 100 });
    try raw.sendTick(.{ .seq = Z_ISN + 1, .flags = h.RST, .win = 0 });
    if (raw.status()) |s| out.note = if (s.state == .listen) "back in LISTEN" else "not listening";
    try raw.send(.{ .seq = 1_000_000, .flags = h.SYN, .win = 100 });
    try raw.peer.ingress(raw.now);
    _ = try raw.peer.pollAtOnly(raw.now);
    try raw.tick(1000);
}

/// 626d8da: 100 payload bytes and a FIN in one segment against a 64-byte window.
fn probeFinAfterTruncation(raw: *Raw, out: *Outcome) !void {
    _ = try raw.peer.listen(P_PORT);
    try raw.handshake(&.{}, 1000);
    var data: [100]u8 = undefined;
    h.fillStream(5, 0, &data);
    try raw.sendTick(.{ .seq = Z_ISN + 1, .ack = raw.peer_isn +% 1, .flags = h.FIN, .payload = &data });
    if (raw.lastTcp()) |f| out.ack = f.ack;
    // what the sender does next: retransmit from the acknowledged point, FIN included
    try raw.tick(300_000);
    try raw.sendTick(.{ .seq = Z_ISN + 1 + 65, .ack = raw.peer_isn +% 1, .flags = h.FIN, .payload = data[65..] });
    if (raw.status()) |s| {
        out.rx_total = s.rx_total;
        out.rx_hash_ok = s.rx_hash == h.streamHash(5, s.rx_total);
        out.rx_finished = s.rx_finished;
    }
}

// ---------------------------------------------------------------------------
// Replay of the pinned zmoltcp law counterexamples against smoltcp.
//
// zmoltcp's own socket is the oracle that generates the segment stream (the laws derive each
// segment from the socket's state); every ingress is mirrored to smoltcp with acknowledgment
// numbers shifted by the difference of the two initial sequence numbers, every dispatch becomes
// an egress poll, and every pollAt a poll_at query. Shifting our side of the sequence space is an
// isomorphism, so the segments mean the same to smoltcp as they did to zmoltcp.
// ---------------------------------------------------------------------------

const zm = @import("zmoltcp");
const pt = @import("pinned_tcp.zig");
const OracleSock = zm.socket.tcp.Socket(zm.wire.ipv4, 4);
const Seq = zm.wire.tcp.SeqNumber;

const ReplayLog = struct {
    ops_done: usize = 0,
    clipped: usize = 0,
    delivered: usize = 0,
    died_at: ?usize = null,
    died_kind: u8 = 0,
    last_state: h.State = .closed,
};

var replay_rx: [140_000]u8 = undefined;
var replay_tx: [4096]u8 = undefined;
var replay_payload: [280_000]u8 = @splat(0x5a);
var replay_opts: pt.Opts = undefined;

fn tsSeven() u32 {
    return 7;
}

fn buildOptions(buf: *[40]u8, r: zm.socket.tcp.TcpRepr) []const u8 {
    var n: usize = 0;
    if (r.max_seg_size) |m| {
        buf[n..][0..4].* = .{ 2, 4, @intCast(m >> 8), @truncate(m) };
        n += 4;
    }
    if (r.window_scale) |w| {
        buf[n..][0..4].* = .{ 1, 3, 3, w };
        n += 4;
    }
    if (r.sack_permitted) {
        buf[n..][0..4].* = .{ 1, 1, 4, 2 };
        n += 4;
    }
    if (r.timestamp) |t| {
        buf[n..][0..4].* = .{ 1, 1, 8, 10 };
        std.mem.writeInt(u32, buf[n + 4 ..][0..4], t.tsval, .big);
        std.mem.writeInt(u32, buf[n + 8 ..][0..4], t.tsecr, .big);
        n += 12;
    }
    return buf[0..n];
}

const Replay = struct {
    raw: *Raw,
    s: OracleSock,
    cap: usize,
    isn: Seq,
    last_sent_end: ?Seq = null,
    o_isn: ?u32 = null,
    p_isn: ?u32 = null,
    log: *ReplayLog,

    const local = h.P_V4; // the socket under test is the peer
    const remote = h.Z_V4; // the segments come from the harness

    fn op(self: *Replay, o: pt.Op, now: zm.time.Instant, now_us: u64) !void {
        const s = &self.s;
        const raw = self.raw;
        switch (o.kind % 14) {
            0, 1, 2, 3, 4, 5, 6, 7 => {
                var r: zm.socket.tcp.TcpRepr = .{ .src_port = 5000, .dst_port = 80 };
                const handshaking = s.state == .listen or s.state == .syn_sent;
                r.control = if (s.state == .listen) .syn else switch (o.a % 9) {
                    0 => .syn,
                    1, 2 => .fin,
                    3 => .rst,
                    4 => .psh,
                    else => .none,
                };
                const opts = replay_opts;
                if (r.control == .syn and opts.ws) r.window_scale = @intCast(o.b % 15);
                if (r.control == .syn) r.max_seg_size = if (o.b & 1 == 0) null else o.b;
                if (r.control == .syn) r.sack_permitted = opts.sack;
                if (r.control == .syn and opts.ts) r.timestamp = .{ .tsval = 1, .tsecr = 0 };
                const base = if (handshaking) self.isn else s.remote_seq_no.add(s.rx_buffer.len());
                const cap = self.cap;
                const offset: usize = switch (o.c % 8) {
                    0, 1, 2 => 0,
                    3 => o.b % 100,
                    4 => cap / 2 + o.b % 64,
                    5 => cap -| (o.b % 64),
                    6 => cap + o.b % 64,
                    else => o.b,
                };
                r.seq_number = if (r.control == .syn) self.isn else base.add(offset);
                if (s.state != .listen and !(s.state == .syn_sent and r.control == .syn and o.b & 4 != 0)) {
                    r.ack_number = switch (o.b % 6) {
                        0, 1, 2 => self.last_sent_end orelse s.local_seq_no,
                        3 => s.local_seq_no.add(1),
                        4 => s.local_seq_no,
                        else => Seq.fromU32(@as(u32, o.a) *% 65537),
                    };
                }
                r.window_len = switch (o.a % 5) {
                    0 => 0,
                    1 => 100,
                    2 => 65535,
                    else => o.a,
                };
                const plen: usize = switch ((o.a >> 4) % 8) {
                    0, 1, 2 => 0,
                    3 => 1,
                    4 => o.b % 64,
                    5 => cap / 2,
                    6 => cap + o.b % 129,
                    else => @min(2 * cap, replay_payload.len),
                };
                r.payload = replay_payload[0..plen];
                if (!s.accepts(remote, local, r)) return;
                _ = s.process(now, remote, local, r);
                if (s.state == .syn_sent or s.state == .syn_received) self.o_isn = s.local_seq_no.toU32();

                const delta: u32 = if (self.o_isn) |a| (if (self.p_isn) |b| b -% a else 0) else 0;
                var seg_payload: []const u8 = r.payload;
                if (seg_payload.len > 65535 - 60) {
                    seg_payload = seg_payload[0 .. 65535 - 60];
                    self.log.clipped += 1;
                }
                var opt_buf: [40]u8 = undefined;
                try raw.send(.{
                    .seq = r.seq_number.toU32(),
                    .ack = if (r.ack_number) |a| a.toU32() +% delta else null,
                    .flags = switch (r.control) {
                        .none => 0,
                        .psh => h.PSH,
                        .syn => h.SYN,
                        .fin => h.FIN,
                        .rst => h.RST,
                    },
                    .win = r.window_len,
                    .opts = buildOptions(&opt_buf, r),
                    .payload = seg_payload,
                    .sport = 5000,
                    .dport = 80,
                });
                self.log.delivered += 1;
                try raw.peer.ingress(now_us);
            },
            8, 9 => {
                if (s.dispatch(now)) |d| self.last_sent_end = d.repr.seq_number.add(d.repr.segmentLen());
                raw.inbox.clearRetainingCapacity();
                raw.peer.egress(now_us, &raw.inbox) catch |e| {
                    raw.dead = true;
                    return e;
                };
                for (raw.inbox.items) |*f| {
                    if (h.parseTcp(f.slice())) |i| {
                        if (i.has(h.SYN)) self.p_isn = i.seq;
                    }
                }
            },
            10 => {
                var out: [512]u8 = undefined;
                _ = s.recvSlice(out[0 .. o.a % 512]) catch {};
                _ = try raw.peer.recvNow(o.a % 512);
            },
            11 => {
                _ = s.sendSlice(replay_payload[0 .. o.a % 1500]) catch 0;
                _ = try raw.peer.writeBytes(o.a % 1500);
            },
            12 => switch (o.a % 5) {
                0 => {
                    s.close();
                    try raw.peer.close();
                },
                1 => {
                    s.abort();
                    try raw.peer.abort();
                },
                2 => if (!s.isOpen()) {
                    s.connect(remote, 5000, local, 80) catch {};
                    self.o_isn = s.local_seq_no.toU32();
                    self.p_isn = null;
                    _ = try raw.peer.connect(5000, 80);
                },
                3 => if (!s.isOpen()) {
                    s.listen(.{ .port = 80 }) catch {};
                    self.o_isn = null;
                    self.p_isn = null;
                    _ = try raw.peer.listen(80);
                },
                else => {},
            },
            else => {},
        }
        _ = s.pollAt();
        _ = try raw.peer.pollAtOnly(now_us);
    }
};

fn replayCase(gpa: std.mem.Allocator, io: std.Io, exe: []const u8, rx_pick: usize, secret: u32, ops: [48]pt.Op, log: *ReplayLog, msg: *[512]u8, msg_len: *usize) !void {
    const cap = pt.rx_sizes[rx_pick];
    const raw = try Raw.start(gpa, io, exe, .{ .rx_buf = @intCast(cap), .tx_buf = 4096, .timestamps = replay_opts.ts, .seed = secret });
    defer raw.deinit();
    var rep: Replay = .{
        .raw = raw,
        .s = OracleSock.initWithInitialSequenceSecret(replay_rx[0..cap], &replay_tx, secret),
        .cap = cap,
        .isn = Seq.fromU32(secret),
        .log = log,
    };
    rep.s.listen(.{ .port = 80 }) catch unreachable;
    if (replay_opts.ts) rep.s.setTsvalGenerator(&tsSeven);
    _ = try raw.peer.listen(80);

    var now_ms: i64 = 0;
    for (ops, 0..) |o, idx| {
        log.ops_done = idx;
        now_ms += o.c;
        const now_us: u64 = @intCast(now_ms * 1000);
        raw.now = now_us;
        rep.op(o, zm.time.Instant.fromMillis(now_ms), now_us) catch |e| switch (e) {
            error.PeerDied => {
                log.died_at = idx;
                log.died_kind = o.kind % 14;
                var tmp: [512]u8 = undefined;
                const line = firstLine(raw, &tmp);
                @memcpy(msg[0..line.len], line);
                msg_len.* = line.len;
                return;
            },
            else => return e,
        };
        if (raw.status()) |st| log.last_state = st.state;
    }
    log.ops_done = ops.len;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

const Probe = struct {
    name: []const u8,
    func: *const fn (*Raw, *Outcome) anyerror!void,
    rx_buf: u32,
};

const probes = [_]Probe{
    .{ .name = "fin-at-zero-window-edge", .func = probeFinAtZeroWindowEdge, .rx_buf = 64 },
    .{ .name = "fin-at-zero-window-edge-finwait", .func = probeFinAtZeroWindowEdgeFinWait, .rx_buf = 64 },
    .{ .name = "unscaled-syn-window", .func = probeUnscaledSynWindow, .rx_buf = 65536 },
    .{ .name = "unscaled-syn-window-single-segment", .func = probeUnscaledSynWindowSingle, .rx_buf = 65536 },
    .{ .name = "simultaneous-open-dispatched", .func = probeSimultaneousOpenDispatched, .rx_buf = 64 },
    .{ .name = "simultaneous-open-undispatched", .func = probeSimultaneousOpenUndispatched, .rx_buf = 64 },
    .{ .name = "rst-in-syn-received-then-syn", .func = probeRstThenSyn, .rx_buf = 64 },
    .{ .name = "fin-after-window-truncation", .func = probeFinAfterTruncation, .rx_buf = 64 },
};

fn envOr(gpa: std.mem.Allocator, key: []const u8, default: []const u8) ![]u8 {
    return std.testing.environ.getAlloc(gpa, key) catch try gpa.dupe(u8, default);
}

test "upstream probes: minimal wire sequences behind the four zmoltcp fixes" {
    const gpa = std.testing.allocator;
    const exe = try h.peerExe(gpa, std.testing.environ);
    defer gpa.free(exe);
    const variant = try envOr(gpa, "ZMOLTCP_PEER_VARIANT", "?");
    defer gpa.free(variant);
    const profile = try envOr(gpa, "ZMOLTCP_PEER_PROFILE", "?");
    defer gpa.free(profile);

    for (probes) |p| {
        const raw = try Raw.start(gpa, std.testing.io, exe, .{ .rx_buf = p.rx_buf, .tx_buf = 4096 });
        defer raw.deinit();
        var out: Outcome = .{};
        var msg_buf: [512]u8 = undefined;
        p.func(raw, &out) catch |e| switch (e) {
            error.PeerDied => {
                out.panic = firstLine(raw, &msg_buf);
                if (std.testing.environ.getAlloc(gpa, "ZMOLTCP_FULL_PANIC")) |v| {
                    gpa.free(v);
                    std.debug.print("{s}", .{raw.peer.deathMessage()});
                } else |_| {}
            },
            else => return e,
        };
        if (out.panic == null) {
            if (raw.status()) |s| out.state = s.state;
        }
        std.debug.print("PROBE {s} {s}/{s}: panic=[{s}] state={s} ack={?d} rx_total={?d} data_ok={?} eof={?} recv_queue={?d} note=[{s}]\n", .{
            p.name,
            variant,
            profile,
            out.panic orelse "",
            if (out.state) |s| @tagName(s) else "-",
            if (out.ack) |a| a -% Z_ISN else null,
            out.rx_total,
            out.rx_hash_ok,
            out.rx_finished,
            out.recv_queue,
            out.note,
        });
        try expectProbe(p.name, variant, profile, out);
    }
}

/// Where the characterized smoltcp panics, as a substring of the panic line; null means no panic.
/// The ring is 65536 bytes; with debug assertions the debug_assert! in tcp.rs fires before the
/// hard assert in ring_buffer.rs.
fn expectedPanic(name: []const u8, variant: []const u8, profile: []const u8) ?[]const u8 {
    const is_ref = std.mem.eql(u8, variant, "ref");
    const release = std.mem.eql(u8, profile, "release");
    const eql = std.mem.eql;
    if (eql(u8, name, "unscaled-syn-window") or (eql(u8, name, "unscaled-syn-window-single-segment") and !release)) {
        if (release) return "ring_buffer.rs:345";
        return if (is_ref) "tcp.rs:2152" else "tcp.rs:2312";
    }
    // 336a1dd (smoltcp PR 1223) fixed the underflow in last_scaled_window.
    if (eql(u8, name, "simultaneous-open-undispatched") and is_ref) return "tcp.rs:73";
    return null;
}

fn expectProbe(name: []const u8, variant: []const u8, profile: []const u8, out: Outcome) !void {
    const want = expectedPanic(name, variant, profile);
    if (want) |needle| {
        const got = out.panic orelse return error.ExpectedPanicDidNotHappen;
        if (std.mem.indexOf(u8, got, needle) == null) return error.PanicLocationChanged;
    } else if (out.panic != null) return error.UnexpectedPanic;
    const eql = std.mem.eql;
    // smoltcp acknowledges a FIN whose payload the window truncated: ack covers the FIN (66), the
    // stream ends after 64 of the 100 bytes, and the retransmission is ignored.
    if (eql(u8, name, "fin-after-window-truncation")) {
        if (out.ack != @as(?u32, Z_ISN + 66) or out.rx_total != 64 or out.rx_finished != true or out.state != .close_wait)
            return error.FinTruncationBehaviorChanged;
    }
    if (eql(u8, name, "fin-at-zero-window-edge") and out.state != .close_wait) return error.UnexpectedState;
    if (eql(u8, name, "fin-at-zero-window-edge-finwait") and out.state != .time_wait) return error.UnexpectedState;
}

test "upstream replay: the pinned zmoltcp law counterexamples against smoltcp" {
    const gpa = std.testing.allocator;
    const exe = try h.peerExe(gpa, std.testing.environ);
    defer gpa.free(exe);
    const variant = try envOr(gpa, "ZMOLTCP_PEER_VARIANT", "?");
    defer gpa.free(variant);
    const profile = try envOr(gpa, "ZMOLTCP_PEER_PROFILE", "?");
    defer gpa.free(profile);

    inline for (comptime std.meta.fieldNames(@TypeOf(pt.pinned))) |law| {
        inline for (@field(pt.pinned, law), 0..) |case, n| {
            var ops: [48]pt.Op = undefined;
            inline for (case[3], 0..) |o, i| ops[i] = .{ .kind = o.kind, .a = o.a, .b = o.b, .c = o.c };
            replay_opts = .{ .v6 = case[2].v6, .ws = case[2].ws, .ts = case[2].ts, .sack = case[2].sack };
            var log: ReplayLog = .{};
            var msg: [512]u8 = undefined;
            var msg_len: usize = 0;
            try replayCase(gpa, std.testing.io, exe, case[0], case[1], ops, &log, &msg, &msg_len);
            std.debug.print("REPLAY {s}#{d} {s}/{s}: ops={d} delivered={d} clipped={d} panic=[{s}] died_at={?d} (op kind {d}) final_peer_state={s}\n", .{
                law,
                n,
                variant,
                profile,
                log.ops_done,
                log.delivered,
                log.clipped,
                msg[0..msg_len],
                log.died_at,
                log.died_kind,
                @tagName(log.last_state),
            });
            // The only pinned case that reaches a smoltcp panic does it through simultaneous open on
            // 08bacc9 (fixed by 336a1dd); the others run to the end on both revisions.
            const expect_panic = std.mem.eql(u8, variant, "ref") and std.mem.eql(u8, law, "ringsStayInBounds") and n == 0;
            if (expect_panic != (log.died_at != null)) return error.ReplayBehaviorChanged;
            if (expect_panic and std.mem.indexOf(u8, msg[0..msg_len], "tcp.rs:73") == null) return error.PanicLocationChanged;
        }
    }
}
