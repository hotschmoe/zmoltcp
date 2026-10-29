//! End-to-end scenarios: zmoltcp against a real smoltcp peer over a harness-controlled link.
//!
//! Each scenario runs in both directions (which side connects, which side sends) and over IPv4
//! and IPv6 where the protocol path differs. A failure means the two stacks disagree; the
//! failing dump names the side that diverged from the wire.

const std = @import("std");
const zv = @import("zv");
const h = @import("harness.zig");

const Side = h.Side;
const Dir = h.Dir;

const sides = [_]Side{ .zig, .peer };

fn other(s: Side) Side {
    return if (s == .zig) .peer else .zig;
}

fn fixture(comptime v6: bool, cfg: h.SimConfig) !*h.Sim(v6) {
    const gpa = std.testing.allocator;
    const exe = try h.peerExe(gpa, std.testing.environ);
    defer gpa.free(exe);
    return h.Sim(v6).create(gpa, std.testing.io, exe, cfg);
}

const Verdict = struct {
    completed: bool,
    exact: bool,
    receiver_total: u64,
    receiver_hash: u64,
};

fn transferConfig(base: h.SimConfig, sender: Side) h.SimConfig {
    var cfg = base;
    cfg.peer.auto_close_on_eof = sender == .zig;
    cfg.z_auto_close_on_eof = sender == .peer;
    return cfg;
}

fn bothDone(_: void, sim: anytype) !bool {
    const ps = try sim.peerStatus();
    return sim.zState().isDone() and ps.state.isDone();
}

fn bothEstablished(_: void, sim: anytype) !bool {
    const ps = try sim.peerStatus();
    return sim.zState() == .established and ps.state == .established;
}

fn report(sim: anytype, err: anyerror) anyerror {
    if (err == error.PeerDied) std.debug.print("peer died: {s}\n", .{sim.peer.deathMessage()});
    return err;
}

fn failDump(sim: anytype, what: []const u8) anyerror {
    std.debug.print("{s}\n", .{what});
    sim.dump("fail");
    return error.ScenarioFailed;
}

/// Run one one-directional transfer to a graceful close and compare what arrived.
fn runTransfer(sim: anytype, client: Side, sender: Side, total: u64, seed: u64, limit_us: u64) !Verdict {
    try sim.open(client);
    switch (sender) {
        .zig => sim.zSend(seed, total, true),
        .peer => try sim.peer.sendStream(seed, total, true),
    }
    const completed = sim.runUntil({}, bothDone, limit_us) catch |e| return report(sim, e);
    const want = h.streamHash(seed, total);
    const ps = try sim.peerStatus();
    const rt = if (sender == .zig) ps.rx_total else sim.rx_total;
    const rh = if (sender == .zig) ps.rx_hash else sim.rx_hash;
    return .{ .completed = completed, .exact = rt == total and rh == want, .receiver_total = rt, .receiver_hash = rh };
}

fn expectVerdict(sim: anytype, v: Verdict) !void {
    if (!v.completed or !v.exact) {
        std.debug.print("completed={} exact={} receiver_total={d} hash={x}\n", .{ v.completed, v.exact, v.receiver_total, v.receiver_hash });
        sim.dump("verdict");
        return error.TransferFailed;
    }
}

const S = 1000 * 1000;

// ---------------------------------------------------------------------------
// 1. handshake + small echo
// ---------------------------------------------------------------------------

fn echoScenario(comptime v6: bool, client: Side) !void {
    const sim = try fixture(v6, .{ .peer = .{ .auto_close_on_eof = true }, .z_auto_close_on_eof = true });
    defer sim.destroy();
    errdefer sim.dump("echo");
    const seed = 77;
    const total = 3000;
    // The server echoes, the client sends and half-closes, then reads the echo back.
    if (client == .zig) try sim.peer.setEcho(true) else sim.echo = true;
    try sim.open(client);
    switch (client) {
        .zig => sim.zSend(seed, total, true),
        .peer => try sim.peer.sendStream(seed, total, true),
    }
    const done = sim.runUntil({}, bothDone, 30 * S) catch |e| return report(sim, e);
    try std.testing.expect(done);
    const ps = try sim.peerStatus();
    const want = h.streamHash(seed, total);
    try std.testing.expectEqual(@as(u64, total), ps.rx_total);
    try std.testing.expectEqual(@as(u64, total), sim.rx_total);
    try std.testing.expectEqual(want, ps.rx_hash);
    try std.testing.expectEqual(want, sim.rx_hash);
}

test "1 handshake and echo" {
    inline for (.{ false, true }) |v6| {
        for (sides) |client| try echoScenario(v6, client);
    }
}

// ---------------------------------------------------------------------------
// 2. bulk transfer, byte exact
// ---------------------------------------------------------------------------

fn bulkScenario(comptime v6: bool, client: Side, sender: Side) !void {
    const sim = try fixture(v6, transferConfig(.{
        .z_rx = 48 * 1024,
        .z_tx = 48 * 1024,
        .peer = .{ .rx_buf = 48 * 1024, .tx_buf = 48 * 1024 },
    }, sender));
    defer sim.destroy();
    errdefer sim.dump("bulk");
    const v = try runTransfer(sim, client, sender, 1 << 20, 0xb01c, 120 * S);
    try expectVerdict(sim, v);
}

test "2 bulk transfer of 1 MiB, byte exact" {
    inline for (.{ false, true }) |v6| {
        for (sides) |client| for (sides) |sender| try bulkScenario(v6, client, sender);
    }
}

// ---------------------------------------------------------------------------
// 3. bulk transfer over a lossy, reordering link
// ---------------------------------------------------------------------------

fn lossyScenario(comptime v6: bool, client: Side, sender: Side, seed: u64) !void {
    const sim = try fixture(v6, transferConfig(.{
        .z_rx = 48 * 1024,
        .z_tx = 48 * 1024,
        .peer = .{ .rx_buf = 48 * 1024, .tx_buf = 48 * 1024 },
        .sched = .{
            .seed = seed,
            .delay_us = 5000,
            .jitter_us = 2000,
            .loss_pm = 50,
            .reorder_pm = 50,
            .dup_pm = 10,
        },
    }, sender));
    defer sim.destroy();
    errdefer sim.dump("lossy");
    const v = try runTransfer(sim, client, sender, 1 << 20, 0x1055, 1200 * S);
    try expectVerdict(sim, v);
    const t = sim.link.tap;
    try std.testing.expect(t.dropped[0] + t.dropped[1] > 0);
    try std.testing.expect(t.reordered[0] + t.reordered[1] > 0);
}

test "3 bulk transfer with 5 percent loss and reordering" {
    for (sides) |sender| try lossyScenario(false, other(sender), sender, 0xa11ce);
    for (sides) |sender| try lossyScenario(true, sender, sender, 0xb0b);
}

// ---------------------------------------------------------------------------
// 4. window scaling with buffers over 64 KiB
// ---------------------------------------------------------------------------

fn windowScaleScenario(comptime v6: bool, sender: Side) !void {
    const sim = try fixture(v6, transferConfig(.{
        .z_rx = 256 * 1024,
        .z_tx = 256 * 1024,
        .peer = .{ .rx_buf = 256 * 1024, .tx_buf = 256 * 1024 },
        .sched = .{ .delay_us = 20_000 },
    }, sender));
    defer sim.destroy();
    errdefer sim.dump("window scale");
    const v = try runTransfer(sim, other(sender), sender, 1 << 20, 0x5ca1e, 120 * S);
    try expectVerdict(sim, v);
    const t = sim.link.tap;
    // both SYNs offered a scale factor and the receiver advertised more than 64 KiB
    const client_dir: usize = @backingInt(Dir.from(other(sender)));
    try std.testing.expect(t.first_syn[client_dir].?.ws != null);
    try std.testing.expect(t.synack[1 - client_dir].?.ws != null);
    const recv_dir: usize = if (sender == .zig) 1 else 0;
    if (t.max_eff_window[recv_dir] <= 65535) {
        std.debug.print("max effective window {d}\n", .{t.max_eff_window[recv_dir]});
        return error.WindowNeverExceeded64K;
    }
}

test "4 window scaling with buffers over 64 KiB" {
    inline for (.{ false, true }) |v6| {
        for (sides) |sender| try windowScaleScenario(v6, sender);
    }
}

// ---------------------------------------------------------------------------
// 5. zero window, persist, resume
// ---------------------------------------------------------------------------

const ZeroCtx = struct { receiver: Side, rx_cap: u32, saw_full: bool = false };

fn receiverFull(ctx: *ZeroCtx, sim: anytype) !bool {
    const q: u32 = if (ctx.receiver == .zig) @intCast(sim.sock.recvQueue()) else (try sim.peerStatus()).recv_queue;
    ctx.saw_full = q >= ctx.rx_cap;
    const recv_dir: usize = if (ctx.receiver == .zig) 0 else 1;
    return ctx.saw_full and sim.link.tap.zero_window_acks[recv_dir] > 0;
}

fn zeroWindowScenario(comptime v6: bool, sender: Side) !void {
    const rx_cap: u32 = 8 * 1024;
    const receiver = other(sender);
    var cfg: h.SimConfig = transferConfig(.{ .z_rx = rx_cap, .z_tx = 32 * 1024, .peer = .{ .rx_buf = rx_cap, .tx_buf = 32 * 1024 } }, sender);
    cfg.z_ack_delay_ms = 10;
    const sim = try fixture(v6, cfg);
    defer sim.destroy();
    errdefer sim.dump("zero window");
    const total: u64 = 96 * 1024;
    const seed = 0x2e60;
    try sim.open(other(sender));
    if (receiver == .zig) sim.recv_enabled = false else try sim.peer.setRecv(false);
    switch (sender) {
        .zig => sim.zSend(seed, total, true),
        .peer => try sim.peer.sendStream(seed, total, true),
    }
    var ctx: ZeroCtx = .{ .receiver = receiver, .rx_cap = rx_cap };
    const stalled = sim.runUntil(&ctx, receiverFull, 30 * S) catch |e| return report(sim, e);
    if (!stalled) return failDump(sim, "receiver never advertised a zero window");
    // sit in persist for a while: the sender must keep probing without overrunning the buffer
    const frames_before = sim.link.tap.frames[@backingInt(Dir.from(sender))];
    try sim.runFor(20 * S);
    const frames_after = sim.link.tap.frames[@backingInt(Dir.from(sender))];
    if (frames_after == frames_before) return failDump(sim, "sender stopped probing a zero window");
    if (frames_after - frames_before > 200) return failDump(sim, "sender flooded a zero window");
    const ps = try sim.peerStatus();
    const delivered = if (receiver == .zig) sim.rx_total else ps.rx_total;
    try std.testing.expectEqual(@as(u64, 0), delivered);
    // reopen the window and finish
    if (receiver == .zig) sim.recv_enabled = true else try sim.peer.setRecv(true);
    const done = sim.runUntil({}, bothDone, 120 * S) catch |e| return report(sim, e);
    try std.testing.expect(done);
    const ps2 = try sim.peerStatus();
    const rt = if (receiver == .zig) sim.rx_total else ps2.rx_total;
    const rh = if (receiver == .zig) sim.rx_hash else ps2.rx_hash;
    try std.testing.expectEqual(total, rt);
    try std.testing.expectEqual(h.streamHash(seed, total), rh);
}

test "5 zero window, persist probes, resume" {
    inline for (.{ false, true }) |v6| {
        for (sides) |sender| try zeroWindowScenario(v6, sender);
    }
}

// ---------------------------------------------------------------------------
// 6. simultaneous close
// ---------------------------------------------------------------------------

fn simultaneousCloseScenario(comptime v6: bool, client: Side) !void {
    const sim = try fixture(v6, .{});
    defer sim.destroy();
    errdefer sim.dump("simultaneous close");
    try sim.open(client);
    const up = sim.runUntil({}, bothEstablished, 30 * S) catch |e| return report(sim, e);
    try std.testing.expect(up);
    sim.sock.close();
    try sim.peer.close();
    const done = sim.runUntil({}, bothDone, 60 * S) catch |e| return report(sim, e);
    try std.testing.expect(done);
    try std.testing.expect(sim.sawState(.closing));
    try std.testing.expectEqual(h.State.time_wait, sim.zState());
}

fn simultaneousCloseWithData(comptime v6: bool, client: Side) !void {
    const sim = try fixture(v6, .{
        .z_rx = 32 * 1024,
        .z_tx = 32 * 1024,
        .peer = .{ .rx_buf = 32 * 1024, .tx_buf = 32 * 1024 },
        .sched = .{ .delay_us = 3000 },
    });
    defer sim.destroy();
    errdefer sim.dump("simultaneous close with data");
    const total: u64 = 100_000;
    try sim.open(client);
    sim.zSend(1, total, true);
    try sim.peer.sendStream(2, total, true);
    const done = sim.runUntil({}, bothDone, 120 * S) catch |e| return report(sim, e);
    try std.testing.expect(done);
    const ps = try sim.peerStatus();
    try std.testing.expectEqual(total, ps.rx_total);
    try std.testing.expectEqual(h.streamHash(1, total), ps.rx_hash);
    try std.testing.expectEqual(total, sim.rx_total);
    try std.testing.expectEqual(h.streamHash(2, total), sim.rx_hash);
}

test "6 simultaneous close" {
    inline for (.{ false, true }) |v6| {
        for (sides) |client| {
            try simultaneousCloseScenario(v6, client);
            try simultaneousCloseWithData(v6, client);
        }
    }
}

// ---------------------------------------------------------------------------
// 7. half-close: one side shuts its write half, the other keeps sending
// ---------------------------------------------------------------------------

fn halfCloseScenario(comptime v6: bool, client: Side, shutter: Side) !void {
    const sim = try fixture(v6, .{
        .z_rx = 32 * 1024,
        .z_tx = 32 * 1024,
        .peer = .{ .rx_buf = 32 * 1024, .tx_buf = 32 * 1024 },
        .sched = .{ .delay_us = 2000 },
    });
    defer sim.destroy();
    errdefer sim.dump("half close");
    const short: u64 = 10_000;
    const long: u64 = 200_000;
    try sim.open(client);
    const z_total: u64 = if (shutter == .zig) short else long;
    const p_total: u64 = if (shutter == .peer) short else long;
    sim.zSend(11, z_total, true);
    try sim.peer.sendStream(12, p_total, true);
    const done = sim.runUntil({}, bothDone, 120 * S) catch |e| return report(sim, e);
    try std.testing.expect(done);
    const ps = try sim.peerStatus();
    try std.testing.expectEqual(z_total, ps.rx_total);
    try std.testing.expectEqual(h.streamHash(11, z_total), ps.rx_hash);
    try std.testing.expectEqual(p_total, sim.rx_total);
    try std.testing.expectEqual(h.streamHash(12, p_total), sim.rx_hash);
    // zmoltcp sat in the half-closed state on its side
    try std.testing.expect(sim.sawState(if (shutter == .zig) .fin_wait_2 else .close_wait));
}

test "7 half-close" {
    inline for (.{ false, true }) |v6| {
        for (sides) |client| for (sides) |shutter| try halfCloseScenario(v6, client, shutter);
    }
}

// ---------------------------------------------------------------------------
// 8. RST / abort mid-transfer
// ---------------------------------------------------------------------------

const AbortCtx = struct { receiver: Side, at: u64 };

fn receivedEnough(ctx: *AbortCtx, sim: anytype) !bool {
    const got = if (ctx.receiver == .zig) sim.rx_total else (try sim.peerStatus()).rx_total;
    return got >= ctx.at;
}

fn abortScenario(comptime v6: bool, sender: Side, aborter: Side) !void {
    const sim = try fixture(v6, transferConfig(.{
        .z_rx = 32 * 1024,
        .z_tx = 32 * 1024,
        .peer = .{ .rx_buf = 32 * 1024, .tx_buf = 32 * 1024 },
        .sched = .{ .delay_us = 2000 },
    }, sender));
    defer sim.destroy();
    errdefer sim.dump("abort");
    try sim.open(other(sender));
    switch (sender) {
        .zig => sim.zSend(5, 1 << 20, true),
        .peer => try sim.peer.sendStream(5, 1 << 20, true),
    }
    var ctx: AbortCtx = .{ .receiver = other(sender), .at = 100_000 };
    const mid = sim.runUntil(&ctx, receivedEnough, 60 * S) catch |e| return report(sim, e);
    try std.testing.expect(mid);
    switch (aborter) {
        .zig => sim.sock.abort(),
        .peer => try sim.peer.abort(),
    }
    const done = sim.runUntil({}, bothDone, 30 * S) catch |e| return report(sim, e);
    try std.testing.expect(done);
    // the aborted side reset the other one: no graceful close, and the RST is on the wire
    const ps = try sim.peerStatus();
    const rst_dir: usize = @backingInt(Dir.from(aborter));
    try std.testing.expect(sim.link.tap.rsts[rst_dir] >= 1);
    try std.testing.expectEqual(h.State.closed, sim.zState());
    try std.testing.expectEqual(h.State.closed, ps.state);
}

test "8 abort mid-transfer resets the peer" {
    inline for (.{ false, true }) |v6| {
        for (sides) |sender| for (sides) |aborter| try abortScenario(v6, sender, aborter);
    }
}

// ---------------------------------------------------------------------------
// 9. SACK and timestamps, negotiated versus declined
// ---------------------------------------------------------------------------

fn optionsScenario(comptime v6: bool, z_ts: bool, p_ts: bool, sender: Side) !void {
    const sim = try fixture(v6, transferConfig(.{
        .z_timestamps = z_ts,
        .z_rx = 48 * 1024,
        .z_tx = 48 * 1024,
        .peer = .{ .timestamps = p_ts, .rx_buf = 48 * 1024, .tx_buf = 48 * 1024 },
    }, sender));
    defer sim.destroy();
    errdefer sim.dump("timestamps");
    const v = try runTransfer(sim, other(sender), sender, 200_000, 9, 60 * S);
    try expectVerdict(sim, v);
    const t = sim.link.tap;
    const send_dir: usize = @backingInt(Dir.from(sender));
    const client_dir: usize = @backingInt(Dir.from(other(sender)));
    const syn = t.first_syn[client_dir].?;
    const synack = t.synack[1 - client_dir].?;
    const client_ts = if (other(sender) == .zig) z_ts else p_ts;
    const server_ts = if (sender == .zig) z_ts else p_ts;
    try std.testing.expectEqual(client_ts, syn.ts);
    try std.testing.expectEqual(client_ts and server_ts, synack.ts);
    if (z_ts and p_ts) {
        try std.testing.expect(t.ts_data_segments[send_dir] == t.data_segments[send_dir]);
    } else {
        try std.testing.expectEqual(@as(u64, 0), t.ts_data_segments[send_dir]);
    }
}

test "9a timestamps negotiated only when both sides enable them" {
    inline for (.{ false, true }) |v6| {
        for ([_]bool{ false, true }) |z_ts| for ([_]bool{ false, true }) |p_ts| for (sides) |sender|
            try optionsScenario(v6, z_ts, p_ts, sender);
    }
}

fn sackScenario(comptime v6: bool, sender: Side, strip: bool) !void {
    const sim = try fixture(v6, transferConfig(.{
        .z_rx = 48 * 1024,
        .z_tx = 48 * 1024,
        .peer = .{ .rx_buf = 48 * 1024, .tx_buf = 48 * 1024 },
        .sched = .{ .seed = 99, .delay_us = 4000, .loss_pm = 30, .reorder_pm = 30, .strip_sack = strip },
    }, sender));
    defer sim.destroy();
    errdefer sim.dump("sack");
    const v = try runTransfer(sim, other(sender), sender, 300_000, 31, 600 * S);
    try expectVerdict(sim, v);
    const t = sim.link.tap;
    const recv_dir: usize = 1 - @backingInt(Dir.from(sender));
    const client_dir: usize = @backingInt(Dir.from(other(sender)));
    try std.testing.expectEqual(!strip, t.first_syn[client_dir].?.sack_perm);
    if (strip) {
        try std.testing.expectEqual(@as(u64, 0), t.sack_acks[0] + t.sack_acks[1]);
    } else {
        if (t.sack_acks[recv_dir] == 0) return failDump(sim, "no SACK blocks although negotiated and segments were lost");
    }
}

test "9b SACK negotiated and declined" {
    inline for (.{ false, true }) |v6| {
        for (sides) |sender| for ([_]bool{ false, true }) |strip| try sackScenario(v6, sender, strip);
    }
}

fn declinedScaleScenario(sender: Side) !void {
    const sim = try fixture(false, transferConfig(.{
        .z_rx = 128 * 1024,
        .z_tx = 128 * 1024,
        .peer = .{ .rx_buf = 128 * 1024, .tx_buf = 128 * 1024 },
        .sched = .{ .strip_ws = true, .delay_us = 5000 },
    }, sender));
    defer sim.destroy();
    errdefer sim.dump("window scale declined");
    const v = try runTransfer(sim, other(sender), sender, 400_000, 8, 120 * S);
    try expectVerdict(sim, v);
    const t = sim.link.tap;
    try std.testing.expect(t.max_eff_window[0] <= 65535 and t.max_eff_window[1] <= 65535);
}

test "9c window scaling declined" {
    for (sides) |sender| try declinedScaleScenario(sender);
}

// ---------------------------------------------------------------------------
// 10. MSS / MTU edges
// ---------------------------------------------------------------------------

fn mssScenario(comptime v6: bool, sender: Side, peer_mtu: u16, ts: bool) !void {
    const sim = try fixture(v6, transferConfig(.{
        .z_timestamps = ts,
        .z_rx = 48 * 1024,
        .z_tx = 48 * 1024,
        .peer = .{ .timestamps = ts, .mtu = peer_mtu, .rx_buf = 48 * 1024, .tx_buf = 48 * 1024 },
    }, sender));
    defer sim.destroy();
    errdefer sim.dump("mss");
    const v = try runTransfer(sim, other(sender), sender, 400_000, 10, 60 * S);
    try expectVerdict(sim, v);
    const t = sim.link.tap;
    const ip_hdr: usize = if (v6) 60 else 40;
    const ts_len: usize = if (ts) 12 else 0;
    const dir: usize = @backingInt(Dir.from(sender));
    // the largest segment a sender may use: the smaller of its own and the receiver's MTU
    const mtu: usize = @min(@as(usize, peer_mtu), 1514) - 14;
    const want_payload = mtu - ip_hdr - ts_len;
    if (t.max_payload[dir] != want_payload) {
        std.debug.print("max payload {d}, expected {d} (mtu {d})\n", .{ t.max_payload[dir], want_payload, peer_mtu });
        return failDump(sim, "segment size is not the largest the path allows");
    }
    try std.testing.expect(t.max_frame[dir] <= mtu + 14);
}

test "10 MSS and MTU edges" {
    inline for (.{ false, true }) |v6| {
        for (sides) |sender| {
            try mssScenario(v6, sender, 1514, false);
            try mssScenario(v6, sender, 1514, true);
            try mssScenario(v6, sender, if (v6) 1294 else 1300, false);
        }
    }
}

// ---------------------------------------------------------------------------
// Law: a transfer over any link schedule is byte exact
// ---------------------------------------------------------------------------

const transfer_sizes = [_]u64{ 1, 1000, 30_000, 100_000 };

const LinkFlags = struct { z_sends: bool, v6: bool, big_buffers: bool, timestamps: bool };

fn exactOver(comptime v6: bool, seed: u64, sched: h.Schedule, f: LinkFlags, total: u64) bool {
    const z_buf: usize = if (f.big_buffers) 160 * 1024 else 24 * 1024;
    const sender: Side = if (f.z_sends) .zig else .peer;
    const sim = fixture(v6, transferConfig(.{
        .z_rx = z_buf,
        .z_tx = z_buf,
        .z_timestamps = f.timestamps,
        .z_secret = seed,
        .peer = .{ .rx_buf = 24 * 1024, .tx_buf = 24 * 1024, .timestamps = f.timestamps, .seed = seed },
        .sched = sched,
    }, sender)) catch return false;
    defer sim.destroy();
    const v = runTransfer(sim, other(sender), sender, total, seed, 3600 * S) catch |e| {
        std.debug.print("law: transfer errored: {s}\n", .{@errorName(e)});
        return false;
    };
    return v.completed and v.exact;
}

pub const transfer_laws = struct {
    /// Whatever the link does (drops, duplicates, reorders, delays, corrupts), what the receiver
    /// gets is exactly what the sender sent, and both sides reach a closed state.
    pub fn transferIsExact(
        seed: u64,
        loss_pm: zv.Ranged(0, 150),
        dup_pm: zv.Ranged(0, 50),
        reorder_pm: zv.Ranged(0, 200),
        corrupt_pm: zv.Ranged(0, 30),
        delay_ms: zv.Ranged(1, 40),
        jitter_ms: zv.Ranged(0, 8),
        size_pick: zv.Ranged(0, transfer_sizes.len - 1),
        f: LinkFlags,
    ) bool {
        const sched: h.Schedule = .{
            .seed = seed,
            .delay_us = @as(u32, delay_ms.get()) * 1000,
            .jitter_us = @as(u32, jitter_ms.get()) * 1000,
            .loss_pm = @intCast(loss_pm.get()),
            .dup_pm = @intCast(dup_pm.get()),
            .reorder_pm = @intCast(reorder_pm.get()),
            .corrupt_pm = @intCast(corrupt_pm.get()),
        };
        const total = transfer_sizes[size_pick.get()];
        return if (f.v6) exactOver(true, seed, sched, f, total) else exactOver(false, seed, sched, f, total);
    }
};
test "law: transferIsExact over seeded link schedules" {
    try zv.checkLaws(transfer_laws, .{ .iterations = 200, .seed = 0x7ac3 });
}
