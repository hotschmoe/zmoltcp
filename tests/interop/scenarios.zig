//! End-to-end scenarios: zmoltcp against a real smoltcp peer over a harness-controlled link.

const std = @import("std");
const zv = @import("zv");
const h = @import("harness.zig");

const Side = h.Side;

fn other(s: Side) Side {
    return if (s == .zig) .peer else .zig;
}

fn peerPath() ![]u8 {
    return h.peerExe(std.testing.allocator, std.testing.environ);
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

/// Run one one-directional transfer to a graceful close and compare what arrived.
fn runTransfer(sim: anytype, client: Side, sender: Side, total: u64, seed: u64, limit_us: u64) !Verdict {
    try sim.open(client);
    switch (sender) {
        .zig => sim.zSend(seed, total, true),
        .peer => try sim.peer.sendStream(seed, total, true),
    }
    const completed = try sim.runUntil({}, bothDone, limit_us);
    const want = h.streamHash(seed, total);
    const ps = try sim.peerStatus();
    const rt = if (sender == .zig) ps.rx_total else sim.rx_total;
    const rh = if (sender == .zig) ps.rx_hash else sim.rx_hash;
    return .{ .completed = completed, .exact = rt == total and rh == want, .receiver_total = rt, .receiver_hash = rh };
}

fn expectVerdict(v: Verdict) !void {
    if (!v.completed or !v.exact) {
        std.debug.print("transfer verdict: completed={} exact={} receiver_total={d} hash={x}\n", .{ v.completed, v.exact, v.receiver_total, v.receiver_hash });
        return error.TransferFailed;
    }
}

fn fixture(comptime v6: bool, cfg: h.SimConfig) !*h.Sim(v6) {
    const exe = try peerPath();
    defer std.testing.allocator.free(exe);
    return h.Sim(v6).create(std.testing.allocator, std.testing.io, exe, cfg);
}

fn dieWith(sim: anytype, err: anyerror) anyerror {
    if (err == error.PeerDied) std.debug.print("peer died: {s}\n", .{sim.peer.deathMessage()});
    return err;
}

// 1. handshake + small echo

fn echoScenario(comptime v6: bool, client: Side) !void {
    const sim = try fixture(v6, .{ .peer = .{ .auto_close_on_eof = true }, .z_auto_close_on_eof = true });
    defer sim.destroy();
    errdefer sim.dump("echo");
    sim.echo = true;
    try sim.peer.setEcho(true);
    // the client sends, half-closes, and reads the echo back
    try sim.open(client);
    const seed = 77;
    const total = 3000;
    switch (client) {
        .zig => sim.zSend(seed, total, true),
        .peer => try sim.peer.sendStream(seed, total, true),
    }
    // only the server echoes
    if (client == .zig) sim.echo = false else try sim.peer.setEcho(false);
    const done = sim.runUntil({}, bothDone, 30_000_000) catch |e| return dieWith(sim, e);
    try std.testing.expect(done);
    const ps = try sim.peerStatus();
    const want = h.streamHash(seed, total);
    if (client == .zig) {
        try std.testing.expectEqual(@as(u64, total), sim.rx_total);
        try std.testing.expectEqual(want, sim.rx_hash);
        try std.testing.expectEqual(@as(u64, total), ps.rx_total);
    } else {
        try std.testing.expectEqual(@as(u64, total), ps.rx_total);
        try std.testing.expectEqual(want, ps.rx_hash);
        try std.testing.expectEqual(@as(u64, total), sim.rx_total);
    }
}

test "1 handshake and echo, zmoltcp client, IPv4" {
    try echoScenario(false, .zig);
}
