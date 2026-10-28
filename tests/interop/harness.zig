//! Interop harness: a zmoltcp Stack and a real smoltcp peer (tests/interop/peer) joined by a
//! link this file controls. Both sides run on one virtual clock the harness advances; the
//! link drops, duplicates, reorders, delays and corrupts frames from a seeded schedule.
//!
//!   zmoltcp Stack <-> Dev <-> [Link: schedule, tap] <-> stdin/stdout framing <-> smoltcp peer
//!
//! Nothing here reads the wall clock or touches the network, so a run is a pure function
//! of its configuration and seeds.

const std = @import("std");
const zmoltcp = @import("zmoltcp");

const stack_mod = zmoltcp.stack;
const tcp_socket = zmoltcp.socket.tcp;
const iface_mod = zmoltcp.iface;
const ipv4 = zmoltcp.wire.ipv4;
const ipv6 = zmoltcp.wire.ipv6;
const ethernet = zmoltcp.wire.ethernet;
const Instant = zmoltcp.time.Instant;

pub const MAX_FRAME = 1514;
pub const Frame = struct {
    len: u16 = 0,
    data: [MAX_FRAME]u8 = undefined,

    pub fn slice(self: *const Frame) []const u8 {
        return self.data[0..self.len];
    }

    pub fn from(bytes: []const u8) Frame {
        var f: Frame = .{ .len = @intCast(bytes.len) };
        @memcpy(f.data[0..bytes.len], bytes);
        return f;
    }
};

pub const Side = enum { zig, peer };
pub const Dir = enum(u1) {
    to_peer,
    to_zig,

    pub fn from(side: Side) Dir {
        return if (side == .zig) .to_peer else .to_zig;
    }
};

pub const Z_MAC: [6]u8 = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
pub const P_MAC: [6]u8 = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
pub const Z_V4: [4]u8 = .{ 10, 0, 0, 1 };
pub const P_V4: [4]u8 = .{ 10, 0, 0, 2 };
pub const SERVER_PORT: u16 = 4000;
pub const CLIENT_PORT: u16 = 50000;

pub fn linkLocal(mac: [6]u8) [16]u8 {
    return iface_mod.Interface.linkLocalFromMac(mac);
}

// ---------------------------------------------------------------------------
// Deterministic byte stream, identical to the peer's
// ---------------------------------------------------------------------------

fn mix(x: u64) u64 {
    var z = x +% 0x9E37_79B9_7F4A_7C15;
    z = (z ^ (z >> 30)) *% 0xBF58_476D_1CE4_E5B9;
    z = (z ^ (z >> 27)) *% 0x94D0_49BB_1331_11EB;
    return z ^ (z >> 31);
}

pub fn streamByte(seed: u64, i: u64) u8 {
    return @truncate(mix(seed ^ (i >> 3)) >> @intCast((i & 7) * 8));
}

pub fn fillStream(seed: u64, start: u64, out: []u8) void {
    for (out, 0..) |*b, k| b.* = streamByte(seed, start + k);
}

pub const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

pub fn fnvUpdate(h_in: u64, data: []const u8) u64 {
    var h = h_in;
    for (data) |b| {
        h ^= b;
        h *%= 0x0000_0100_0000_01b3;
    }
    return h;
}

pub fn streamHash(seed: u64, total: u64) u64 {
    var h = FNV_OFFSET;
    var buf: [4096]u8 = undefined;
    var pos: u64 = 0;
    while (pos < total) {
        const n: usize = @intCast(@min(total - pos, buf.len));
        fillStream(seed, pos, buf[0..n]);
        h = fnvUpdate(h, buf[0..n]);
        pos += n;
    }
    return h;
}

// ---------------------------------------------------------------------------
// Minimal independent TCP/IP frame codec (does not use the library under test)
// ---------------------------------------------------------------------------

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const PSH: u8 = 0x08;
pub const ACK: u8 = 0x10;

pub const TcpInfo = struct {
    v6: bool,
    ip_off: usize,
    tcp_off: usize,
    payload_off: usize,
    payload_len: usize,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    mss: ?u16 = null,
    ws: ?u8 = null,
    sack_perm: bool = false,
    ts: bool = false,
    sack_blocks: u8 = 0,
    sack_perm_off: ?usize = null,

    pub fn has(self: TcpInfo, f: u8) bool {
        return self.flags & f != 0;
    }
};

fn be16(b: []const u8) u16 {
    return std.mem.readInt(u16, b[0..2], .big);
}
fn be32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .big);
}

pub fn parseTcp(f: []const u8) ?TcpInfo {
    if (f.len < 14 + 20) return null;
    const et = be16(f[12..]);
    var info: TcpInfo = undefined;
    var ip_end: usize = undefined;
    if (et == 0x0800) {
        const ihl = (f[14] & 0xf) * 4;
        if (f[14] >> 4 != 4 or ihl < 20 or f[23] != 6) return null;
        info.v6 = false;
        info.ip_off = 14;
        info.tcp_off = 14 + ihl;
        ip_end = 14 + be16(f[16..]);
    } else if (et == 0x86dd) {
        if (f.len < 14 + 40 + 20 or f[20] != 6) return null;
        info.v6 = true;
        info.ip_off = 14;
        info.tcp_off = 14 + 40;
        ip_end = 14 + 40 + be16(f[18..]);
    } else return null;
    if (ip_end > f.len or info.tcp_off + 20 > ip_end) return null;
    const t = f[info.tcp_off..];
    const doff = (t[12] >> 4) * 4;
    if (doff < 20 or info.tcp_off + doff > ip_end) return null;
    info.src_port = be16(t[0..]);
    info.dst_port = be16(t[2..]);
    info.seq = be32(t[4..]);
    info.ack = be32(t[8..]);
    info.flags = t[13];
    info.window = be16(t[14..]);
    info.payload_off = info.tcp_off + doff;
    info.payload_len = ip_end - info.payload_off;
    info.mss = null;
    info.ws = null;
    info.sack_perm = false;
    info.ts = false;
    info.sack_blocks = 0;
    info.sack_perm_off = null;
    var i: usize = 20;
    while (i < doff) {
        const kind = t[i];
        if (kind == 0) break;
        if (kind == 1) {
            i += 1;
            continue;
        }
        if (i + 1 >= doff) break;
        const len = t[i + 1];
        if (len < 2 or i + len > doff) break;
        switch (kind) {
            2 => if (len == 4) {
                info.mss = be16(t[i + 2 ..]);
            },
            3 => if (len == 3) {
                info.ws = t[i + 2];
            },
            4 => {
                info.sack_perm = true;
                info.sack_perm_off = info.tcp_off + i;
            },
            5 => info.sack_blocks = (len - 2) / 8,
            8 => info.ts = true,
            else => {},
        }
        i += len;
    }
    return info;
}

fn csumAdd(sum_in: u32, data: []const u8) u32 {
    var s = sum_in;
    var i: usize = 0;
    while (i + 1 < data.len) : (i += 2) s += be16(data[i..]);
    if (data.len & 1 == 1) s += @as(u32, data[data.len - 1]) << 8;
    return s;
}

fn csumFinish(sum_in: u32) u16 {
    var s = sum_in;
    while (s >> 16 != 0) s = (s & 0xffff) + (s >> 16);
    return ~@as(u16, @truncate(s));
}

/// Recompute the IPv4 header checksum and the TCP checksum of a frame in place.
pub fn fixChecksums(f: []u8, info: TcpInfo) void {
    const tcp_len = info.payload_off + info.payload_len - info.tcp_off;
    f[info.tcp_off + 16] = 0;
    f[info.tcp_off + 17] = 0;
    var s: u32 = 0;
    if (info.v6) {
        s = csumAdd(s, f[info.ip_off + 8 .. info.ip_off + 40]);
        s += @intCast(tcp_len);
        s += 6;
    } else {
        s = csumAdd(s, f[info.ip_off + 12 .. info.ip_off + 20]);
        s += @intCast(tcp_len);
        s += 6;
        f[info.ip_off + 10] = 0;
        f[info.ip_off + 11] = 0;
        const c = csumFinish(csumAdd(0, f[info.ip_off..info.tcp_off]));
        std.mem.writeInt(u16, f[info.ip_off + 10 ..][0..2], c, .big);
    }
    s = csumAdd(s, f[info.tcp_off .. info.tcp_off + tcp_len]);
    std.mem.writeInt(u16, f[info.tcp_off + 16 ..][0..2], csumFinish(s), .big);
}

pub const SegSpec = struct {
    v6: bool = false,
    src_mac: [6]u8 = Z_MAC,
    dst_mac: [6]u8 = P_MAC,
    src_ip: [16]u8 = pad16(Z_V4),
    dst_ip: [16]u8 = pad16(P_V4),
    src_port: u16 = CLIENT_PORT,
    dst_port: u16 = SERVER_PORT,
    seq: u32 = 0,
    ack: ?u32 = null,
    flags: u8 = 0,
    window: u16 = 0,
    /// Raw options, already padded to a multiple of 4 bytes.
    options: []const u8 = &.{},
    payload: []const u8 = &.{},
};

/// Build a complete Ethernet+IP+TCP frame with valid checksums.
pub fn buildTcp(buf: []u8, spec: SegSpec) []u8 {
    std.debug.assert(spec.options.len % 4 == 0);
    @memcpy(buf[0..6], &spec.dst_mac);
    @memcpy(buf[6..12], &spec.src_mac);
    const tcp_len = 20 + spec.options.len + spec.payload.len;
    var off: usize = 14;
    if (spec.v6) {
        std.mem.writeInt(u16, buf[12..14], 0x86dd, .big);
        @memset(buf[14..54], 0);
        buf[14] = 0x60;
        std.mem.writeInt(u16, buf[18..20], @intCast(tcp_len), .big);
        buf[20] = 6;
        buf[21] = 64;
        @memcpy(buf[22..38], &spec.src_ip);
        @memcpy(buf[38..54], &spec.dst_ip);
        off = 54;
    } else {
        std.mem.writeInt(u16, buf[12..14], 0x0800, .big);
        @memset(buf[14..34], 0);
        buf[14] = 0x45;
        std.mem.writeInt(u16, buf[16..18], @intCast(20 + tcp_len), .big);
        std.mem.writeInt(u16, buf[20..22], 0x4000, .big);
        buf[22] = 64;
        buf[23] = 6;
        @memcpy(buf[26..30], spec.src_ip[0..4]);
        @memcpy(buf[30..34], spec.dst_ip[0..4]);
        off = 34;
    }
    const t = buf[off..];
    std.mem.writeInt(u16, t[0..2], spec.src_port, .big);
    std.mem.writeInt(u16, t[2..4], spec.dst_port, .big);
    std.mem.writeInt(u32, t[4..8], spec.seq, .big);
    std.mem.writeInt(u32, t[8..12], spec.ack orelse 0, .big);
    t[12] = @intCast(((20 + spec.options.len) / 4) << 4);
    t[13] = spec.flags | (if (spec.ack != null) ACK else 0);
    std.mem.writeInt(u16, t[14..16], spec.window, .big);
    t[16] = 0;
    t[17] = 0;
    t[18] = 0;
    t[19] = 0;
    @memcpy(t[20..][0..spec.options.len], spec.options);
    @memcpy(t[20 + spec.options.len ..][0..spec.payload.len], spec.payload);
    const total = off + tcp_len;
    const info = parseTcp(buf[0..total]).?;
    fixChecksums(buf[0..total], info);
    return buf[0..total];
}

// ---------------------------------------------------------------------------
// Link
// ---------------------------------------------------------------------------

/// A link schedule: everything random about the link, from one seed. Rates are per mille.
pub const Schedule = struct {
    seed: u64 = 1,
    delay_us: u32 = 1000,
    jitter_us: u32 = 0,
    loss_pm: u16 = 0,
    dup_pm: u16 = 0,
    reorder_pm: u16 = 0,
    corrupt_pm: u16 = 0,
    /// Extra delay given to a frame chosen for reordering.
    reorder_extra_us: u32 = 4000,
    /// Rewrite SYN segments so the option is not offered/accepted.
    strip_sack: bool = false,
    strip_ws: bool = false,
    /// Only the first frame in this direction is dropped, n times (handshake loss tests).
    drop_first_syn: bool = false,
};

pub const Tap = struct {
    frames: [2]u64 = .{ 0, 0 },
    dropped: [2]u64 = .{ 0, 0 },
    duplicated: [2]u64 = .{ 0, 0 },
    reordered: [2]u64 = .{ 0, 0 },
    corrupted: [2]u64 = .{ 0, 0 },
    max_frame: [2]usize = .{ 0, 0 },
    max_payload: [2]usize = .{ 0, 0 },
    data_segments: [2]u64 = .{ 0, 0 },
    ts_data_segments: [2]u64 = .{ 0, 0 },
    sack_acks: [2]u64 = .{ 0, 0 },
    zero_window_acks: [2]u64 = .{ 0, 0 },
    rsts: [2]u64 = .{ 0, 0 },
    fins: [2]u64 = .{ 0, 0 },
    max_eff_window: [2]u32 = .{ 0, 0 },
    first_syn: [2]?TcpInfo = .{ null, null },
    synack: [2]?TcpInfo = .{ null, null },
    ws_shift: [2]u8 = .{ 0, 0 },

    fn observe(self: *Tap, dir: Dir, f: []const u8) void {
        const d = @backingInt(dir);
        self.frames[d] += 1;
        self.max_frame[d] = @max(self.max_frame[d], f.len);
        const info = parseTcp(f) orelse return;
        if (info.has(SYN)) {
            if (info.has(ACK)) {
                if (self.synack[d] == null) self.synack[d] = info;
            } else if (self.first_syn[d] == null) self.first_syn[d] = info;
            self.ws_shift[d] = info.ws orelse 0;
        }
        if (info.has(RST)) self.rsts[d] += 1;
        if (info.has(FIN)) self.fins[d] += 1;
        if (info.payload_len > 0) {
            self.data_segments[d] += 1;
            self.max_payload[d] = @max(self.max_payload[d], info.payload_len);
            if (info.ts) self.ts_data_segments[d] += 1;
        }
        if (info.sack_blocks > 0) self.sack_acks[d] += 1;
        if (!info.has(SYN) and !info.has(RST) and info.has(ACK)) {
            // The receiver of this segment scales with the shift this side announced in its SYN.
            const eff = @as(u32, info.window) << @intCast(self.ws_shift[d]);
            self.max_eff_window[d] = @max(self.max_eff_window[d], eff);
            if (info.window == 0 and info.payload_len == 0 and !info.has(FIN)) self.zero_window_acks[d] += 1;
        }
    }
};

const InFlight = struct { due: u64, order: u64, dir: Dir, frame: Frame };

pub const Link = struct {
    sched: Schedule,
    rng: [2]std.Random.DefaultPrng,
    queue: std.ArrayList(InFlight) = .empty,
    order: u64 = 0,
    tap: Tap = .{},
    trace: bool = false,
    gpa: std.mem.Allocator,

    pub fn init(gpa: std.mem.Allocator, sched: Schedule) Link {
        return .{
            .sched = sched,
            .rng = .{
                std.Random.DefaultPrng.init(sched.seed ^ 0x1111_2222_3333_4444),
                std.Random.DefaultPrng.init(sched.seed ^ 0x5555_6666_7777_8888),
            },
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *Link) void {
        self.queue.deinit(self.gpa);
    }

    fn insert(self: *Link, item: InFlight) !void {
        var i = self.queue.items.len;
        while (i > 0) : (i -= 1) {
            const prev = self.queue.items[i - 1];
            if (prev.due < item.due or (prev.due == item.due and prev.order < item.order)) break;
        }
        try self.queue.insert(self.gpa, i, item);
    }

    /// Hand a frame to the link at time `now`. Every random choice is drawn for every frame so
    /// a schedule's decisions for frame k do not depend on what was decided for frame k-1.
    pub fn send(self: *Link, dir: Dir, now: u64, bytes: []const u8) !void {
        const d = @backingInt(dir);
        const s = self.sched;
        var f = Frame.from(bytes);
        if (s.strip_sack or s.strip_ws) self.mangle(&f);
        self.tap.observe(dir, f.slice());
        if (self.trace) traceFrame(dir, now, f.slice());
        const r = self.rng[d].random();
        const lose = r.uintLessThan(u16, 1000) < s.loss_pm;
        const dup = r.uintLessThan(u16, 1000) < s.dup_pm;
        const reorder = r.uintLessThan(u16, 1000) < s.reorder_pm;
        const corrupt = r.uintLessThan(u16, 1000) < s.corrupt_pm;
        const jitter: u32 = if (s.jitter_us == 0) 0 else r.uintLessThan(u32, s.jitter_us + 1);
        const flip = r.uintLessThan(u32, @as(u32, f.len) * 8);
        if (lose) {
            self.tap.dropped[d] += 1;
            return;
        }
        if (corrupt) {
            f.data[flip / 8] ^= @as(u8, 1) << @intCast(flip % 8);
            self.tap.corrupted[d] += 1;
        }
        var due = now + s.delay_us + jitter;
        if (reorder) {
            due += s.reorder_extra_us;
            self.tap.reordered[d] += 1;
        }
        self.order += 1;
        try self.insert(.{ .due = due, .order = self.order, .dir = dir, .frame = f });
        if (dup) {
            self.tap.duplicated[d] += 1;
            self.order += 1;
            try self.insert(.{ .due = due + 1, .order = self.order, .dir = dir, .frame = f });
        }
    }

    fn mangle(self: *Link, f: *Frame) void {
        const info = parseTcp(f.slice()) orelse return;
        if (!info.has(SYN)) return;
        const t = f.data[info.tcp_off..];
        const doff = (t[12] >> 4) * 4;
        var i: usize = 20;
        while (i < doff) {
            const kind = t[i];
            if (kind == 0) break;
            if (kind == 1) {
                i += 1;
                continue;
            }
            const len = t[i + 1];
            if ((kind == 4 and self.sched.strip_sack) or (kind == 3 and self.sched.strip_ws)) {
                @memset(t[i..][0..len], 1);
            }
            i += len;
        }
        fixChecksums(f.data[0..f.len], info);
    }

    pub fn nextDue(self: *const Link) ?u64 {
        return if (self.queue.items.len == 0) null else self.queue.items[0].due;
    }

    pub fn popDue(self: *Link, now: u64) ?InFlight {
        if (self.queue.items.len == 0 or self.queue.items[0].due > now) return null;
        return self.queue.orderedRemove(0);
    }
};

// ---------------------------------------------------------------------------
// Peer process
// ---------------------------------------------------------------------------

pub const PeerConfig = struct {
    v6: bool = false,
    rx_buf: u32 = 16 * 1024,
    tx_buf: u32 = 16 * 1024,
    mtu: u16 = 1514,
    timestamps: bool = false,
    nagle_off: bool = false,
    ack_delay_off: bool = false,
    auto_close_on_eof: bool = false,
    cc: enum(u8) { none = 0, reno = 1, cubic = 2 } = .none,
    seed: u64 = 0x5eed,
};

pub const PeerStatus = struct {
    state: State,
    may_send: bool,
    may_recv: bool,
    can_send: bool,
    can_recv: bool,
    active: bool,
    listening: bool,
    rx_finished: bool,
    rx_total: u64,
    rx_hash: u64,
    tx_total: u64,
    send_queue: u32,
    recv_queue: u32,
};

/// Canonical TCP state numbering shared with the peer.
pub const State = enum(u8) {
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

    pub fn fromZ(s: tcp_socket.State) State {
        return switch (s) {
            .closed => .closed,
            .listen => .listen,
            .syn_sent => .syn_sent,
            .syn_received => .syn_received,
            .established => .established,
            .fin_wait_1 => .fin_wait_1,
            .fin_wait_2 => .fin_wait_2,
            .close_wait => .close_wait,
            .closing => .closing,
            .last_ack => .last_ack,
            .time_wait => .time_wait,
        };
    }

    pub fn isDone(s: State) bool {
        return s == .closed or s == .time_wait;
    }
};

pub const PeerError = error{ PeerDied, PeerProtocol };

pub const PeerProc = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    rbuf: [64 * 1024]u8 = undefined,
    wbuf: [4096]u8 = undefined,
    reader: std.Io.File.Reader = undefined,
    writer: std.Io.File.Writer = undefined,
    /// Why the peer died, when it did (its stderr).
    death: [2048]u8 = undefined,
    death_len: usize = 0,

    pub fn start(gpa: std.mem.Allocator, io: std.Io, exe: []const u8, cfg: PeerConfig) !*PeerProc {
        const self = try gpa.create(PeerProc);
        errdefer gpa.destroy(self);
        const child = try std.process.spawn(io, .{
            .argv = &.{exe},
            .stdin = .pipe,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        self.* = .{ .gpa = gpa, .io = io, .child = child };
        self.reader = self.child.stdout.?.readerStreaming(io, &self.rbuf);
        self.writer = self.child.stdin.?.writerStreaming(io, &self.wbuf);
        var p: [24]u8 = undefined;
        p[0] = @intFromBool(cfg.v6);
        std.mem.writeInt(u32, p[1..5], cfg.rx_buf, .little);
        std.mem.writeInt(u32, p[5..9], cfg.tx_buf, .little);
        std.mem.writeInt(u16, p[9..11], cfg.mtu, .little);
        p[11] = @as(u8, @intFromBool(cfg.timestamps)) | @as(u8, @intFromBool(cfg.nagle_off)) << 1 |
            @as(u8, @intFromBool(cfg.ack_delay_off)) << 2 | @as(u8, @intFromBool(cfg.auto_close_on_eof)) << 3;
        p[12] = @backingInt(cfg.cc);
        std.mem.writeInt(u64, p[13..21], cfg.seed, .little);
        _ = try self.request('H', p[0..21], null);
        return self;
    }

    pub fn deinit(self: *PeerProc) void {
        if (self.child.id != null) {
            self.write('B', &.{}) catch {};
            self.child.kill(self.io);
        }
        self.gpa.destroy(self);
    }

    fn write(self: *PeerProc, ty: u8, payload: []const u8) !void {
        const w = &self.writer.interface;
        var hdr: [5]u8 = undefined;
        hdr[0] = ty;
        std.mem.writeInt(u32, hdr[1..5], @intCast(payload.len), .little);
        w.writeAll(&hdr) catch return self.died();
        w.writeAll(payload) catch return self.died();
        w.flush() catch return self.died();
    }

    fn died(self: *PeerProc) PeerError {
        if (self.child.stderr) |e| {
            var r = e.readerStreaming(self.io, &.{});
            self.death_len = r.interface.readSliceShort(&self.death) catch 0;
        }
        return error.PeerDied;
    }

    pub fn deathMessage(self: *const PeerProc) []const u8 {
        return self.death[0..self.death_len];
    }

    /// Send one request; collect `F` frames into `frames` (if given) and return the `A` payload
    /// (valid until the next request).
    pub fn request(self: *PeerProc, ty: u8, payload: []const u8, frames: ?*std.ArrayList(Frame)) ![]const u8 {
        try self.write(ty, payload);
        const r = &self.reader.interface;
        while (true) {
            var hdr: [5]u8 = undefined;
            r.readSliceAll(&hdr) catch return self.died();
            const len = std.mem.readInt(u32, hdr[1..5], .little);
            if (len > self.rbuf.len / 2) return error.PeerProtocol;
            const body = r.take(len) catch return self.died();
            switch (hdr[0]) {
                'F' => {
                    if (frames) |fl| try fl.append(self.gpa, Frame.from(body)) else return error.PeerProtocol;
                },
                'A' => return body,
                else => return error.PeerProtocol,
            }
        }
    }

    pub fn deliver(self: *PeerProc, frame: []const u8) !void {
        _ = try self.request('F', frame, null);
    }

    /// Advance the peer to `now` microseconds; returns its next poll time or null.
    pub fn tick(self: *PeerProc, now: u64, frames: *std.ArrayList(Frame)) !?u64 {
        var p: [8]u8 = undefined;
        std.mem.writeInt(u64, &p, now, .little);
        const a = try self.request('T', &p, frames);
        const at = std.mem.readInt(i64, a[0..8], .little);
        return if (at < 0) null else @intCast(at);
    }

    pub fn listen(self: *PeerProc, port: u16) !bool {
        var p: [2]u8 = undefined;
        std.mem.writeInt(u16, &p, port, .little);
        return (try self.request('L', &p, null))[0] != 0;
    }

    pub fn connect(self: *PeerProc, remote_port: u16, local_port: u16) !bool {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u16, p[0..2], remote_port, .little);
        std.mem.writeInt(u16, p[2..4], local_port, .little);
        return (try self.request('K', &p, null))[0] != 0;
    }

    pub fn sendStream(self: *PeerProc, seed: u64, total: u64, close_after: bool) !void {
        var p: [17]u8 = undefined;
        std.mem.writeInt(u64, p[0..8], seed, .little);
        std.mem.writeInt(u64, p[8..16], total, .little);
        p[16] = @intFromBool(close_after);
        _ = try self.request('S', &p, null);
    }

    pub fn setEcho(self: *PeerProc, on: bool) !void {
        _ = try self.request('E', &.{@intFromBool(on)}, null);
    }

    pub fn setRecv(self: *PeerProc, on: bool) !void {
        _ = try self.request('R', &.{@intFromBool(on)}, null);
    }

    pub fn recvNow(self: *PeerProc, n: u32) !u32 {
        var p: [4]u8 = undefined;
        std.mem.writeInt(u32, &p, n, .little);
        const a = try self.request('V', &p, null);
        return std.mem.readInt(u32, a[0..4], .little);
    }

    pub fn close(self: *PeerProc) !void {
        _ = try self.request('X', &.{}, null);
    }

    pub fn abort(self: *PeerProc) !void {
        _ = try self.request('Z', &.{}, null);
    }

    pub fn query(self: *PeerProc) !PeerStatus {
        const a = try self.request('Q', &.{}, null);
        return .{
            .state = @fromBackingInt(@intCast(a[0])),
            .may_send = a[1] & 1 != 0,
            .may_recv = a[1] & 2 != 0,
            .can_send = a[1] & 4 != 0,
            .can_recv = a[1] & 8 != 0,
            .active = a[1] & 16 != 0,
            .listening = a[1] & 32 != 0,
            .rx_finished = a[1] & 64 != 0,
            .rx_total = std.mem.readInt(u64, a[2..10], .little),
            .rx_hash = std.mem.readInt(u64, a[10..18], .little),
            .tx_total = std.mem.readInt(u64, a[18..26], .little),
            .send_queue = std.mem.readInt(u32, a[26..30], .little),
            .recv_queue = std.mem.readInt(u32, a[30..34], .little),
        };
    }
};

// ---------------------------------------------------------------------------
// zmoltcp device
// ---------------------------------------------------------------------------

const DEV_SLOTS = 1024;

pub const Dev = struct {
    pub const medium: iface_mod.Medium = .ethernet;

    rx: [DEV_SLOTS]Frame = undefined,
    rx_head: usize = 0,
    rx_count: usize = 0,
    tx: [DEV_SLOTS]Frame = undefined,
    tx_count: usize = 0,
    tx_overflow: u64 = 0,

    pub fn capabilities() iface_mod.DeviceCapabilities {
        return .{};
    }

    pub fn enqueueRx(self: *Dev, bytes: []const u8) void {
        if (self.rx_count == DEV_SLOTS) return;
        self.rx[(self.rx_head + self.rx_count) % DEV_SLOTS] = Frame.from(bytes);
        self.rx_count += 1;
    }

    pub fn receive(self: *Dev) ?[]const u8 {
        if (self.rx_count == 0) return null;
        const slot = &self.rx[self.rx_head];
        self.rx_head = (self.rx_head + 1) % DEV_SLOTS;
        self.rx_count -= 1;
        return slot.slice();
    }

    pub fn transmit(self: *Dev, bytes: []const u8) void {
        if (self.tx_count == DEV_SLOTS) {
            self.tx_overflow += 1;
            return;
        }
        self.tx[self.tx_count] = Frame.from(bytes);
        self.tx_count += 1;
    }
};

/// Print every frame the link sees (debugging aid).
pub var trace_all: bool = false;

var g_ts_ms: u32 = 0;
fn tsGen() u32 {
    return g_ts_ms;
}

// ---------------------------------------------------------------------------
// Simulation
// ---------------------------------------------------------------------------

pub const SimConfig = struct {
    v6: bool = false,
    sched: Schedule = .{},
    z_rx: usize = 16 * 1024,
    z_tx: usize = 16 * 1024,
    z_timestamps: bool = false,
    z_nagle: bool = true,
    z_ack_delay_ms: ?u32 = null,
    z_auto_close_on_eof: bool = false,
    z_secret: u64 = 0x2152,
    z_cc: enum { none, reno, cubic } = .none,
    peer: PeerConfig = .{},
    /// Largest idle jump when neither side has a timer.
    max_idle_us: u64 = 100_000,
};

pub const Stats = struct { steps: u64 = 0 };

pub fn Sim(comptime v6: bool) type {
    const Ip = if (v6) ipv6 else ipv4;
    const Tcp = tcp_socket.Socket(Ip, 8);
    const Sockets = if (v6) struct { tcp6_sockets: []*Tcp } else struct { tcp4_sockets: []*Tcp };
    const Stk = stack_mod.Stack(Dev, Sockets);

    return struct {
        const Self = @This();
        pub const TcpSock = Tcp;
        pub const is_v6 = v6;

        gpa: std.mem.Allocator,
        cfg: SimConfig,
        peer: *PeerProc,
        link: Link,
        dev: *Dev,
        stk: *Stk,
        sock: *Tcp,
        sock_arr: [1]*Tcp,
        rx_mem: []u8,
        tx_mem: []u8,
        now: u64 = 0,
        peer_at: ?u64 = null,
        steps: u64 = 0,
        scratch: std.ArrayList(Frame) = .empty,
        states_seen: u16 = 0,

        // zig-side application
        recv_enabled: bool = true,
        recv_limit: ?u64 = null,
        echo: bool = false,
        echo_q: std.ArrayList(u8) = .empty,
        rx_total: u64 = 0,
        rx_hash: u64 = FNV_OFFSET,
        rx_finished: bool = false,
        gen_seed: u64 = 0,
        gen_total: u64 = 0,
        gen_done: u64 = 0,
        close_after_send: bool = false,
        tx_total: u64 = 0,
        auto_close_on_eof: bool = false,
        /// Optional hook run each step after the apps (scenario-specific actions).
        hook: ?*const fn (*Self) anyerror!void = null,

        pub const z_addr: Ip.Address = if (v6) linkLocal(Z_MAC) else Z_V4;
        pub const p_addr: Ip.Address = if (v6) linkLocal(P_MAC) else P_V4;

        pub fn create(gpa: std.mem.Allocator, io: std.Io, peer_exe: []const u8, cfg_in: SimConfig) !*Self {
            var cfg = cfg_in;
            cfg.v6 = v6;
            cfg.peer.v6 = v6;
            const self = try gpa.create(Self);
            errdefer gpa.destroy(self);
            const peer = try PeerProc.start(gpa, io, peer_exe, cfg.peer);
            errdefer peer.deinit();
            const dev = try gpa.create(Dev);
            errdefer gpa.destroy(dev);
            dev.* = .{};
            const sock = try gpa.create(Tcp);
            errdefer gpa.destroy(sock);
            const rx_mem = try gpa.alloc(u8, cfg.z_rx);
            errdefer gpa.free(rx_mem);
            const tx_mem = try gpa.alloc(u8, cfg.z_tx);
            errdefer gpa.free(tx_mem);
            const stk = try gpa.create(Stk);
            errdefer gpa.destroy(stk);

            sock.* = Tcp.initWithInitialSequenceSecret(rx_mem, tx_mem, cfg.z_secret);
            sock.setNagleEnabled(cfg.z_nagle);
            sock.setAckDelay(if (cfg.z_ack_delay_ms) |ms| zmoltcp.time.Duration.fromMillis(ms) else null);
            if (cfg.z_timestamps) sock.setTsvalGenerator(&tsGen);
            switch (cfg.z_cc) {
                .none => {},
                .reno => sock.setCongestionControl(.{ .reno = .{} }),
                .cubic => sock.setCongestionControl(.{ .cubic = .{} }),
            }
            self.* = .{
                .gpa = gpa,
                .cfg = cfg,
                .peer = peer,
                .link = blk: {
                    var l = Link.init(gpa, cfg.sched);
                    l.trace = trace_all;
                    break :blk l;
                },
                .dev = dev,
                .stk = stk,
                .sock = sock,
                .sock_arr = .{sock},
                .rx_mem = rx_mem,
                .tx_mem = tx_mem,
                .auto_close_on_eof = cfg.z_auto_close_on_eof,
            };
            const socks: Sockets = if (v6) .{ .tcp6_sockets = &self.sock_arr } else .{ .tcp4_sockets = &self.sock_arr };
            stk.* = Stk.init(Z_MAC, socks);
            if (v6) {
                stk.iface.setIpv6Addrs(&.{.{ .address = z_addr, .prefix_len = 64 }});
            } else {
                stk.iface.v4.addIpAddr(.{ .address = z_addr, .prefix_len = 24 });
            }
            return self;
        }

        pub fn destroy(self: *Self) void {
            const gpa = self.gpa;
            self.peer.deinit();
            self.link.deinit();
            self.scratch.deinit(gpa);
            self.echo_q.deinit(gpa);
            gpa.free(self.rx_mem);
            gpa.free(self.tx_mem);
            gpa.destroy(self.stk);
            gpa.destroy(self.sock);
            gpa.destroy(self.dev);
            gpa.destroy(self);
        }

        // -- connection setup --

        /// `client` connects to the other side, which listens.
        pub fn open(self: *Self, client: Side) !void {
            switch (client) {
                .zig => {
                    if (!try self.peer.listen(SERVER_PORT)) return error.PeerListenFailed;
                    try self.sock.connect(p_addr, SERVER_PORT, z_addr, CLIENT_PORT);
                },
                .peer => {
                    try self.sock.listen(.{ .port = SERVER_PORT });
                    if (!try self.peer.connect(SERVER_PORT, CLIENT_PORT)) return error.PeerConnectFailed;
                },
            }
        }

        // -- applications --

        pub fn zSend(self: *Self, seed: u64, total: u64, close_after: bool) void {
            self.gen_seed = seed;
            self.gen_total = total;
            self.gen_done = 0;
            self.close_after_send = close_after;
        }

        fn takeRx(self: *Self, max: usize) !usize {
            var buf: [8192]u8 = undefined;
            var got: usize = 0;
            while (got < max) {
                const want = @min(max - got, buf.len);
                const n = self.sock.recvSlice(buf[0..want]) catch break;
                if (n == 0) break;
                self.rx_total += n;
                self.rx_hash = fnvUpdate(self.rx_hash, buf[0..n]);
                if (self.echo) try self.echo_q.appendSlice(self.gpa, buf[0..n]);
                got += n;
            }
            return got;
        }

        fn appStep(self: *Self) !bool {
            var progress = false;
            const s = self.sock;
            if (self.recv_enabled) {
                const max: usize = if (self.recv_limit) |l| @intCast(l -| self.rx_total) else std.math.maxInt(usize) / 2;
                if (try self.takeRx(max) > 0) progress = true;
            }
            if (!self.rx_finished and !s.mayRecv() and !s.canRecv() and switch (s.getState()) {
                .close_wait, .last_ack, .closing, .time_wait, .fin_wait_2 => true,
                else => false,
            }) {
                self.rx_finished = true;
                progress = true;
            }
            while (s.maySend() and s.canSend()) {
                if (self.echo_q.items.len > 0) {
                    const n = s.sendSlice(self.echo_q.items) catch break;
                    if (n == 0) break;
                    self.tx_total += n;
                    std.mem.copyForwards(u8, self.echo_q.items, self.echo_q.items[n..]);
                    self.echo_q.shrinkRetainingCapacity(self.echo_q.items.len - n);
                    progress = true;
                } else if (self.gen_done < self.gen_total) {
                    const room = s.sendCapacity() - s.sendQueue();
                    const n: usize = @intCast(@min(@min(self.gen_total - self.gen_done, room), 32 * 1024));
                    if (n == 0) break;
                    const chunk = try self.gpa.alloc(u8, n);
                    defer self.gpa.free(chunk);
                    fillStream(self.gen_seed, self.gen_done, chunk);
                    const m = s.sendSlice(chunk) catch break;
                    if (m == 0) break;
                    self.gen_done += m;
                    self.tx_total += m;
                    progress = true;
                } else break;
            }
            const drained = self.echo_q.items.len == 0 and self.gen_done >= self.gen_total;
            const st = s.getState();
            if (self.close_after_send and self.gen_total > 0 and self.gen_done >= self.gen_total and
                (st == .established or st == .close_wait))
            {
                s.close();
                self.close_after_send = false;
                progress = true;
            }
            if (self.auto_close_on_eof and self.rx_finished and drained and st == .close_wait) {
                s.close();
                progress = true;
            }
            return progress;
        }

        // -- time --

        fn drainDev(self: *Self) !void {
            for (self.dev.tx[0..self.dev.tx_count]) |*f| try self.link.send(.to_peer, self.now, f.slice());
            self.dev.tx_count = 0;
        }

        fn zPump(self: *Self) !void {
            var i: usize = 0;
            while (i < 100_000) : (i += 1) {
                const act = self.stk.poll(Instant.fromMicros(@intCast(self.now)), self.dev);
                const app = try self.appStep();
                try self.drainDev();
                self.states_seen |= @as(u16, 1) << @as(u4, @intCast(@backingInt(State.fromZ(self.sock.getState()))));
                if (!act and !app) return;
            }
            return error.PumpDidNotQuiesce;
        }

        pub fn sawState(self: *const Self, s: State) bool {
            return self.states_seen & (@as(u16, 1) << @as(u4, @intCast(@backingInt(s)))) != 0;
        }

        /// Run both sides at the current instant, then advance to the next event.
        pub fn step(self: *Self) !void {
            self.steps += 1;
            g_ts_ms = @intCast(self.now / 1000);
            while (self.link.popDue(self.now)) |item| switch (item.dir) {
                .to_zig => self.dev.enqueueRx(item.frame.slice()),
                .to_peer => try self.peer.deliver(item.frame.slice()),
            };
            try self.zPump();
            if (self.hook) |h| try h(self);
            self.scratch.clearRetainingCapacity();
            self.peer_at = try self.peer.tick(self.now, &self.scratch);
            for (self.scratch.items) |*f| try self.link.send(.to_zig, self.now, f.slice());

            var next: u64 = self.now + self.cfg.max_idle_us;
            if (self.link.nextDue()) |d| next = @min(next, d);
            if (self.stk.pollAt()) |t| next = @min(next, @as(u64, @intCast(@max(t.totalMicros(), 0))));
            if (self.peer_at) |t| next = @min(next, t);
            self.now = @max(next, self.now + 1);
        }

        /// Step until `pred` holds or `limit_us` of virtual time passes. Returns whether it held.
        pub fn runUntil(self: *Self, ctx: anytype, comptime pred: anytype, limit_us: u64) !bool {
            const deadline = self.now + limit_us;
            while (self.now <= deadline) {
                try self.step();
                if (try pred(ctx, self)) return true;
                if (self.steps > 400_000) return error.StepBudgetExceeded;
            }
            return false;
        }

        pub fn runFor(self: *Self, duration_us: u64) !void {
            const deadline = self.now + duration_us;
            while (self.now < deadline) try self.step();
        }

        // -- helpers for scenarios --

        pub fn zState(self: *const Self) State {
            return State.fromZ(self.sock.getState());
        }

        pub fn peerStatus(self: *Self) !PeerStatus {
            return self.peer.query();
        }

        pub fn bothDone(_: void, self: *Self) !bool {
            const ps = try self.peer.query();
            return self.zState().isDone() and ps.state.isDone();
        }

        pub fn bothEstablished(_: void, self: *Self) !bool {
            const ps = try self.peer.query();
            return self.zState() == .established and ps.state == .established;
        }

        pub fn dump(self: *Self, comptime tag: []const u8) void {
            const ps = self.peer.query() catch return;
            std.debug.print("[{s}] t={d}us steps={d} z={s} rx={d} tx={d} | peer={s} rx={d} tx={d} | tap to_peer={d} to_zig={d} drop={d}/{d}\n", .{
                tag,                      self.now,                self.steps,              @tagName(self.zState()),
                self.rx_total,            self.tx_total,           @tagName(ps.state),      ps.rx_total,
                ps.tx_total,              self.link.tap.frames[0], self.link.tap.frames[1], self.link.tap.dropped[0],
                self.link.tap.dropped[1],
            });
        }
    };
}

// ---------------------------------------------------------------------------
// Peer location
// ---------------------------------------------------------------------------

/// Path of the peer binary: ZMOLTCP_PEER (set by `zig build interop`).
pub fn peerExe(gpa: std.mem.Allocator, environ: std.process.Environ) ![]u8 {
    return environ.getAlloc(gpa, "ZMOLTCP_PEER") catch return error.PeerNotConfigured;
}

pub fn pad16(a: [4]u8) [16]u8 {
    var r: [16]u8 = @splat(0);
    @memcpy(r[0..4], &a);
    return r;
}

fn traceFrame(dir: Dir, now: u64, f: []const u8) void {
    const d = if (dir == .to_peer) "Z->P" else "P->Z";
    if (parseTcp(f)) |i| {
        std.debug.print("{d:>10}us {s} len={d} {s}{s}{s}{s}{s} seq={d} ack={d} win={d} pl={d} ts={} sack={d}\n", .{
            now,                         d,                           f.len,
            if (i.has(SYN)) "S" else "", if (i.has(ACK)) "A" else "", if (i.has(FIN)) "F" else "",
            if (i.has(RST)) "R" else "", if (i.has(PSH)) "P" else "", i.seq,
            i.ack,                       i.window,                    i.payload_len,
            i.ts,                        i.sack_blocks,
        });
    } else {
        std.debug.print("{d:>10}us {s} len={d} non-tcp ethertype={x}\n", .{ now, d, f.len, if (f.len >= 14) be16(f[12..]) else 0 });
    }
}
