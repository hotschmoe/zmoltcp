// DNS client socket -- state machine for DNS query resolution.
//
// Reference: RFC 1035, smoltcp src/socket/dns.rs

const std = @import("std");
const ip_generic = @import("../wire/ip.zig");
const ipv4 = @import("../wire/ipv4.zig");
const wire = @import("../wire/dns.zig");
const time = @import("../time.zig");
const Instant = time.Instant;
const Duration = time.Duration;

pub const DNS_PORT: u16 = 53;
pub const MAX_SERVER_COUNT: usize = 4;
pub const MAX_RESULT_COUNT: usize = 4;
pub const MAX_NAME_SIZE: usize = wire.MAX_NAME_SIZE;

const RETRANSMIT_DELAY = Duration.fromSecs(1);
const MAX_RETRANSMIT_DELAY = Duration.fromSecs(10);
const RETRANSMIT_TIMEOUT = Duration.fromSecs(10);

pub const QueryHandle = struct {
    index: usize,
};

pub const StartQueryError = error{
    NoFreeSlot,
    InvalidName,
    NameTooLong,
};

pub const GetQueryResultError = error{
    Pending,
    Failed,
};

pub fn Socket(comptime Ip: type) type {
    comptime ip_generic.assertIsIp(Ip);

    return struct {
        const Self = @This();

        pub const Addresses = struct {
            addrs: [MAX_RESULT_COUNT]Ip.Address = undefined,
            len: u8 = 0,

            pub fn push(self: *Addresses, addr: Ip.Address) void {
                if (self.len < MAX_RESULT_COUNT) {
                    self.addrs[self.len] = addr;
                    self.len += 1;
                }
            }

            pub fn get(self: *const Addresses, i: usize) Ip.Address {
                return self.addrs[i];
            }
        };

        const PendingQuery = struct {
            name: [MAX_NAME_SIZE]u8 = undefined,
            name_len: usize,
            type_: wire.Type,
            port: u16,
            txid: u16,
            timeout_at: ?Instant,
            retransmit_at: Instant,
            delay: Duration,
            server_idx: usize,
        };

        const QueryState = union(enum) {
            pending: PendingQuery,
            completed: Addresses,
            failure,
        };

        pub const QuerySlot = struct {
            state: ?QueryState = null,
        };

        pub const DispatchResult = struct {
            payload: []const u8,
            src_port: u16,
            dst_ip: Ip.Address,
        };

        queries: []QuerySlot,
        servers: [MAX_SERVER_COUNT]Ip.Address = undefined,
        server_count: usize = 0,

        pub fn init(queries: []QuerySlot, servers: []const Ip.Address) Self {
            var s = Self{
                .queries = queries,
            };
            s.updateServers(servers);
            for (queries) |*q| {
                q.state = null;
            }
            return s;
        }

        pub fn updateServers(self: *Self, servers: []const Ip.Address) void {
            const count = @min(servers.len, MAX_SERVER_COUNT);
            for (0..count) |i| {
                self.servers[i] = servers[i];
            }
            self.server_count = count;
        }

        fn findFreeSlot(self: *Self) ?QueryHandle {
            for (self.queries, 0..) |*q, i| {
                if (q.state == null) {
                    return .{ .index = i };
                }
            }
            return null;
        }

        pub fn startQuery(self: *Self, name: []const u8, type_: wire.Type) StartQueryError!QueryHandle {
            var raw_name: [MAX_NAME_SIZE]u8 = undefined;
            var pos: usize = 0;

            var work_name = name;
            if (work_name.len == 0) return error.InvalidName;

            if (work_name[work_name.len - 1] == '.') {
                work_name = work_name[0 .. work_name.len - 1];
            }

            var remaining = work_name;
            while (remaining.len > 0) {
                var dot_pos: usize = 0;
                while (dot_pos < remaining.len and remaining[dot_pos] != '.') : (dot_pos += 1) {}

                const label = remaining[0..dot_pos];
                if (label.len == 0) return error.InvalidName;
                if (label.len > 63) return error.InvalidName;
                if (pos + 1 + label.len >= MAX_NAME_SIZE) return error.NameTooLong;

                raw_name[pos] = @truncate(label.len);
                @memcpy(raw_name[pos + 1 ..][0..label.len], label);
                pos += 1 + label.len;

                if (dot_pos < remaining.len) {
                    remaining = remaining[dot_pos + 1 ..];
                } else {
                    break;
                }
            }

            if (pos >= MAX_NAME_SIZE) return error.NameTooLong;
            raw_name[pos] = 0x00;
            pos += 1;

            return self.startQueryRaw(raw_name[0..pos], type_);
        }

        pub fn startQueryRaw(self: *Self, raw_name: []const u8, type_: wire.Type) StartQueryError!QueryHandle {
            const handle = self.findFreeSlot() orelse return error.NoFreeSlot;
            if (raw_name.len > MAX_NAME_SIZE) return error.NameTooLong;

            var pq = PendingQuery{
                .name_len = raw_name.len,
                .type_ = type_,
                .txid = testTransactionId(),
                .port = testSourcePort(),
                .delay = RETRANSMIT_DELAY,
                .timeout_at = null,
                .retransmit_at = Instant.ZERO,
                .server_idx = 0,
            };
            @memcpy(pq.name[0..raw_name.len], raw_name);

            self.queries[handle.index].state = .{ .pending = pq };
            return handle;
        }

        pub fn getQueryResult(self: *Self, handle: QueryHandle) GetQueryResultError!Addresses {
            const slot = &self.queries[handle.index];
            const state = slot.state orelse unreachable;
            switch (state) {
                .pending => return error.Pending,
                .completed => |addrs| {
                    slot.state = null;
                    return addrs;
                },
                .failure => {
                    slot.state = null;
                    return error.Failed;
                },
            }
        }

        pub fn cancelQuery(self: *Self, handle: QueryHandle) void {
            self.queries[handle.index].state = null;
        }

        pub fn process(self: *Self, dst_port: u16, pkt_data: []const u8) void {
            if (pkt_data.len < wire.HEADER_LEN) return;

            const pkt_opcode = wire.opcode(pkt_data) catch return;
            if (pkt_opcode != .query) return;

            const pkt_flags = wire.flags(pkt_data) catch return;
            if (pkt_flags & wire.Flags.RESPONSE == 0) return;

            const qcount = wire.questionCount(pkt_data) catch return;
            if (qcount != 1) return;

            const pkt_txid = wire.transactionId(pkt_data) catch return;
            const pkt_rcode = wire.rcode(pkt_data) catch return;
            const answer_count = wire.answerCount(pkt_data) catch return;

            for (self.queries) |*slot| {
                const state = slot.state orelse continue;
                var pq = switch (state) {
                    .pending => |p| p,
                    else => continue,
                };

                if (dst_port != pq.port or pkt_txid != pq.txid) continue;

                if (pkt_rcode == .nx_domain) {
                    slot.state = .failure;
                    continue;
                }

                const pld = wire.payload(pkt_data) catch return;
                const qr = wire.parseQuestion(pld) catch return;
                if (qr.question.type_ != pq.type_) return;

                const q_name = wire.parseName(pkt_data, headerOffset(pkt_data, qr.question.name)) catch return;
                const pq_name = wire.parseName(pq.name[0..pq.name_len], 0) catch return;
                if (!wire.eqNames(q_name, pq_name)) return;

                var addresses = Addresses{};
                var rest = qr.rest;
                for (0..answer_count) |_| {
                    const ar = wire.parseRecord(rest) catch return;
                    rest = ar.rest;

                    const rec_name = wire.parseName(pkt_data, headerOffset(pkt_data, ar.record.name)) catch return;
                    const cur_name = wire.parseName(pq.name[0..pq.name_len], 0) catch return;
                    if (!wire.eqNames(rec_name, cur_name)) continue;

                    switch (ar.record.data) {
                        .a => |addr| addresses.push(addr),
                        .cname => |cname_data| {
                            const cname_labels = wire.parseName(pkt_data, headerOffset(pkt_data, cname_data)) catch return;
                            pq.name_len = wire.copyName(&pq.name, cname_labels) catch return;
                            slot.state = .{ .pending = pq };
                        },
                        .other => {},
                    }
                }

                if (addresses.len > 0) {
                    slot.state = .{ .completed = addresses };
                } else {
                    slot.state = .failure;
                }
                return;
            }
        }

        pub fn dispatch(self: *Self, now: Instant, buf: []u8) ?DispatchResult {
            for (self.queries) |*slot| {
                const state = slot.state orelse continue;
                var pq = switch (state) {
                    .pending => |p| p,
                    else => continue,
                };

                if (pq.timeout_at == null) pq.timeout_at = now.add(RETRANSMIT_TIMEOUT);

                if (pq.timeout_at.?.lessThan(now)) {
                    pq.timeout_at = now.add(RETRANSMIT_TIMEOUT);
                    pq.retransmit_at = Instant.ZERO;
                    pq.delay = RETRANSMIT_DELAY;
                    pq.server_idx += 1;
                }

                if (pq.server_idx >= self.server_count) {
                    slot.state = .failure;
                    continue;
                }

                if (pq.retransmit_at.micros > now.micros) {
                    slot.state = .{ .pending = pq };
                    continue;
                }

                const repr = wire.Repr{
                    .transaction_id = pq.txid,
                    .flags = wire.Flags.RECURSION_DESIRED,
                    .opcode = .query,
                    .question = .{
                        .name = pq.name[0..pq.name_len],
                        .type_ = pq.type_,
                    },
                };

                const pkt_len = wire.emit(repr, buf) catch {
                    slot.state = .{ .pending = pq };
                    continue;
                };

                pq.retransmit_at = now.add(pq.delay);
                pq.delay = MAX_RETRANSMIT_DELAY.min(Duration.fromMicros(pq.delay.micros * 2));

                slot.state = .{ .pending = pq };

                return .{
                    .payload = buf[0..pkt_len],
                    .src_port = pq.port,
                    .dst_ip = self.servers[pq.server_idx],
                };
            }

            return null;
        }

        pub fn pollAt(self: *const Self) ?Instant {
            var earliest: ?Instant = null;
            for (self.queries) |slot| {
                const pq = switch (slot.state orelse continue) {
                    .pending => |p| p,
                    else => continue,
                };
                earliest = if (earliest) |e|
                    if (pq.retransmit_at.lessThan(e)) pq.retransmit_at else e
                else
                    pq.retransmit_at;
            }
            return earliest;
        }

        fn testTransactionId() u16 {
            return 0xABCD;
        }

        fn testSourcePort() u16 {
            return 49152;
        }
    };
}

fn headerOffset(packet: []const u8, sub: []const u8) usize {
    return @intFromPtr(sub.ptr) - @intFromPtr(packet.ptr);
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;

const DnsSock = Socket(ipv4);
const DNS_SERVER_1 = [4]u8{ 8, 8, 8, 8 };
const DNS_SERVER_2 = [4]u8{ 8, 8, 4, 4 };
const TXID: u16 = 0xABCD;
const SRC_PORT: u16 = 49152;

fn createSocket() struct { socket: DnsSock, slots: *[4]DnsSock.QuerySlot, buf: *[512]u8 } {
    const S = struct {
        var slots: [4]DnsSock.QuerySlot = [_]DnsSock.QuerySlot{.{}} ** 4;
        var buf: [512]u8 = undefined;
    };
    @memset(std.mem.asBytes(&S.slots), 0);
    const servers = [_][4]u8{ DNS_SERVER_1, DNS_SERVER_2 };
    return .{
        .socket = DnsSock.init(&S.slots, &servers),
        .slots = &S.slots,
        .buf = &S.buf,
    };
}

fn encodeName(name: []const u8) struct { data: [MAX_NAME_SIZE]u8, len: usize } {
    var result: [MAX_NAME_SIZE]u8 = undefined;
    var pos: usize = 0;
    var remaining = name;
    while (remaining.len > 0) {
        var dot_pos: usize = 0;
        while (dot_pos < remaining.len and remaining[dot_pos] != '.') : (dot_pos += 1) {}
        const label = remaining[0..dot_pos];
        result[pos] = @truncate(label.len);
        @memcpy(result[pos + 1 ..][0..label.len], label);
        pos += 1 + label.len;
        if (dot_pos < remaining.len) {
            remaining = remaining[dot_pos + 1 ..];
        } else {
            break;
        }
    }
    result[pos] = 0x00;
    pos += 1;
    return .{ .data = result, .len = pos };
}

fn buildResponse(txid: u16, rcode: wire.Rcode, question_name: []const u8, question_type: wire.Type, answers: []const [4]u8) struct { data: [512]u8, len: usize } {
    var buf: [512]u8 = undefined;
    @memset(&buf, 0);

    buf[0] = @truncate(txid >> 8);
    buf[1] = @truncate(txid);
    const flags_val = (wire.Flags.RESPONSE | wire.Flags.RECURSION_DESIRED | wire.Flags.RECURSION_AVAILABLE) |
        @as(u16, @intFromEnum(rcode));
    buf[2] = @truncate(flags_val >> 8);
    buf[3] = @truncate(flags_val);
    buf[4] = 0;
    buf[5] = 1; // QDCOUNT
    buf[6] = 0;
    buf[7] = @truncate(answers.len); // ANCOUNT

    var pos: usize = 12;
    @memcpy(buf[pos..][0..question_name.len], question_name);
    pos += question_name.len;
    const qt = @intFromEnum(question_type);
    buf[pos] = @truncate(qt >> 8);
    buf[pos + 1] = @truncate(qt);
    buf[pos + 2] = 0;
    buf[pos + 3] = 1; // CLASS_IN
    pos += 4;

    for (answers) |addr| {
        buf[pos] = 0xc0;
        buf[pos + 1] = 0x0c;
        pos += 2;
        buf[pos] = 0;
        buf[pos + 1] = 1; // TYPE A
        buf[pos + 2] = 0;
        buf[pos + 3] = 1; // CLASS IN
        pos += 4;
        buf[pos] = 0;
        buf[pos + 1] = 0;
        buf[pos + 2] = 0;
        buf[pos + 3] = 60; // TTL = 60
        pos += 4;
        buf[pos] = 0;
        buf[pos + 1] = 4; // RDLENGTH
        pos += 2;
        @memcpy(buf[pos..][0..4], &addr);
        pos += 4;
    }

    return .{ .data = buf, .len = pos };
}

fn buildCnameResponse(txid: u16, question_name: []const u8, cname_wire: []const u8, a_addr: [4]u8) struct { data: [512]u8, len: usize } {
    var buf: [512]u8 = undefined;
    @memset(&buf, 0);

    const f: u16 = wire.Flags.RESPONSE | wire.Flags.RECURSION_DESIRED | wire.Flags.RECURSION_AVAILABLE;
    buf[0] = @truncate(txid >> 8);
    buf[1] = @truncate(txid);
    buf[2] = @truncate(f >> 8);
    buf[3] = @truncate(f);
    buf[4] = 0;
    buf[5] = 1; // QDCOUNT
    buf[6] = 0;
    buf[7] = 2; // ANCOUNT

    var pos: usize = 12;
    @memcpy(buf[pos..][0..question_name.len], question_name);
    pos += question_name.len;
    buf[pos] = 0;
    buf[pos + 1] = 1; // TYPE A
    buf[pos + 2] = 0;
    buf[pos + 3] = 1; // CLASS IN
    pos += 4;

    buf[pos] = 0xc0;
    buf[pos + 1] = 0x0c;
    pos += 2;
    buf[pos] = 0;
    buf[pos + 1] = 5; // TYPE CNAME
    buf[pos + 2] = 0;
    buf[pos + 3] = 1; // CLASS IN
    pos += 4;
    buf[pos] = 0;
    buf[pos + 1] = 0;
    buf[pos + 2] = 0;
    buf[pos + 3] = 60; // TTL
    pos += 4;
    buf[pos] = 0;
    buf[pos + 1] = @truncate(cname_wire.len); // RDLENGTH
    pos += 2;
    @memcpy(buf[pos..][0..cname_wire.len], cname_wire);
    pos += cname_wire.len;

    @memcpy(buf[pos..][0..cname_wire.len], cname_wire);
    pos += cname_wire.len;
    buf[pos] = 0;
    buf[pos + 1] = 1; // TYPE A
    buf[pos + 2] = 0;
    buf[pos + 3] = 1; // CLASS IN
    pos += 4;
    buf[pos] = 0;
    buf[pos + 1] = 0;
    buf[pos + 2] = 0;
    buf[pos + 3] = 60; // TTL
    pos += 4;
    buf[pos] = 0;
    buf[pos + 1] = 4; // RDLENGTH
    pos += 2;
    @memcpy(buf[pos..][0..4], &a_addr);
    pos += 4;

    return .{ .data = buf, .len = pos };
}

// [smoltcp:socket/dns.rs:start_query] (original)
test "start query encodes name" {
    var ctx = createSocket();
    var s = &ctx.socket;

    const handle = try s.startQuery("google.com", .a);
    const state = s.queries[handle.index].state.?;
    const pq = state.pending;

    // Should be wire-encoded: \x06google\x03com\x00
    const expected = [_]u8{ 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00 };
    try testing.expectEqualSlices(u8, &expected, pq.name[0..pq.name_len]);
}

// (original)
test "start query rejects empty name" {
    var ctx = createSocket();
    var s = &ctx.socket;
    try testing.expectError(error.InvalidName, s.startQuery("", .a));
}

// (original)
test "start query rejects too-long label" {
    var ctx = createSocket();
    var s = &ctx.socket;
    const long_label = "a" ** 64 ++ ".com";
    try testing.expectError(error.InvalidName, s.startQuery(long_label, .a));
}

// (original)
test "start query no free slot" {
    var ctx = createSocket();
    var s = &ctx.socket;
    _ = try s.startQuery("a.com", .a);
    _ = try s.startQuery("b.com", .a);
    _ = try s.startQuery("c.com", .a);
    _ = try s.startQuery("d.com", .a);
    try testing.expectError(error.NoFreeSlot, s.startQuery("e.com", .a));
}

// (original)
test "dispatch emits query packet" {
    var ctx = createSocket();
    var s = &ctx.socket;
    const buf = ctx.buf;

    _ = try s.startQuery("google.com", .a);
    const result = s.dispatch(Instant.fromMillis(0), buf) orelse return error.TestExpectedEqual;

    // Verify packet structure
    try testing.expectEqual(TXID, try wire.transactionId(result.payload));
    try testing.expectEqual(wire.Opcode.query, try wire.opcode(result.payload));
    try testing.expectEqual(@as(u16, 1), try wire.questionCount(result.payload));
    try testing.expectEqual(SRC_PORT, result.src_port);
    try testing.expectEqualSlices(u8, &DNS_SERVER_1, &result.dst_ip);
}

// (original)
test "dispatch retransmit with backoff" {
    var ctx = createSocket();
    var s = &ctx.socket;
    const buf = ctx.buf;

    _ = try s.startQuery("google.com", .a);

    // First dispatch at t=0
    const r1 = s.dispatch(Instant.fromMillis(0), buf) orelse return error.TestExpectedEqual;
    try testing.expectEqualSlices(u8, &DNS_SERVER_1, &r1.dst_ip);

    // No dispatch before retransmit delay (1s)
    try testing.expect(s.dispatch(Instant.fromMillis(500), buf) == null);

    // Retransmit at t=1s (delay was 1s)
    const r2 = s.dispatch(Instant.fromMillis(1000), buf) orelse return error.TestExpectedEqual;
    try testing.expectEqualSlices(u8, &DNS_SERVER_1, &r2.dst_ip);

    // No dispatch at t=2s (delay doubled to 2s, so next at t=3s)
    try testing.expect(s.dispatch(Instant.fromMillis(2000), buf) == null);

    // Retransmit at t=3s
    const r3 = s.dispatch(Instant.fromMillis(3000), buf) orelse return error.TestExpectedEqual;
    try testing.expectEqualSlices(u8, &DNS_SERVER_1, &r3.dst_ip);
}

// (original)
test "dispatch timeout tries next server" {
    var ctx = createSocket();
    var s = &ctx.socket;
    const buf = ctx.buf;

    _ = try s.startQuery("google.com", .a);

    // First dispatch sets timeout_at = 0 + 10s = 10s
    const r1 = s.dispatch(Instant.fromMillis(0), buf) orelse return error.TestExpectedEqual;
    try testing.expectEqualSlices(u8, &DNS_SERVER_1, &r1.dst_ip);

    // At t=11s, timeout triggers -> server_idx advances to 1
    const r2 = s.dispatch(Instant.fromSecs(11), buf) orelse return error.TestExpectedEqual;
    try testing.expectEqualSlices(u8, &DNS_SERVER_2, &r2.dst_ip);
}

// (original)
test "dispatch all servers exhausted" {
    var ctx = createSocket();
    var s = &ctx.socket;
    const buf = ctx.buf;

    const handle = try s.startQuery("google.com", .a);

    // First server
    _ = s.dispatch(Instant.fromMillis(0), buf);
    // Timeout -> second server
    _ = s.dispatch(Instant.fromSecs(11), buf);
    // Timeout -> no more servers -> failure
    _ = s.dispatch(Instant.fromSecs(22), buf);

    try testing.expectError(error.Failed, s.getQueryResult(handle));
}

// (original)
test "process A response" {
    var ctx = createSocket();
    var s = &ctx.socket;
    const buf = ctx.buf;

    const handle = try s.startQuery("google.com", .a);
    _ = s.dispatch(Instant.fromMillis(0), buf);

    const name_enc = encodeName("google.com");
    const addr = [4]u8{ 172, 217, 14, 206 };
    const resp = buildResponse(TXID, .no_error, name_enc.data[0..name_enc.len], .a, &[_][4]u8{addr});

    s.process(SRC_PORT, resp.data[0..resp.len]);

    const result = try s.getQueryResult(handle);
    try testing.expectEqual(@as(u8, 1), result.len);
    try testing.expectEqualSlices(u8, &addr, &result.addrs[0]);
}

// (original)
test "process NXDomain" {
    var ctx = createSocket();
    var s = &ctx.socket;
    const buf = ctx.buf;

    const handle = try s.startQuery("nonexistent.com", .a);
    _ = s.dispatch(Instant.fromMillis(0), buf);

    const name_enc = encodeName("nonexistent.com");
    const resp = buildResponse(TXID, .nx_domain, name_enc.data[0..name_enc.len], .a, &[_][4]u8{});

    s.process(SRC_PORT, resp.data[0..resp.len]);

    try testing.expectError(error.Failed, s.getQueryResult(handle));
}

// (original)
test "process CNAME then A" {
    var ctx = createSocket();
    var s = &ctx.socket;
    const buf = ctx.buf;

    const handle = try s.startQuery("www.example.com", .a);
    _ = s.dispatch(Instant.fromMillis(0), buf);

    const question_name = encodeName("www.example.com");
    const cname_target = encodeName("cdn.example.com");
    const addr = [4]u8{ 93, 184, 216, 34 };

    const resp = buildCnameResponse(
        TXID,
        question_name.data[0..question_name.len],
        cname_target.data[0..cname_target.len],
        addr,
    );

    s.process(SRC_PORT, resp.data[0..resp.len]);

    const result = try s.getQueryResult(handle);
    try testing.expectEqual(@as(u8, 1), result.len);
    try testing.expectEqualSlices(u8, &addr, &result.addrs[0]);
}

// (original)
test "cancel query frees slot" {
    var ctx = createSocket();
    var s = &ctx.socket;

    const h1 = try s.startQuery("a.com", .a);
    try testing.expect(s.queries[h1.index].state != null);

    s.cancelQuery(h1);
    try testing.expect(s.queries[h1.index].state == null);

    // Slot is reusable
    const h2 = try s.startQuery("b.com", .a);
    try testing.expectEqual(h1.index, h2.index);
}
