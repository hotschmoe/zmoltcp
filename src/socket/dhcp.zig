// DHCPv4 client socket -- state machine for DHCP address acquisition.
//
// Reference: RFC 2131, smoltcp src/socket/dhcpv4.rs

const std = @import("std");
const wire = @import("../wire/dhcp.zig");
const time = @import("../time.zig");
const Instant = time.Instant;
const Duration = time.Duration;

const DEFAULT_LEASE_DURATION = Duration.fromSecs(120);

const DEFAULT_PARAMETER_REQUEST_LIST = [_]u8{
    wire.OPT_SUBNET_MASK,
    wire.OPT_ROUTER,
    wire.OPT_DOMAIN_NAME_SERVER,
};

pub const ServerInfo = struct {
    address: [4]u8,
    identifier: [4]u8,

    pub fn eql(self: ServerInfo, other: ServerInfo) bool {
        return std.mem.eql(u8, &self.address, &other.address) and
            std.mem.eql(u8, &self.identifier, &other.identifier);
    }
};

pub const Config = struct {
    server: ServerInfo,
    address: [4]u8,
    prefix_len: u6,
    router: ?[4]u8,
    dns_servers: wire.DnsServers,

    pub fn eql(self: *const Config, other: *const Config) bool {
        return self.server.eql(other.server) and
            std.mem.eql(u8, &self.address, &other.address) and
            self.prefix_len == other.prefix_len and
            optionalAddrEql(self.router, other.router) and
            self.dns_servers.eql(&other.dns_servers);
    }
};

fn optionalAddrEql(a: ?[4]u8, b: ?[4]u8) bool {
    const aa = a orelse return b == null;
    const bb = b orelse return false;
    return std.mem.eql(u8, &aa, &bb);
}

pub const Event = union(enum) {
    configured: Config,
    deconfigured,

    pub fn eql(self: Event, other: Event) bool {
        return switch (self) {
            .deconfigured => other == .deconfigured,
            .configured => |c1| switch (other) {
                .configured => |c2| c1.eql(&c2),
                .deconfigured => false,
            },
        };
    }
};

pub const RetryConfig = struct {
    discover_timeout: Duration = Duration.fromSecs(10),
    initial_request_timeout: Duration = Duration.fromSecs(5),
    request_retries: u16 = 5,
    min_renew_timeout: Duration = Duration.fromSecs(60),
    max_renew_timeout: Duration = .{ .micros = std.math.maxInt(i64) },
};

const DiscoverState = struct {
    retry_at: Instant,
};

const RequestState = struct {
    retry_at: Instant,
    retry: u16,
    server: ServerInfo,
    requested_ip: [4]u8,
};

const RenewState = struct {
    config: Config,
    renew_at: Instant,
    rebind_at: Instant,
    rebinding: bool,
    expires_at: Instant,
};

const ClientState = union(enum) {
    discovering: DiscoverState,
    requesting: RequestState,
    renewing: RenewState,
};

pub const DispatchResult = struct {
    dhcp_repr: wire.Repr,
    src_ip: [4]u8,
    dst_ip: [4]u8,
};

pub const Socket = struct {
    state: ClientState,
    config_changed: bool,
    transaction_id: u32,
    max_lease_duration: ?Duration,
    retry_config: RetryConfig,
    ignore_naks: bool,
    server_port: u16,
    client_port: u16,
    hardware_address: [6]u8,

    const ZERO_IP = [4]u8{ 0, 0, 0, 0 };
    const BCAST_IP = [4]u8{ 255, 255, 255, 255 };

    pub fn init(hardware_address: [6]u8) Socket {
        return .{
            .state = .{ .discovering = .{ .retry_at = Instant.fromMillis(0) } },
            .config_changed = true,
            .transaction_id = 1,
            .max_lease_duration = null,
            .retry_config = .{},
            .ignore_naks = false,
            .server_port = wire.SERVER_PORT,
            .client_port = wire.CLIENT_PORT,
            .hardware_address = hardware_address,
        };
    }

    pub fn setPorts(self: *Socket, server_port: u16, client_port: u16) void {
        self.server_port = server_port;
        self.client_port = client_port;
    }

    pub fn setRetryConfig(self: *Socket, config: RetryConfig) void {
        self.retry_config = config;
    }

    pub fn getRetryConfig(self: *const Socket) RetryConfig {
        return self.retry_config;
    }

    pub fn setMaxLeaseDuration(self: *Socket, max: ?Duration) void {
        self.max_lease_duration = max;
    }

    pub fn setIgnoreNaks(self: *Socket, ignore: bool) void {
        self.ignore_naks = ignore;
    }

    pub fn poll(self: *Socket) ?Event {
        if (!self.config_changed) return null;
        self.config_changed = false;
        return switch (self.state) {
            .renewing => |s| .{ .configured = s.config },
            else => .deconfigured,
        };
    }

    pub fn reset(self: *Socket) void {
        switch (self.state) {
            .renewing => self.configChanged(),
            else => {},
        }
        self.state = .{ .discovering = .{ .retry_at = Instant.fromMillis(0) } };
    }

    pub fn process(self: *Socket, now: Instant, src_ip: [4]u8, dhcp_repr: wire.Repr) void {
        if (!std.mem.eql(u8, &dhcp_repr.client_hardware_address, &self.hardware_address)) return;
        if (dhcp_repr.transaction_id != self.transaction_id) return;

        const server_identifier = dhcp_repr.server_identifier orelse return;

        switch (self.state) {
            .discovering => {
                if (dhcp_repr.message_type != .offer) return;
                if (!isUnicast(dhcp_repr.your_ip)) return;
                self.state = .{ .requesting = .{
                    .retry_at = now,
                    .retry = 0,
                    .server = .{
                        .address = src_ip,
                        .identifier = server_identifier,
                    },
                    .requested_ip = dhcp_repr.your_ip,
                } };
            },
            .requesting => |state| {
                switch (dhcp_repr.message_type) {
                    .ack => {
                        if (parseAck(now, dhcp_repr, self.max_lease_duration, state.server)) |result| {
                            self.state = .{ .renewing = .{
                                .config = result.config,
                                .renew_at = result.renew_at,
                                .rebind_at = result.rebind_at,
                                .rebinding = false,
                                .expires_at = result.expires_at,
                            } };
                            self.configChanged();
                        }
                    },
                    .nak => {
                        if (!self.ignore_naks) self.reset();
                    },
                    else => {},
                }
            },
            .renewing => |*state| {
                switch (dhcp_repr.message_type) {
                    .ack => {
                        if (parseAck(now, dhcp_repr, self.max_lease_duration, state.config.server)) |result| {
                            const changed = !state.config.eql(&result.config);
                            state.renew_at = result.renew_at;
                            state.rebind_at = result.rebind_at;
                            state.rebinding = false;
                            state.expires_at = result.expires_at;
                            if (changed) {
                                state.config = result.config;
                                self.configChanged();
                            }
                        }
                    },
                    .nak => {
                        if (!self.ignore_naks) self.reset();
                    },
                    else => {},
                }
            },
        }
    }

    pub fn dispatch(self: *Socket, now: Instant) ?DispatchResult {
        var dhcp_repr = wire.Repr{
            .message_type = .discover,
            .transaction_id = self.transaction_id,
            .secs = 0,
            .client_hardware_address = self.hardware_address,
            .client_ip = ZERO_IP,
            .your_ip = ZERO_IP,
            .server_ip = ZERO_IP,
            .router = null,
            .subnet_mask = null,
            .relay_agent_ip = ZERO_IP,
            .broadcast = false,
            .requested_ip = null,
            .client_identifier = self.hardware_address,
            .server_identifier = null,
            .parameter_request_list = &DEFAULT_PARAMETER_REQUEST_LIST,
            .max_size = 1432,
            .lease_duration = null,
            .renew_duration = null,
            .rebind_duration = null,
            .dns_servers = null,
        };

        var src_ip = ZERO_IP;
        var dst_ip = BCAST_IP;

        switch (self.state) {
            .discovering => |*state| {
                if (now.lessThan(state.retry_at)) return null;

                const next_txid = testTransactionId();
                dhcp_repr.transaction_id = next_txid;

                state.retry_at = now.add(self.retry_config.discover_timeout);
                self.transaction_id = next_txid;

                return .{ .dhcp_repr = dhcp_repr, .src_ip = src_ip, .dst_ip = dst_ip };
            },
            .requesting => |*state| {
                if (now.lessThan(state.retry_at)) return null;

                if (state.retry >= self.retry_config.request_retries) {
                    self.reset();
                    return null;
                }

                dhcp_repr.message_type = .request;
                dhcp_repr.requested_ip = state.requested_ip;
                dhcp_repr.server_identifier = state.server.identifier;

                const shift: u5 = @intCast(state.retry / 2);
                state.retry_at = now.add(self.retry_config.initial_request_timeout.shl(shift));
                state.retry += 1;

                return .{ .dhcp_repr = dhcp_repr, .src_ip = src_ip, .dst_ip = dst_ip };
            },
            .renewing => |*state| {
                if (now.greaterThanOrEqual(state.expires_at)) {
                    self.reset();
                    return null;
                }

                if (now.lessThan(state.renew_at)) return null;
                if (state.rebinding and now.lessThan(state.rebind_at)) return null;

                state.rebinding = state.rebinding or now.greaterThanOrEqual(state.rebind_at);

                src_ip = state.config.address;
                if (!state.rebinding) {
                    dst_ip = state.config.server.address;
                }

                dhcp_repr.message_type = .request;
                dhcp_repr.client_ip = state.config.address;

                const next_txid = testTransactionId();
                dhcp_repr.transaction_id = next_txid;

                if (state.rebinding) {
                    const remaining = Duration.fromMicros(state.expires_at.totalMicros() - now.totalMicros());
                    const half = remaining.divFloor(2);
                    state.rebind_at = now.add(
                        self.retry_config.min_renew_timeout
                            .max(half)
                            .min(self.retry_config.max_renew_timeout),
                    );
                } else {
                    const remaining_to_t2 = Duration.fromMicros(state.rebind_at.totalMicros() - now.totalMicros());
                    const half = remaining_to_t2.divFloor(2);
                    state.renew_at = now.add(
                        self.retry_config.min_renew_timeout
                            .max(half)
                            .min(remaining_to_t2)
                            .min(self.retry_config.max_renew_timeout),
                    );
                }

                self.transaction_id = next_txid;

                return .{ .dhcp_repr = dhcp_repr, .src_ip = src_ip, .dst_ip = dst_ip };
            },
        }
    }

    pub fn pollAt(self: *const Socket) Instant {
        return switch (self.state) {
            .discovering => |s| s.retry_at,
            .requesting => |s| s.retry_at,
            .renewing => |s| blk: {
                const timer = if (s.rebinding)
                    s.rebind_at
                else
                    minInstant(s.renew_at, s.rebind_at);
                break :blk minInstant(timer, s.expires_at);
            },
        };
    }

    fn configChanged(self: *Socket) void {
        self.config_changed = true;
    }

    fn isUnicast(addr: [4]u8) bool {
        // Not 0.0.0.0 and not 255.255.255.255 and not multicast (224-239.x.x.x)
        if (std.mem.eql(u8, &addr, &ZERO_IP)) return false;
        if (std.mem.eql(u8, &addr, &BCAST_IP)) return false;
        if (addr[0] >= 224 and addr[0] <= 239) return false;
        return true;
    }

    fn minInstant(a: Instant, b: Instant) Instant {
        return if (a.lessThan(b)) a else b;
    }

    fn testTransactionId() u32 {
        return 0x12345678;
    }
};

const ParseAckResult = struct {
    config: Config,
    renew_at: Instant,
    rebind_at: Instant,
    expires_at: Instant,
};

fn parseAck(
    now: Instant,
    dhcp_repr: wire.Repr,
    max_lease_duration: ?Duration,
    server: ServerInfo,
) ?ParseAckResult {
    const subnet_mask = dhcp_repr.subnet_mask orelse return null;
    const prefix_len = subnetMaskToPrefixLen(subnet_mask) orelse return null;

    if (!Socket.isUnicast(dhcp_repr.your_ip)) return null;

    var lease_duration = if (dhcp_repr.lease_duration) |d|
        Duration.fromSecs(@as(i64, d))
    else
        DEFAULT_LEASE_DURATION;

    if (max_lease_duration) |max| {
        lease_duration = lease_duration.min(max);
    }

    var dns_servers = wire.DnsServers{};
    if (dhcp_repr.dns_servers) |servers| {
        for (0..servers.len) |i| {
            if (Socket.isUnicast(servers.addrs[i])) {
                dns_servers.push(servers.addrs[i]);
            }
        }
    }

    const config = Config{
        .server = server,
        .address = dhcp_repr.your_ip,
        .prefix_len = prefix_len,
        .router = dhcp_repr.router,
        .dns_servers = dns_servers,
    };

    // RFC 2131 T1/T2 computation
    const t1_t2 = computeT1T2(lease_duration, dhcp_repr.renew_duration, dhcp_repr.rebind_duration);

    return .{
        .config = config,
        .renew_at = now.add(t1_t2.t1),
        .rebind_at = now.add(t1_t2.t2),
        .expires_at = now.add(lease_duration),
    };
}

const T1T2 = struct { t1: Duration, t2: Duration };

fn computeT1T2(lease: Duration, renew_secs: ?u32, rebind_secs: ?u32) T1T2 {
    const default_t1 = lease.divFloor(2);
    const default_t2 = Duration.fromMicros(@divTrunc(lease.totalMicros() * 7, 8));

    const rd = if (renew_secs) |d| Duration.fromSecs(@as(i64, d)) else null;
    const rbd = if (rebind_secs) |d| Duration.fromSecs(@as(i64, d)) else null;

    if (rd) |t1| {
        if (rbd) |t2| {
            // Both provided: use if T1 < T2 < lease, else defaults
            if (t1.lessThan(t2) and t2.lessThan(lease))
                return .{ .t1 = t1, .t2 = t2 };
            return .{ .t1 = default_t1, .t2 = default_t2 };
        }
        // Only T1: derive T2 = T1 + 0.75 * (lease - T1)
        if (t1.lessThan(lease)) {
            const gap = Duration.fromMicros(lease.totalMicros() - t1.totalMicros());
            return .{ .t1 = t1, .t2 = t1.add(Duration.fromMicros(@divTrunc(gap.totalMicros() * 3, 4))) };
        }
        return .{ .t1 = default_t1, .t2 = default_t2 };
    }

    if (rbd) |t2| {
        // Only T2: clamp T1 to min(default, T2)
        if (t2.lessThan(lease))
            return .{ .t1 = default_t1.min(t2), .t2 = t2 };
        return .{ .t1 = default_t1, .t2 = default_t2 };
    }

    return .{ .t1 = default_t1, .t2 = default_t2 };
}

fn subnetMaskToPrefixLen(mask: [4]u8) ?u6 {
    const m: u32 = @as(u32, mask[0]) << 24 | @as(u32, mask[1]) << 16 |
        @as(u32, mask[2]) << 8 | @as(u32, mask[3]);
    if (m == 0) return 0;
    // Check that mask is contiguous 1s followed by 0s
    const inverted = ~m;
    if ((inverted & (inverted + 1)) != 0) return null;
    return @intCast(@popCount(m));
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;

const TXID: u32 = 0x12345678;
const MY_IP = [4]u8{ 192, 168, 1, 42 };
const SERVER_IP = [4]u8{ 192, 168, 1, 1 };
const DNS_IP_1 = [4]u8{ 1, 1, 1, 1 };
const DNS_IP_2 = [4]u8{ 1, 1, 1, 2 };
const DNS_IP_3 = [4]u8{ 1, 1, 1, 3 };
const MASK_24 = [4]u8{ 255, 255, 255, 0 };
const MY_MAC = [6]u8{ 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
const T_IP_ZERO = [4]u8{ 0, 0, 0, 0 };
const T_IP_BCAST = [4]u8{ 255, 255, 255, 255 };

fn dnsServers() wire.DnsServers {
    var servers = wire.DnsServers{};
    servers.push(DNS_IP_1);
    servers.push(DNS_IP_2);
    servers.push(DNS_IP_3);
    return servers;
}

fn dhcpDefault() wire.Repr {
    return .{
        .message_type = @enumFromInt(99),
        .transaction_id = TXID,
        .secs = 0,
        .client_hardware_address = MY_MAC,
        .client_ip = T_IP_ZERO,
        .your_ip = T_IP_ZERO,
        .server_ip = T_IP_ZERO,
        .router = null,
        .subnet_mask = null,
        .relay_agent_ip = T_IP_ZERO,
        .broadcast = false,
        .requested_ip = null,
        .client_identifier = null,
        .server_identifier = null,
        .parameter_request_list = null,
        .dns_servers = null,
        .max_size = null,
        .renew_duration = null,
        .rebind_duration = null,
        .lease_duration = null,
    };
}

fn dhcpDiscover() wire.Repr {
    var repr = dhcpDefault();
    repr.message_type = .discover;
    repr.client_identifier = MY_MAC;
    repr.parameter_request_list = &[_]u8{ 1, 3, 6 };
    repr.max_size = 1432;
    return repr;
}

fn dhcpOffer() wire.Repr {
    var repr = dhcpDefault();
    repr.message_type = .offer;
    repr.server_ip = SERVER_IP;
    repr.server_identifier = SERVER_IP;
    repr.your_ip = MY_IP;
    repr.router = SERVER_IP;
    repr.subnet_mask = MASK_24;
    repr.dns_servers = dnsServers();
    repr.lease_duration = 1000;
    return repr;
}

fn dhcpRequest() wire.Repr {
    var repr = dhcpDefault();
    repr.message_type = .request;
    repr.client_identifier = MY_MAC;
    repr.server_identifier = SERVER_IP;
    repr.max_size = 1432;
    repr.requested_ip = MY_IP;
    repr.parameter_request_list = &[_]u8{ 1, 3, 6 };
    return repr;
}

fn dhcpAck() wire.Repr {
    var repr = dhcpDefault();
    repr.message_type = .ack;
    repr.server_ip = SERVER_IP;
    repr.server_identifier = SERVER_IP;
    repr.your_ip = MY_IP;
    repr.router = SERVER_IP;
    repr.subnet_mask = MASK_24;
    repr.dns_servers = dnsServers();
    repr.lease_duration = 1000;
    return repr;
}

fn dhcpNak() wire.Repr {
    var repr = dhcpDefault();
    repr.message_type = .nak;
    repr.server_ip = SERVER_IP;
    repr.server_identifier = SERVER_IP;
    return repr;
}

fn dhcpRenew() wire.Repr {
    var repr = dhcpDefault();
    repr.message_type = .request;
    repr.client_identifier = MY_MAC;
    repr.client_ip = MY_IP;
    repr.max_size = 1432;
    repr.parameter_request_list = &[_]u8{ 1, 3, 6 };
    return repr;
}

fn createSocket() Socket {
    var s = Socket.init(MY_MAC);
    const ev = s.poll();
    std.debug.assert(ev != null and ev.? == .deconfigured);
    return s;
}

fn createSocketDifferentPort() Socket {
    var s = Socket.init(MY_MAC);
    s.setPorts(6700, 6800);
    const ev = s.poll();
    std.debug.assert(ev != null and ev.? == .deconfigured);
    return s;
}

fn createSocketBound() Socket {
    var s = createSocket();
    s.state = .{ .renewing = .{
        .config = .{
            .server = .{
                .address = SERVER_IP,
                .identifier = SERVER_IP,
            },
            .address = MY_IP,
            .prefix_len = 24,
            .dns_servers = dnsServers(),
            .router = SERVER_IP,
        },
        .renew_at = Instant.fromSecs(500),
        .rebind_at = Instant.fromSecs(875),
        .rebinding = false,
        .expires_at = Instant.fromSecs(1000),
    } };
    return s;
}

fn send(s: *Socket, timestamp: Instant, repr: wire.Repr) void {
    s.process(timestamp, SERVER_IP, repr);
}

fn sendFrom(s: *Socket, timestamp: Instant, src_ip: [4]u8, repr: wire.Repr) void {
    s.process(timestamp, src_ip, repr);
}

fn recv(s: *Socket, timestamp: Instant) ?DispatchResult {
    // dispatch may reset state without emitting (e.g. request retries exceeded),
    // so we re-enter to let the new state emit.
    var iterations: u8 = 0;
    while (timestamp.greaterThanOrEqual(s.pollAt())) {
        if (s.dispatch(timestamp)) |result| return result;
        iterations += 1;
        if (iterations >= 4) break;
    }
    return null;
}

fn expectReprEql(expected: wire.Repr, got: wire.Repr) !void {
    try testing.expectEqual(expected.message_type, got.message_type);
    try testing.expectEqualSlices(u8, &expected.client_hardware_address, &got.client_hardware_address);
    try testing.expectEqualSlices(u8, &expected.client_ip, &got.client_ip);
    if (expected.requested_ip) |e| {
        const g = got.requested_ip orelse return error.TestExpectedEqual;
        try testing.expectEqualSlices(u8, &e, &g);
    } else {
        try testing.expect(got.requested_ip == null);
    }
    if (expected.server_identifier) |e| {
        const g = got.server_identifier orelse return error.TestExpectedEqual;
        try testing.expectEqualSlices(u8, &e, &g);
    } else {
        try testing.expect(got.server_identifier == null);
    }
    if (expected.client_identifier) |e| {
        const g = got.client_identifier orelse return error.TestExpectedEqual;
        try testing.expectEqualSlices(u8, &e, &g);
    } else {
        try testing.expect(got.client_identifier == null);
    }
    if (expected.parameter_request_list) |e| {
        try testing.expectEqualSlices(u8, e, got.parameter_request_list orelse return error.TestExpectedEqual);
    } else {
        try testing.expect(got.parameter_request_list == null);
    }
    try testing.expectEqual(expected.max_size, got.max_size);
}

fn expectRecvDiscover(s: *Socket, timestamp: Instant) !void {
    const result = recv(s, timestamp) orelse return error.TestExpectedEqual;
    try expectReprEql(dhcpDiscover(), result.dhcp_repr);
    try testing.expectEqualSlices(u8, &T_IP_ZERO, &result.src_ip);
    try testing.expectEqualSlices(u8, &T_IP_BCAST, &result.dst_ip);
}

fn expectRecvRequest(s: *Socket, timestamp: Instant) !void {
    const result = recv(s, timestamp) orelse return error.TestExpectedEqual;
    try expectReprEql(dhcpRequest(), result.dhcp_repr);
    try testing.expectEqualSlices(u8, &T_IP_ZERO, &result.src_ip);
    try testing.expectEqualSlices(u8, &T_IP_BCAST, &result.dst_ip);
}

fn expectRecvRenew(s: *Socket, timestamp: Instant) !void {
    const result = recv(s, timestamp) orelse return error.TestExpectedEqual;
    try expectReprEql(dhcpRenew(), result.dhcp_repr);
    try testing.expectEqualSlices(u8, &MY_IP, &result.src_ip);
    try testing.expectEqualSlices(u8, &SERVER_IP, &result.dst_ip);
}

fn expectRecvRebind(s: *Socket, timestamp: Instant) !void {
    const result = recv(s, timestamp) orelse return error.TestExpectedEqual;
    try expectReprEql(dhcpRenew(), result.dhcp_repr);
    try testing.expectEqualSlices(u8, &MY_IP, &result.src_ip);
    try testing.expectEqualSlices(u8, &T_IP_BCAST, &result.dst_ip);
}

fn expectRecvNone(s: *Socket, timestamp: Instant) !void {
    const result = recv(s, timestamp);
    try testing.expect(result == null);
}

// [smoltcp:socket/dhcpv4.rs:test_bind]
test "bind" {
    var s = createSocket();

    try expectRecvDiscover(&s, Instant.fromMillis(0));
    try testing.expect(s.poll() == null);
    send(&s, Instant.fromMillis(0), dhcpOffer());
    try testing.expect(s.poll() == null);
    try expectRecvRequest(&s, Instant.fromMillis(0));
    try testing.expect(s.poll() == null);
    send(&s, Instant.fromMillis(0), dhcpAck());

    const ev = s.poll() orelse return error.TestExpectedEqual;
    switch (ev) {
        .configured => |config| {
            try testing.expect(config.server.eql(.{ .address = SERVER_IP, .identifier = SERVER_IP }));
            try testing.expectEqualSlices(u8, &MY_IP, &config.address);
            try testing.expectEqual(@as(u6, 24), config.prefix_len);
            try testing.expectEqualSlices(u8, &SERVER_IP, &(config.router orelse return error.TestExpectedEqual));
        },
        .deconfigured => return error.TestExpectedEqual,
    }

    switch (s.state) {
        .renewing => |r| {
            try testing.expect(r.renew_at.eql(Instant.fromSecs(500)));
            try testing.expect(r.rebind_at.eql(Instant.fromSecs(875)));
            try testing.expect(r.expires_at.eql(Instant.fromSecs(1000)));
        },
        else => return error.TestExpectedEqual,
    }
}

// [smoltcp:socket/dhcpv4.rs:test_bind_different_ports]
test "bind different ports" {
    var s = createSocketDifferentPort();

    try expectRecvDiscover(&s, Instant.fromMillis(0));
    try testing.expect(s.poll() == null);
    send(&s, Instant.fromMillis(0), dhcpOffer());
    try testing.expect(s.poll() == null);
    try expectRecvRequest(&s, Instant.fromMillis(0));
    try testing.expect(s.poll() == null);
    send(&s, Instant.fromMillis(0), dhcpAck());

    const ev = s.poll() orelse return error.TestExpectedEqual;
    switch (ev) {
        .configured => |config| {
            try testing.expect(config.server.eql(.{ .address = SERVER_IP, .identifier = SERVER_IP }));
            try testing.expectEqualSlices(u8, &MY_IP, &config.address);
            try testing.expectEqual(@as(u6, 24), config.prefix_len);
        },
        .deconfigured => return error.TestExpectedEqual,
    }

    switch (s.state) {
        .renewing => |r| {
            try testing.expect(r.renew_at.eql(Instant.fromSecs(500)));
            try testing.expect(r.rebind_at.eql(Instant.fromSecs(875)));
            try testing.expect(r.expires_at.eql(Instant.fromSecs(1000)));
        },
        else => return error.TestExpectedEqual,
    }
}

// [smoltcp:socket/dhcpv4.rs:test_discover_retransmit]
test "discover retransmit" {
    var s = createSocket();

    try expectRecvDiscover(&s, Instant.fromMillis(0));
    try expectRecvNone(&s, Instant.fromMillis(1_000));
    try expectRecvDiscover(&s, Instant.fromMillis(10_000));
    try expectRecvNone(&s, Instant.fromMillis(11_000));
    try expectRecvDiscover(&s, Instant.fromMillis(20_000));

    send(&s, Instant.fromMillis(20_000), dhcpOffer());
    try expectRecvRequest(&s, Instant.fromMillis(20_000));
}

// [smoltcp:socket/dhcpv4.rs:test_request_retransmit]
test "request retransmit" {
    var s = createSocket();

    try expectRecvDiscover(&s, Instant.fromMillis(0));
    send(&s, Instant.fromMillis(0), dhcpOffer());
    try expectRecvRequest(&s, Instant.fromMillis(0));
    try expectRecvNone(&s, Instant.fromMillis(1_000));
    try expectRecvRequest(&s, Instant.fromMillis(5_000));
    try expectRecvNone(&s, Instant.fromMillis(6_000));
    try expectRecvRequest(&s, Instant.fromMillis(10_000));
    try expectRecvNone(&s, Instant.fromMillis(15_000));
    try expectRecvRequest(&s, Instant.fromMillis(20_000));

    send(&s, Instant.fromMillis(20_000), dhcpAck());

    switch (s.state) {
        .renewing => |r| {
            try testing.expect(r.renew_at.eql(Instant.fromSecs(20 + 500)));
            try testing.expect(r.expires_at.eql(Instant.fromSecs(20 + 1000)));
        },
        else => return error.TestExpectedEqual,
    }
}

// [smoltcp:socket/dhcpv4.rs:test_request_timeout]
test "request timeout" {
    var s = createSocket();

    try expectRecvDiscover(&s, Instant.fromMillis(0));
    send(&s, Instant.fromMillis(0), dhcpOffer());
    try expectRecvRequest(&s, Instant.fromMillis(0));
    try expectRecvRequest(&s, Instant.fromMillis(5_000));
    try expectRecvRequest(&s, Instant.fromMillis(10_000));
    try expectRecvRequest(&s, Instant.fromMillis(20_000));
    try expectRecvRequest(&s, Instant.fromMillis(30_000));

    // After 5 tries and 70 seconds, it gives up.
    // Retry schedule: 0, 5, 10, 20, 30 -> next at 50, then timeout check at 70
    try expectRecvDiscover(&s, Instant.fromMillis(70_000));

    send(&s, Instant.fromMillis(60_000), dhcpOffer());
    try expectRecvRequest(&s, Instant.fromMillis(60_000));
}

// [smoltcp:socket/dhcpv4.rs:test_request_nak]
test "request nak" {
    var s = createSocket();

    try expectRecvDiscover(&s, Instant.fromMillis(0));
    send(&s, Instant.fromMillis(0), dhcpOffer());
    try expectRecvRequest(&s, Instant.fromMillis(0));
    send(&s, Instant.fromMillis(0), dhcpNak());
    try expectRecvDiscover(&s, Instant.fromMillis(0));
}

// [smoltcp:socket/dhcpv4.rs:test_renew]
test "renew" {
    var s = createSocketBound();

    try expectRecvNone(&s, Instant.fromMillis(0));
    try testing.expect(s.poll() == null);
    try expectRecvRenew(&s, Instant.fromMillis(500_000));
    try testing.expect(s.poll() == null);

    switch (s.state) {
        .renewing => |r| {
            // expiration still hasn't been bumped -- no ACK yet
            try testing.expect(r.expires_at.eql(Instant.fromSecs(1000)));
        },
        else => return error.TestExpectedEqual,
    }

    send(&s, Instant.fromMillis(500_000), dhcpAck());
    try testing.expect(s.poll() == null);

    switch (s.state) {
        .renewing => |r| {
            try testing.expect(r.renew_at.eql(Instant.fromSecs(500 + 500)));
            try testing.expect(r.expires_at.eql(Instant.fromSecs(500 + 1000)));
        },
        else => return error.TestExpectedEqual,
    }
}

// [smoltcp:socket/dhcpv4.rs:test_renew_rebind_retransmit]
test "renew rebind retransmit" {
    var s = createSocketBound();

    try expectRecvNone(&s, Instant.fromMillis(0));
    // First renew at T1
    try expectRecvNone(&s, Instant.fromMillis(499_000));
    try expectRecvRenew(&s, Instant.fromMillis(500_000));
    // Next renew at half way to T2
    try expectRecvNone(&s, Instant.fromMillis(687_000));
    try expectRecvRenew(&s, Instant.fromMillis(687_500));
    // Next renew at half way again to T2
    try expectRecvNone(&s, Instant.fromMillis(781_000));
    try expectRecvRenew(&s, Instant.fromMillis(781_250));
    // Next renew 60s later (minimum interval)
    try expectRecvNone(&s, Instant.fromMillis(841_000));
    try expectRecvRenew(&s, Instant.fromMillis(841_250));
    // No more renews due to minimum interval
    try expectRecvNone(&s, Instant.fromMillis(874_000));
    // First rebind
    try expectRecvRebind(&s, Instant.fromMillis(875_000));
    // Next rebind half way to expiry
    try expectRecvNone(&s, Instant.fromMillis(937_000));
    try expectRecvRebind(&s, Instant.fromMillis(937_500));
    // Next rebind 60s later (minimum interval)
    try expectRecvNone(&s, Instant.fromMillis(997_000));
    try expectRecvRebind(&s, Instant.fromMillis(997_500));

    send(&s, Instant.fromMillis(999_000), dhcpAck());
    switch (s.state) {
        .renewing => |r| {
            try testing.expect(r.renew_at.eql(Instant.fromSecs(999 + 500)));
            try testing.expect(r.expires_at.eql(Instant.fromSecs(999 + 1000)));
        },
        else => return error.TestExpectedEqual,
    }
}

// [smoltcp:socket/dhcpv4.rs:test_renew_rebind_timeout]
test "renew rebind timeout" {
    var s = createSocketBound();

    try expectRecvNone(&s, Instant.fromMillis(0));
    try expectRecvRenew(&s, Instant.fromMillis(500_000));
    try expectRecvRenew(&s, Instant.fromMillis(687_500));
    try expectRecvRenew(&s, Instant.fromMillis(781_250));
    try expectRecvRenew(&s, Instant.fromMillis(841_250));
    // Lease expires at 1000s -- reset to discovering
    try expectRecvDiscover(&s, Instant.fromMillis(1_000_000));
    switch (s.state) {
        .discovering => {},
        else => return error.TestExpectedEqual,
    }
}

// [smoltcp:socket/dhcpv4.rs:test_min_max_renew_timeout]
test "min max renew timeout" {
    var s = createSocketBound();
    s.retry_config.max_renew_timeout = Duration.fromSecs(120);
    s.retry_config.min_renew_timeout = Duration.fromSecs(45);

    try expectRecvNone(&s, Instant.fromMillis(0));
    // First renew at T1
    try expectRecvNone(&s, Instant.fromMillis(499_999));
    try expectRecvRenew(&s, Instant.fromMillis(500_000));
    // Next renew 120s after T1 (hit the max)
    try expectRecvNone(&s, Instant.fromMillis(619_999));
    try expectRecvRenew(&s, Instant.fromMillis(620_000));
    // Next renew 120s after previous (max again)
    try expectRecvNone(&s, Instant.fromMillis(739_999));
    try expectRecvRenew(&s, Instant.fromMillis(740_000));
    // Next renew half way to T2
    try expectRecvNone(&s, Instant.fromMillis(807_499));
    try expectRecvRenew(&s, Instant.fromMillis(807_500));
    // Next renew 45s after (hit the min)
    try expectRecvNone(&s, Instant.fromMillis(852_499));
    try expectRecvRenew(&s, Instant.fromMillis(852_500));
    // Next is rebind (min puts us after T2)
    try expectRecvNone(&s, Instant.fromMillis(874_999));
    try expectRecvRebind(&s, Instant.fromMillis(875_000));
}

// [smoltcp:socket/dhcpv4.rs:test_renew_nak]
test "renew nak" {
    var s = createSocketBound();

    try expectRecvRenew(&s, Instant.fromMillis(500_000));
    send(&s, Instant.fromMillis(500_000), dhcpNak());
    try expectRecvDiscover(&s, Instant.fromMillis(500_000));
}
