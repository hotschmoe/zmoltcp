// DHCPv4 packet parsing and serialization.
//
// Reference: RFC 2131, smoltcp src/wire/dhcpv4.rs

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;
pub const MAX_DNS_SERVER_COUNT = 3;

const MAGIC_NUMBER: u32 = 0x63825363;
const MIN_HEADER_LEN = 240;

pub const OpCode = enum(u8) {
    request = 1,
    reply = 2,
    _,
};

pub const MessageType = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
    _,

    pub fn opCode(self: MessageType) OpCode {
        return switch (self) {
            .discover, .inform, .request, .decline, .release => .request,
            .offer, .ack, .nak => .reply,
            _ => @enumFromInt(0),
        };
    }
};

// DHCP option codes (constants, not an enum -- too sparse)
pub const OPT_PAD: u8 = 0;
pub const OPT_END: u8 = 255;
pub const OPT_SUBNET_MASK: u8 = 1;
pub const OPT_ROUTER: u8 = 3;
pub const OPT_DOMAIN_NAME_SERVER: u8 = 6;
pub const OPT_REQUESTED_IP: u8 = 50;
pub const OPT_IP_LEASE_TIME: u8 = 51;
pub const OPT_DHCP_MESSAGE_TYPE: u8 = 53;
pub const OPT_SERVER_IDENTIFIER: u8 = 54;
pub const OPT_PARAMETER_REQUEST_LIST: u8 = 55;
pub const OPT_MAX_DHCP_MESSAGE_SIZE: u8 = 57;
pub const OPT_RENEWAL_TIME_VALUE: u8 = 58;
pub const OPT_REBINDING_TIME_VALUE: u8 = 59;
pub const OPT_CLIENT_ID: u8 = 61;

pub const DnsServers = struct {
    addrs: [MAX_DNS_SERVER_COUNT][4]u8 = undefined,
    len: u8 = 0,

    pub fn push(self: *DnsServers, addr: [4]u8) void {
        if (self.len < MAX_DNS_SERVER_COUNT) {
            self.addrs[self.len] = addr;
            self.len += 1;
        }
    }

    pub fn get(self: *const DnsServers, i: usize) [4]u8 {
        return self.addrs[i];
    }

    pub fn eql(self: *const DnsServers, other: *const DnsServers) bool {
        if (self.len != other.len) return false;
        for (0..self.len) |i| {
            if (!std.mem.eql(u8, &self.addrs[i], &other.addrs[i])) return false;
        }
        return true;
    }
};

pub const Repr = struct {
    message_type: MessageType,
    transaction_id: u32,
    secs: u16,
    client_hardware_address: [6]u8,
    client_ip: [4]u8,
    your_ip: [4]u8,
    server_ip: [4]u8,
    relay_agent_ip: [4]u8,
    broadcast: bool,
    requested_ip: ?[4]u8,
    client_identifier: ?[6]u8,
    server_identifier: ?[4]u8,
    router: ?[4]u8,
    subnet_mask: ?[4]u8,
    max_size: ?u16,
    lease_duration: ?u32,
    renew_duration: ?u32,
    rebind_duration: ?u32,
    dns_servers: ?DnsServers,
    parameter_request_list: ?[]const u8,
};

pub const ParseError = error{
    Truncated,
    InvalidMagic,
    InvalidHardware,
    MissingMessageType,
};

pub fn parse(data: []const u8) ParseError!Repr {
    if (data.len < MIN_HEADER_LEN) return error.Truncated;

    // Validate hardware type (Ethernet = 1) and hardware address length (6)
    if (data[1] != 1 or data[2] != 6) return error.InvalidHardware;

    // Validate magic cookie
    const magic = @as(u32, data[236]) << 24 | @as(u32, data[237]) << 16 |
        @as(u32, data[238]) << 8 | @as(u32, data[239]);
    if (magic != MAGIC_NUMBER) return error.InvalidMagic;

    const op: OpCode = @enumFromInt(data[0]);
    const transaction_id = @as(u32, data[4]) << 24 | @as(u32, data[5]) << 16 |
        @as(u32, data[6]) << 8 | @as(u32, data[7]);
    const secs = @as(u16, data[8]) << 8 | @as(u16, data[9]);
    const flags = @as(u16, data[10]) << 8 | @as(u16, data[11]);
    const broadcast = (flags & 0x8000) != 0;

    var message_type: ?MessageType = null;
    var requested_ip: ?[4]u8 = null;
    var client_identifier: ?[6]u8 = null;
    var server_identifier: ?[4]u8 = null;
    var router: ?[4]u8 = null;
    var subnet_mask: ?[4]u8 = null;
    var parameter_request_list: ?[]const u8 = null;
    var dns_servers: ?DnsServers = null;
    var max_size: ?u16 = null;
    var lease_duration: ?u32 = null;
    var renew_duration: ?u32 = null;
    var rebind_duration: ?u32 = null;

    // Iterate TLV options starting at offset 240
    var pos: usize = MIN_HEADER_LEN;
    while (pos < data.len) {
        const kind = data[pos];
        if (kind == OPT_END) break;
        if (kind == OPT_PAD) {
            pos += 1;
            continue;
        }
        if (pos + 1 >= data.len) break;
        const opt_len = data[pos + 1];
        if (pos + 2 + @as(usize, opt_len) > data.len) break;
        const opt_data = data[pos + 2 .. pos + 2 + @as(usize, opt_len)];
        pos += 2 + @as(usize, opt_len);

        switch (kind) {
            OPT_DHCP_MESSAGE_TYPE => {
                if (opt_data.len == 1) {
                    const value: MessageType = @enumFromInt(opt_data[0]);
                    if (value.opCode() == op) {
                        message_type = value;
                    }
                }
            },
            OPT_REQUESTED_IP => {
                if (opt_data.len == 4) {
                    requested_ip = opt_data[0..4].*;
                }
            },
            OPT_CLIENT_ID => {
                if (opt_data.len == 7) {
                    // First byte is hardware type (1 = Ethernet)
                    if (opt_data[0] != 1) return error.InvalidHardware;
                    client_identifier = opt_data[1..7].*;
                }
            },
            OPT_SERVER_IDENTIFIER => {
                if (opt_data.len == 4) {
                    server_identifier = opt_data[0..4].*;
                }
            },
            OPT_ROUTER => {
                if (opt_data.len == 4) {
                    router = opt_data[0..4].*;
                }
            },
            OPT_SUBNET_MASK => {
                if (opt_data.len == 4) {
                    subnet_mask = opt_data[0..4].*;
                }
            },
            OPT_MAX_DHCP_MESSAGE_SIZE => {
                if (opt_data.len == 2) {
                    max_size = @as(u16, opt_data[0]) << 8 | @as(u16, opt_data[1]);
                }
            },
            OPT_RENEWAL_TIME_VALUE => {
                if (opt_data.len == 4) {
                    renew_duration = @as(u32, opt_data[0]) << 24 | @as(u32, opt_data[1]) << 16 |
                        @as(u32, opt_data[2]) << 8 | @as(u32, opt_data[3]);
                }
            },
            OPT_REBINDING_TIME_VALUE => {
                if (opt_data.len == 4) {
                    rebind_duration = @as(u32, opt_data[0]) << 24 | @as(u32, opt_data[1]) << 16 |
                        @as(u32, opt_data[2]) << 8 | @as(u32, opt_data[3]);
                }
            },
            OPT_IP_LEASE_TIME => {
                if (opt_data.len == 4) {
                    lease_duration = @as(u32, opt_data[0]) << 24 | @as(u32, opt_data[1]) << 16 |
                        @as(u32, opt_data[2]) << 8 | @as(u32, opt_data[3]);
                }
            },
            OPT_PARAMETER_REQUEST_LIST => {
                parameter_request_list = opt_data;
            },
            OPT_DOMAIN_NAME_SERVER => {
                var servers = DnsServers{};
                var i: usize = 0;
                while (i + 4 <= opt_data.len) : (i += 4) {
                    servers.push(opt_data[i..][0..4].*);
                }
                dns_servers = servers;
            },
            else => {},
        }
    }

    const mt = message_type orelse return error.MissingMessageType;

    return .{
        .message_type = mt,
        .transaction_id = transaction_id,
        .secs = secs,
        .client_hardware_address = data[28..34].*,
        .client_ip = data[12..16].*,
        .your_ip = data[16..20].*,
        .server_ip = data[20..24].*,
        .relay_agent_ip = data[24..28].*,
        .broadcast = broadcast,
        .requested_ip = requested_ip,
        .client_identifier = client_identifier,
        .server_identifier = server_identifier,
        .router = router,
        .subnet_mask = subnet_mask,
        .max_size = max_size,
        .lease_duration = lease_duration,
        .renew_duration = renew_duration,
        .rebind_duration = rebind_duration,
        .dns_servers = dns_servers,
        .parameter_request_list = parameter_request_list,
    };
}

/// Compute exact buffer size needed for emit.
pub fn bufferLen(repr: Repr) usize {
    // Fixed header (240) + message type option (3) + end byte (1)
    var len: usize = MIN_HEADER_LEN + 3 + 1;
    if (repr.requested_ip != null) len += 6;
    if (repr.client_identifier != null) len += 9; // 2 + 1(htype) + 6(addr)
    if (repr.server_identifier != null) len += 6;
    if (repr.max_size != null) len += 4;
    if (repr.router != null) len += 6;
    if (repr.subnet_mask != null) len += 6;
    if (repr.lease_duration != null) len += 6;
    if (repr.dns_servers) |servers| {
        len += 2 + @as(usize, servers.len) * 4;
    }
    if (repr.parameter_request_list) |list| {
        len += 2 + list.len;
    }
    return len;
}

pub fn emit(repr: Repr, buf: []u8) error{BufferTooSmall}!usize {
    const required = bufferLen(repr);
    if (buf.len < required) return error.BufferTooSmall;

    // Zero the sname and file regions
    @memset(buf[34..236], 0);

    // Fixed header
    buf[0] = @intFromEnum(repr.message_type.opCode());
    buf[1] = 1; // htype = Ethernet
    buf[2] = 6; // hlen = 6
    buf[3] = 0; // hops
    buf[4] = @truncate(repr.transaction_id >> 24);
    buf[5] = @truncate(repr.transaction_id >> 16);
    buf[6] = @truncate(repr.transaction_id >> 8);
    buf[7] = @truncate(repr.transaction_id);
    buf[8] = @truncate(repr.secs >> 8);
    buf[9] = @truncate(repr.secs);
    const flags: u16 = if (repr.broadcast) 0x8000 else 0;
    buf[10] = @truncate(flags >> 8);
    buf[11] = @truncate(flags);
    @memcpy(buf[12..16], &repr.client_ip);
    @memcpy(buf[16..20], &repr.your_ip);
    @memcpy(buf[20..24], &repr.server_ip);
    @memcpy(buf[24..28], &repr.relay_agent_ip);
    @memcpy(buf[28..34], &repr.client_hardware_address);

    // Magic cookie
    buf[236] = 0x63;
    buf[237] = 0x82;
    buf[238] = 0x53;
    buf[239] = 0x63;

    // Options
    var pos: usize = MIN_HEADER_LEN;

    // Message type (always first)
    pos = emitOption(buf, pos, OPT_DHCP_MESSAGE_TYPE, &[_]u8{@intFromEnum(repr.message_type)});

    // Client identifier
    if (repr.client_identifier) |addr| {
        var data: [7]u8 = undefined;
        data[0] = 1; // hardware type = Ethernet
        @memcpy(data[1..7], &addr);
        pos = emitOption(buf, pos, OPT_CLIENT_ID, &data);
    }

    // Server identifier
    if (repr.server_identifier) |addr| {
        pos = emitOption(buf, pos, OPT_SERVER_IDENTIFIER, &addr);
    }

    // Router
    if (repr.router) |addr| {
        pos = emitOption(buf, pos, OPT_ROUTER, &addr);
    }

    // Subnet mask
    if (repr.subnet_mask) |addr| {
        pos = emitOption(buf, pos, OPT_SUBNET_MASK, &addr);
    }

    // Requested IP
    if (repr.requested_ip) |addr| {
        pos = emitOption(buf, pos, OPT_REQUESTED_IP, &addr);
    }

    // Max DHCP message size
    if (repr.max_size) |size| {
        const data = [_]u8{ @truncate(size >> 8), @truncate(size) };
        pos = emitOption(buf, pos, OPT_MAX_DHCP_MESSAGE_SIZE, &data);
    }

    // Lease duration
    if (repr.lease_duration) |dur| {
        const data = [_]u8{
            @truncate(dur >> 24), @truncate(dur >> 16),
            @truncate(dur >> 8),  @truncate(dur),
        };
        pos = emitOption(buf, pos, OPT_IP_LEASE_TIME, &data);
    }

    // Parameter request list
    if (repr.parameter_request_list) |list| {
        pos = emitOption(buf, pos, OPT_PARAMETER_REQUEST_LIST, list);
    }

    // DNS servers
    if (repr.dns_servers) |servers| {
        var data: [MAX_DNS_SERVER_COUNT * 4]u8 = undefined;
        for (0..servers.len) |i| {
            @memcpy(data[i * 4 ..][0..4], &servers.addrs[i]);
        }
        pos = emitOption(buf, pos, OPT_DOMAIN_NAME_SERVER, data[0 .. @as(usize, servers.len) * 4]);
    }

    // END
    buf[pos] = OPT_END;
    pos += 1;

    return pos;
}

fn emitOption(buf: []u8, pos: usize, kind: u8, data: []const u8) usize {
    buf[pos] = kind;
    buf[pos + 1] = @truncate(data.len);
    @memcpy(buf[pos + 2 .. pos + 2 + data.len], data);
    return pos + 2 + data.len;
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const std = @import("std");
const testing = std.testing;

const IP_NULL = [4]u8{ 0, 0, 0, 0 };
const CLIENT_MAC = [6]u8{ 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42 };
const DHCP_SIZE: u16 = 1500;

// [smoltcp:wire/dhcpv4.rs:DISCOVER_BYTES]
const DISCOVER_BYTES = [_]u8{
    0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x3d, 0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
    0x82, 0x01, 0xfc, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
    0x35, 0x01, 0x01, 0x3d, 0x07, 0x01, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42, 0x32, 0x04, 0x00,
    0x00, 0x00, 0x00, 0x39, 0x02, 0x05, 0xdc, 0x37, 0x04, 0x01, 0x03, 0x06, 0x2a, 0xff, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// [smoltcp:wire/dhcpv4.rs:ACK_DNS_SERVER_BYTES]
const ACK_DNS_SERVER_BYTES = [_]u8{
    0x02, 0x01, 0x06, 0x00, 0xcc, 0x34, 0x75, 0xab, 0x00, 0x00, 0x80, 0x00, 0x0a, 0xff, 0x06,
    0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xff, 0x06, 0xfe, 0x34, 0x17,
    0xeb, 0xc9, 0xaa, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
    0x35, 0x01, 0x05, 0x36, 0x04, 0xa3, 0x01, 0x4a, 0x16, 0x01, 0x04, 0xff, 0xff, 0xff, 0x00,
    0x2b, 0x05, 0xdc, 0x03, 0x4e, 0x41, 0x50, 0x0f, 0x15, 0x6e, 0x61, 0x74, 0x2e, 0x70, 0x68,
    0x79, 0x73, 0x69, 0x63, 0x73, 0x2e, 0x6f, 0x78, 0x2e, 0x61, 0x63, 0x2e, 0x75, 0x6b, 0x00,
    0x03, 0x04, 0x0a, 0xff, 0x06, 0xfe, 0x06, 0x10, 0xa3, 0x01, 0x4a, 0x06, 0xa3, 0x01, 0x4a,
    0x07, 0xa3, 0x01, 0x4a, 0x03, 0xa3, 0x01, 0x4a, 0x04, 0x2c, 0x10, 0xa3, 0x01, 0x4a, 0x03,
    0xa3, 0x01, 0x4a, 0x04, 0xa3, 0x01, 0x4a, 0x06, 0xa3, 0x01, 0x4a, 0x07, 0x2e, 0x01, 0x08,
    0xff,
};

// [smoltcp:wire/dhcpv4.rs:ACK_LEASE_TIME_BYTES]
const ACK_LEASE_TIME_BYTES = [_]u8{
    0x02, 0x01, 0x06, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0a, 0x22, 0x10, 0x0b, 0x0a, 0x22, 0x10, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x04, 0x91,
    0x62, 0xd2, 0xa8, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x82, 0x53, 0x63,
    0x35, 0x01, 0x05, 0x36, 0x04, 0x0a, 0x22, 0x10, 0x0a, 0x33, 0x04, 0x00, 0x00, 0x02, 0x56,
    0x01, 0x04, 0xff, 0xff, 0xff, 0x00, 0x03, 0x04, 0x0a, 0x22, 0x10, 0x0a, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

fn discoverRepr() Repr {
    return .{
        .message_type = .discover,
        .transaction_id = 0x3d1d,
        .client_hardware_address = CLIENT_MAC,
        .client_ip = IP_NULL,
        .your_ip = IP_NULL,
        .server_ip = IP_NULL,
        .router = null,
        .subnet_mask = null,
        .relay_agent_ip = IP_NULL,
        .broadcast = false,
        .secs = 0,
        .max_size = DHCP_SIZE,
        .renew_duration = null,
        .rebind_duration = null,
        .lease_duration = null,
        .requested_ip = IP_NULL,
        .client_identifier = CLIENT_MAC,
        .server_identifier = null,
        .parameter_request_list = &[_]u8{ 1, 3, 6, 42 },
        .dns_servers = null,
    };
}

fn offerRepr() Repr {
    return .{
        .message_type = .offer,
        .transaction_id = 0x3d1d,
        .client_hardware_address = CLIENT_MAC,
        .client_ip = IP_NULL,
        .your_ip = IP_NULL,
        .server_ip = IP_NULL,
        .router = IP_NULL,
        .subnet_mask = IP_NULL,
        .relay_agent_ip = IP_NULL,
        .secs = 0,
        .broadcast = false,
        .requested_ip = null,
        .client_identifier = CLIENT_MAC,
        .server_identifier = null,
        .parameter_request_list = null,
        .dns_servers = null,
        .max_size = null,
        .renew_duration = null,
        .rebind_duration = null,
        .lease_duration = 0xffff_ffff,
    };
}

// [smoltcp:wire/dhcpv4.rs:test_deconstruct_discover]
test "deconstruct discover raw fields" {
    // Validate fixed header fields directly from bytes
    try testing.expectEqual(@as(u8, 0x01), DISCOVER_BYTES[0]); // op = Request
    try testing.expectEqual(@as(u8, 0x01), DISCOVER_BYTES[1]); // htype = Ethernet
    try testing.expectEqual(@as(u8, 0x06), DISCOVER_BYTES[2]); // hlen = 6
    try testing.expectEqual(@as(u8, 0x00), DISCOVER_BYTES[3]); // hops = 0

    // xid = 0x00003d1d
    const xid = @as(u32, DISCOVER_BYTES[4]) << 24 | @as(u32, DISCOVER_BYTES[5]) << 16 |
        @as(u32, DISCOVER_BYTES[6]) << 8 | @as(u32, DISCOVER_BYTES[7]);
    try testing.expectEqual(@as(u32, 0x3d1d), xid);

    // secs = 0
    const secs_val = @as(u16, DISCOVER_BYTES[8]) << 8 | @as(u16, DISCOVER_BYTES[9]);
    try testing.expectEqual(@as(u16, 0), secs_val);

    // All IP fields zero
    try testing.expectEqualSlices(u8, &IP_NULL, DISCOVER_BYTES[12..16]); // ciaddr
    try testing.expectEqualSlices(u8, &IP_NULL, DISCOVER_BYTES[16..20]); // yiaddr
    try testing.expectEqualSlices(u8, &IP_NULL, DISCOVER_BYTES[20..24]); // siaddr
    try testing.expectEqualSlices(u8, &IP_NULL, DISCOVER_BYTES[24..28]); // giaddr

    // chaddr
    try testing.expectEqualSlices(u8, &CLIENT_MAC, DISCOVER_BYTES[28..34]);

    // magic cookie
    const magic = @as(u32, DISCOVER_BYTES[236]) << 24 | @as(u32, DISCOVER_BYTES[237]) << 16 |
        @as(u32, DISCOVER_BYTES[238]) << 8 | @as(u32, DISCOVER_BYTES[239]);
    try testing.expectEqual(@as(u32, 0x63825363), magic);

    // Parse to verify options are iterable
    const repr = try parse(&DISCOVER_BYTES);
    try testing.expectEqual(MessageType.discover, repr.message_type);
}

// [smoltcp:wire/dhcpv4.rs:test_parse_discover]
test "parse discover" {
    const repr = try parse(&DISCOVER_BYTES);
    const expected = discoverRepr();
    try testing.expectEqual(expected.message_type, repr.message_type);
    try testing.expectEqual(expected.transaction_id, repr.transaction_id);
    try testing.expectEqual(expected.secs, repr.secs);
    try testing.expectEqualSlices(u8, &expected.client_hardware_address, &repr.client_hardware_address);
    try testing.expectEqualSlices(u8, &expected.client_ip, &repr.client_ip);
    try testing.expectEqualSlices(u8, &expected.your_ip, &repr.your_ip);
    try testing.expectEqualSlices(u8, &expected.server_ip, &repr.server_ip);
    try testing.expectEqualSlices(u8, &expected.relay_agent_ip, &repr.relay_agent_ip);
    try testing.expectEqual(expected.broadcast, repr.broadcast);
    try testing.expectEqual(expected.max_size, repr.max_size);
    try testing.expectEqualSlices(u8, &(expected.requested_ip orelse unreachable), &(repr.requested_ip orelse unreachable));
    try testing.expectEqualSlices(u8, &(expected.client_identifier orelse unreachable), &(repr.client_identifier orelse unreachable));
    try testing.expect(repr.server_identifier == null);
    try testing.expectEqualSlices(u8, expected.parameter_request_list.?, repr.parameter_request_list.?);
    try testing.expect(repr.dns_servers == null);
}

// [smoltcp:wire/dhcpv4.rs:test_emit_discover]
test "emit discover" {
    const repr = comptime discoverRepr();
    var buf: [bufferLen(repr)]u8 = undefined;
    @memset(&buf, 0xa5);
    const written = try emit(repr, &buf);
    // Compare up to written length with the reference bytes
    try testing.expectEqualSlices(u8, DISCOVER_BYTES[0..written], buf[0..written]);
    // Remaining bytes in reference should be zero (padding)
    for (DISCOVER_BYTES[written..]) |b| {
        try testing.expectEqual(@as(u8, 0), b);
    }
}

// [smoltcp:wire/dhcpv4.rs:test_emit_offer]
test "emit offer" {
    const repr = offerRepr();
    var buf: [512]u8 = undefined;
    _ = try emit(repr, &buf);
}

// [smoltcp:wire/dhcpv4.rs:test_emit_offer_dns]
test "emit offer with dns servers roundtrip" {
    var repr = offerRepr();
    var servers = DnsServers{};
    servers.push(.{ 163, 1, 74, 6 });
    servers.push(.{ 163, 1, 74, 7 });
    servers.push(.{ 163, 1, 74, 3 });
    repr.dns_servers = servers;

    var buf: [512]u8 = undefined;
    const written = try emit(repr, &buf);

    const parsed = try parse(buf[0..written]);
    try testing.expect(parsed.dns_servers != null);
    const got = parsed.dns_servers.?;
    try testing.expectEqual(@as(u8, 3), got.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 163, 1, 74, 6 }, &got.addrs[0]);
    try testing.expectEqualSlices(u8, &[_]u8{ 163, 1, 74, 7 }, &got.addrs[1]);
    try testing.expectEqualSlices(u8, &[_]u8{ 163, 1, 74, 3 }, &got.addrs[2]);
}

// [smoltcp:wire/dhcpv4.rs:test_emit_dhcp_option]
test "emit dhcp option TLV" {
    const data = [_]u8{ 1, 3, 6 };
    var buf: [5]u8 = undefined;
    @memset(&buf, 0xa5);
    const pos = emitOption(&buf, 0, OPT_PARAMETER_REQUEST_LIST, &data);
    try testing.expectEqual(@as(usize, 5), pos);
    try testing.expectEqual(OPT_PARAMETER_REQUEST_LIST, buf[0]);
    try testing.expectEqual(@as(u8, 3), buf[1]);
    try testing.expectEqualSlices(u8, &data, buf[2..5]);
}

// [smoltcp:wire/dhcpv4.rs:test_parse_ack_dns_servers]
test "parse ack with dns servers capped at 3" {
    const repr = try parse(&ACK_DNS_SERVER_BYTES);
    try testing.expect(repr.dns_servers != null);
    const servers = repr.dns_servers.?;
    try testing.expectEqual(@as(u8, 3), servers.len);
    try testing.expectEqualSlices(u8, &[_]u8{ 163, 1, 74, 6 }, &servers.addrs[0]);
    try testing.expectEqualSlices(u8, &[_]u8{ 163, 1, 74, 7 }, &servers.addrs[1]);
    try testing.expectEqualSlices(u8, &[_]u8{ 163, 1, 74, 3 }, &servers.addrs[2]);
}

// [smoltcp:wire/dhcpv4.rs:test_parse_ack_lease_duration]
test "parse ack with lease duration" {
    const repr = try parse(&ACK_LEASE_TIME_BYTES);
    try testing.expectEqual(@as(u32, 598), repr.lease_duration.?);
}

// [smoltcp:wire/dhcpv4.rs:test_construct_discover]
test "construct discover from bytes" {
    var buf: [276]u8 = undefined;
    @memset(&buf, 0xa5);

    // Fixed header
    buf[0] = 0x01; // op = Request
    buf[1] = 0x01; // htype = Ethernet
    buf[2] = 0x06; // hlen = 6
    buf[3] = 0x00; // hops

    // xid = 0x3d1d
    buf[4] = 0x00;
    buf[5] = 0x00;
    buf[6] = 0x3d;
    buf[7] = 0x1d;

    // secs = 0, flags = 0
    @memset(buf[8..12], 0);

    // ciaddr, yiaddr, siaddr, giaddr = 0
    @memset(buf[12..28], 0);

    // chaddr
    @memcpy(buf[28..34], &CLIENT_MAC);

    // sname + file zeroed
    @memset(buf[34..236], 0);

    // magic cookie
    buf[236] = 0x63;
    buf[237] = 0x82;
    buf[238] = 0x53;
    buf[239] = 0x63;

    // Options
    var pos: usize = 240;
    pos = emitOption(&buf, pos, OPT_DHCP_MESSAGE_TYPE, &[_]u8{0x01});
    pos = emitOption(&buf, pos, OPT_CLIENT_ID, &[_]u8{ 0x01, 0x00, 0x0b, 0x82, 0x01, 0xfc, 0x42 });
    pos = emitOption(&buf, pos, OPT_REQUESTED_IP, &[_]u8{ 0x00, 0x00, 0x00, 0x00 });
    pos = emitOption(&buf, pos, OPT_MAX_DHCP_MESSAGE_SIZE, &[_]u8{ 0x05, 0xdc });
    pos = emitOption(&buf, pos, OPT_PARAMETER_REQUEST_LIST, &[_]u8{ 1, 3, 6, 42 });
    buf[pos] = OPT_END;
    pos += 1;

    // Zero padding
    @memset(buf[pos..276], 0);

    try testing.expectEqualSlices(u8, &DISCOVER_BYTES, &buf);
}
