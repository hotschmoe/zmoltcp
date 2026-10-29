//! Mistakes shaped like the ones zmoltcp's API invites, with their verdicts pinned in own/seeded.expect (`zig build
//! own-seeded`): sockets keep the buffers their caller lends them, so a buffer on the caller's stack must outlive the
//! socket; a DNS query handle names one query and goes stale when the query is cancelled (the audit finding fixed in
//! a10dc54). The `ok` cases are the same calls used correctly. Nothing here is part of the library.

const zmoltcp = @import("zmoltcp");

const ipv4 = zmoltcp.wire.ipv4;
const Dns = zmoltcp.socket.dns.Socket(ipv4);
const Tcp = zmoltcp.socket.tcp.Socket(ipv4, 4);

pub fn okQueryRoundTrip(sock: *Dns) void {
    const handle = sock.startQuery("example.org", .a) catch return;
    _ = sock.getQueryResult(handle) catch {};
    sock.cancelQuery(handle);
}

pub fn okSocketOverCallerStorage(rx: []u8, tx: []u8) Tcp {
    return Tcp.init(rx, tx);
}

pub fn okSocketOnLocalStorageUsedHere() bool {
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    const sock = Tcp.init(&rx, &tx);
    return sock.isOpen();
}

pub fn badStaleQueryHandle(sock: *Dns) void {
    const handle = sock.startQuery("example.org", .a) catch return;
    sock.cancelQuery(handle);
    _ = sock.getQueryResult(handle) catch {};
}

pub fn badSocketKeepsLocalBuffers() Tcp {
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    return Tcp.init(&rx, &tx);
}

pub fn badSocketStoredOverLocalBuffers(slot: *Tcp) void {
    var rx: [256]u8 = undefined;
    var tx: [256]u8 = undefined;
    slot.* = Tcp.init(&rx, &tx);
}

pub fn badDnsOverLocalSlots(servers: []const ipv4.Address) Dns {
    var slots: [2]Dns.QuerySlot = .{ .{}, .{} };
    return Dns.init(&slots, servers);
}
