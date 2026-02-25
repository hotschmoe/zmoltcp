// Generic IP types parameterized over an address family.
//
// Provides Cidr, Endpoint, and ListenEndpoint as comptime-generic types
// that work with any IP address type satisfying the Ip contract.

const std = @import("std");

pub fn assertIsIp(comptime Ip: type) void {
    comptime {
        if (!@hasDecl(Ip, "Address")) @compileError("Ip must have Address type");
        if (!@hasDecl(Ip, "ADDRESS_LEN")) @compileError("Ip must have ADDRESS_LEN");
        if (!@hasDecl(Ip, "UNSPECIFIED")) @compileError("Ip must have UNSPECIFIED");
        if (!@hasDecl(Ip, "isUnspecified")) @compileError("Ip must have isUnspecified()");
        if (!@hasDecl(Ip, "isBroadcast")) @compileError("Ip must have isBroadcast()");
        if (!@hasDecl(Ip, "isMulticast")) @compileError("Ip must have isMulticast()");
        if (!@hasDecl(Ip, "isLoopback")) @compileError("Ip must have isLoopback()");
        if (!@hasDecl(Ip, "Protocol")) @compileError("Ip must have Protocol type");
    }
}

pub fn Cidr(comptime Ip: type) type {
    comptime assertIsIp(Ip);

    const BITS = Ip.ADDRESS_LEN * 8;
    const IntType = std.meta.Int(.unsigned, BITS);

    return struct {
        address: Ip.Address,
        prefix_len: u8,

        const Self = @This();

        fn addrToInt(addr: Ip.Address) IntType {
            var result: IntType = 0;
            for (addr) |byte| {
                result = (result << 8) | @as(IntType, byte);
            }
            return result;
        }

        fn intToAddr(val: IntType) Ip.Address {
            var addr: Ip.Address = undefined;
            var v = val;
            var i: usize = Ip.ADDRESS_LEN;
            while (i > 0) {
                i -= 1;
                addr[i] = @truncate(v);
                v >>= 8;
            }
            return addr;
        }

        fn hostMask(self: Self) IntType {
            if (self.prefix_len == 0) return @as(IntType, 0) -% 1;
            if (self.prefix_len >= BITS) return 0;
            const shift: std.math.Log2Int(IntType) = @intCast(BITS - self.prefix_len);
            return (@as(IntType, 1) << shift) -% 1;
        }

        pub fn networkMask(self: Self) IntType {
            return ~self.hostMask();
        }

        pub fn networkAddr(self: Self) Ip.Address {
            return intToAddr(addrToInt(self.address) & self.networkMask());
        }

        pub fn broadcast(self: Self) ?Ip.Address {
            if (self.prefix_len >= BITS - 1) return null;
            return intToAddr(addrToInt(self.address) | self.hostMask());
        }

        pub fn contains(self: Self, addr: Ip.Address) bool {
            return (addrToInt(addr) & self.networkMask()) == (addrToInt(self.address) & self.networkMask());
        }
    };
}

pub fn Endpoint(comptime Ip: type) type {
    comptime assertIsIp(Ip);
    return struct {
        addr: Ip.Address,
        port: u16,
    };
}

pub fn ListenEndpoint(comptime Ip: type) type {
    comptime assertIsIp(Ip);
    return struct {
        addr: ?Ip.Address = null,
        port: u16 = 0,
    };
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

const testing = std.testing;
const ipv4 = @import("ipv4.zig");

test "Cidr(ipv4) basic containment" {
    const IpCidr = Cidr(ipv4);
    const cidr = IpCidr{ .address = .{ 192, 168, 1, 10 }, .prefix_len = 24 };
    try testing.expect(cidr.contains(.{ 192, 168, 1, 0 }));
    try testing.expect(cidr.contains(.{ 192, 168, 1, 255 }));
    try testing.expect(!cidr.contains(.{ 192, 168, 0, 0 }));
    try testing.expect(!cidr.contains(.{ 192, 168, 2, 0 }));
}

test "Cidr(ipv4) prefix_len 0 contains all" {
    const IpCidr = Cidr(ipv4);
    const cidr = IpCidr{ .address = .{ 0, 0, 0, 0 }, .prefix_len = 0 };
    try testing.expect(cidr.contains(.{ 127, 0, 0, 1 }));
    try testing.expect(cidr.contains(.{ 255, 255, 255, 255 }));
}

test "Cidr(ipv4) broadcast and networkAddr" {
    const IpCidr = Cidr(ipv4);
    const cidr = IpCidr{ .address = .{ 192, 168, 1, 10 }, .prefix_len = 24 };
    try testing.expectEqual(ipv4.Address{ 192, 168, 1, 0 }, cidr.networkAddr());
    try testing.expectEqual(ipv4.Address{ 192, 168, 1, 255 }, cidr.broadcast().?);
}

test "Endpoint and ListenEndpoint basic usage" {
    const Ep = Endpoint(ipv4);
    const ep = Ep{ .addr = .{ 10, 0, 0, 1 }, .port = 80 };
    try testing.expectEqual(@as(u16, 80), ep.port);

    const LEp = ListenEndpoint(ipv4);
    const lep = LEp{ .port = 443 };
    try testing.expectEqual(@as(?ipv4.Address, null), lep.addr);
}
