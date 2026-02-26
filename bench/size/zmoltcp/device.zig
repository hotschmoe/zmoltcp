const zmoltcp = @import("zmoltcp");

pub const BenchDevice = struct {
    pub const medium: zmoltcp.iface.Medium = .ethernet;

    pub fn receive(_: *BenchDevice) ?[]const u8 {
        return null;
    }

    pub fn transmit(_: *BenchDevice, _: []const u8) void {}
};
