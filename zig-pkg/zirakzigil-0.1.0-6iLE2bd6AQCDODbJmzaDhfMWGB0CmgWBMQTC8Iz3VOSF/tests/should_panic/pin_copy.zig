// A self-referential struct is returned/copied by value: its internal pointer
// now points at the old location. PinCheck notices on the next method call.
const zv = @import("zv");

const Node = struct {
    pin: zv.PinCheck = .{},
    self_ref: ?*Node = null,
    fn touch(n: *Node) void {
        n.pin.check();
    }
};

pub fn main() void {
    var original: Node = .{};
    original.pin.pin();
    original.self_ref = &original;
    var moved = original; // innocent-looking copy
    moved.touch(); // must panic
}
