//! Compiled (never run) for freestanding targets by `zig build freestanding`.
//! Touches every runtime part of zv so an OS dependency cannot sneak in.

const zv = @import("zv");

const Percent = zv.Ranged(0, 100);
const Slots = zv.Pool(u32, 4, struct {});
const Token = zv.Linear(u32);

pub const assurance = .{ .smoke = .checked, .clamp = .verified };

comptime {
    zv.requireAssurance(@This(), .checked);
}

pub fn clamp(x: u32, cap: u32) u32 {
    zv.requires(cap > 0);
    const r = @min(x, cap);
    return zv.ensures(r, r <= cap);
}

pub fn smoke(x: u32) u32 {
    var pool: Slots = .{};
    const h = pool.alloc(x) catch return 0;
    pool.get(h).* += 1;

    const pct = Percent.from(x % 101) catch return 0;
    const sum = zv.add(pct, Percent.lit(1));

    const token: Token = .init(sum.get());
    var pinned: zv.PinCheck = .{};
    pinned.pin();
    pinned.check();
    if (zv.ghost) zv.assume(true);

    const v = pool.get(h).* + token.consume() + clamp(x, 10);
    _ = pool.isLive(h);
    pool.free(h);
    return v;
}

export fn zv_freestanding_smoke(x: u32) u32 {
    return smoke(x);
}
