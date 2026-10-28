//! Assurance manifests: the governance layer (vector H).
//!
//! Every module declares `pub const assurance = .{ ... }` classifying each of
//! its public runtime declarations, and calls `requireAssurance(@This(), floor)`
//! in a `comptime` block. A new public function cannot be added without
//! saying how much assurance it carries.
//!
//! What a manifest entry may be, by kind of `pub` declaration:
//!
//!   pub fn f(...) R           `.f = .tested`  (any `Level`, at or above the floor)
//!   pub fn T(comptime ...) type   `.T = zv.governed(T(u8))`  (see below)
//!   pub const X = struct { pub fn m() void {} }
//!                             `.X = .{ .m = .tested }`  (nested manifest), or
//!                             `.X = .external` if the type is not ours
//!   pub const Y = zv.Ranged(0, 9) / @import("other.zig")
//!                             nothing: a type with its own `assurance` is
//!                             checked against that manifest, recursively
//!   pub const n = 42, pub const E = error{...}   nothing: not runtime code
//!
//! Type constructors are not classified by level because their methods only
//! exist once instantiated. `zv.governed(T(u8))` names a witness instantiation
//! that the walk audits like any other type; bare `.governed` only records the
//! unchecked promise (and is counted as `unwitnessed`) that the returned
//! type carries its own `pub const assurance` and gates itself with
//! `comptime requireAssurance(@This(), floor)`; reviewers grep for it.

const std = @import("std");

pub const Level = enum(u8) {
    /// Reviewed by a code owner; no machine-checked contract. Must be rare.
    trusted = 0,
    /// Covered by tests / laws only.
    tested = 1,
    /// Contracts present and checked at runtime in safe builds.
    checked = 2,
    /// Contracts discharged statically by zvc. CI fails if zvc cannot prove it.
    verified = 3,
};

/// How many declarations landed in each bucket. `governed` and `external` are
/// not levels: they count type constructors and foreign types respectively.
pub const Counts = struct {
    verified: usize = 0,
    checked: usize = 0,
    tested: usize = 0,
    trusted: usize = 0,
    /// Type constructors with a witness instantiation, audited recursively.
    governed: usize = 0,
    /// Type constructors promised governed but not witnessed. Ratchet to zero.
    unwitnessed: usize = 0,
    external: usize = 0,

    /// Classified functions (those that carry a `Level`).
    pub fn fns(c: Counts) usize {
        return c.verified + c.checked + c.tested + c.trusted;
    }

    pub fn add(a: Counts, b: Counts) Counts {
        var sum = a;
        inline for (@typeInfo(Counts).@"struct".field_names) |name| @field(sum, name) += @field(b, name);
        return sum;
    }
};

/// Manifest entry for a type constructor, with a witness instantiation the
/// walk audits like any other type: `.RingBuffer = zv.governed(RingBuffer(u8))`.
/// Bare `.governed` is still accepted but reported as `unwitnessed`.
pub fn governed(comptime witness: type) Governed {
    return .{ .witness = witness };
}

pub const Governed = struct { witness: type };

pub const Audit = struct {
    counts: Counts = .{},
    /// Empty when the module satisfies the manifest rules; otherwise the
    /// first violation, phrased as the compile error `requireAssurance` raises.
    problem: []const u8 = "",
};

/// Enforce at compile time that `M` (and every type reachable through its
/// `pub` declarations) is fully classified at or above `floor`.
pub fn requireAssurance(comptime M: type, comptime floor: Level) void {
    comptime {
        const a = audit(M, floor);
        if (a.problem.len != 0) @compileError(a.problem);
    }
}

/// Per-bucket counts for `M`. Never fails: a module with problems reports
/// whatever it could classify. Use `audit` to see the problem.
pub fn assuranceCounts(comptime M: type) Counts {
    return comptime audit(M, .trusted).counts;
}

/// Non-failing form of `requireAssurance`, used by the report.
pub fn audit(comptime M: type, comptime floor: Level) Audit {
    return comptime blk: {
        if (!@hasDecl(M, "assurance"))
            break :blk .{ .problem = "zv: " ++ @typeName(M) ++ " has no `pub const assurance` manifest. " ++
                "Add `pub const assurance = .{ .some_fn = .tested };` listing every pub fn, then " ++
                "`comptime { zv.requireAssurance(@This(), .tested); }`" };
        const w = walk(M, M.assurance, floor, &.{});
        break :blk .{ .counts = w.counts, .problem = w.problem };
    };
}

const Walk = struct {
    counts: Counts = .{},
    problem: []const u8 = "",
    /// Types already visited, so aliases and cycles are counted once.
    seen: []const type = &.{},
};

const Entry = union(enum) { level: Level, governed, witnessed: type, external, nested, bad: []const u8 };

fn entryOf(comptime v: anytype) Entry {
    const V = @TypeOf(v);
    if (V == Level) return .{ .level = v };
    if (V == Governed) return .{ .witnessed = v.witness };
    if (V == @TypeOf(.enum_literal)) {
        const tag = @tagName(v);
        if (std.meta.stringToEnum(Level, tag)) |level| return .{ .level = level };
        if (std.mem.eql(u8, tag, "governed")) return .governed;
        if (std.mem.eql(u8, tag, "external")) return .external;
        return .{ .bad = "`." ++ tag ++ "` is not an assurance level; use .verified, .checked, .tested, .trusted, .governed or .external" };
    }
    if (@typeInfo(V) == .@"struct") return .nested;
    return .{ .bad = "entries must be a level literal such as `.tested` or a nested `.{ ... }` manifest, not " ++ @typeName(V) };
}

fn isContainer(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => true,
        else => false,
    };
}

fn hasFns(comptime T: type) bool {
    for (std.meta.declarations(T)) |name| {
        if (@typeInfo(@TypeOf(@field(T, name))) == .@"fn") return true;
    }
    return false;
}

fn failed(comptime w: Walk, comptime msg: []const u8) Walk {
    var out = w;
    out.problem = "zv: " ++ msg;
    return out;
}

fn contains(comptime haystack: []const type, comptime T: type) bool {
    for (haystack) |h| if (h == T) return true;
    return false;
}

fn walk(comptime T: type, comptime manifest: anytype, comptime floor: Level, comptime seen: []const type) Walk {
    @setEvalBranchQuota(1_000_000);
    var w: Walk = .{ .seen = seen ++ [_]type{T} };
    const where = @typeName(T);
    const Manifest = @TypeOf(manifest);
    if (@typeInfo(Manifest) != .@"struct")
        return failed(w, "`assurance` of " ++ where ++ " must be an anonymous struct literal like `.{ .f = .tested }`");

    for (@typeInfo(Manifest).@"struct".field_names) |key| {
        if (!@hasDecl(T, key))
            return failed(w, "assurance manifest of " ++ where ++ " names `" ++ key ++ "`, which is not a pub decl. " ++
                "Remove the entry (or restore the declaration).");
    }

    for (std.meta.declarations(T)) |name| {
        if (std.mem.eql(u8, name, "assurance")) continue;
        const D = @TypeOf(@field(T, name));
        const has_entry = @hasField(Manifest, name);

        if (@typeInfo(D) == .@"fn") {
            const makes_type = @typeInfo(D).@"fn".return_type == type;
            if (!has_entry)
                return failed(w, "pub fn `" ++ name ++ "` in " ++ where ++ " is missing from its assurance manifest. " ++
                    "Add `." ++ name ++ " = " ++ (if (makes_type) "zv.governed(" ++ name ++ "(...))" else ".tested") ++ "` (or higher) to `pub const assurance`.");
            switch (entryOf(@field(manifest, name))) {
                .level => |level| {
                    if (makes_type)
                        return failed(w, "`" ++ name ++ "` in " ++ where ++ " returns a type, so it has no level of its own. " ++
                            "Mark it `." ++ name ++ " = zv.governed(" ++ name ++ "(...))` (or bare `.governed`) and give the returned type its own `pub const assurance` " ++
                            "plus `comptime { zv.requireAssurance(@This(), floor); }`.");
                    if (@backingInt(level) < @backingInt(floor))
                        return failed(w, "`" ++ name ++ "` is ." ++ @tagName(level) ++ ", below this module's floor ." ++ @tagName(floor) ++
                            ". Raise it (add tests or contracts); lowering a floor needs a code owner.");
                    switch (level) {
                        inline else => |l| @field(w.counts, @tagName(l)) += 1,
                    }
                },
                .governed => {
                    if (!makes_type)
                        return failed(w, "`" ++ name ++ "` in " ++ where ++ " does not return a type, so `.governed` does not apply. " ++
                            "Give it a level such as `.tested`.");
                    w.counts.unwitnessed += 1;
                },
                .witnessed => |W| {
                    if (!makes_type)
                        return failed(w, "`" ++ name ++ "` in " ++ where ++ " does not return a type, so `zv.governed(...)` does not apply. " ++
                            "Give it a level such as `.tested`.");
                    if (!isContainer(W) or !@hasDecl(W, "assurance"))
                        return failed(w, "the witness `" ++ @typeName(W) ++ "` for `" ++ name ++ "` in " ++ where ++ " has no `pub const assurance` manifest. " ++
                            "Add one inside the returned type, plus `comptime { zv.requireAssurance(@This(), floor); }`.");
                    w.counts.governed += 1;
                    if (!contains(w.seen, W)) w = merge(w, walk(W, W.assurance, floor, w.seen));
                    if (w.problem.len != 0) return w;
                },
                .external => w.counts.external += 1,
                .nested => return failed(w, "`" ++ name ++ "` in " ++ where ++ " is a function; its entry must be a level, not a nested manifest."),
                .bad => |msg| return failed(w, "manifest entry `" ++ name ++ "` of " ++ where ++ ": " ++ msg),
            }
        } else if (D == type) {
            const C = @field(T, name);
            if (!isContainer(C) or contains(w.seen, C)) {
                if (has_entry)
                    return failed(w, "manifest entry `" ++ name ++ "` of " ++ where ++ " does not apply: it is not a container type " ++
                        "with functions of its own (or is an alias of one already classified). Remove it.");
                continue;
            }
            if (@hasDecl(C, "assurance")) {
                if (has_entry)
                    return failed(w, "`" ++ name ++ "` carries its own assurance manifest; remove `." ++ name ++ "` from " ++ where ++ "'s.");
                const sub = walk(C, C.assurance, floor, w.seen);
                w = merge(w, sub);
            } else if (has_entry) {
                switch (entryOf(@field(manifest, name))) {
                    .external => w.counts.external += 1,
                    .nested => w = merge(w, walk(C, @field(manifest, name), floor, w.seen)),
                    .bad => |msg| return failed(w, "manifest entry `" ++ name ++ "` of " ++ where ++ ": " ++ msg),
                    else => return failed(w, "`" ++ name ++ "` in " ++ where ++ " is a type. Its entry must be `.external` (not ours) " ++
                        "or a nested manifest like `.{ .method = .tested }`."),
                }
            } else if (hasFns(C)) {
                return failed(w, "pub type `" ++ name ++ "` in " ++ where ++ " has pub functions but is not classified. " ++
                    "Add `." ++ name ++ " = .{ .method_name = .tested, ... }` to `pub const assurance`, give the type its own " ++
                    "`pub const assurance`, or mark a foreign type `." ++ name ++ " = .external`.");
            } else {
                w = merge(w, walk(C, .{}, floor, w.seen));
            }
            if (w.problem.len != 0) return w;
        } else if (has_entry) {
            return failed(w, "manifest entry `" ++ name ++ "` of " ++ where ++ " names a constant or variable, not a function or type. Remove it.");
        }
    }
    return w;
}

fn merge(comptime parent: Walk, comptime child: Walk) Walk {
    return .{
        .counts = parent.counts.add(child.counts),
        .problem = child.problem,
        .seen = child.seen,
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

test "counts a flat module" {
    const M = struct {
        pub const assurance = .{ .a = .verified, .b = .tested, .c = .tested };
        pub fn a() void {}
        pub fn b() void {}
        pub fn c() void {}
    };
    const c = assuranceCounts(M);
    try std.testing.expectEqual(@as(usize, 3), c.fns());
    try std.testing.expectEqual(@as(usize, 1), c.verified);
    try std.testing.expectEqual(@as(usize, 2), c.tested);
    comptime requireAssurance(M, .tested);
}

test "type constructors are governed, instances are walked" {
    const M = struct {
        pub const assurance = .{ .Box = .governed, .Boxed = .{ .get = .checked }, .gen = .tested };
        pub fn Box(comptime T: type) type {
            return struct {
                v: T,
                pub const assurance = .{ .get = .tested };
                pub fn get(b: @This()) T {
                    return b.v;
                }
            };
        }
        pub fn gen(comptime T: type, x: T) T {
            return x;
        }
        pub const Boxed = struct {
            pub fn get() void {}
        };
        pub const Instance = Box(u8);
        pub const Mod = struct {
            pub const Inner = struct {};
        };
    };
    const c = assuranceCounts(M);
    try std.testing.expectEqual(@as(usize, 1), c.unwitnessed);
    try std.testing.expectEqual(@as(usize, 1), c.checked);
    try std.testing.expectEqual(@as(usize, 2), c.tested); // gen and Instance.get
}

test "a witness instantiation is audited and counted" {
    const M = struct {
        pub const assurance = .{ .Box = governed(Box(u8)) };
        pub fn Box(comptime T: type) type {
            return struct {
                v: T,
                pub const assurance = .{ .get = .checked };
                pub fn get(b: @This()) T {
                    return b.v;
                }
            };
        }
    };
    const c = assuranceCounts(M);
    try std.testing.expectEqual(@as(usize, 1), c.governed);
    try std.testing.expectEqual(@as(usize, 0), c.unwitnessed);
    try std.testing.expectEqual(@as(usize, 1), c.checked);
}

test "audit reports problems without failing the build" {
    const Missing = struct {
        pub const assurance = .{};
        pub fn f() void {}
    };
    const a = audit(Missing, .tested);
    try std.testing.expect(std.mem.indexOf(u8, a.problem, "missing from its assurance manifest") != null);
    const Bare = struct {};
    try std.testing.expect(std.mem.indexOf(u8, audit(Bare, .tested).problem, "no `pub const assurance`") != null);
}
