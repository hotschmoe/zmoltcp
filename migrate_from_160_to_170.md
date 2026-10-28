# Zig 0.16.0 to 0.17.0 migration notes (zmoltcp 0.2.0)

Changes required in this codebase; useful as a checklist for consumers.

- `**` array repetition removed. Use `@splat` with a known result type:
  `var buf: [64]u8 = .{0} ** 64;` becomes `var buf: [64]u8 = @splat(0);`.
  Struct elements: `[_]Entry{.{}} ** N` becomes `@splat(.{})` (or `@splat(.empty)`).
  Optional elements: `.{null} ** N` becomes `@splat(null)`.
  Untyped consts need a type: `const x = [_]u8{0xAA} ** 16;` becomes
  `const x: [16]u8 = @splat(0xAA);`.
- Repeated multi-element patterns (string `"abc" ** 100`): splat an array of
  arrays and `@ptrCast`:
  `const p: [100][3]u8 = @splat("abc".*); const s: *const [300]u8 = @ptrCast(&p);`
- `@enumFromInt` is now `@fromBackingInt`, `@intFromEnum` is now `@backingInt`
  (`zig fmt` rewrites both). The formatter emits `@fromBackingInt(@intCast(x))`;
  drop the `@intCast` when `x` already has the enum's backing type, and use a
  single `@truncate` for narrower backing types (`enum(u2)`, `enum(u3)`).
- `zig fmt` is stricter: binary operators need consistent spacing, one-line
  function bodies are expanded.
- The `error_tracing = false` fuzz workaround in `build.zig` was removed; a
  `-ffuzz -ferror-tracing` test build compiles on 0.17.0 (checked by
  cross-compiling to x86_64-linux; `--fuzz` itself is not implemented on Windows).
- `minimum_zig_version` is now 0.17.0 and the package version is 0.2.0.

No `@typeInfo`, `std.meta.fields`, or `StaticBitSet` uses existed in this codebase.
