# CLAUDE.md - zmoltcp

## What This Is

zmoltcp is a pure Zig TCP/IP stack for freestanding targets, architecturally
inspired by smoltcp (Rust no_std). It is a standalone library with no kernel
dependencies.

Primary consumer: the Laminae kernel (github.com/hotschmoe/laminae), where
zmoltcp replaces the C-based lwIP network stack.

## Build and Test

```bash
zig build test                                    # Run all tests (host-native)
zig build test -- --summary all                   # Verbose test output
zig build -Dtarget=aarch64-freestanding-none      # Cross-compile check
```

Zig version: 0.15.2

## Architecture

smoltcp is the reference. Not a line-by-line port -- we use smoltcp's design
patterns and test cases, implemented in idiomatic Zig.

```
src/
  wire/       Protocol wire formats (parse + serialize)
  socket/     Protocol state machines
  storage/    Ring buffers, TCP segment reassembler
  iface.zig   Network interface, packet routing
  stack.zig   Top-level poll loop
  root.zig    Library entry point
```

### Key Patterns

- **Repr/parse/emit**: Every protocol has a `Repr` struct (high-level),
  `parse()` (bytes -> Repr), and `emit()` (Repr -> bytes)
- **Zero allocation**: All buffers are caller-provided `[]u8` slices
- **Poll model**: No callbacks, no timers. `poll(timestamp)` returns next
  event time. Caller owns the event loop.
- **Tests inline with code**: Each module has its own test block at the bottom

### Reference Material

- `ref/smoltcp/` -- git submodule of smoltcp source (read-only reference)
- `tests/CONFORMANCE.md` -- tracks which smoltcp tests have been transliterated
- `SPEC.md` -- full conformance testing methodology

## Conventions

- No emojis in code or docs
- Tests tagged with smoltcp origin: `// [smoltcp:file:test_name]`
- Errors use Zig error unions, not sentinels or magic values
- Network byte order handled explicitly: parse reads big-endian from wire,
  Repr fields are in host order, emit writes big-endian to wire
- All wire format structs use manual byte indexing (not packed structs) to
  avoid alignment issues on freestanding targets

## File Ownership

- `src/` -- zmoltcp library source (what downstream projects import)
- `ref/smoltcp/` -- read-only reference, never modify
- `tests/CONFORMANCE.md` -- update when adding/completing tests
- `SPEC.md` -- update when methodology changes

## Do Not

- Add kernel-specific code (ICC, SHM, syscalls). That belongs in laminae.
- Use `std.os` or `std.net` -- this is a freestanding library
- Modify anything under `ref/smoltcp/`
- Add allocator dependencies -- all memory is caller-provided
