<!-- BEGIN:header -->
# CLAUDE.md

we love you, Claude! do your best today
<!-- END:header -->

<!-- BEGIN:rule-1-no-delete -->
## RULE 1 - NO DELETIONS (ARCHIVE INSTEAD)

You may NOT delete any file or directory. Instead, move deprecated files to `.archive/`.

**When you identify files that should be removed:**
1. Create `.archive/` directory if it doesn't exist
2. Move the file: `mv path/to/file .archive/`
3. Notify me: "Moved `path/to/file` to `.archive/` - deprecated because [reason]"

**Rules:**
- This applies to ALL files, including ones you just created (tests, tmp files, scripts, etc.)
- You do not get to decide that something is "safe" to delete
- The `.archive/` directory is gitignored - I will review and permanently delete when ready
- If `.archive/` doesn't exist and you can't create it, ask me before proceeding

**Only I can run actual delete commands** (`rm`, `git clean`, etc.) after reviewing `.archive/`.
<!-- END:rule-1-no-delete -->

<!-- BEGIN:irreversible-actions -->
### IRREVERSIBLE GIT & FILESYSTEM ACTIONS

Absolutely forbidden unless I give the **exact command and explicit approval** in the same message:

- `git reset --hard`
- `git clean -fd`
- `rm -rf`
- Any command that can delete or overwrite code/data

Rules:

1. If you are not 100% sure what a command will delete, do not propose or run it. Ask first.
2. Prefer safe tools: `git status`, `git diff`, `git stash`, copying to backups, etc.
3. After approval, restate the command verbatim, list what it will affect, and wait for confirmation.
4. When a destructive command is run, record in your response:
   - The exact user text authorizing it
   - The command run
   - When you ran it

If that audit trail is missing, then you must act as if the operation never happened.
<!-- END:irreversible-actions -->

<!-- BEGIN:code-discipline -->
### Code Editing Discipline

- Do **not** run scripts that bulk-modify code (codemods, invented one-off scripts, giant `sed`/regex refactors).
- Large mechanical changes: break into smaller, explicit edits and review diffs.
- Subtle/complex changes: edit by hand, file-by-file, with careful reasoning.
- **NO EMOJIS** - do not use emojis or non-textual characters.
- ASCII diagrams are encouraged for visualizing flows.
- Keep in-line comments to a minimum. Use external documentation for complex logic.
- In-line commentary should be value-add, concise, and focused on info not easily gleaned from the code.
<!-- END:code-discipline -->

<!-- BEGIN:no-legacy -->
### No Legacy Code - Full Migrations Only

We optimize for clean architecture, not backwards compatibility. **When we refactor, we fully migrate.**

- No "compat shims", "v2" file clones, or deprecation wrappers
- When changing behavior, migrate ALL callers and remove old code **in the same commit**
- No `_legacy` suffixes, no `_old` prefixes, no "will remove later" comments
- New files are only for genuinely new domains that don't fit existing modules
- The bar for adding files is very high

**Rationale**: Legacy compatibility code creates technical debt that compounds. A clean break is always better than a gradual migration that never completes.
<!-- END:no-legacy -->

<!-- BEGIN:dev-philosophy -->
## Development Philosophy

**Make it work, make it right, make it fast** - in that order.

**This codebase will outlive you** - every shortcut becomes someone else's burden. Patterns you establish will be copied. Corners you cut will be cut again.

**Fight entropy** - leave the codebase better than you found it.

**Inspiration vs. Recreation** - take the opportunity to explore unconventional or new ways to accomplish tasks. Do not be afraid to challenge assumptions or propose new ideas. BUT we also do not want to reinvent the wheel for the sake of it. If there is a well-established pattern or library take inspiration from it and make it your own. (or suggest it for inclusion in the codebase)
<!-- END:dev-philosophy -->

<!-- BEGIN:testing-philosophy -->
## Testing Philosophy: Diagnostics, Not Verdicts

**Tests are diagnostic tools, not success criteria.** A passing test suite does not mean the code is good. A failing test does not mean the code is wrong.

**When a test fails, ask three questions in order:**
1. Is the test itself correct and valuable?
2. Does the test align with our current design vision?
3. Is the code actually broken?

Only if all three answers are "yes" should you fix the code.

**Why this matters:**
- Tests encode assumptions. Assumptions can be wrong or outdated.
- Changing code to pass a bad test makes the codebase worse, not better.
- Evolving projects explore new territory - legacy testing assumptions don't always apply.

**What tests ARE good for:**
- **Regression detection**: Did a refactor break dependent modules? Did API changes break integrations?
- **Sanity checks**: Does initialization complete? Do core operations succeed? Does the happy path work?
- **Behavior documentation**: Tests show what the code currently does, not necessarily what it should do.

**What tests are NOT:**
- A definition of correctness
- A measure of code quality
- Something to "make pass" at all costs
- A specification to code against

**The real success metric**: Does the code further our project's vision and goals?

**Don't test the type system**: When writing tests, do not add cases for invariants or errors already enforced by the static type system (e.g., type mismatches, missing required arguments, nullability violations, return type correctness, enum exhaustiveness). The type checker handles these at compile time. Test solely runtime behaviors, business rules, algorithmic logic, and edge cases using only valid typed inputs.
<!-- END:testing-philosophy -->

<!-- BEGIN:footer -->
---

we love you, Claude! do your best today
<!-- END:footer -->

---

## Project-Specific Content - zmoltcp

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
- **Poll model**: No callbacks, no timers. `poll(timestamp, device)` drives
  I/O (returns bool). `pollAt()` returns next event time. Caller owns the
  event loop.
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
