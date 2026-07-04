# zmoltcp Fuzzing

zmoltcp fuzzing covers packet-facing parsers, public stack ingress, fragment
reassembly, storage buffers, socket state machines, RPL state, and PHY
middleware. Shared harness code lives in `src/fuzz.zig`; each active fuzz
target has a single-test entrypoint under `src/fuzz/` so `zig build fuzz-dns`,
`zig build fuzz-stack-ingress`, and the other build steps fuzz deterministic
surfaces instead of relying on runner target selection.

## Policy

- Any new externally influenced parser or packet ingress path needs malformed
  input coverage in the same change.
- Any fuzz failure must become a deterministic regression test before or with
  the fix.
- Harnesses use bounded loops and fixed scratch buffers. Do not add production
  heap allocation to make fuzzing easier.
- Operation-stream fuzzers should call valid public APIs unless the change is
  deliberately hardening that API boundary.

## Local Commands

Run the deterministic suite first:

```bash
mise run test
```

Run a bounded native fuzz pass:

```bash
mise run fuzz
```

The `fuzz` task and CI both use `scripts/fuzz-smoke.sh`. By default it loops
over all P0 targets with fresh caches:

- `fuzz-dns`
- `fuzz-tcp-header`
- `fuzz-ip-header`
- `fuzz-ipv6-extension`
- `fuzz-stack-ingress`
- `fuzz-reassembly`

The smoke script treats Zig 0.16.0 saved-crash output as a failure even when
the build process exits zero. Override `FUZZ_SMOKE_TARGETS`,
`FUZZ_SMOKE_LIMIT`, `FUZZ_SMOKE_TIMEOUT`, or `FUZZ_SMOKE_WALL_TIMEOUT` for
focused local runs. `FUZZ_SMOKE_COVERAGE_RETRIES` controls how many
instrumented coverage attempts to make before fallback. CI uses smaller
per-target fuzz and retry limits than the local defaults because it is a
regression gate, not a campaign runner. The smoke script reuses one Zig cache
across targets for speed; if coverage corruption or a wall-clock timeout
occurs, it switches that target to a fresh cache and uses the CI-only
non-instrumented fallback when enabled.

Run lower-priority smoke groups explicitly:

```bash
mise run fuzz-p1
mise run fuzz-p2
mise run fuzz-all
```

Use a larger target-specific limit for local parser or ingress work when the
extra runtime is acceptable:

```bash
zig build fuzz-stack-ingress --fuzz=100K --test-timeout 2m --summary all
```

For longer campaigns with wall-clock caps and preserved logs/caches:

```bash
FUZZ_LONG_LIMIT=500K FUZZ_LONG_WALL_TIMEOUT=15m mise run fuzz-long
```

Keep PR and CI limits small enough that the step is a regression gate, not a
long campaign.

Run `mise run check` for the full local suite: tests, demos, bounded fuzz, and
the freestanding cross-compile check.

## Zig 0.16.0 Notes

Use the dedicated `fuzz-*` build steps rather than `zig build test --fuzz`.
Those steps build threaded test binaries and disable error tracing because the
Zig 0.16.0 fuzz runner needs concurrent input polling and fails to compile with
error traces enabled.

Each individual `fuzz-*` build step contains exactly one `testing.fuzz` test.
This keeps the report's target name meaningful and lets developers spend a
known budget on a specific parser, ingress path, or state machine. Treat output
containing `run test failure`, `terminated with signal`, `input saved to`,
`panic:`, or `failed with error` as a failed fuzz run even if the build process
exits zero.

On GitHub's Linux runners, Zig 0.16.0 can repeatedly fail native fuzzing with
`corrupted coverage file` before executing a target. CI retries that runner
artifact with fresh caches and then falls back to non-instrumented fuzz target
smoke so parser and state-machine fuzz tests still compile and run. Local
`mise run fuzz` does not enable that fallback; coverage corruption should stay
visible during development.

## Failure Flow

1. Reproduce the failure with the saved input from `.zig-cache/f/crash`.
2. Minimize the shape enough to understand the parser or state-machine bug.
3. Add a deterministic test in the module that owns the failed invariant.
4. Fix the code.
5. Rerun `zig build test` and the matching bounded fuzz command.

Do not commit `.zig-cache` artifacts.
