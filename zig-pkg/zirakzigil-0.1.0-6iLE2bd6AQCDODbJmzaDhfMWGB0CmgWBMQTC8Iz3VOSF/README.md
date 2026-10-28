# Zirakzigil

**A formalization layer for multi-contributor Zig.** Contracts, refinement types, ownership backstops and an SMT verifier, stacked on top of the stock Zig compiler with no fork and no new syntax.

> *Zirakzigil* is the dwarven name for the Silvertine. Durin's Endless Stair climbs from the deepest level of Moria to the tower on its summit. This project is a stair of that kind, a stack of layers where each one checks what the layer below cannot.

## The problem

**In Rust, a weaker contributor does less damage than in Zig.** Rust's borrow checker and type system turn many ownership, aliasing and lifetime mistakes into compile errors at the line where they were made. A reviewer can approve a diff by reading the diff and the signatures it touches, because the compiler has already checked the rest. Bugs and slow drift away from the original design are stopped before merge, however many people touch the code.

Zig gives explicit *mechanics* (allocators, control flow, error handling) but not explicit *invariants*. Who frees this slice? Is this pointer still valid after `append`? Is it legal to copy this struct? Which handle belongs to which pool? In Zig those answers live in the original author's head. The language effectively assumes **one person who understands the whole program**, and it works well when that holds. It degrades when the code is shared among people who each understand only part of it.

**That is the situation we expect.** Projects will be worked on by many contributors, and many of them will be **agents**: some frontier LLMs, some small models running locally, with very different levels of skill. An agent that cannot hold the whole program in context is exactly the "contributor who only understands part of the code" that Zig handles badly. Experience so far with agent-driven development points the same way. Agents stay on track when a checker tells them, precisely and immediately, that they are wrong. Languages with strong static checking or formal verification keep agents in their lane; languages that rely on the author's discipline let them drift.

**Zirakzigil's goal** is to give Zig that guard rail without forking the language:

1. Move invariants out of authors' heads into **signatures, types and contracts** a machine checks at every call site.
2. Make every function's **level of assurance explicit**, and make it a compile error to lower it quietly.
3. Let the **least trusted contributor** (a junior, a small local model) satisfy a checker owned by the **most trusted** (the maintainers), with errors reported where the mistake was made.

## The stack

| Layer | What it catches | Status |
| --- | --- | --- |
| **A. Contracts** `zv.requires` / `ensures` / `invariant` | Broken pre/postconditions, blamed on the side that broke them | Built |
| **B. Refinement and brand types** `zv.Ranged`, `zv.Pool(..., struct {})` | Overflow in ranged arithmetic, out-of-range values, cross-pool handle mixups, unsafe narrowing | Built |
| **C. Runtime ownership backstops** `zv.Linear`, generational handles, `zv.PinCheck` | Double consume, use-after-free via stale handle, copied self-referential structs, leaks | Built |
| **D. Static ownership checker** `zv-own` (over AIR) | The bugs in C, at compile time, plus region escapes and pointer invalidation | Designed |
| **E. Deductive verifier** `zvc` (Verus-style, Z3) | Functional correctness and absence of every safety panic | Spike, on a source subset |
| **F. C backend + CBMC** | Panic-freedom of bounded proof harnesses | C emission tested, checker not wired |
| **H. Governance** assurance manifest + laws | Silent erosion of guarantees by contributors | Built |

Every module declares how much assurance each public function carries, and the compiler enforces it:

```zig
pub const assurance = .{ .midpoint = .verified, .scale = .checked };
comptime { zv.requireAssurance(@This(), .checked); } // missing entry or downgrade = compile error

pub fn midpoint(lo: u32, hi: u32) u32 {
    zv.requires(lo <= hi);
    const mid = lo + (hi - lo) / 2;
    return zv.ensures(mid, lo <= mid and mid <= hi);
}
```

The same function is compiled normally, checked at runtime in safe builds (contracts vanish in `ReleaseFast`), and proved statically by `zvc`. The naive `(lo + hi) / 2` passes every small unit test; `zvc` rejects it with the counterexample `lo=1, hi=4294967295`.

The full rationale, the survey of prior art (Verus, Bend 2, SPARK, CN, Kani) and the detailed roadmap are in [`docs/design.md`](docs/design.md).

## Does it catch anything plain Zig misses?

Each negative test has a plain-Zig **control** in `tests/baseline/`: the same bug written without `zv`, run on the stock compiler. `./tools/run_baseline.sh` checks that each control behaves as documented below.

| Bug | Plain Zig 0.17 (Debug / ReleaseSafe / ReleaseFast) | With `zv` |
| --- | --- | --- |
| Copied withdrawal token deposited twice | silent / silent / silent: `total=160`, started with 100 | **panic** in safe builds |
| Stale handle after the slot is reused | silent / silent / silent: debits the new owner | **panic** in safe builds |
| Self-referential struct copied by value | silent / silent / silent: writes go to the original | **panic** in safe builds |
| Handle from one pool used on another | silent / silent / silent | **compile error** |
| Out-of-range value (`pct = 101`) | silent / silent / silent | **compile error** |
| Index type wider than the array | panic / panic / undefined behavior, and only on paths a test runs | **compile error** |
| Narrowing a value that may not fit | panic / panic / undefined behavior, via `@intCast` | **compile error** |
| `(lo + hi) / 2` midpoint overflow | panic / panic / undefined behavior, only if a test uses a huge input; small-input unit tests pass | **proved buggy** by `zvc`, with a counterexample and no test needed |
| Caller violates a documented precondition | panic / panic / undefined behavior; the panic points inside the callee | Same panic, but it **blames the caller** |
| Public function with no assurance level, or a downgraded one | not expressible | **compile error** |

To be clear about the weak spots: the runtime backstops (layer C) are switched off in `ReleaseFast`, exactly like Zig's own safety checks, so they only catch what tests and fuzzing actually run in a safe build. Moving those catches to compile time is the job of `zv-own` (Phase 3).

## Layout

| Path | What it is |
| --- | --- |
| `src/zv.zig` | The library root: contracts, `Ranged` integers, branded generational `Pool`, `Linear(T)`, `PinCheck`; re-exports the rest |
| `src/manifest.zig` | Assurance manifests: `requireAssurance`, `assuranceCounts`, `audit` |
| `src/laws.zig` | Executable laws: seeded `checkLaws` (with `replay`), fuzzer-driven `fuzzLaws`, `Bytes(max)` |
| `src/report.zig` | `zv.report`: per-module assurance table for `zig build assurance` |
| `examples/search.zig` | Functions with contracts. Two contain planted bugs (`midpointNaive`, `withdrawNaive`) |
| `examples/ledger.zig` | Accounts in a branded pool, money as linear tokens, laws checked as properties |
| `examples/assurance.zig` | The one-line-per-module opt-in to the assurance report |
| `tests/consumer/` | A downstream project depending on this package by path; built by `zig build test` |
| `tests/freestanding/` | Smoke object cross-compiled for aarch64 and riscv64 freestanding |
| `tests/should_panic/` | Contributor mistakes that must panic in safe builds |
| `tests/compile_fail/cases.txt` | Contributor mistakes that must be rejected at compile time |
| `tests/baseline/` | The same mistakes in plain Zig, showing what the stock compiler does with them |
| `tools/zvc.py` | Static verifier spike: proves `.verified` functions with Z3 |
| `tools/run_negative.sh` | Runs the should-panic and compile-fail suites |
| `tools/run_baseline.sh` | Runs the plain-Zig controls in three build modes |
| `docs/design.md` | Design document |
| `docs/adoption.md` | Consumer guide: dependency lines, manifest rules, report, laws and fuzzing |

## Running it

Requires **Zig 0.17.0** (pinned in `build.zig.zon`), and Python 3 with `z3-solver` for the verifier.

```sh
zig build test                          # unit, example and law tests, freestanding cross-compile, tests/consumer
zig build test -Doptimize=ReleaseFast   # contracts compile out
zig build test -Dghost=true             # ghost (verification-only) code compiled in
zig build assurance                     # per-module assurance table for the examples
zig build freestanding                  # zv for aarch64 / riscv64 freestanding, Debug and ReleaseSafe
zig build test --fuzz                   # laws under the real fuzzer (Linux/macOS only; not implemented on Windows)
./tools/run_negative.sh                 # 5 must-panic + 21 must-not-compile cases
./tools/run_baseline.sh                 # the same bugs in plain Zig (about 1.5 min)
pip install z3-solver
python3 tools/zvc.py examples/search.zig   # expect 4 verified, 2 rejected, exit code 1
```

To use `zv` from another project see [`docs/adoption.md`](docs/adoption.md): `b.dependency("zirakzigil", .{ .ghost = ghost }).module("zv")`, one `.{ "name", module }` line per module in the assurance report.

## Results (Zig 0.17.0, 2026-10-28)

| Check | Result |
| --- | --- |
| `zig build test` | 20/20 (unit, examples, consumer project, freestanding cross-compile) in Debug, ReleaseSafe, ReleaseFast and ReleaseSmall, each with and without `-Dghost=true` |
| Must panic: double consume, stale handle, pinned copy, violated precondition, parser law with an unguarded read | 5/5 |
| Must not compile: the original 6 plus 15 manifest rules (type constructors, methods, re-exports, foreign types, witnesses, typos, stale entries) | 21/21 |
| Plain-Zig controls | 9/9 behave as documented: 5 silent in every mode, 4 caught only at runtime in safe builds |
| `zvc examples/search.zig` | 6 functions in ~0.6 s: 4 verified, 2 planted bugs rejected with counterexamples |

The prototype was first built on Zig 0.16.0. Porting it to 0.17 took four mechanical changes: `**` array repetition became `@splat`, `StaticBitSet.initEmpty()` became `.empty`, `@typeInfo(T).@"struct"` exposes `decl_names` / `field_names` / `field_types` in place of `decls` / `fields`, and `@intFromEnum` became `@backingInt`. None of them touched the design. Only layers that read compiler internals (AIR) will need real rework per release.

### What `zvc` understands today

Integer and bool parameters, `[]const T` slices, `const`/`var`, assignment and `+= -= *=`, `if`/`else`, `while` with a leading `zv.invariant`, `return` with `zv.ensures`, `+ - * / %`, comparisons, `and`/`or`/`!`, `xs[i]`, `xs.len`, `@as` widening. Anything else is reported **UNPROVEN**, never silently accepted. Termination is not checked and calls are not yet modular.

## Limits, honestly

- `zvc` parses a source subset, not Zig's AIR. Generics, comptime-dependent code, calls, structs and pointers are out of scope for now.
- Ownership is enforced only at runtime. The static checker `zv-own` is designed but not built.
- The `Linear` ledger is a fixed 16K-slot global with no thread safety. It is fine for tests, not for production.

## Roadmap

Each phase ships value before the next one starts. Phases are ordered by dependency, not dated; each gate is the evidence that the next phase is worth building.

![Roadmap: Phase 0 to Phase 4 with exit gates, plus parallel track F](docs/img/roadmap.png)

| Phase | Scope | Exit gate |
| --- | --- | --- |
| **0. Adopt the comptime and runtime layers** (no fork) | `zv` contracts, `Ranged`, `Pool`, `Linear`; manifests; laws and fuzzing in CI | Every module has a manifest at floor `.tested` or higher |
| **1. AIR exporter** | One small compiler patch: per-function AIR as versioned JSON in ghost builds | Every function in a pilot codebase exports and round-trips |
| **2. `zvc` on AIR** | Port the spike: modular calls, structs, termination, ghost `Int` and `Seq` | Spike results reproduce from AIR, plus one real kernel verified |
| **3. `zv-own`** | Linearity, allocator regions, pointer invalidation, pinned types | Catches seeded ownership bugs at a false-positive rate the team accepts |
| **4. Verified core** | `PointsTo` permission tokens, a verified allocator, proof agents in CI | The core is `.verified` and the `.trusted` count is falling |
| **Parallel track F** | C backend plus CBMC proof harnesses | Needs no fork, so it can start any time |

Phase 1 is the one decision that commits the project to maintaining a pinned compiler patch.

## License

Public domain, via [The Unlicense](LICENSE). Do whatever you want with it.
