#!/usr/bin/env bash
#
# Binary Size Comparison: zmoltcp (Zig) vs smoltcp (Rust)
#
# Builds both libraries as static objects for aarch64-freestanding-none
# with size-optimized settings, then compares .text/.data/.bss sections.
#
# Prerequisites:
#   rustup target add aarch64-unknown-none
#   zig (0.15.x), cargo, llvm-size on PATH

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$SCRIPT_DIR/out"
ZIG_DIR="$SCRIPT_DIR/zmoltcp"
RUST_DIR="$SCRIPT_DIR/smoltcp-bench"

ZIG_TARGET="aarch64-freestanding-none"
RUST_TARGET="aarch64-unknown-none"

SCENARIOS="a b c d e"

mkdir -p "$OUT_DIR"

# ── Zig builds ──────────────────────────────────────────────────────────

echo "=== Building zmoltcp scenarios (Zig) ==="

for s in $SCENARIOS; do
    echo "  scenario_${s}..."
    zig build-obj \
        -target "$ZIG_TARGET" \
        -OReleaseSmall \
        --dep zmoltcp \
        -Mroot="$ZIG_DIR/scenario_${s}.zig" \
        -Mzmoltcp="$ROOT_DIR/src/root.zig" \
        --cache-dir "$OUT_DIR/.zig-cache" \
        -femit-bin="$OUT_DIR/zmoltcp_${s}.o" \
        2>&1 | tail -1
done

# ── Rust builds ─────────────────────────────────────────────────────────

echo ""
echo "=== Building smoltcp scenarios (Rust) ==="

for s in $SCENARIOS; do
    echo "  scenario_${s}..."
    # Clean between scenarios to prevent Cargo feature unification
    cargo clean --manifest-path "$RUST_DIR/Cargo.toml" --target-dir "$OUT_DIR/rust-target" 2>/dev/null || true
    cargo build \
        --manifest-path "$RUST_DIR/Cargo.toml" \
        --release \
        --features "scenario-${s}" \
        --target "$RUST_TARGET" \
        --target-dir "$OUT_DIR/rust-target" \
        2>&1 | tail -1
    # Copy the .a before cleaning for next scenario
    cp "$OUT_DIR/rust-target/${RUST_TARGET}/release/libsmoltcp_bench.a" \
       "$OUT_DIR/smoltcp_${s}.a"
done

# ── Measurement ─────────────────────────────────────────────────────────

echo ""
echo "=== Section sizes ==="
echo ""

# Determine the llvm-size binary
LLVM_SIZE="llvm-size"
if ! command -v "$LLVM_SIZE" >/dev/null 2>&1; then
    # Try versioned names
    for v in 19 18 17 16 15 14; do
        if command -v "llvm-size-${v}" >/dev/null 2>&1; then
            LLVM_SIZE="llvm-size-${v}"
            break
        fi
    done
fi

# Also accept plain `size` as fallback
if ! command -v "$LLVM_SIZE" >/dev/null 2>&1; then
    if command -v size >/dev/null 2>&1; then
        LLVM_SIZE="size"
    else
        echo "ERROR: neither llvm-size nor size found on PATH" >&2
        exit 1
    fi
fi

# Collect sizes into arrays
declare -A Z_TEXT Z_DATA Z_BSS R_TEXT R_DATA R_BSS

for s in $SCENARIOS; do
    zig_obj="$OUT_DIR/zmoltcp_${s}.o"
    rust_lib="$OUT_DIR/smoltcp_${s}.a"

    # Zig: single .o file -- use totals (only one member)
    read -r t d b _ <<< "$("$LLVM_SIZE" -B "$zig_obj" | tail -1)"
    Z_TEXT[$s]=$t; Z_DATA[$s]=$d; Z_BSS[$s]=$b

    # Rust: .a archive -- extract only the smoltcp_bench object, skip compiler_builtins
    read -r t d b _ <<< "$("$LLVM_SIZE" -B "$rust_lib" | grep 'smoltcp_bench' | awk '{t+=$1; d+=$2; b+=$3} END {print t, d, b}')"
    R_TEXT[$s]=$t; R_DATA[$s]=$d; R_BSS[$s]=$b
done

# ── Output table ────────────────────────────────────────────────────────

LABELS_A="A: TCP/IPv4"
LABELS_B="B: TCP+UDP+ICMP"
LABELS_C="C: Full IPv4"
LABELS_D="D: Dual-stack"
LABELS_E="E: Wire-only"

printf "\n"
printf "%-18s  %10s  %10s  %10s  %10s  %8s\n" \
    "Scenario" "zmoltcp" "smoltcp" "Delta" "Ratio" "Section"
printf "%-18s  %10s  %10s  %10s  %10s  %8s\n" \
    "--------" "-------" "-------" "-----" "-----" "-------"

for s in $SCENARIOS; do
    eval "label=\$LABELS_$(echo $s | tr a-z A-Z)"

    zt=${Z_TEXT[$s]}; rt=${R_TEXT[$s]}
    zd=${Z_DATA[$s]}; rd=${R_DATA[$s]}
    zb=${Z_BSS[$s]}; rb=${R_BSS[$s]}

    dt=$((zt - rt))
    dd=$((zd - rd))
    db=$((zb - rb))

    # Ratio (zmoltcp / smoltcp), avoid div-by-zero
    if [ "$rt" -gt 0 ]; then
        ratio_t=$(awk "BEGIN { printf \"%.2fx\", $zt / $rt }")
    else
        ratio_t="n/a"
    fi

    printf "%-18s  %10d  %10d  %+10d  %10s  %8s\n" "$label" "$zt" "$rt" "$dt" "$ratio_t" ".text"
    printf "%-18s  %10d  %10d  %+10d  %10s  %8s\n" "" "$zd" "$rd" "$dd" "" ".data"
    printf "%-18s  %10d  %10d  %+10d  %10s  %8s\n" "" "$zb" "$rb" "$db" "" ".bss"
    printf "\n"
done

# Total .text summary
zt_total=0; rt_total=0
for s in $SCENARIOS; do
    zt_total=$((zt_total + Z_TEXT[$s]))
    rt_total=$((rt_total + R_TEXT[$s]))
done
dt_total=$((zt_total - rt_total))
if [ "$rt_total" -gt 0 ]; then
    ratio_total=$(awk "BEGIN { printf \"%.2fx\", $zt_total / $rt_total }")
else
    ratio_total="n/a"
fi

printf "%-18s  %10d  %10d  %+10d  %10s  %8s\n" \
    "TOTAL .text" "$zt_total" "$rt_total" "$dt_total" "$ratio_total" ""

echo ""
echo "Build settings: Zig=ReleaseSmall(-Oz) Rust=opt-level=z+LTO"
echo "Target: aarch64 freestanding (no std, no alloc, no debug info)"
