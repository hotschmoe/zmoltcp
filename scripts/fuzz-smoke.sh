#!/bin/bash
set -euo pipefail

DEFAULT_TARGETS=(
  fuzz-dns
  fuzz-tcp-header
  fuzz-ip-header
  fuzz-ipv6-extension
  fuzz-stack-ingress
  fuzz-reassembly
)

read -r -a TARGETS <<< "${FUZZ_SMOKE_TARGETS:-${DEFAULT_TARGETS[*]}}"
FUZZ_SMOKE_LIMIT="${FUZZ_SMOKE_LIMIT:-10K}"
FUZZ_SMOKE_TIMEOUT="${FUZZ_SMOKE_TIMEOUT:-30s}"
FUZZ_SMOKE_WALL_TIMEOUT="${FUZZ_SMOKE_WALL_TIMEOUT:-90s}"
FUZZ_SMOKE_REUSE_CACHE="${FUZZ_SMOKE_REUSE_CACHE:-1}"
FUZZ_SMOKE_COVERAGE_RETRIES="${FUZZ_SMOKE_COVERAGE_RETRIES:-3}"
FAILURE_RE='run test failure|terminated with signal|input saved to|panic:|failed with error'

TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN="$(command -v timeout)"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN="$(command -v gtimeout)"
fi

run_with_timeout() {
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "$FUZZ_SMOKE_WALL_TIMEOUT" "$@"
  else
    "$@"
  fi
}

SHARED_CACHE_DIR=""
SHARED_CACHE_BAD=0
if [ "$FUZZ_SMOKE_REUSE_CACHE" = "1" ]; then
  SHARED_CACHE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zmoltcp-fuzz-shared-cache.XXXXXX")"
  trap 'rm -rf "$SHARED_CACHE_DIR"' EXIT
fi

run_target() {
  local target="$1"

  for attempt in 1 2 3; do
    local log_file
    local cache_dir
    local cleanup_cache
    log_file="$(mktemp "${TMPDIR:-/tmp}/zmoltcp-${target}.XXXXXX")"
    if [ "$attempt" -eq 1 ] && [ "$FUZZ_SMOKE_REUSE_CACHE" = "1" ] && [ "$SHARED_CACHE_BAD" -eq 0 ]; then
      cache_dir="$SHARED_CACHE_DIR"
      cleanup_cache=0
    else
      cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/zmoltcp-${target}-cache.XXXXXX")"
      cleanup_cache=1
    fi

    export ZIG_LOCAL_CACHE_DIR="$cache_dir/local"
    export ZIG_GLOBAL_CACHE_DIR="$cache_dir/global"
    mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

    echo "fuzz smoke target: $target"
    set +e
    run_with_timeout zig build "$target" --fuzz="$FUZZ_SMOKE_LIMIT" --test-timeout "$FUZZ_SMOKE_TIMEOUT" --summary all 2>&1 | tee "$log_file"
    build_status=${PIPESTATUS[0]}
    set -e

    if [ "$build_status" -eq 0 ] && ! grep -Eq "$FAILURE_RE" "$log_file"; then
      rm -f "$log_file"
      if [ "$cleanup_cache" -eq 1 ]; then
        rm -rf "$cache_dir"
      fi
      return 0
    fi

    timed_out=0
    if [ -n "$TIMEOUT_BIN" ] && [ "$build_status" -eq 124 ]; then
      timed_out=1
      echo "$target hit wall-clock timeout $FUZZ_SMOKE_WALL_TIMEOUT" >&2
      if [ "$cleanup_cache" -eq 0 ]; then
        SHARED_CACHE_BAD=1
      fi
    fi

    if grep -q 'corrupted coverage file' "$log_file"; then
      if [ "$cleanup_cache" -eq 0 ]; then
        SHARED_CACHE_BAD=1
      fi
      if [ "$attempt" -lt "$FUZZ_SMOKE_COVERAGE_RETRIES" ]; then
        echo "$target hit Zig coverage cache corruption; retrying with a fresh cache" >&2
        rm -f "$log_file"
        if [ "$cleanup_cache" -eq 1 ]; then
          rm -rf "$cache_dir"
        fi
        continue
      fi

      if [ "${ZIG_FUZZ_ALLOW_COVERAGE_FALLBACK:-0}" = "1" ]; then
        echo "$target hit repeated Zig coverage cache corruption; running non-instrumented target smoke" >&2
        rm -f "$log_file"
        if [ "$cleanup_cache" -eq 1 ]; then
          rm -rf "$cache_dir"
        fi

        log_file="$(mktemp "${TMPDIR:-/tmp}/zmoltcp-${target}.XXXXXX")"
        cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/zmoltcp-${target}-cache.XXXXXX")"
        export ZIG_LOCAL_CACHE_DIR="$cache_dir/local"
        export ZIG_GLOBAL_CACHE_DIR="$cache_dir/global"
        mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

        set +e
        run_with_timeout zig build "$target" --summary all 2>&1 | tee "$log_file"
        fallback_status=${PIPESTATUS[0]}
        set -e
        if [ "$fallback_status" -eq 0 ] && ! grep -Eq "$FAILURE_RE" "$log_file"; then
          rm -f "$log_file"
          rm -rf "$cache_dir"
          return 0
        fi
      fi
    fi

    if [ "$timed_out" -eq 1 ] && [ "${ZIG_FUZZ_ALLOW_COVERAGE_FALLBACK:-0}" = "1" ]; then
      echo "$target timed out under Zig fuzz instrumentation; running non-instrumented target smoke" >&2
      rm -f "$log_file"
      if [ "$cleanup_cache" -eq 1 ]; then
        rm -rf "$cache_dir"
      fi

      log_file="$(mktemp "${TMPDIR:-/tmp}/zmoltcp-${target}.XXXXXX")"
      cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/zmoltcp-${target}-cache.XXXXXX")"
      export ZIG_LOCAL_CACHE_DIR="$cache_dir/local"
      export ZIG_GLOBAL_CACHE_DIR="$cache_dir/global"
      mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

      set +e
      run_with_timeout zig build "$target" --summary all 2>&1 | tee "$log_file"
      fallback_status=${PIPESTATUS[0]}
      set -e
      if [ "$fallback_status" -eq 0 ] && ! grep -Eq "$FAILURE_RE" "$log_file"; then
        rm -f "$log_file"
        rm -rf "$cache_dir"
        return 0
      fi
    fi

    if grep -Eq "$FAILURE_RE" "$log_file"; then
      echo "$target output contained failure markers" >&2
    fi
    echo "$target fuzz log preserved at $log_file" >&2
    echo "$target fuzz cache preserved at $cache_dir" >&2
    return 1
  done
}

for target in "${TARGETS[@]}"; do
  run_target "$target"
done
