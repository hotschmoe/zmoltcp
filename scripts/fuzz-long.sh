#!/bin/bash
set -euo pipefail

DEFAULT_TARGETS=(
  fuzz-dns
  fuzz-tcp-header
  fuzz-ip-header
  fuzz-ipv6-extension
  fuzz-stack-ingress
  fuzz-reassembly
  fuzz-protocol-parsers
  fuzz-rpl-state
  fuzz-storage-streams
  fuzz-socket-state
  fuzz-phy-middleware
)

read -r -a TARGETS <<< "${FUZZ_LONG_TARGETS:-${DEFAULT_TARGETS[*]}}"
FUZZ_LONG_LIMIT="${FUZZ_LONG_LIMIT:-500K}"
FUZZ_LONG_WALL_TIMEOUT="${FUZZ_LONG_WALL_TIMEOUT:-15m}"
FUZZ_LONG_TEST_TIMEOUT="${FUZZ_LONG_TEST_TIMEOUT:-5m}"
FUZZ_LONG_LOG_DIR="${FUZZ_LONG_LOG_DIR:-/tmp/zmoltcp-fuzz-logs}"
FAILURE_RE='run test failure|terminated with signal|input saved to|panic:|failed with error|corrupted coverage file'

TIMEOUT_BIN="${FUZZ_LONG_TIMEOUT_BIN:-}"
if [ -z "$TIMEOUT_BIN" ]; then
  if command -v timeout >/dev/null 2>&1; then
    TIMEOUT_BIN="$(command -v timeout)"
  elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_BIN="$(command -v gtimeout)"
  else
    echo "timeout or gtimeout is required for fuzz-long" >&2
    exit 127
  fi
fi

mkdir -p "$FUZZ_LONG_LOG_DIR"
overall=0

for target in "${TARGETS[@]}"; do
  timestamp="$(date +%Y%m%d-%H%M%S)"
  log_file="$FUZZ_LONG_LOG_DIR/${target}-${timestamp}.log"
  cache_dir="$(mktemp -d "${TMPDIR:-/tmp}/zmoltcp-${target}-long-cache.XXXXXX")"

  export ZIG_LOCAL_CACHE_DIR="$cache_dir/local"
  export ZIG_GLOBAL_CACHE_DIR="$cache_dir/global"
  mkdir -p "$ZIG_LOCAL_CACHE_DIR" "$ZIG_GLOBAL_CACHE_DIR"

  echo "fuzz long target: $target"
  echo "log=$log_file"
  echo "cache=$cache_dir"

  set +e
  "$TIMEOUT_BIN" "$FUZZ_LONG_WALL_TIMEOUT" \
    zig build "$target" \
      --fuzz="$FUZZ_LONG_LIMIT" \
      --test-timeout "$FUZZ_LONG_TEST_TIMEOUT" \
      --summary all 2>&1 | tee "$log_file"
  status=${PIPESTATUS[0]}
  set -e

  if [ "$status" -eq 124 ]; then
    echo "$target reached wall-clock timeout $FUZZ_LONG_WALL_TIMEOUT" >&2
    overall=1
  elif [ "$status" -ne 0 ]; then
    echo "$target failed with status $status" >&2
    overall=1
  elif grep -Eq "$FAILURE_RE" "$log_file"; then
    echo "$target output contained failure markers" >&2
    overall=1
  fi
done

exit "$overall"
