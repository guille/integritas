#!/usr/bin/env bash
set -euo pipefail

# Benchmark harness for integritas vs hashdeep.
# Generates test data, runs both tools, and reports timing.
#
# Requirements: hashdeep, cargo (builds integritas in release mode), bc
#
# Usage: ./benchmarks/run.sh [--keep-data]
#   --keep-data: don't delete generated test files after running

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_DIR="${TMPDIR:-/tmp}/integritas_bench_$$"
KEEP_DATA=false

for arg in "$@"; do
  case "$arg" in
    --keep-data) KEEP_DATA=true ;;
  esac
done

cleanup() {
  if [ "$KEEP_DATA" = false ]; then
    rm -rf "$BENCH_DIR"
  else
    echo "Test data kept at: $BENCH_DIR"
  fi
}
trap cleanup EXIT

echo "=== Integritas Benchmark Suite ==="
echo "Working directory: $BENCH_DIR"
echo ""

# Build release binary
echo "Building integritas (release)..."
cargo build --release --manifest-path "$PROJECT_DIR/Cargo.toml" 2>/dev/null
INTEGRITAS="$PROJECT_DIR/target/release/integritas"
echo ""

# Generate test data
echo "Generating test data..."
mkdir -p "$BENCH_DIR/single" "$BENCH_DIR/small" "$BENCH_DIR/mixed"

echo "  - 1 GB file..."
dd if=/dev/urandom of="$BENCH_DIR/single/1gb.bin" bs=1M count=1000 2>/dev/null

echo "  - 1000 x 4 KB files..."
for i in $(seq 1 1000); do
  dd if=/dev/urandom of="$BENCH_DIR/small/file_$i.bin" bs=4096 count=1 2>/dev/null
done

echo "  - Mixed workload (3 large + 50 small = ~1 GB)..."
dd if=/dev/urandom of="$BENCH_DIR/mixed/large1.bin" bs=1M count=200 2>/dev/null
dd if=/dev/urandom of="$BENCH_DIR/mixed/large2.bin" bs=1M count=300 2>/dev/null
dd if=/dev/urandom of="$BENCH_DIR/mixed/large3.bin" bs=1M count=500 2>/dev/null
for i in $(seq 1 50); do
  dd if=/dev/urandom of="$BENCH_DIR/mixed/small_$i.bin" bs=64K count=1 2>/dev/null
done
echo ""

# Drop caches if running as root (for fair comparison)
if [ "$(id -u)" -eq 0 ]; then
  sync && echo 3 > /proc/sys/vm/drop_caches
  echo "Page cache dropped."
fi

# Benchmarks
run_bench() {
  local label="$1"
  local cmd="$2"
  echo -n "  $label: "
  # Run 3 times, take the best (wall clock)
  local best=999999
  for _ in 1 2 3; do
    local t
    t=$( { time eval "$cmd" > /dev/null 2>&1; } 2>&1 | grep real | awk '{print $2}' | sed 's/[ms]/ /g' | awk '{printf "%.3f", $1*60+$2}' )
    if (( $(echo "$t < $best" | bc -l) )); then
      best=$t
    fi
  done
  echo "${best}s"
}

echo "=== 1 GB single file ==="
run_bench "integritas -j8 (parallel)" "$INTEGRITAS compute -j 8 -q $BENCH_DIR/single -o $BENCH_DIR/single/.integritas-manifest.json"
run_bench "integritas -j1 (sequential)" "$INTEGRITAS compute -j 1 -q $BENCH_DIR/single -o $BENCH_DIR/single/.integritas-manifest.json"
run_bench "hashdeep -j8 (MD5+SHA256)" "hashdeep -j 8 -r -l $BENCH_DIR/single/1gb.bin"
run_bench "hashdeep -j1 (MD5+SHA256)" "hashdeep -j 1 -r -l $BENCH_DIR/single/1gb.bin"
echo ""

echo "=== 1000 x 4 KB small files ==="
run_bench "integritas -j8 (parallel)" "$INTEGRITAS compute -j 8 -q $BENCH_DIR/small -o $BENCH_DIR/small/.integritas-manifest.json"
run_bench "integritas -j1 (sequential)" "$INTEGRITAS compute -j 1 -q $BENCH_DIR/small -o $BENCH_DIR/small/.integritas-manifest.json"
run_bench "hashdeep -j8 (MD5+SHA256)" "hashdeep -j 8 -r -l $BENCH_DIR/small"
run_bench "hashdeep -j1 (MD5+SHA256)" "hashdeep -j 1 -r -l $BENCH_DIR/small"
echo ""

echo "=== Mixed (1 GB: 3 large + 50 small) ==="
run_bench "integritas -j8 (parallel)" "$INTEGRITAS compute -j 8 -q $BENCH_DIR/mixed -o $BENCH_DIR/mixed/.integritas-manifest.json"
run_bench "integritas -j1 (sequential)" "$INTEGRITAS compute -j 1 -q $BENCH_DIR/mixed -o $BENCH_DIR/mixed/.integritas-manifest.json"
run_bench "hashdeep -j8 (MD5+SHA256)" "hashdeep -j 8 -r -l $BENCH_DIR/mixed"
run_bench "hashdeep -j1 (MD5+SHA256)" "hashdeep -j 1 -r -l $BENCH_DIR/mixed"
echo ""

echo "Done."
