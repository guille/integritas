#!/usr/bin/env bash
#
# End-to-end CLI benchmarks. Criterion covers in-process work whose deltas are
# smaller than process startup noise; this covers whole-command wall time.
#
#   BENCH_FILES      files in the fixture tree     (default 20000)
#   BENCH_FILE_SIZE  bytes per file                (default 4096)
#   BENCH_THREADS    -j values to sweep            (default 1,$(nproc))
#   BENCH_TREE       fixture location              (default target/bench-tree)
#   BENCH_BASELINE   another integritas binary to compare against
#
# Point BENCH_TREE at a tmpfs to take the filesystem out of the measurement, or
# leave it under target/ to keep real I/O in.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

files=${BENCH_FILES:-20000}
size=${BENCH_FILE_SIZE:-4096}
threads=${BENCH_THREADS:-1,$(nproc)}
tree=${BENCH_TREE:-target/bench-tree}
stamp=$tree.stamp

# The fixture is rebuilt with rm -rf, so only ever touch a tree this script made.
if [[ -e $tree && ! -e $stamp ]]; then
    echo "refusing to touch $tree: no $stamp, so this script did not create it" >&2
    exit 1
fi

cargo build --release --quiet --example mktree
bin=$PWD/target/release/integritas

if [[ $(cat "$stamp" 2>/dev/null) != "$files $size" ]]; then
    rm -rf "$tree"
    mkdir -p "$tree"
    ./target/release/examples/mktree "$tree" "$files" "$size"
    echo "$files $size" >"$stamp"
fi

compute=("-n" "compute -j{threads}" "'$bin' compute '$tree' -q -j{threads} -o '$PWD/target/bench-compute.json'")
check=("-n" "check -j{threads}" "'$bin' check '$tree' -q -j{threads}")

if [[ -n ${BENCH_BASELINE:-} ]]; then
    baseline=$(realpath "$BENCH_BASELINE")
    compute+=("-n" "compute -j{threads} (baseline)" "'$baseline' compute '$tree' -q -j{threads} -o '$PWD/target/bench-compute-baseline.json'")
    check+=("-n" "check -j{threads} (baseline)" "'$baseline' check '$tree' -q -j{threads}")
fi

# check needs a manifest to verify against; compute writes elsewhere via -o.
"$bin" compute "$tree" -q

hyperfine --warmup 1 --parameter-list threads "$threads" \
    --export-markdown target/bench-cli-compute.md "${compute[@]}"

hyperfine --warmup 3 --parameter-list threads "$threads" \
    --export-markdown target/bench-cli-check.md "${check[@]}"
