#!/bin/bash -eu
# Builds the fuzz targets in crates/fuzz/ for ClusterFuzzLite and seeds them with the test
# fixtures, which cover every format r7z reads.
cd "$SRC/r7z"
cargo fuzz build --fuzz-dir crates/fuzz -O --debug-assertions
for target in open recover; do
  cp "crates/fuzz/target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
  find crates/r7z/tests/fixtures -type f -print0 | xargs -0 zip -j -q "$OUT/${target}_seed_corpus.zip"
done
