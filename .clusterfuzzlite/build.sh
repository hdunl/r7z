#!/bin/bash -eu
# Builds the fuzz targets in fuzz/ for ClusterFuzzLite and seeds them with the test
# fixtures, which cover every format r7z reads.
cd "$SRC/r7z"
cargo fuzz build -O --debug-assertions
for target in open recover; do
  cp "fuzz/target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
  find tests/fixtures -type f -print0 | xargs -0 zip -j -q "$OUT/${target}_seed_corpus.zip"
done
