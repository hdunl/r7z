# Development

## Layout

```text
crates/
  r7z/          library and command line tool
    src/
      sevenz/   7z container: data model, header reader (memory-mapped), header writer
      format/   the format layer: Archive trait, registry and detection, nesting, one
                module per format (zip, tar, stream compressors, cab, cpio, ar, rpm, arj,
                lzh, xar, wim, split/base64/ihex), non-7z writers
      codec/    method registry, decode graph, encode chain, 7zAES, parallel LZMA2,
                parallel Deflate/bzip2/xz encoders, parallel bzip2 decoder, zip crypto,
                LZW, LZX, Quantum, MSZIP, LZH/ARJ decoders
      ops/      create, extract/test (format-neutral), damaged-archive recovery, hash,
                benchmark workflows
      util/     CRC64, wildcards, FILETIME/DOS time conversion, code pages, memory,
                formatting
      cli/      7-Zip-compatible argument parser, terminal UI
    tests/      round trips and fixture reads per format (no external tools needed)
  r7z-gui/      desktop app (egui): archive tree model, background jobs, dialogs, theme,
                painter-drawn icons, Explorer integration, Open as folder (ProjFS)
  r7z-shell/    Windows 11 context menu (a COM server) and its package manifests
  fuzz/         cargo-fuzz targets, outside the workspace
  winres.rs     version information and icons, shared by the build scripts
scripts/        interop.sh (two-way 7-Zip matrix), compare.py (benchmarks), release
                packaging
```

Third-party codecs, all pure Rust: [`lzma-rust2`](https://crates.io/crates/lzma-rust2)
(LZMA/LZMA2/xz, BCJ, BCJ2, Delta), `flate2` with `zlib-rs` (Deflate), `deflate64`,
`bzip2` with `libbz2-rs-sys`, `ruzstd`, `lz4_flex` and `ppmd-rust`. Everything else is r7z
code: the containers, the coder graph, 7zAES and zip encryption, the parallel encoders,
the parallel bzip2 decoder, the LZW, LZX, Quantum, LZH and ARJ decoders, the extraction
pipeline and the CLI.

## Releasing

1. Bump the version in `crates/*/Cargo.toml` and `crates/r7z-shell/package/AppxManifest.xml`,
   move `CHANGELOG.md`'s `## Unreleased` under the new version, and write
   `docs/releases/vX.Y.Z.md`. Its `## What's new` section is what the desktop app shows
   before updating (`python scripts/release_notes.py vX.Y.Z` prints it), so keep it to
   Markdown lists, bold, code, links and tables.
2. Merge, then push the tag `vX.Y.Z`. The release workflow's `notes` job puts the notes on
   the run's summary page, and the `release` job waits for a maintainer to approve the
   `release` environment. Read the summary, then approve: only then are the programs
   built, signed (Authenticode, the update manifest and the notes) and published.

## Testing

```bash
cargo test --release --workspace       # unit, round-trip and fixture tests
scripts/interop.sh target/release/r7z 7z
R7Z_MOUNT_TEST=some.7z cargo test --release -p r7z-gui -- --ignored mount
```

The Open as folder tests read the archive named by `R7Z_MOUNT_TEST` and are skipped when
it is unset. One reads every file through the mount's reader in name order and compares it with an
extraction; the other mounts the archive through ProjFS, compares the listing and every
file byte for byte, checks that writing, creating, deleting and renaming are refused, and
ejects. It is skipped when ProjFS is not enabled.

`interop.sh` builds a corpus with Unicode names, empty files and directories, random data
and executable-like data, then checks 100 cases:

- **7z, both ways (39 cases).** Archives r7z makes (every level, solid and non-solid, LZMA,
  Copy, BCJ, Delta, small blocks, AES, header encryption) must test and extract
  byte-identically with 7-Zip, and archives 7-Zip makes (including ARM64 filters) with
  r7z. Wrong passwords, truncation and corruption must be detected.
- **r7z writes, 7-Zip tests and extracts:** zip (levels 0-9, Copy, single-threaded,
  AES-256), tar, tar.gz/tgz, tar.bz2 and tar.xz at several levels, and single-file
  .gz/.bz2/.xz.
- **7-Zip writes, r7z tests and extracts:** zip with Deflate, Deflate64, BZip2, LZMA, PPMd
  and Copy, ZipCrypto and AES-128/256; tar; 7z with PPMd, BZip2, Deflate and Deflate64;
  tars that 7-Zip then compresses with gzip, bzip2 and xz (r7z extracts them in one step);
  split volumes.
- **Formats neither writes:** archives made by the platform's own tools must extract
  identically with r7z and 7-Zip: bsdtar (pax and GNU tar, tar.zst, tar.Z, tar.lzma,
  cpio newc/odc/bin, cpio.gz, xar with gzip/bzip2/none, GNU and BSD ar), makecab (MSZIP,
  LZX:15, LZX:21) and Bandizip (lzh); a WIM 7-Zip writes and a Windows-made XPRESS WIM.

The Rust tests add checked-in fixtures for what no local tool writes: ARJ (methods 0, 1
and 4), LZH methods `-lh1-` to `-lh6-`, `-lzs-` and `-lz5-` (each checked against 7-Zip or
Bandizip when they can read it), Quantum CABs, crc and big-endian cpio, rpm, deb, MS
`.lib`, zstd, lz4, lzma86, Base64, Intel HEX, ZIP64 and GNU/pax sparse tars. Every fixture
is also truncated and bit-flipped to check that damage is reported without a panic.
`crates/r7z/tests/recover.rs` damages archives it builds on purpose (a zeroed central directory, a
truncated zip, 7z, tar.gz and bzip2, a zeroed 7z start header, changed bytes in the middle
of a solid block, a destroyed tar header) and checks exactly which files come back.
