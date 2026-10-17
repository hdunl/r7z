<p align="center">
  <img src="docs/logo.png" width="96" alt="r7z logo">
</p>

<h1 align="center">r7z</h1>

<p align="center">
  A fast archiver for Windows, written in Rust.<br>
  Opens what 7-Zip opens, writes 7z, zip and tar, and extracts several times faster.
</p>

<p align="center">
  <a href="https://github.com/hdunl/r7z/actions/workflows/ci.yml"><img src="https://github.com/hdunl/r7z/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue" alt="License"></a>
  <img src="https://img.shields.io/badge/rust-1.85%2B-orange" alt="Rust 1.85+">
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078d4" alt="Windows 10 | 11">
</p>

<p align="center">
  <img src="docs/screenshots/browse-light.png" alt="r7z desktop app browsing a 7z archive with an image preview" width="900">
</p>

r7z comes as two programs: a command line tool that takes the same commands and switches
as 7-Zip's `7z.exe`, and a desktop app to replace the 7-Zip File Manager. Both are single
executables with no installer and no runtime to set up.

## Highlights

- **Fast extraction.** 2 to 6 times faster than 7-Zip on 7z, zip and compressed tar
  archives full of small files. Most of the time goes into creating files, so r7z writes
  them on a pool of threads and sets timestamps without reopening each file.
- **Faster compression at the default level.** 7z archives at `-mx5` come out 1.3 to 1.8
  times faster, from a parallel LZMA2 encoder whose output 7-Zip reads as is. `.tar.gz` is
  made in one step, about 8 times faster than piping two 7-Zip processes together.
- **Drop-in CLI.** `a`, `x`, `e`, `l`, `t`, `h` and `b` with 7-Zip's switches (`-o`, `-p`,
  `-mx`, `-mhe`, `-ao`, `-x!`, `@listfile` and the rest) and the same exit codes, so
  scripts keep working.
- **Works with 7-Zip both ways.** A 100-case matrix checks that archives r7z writes test
  and extract with 7-Zip, and the other way round.
- **Safe by default.** Paths that try to escape the destination are refused, archives
  are written to a temp file and renamed into place, and the desktop app flags zip bombs
  and disguised executables before you extract anything.
- **Rescues damaged archives.** `x -recover` gets back every file that can still be read
  from a truncated download or a corrupt archive, and says what happened to the rest.
- **Correct names from any language.** Zips made on a Japanese, Chinese, Korean or
  Russian PC show their real file names on every system instead of garbled text.

## Desktop app

<p align="center">
  <img src="docs/screenshots/space-map-dark.png" alt="Space map in the dark theme, showing what takes room in an archive" width="900">
</p>

- Browse folders and archives in one window. Archives inside archives open in place.
- Preview images, text and hex without extracting, and paste a published SHA-256 or MD5 to
  check a download.
- **Space map:** see what takes room in an archive, down to single files.
- **Open as folder:** browse an archive in Explorer without extracting it. Uses Windows
  Projected File System, so no driver to install.
- **Smart extract:** creates a folder only when the archive needs one.
- **Undo extract:** take back the last five extractions, with any replaced files restored.
- Drag files out to Explorer, or copy and paste them.
- Batch extract, convert between formats, and create archives with AES-256.
- Light and dark themes that follow Windows, Explorer right-click menu, and Ctrl+Shift+F to
  search everywhere.
- Updates itself from GitHub releases. Every update is signed, and the signature is
  checked before anything is installed.

The full list is in [docs/desktop-app.md](docs/desktop-app.md).

## Install

Prebuilt Windows x64 binaries are on the [Releases](https://github.com/hdunl/r7z/releases)
page. Put `r7z.exe` somewhere on your `PATH`, and run `r7z-gui.exe` from anywhere.

With a Rust toolchain:

```bash
cargo install --git https://github.com/hdunl/r7z r7z       # command line
cargo install --git https://github.com/hdunl/r7z r7z-gui   # desktop app
```

## Usage

```text
r7z a backup.7z Documents            # create (LZMA2, level 5, all cores)
r7z a secret.7z notes -p -mhe=on     # AES-256, file names encrypted too (prompts)
r7z a site.zip public_html -p        # zip with WinZip AES-256
r7z a src.tar.gz project             # tar + gzip in one step
r7z x backup.7z -oRestore            # extract with paths
r7z x linux-6.9.tar.xz               # the tar inside is extracted directly
r7z x package.deb                    # the files inside data.tar.*
r7z x broken.zip -recover -oRescued  # get back what is still readable
r7z l backup.7z "*.pdf"              # list matching entries
r7z t driver.cab                     # verify every checksum
r7z h -scrcSHA256 *.iso              # hash files
```

`r7z-gui file.7z` opens an archive in the desktop app; `--extract-here`, `--extract-to` and
`--add` are what the Explorer menu entries call.

## Formats

| | Formats |
|---|---|
| **Read and write** | 7z, zip, tar, gzip, bzip2, xz (and `.tar.gz`, `.tar.bz2`, `.tar.xz` in one step) |
| **Read** | zstd, lz4, Z, lzma, lzma86, cab, cpio, ar and deb, rpm, arj, lzh, xar and pkg, wim, esd and swm, split `.001` volumes, Base64, Intel HEX |
| **Zip-based** | jar, docx, xlsx, odt, epub, apk, ipa, appx, nupkg, whl |
| **Encryption** | 7z AES-256 with header encryption; zip WinZip AES (read and write) and ZipCrypto (read) |

Codecs, switches and per-format details: [docs/formats.md](docs/formats.md).

## Performance

Against 7-Zip 25.01 x64, on Windows 11 with 16 threads and an NVMe SSD. The test set is
87 MB in 6,554 files, mostly JavaScript. Each tool runs with its default settings.

| | r7z | 7-Zip | |
|---|---:|---:|---|
| Extract 7z (`-mx5`) | **1.24 s** | 5.11 s | 4.1x faster |
| Create 7z (`-mx5`) | **7.91 s** | 13.98 s | 1.8x faster, 5.7% larger |
| Extract zip | **0.86 s** | 5.34 s | 6.2x faster |
| Create zip | **0.82 s** | 1.23 s | 1.5x faster |
| Create `.tar.gz` | **1.01 s** | 8.15 s | 8.1x faster (7-Zip needs two steps) |
| Extract `.tar.gz` | **1.05 s** | 5.24 s | 5.0x faster |

Raw decoding speed (`t`) is 15 to 20% behind 7-Zip's hand-tuned assembly, and `-mx9` is
slower to create for now. The full tables, the method and how the parallel encoder works
are in [docs/performance.md](docs/performance.md). `scripts/compare.py` reproduces them.

## Building

Rust 1.85 or newer with the MSVC toolchain:

```bash
git clone https://github.com/hdunl/r7z
cd r7z
cargo build --release
```

This builds `target/release/r7z.exe` and `target/release/r7z-gui.exe`. The desktop app's
icon is compiled with `rc.exe` from the Windows SDK; without it the build still succeeds
with the default icon. Source layout and testing: [docs/development.md](docs/development.md).

## Roadmap

- Updating existing archives (`u`, `d`, `rn`, `a` into an existing file)
- RAR and RAR5 extraction
- Disk images and installers: ISO, UDF, VHD, VMDK, DMG, NSIS, MSI
- Writing zstd and lz4
- BCJ2 encoding and a threaded match finder for faster `-mx9`

Smaller gaps are listed at the end of [docs/formats.md](docs/formats.md#not-supported-yet).

## Security

Releases are built and signed by GitHub Actions, with a build provenance attestation
for every file. Updates are verified against a key built into the app. Details, and how to
report a vulnerability privately: [SECURITY.md](SECURITY.md).

## Contributing

Bug reports and pull requests are welcome. For a bug, the output of `r7z t` on the archive
helps a lot, or `%APPDATA%\r7z\crash.log` if the desktop app closed. Please run
`cargo test --release` and `cargo clippy --workspace` before opening a pull request.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.

## Acknowledgements

r7z is an independent implementation. It follows the formats as
[7-Zip](https://www.7-zip.org/) by Igor Pavlov writes and reads them, and the public format
specifications. It builds on [`lzma-rust2`](https://crates.io/crates/lzma-rust2),
[`flate2`](https://crates.io/crates/flate2), [`ruzstd`](https://crates.io/crates/ruzstd),
[`lz4_flex`](https://crates.io/crates/lz4_flex),
[`ppmd-rust`](https://crates.io/crates/ppmd-rust) and [egui](https://github.com/emilk/egui).
