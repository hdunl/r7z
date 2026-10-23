# Changelog

Notable changes to r7z. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

- Updating existing archives. `a` into an existing 7z, zip, tar or compressed tar adds
  and replaces entries; `u` replaces only the entries the files on disk are newer than;
  `d` deletes the entries a name, `-i` or `-x` selects; `rn` renames entries and folders
  (`rn archive old new ...`, wildcards carry through with `*` and `?`). 7z copies every
  folder an update does not touch and re-encodes only the solid blocks that lost an
  entry; zip copies untouched entries byte for byte; tar streams are rewritten. Each
  update is written beside the archive and replaces it only when it succeeds. Encrypted
  archives take their password (`-p`), checked before anything is written, and keep
  header encryption.
- Writes zstd (`.zst`, `.tzst`, `.tar.zst`, and zip members with `-mm=zstd`, method 93),
  lz4 frames (`.lz4`, `.tar.lz4`) and Unix `compress` (`.Z`, `.taz`, `.tar.Z`). zstd has
  its own encoder (hash-chain matches, Huffman literals, predefined FSE tables): about
  2-4% larger than `zstd -3` on text and 8% larger on executables, at 13-45 MB/s
  against zstd's 120 MB/s at level 3.
- Reads the legacy zip methods Implode, Shrink and Reduce (factors 1-4). Implode matches
  Info-ZIP's `unzip` on every test stream, Shrink on 11 of 12; Reduce is checked only
  against r7z's own encoder.
- Reads split zips: `x.z01`, `x.z02`, … with `x.zip` as the last part, or any one of them.
- Symbolic links in tar archives become links where the platform allows (on Windows with
  Developer Mode or the symlink privilege) and only when the target stays inside the
  extraction folder; otherwise the file holding the target text is written, as before.
- Recovery resumes inside damaged bzip2 and xz streams: a damaged block costs only itself,
  is reported, and the blocks after it come back. A tar inside them is found again by
  searching for the next valid header, whatever the shift.
- Faster `-mx5` to `-mx9` when one encoder handles a folder (and xz at those levels): the
  binary tree match finder runs on its own thread, so the parser and range coder no longer
  wait for it on one core. `-mx9` on a 87 MB tree: 29 s against 38 s, with peak memory 9%
  higher. The encoder is a vendored copy of lzma-rust2 0.22's (Apache-2.0), and its output
  is byte-identical to the single-threaded encoder's for the same writes.
- BCJ2 encoding: `-mx8` and `-mx9` store x86 executables (exe, dll, sys, and the other
  executable extensions r7z already knows) as 7-Zip does, with four streams. `-mf=BCJ2`
  forces it. Encrypted archives keep the single BCJ filter.
- Branch converters for ARM, ARMT, ARM64, PPC, SPARC, IA64 and RISC-V. `-mf=ARM64` (and
  the other names) forces one for every file. By default a file with an executable name
  and a PE or ELF header gets the converter for its machine, as 7-Zip picks them.
- RAR 4 and RAR 5 reading: LZ and PPMd, the standard RAR 3 filters (E8, E8E9, Delta,
  RGB, Audio) and RAR 5's E8, E8E9, ARM and Delta, solid units, split `.partNN.rar` and
  `.rNN` volumes, RAR 3 AES-128 and RAR 5 AES-256 with encrypted headers, and CRC32 and
  BLAKE2sp checks. The Itanium filter is unverified; RAR 1.5 and 2.0 are not supported.
- Reads optical and Apple disk images: ISO 9660 (Joliet, Rock Ridge, El Torito boot images,
  files over several extents), UDF 1.02 to 2.60 (Blu-ray metadata partitions), Apple disk
  images (`.dmg` with ADC, zlib, bzip2 and LZFSE chunks, opening the HFS+ partition inside)
  and HFS+/HFSX volumes, including decmpfs files whose payload is in the attribute (files
  with blocks in the resource fork are listed but not extracted). Reads are random access,
  so large images do not load into memory.
- Reads disk images and the file systems in them: VHD (fixed, dynamic, and differencing
  disks, the parent found beside the child), VHDX, VMDK (monolithic sparse, stream-optimized
  and descriptor files), QCOW2, MBR with extended partitions, GPT, FAT12/16/32 with long
  names, exFAT, NTFS (run lists, sparse files, LZNT1 compression) and ext2/3/4 (extents,
  indirect blocks, inline data, symbolic links). Disks nest as in 7-Zip: a VHDX holding a GPT
  holding NTFS lists as the NTFS files. The desktop app opens a partition in place. Disks are
  read by range, so a sparse terabyte costs only its allocation table. This adds 0.23 MiB to
  r7z.exe (3.47 to 3.70 MiB) and 0.22 MiB to the desktop app (9.71 to 9.93 MiB).
- Reads installers and executable containers: MSI, MSP and other OLE (Compound) files, NSIS
  2 and 3 installers (ANSI and Unicode, zlib, bzip2 and LZMA), self-extracting 7z, zip and
  cab archives, PE resources and CHM help files. A plain `.exe` is still not an archive:
  Explorer's "Extract here" and "Open with" show for an executable only when it carries an
  installer or self-extractor payload, and the desktop app offers "Open as archive" for the
  resources of any other program. Inno Setup is not supported yet.
- "Update…" opens a dialog with the release's "What's new" before anything installs, and
  the "Updated" notice can show it too. The text is signed with the update key and bound
  to its version.
- A Microsoft Store build: `--features r7z-gui/store,r7z-shell/store` leaves out the
  updater, the installer and the menu settings, and `scripts/make_store_msix.ps1` packs it
  with the right-click menu, "Open with" for archive types and the `r7z` command. Release
  runs keep the package as a workflow artifact for Partner Center.
- PRIVACY.md: what r7z stores and when it uses the network.

## 0.1.9 - 2026-10-18

- Faster extraction: decoded files wait for the writer threads in a queue bounded by
  size (32 MiB) instead of by count, so decoding runs ahead of file creation; new
  directories are created, and directory times set, a depth level at a time in parallel;
  and a large solid block next to a small one gets most of the decode threads. Extracting
  a 7-Zip-made 7z of a source tree took 17-25% less time in back-to-back runs.
- Deflate (zip, gzip, tar.gz) uses the zlib-rs backend: zip creation about 1.5-2x faster,
  tar.gz testing about 25% faster. The default zip/gzip level moves from zlib 6 to 7,
  which keeps sizes where they were. Parallel gzip chunks are primed with a preset
  dictionary instead of compressing the previous 32 KiB again.
- Adds about 100 KB to each program.

## 0.1.8 - 2026-10-18

- Smaller download: the desktop app is 10.1 MB instead of 12.7 MB and the Explorer menu
  extension 0.3 MB instead of 2.3 MB. The interface libraries are built for size (the
  codecs keep full optimization), the app uses Windows' own fonts instead of carrying
  copies, and the menu extension no longer links every archive parser to read a list of
  file extensions.

## 0.1.7 - 2026-10-18

- r7z can install itself: Install (on the welcome tour's last page, in Settings, or in a
  one-time offer for existing users) copies it to `%LOCALAPPDATA%\Programs\r7z` and adds
  it to the Start menu and Windows search, Settings → Installed apps, Run (`r7z`),
  "Open with" and Default apps for archive types, and the right-click menus. No
  administrator rights. Uninstall from Settings → Apps or from r7z's Settings removes
  all of it and keeps your settings.
- `r7z-gui --install` and `r7z-gui --uninstall --quiet` do the same without a window.
- The Windows 11 menu package is listed as "r7z right-click menu" in Installed apps.

## 0.1.6 - 2026-10-18

- The programs no longer need the Visual C++ Redistributable: the C runtime is linked in,
  so r7z starts on a fresh Windows install.

## 0.1.5 - 2026-10-18

- More entries in the Windows 11 right-click menu: **Add to "name.7z"** and **Add to
  "name.zip"** compress right away with the default settings, **Test archive** checks an
  archive without extracting it, **Convert to .7z** repacks a zip or other archive, and
  **Open in r7z** browses a folder. A divider separates them from the entries that make
  an archive.
- The welcome tour's Explorer page shows the new menu.
- `r7z-gui` takes `--add-7z`, `--add-zip`, `--test` and `--convert`, which the menu uses.

## 0.1.4 - 2026-10-18

The first code-signed release. 0.1.3 was tagged, but its release build stopped at the
signature check and nothing was published.

- Releases are code-signed (Authenticode, Public Trust, timestamped) through Microsoft's
  Artifact Signing, so Windows shows a verified publisher instead of a SmartScreen warning.
- The Windows 11 menu package ships signed, so r7z joins the main context menu on any
  Windows 11 PC, not only with Developer Mode on.
- Updates also install files that are new in a release, such as the Windows 11 menu
  package; before, an update only replaced files that were already there.
- Copies updated by an older version can fetch the Windows 11 menu from Settings →
  Explorer menu → "Get the Windows 11 menu", with the same signed checks as updates.

## 0.1.2 - 2026-10-18

- A welcome tour on first launch shows the main features with screenshots; it can
  be skipped, and reopened from Settings or search everywhere.

## 0.1.1 - 2026-10-17

Security and maintenance release.

- Dependencies are current, with no known advisories: egui 0.37 and rfd 0.17 drop the
  unmaintained `ttf-parser` and `zbus` crates, and the RustCrypto, ureq, ed25519-dalek,
  lz4_flex and getrandom crates move to their latest major versions.
- The updater uses Windows' own TLS and certificate store.
- AES block handling no longer needs an `unsafe` cast.
- Both programs carry Windows version information (product name, description, version).
- Releases include SLSA build provenance (`.intoto.jsonl`) and a Sigstore bundle.
- An r7z submenu in Windows 11's main context menu (`r7z_shell.dll`), for now with
  Developer Mode on; the classic entries stay under "Show more options".
- Selecting several archives and choosing Extract here or Extract to handles them in
  one batch.
- Continuous fuzzing of archive parsing and recovery with ClusterFuzzLite, CodeQL code
  scanning, and an OpenSSF Scorecard.
- Text fields center their text again.
- Crashes found by fuzzing are fixed: integer overflows on crafted WIM sizes, tar sparse
  maps and pax times, zip recovery sizes, recovery offsets and timestamps.
- Built with Rust 1.99.1; Rust 1.95 or newer is required to build from source.

## 0.1.0 - 2026-10-17

First release.

- Command line tool with 7-Zip's commands and switches: add, extract, list, test, hash
  and benchmark.
- Reads 7z, zip, tar, gzip, bzip2, xz, zstd, lz4, Z, lzma, cab, cpio, ar/deb, rpm, arj,
  lzh, xar/pkg, wim/esd/swm, split volumes, Base64 and Intel HEX. Writes 7z, zip, tar,
  gzip, bzip2 and xz.
- Desktop app with archive browsing, preview, space map, safety check, smart and batch
  extract, undo extract, convert, drag and drop, open as folder and Explorer integration.
- Recovery of damaged and truncated archives (`x -recover`).
- Correct names for archives written in legacy code pages (Shift-JIS, GBK, Big5 and
  others).
- Signed automatic updates in the desktop app.
