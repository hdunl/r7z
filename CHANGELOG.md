# Changelog

Notable changes to r7z. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

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
