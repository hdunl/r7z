# Changelog

Notable changes to r7z. Versions follow [Semantic Versioning](https://semver.org/).

## Unreleased

- Both programs carry Windows version information (product name, description, version).

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
