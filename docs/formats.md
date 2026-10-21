# Formats and commands

| Area | Support |
|---|---|
| Commands | `a` add (or replace, in an existing archive), `u` update (replace only older entries), `d` delete, `rn` rename, `x` extract, `e` extract flat, `l` list (`-slt`), `t` test, `h` hash, `b` benchmark, `i` formats and codecs |
| Formats | see the table below; `-t{type}` forces a type, otherwise r7z detects it by signature, then extension |
| Nested archives | a tar (or cpio) inside gzip, bzip2, xz, zstd, lz4, Z or lzma opens as one archive; so do split volumes, an rpm's payload and a deb's `data.tar.*`. `-tgzip` (or any stream type) stops at the outer level |
| 7z codecs | write LZMA2, LZMA, Copy, BCJ, Delta, 7zAES; read also PPMd, BZip2, Deflate, Deflate64, BCJ2, ARM, ARMT, ARM64, PPC, SPARC, IA64, RISC-V |
| Encryption | 7z: AES-256 with 7-Zip's KDF, header encryption (`-mhe=on`). zip: WinZip AES-256 (write), AES-128/192/256 and ZipCrypto (read) |
| Hashes (`h`) | CRC32, CRC64, XXH64, MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256 |
| Metadata | modification time (creation/access with `-mtc`/`-mta`), Windows attributes, Unix modes, links |

## Formats

`r7z i` prints this list with signatures. All formats support `l`, `t`, `x` and `e`.

| Type | Read | Write | Details |
|---|---|---|---|
| 7z | ✓ | ✓ | format 0.4, solid and non-solid, multi-volume through Split |
| zip | ✓ | ✓ | read Store, Deflate, Deflate64, BZip2, LZMA, PPMd, Zstandard and xz; ZIP64; UTF-8 names and the Info-ZIP Unicode path and comment fields; names in legacy code pages detected per archive (see below); ZipCrypto, WinZip AES. Write Store and Deflate, ZIP64, UTF-8 names, NTFS times, AES-256 (`-mem=AES256` is the default with `-p`). Also `.jar .docx .xlsx .odt .epub .apk .ipa .appx .nupkg .whl` |
| tar | ✓ | ✓ | ustar, GNU (long names, old sparse, base-256 sizes), pax (extended headers, sparse 0.1 and 1.0), hard and symbolic links; non-UTF-8 names in old headers decoded with the detected code page. Writes ustar with pax headers for long or non-ASCII names and large files |
| gzip | ✓ | ✓ | multi-member; `.tgz`/`.tar.gz` write and read in one step |
| bzip2 | ✓ | ✓ | multi-stream; `.tbz2`/`.tar.bz2` |
| xz | ✓ | ✓ | CRC32/CRC64/SHA-256 checks, several streams; `.txz`/`.tar.xz` |
| zstd | ✓ | – | concatenated and skippable frames; `.tzst`/`.tar.zst` |
| lz4 | ✓ | – | LZ4 frame format (concatenated frames) and the legacy format |
| Z | ✓ | – | Unix `compress` (LZW, 9-16 bits); `.taz`/`.tar.Z` |
| lzma, lzma86 | ✓ | – | LZMA "alone" files; lzma86 with or without BCJ |
| Cab | ✓ | – | MSZIP, LZX (15-21), Quantum, none; multi-cabinet sets; block checksums |
| Cpio | ✓ | – | odc, newc, crc (checksum verified), old binary in both byte orders |
| Ar | ✓ | – | System V/GNU and BSD names, symbol tables, `.a`, `.lib`, `.deb` (opens `data.tar.*`; `-tar` lists the members) |
| Rpm | ✓ | – | the payload opens through its compressor down to the cpio's files |
| Arj | ✓ | – | methods 0-4; names in the detected code page; garbled (encrypted) entries and multi-volume continuation are listed but not extracted |
| Lzh | ✓ | – | `-lh0-`, `-lh1-`, `-lh4-` to `-lh7-`, `-lzs-`, `-lz5-`, `-lz4-`, header levels 0-3, CRC16 verified; Shift-JIS and other code-page names detected |
| Xar | ✓ | – | `.pkg`/`.xip`; zlib, bzip2, xz, lzma and stored data; SHA-1/MD5/SHA-2 checksums verified; `[TOC].xml` |
| wim | ✓ | – | `.wim .esd .swm .ppkg`: XPRESS, LZX, LZMS, solid resources (ESD), split `.swm` sets, several images (`1/`, `2/`… like 7-Zip), hard links, alternate streams (`file:stream`), SHA-1 verified |
| Split | ✓ | – | `.001`, `.002`… joined in order, then the archive inside is opened |
| Base64 | ✓ | – | plain or PEM-wrapped text |
| IHex | ✓ | – | Intel HEX, one item per contiguous block |

Switches follow 7-Zip: `-o`, `-p`, `-t`, `-mx0..9`, `-mmt[N]`, `-m0=LZMA2:d=..:c=..`, `-md`,
`-mf=off|BCJ|Delta:N`, `-ms=on|off|SIZE`, `-mhe`, `-mhc`, `-mm=Deflate|Copy`,
`-mem=AES256`, `-mcp={code page}` (for reading), `-x!`, `-i!`, `@listfile`, `-r`,
`-ao{a|s|u|t}`, `-y`, `-so`, `-slt`, `-scrc`, `-bd`, and r7z's own `-recover`. Exit codes
are 0 (ok), 1 (warning), 2 (error) and 7 (usage), as in 7-Zip.
`a` picks the format from `-t` or the archive name (`.zip`, `.tar`, `.tar.gz`, `.tgz`,
`.tar.bz2`, `.tar.xz`, `.gz`, `.bz2`, `.xz`; anything else is 7z).

### Updating archives

`a`, `u`, `d` and `rn` change an existing 7z, zip, tar, tar.gz, tar.bz2 or tar.xz archive
(and a single-file `.gz`, `.bz2` or `.xz`):

- `a` adds the named files and directories, replacing entries of the same name; `u` does
  the same only for entries the file on disk is newer than (compared to the second, since
  tar stores whole seconds). Entries not named are kept.
- `d` deletes the entries the names, `-i` and `-x` select; a name that is a directory
  takes its contents with it. `rn` takes pairs, `old new`: a directory moves with its
  contents, and wildcards in `old` (matched against the last component, or the whole path
  when it has a `/`) carry into `new` through its `*` and `?`.
- 7z copies every folder that keeps all its entries as it is, packed bytes included, and
  decodes and encodes again only the solid blocks that lost an entry. A rename changes
  only the header. Zip copies the local header and data of each kept entry byte for byte
  and writes a new central directory, so ZIP64, AES and data descriptors are preserved.
  Tar streams are rewritten, compressed again for tar.gz, tar.bz2 and tar.xz.
- The new archive is written to a temporary file beside the archive, which replaces it
  only when the whole update succeeded. A failed or cancelled update leaves the archive
  as it was.
- Adding and deleting in an archive with encrypted data needs its password (`-p`);
  renaming changes names without decoding anything, so it needs none. A wrong password is
  found before anything is written. New data is encrypted with the password; the existing
  encrypted entries must open with it, so an archive never ends up with two passwords. A
  7z whose header was encrypted keeps that encryption.
- Not updatable: archives with data before their first entry (self-extracting zip stubs),
  zip archives whose entries overlap, and other formats (r7z reports which). A tar hard
  link names its target, so renaming or deleting that target leaves the link pointing at
  nothing; update the link too, or re-create it.

Compared with 7-Zip's console tool, r7z also:

- shows a live progress bar with throughput and ETA (on a terminal; `-bd` turns it off);
- refuses unsafe paths when extracting (`..`, absolute paths, drive letters, Windows device
  names) instead of writing outside the target directory;
- writes archives to a temporary file and renames them into place, so a failed or
  interrupted run never leaves a half-written archive under the real name;
- asks for the password itself when an archive needs one, and says "wrong password"
  rather than reporting a CRC error;
- creates and extracts `.tar.gz`, `.tar.bz2` and `.tar.xz` in one step (7-Zip needs two
  runs, one per layer), and compresses gzip and bzip2 on all cores;
- extracts GNU and pax sparse tar files (7-Zip fails on the first and misnames the
  second), xz- and lzma-compressed xar files, and CAB folders whose files overlap;
- shows the right names for zip, LZH, ARJ and tar archives written in a legacy code page
  on any system. 7-Zip and WinRAR decode such names with the code page of the machine
  they run on, so a Japanese zip opened on a Chinese or Western PC shows mojibake, and a
  Shift-JIS byte that happens to be `\` can split a name into folders. r7z decodes every
  name of the archive with each candidate code page (UTF-8, Shift-JIS, GBK, Big5, Korean,
  DOS and Windows Cyrillic, Greek, Western, Central European and Turkish) and keeps the
  most plausible one; `l -slt` prints the choice as `Code Page`, the desktop app shows it on
  the archive card with a picker, and `-mcp=932` (any supported number) forces a page;
- rescues what is readable from damaged and truncated archives (`x -recover`), described
  below.

## Not supported yet

- RAR, disk images (ISO, UDF, VHD, VMDK, DMG, QCOW, file systems) and installers (NSIS,
  MSI/Compound, PE resources, SFX archives behind a stub).
- Writing zstd, lz4, Z and the read-only formats above; writing ZipCrypto (r7z encrypts
  zip with AES-256); zip Shrink/Implode/Reduce and PKWARE strong encryption; split zips
  (`.z01`); legacy LZ4 frames; garbled or multi-volume ARJ.
- Encoding BCJ2 and the non-x86 branch filters in 7z.
- NTFS alternate streams, security descriptors; symbolic links are extracted as files that
  contain the link target.
- Recovery does not yet resume inside a bzip2 or xz stream after damage (their blocks are
  independent, so it could), or inside a gzip stream; a 7z cut off mid-stream loses the
  partly present last LZMA2 chunk (up to 64 KiB packed).
- Split volumes larger than the memory budget are joined in a temporary file first.
- Stopping r7z with Ctrl-C while creating can leave a `*.r7z-tmp-<pid>` file next to the
  target archive.
