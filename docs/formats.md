# Formats and commands

| Area | Support |
|---|---|
| Commands | `a` add (or replace, in an existing archive), `u` update (replace only older entries), `d` delete, `rn` rename, `x` extract, `e` extract flat, `l` list (`-slt`), `t` test, `h` hash, `b` benchmark, `i` formats and codecs |
| Formats | see the table below; `-t{type}` forces a type, otherwise r7z detects it by signature, then extension |
| Nested archives | a tar (or cpio) inside gzip, bzip2, xz, zstd, lz4, Z or lzma opens as one archive; so do split volumes, an rpm's payload and a deb's `data.tar.*`. `-tgzip` (or any stream type) stops at the outer level |
| 7z codecs | write LZMA2, LZMA, Copy, BCJ, BCJ2, ARM, ARMT, ARM64, PPC, SPARC, IA64, RISC-V, Delta, 7zAES; read also PPMd, BZip2, Deflate, Deflate64 |
| Encryption | 7z: AES-256 with 7-Zip's KDF, header encryption (`-mhe=on`). zip: WinZip AES-256 (write), AES-128/192/256 and ZipCrypto (read) |
| Hashes (`h`) | CRC32, CRC64, XXH64, MD5, SHA1, SHA256, SHA384, SHA512, SHA3-256 |
| Metadata | modification time (creation/access with `-mtc`/`-mta`), Windows attributes, Unix modes, links |

## Formats

`r7z i` prints this list with signatures. All formats support `l`, `t`, `x` and `e`.

| Type | Read | Write | Details |
|---|---|---|---|
| 7z | ✓ | ✓ | format 0.4, solid and non-solid, multi-volume through Split |
| zip | ✓ | ✓ | read Store, Deflate, Deflate64, BZip2, LZMA, PPMd, Zstandard and xz, and the legacy Shrink, Reduce and Implode methods; split zips (`.z01`… and the `.zip` last part); ZIP64; UTF-8 names and the Info-ZIP Unicode path and comment fields; names in legacy code pages detected per archive (see below); ZipCrypto, WinZip AES. Write Store, Deflate and zstd (`-mm=zstd`, method 93), ZIP64, UTF-8 names, NTFS times, AES-256 (`-mem=AES256` is the default with `-p`). Also `.jar .docx .xlsx .odt .epub .apk .ipa .appx .nupkg .whl` |
| tar | ✓ | ✓ | ustar, GNU (long names, old sparse, base-256 sizes), pax (extended headers, sparse 0.1 and 1.0), hard and symbolic links; non-UTF-8 names in old headers decoded with the detected code page. Writes ustar with pax headers for long or non-ASCII names and large files |
| gzip | ✓ | ✓ | multi-member; `.tgz`/`.tar.gz` write and read in one step |
| bzip2 | ✓ | ✓ | multi-stream; `.tbz2`/`.tar.bz2` |
| xz | ✓ | ✓ | CRC32/CRC64/SHA-256 checks, several streams; `.txz`/`.tar.xz` |
| zstd | ✓ | ✓ | concatenated and skippable frames on read; written as one frame with a content checksum, `.tzst`/`.tar.zst`. See the note on zstd below |
| lz4 | ✓ | ✓ | LZ4 frame format (concatenated frames) and the legacy format on read; written as LZ4 frames with `lz4_flex`'s fast compressor, so `-mx` does not change the output; `.tar.lz4` |
| Z | ✓ | ✓ | Unix `compress` (LZW, 9-16 bits, block mode); written with 16-bit codes; `.taz`/`.tar.Z` |
| lzma, lzma86 | ✓ | – | LZMA "alone" files; lzma86 with or without BCJ |
| Cab | ✓ | – | MSZIP, LZX (15-21), Quantum, none; multi-cabinet sets; block checksums |
| Cpio | ✓ | – | odc, newc, crc (checksum verified), old binary in both byte orders |
| Ar | ✓ | – | System V/GNU and BSD names, symbol tables, `.a`, `.lib`, `.deb` (opens `data.tar.*`; `-tar` lists the members) |
| Rpm | ✓ | – | the payload opens through its compressor down to the cpio's files |
| Rar | ✓ | – | RAR 4 (2.9 to 3.x): LZ with Huffman blocks, PPMd variant H, VM standard filters E8, E8E9, Delta, RGB and Audio; the Itanium filter is implemented but unverified (no WinRAR sample). RAR 5: LZ with E8, E8E9, ARM and Delta filters. RAR 1.5 and 2.0 (unpack versions 15, 20 and 26): the adaptive LZ coding of 1.5, and the LZ with Huffman blocks and multimedia (audio) mode of 2.0, including comments kept inside headers and volume sets without end blocks. Encryption: RAR 4 AES-128, RAR 5 AES-256 with password check, and encrypted headers; files encrypted by RAR 1.5 or 2.0 are listed but not decrypted. Split volumes `.partNN.rar` and `.rNN`; solid units; comments and recovery records skipped; CRC32 and BLAKE2sp verified |
| Arj | ✓ | – | methods 0-4; names in the detected code page; garbled (encrypted) entries and multi-volume continuation are listed but not extracted |
| Lzh | ✓ | – | `-lh0-`, `-lh1-`, `-lh4-` to `-lh7-`, `-lzs-`, `-lz5-`, `-lz4-`, header levels 0-3, CRC16 verified; Shift-JIS and other code-page names detected |
| Xar | ✓ | – | `.pkg`/`.xip`; zlib, bzip2, xz, lzma and stored data; SHA-1/MD5/SHA-2 checksums verified; `[TOC].xml` |
| Iso | ✓ | – | ISO 9660 with Joliet names when present, Rock Ridge names, modes, times and symlinks (a symlink extracts as its target text), El Torito boot images listed as `[BOOT]/Boot-<media>.img` as 7-Zip does, and files split over several extents; a hybrid image with a UDF volume opens as UDF |
| Udf | ✓ | – | UDF 1.02 to 2.60, including the metadata partition of Blu-ray images (2.50+); symbolic links; names in 8-bit and UTF-16 |
| Dmg | ✓ | – | Apple UDIF `.dmg`: raw, zero, ADC, zlib, bzip2 and LZFSE/LZVN chunks, koly trailer and XML property list; each partition is an entry, and the HFS+ partition opens inside it. Encrypted images are refused |
| HFS | ✓ | – | HFS+ and HFSX volumes: catalog and extents overflow B-trees, data and resource forks, symbolic and hard links; decmpfs files with the payload in the attribute (zlib and LZVN). Decmpfs files that keep their blocks in the resource fork are listed, but not extracted |
| wim | ✓ | – | `.wim .esd .swm .ppkg`: XPRESS, LZX, LZMS, solid resources (ESD), split `.swm` sets, several images (`1/`, `2/`… like 7-Zip), hard links, alternate streams (`file:stream`), SHA-1 verified |
| Split | ✓ | – | `.001`, `.002`… joined in order, then the archive inside is opened |
| Base64 | ✓ | – | plain or PEM-wrapped text |
| IHex | ✓ | – | Intel HEX, one item per contiguous block |
| VHD | ✓ | – | `.vhd`: fixed and dynamic disks; a differencing disk reads its unstored sectors from the parent next to it, and does not open without it |
| VHDX | ✓ | – | `.vhdx`: header, region tables and block allocation table; a disk whose log was not replayed is refused, and differencing disks are not followed yet |
| VMDK | ✓ | – | `.vmdk`: monolithic sparse, stream-optimized (zlib grains) and descriptor files with FLAT, SPARSE and ZERO extents next to them |
| QCOW2 | ✓ | – | `.qcow2`, version 2 and 3: uncompressed, zlib and zero clusters; a backing file is listed and not followed, so reading a cluster only it holds is an error |
| MBR | ✓ | – | primary and logical (extended) partitions, listed in table order |
| GPT | ✓ | – | primary header, or the backup if the primary is damaged; partition labels; entries named `0.Basic data partition.fat` like 7-Zip |
| FAT | ✓ | – | FAT12, FAT16 and FAT32 with long file names |
| exFAT | ✓ | – | contiguous and chained files; bytes past the valid data length read as zeros |
| NTFS | ✓ | – | master file table with attribute lists; resident and non-resident data, sparse runs, LZNT1 compression; alternate streams and reparse targets are not read |
| Ext | ✓ | – | ext2, ext3 and ext4: indirect blocks, extent trees, inline data, symbolic links; devices, FIFOs and sockets are not listed |
| Compound | ✓ | – | `.msi .msp .msm` and other OLE storages (`.doc`, `.xls`) by signature: Windows Installer's packed stream names decoded as 7-Zip shows them, listed in 7-Zip's order; a package whose only cabinet is one `.cab` stream opens that cabinet as a nested archive |
| Nsis | ✓ | – | NSIS 2 and 3 installers, ANSI and Unicode; zlib, bzip2 and LZMA (with the x86 filter), solid and per-file data; file names and install folders read from the script; uninstallers rebuilt as the installer does. Found in the overlay of a PE file, not by name |
| Inno | ✓ | – | Inno Setup installers from 5.5 to 6.7 (setup data formats 5.5.0 to 6.7.0), ANSI and Unicode; stored, zlib, bzip2, LZMA and LZMA2 data, solid or per file, with Inno's x86 call filter undone; SHA-1 and SHA-256 checked. Names are the install destinations with their constant as the first folder (`app/bin/tool.exe`); files installed for one language get it added when names collide. The uninstaller and external files are not listed; encrypted files and data in separate `setup-N.bin` files are listed but not extracted |
| Sfx | ✓ | – | 7z, zip, RAR and cab archives appended to an executable stub (7-Zip and WinRAR style), found by signature after the PE image; listed as the archive type they are |
| PE | ✓ | – | `.exe` and `.dll` resources as folders by type, name and language: icon groups as `.ico` files, version information as `key=value` lines, manifests, RCDATA. Opened only with `-tPE` or "Open as archive", so a plain executable is never an archive |
| Chm | ✓ | – | compiled HTML help (ITSF versions 2 and 3): stored and LZX-compressed sections, listed as 7-Zip does; the `Block` column shows the LZX reset interval |

Disk images nest like 7-Zip's: a `.vhdx` holding a GPT holding NTFS lists as the NTFS files,
with each level in the listing. A virtual disk holds a partition table or a file system;
when a table has one partition, the partition's file system opens as the next level, and
with several, each partition is an entry numbered from 0 (`0.fat`, `1.fat`, `2.img`; `img` is a partition r7z does
not read). The desktop app opens a partition in place, without copying it out. Virtual disks
are read by range, so a sparse terabyte costs only its allocation table.

Switches follow 7-Zip: `-o`, `-p`, `-t`, `-mx0..9`, `-mmt[N]`, `-m0=LZMA2:d=..:c=..`, `-md`,
`-mf=on|off|BCJ|BCJ2|ARM|ARMT|ARM64|PPC|SPARC|IA64|RISCV|Delta:N`, `-ms=on|off|SIZE`, `-mhe`, `-mhc`, `-mm=Deflate|Copy`,
`-mem=AES256`, `-mcp={code page}` (for reading), `-x!`, `-i!`, `@listfile`, `-r`,
`-ao{a|s|u|t}`, `-y`, `-so`, `-slt`, `-scrc`, `-bd`, and r7z's own `-recover`. Exit codes
are 0 (ok), 1 (warning), 2 (error) and 7 (usage), as in 7-Zip.
`a` picks the format from `-t` or the archive name (`.zip`, `.tar`, `.tar.gz`, `.tgz`,
`.tar.bz2`, `.tar.xz`, `.gz`, `.bz2`, `.xz`; anything else is 7z).

### Updating archives

`a`, `u`, `d` and `rn` change an existing 7z, zip or tar archive, a tar compressed with
gzip, bzip2, xz, zstd, lz4 or Z, and a single-file `.gz`, `.bz2`, `.xz`, `.zst`, `.lz4` or
`.Z`:

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
  Tar streams are rewritten, and compressed again with the same compressor.
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
  below; in bzip2 and xz streams a damaged block costs only itself, and the blocks after it
  come back, with the lost ones reported;
- extracts symbolic links as links where the platform allows it (on Windows with Developer
  Mode or the symbolic link privilege). A link is made only when its target stays inside the
  extraction folder and no folder on the way is a link; otherwise the file that holds the
  target text is written, as before.

RAR reading follows RARLAB's public RAR 5.0 technote and the layouts used by libarchive's
BSD-licensed `archive_read_support_format_rar.c` and `archive_read_support_format_rar5.c`,
which were studied for design only; no code was copied. The RAR 3 filter programs are
recognised by their bytecode length and CRC-32, as RAR's own encoder writes them, and run
as fixed transforms rather than a general RAR VM. Test fixtures were written with WinRAR
and checked byte-for-byte against 7-Zip.

RAR 1.5 and 2.0 have no published specification. Their decoders follow the formats as
RAR's own extractors decode them; the 2.0 decoder was checked against the BSD-licensed
rardecode Go package, and both against the CRC32 of every file in archives made by RAR
1.5x and 2.90, including WinRAR 2.90's own solid installer.

Inno Setup stores its setup data as raw Delphi records whose layout changes between
releases. `scripts/inno_layouts.py` computes the size of each record and the offsets of
the fields r7z reads from the record definitions in each release's `Struct.pas`
(jrsoftware/issrc), and writes them to `crates/r7z/src/format/inno/layouts.rs`. The reader
was checked against installers made by Inno Setup 5.6.1 and 6.7.3 and the installers of
Inno Setup 5.6.1 and 6.7.3 themselves, and against two third-party installers made with
6.1.

## Not supported yet

- RAR 1.5 and 2.0 encryption; APFS and file
  systems other than FAT, exFAT, NTFS, ext2/3/4 and HFS+; VHDX log replay, differencing
  VHDX and QCOW2 backing files; NSIS 1.x installers, and the `[NSIS].nsi` script that
  7-Zip writes out; Inno Setup installers older than 5.5, encrypted Inno Setup files, and
  Inno Setup data split into `setup-N.bin` files.
- Legacy zip methods are read only, and checked unevenly: Implode matches Info-ZIP's
  `unzip` on every test stream; Shrink matches it on 11 of 12 (one 150 KB stream with
  periodic clears is still decoded differently); Reduce has only round-trip tests from
  r7z's own encoder. Real archives from PKWARE's tools have not been tried.
- Writing the read-only formats above, and writing ZipCrypto (r7z encrypts zip with
  AES-256); writing zip Shrink, Reduce and Implode; PKWARE strong encryption; garbled or
  multi-volume ARJ; zip split archives whose offsets count from each part (r7z reads
  parts joined in order, as `cat` joins them).
- zstd output: literals with more than 128 distinct byte values are stored raw (the
  Huffman weights are not FSE-coded yet), so executables come out about 8% larger than
  `zstd -3`; text about 2-3% larger. The encoder runs at 13-45 MB/s, from a third
  (level 1) to a tenth (level 9) of `zstd -3`'s speed.
- NTFS alternate streams, security descriptors.
- Recovery does not yet resume inside a gzip stream, nor inside an lz4 or zstd stream (their
  frames could resume the same way); a 7z cut off mid-stream loses the partly present last
  LZMA2 chunk (up to 64 KiB packed).
- Split volumes larger than the memory budget are joined in a temporary file first.
- Stopping r7z with Ctrl-C while creating can leave a `*.r7z-tmp-<pid>` file next to the
  target archive.
