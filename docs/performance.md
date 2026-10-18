# Performance

## 7z

These numbers compare r7z with 7-Zip 25.01 x64 on one machine: Windows 11, 16 logical
cores, 32 GB RAM, NVMe SSD. Each tool uses its defaults with `-bd`. Creation runs once;
`t` and `x` take the best of 3 warm runs. Reproduce with `scripts/compare.py`.

`rea` is a Node.js tool install (87 MB, 6,554 files, mostly JavaScript).
`node` is a Node.js 24 distribution (107 MB, dominated by one 80 MB executable).

| Input | Level | Tool | Create | CPU | Peak mem | Size | Test | Extract |
|---|---|---|---|---|---|---|---|---|
| rea | mx1 | r7z | 1.46 s | 7.8 s | 84 MiB | 17.02 MB | 0.17 s | **0.88 s** |
| rea | mx1 | 7-Zip | 1.47 s | 5.5 s | 75 MiB | 16.78 MB | 0.10 s | 4.93 s |
| rea | mx5 | r7z | **7.91 s** | 66.3 s | 1849 MiB | 9.60 MB | 0.41 s | **1.24 s** |
| rea | mx5 | 7-Zip | 13.98 s | 19.2 s | 390 MiB | 9.08 MB | 0.35 s | 5.11 s |
| rea | mx9 | r7z | 32.80 s | 34.0 s | 911 MiB | 8.84 MB | 0.42 s | **1.09 s** |
| rea | mx9 | 7-Zip | 16.71 s | 23.8 s | 930 MiB | 8.84 MB | 0.34 s | 5.15 s |
| node | mx1 | r7z | 1.33 s | 11.6 s | 83 MiB | 30.39 MB | 0.27 s | **0.46 s** |
| node | mx1 | 7-Zip | 1.25 s | 10.1 s | 77 MiB | 30.16 MB | 0.18 s | 1.74 s |
| node | mx5 | r7z | **12.53 s** | 85.8 s | 1808 MiB | 24.86 MB | 1.07 s | **1.22 s** |
| node | mx5 | 7-Zip | 16.16 s | 26.4 s | 388 MiB | 24.66 MB | 0.88 s | 2.46 s |
| node | mx9 | r7z | 41.98 s | 42.2 s | 940 MiB | 24.47 MB | 1.10 s | **1.24 s** |
| node | mx9 | 7-Zip | 16.36 s | 28.6 s | 940 MiB | 23.67 MB | 0.89 s | 2.45 s |

How to read this:

- **Extraction is 2-5.6x faster.** Most of extraction time goes into creating, writing and
  closing files. r7z hands small files to a pool of writer threads, sets timestamps on the
  open handle instead of reopening, and only creates directories that are missing.
- **The default level (mx5) creates archives 1.3-1.8x faster, 0.8-5.7% larger, using
  about 4.7x more memory.** See "How the parallel encoder works" below.
- **mx9 is 2-2.6x slower.** The input fits in one LZMA2 block (4x the dictionary, 1 GiB
  at mx9), and 7-Zip runs a separate match-finder thread per block, which r7z's encoder
  does not have yet. Inputs larger than one block compress in parallel. On text, mx9
  output is the same size as 7-Zip's. On executables 7-Zip's mx9 uses BCJ2, which r7z
  can decode but not yet encode, so its output is 3.4% smaller on the `node` corpus.
- **Raw decoding is 15-20% slower** (the `Test` column). This is the pure-Rust LZMA decoder
  (`lzma-rust2`) against 7-Zip's hand-tuned C and assembly. Archives that r7z writes with
  several blocks decode in parallel.
- mx1 is on par in speed, with about 1% larger output.
- **Why mx7-9 aren't split like mx5.** Splitting a group into sub-blocks primed with the
  whole dictionary keeps the ratio (within 0.03%), but priming a byte through the bt4
  match finder costs nearly as much as encoding it. On `rea` at mx9: 1 sub-block 32.4 s
  and 911 MiB; 2 sub-blocks 30.4 s and 1311 MiB; 3 sub-blocks 30.6 s and 1514 MiB; 4
  sub-blocks 38.2 s. Closing this gap needs a match finder on its own thread, as 7-Zip
  has.

### Since 0.1.8

Measured back to back on the same machine and `rea` tree (best of 5 runs each):

| | 0.1.8 | Now |
|---|---|---|
| Extract 7-Zip's mx5 `.7z` | 1.13-1.38 s | 0.88-1.15 s |
| Test `.tar.gz` | 0.32 s | 0.23-0.26 s |
| Create zip (mx5) | 0.78-1.11 s, 24.45 MB | 0.49-0.61 s, 24.38 MB |
| Create `.tar.gz` | 1.05-1.06 s, 20.54 MB | 0.86-1.10 s, 20.48 MB |
| Peak memory, extract 7z / zip | 67 / 43 MiB | 83 / 88 MiB |

The ranges are across separate runs on a machine that wasn't idle. Extraction of zip and
`.tar.gz` changed by less than the run-to-run noise. The tables above predate these
changes.

`r7z b` runs a self-contained LZMA2 benchmark (`-mmt`, `-mx`, `-md` apply).

## Other formats

Same machine and `rea` tree as above (6,554 files, 87 MB). 7-Zip cannot create or extract
`.tar.gz` and friends in one run, so its rows chain two 7-Zip processes through a pipe
(`7z a -ttar -so | 7z a -si -tgzip`). Create runs once, extract is the best of 2. Reproduce
the 7z numbers with `scripts/compare.py`.

| Case | Tool | Create | Size | Extract |
|---|---|---|---|---|
| zip mx5 | r7z | **0.82 s** | 24.45 MB | **0.86 s** |
| zip mx5 | 7-Zip | 1.23 s | 23.54 MB | 5.34 s |
| tar.gz | r7z | **1.01 s** | 20.54 MB | **1.05 s** |
| tar.gz | 7-Zip (2 steps) | 8.15 s | 19.79 MB | 5.24 s |
| tar.bz2 | r7z | **1.44 s** | 16.54 MB | **1.56 s** |
| tar.bz2 | 7-Zip (2 steps) | 2.11 s | 15.37 MB | 6.01 s |
| tar.xz | r7z | **7.29 s** | 9.73 MB | **1.43 s** |
| tar.xz | 7-Zip (2 steps) | 13.80 s | 9.17 MB | 5.28 s |

Extraction rows extract archives 7-Zip made. How to read this:

- **Extraction is 3.7-6.2x faster**, for the same reasons as with 7z archives (writer
  threads, handle-based timestamps). zip entries also decode in parallel.
- **zip and gzip are compressed on every core.** zip compresses files concurrently and
  splits large ones; gzip uses chunked Deflate primed with the previous 32 KiB, which
  keeps the output within 4% of 7-Zip's (single-threaded) encoder (7-Zip's Deflate searches
  harder than zlib-style levels; `-mx9` narrows the gap only slightly).
- **bzip2 is compressed and decompressed in parallel.** Output is one bzip2 stream per
  900 kB block, which every bzip2 reader accepts. Decoding finds block boundaries by their
  48-bit magic and decodes blocks on all cores (`t` on 7-Zip's 15 MB `.tar.bz2`: 0.77 s
  against 0.98 s, including the tar check), with a sequential fallback.
- **xz uses the 7z LZMA2 encoder** (parallel primed sub-blocks, one xz block per 4x
  dictionary), so its size and speed track r7z's 7z numbers. Decoding a single-block xz
  file is single-threaded and about 2x slower than 7-Zip's assembly decoder (`t`: 0.76 s
  against 0.39 s); multi-block files decode in parallel.
- A compressed tar is decompressed once: the tar is indexed while it streams, and its
  bytes are kept in memory (up to 1 GiB, or a quarter of free memory) for extraction.
  Larger tars are decompressed a second time instead.

## How the parallel encoder works

LZMA2 data is a sequence of chunks. A chunk can reset the dictionary, which makes the data
after it decodable on its own, or reset only the coder state while keeping the
dictionary.

- **Groups.** r7z resets the dictionary every 4x dictionary size, the same block size
  7-Zip uses. A group is the unit of parallel decoding, in r7z and in 7-Zip.
- **Sub-blocks.** Inside a group, r7z splits the input into sub-blocks and compresses them
  on separate threads. Each sub-block's encoder is primed with the data before it as a
  preset dictionary, and its first chunk resets only the coder state. A normal sequential
  decoder sees one continuous dictionary, so 7-Zip reads these streams unchanged.

Priming costs CPU, because the match finder must index the preset bytes. The level decides
the trade-off:

| Level | Sub-blocks | Measured effect versus 7-Zip |
|---|---|---|
| mx1-4 | independent (no priming) | fastest; larger output on redundant trees |
| mx5-6 | at least 8 MiB, primed with 8 MiB | 1.3-1.8x faster, 0.8-5.7% larger |
| mx7-9 | none within a group | same ratio as single-threaded LZMA2 |

`-m0=LZMA2:c=SIZE` sets the group size, and `-mmt1` gives the single-threaded
encoding. The dictionary per level matches what 7-Zip 25.01 stores: 2^18, 2^20, 2^22 and
2^24 for mx1-4, then 2^(level+20) up to 256 MiB at mx9.

Other speed levers:

- **Decoding.** Independent folders decode in parallel. LZMA2 streams with several groups
  decode their groups in parallel. Input archives are memory-mapped.
- **Inputs.** Small input files are read ahead by helper threads.
- **Hardware.** CRC32 uses PCLMULQDQ, AES uses AES-NI and SHA-256 uses SHA-NI, all chosen at
  runtime by the `crc32fast`, `aes` and `sha2` crates.
- **Encryption.** The 7zAES key is derived once per archive and password, not once per
  folder.
- **Memory.** Encoder threads are capped so their estimated working set stays within half
  of RAM and three quarters of currently free memory.
