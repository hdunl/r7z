# Damaged archives

`r7z x damaged.zip -recover -oRescued` (also `e` and `t`) extracts every file that can still
be read, instead of stopping at the first error, and then says what became of the rest:

```text
$ r7z x pics-cut.zip -recover -oout        # the last 40% of the download is missing
warning: the central directory is unusable (zip central directory not found (truncated archive?)); rebuilt the file list from 111 local headers
warning: pics/img26.jpg: the file ends inside this entry (482056 of 917673 bytes present)
  pics/img26.jpg: partial (kept): incomplete deflate stream
warning: Recovered: 93 of 94 files, 15.8 MiB in 35 ms, 1 partial
```

Each file comes out *recovered* (complete and, where the format has one, checksum
verified), *partial* (the readable part is written under the file's own name, and the
reason is given) or *lost*. The exit code is 0 when nothing was damaged, 1 when something
was recovered and 2 when nothing could be. What it can do per format:

- **zip:** without a usable central directory (a truncated download, or one that has been
  zeroed or overwritten), the file list is rebuilt from the local header in front of each
  entry, so names, times, ZIP64 sizes and encryption all still work. Entries written with
  data descriptors are delimited by decoding their Deflate stream, or by finding the
  descriptor whose size matches. Every entry whose data decodes and passes its CRC is
  extracted. Bytes that belong to no entry are reported with their offset.
- **7z:** a damaged or zeroed start header (an interrupted write leaves one) is worked
  around by scanning for the archive header, and a header whose CRC no longer matches is
  read anyway. Damage inside the data stays local: non-solid blocks decode independently,
  in a solid block the files before the damage are kept, and decoding resumes at the
  next LZMA2 dictionary reset, so files after the damaged part are not lost with it. 7-Zip
  writes such resets between the blocks it compresses on separate threads; a block
  written as one LZMA2 stream has none, and every file after the damage in it is lost
  (with any tool). When the header is gone entirely (a download cut short), the packed
  data is decoded as a raw LZMA2 stream. File names are lost then, but a single-file
  archive such as `disk.iso.7z` gives back `disk.iso` up to the cut.
- **gzip, bzip2, xz and the other stream formats:** the data up to the damage is kept
  and the report says after how many bytes decoding stopped. An archive inside (a
  `.tar.gz`) is then read as far as that data goes.
- **tar:** after a damaged header, reading resumes at the next valid header. An entry cut
  off by the end of the data is kept as partial.

The library side is `r7z::ops::recover` (`recover_file`, or `format::open_recover` plus
`recover`), which returns the outcome of each entry and the notes.
