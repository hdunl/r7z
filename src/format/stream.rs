//! Single-stream compressors: gzip, bzip2, xz, zstd, lz4, Z (LZW), lzma and lzma86.
//!
//! Each holds one entry whose data is the decompressed stream. They all share
//! [`StreamArchive`]; a handler only parses its header for metadata and supplies a decoder.
//! Because they implement `Archive::stream`, the format layer opens a tar (or any other
//! archive) found inside, so `x.tar.gz` lists as the tar.

use std::io::{self, Cursor, Read};
use std::sync::Arc;

use super::data::{BoxRead, Input, Opener, Slice};
use super::{
    stream_entry_name, Archive, Ctx, Entry, EntryFn, Format, OpenOptions, Signature, Unit,
};
use crate::error::{Error, Result};
use crate::util::time::unix_to_filetime;

/// Turns the raw compressed stream into the decompressed one.
type Decoder = Arc<dyn Fn(BoxRead) -> Result<BoxRead> + Send + Sync>;

/// An archive of one compressed stream.
pub struct StreamArchive {
    fmt: &'static Format,
    input: Opener,
    decoder: Decoder,
    entries: Vec<Entry>,
    units: Vec<Unit>,
    props: Vec<(&'static str, String)>,
}

impl StreamArchive {
    fn boxed(
        fmt: &'static Format,
        input: &Input,
        decoder: Decoder,
        entry: Entry,
        props: Vec<(&'static str, String)>,
    ) -> Box<dyn Archive> {
        Box::new(StreamArchive {
            fmt,
            input: input.opener(),
            decoder,
            entries: vec![entry],
            units: vec![Unit {
                entries: vec![0],
                encrypted: false,
            }],
            props,
        })
    }
}

impl Archive for StreamArchive {
    fn format(&self) -> &'static Format {
        self.fmt
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, _unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let mut r = (self.decoder)((self.input)()?)?;
        f(0, &mut r)?;
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        self.props.clone()
    }

    fn verifies_data(&self) -> bool {
        true
    }

    fn stream(&self, _i: usize) -> Option<Opener> {
        let (input, decoder) = (self.input.clone(), self.decoder.clone());
        Some(Arc::new(move || decoder(input()?)))
    }
}

fn base_entry(name: String, input: &Input) -> Entry {
    Entry {
        name,
        packed_size: match input {
            Input::Mem(s) => Some(s.len() as u64),
            Input::Stream { size_hint, .. } => *size_hint,
        },
        ..Default::default()
    }
}

/// The first `n` bytes of the input (fewer at EOF).
fn head(input: &Input, n: usize) -> Result<Vec<u8>> {
    match input {
        Input::Mem(s) => Ok(s[..s.len().min(n)].to_vec()),
        Input::Stream { open, .. } => {
            let mut r = open()?;
            let mut buf = vec![0u8; n];
            let mut got = 0;
            while got < n {
                let k = super::data::read_some(&mut *r, &mut buf[got..])?;
                if k == 0 {
                    break;
                }
                got += k;
            }
            buf.truncate(got);
            Ok(buf)
        }
    }
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

// ---------------------------------------------------------------------------------------
// gzip

pub static GZIP: Format = Format {
    name: "gzip",
    aliases: &["gz", "tgz"],
    extensions: &["gz", "gzip", "tgz", "tpz", "apk"],
    signatures: &[Signature::at(0, &[0x1F, 0x8B, 0x08])],
    detect: None,
    write: true,
    stream: true,
    sequential: true,
    open: open_gzip,
};

struct GzHeader {
    name: Option<String>,
    mtime: u32,
    os: u8,
    comment: Option<String>,
    len: usize,
}

fn latin1(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => b.iter().map(|&c| c as char).collect(),
    }
}

fn parse_gzip_header(h: &[u8]) -> Result<GzHeader> {
    if h.len() < 10 || h[0] != 0x1F || h[1] != 0x8B || h[2] != 8 {
        return Err(Error::NotArchive);
    }
    let flg = h[3];
    if flg & 0xE0 != 0 {
        return Err(Error::corrupt("gzip header has reserved flags set"));
    }
    let mtime = u32::from_le_bytes(h[4..8].try_into().unwrap());
    let os = h[9];
    let mut p = 10usize;
    let need = |p: usize, n: usize| -> Result<()> {
        if p + n > h.len() {
            Err(Error::corrupt("gzip header truncated"))
        } else {
            Ok(())
        }
    };
    if flg & 4 != 0 {
        need(p, 2)?;
        let xlen = u16::from_le_bytes([h[p], h[p + 1]]) as usize;
        need(p + 2, xlen)?;
        p += 2 + xlen;
    }
    let zstr = |p: &mut usize| -> Result<String> {
        let end = h[*p..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::corrupt("gzip header string unterminated"))?;
        let s = latin1(&h[*p..*p + end]);
        *p += end + 1;
        Ok(s)
    };
    let name = if flg & 8 != 0 {
        Some(zstr(&mut p)?)
    } else {
        None
    };
    let comment = if flg & 16 != 0 {
        Some(zstr(&mut p)?)
    } else {
        None
    };
    if flg & 2 != 0 {
        need(p, 2)?;
        p += 2;
    }
    Ok(GzHeader {
        name,
        mtime,
        os,
        comment,
        len: p,
    })
}

fn host_os(os: u8) -> &'static str {
    match os {
        0 => "FAT",
        3 => "Unix",
        7 => "Macintosh",
        10 => "NTFS",
        11 => "NTFS",
        _ => "Unknown",
    }
}

fn open_gzip(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let h = head(&input, 65536)?;
    let hdr = parse_gzip_header(&h)?;
    let name = hdr
        .name
        .as_deref()
        .map(|n| n.rsplit(['/', '\\']).next().unwrap_or(n).to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| stream_entry_name(&opts.name, &["gz", "gzip"], &["tgz", "tpz", "apk"]));
    let mut e = base_entry(name, &input);
    if hdr.mtime != 0 {
        e.mtime = Some(unix_to_filetime(hdr.mtime as i64));
    }
    e.method = Some("Deflate".into());
    e.comment = hdr.comment.clone();
    if let Input::Mem(s) = &input {
        if s.len() >= 18 {
            let t = &s[s.len() - 8..];
            e.crc = Some(u32::from_le_bytes(t[..4].try_into().unwrap()));
            e.size = Some(u32::from_le_bytes(t[4..].try_into().unwrap()) as u64);
        }
    }
    let props = vec![
        ("Headers Size", hdr.len.to_string()),
        ("Host OS", host_os(hdr.os).into()),
    ];
    let dec: Decoder = Arc::new(|r| Ok(Box::new(flate2::read::MultiGzDecoder::new(r)) as BoxRead));
    // The CRC shown is the last member's; the decoder checks every member itself.
    Ok(StreamArchive::boxed(&GZIP, &input, dec, e, props))
}

// ---------------------------------------------------------------------------------------
// bzip2

pub static BZIP2: Format = Format {
    name: "bzip2",
    aliases: &["bz2", "tbz", "tbz2"],
    extensions: &["bz2", "bzip2", "tbz2", "tbz"],
    signatures: &[Signature::at(0, b"BZh")],
    detect: Some(detect_bzip2),
    write: true,
    stream: true,
    sequential: true,
    open: open_bzip2,
};

fn detect_bzip2(h: &[u8]) -> bool {
    h.len() >= 10
        && (b'1'..=b'9').contains(&h[3])
        && (h[4..10] == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
            || h[4..10] == [0x17, 0x72, 0x45, 0x38, 0x50, 0x90])
}

fn open_bzip2(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let h = head(&input, 10)?;
    if !detect_bzip2(&h) {
        return Err(Error::NotArchive);
    }
    let mut e = base_entry(
        stream_entry_name(&opts.name, &["bz2", "bzip2"], &["tbz2", "tbz"]),
        &input,
    );
    e.method = Some(format!("BZip2:{}", (h[3] - b'0') as u32 * 100));
    let dec: Decoder = match &input {
        // Blocks decode in parallel when the whole file is at hand.
        Input::Mem(s) if s.len() > 1 << 20 && crate::util::default_threads() > 1 => {
            let s = s.clone();
            Arc::new(move |_r| {
                let threads = crate::util::default_threads();
                Ok(Box::new(crate::codec::bzip2par::ParBzip2Reader::new(
                    s.clone(),
                    threads,
                )) as BoxRead)
            })
        }
        _ => Arc::new(|r| Ok(Box::new(bzip2::read::MultiBzDecoder::new(r)) as BoxRead)),
    };
    Ok(StreamArchive::boxed(&BZIP2, &input, dec, e, Vec::new()))
}

// ---------------------------------------------------------------------------------------
// xz

pub static XZ: Format = Format {
    name: "xz",
    aliases: &["txz"],
    extensions: &["xz", "txz"],
    signatures: &[Signature::at(0, &[0xFD, b'7', b'z', b'X', b'Z', 0])],
    detect: None,
    write: true,
    stream: true,
    sequential: true,
    open: open_xz,
};

/// Totals from the xz indexes, walked from the end of the file.
struct XzIndex {
    unpacked: u64,
    blocks: u64,
    streams: u64,
    check: u8,
}

fn xz_vli(b: &[u8], p: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..9 {
        let c = *b.get(*p)?;
        *p += 1;
        v |= ((c & 0x7F) as u64) << (7 * i);
        if c & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

fn xz_index(data: &[u8]) -> Option<XzIndex> {
    let mut end = data.len();
    let mut idx = XzIndex {
        unpacked: 0,
        blocks: 0,
        streams: 0,
        check: 0,
    };
    while end > 0 {
        // Stream padding is zero bytes in multiples of four.
        while end >= 4 && data[end - 4..end] == [0, 0, 0, 0] {
            end -= 4;
        }
        if end < 24 {
            return None;
        }
        let footer = &data[end - 12..end];
        if &footer[10..12] != b"YZ"
            || crc32fast::hash(&footer[4..10]) != u32::from_le_bytes(footer[..4].try_into().ok()?)
        {
            return None;
        }
        let index_size = (u32::from_le_bytes(footer[4..8].try_into().ok()?) as usize + 1) * 4;
        idx.check = footer[9] & 0x0F;
        let index_start = (end - 12).checked_sub(index_size)?;
        let index = &data[index_start..end - 12];
        let mut p = 1usize;
        if index.first() != Some(&0) {
            return None;
        }
        let n = xz_vli(index, &mut p)?;
        let mut blocks_size = 0u64;
        for _ in 0..n {
            let unpadded = xz_vli(index, &mut p)?;
            let unpacked = xz_vli(index, &mut p)?;
            blocks_size = blocks_size.checked_add(unpadded.checked_add(3)? & !3)?;
            idx.unpacked = idx.unpacked.checked_add(unpacked)?;
        }
        idx.blocks += n;
        idx.streams += 1;
        let start = (index_start as u64)
            .checked_sub(blocks_size)?
            .checked_sub(12)?;
        if data.get(start as usize..start as usize + 6)? != [0xFD, b'7', b'z', b'X', b'Z', 0] {
            return None;
        }
        end = start as usize;
    }
    Some(idx)
}

fn open_xz(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let h = head(&input, 12)?;
    if h.len() < 12 || !XZ.signatures[0].matches(&h) {
        return Err(Error::NotArchive);
    }
    let mut e = base_entry(stream_entry_name(&opts.name, &["xz"], &["txz"]), &input);
    let check = h[7] & 0x0F;
    let mut blocks = 0;
    let mut props = Vec::new();
    if let Input::Mem(s) = &input {
        if let Some(ix) = xz_index(s) {
            e.size = Some(ix.unpacked);
            blocks = ix.blocks;
            props.push(("Blocks", ix.blocks.to_string()));
            if ix.streams > 1 {
                props.push(("Streams", ix.streams.to_string()));
            }
        }
    }
    let check_name = match check {
        0 => "",
        1 => " CRC32",
        4 => " CRC64",
        10 => " SHA256",
        _ => " check?",
    };
    e.method = Some(format!("LZMA2{check_name}"));
    props.push(("Method", format!("LZMA2{check_name}")));
    let dec: Decoder = match &input {
        // Several independent blocks decode in parallel.
        Input::Mem(s) if blocks > 1 && crate::util::default_threads() > 1 => {
            let s = s.clone();
            Arc::new(move |_r| {
                let threads = crate::util::default_threads() as u32;
                let rd = lzma_rust2::XzReaderMt::new(Cursor::new(s.clone()), true, threads)
                    .map_err(super::data::data_err)?;
                Ok(Box::new(rd) as BoxRead)
            })
        }
        _ => Arc::new(|r| Ok(Box::new(lzma_rust2::XzReader::new(r, true)) as BoxRead)),
    };
    Ok(StreamArchive::boxed(&XZ, &input, dec, e, props))
}

// ---------------------------------------------------------------------------------------
// zstd

pub static ZSTD: Format = Format {
    name: "zstd",
    aliases: &["zst", "tzst"],
    extensions: &["zst", "tzst", "zstd"],
    signatures: &[Signature::at(0, &[0x28, 0xB5, 0x2F, 0xFD])],
    detect: None,
    write: false,
    stream: true,
    sequential: true,
    open: open_zstd,
};

/// Decodes concatenated zstd frames, skipping skippable frames.
pub struct ZstdReader<R: Read> {
    src: R,
    dec: ruzstd::decoding::FrameDecoder,
    in_frame: bool,
}

impl<R: Read> ZstdReader<R> {
    pub fn new(src: R) -> Self {
        ZstdReader {
            src,
            dec: ruzstd::decoding::FrameDecoder::new(),
            in_frame: false,
        }
    }

    fn next_frame(&mut self) -> io::Result<bool> {
        loop {
            // Peek the magic to tell EOF from a new frame.
            let mut magic = [0u8; 4];
            let mut got = 0;
            while got < 4 {
                let k = self.src.read(&mut magic[got..])?;
                if k == 0 {
                    break;
                }
                got += k;
            }
            if got == 0 {
                return Ok(false);
            }
            if got < 4 {
                return Err(io_err("zstd: truncated frame header"));
            }
            let m = u32::from_le_bytes(magic);
            if (0x184D2A50..=0x184D2A5F).contains(&m) {
                let mut len = [0u8; 4];
                self.src.read_exact(&mut len)?;
                let n = u32::from_le_bytes(len) as u64;
                let skipped = io::copy(&mut (&mut self.src).take(n), &mut io::sink())?;
                if skipped != n {
                    return Err(io_err("zstd: truncated skippable frame"));
                }
                continue;
            }
            let mut chained = Cursor::new(magic).chain(&mut self.src);
            self.dec.init(&mut chained).map_err(io_err)?;
            return Ok(true);
        }
    }
}

impl<R: Read> Read for ZstdReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use ruzstd::decoding::BlockDecodingStrategy;
        loop {
            if !self.in_frame {
                if !self.next_frame()? {
                    return Ok(0);
                }
                self.in_frame = true;
            }
            if self.dec.can_collect() > 0 {
                return self.dec.read(buf);
            }
            if self.dec.is_finished() {
                self.in_frame = false;
                continue;
            }
            self.dec
                .decode_blocks(
                    &mut self.src,
                    BlockDecodingStrategy::UptoBytes(buf.len().max(1 << 16)),
                )
                .map_err(io_err)?;
        }
    }
}

fn zstd_content_size(h: &[u8]) -> Option<u64> {
    let fhd = *h.get(4)?;
    let fcs_flag = fhd >> 6;
    let single = fhd & 0x20 != 0;
    let did = [0usize, 1, 2, 4][(fhd & 3) as usize];
    let p = 5 + if single { 0 } else { 1 } + did;
    let n = match (fcs_flag, single) {
        (0, true) => 1,
        (0, false) => return None,
        (1, _) => 2,
        (2, _) => 4,
        _ => 8,
    };
    let b = h.get(p..p + n)?;
    let mut v = 0u64;
    for (i, &x) in b.iter().enumerate() {
        v |= (x as u64) << (8 * i);
    }
    Some(if n == 2 { v + 256 } else { v })
}

fn open_zstd(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let h = head(&input, 18)?;
    if !ZSTD.signatures[0].matches(&h) {
        return Err(Error::NotArchive);
    }
    let mut e = base_entry(
        stream_entry_name(&opts.name, &["zst", "zstd"], &["tzst"]),
        &input,
    );
    e.method = Some("ZSTD".into());
    // A frame's content size is the total only when it is the only frame; trust it for
    // display, the decoder reads to the end either way.
    e.size = zstd_content_size(&h).filter(|_| matches!(input, Input::Mem(_)));
    let dec: Decoder = Arc::new(|r| Ok(Box::new(ZstdReader::new(r)) as BoxRead));
    Ok(StreamArchive::boxed(&ZSTD, &input, dec, e, Vec::new()))
}

// ---------------------------------------------------------------------------------------
// lz4

pub static LZ4: Format = Format {
    name: "lz4",
    aliases: &["tlz4"],
    extensions: &["lz4", "tlz4"],
    signatures: &[
        Signature::at(0, &[0x04, 0x22, 0x4D, 0x18]),
        Signature::at(0, &[0x02, 0x21, 0x4C, 0x18]),
    ],
    detect: None,
    write: false,
    stream: true,
    sequential: true,
    open: open_lz4,
};

const LZ4_LEGACY: u32 = 0x184C_2102;

fn open_lz4(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let h = head(&input, 15)?;
    if LZ4.signatures[1].matches(&h) {
        let mut e = base_entry(stream_entry_name(&opts.name, &["lz4"], &["tlz4"]), &input);
        e.method = Some("LZ4 legacy".into());
        let dec: Decoder = Arc::new(|r| Ok(Box::new(Lz4Legacy::new(r)) as BoxRead));
        return Ok(StreamArchive::boxed(&LZ4, &input, dec, e, Vec::new()));
    }
    if !LZ4.signatures[0].matches(&h) || h.len() < 7 {
        return Err(Error::NotArchive);
    }
    let mut e = base_entry(stream_entry_name(&opts.name, &["lz4"], &["tlz4"]), &input);
    e.method = Some("LZ4".into());
    if h[4] & 0x08 != 0 && h.len() >= 14 && matches!(input, Input::Mem(_)) {
        e.size = Some(u64::from_le_bytes(h[6..14].try_into().unwrap()));
    }
    let dec: Decoder = Arc::new(|r| {
        let consumed = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let counted = Counted {
            inner: r,
            n: consumed.clone(),
        };
        Ok(Box::new(Lz4Frames {
            dec: lz4_flex::frame::FrameDecoder::new(counted),
            consumed,
        }) as BoxRead)
    });
    Ok(StreamArchive::boxed(&LZ4, &input, dec, e, Vec::new()))
}

/// The legacy LZ4 format (`lz4 -l`, Linux kernels): a magic, then blocks of at most 8 MiB
/// output, each `u32le compressed size` + data; a repeated magic starts a new frame.
struct Lz4Legacy {
    src: BoxRead,
    out: Vec<u8>,
    pos: usize,
    started: bool,
    done: bool,
}

impl Lz4Legacy {
    fn new(src: BoxRead) -> Self {
        Lz4Legacy {
            src,
            out: Vec::new(),
            pos: 0,
            started: false,
            done: false,
        }
    }

    fn word(&mut self) -> io::Result<Option<u32>> {
        let mut b = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            let k = self.src.read(&mut b[got..])?;
            if k == 0 {
                break;
            }
            got += k;
        }
        match got {
            0 => Ok(None),
            4 => Ok(Some(u32::from_le_bytes(b))),
            _ => Err(io_err("lz4: truncated block header")),
        }
    }
}

impl Read for Lz4Legacy {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        const MAX_OUT: usize = 8 << 20;
        while self.pos == self.out.len() {
            if self.done {
                return Ok(0);
            }
            if !self.started {
                self.started = true;
                if self.word()? != Some(LZ4_LEGACY) {
                    return Err(io_err("lz4: bad legacy magic"));
                }
            }
            let Some(n) = self.word()? else {
                self.done = true;
                return Ok(0);
            };
            if n == LZ4_LEGACY {
                continue;
            }
            // Block sizes are bounded by the compressed size of an 8 MiB block.
            if n as usize > MAX_OUT + MAX_OUT / 255 + 16 {
                return Err(io_err("lz4: block size out of range"));
            }
            let mut block = vec![0u8; n as usize];
            self.src.read_exact(&mut block)?;
            self.out.resize(MAX_OUT, 0);
            let got = lz4_flex::block::decompress_into(&block, &mut self.out).map_err(io_err)?;
            self.out.truncate(got);
            self.pos = 0;
        }
        let k = (self.out.len() - self.pos).min(buf.len());
        buf[..k].copy_from_slice(&self.out[self.pos..self.pos + k]);
        self.pos += k;
        Ok(k)
    }
}

/// Counts bytes read from the inner reader.
struct Counted {
    inner: BoxRead,
    n: Arc<std::sync::atomic::AtomicU64>,
}

impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let k = self.inner.read(buf)?;
        self.n
            .fetch_add(k as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(k)
    }
}

/// lz4_flex returns end-of-data at each frame end; continue while input remains.
struct Lz4Frames {
    dec: lz4_flex::frame::FrameDecoder<Counted>,
    consumed: Arc<std::sync::atomic::AtomicU64>,
}

impl Read for Lz4Frames {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let before = self.consumed.load(std::sync::atomic::Ordering::Relaxed);
            let n = self.dec.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            if self.consumed.load(std::sync::atomic::Ordering::Relaxed) == before {
                return Ok(0);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// Z (Unix compress, LZW)

pub static Z: Format = Format {
    name: "Z",
    aliases: &["compress", "taz"],
    extensions: &["z", "taz"],
    signatures: &[Signature::at(0, &[0x1F, 0x9D])],
    detect: Some(|h| h.len() >= 3 && (9..=16).contains(&(h[2] & 0x1F)) && h[2] & 0x60 == 0),
    write: false,
    stream: true,
    sequential: true,
    open: open_z,
};

fn open_z(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let h = head(&input, 3)?;
    if !Z.signatures[0].matches(&h) || !(Z.detect.unwrap())(&h) {
        return Err(Error::NotArchive);
    }
    let mut e = base_entry(stream_entry_name(&opts.name, &["z"], &["taz"]), &input);
    e.method = Some(format!("LZW:{}", h[2] & 0x1F));
    let dec: Decoder = Arc::new(|r| Ok(Box::new(crate::codec::lzw::LzwReader::new(r)?) as BoxRead));
    Ok(StreamArchive::boxed(&Z, &input, dec, e, Vec::new()))
}

// ---------------------------------------------------------------------------------------
// lzma (LZMA "alone") and lzma86

pub static LZMA: Format = Format {
    name: "lzma",
    aliases: &[],
    extensions: &["lzma"],
    signatures: &[],
    detect: Some(lzma_header_ok),
    write: false,
    stream: true,
    sequential: true,
    open: open_lzma,
};

pub static LZMA86: Format = Format {
    name: "lzma86",
    aliases: &[],
    extensions: &["lzma86"],
    signatures: &[],
    detect: Some(|h| h.len() > 1 && h[0] <= 1 && lzma_header_ok(&h[1..])),
    write: false,
    stream: true,
    sequential: true,
    open: open_lzma86,
};

/// Plausibility check for a 13-byte LZMA header: valid lc/lp/pb, a dictionary size 7-Zip
/// would write, and a size that is either unknown or below 2^56.
fn lzma_header_ok(h: &[u8]) -> bool {
    if h.len() < 13 || h[0] >= 9 * 5 * 5 {
        return false;
    }
    let dict = u32::from_le_bytes(h[1..5].try_into().unwrap());
    let size = u64::from_le_bytes(h[5..13].try_into().unwrap());
    let dict_ok = (12..=31).any(|b| dict == 1 << b || dict == 3 << (b - 1)) || dict == u32::MAX;
    dict_ok && (size == u64::MAX || size < 1 << 56)
}

fn lzma_entry(input: &Input, h: &[u8], name: String) -> Entry {
    let mut e = base_entry(name, input);
    let size = u64::from_le_bytes(h[5..13].try_into().unwrap());
    if size != u64::MAX {
        e.size = Some(size);
    }
    let dict = u32::from_le_bytes(h[1..5].try_into().unwrap());
    e.method = Some(format!(
        "LZMA:{}",
        crate::util::fmt::dict_label(dict as u64)
    ));
    e
}

fn lzma_reader(r: BoxRead) -> Result<BoxRead> {
    let rd =
        lzma_rust2::LzmaReader::new_mem_limit(r, u32::MAX, None).map_err(super::data::data_err)?;
    Ok(Box::new(rd))
}

fn open_lzma(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let h = head(&input, 13)?;
    if !lzma_header_ok(&h) {
        return Err(Error::NotArchive);
    }
    let e = lzma_entry(&input, &h, stream_entry_name(&opts.name, &["lzma"], &[]));
    let dec: Decoder = Arc::new(lzma_reader);
    Ok(StreamArchive::boxed(&LZMA, &input, dec, e, Vec::new()))
}

fn open_lzma86(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let h = head(&input, 14)?;
    if h.len() < 14 || h[0] > 1 || !lzma_header_ok(&h[1..]) {
        return Err(Error::NotArchive);
    }
    let mut e = lzma_entry(
        &input,
        &h[1..],
        stream_entry_name(&opts.name, &["lzma86"], &[]),
    );
    let bcj = h[0] == 1;
    if bcj {
        e.method = Some(format!("{} BCJ", e.method.unwrap()));
    }
    let dec: Decoder = Arc::new(move |mut r| {
        let mut flag = [0u8; 1];
        super::data::read_exact(&mut r, &mut flag)?;
        let lz = lzma_reader(r)?;
        Ok(if bcj {
            Box::new(lzma_rust2::filter::bcj::BcjReader::new_x86(lz, 0)) as BoxRead
        } else {
            lz
        })
    });
    Ok(StreamArchive::boxed(&LZMA86, &input, dec, e, Vec::new()))
}

/// Exposes `data` as a single-stream "archive" (used by split and base64).
pub fn plain(
    fmt: &'static Format,
    data: Slice,
    name: String,
    props: Vec<(&'static str, String)>,
) -> Box<dyn Archive> {
    let input = Input::Mem(data);
    let mut e = base_entry(name, &input);
    e.size = e.packed_size;
    let dec: Decoder = Arc::new(Ok);
    StreamArchive::boxed(fmt, &input, dec, e, props)
}
