//! Microsoft Cabinet (CAB), read-only.
//!
//! A cabinet holds folders (solid streams of CFDATA blocks, each block compressed on its
//! own but sharing the decoder state of its folder) and files placed at offsets inside
//! them. Each folder is one unit. Multi-cabinet sets are followed through the previous and
//! next cabinet names when those files sit next to the opened one; a folder can then span
//! volumes, and a block split between two volumes is rejoined before decoding.

use std::collections::VecDeque;
use std::io::{self, Read};
use std::path::Path;

use super::data::{self, Slice};
use super::{
    Archive, Columns, Ctx, Entry, EntryFn, Flow, Format, Input, OpenOptions, Signature, Unit,
};
use crate::codec::lzx::Lzx;
use crate::codec::mszip::MsZip;
use crate::codec::quantum::Quantum;
use crate::error::{Error, Result};
use crate::sevenz::attr;
use crate::util::time::dos_to_filetime;

pub static FORMAT: Format = Format {
    name: "Cab",
    aliases: &[],
    extensions: &["cab"],
    signatures: &[Signature::at(0, b"MSCF\0\0\0\0")],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

const FLAG_PREV: u16 = 1;
const FLAG_NEXT: u16 = 2;
const FLAG_RESERVE: u16 = 4;
const NAME_IS_UTF8: u16 = 0x80;
/// Folder indexes of files whose data spans cabinets.
const FROM_PREV: u16 = 0xFFFD;
const TO_NEXT: u16 = 0xFFFE;
const PREV_AND_NEXT: u16 = 0xFFFF;
/// A set never has more cabinets than `iCabinet` can number.
const MAX_VOLUMES: usize = 1 << 16;

const METHOD_NONE: u16 = 0;
const METHOD_MSZIP: u16 = 1;
const METHOD_QUANTUM: u16 = 2;
const METHOD_LZX: u16 = 3;

/// The method name as 7-Zip prints it: `None`, `MSZip`, `Quantum:21`, `LZX:21`.
fn method_name(method: u16, param: u16) -> String {
    match method {
        METHOD_NONE => "None".into(),
        METHOD_MSZIP => "MSZip".into(),
        METHOD_QUANTUM => format!("Quantum:{param}"),
        METHOD_LZX => format!("LZX:{param}"),
        m => m.to_string(),
    }
}

struct RawFolder {
    /// Offset of the first CFDATA block in the cabinet.
    start: u32,
    blocks: u16,
    /// `typeCompress`: method in the low nibble, window bits (LZX, Quantum) in the high byte.
    ctype: u16,
}

impl RawFolder {
    fn method(&self) -> u16 {
        self.ctype & 0xF
    }

    fn param(&self) -> u16 {
        self.ctype >> 8
    }
}

struct RawFile {
    size: u32,
    offset: u32,
    folder: u16,
    date: u16,
    time: u16,
    attrib: u16,
    name: Vec<u8>,
}

/// One parsed cabinet file.
struct Volume {
    data: Slice,
    /// `cbCabinet`.
    size: u32,
    set_id: u16,
    index: u16,
    prev: Option<Vec<u8>>,
    next: Option<Vec<u8>>,
    data_reserve: usize,
    folders: Vec<RawFolder>,
    files: Vec<RawFile>,
}

/// Bounds-checked little-endian reads over header bytes.
struct Cur<'a> {
    d: &'a [u8],
    pos: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.d.len())
            .ok_or_else(|| Error::corrupt("CAB header is truncated"))?;
        let s = &self.d[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// A NUL-terminated string (without the NUL).
    fn cstr(&mut self) -> Result<&'a [u8]> {
        let rest = self.d.get(self.pos..).unwrap_or(&[]);
        let n = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::corrupt("CAB header is truncated"))?;
        let s = &rest[..n];
        self.pos += n + 1;
        Ok(s)
    }
}

impl Volume {
    fn parse(data: Slice) -> Result<Volume> {
        let d: &[u8] = &data;
        if !FORMAT.signatures[0].matches(d) {
            return Err(Error::NotArchive);
        }
        let mut c = Cur { d, pos: 8 };
        let size = c.u32()?;
        c.u32()?;
        let files_at = c.u32()?;
        c.take(6)?; // reserved3, versionMinor, versionMajor
        let n_folders = c.u16()?;
        let n_files = c.u16()?;
        let flags = c.u16()?;
        let set_id = c.u16()?;
        let index = c.u16()?;
        let (mut folder_reserve, mut data_reserve) = (0, 0);
        if flags & FLAG_RESERVE != 0 {
            let header_reserve = c.u16()?;
            folder_reserve = c.u8()? as usize;
            data_reserve = c.u8()? as usize;
            c.take(header_reserve as usize)?;
        }
        let mut link = |flag: u16| -> Result<Option<Vec<u8>>> {
            if flags & flag == 0 {
                return Ok(None);
            }
            let name = c.cstr()?.to_vec();
            c.cstr()?; // disk label
            Ok(Some(name))
        };
        let prev = link(FLAG_PREV)?;
        let next = link(FLAG_NEXT)?;
        let mut folders = Vec::with_capacity(n_folders as usize);
        for _ in 0..n_folders {
            folders.push(RawFolder {
                start: c.u32()?,
                blocks: c.u16()?,
                ctype: c.u16()?,
            });
            c.take(folder_reserve)?;
        }
        let mut c = Cur {
            d,
            pos: files_at as usize,
        };
        let mut files = Vec::with_capacity(n_files as usize);
        for _ in 0..n_files {
            files.push(RawFile {
                size: c.u32()?,
                offset: c.u32()?,
                folder: c.u16()?,
                date: c.u16()?,
                time: c.u16()?,
                attrib: c.u16()?,
                name: c.cstr()?.to_vec(),
            });
        }
        Ok(Volume {
            data,
            size,
            set_id,
            index,
            prev,
            next,
            data_reserve,
            folders,
            files,
        })
    }

    /// The first folder continues the previous cabinet's last one.
    fn has_prev_folder(&self) -> bool {
        !self.folders.is_empty()
            && self
                .files
                .iter()
                .any(|f| f.folder == FROM_PREV || f.folder == PREV_AND_NEXT)
    }

    /// The folder index a file's data starts in, resolving the spanning markers.
    fn local_folder(&self, f: &RawFile) -> Option<usize> {
        let n = self.folders.len();
        match f.folder {
            FROM_PREV | PREV_AND_NEXT => (n > 0).then_some(0),
            TO_NEXT => n.checked_sub(1),
            i if (i as usize) < n => Some(i as usize),
            _ => None,
        }
    }
}

/// Opens a sibling cabinet named inside a cabinet header (only its file name is used).
fn load_sibling(dir: &Path, raw_name: &[u8]) -> std::result::Result<Volume, String> {
    let name = crate::util::text::ansi(raw_name);
    let base = name.rsplit(['/', '\\']).next().unwrap_or("").to_string();
    if base.is_empty() || base == "." || base == ".." {
        return Err(name);
    }
    let data = Slice::map_file(&dir.join(&base)).map_err(|_| base.clone())?;
    Volume::parse(data).map_err(|_| base)
}

/// The cabinets of the set around `first`, in order, and the opened one's position.
/// Records the name of the first cabinet that could not be opened.
fn collect_volumes(
    first: Volume,
    dir: Option<&Path>,
    missing: &mut Option<String>,
) -> (Vec<Volume>, usize) {
    let mut vols = VecDeque::from([first]);
    let mut opened = 0;
    let Some(dir) = dir else {
        return (vols.into(), 0);
    };
    // Backwards: the previous name may point at the first cabinet of the spanning folder
    // rather than the adjacent one, so walk forward from it until the chain joins up.
    'back: while let Some(prev) = vols[0].prev.clone() {
        let target = vols[0].index as u32;
        let set_id = vols[0].set_id;
        let mut chain: Vec<Volume> = Vec::new();
        let mut name = prev;
        loop {
            let v = match load_sibling(dir, &name) {
                Ok(v) => v,
                Err(n) => {
                    missing.get_or_insert(n);
                    break 'back;
                }
            };
            let in_order = chain
                .last()
                .is_none_or(|l| v.index as u32 == l.index as u32 + 1);
            if v.set_id != set_id
                || v.index as u32 >= target
                || !in_order
                || vols.len() + chain.len() >= MAX_VOLUMES
            {
                break 'back;
            }
            let joins = v.index as u32 + 1 == target;
            let next = v.next.clone();
            chain.push(v);
            if joins {
                break;
            }
            match next {
                Some(n) => name = n,
                None => break 'back,
            }
        }
        opened += chain.len();
        for v in chain.into_iter().rev() {
            vols.push_front(v);
        }
    }
    while let Some(next) = vols.back().and_then(|b| b.next.clone()) {
        let back = vols.back().unwrap();
        match load_sibling(dir, &next) {
            Ok(v)
                if v.set_id == back.set_id
                    && v.index as u32 == back.index as u32 + 1
                    && vols.len() < MAX_VOLUMES =>
            {
                vols.push_back(v)
            }
            Ok(_) => break,
            Err(n) => {
                missing.get_or_insert(n);
                break;
            }
        }
    }
    (vols.into(), opened)
}

/// A folder of the whole set: its pieces in each cabinet, in order.
struct Folder {
    ctype: u16,
    /// `(volume, folder index in that volume)`.
    segments: Vec<(usize, usize)>,
    /// The folder starts in a cabinet that is not part of the opened set.
    missing_start: bool,
}

enum Source {
    Folder(usize),
    /// Files whose folder index names no folder.
    Invalid,
}

pub struct Cab {
    vols: Vec<Volume>,
    opened: usize,
    folders: Vec<Folder>,
    entries: Vec<Entry>,
    /// Each entry's offset in its folder's uncompressed stream.
    offsets: Vec<u64>,
    units: Vec<Unit>,
    sources: Vec<Source>,
    /// A cabinet of the set that could not be opened.
    missing: Option<String>,
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let first = Volume::parse(input.into_mem()?)?;
    let dir = opts.path.as_deref().and_then(Path::parent);
    let mut missing = None;
    let (vols, opened) = collect_volumes(first, dir, &mut missing);
    Ok(Box::new(Cab::new(vols, opened, missing)))
}

/// Folder-index bookkeeping for one file of the set.
struct Item {
    vol: usize,
    file: usize,
    /// 7-Zip's set-wide folder number (`-1` for a folder continued from a missing cabinet),
    /// used for ordering and the `Block` column.
    key: i64,
    folder: Option<usize>,
}

impl Cab {
    fn new(vols: Vec<Volume>, opened: usize, missing: Option<String>) -> Cab {
        // Number folders across the set: a cabinet whose first folder continues the
        // previous cabinet's last one shares that folder.
        let shift = vols[0].has_prev_folder() as i64;
        let mut folders: Vec<Folder> = Vec::new();
        let mut starts = Vec::with_capacity(vols.len());
        let mut next_id = 0i64;
        // After each volume, `folders.len() == next_id + shift`.
        for (v, vol) in vols.iter().enumerate() {
            let prev = vol.has_prev_folder();
            let cont = prev && (v == 0 || !folders.is_empty());
            let start = next_id - cont as i64;
            starts.push(start);
            for (k, rf) in vol.folders.iter().enumerate() {
                if k == 0 && cont && v > 0 {
                    folders.last_mut().unwrap().segments.push((v, k));
                } else {
                    folders.push(Folder {
                        ctype: rf.ctype,
                        segments: vec![(v, k)],
                        // Continued data with no earlier piece in the set.
                        missing_start: k == 0 && prev,
                    });
                }
            }
            next_id += vol.folders.len() as i64 - cont as i64;
        }

        let mut items = Vec::new();
        for (v, vol) in vols.iter().enumerate() {
            for (i, f) in vol.files.iter().enumerate() {
                let local = vol.local_folder(f);
                items.push(Item {
                    vol: v,
                    file: i,
                    key: starts[v] + local.map_or(f.folder as i64, |l| l as i64),
                    folder: local.map(|l| (starts[v] + l as i64 + shift) as usize),
                });
            }
        }
        // 7-Zip's order: directories first, then by folder and offset; the copies of a file
        // listed in each cabinet it spans collapse into one.
        let file = |it: &Item| &vols[it.vol].files[it.file];
        items.sort_by(|a, b| {
            let (fa, fb) = (file(a), file(b));
            let dir = |f: &RawFile| f.attrib as u32 & attr::DIRECTORY == 0;
            (dir(fa), a.key, fa.offset, fa.size, a.vol, a.file).cmp(&(
                dir(fb),
                b.key,
                fb.offset,
                fb.size,
                b.vol,
                b.file,
            ))
        });
        items.dedup_by(|b, a| {
            let (fa, fb) = (file(a), file(b));
            a.key == b.key && fa.offset == fb.offset && fa.size == fb.size && fa.name == fb.name
        });

        let packed = folder_packed_sizes(&vols, &folders);
        let mut seen = vec![false; folders.len()];
        let mut entries = Vec::with_capacity(items.len());
        let mut offsets = Vec::with_capacity(items.len());
        for it in &items {
            let f = file(it);
            let utf8 = f.attrib & NAME_IS_UTF8 != 0;
            let name = if utf8 {
                String::from_utf8_lossy(&f.name).into_owned()
            } else {
                crate::util::text::ansi(&f.name)
            };
            let attrib = f.attrib as u32
                & (attr::READONLY | attr::HIDDEN | attr::SYSTEM | attr::DIRECTORY | attr::ARCHIVE);
            let folder = it.folder.map(|i| &folders[i]);
            let first = it
                .folder
                .is_some_and(|i| !std::mem::replace(&mut seen[i], true));
            entries.push(Entry {
                name: name.replace('\\', "/"),
                is_dir: attrib & attr::DIRECTORY != 0,
                size: Some(f.size as u64),
                packed_size: it.folder.filter(|_| first).map(|i| packed[i]),
                mtime: dos_to_filetime(f.date, f.time),
                attrib: Some(attrib),
                method: folder.map(|fo| method_name(fo.ctype & 0xF, fo.ctype >> 8)),
                block: usize::try_from(it.key).ok().filter(|_| it.folder.is_some()),
                ..Default::default()
            });
            offsets.push(f.offset as u64);
        }

        // One unit per folder. Overlapping files (rare) go to extra units that decode the
        // folder again.
        let mut units = Vec::new();
        let mut sources = Vec::new();
        let mut invalid = Vec::new();
        let mut i = 0;
        while i < items.len() {
            let Some(fi) = items[i].folder else {
                if entries[i].size_or_zero() > 0 {
                    invalid.push(i);
                }
                i += 1;
                continue;
            };
            let mut chains: Vec<(u64, Vec<usize>)> = Vec::new();
            while i < items.len() && items[i].folder == Some(fi) {
                let size = entries[i].size_or_zero();
                if size > 0 && !entries[i].is_dir {
                    let (off, end) = (offsets[i], offsets[i] + size);
                    match chains.iter_mut().find(|(e, _)| *e <= off) {
                        Some(c) => {
                            c.0 = end;
                            c.1.push(i);
                        }
                        None => chains.push((end, vec![i])),
                    }
                }
                i += 1;
            }
            for (_, ents) in chains {
                units.push(Unit {
                    entries: ents,
                    encrypted: false,
                });
                sources.push(Source::Folder(fi));
            }
        }
        if !invalid.is_empty() {
            units.push(Unit {
                entries: invalid,
                encrypted: false,
            });
            sources.push(Source::Invalid);
        }
        Cab {
            vols,
            opened,
            folders,
            entries,
            offsets,
            units,
            sources,
            missing,
        }
    }

    /// The error for a folder whose data runs out: a missing next cabinet, or damage.
    fn end_error(&self, folder: &Folder) -> Error {
        let (v, k) = *folder.segments.last().unwrap();
        let vol = &self.vols[v];
        if v + 1 == self.vols.len() && k + 1 == vol.folders.len() && vol.next.is_some() {
            let name = self.missing.clone().unwrap_or_else(|| {
                crate::util::text::ansi(vol.next.as_deref().unwrap_or_default())
            });
            return Error::unsupported(format!(
                "file data continues in cabinet {name}, which is missing"
            ));
        }
        Error::corrupt("unexpected end of CAB folder data")
    }
}

/// Bytes each folder occupies, measured up to the next folder's data (or the cabinet end)
/// so opening never walks block chains.
fn folder_packed_sizes(vols: &[Volume], folders: &[Folder]) -> Vec<u64> {
    let ends: Vec<Vec<u64>> = vols
        .iter()
        .map(|vol| {
            let limit = (vol.size as u64).min(vol.data.len() as u64);
            let mut starts: Vec<u64> = vol.folders.iter().map(|f| f.start as u64).collect();
            starts.sort_unstable();
            vol.folders
                .iter()
                .map(|f| {
                    let s = f.start as u64;
                    let end = starts.iter().copied().find(|&x| x > s).unwrap_or(limit);
                    end.max(s).min(limit.max(s)) - s
                })
                .collect()
        })
        .collect();
    folders
        .iter()
        .map(|f| f.segments.iter().map(|&(v, k)| ends[v][k]).sum())
        .collect()
}

/// The CAB block checksum: XOR of little-endian words, the tail bytes packed high to low.
fn checksum(data: &[u8], seed: u32) -> u32 {
    let mut sum = seed;
    let mut words = data.chunks_exact(4);
    for w in &mut words {
        sum ^= u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    }
    let tail = words
        .remainder()
        .iter()
        .fold(0u32, |acc, &b| (acc << 8) | b as u32);
    sum ^ tail
}

enum Decoder {
    Store,
    MsZip(Box<MsZip>),
    Lzx(Box<Lzx>),
    Quantum(Box<Quantum>),
}

impl Decoder {
    fn new(ctype: u16) -> Result<Decoder> {
        let param = (ctype >> 8) as u32;
        Ok(match ctype & 0xF {
            METHOD_NONE => Decoder::Store,
            METHOD_MSZIP => Decoder::MsZip(Box::new(MsZip::new())),
            METHOD_QUANTUM => Decoder::Quantum(Box::new(Quantum::new(param)?)),
            METHOD_LZX => Decoder::Lzx(Box::new(Lzx::new(param)?)),
            m => return Err(Error::unsupported(format!("CAB compression method {m}"))),
        })
    }
}

/// Decodes one folder's blocks in order, across cabinets.
struct FolderReader<'a> {
    cab: &'a Cab,
    folder: &'a Folder,
    seg: usize,
    /// Blocks already read from the current segment.
    block: u32,
    /// Offset of the next CFDATA header in the current segment's cabinet.
    at: usize,
    dec: Decoder,
    out: Vec<u8>,
    /// Stored data served straight from the cabinet instead of `out`.
    raw: Option<&'a [u8]>,
    pos: usize,
    /// The first parts of a block split across cabinets.
    join: Vec<u8>,
}

impl<'a> FolderReader<'a> {
    fn new(cab: &'a Cab, folder: &'a Folder) -> Result<Self> {
        let (v, k) = folder.segments[0];
        Ok(FolderReader {
            cab,
            folder,
            seg: 0,
            block: 0,
            at: cab.vols[v].folders[k].start as usize,
            dec: Decoder::new(folder.ctype)?,
            out: Vec::new(),
            raw: None,
            pos: 0,
            join: Vec::new(),
        })
    }

    /// Decodes the next non-empty block; `false` at the end of the folder.
    fn next_block(&mut self) -> Result<bool> {
        loop {
            let Some(&(v, k)) = self.folder.segments.get(self.seg) else {
                return Ok(false);
            };
            let vol: &'a Volume = &self.cab.vols[v];
            let rf = &vol.folders[k];
            if self.block >= rf.blocks as u32 {
                self.seg += 1;
                if let Some(&(nv, nk)) = self.folder.segments.get(self.seg) {
                    self.block = 0;
                    self.at = self.cab.vols[nv].folders[nk].start as usize;
                    continue;
                }
                if !self.join.is_empty() {
                    return Err(self.cab.end_error(self.folder));
                }
                return Ok(false);
            }
            let d: &'a [u8] = &vol.data;
            let head_len = 8 + vol.data_reserve;
            let past_end = || Error::corrupt("CAB data block is past the end of the cabinet");
            let head = d
                .get(self.at..self.at.saturating_add(head_len))
                .ok_or_else(past_end)?;
            let sum = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
            let packed = u16::from_le_bytes([head[4], head[5]]) as usize;
            let size = u16::from_le_bytes([head[6], head[7]]) as usize;
            let body_at = self.at + head_len;
            let body = d.get(body_at..body_at + packed).ok_or_else(past_end)?;
            if sum != 0 && checksum(&head[4..], checksum(body, 0)) != sum {
                return Err(Error::corrupt("CAB data block checksum mismatch"));
            }
            self.at = body_at + packed;
            self.block += 1;
            if size == 0 {
                // The first part of a block that continues in the next cabinet, or an empty block.
                if self.block == rf.blocks as u32 {
                    self.join.extend_from_slice(body);
                }
                continue;
            }
            let joined = !self.join.is_empty();
            let mut buf = std::mem::take(&mut self.join);
            let payload: &[u8] = if joined {
                buf.extend_from_slice(body);
                &buf
            } else {
                body
            };
            let r = self.decode(payload, size, if joined { None } else { Some(body) });
            buf.clear();
            self.join = buf;
            r?;
            return Ok(true);
        }
    }

    /// Decodes one block. `direct` is the same payload borrowed from the cabinet, when it
    /// was not reassembled.
    fn decode(&mut self, payload: &[u8], size: usize, direct: Option<&'a [u8]>) -> Result<()> {
        self.pos = 0;
        self.raw = None;
        match &mut self.dec {
            Decoder::Store => {
                if payload.len() != size {
                    return Err(Error::corrupt("stored CAB block sizes disagree"));
                }
                match direct {
                    Some(d) => self.raw = Some(d),
                    None => {
                        self.out.clear();
                        self.out.extend_from_slice(payload);
                    }
                }
            }
            Decoder::MsZip(m) => m.decode_block(payload, size, &mut self.out)?,
            Decoder::Lzx(l) => l.decode_frame(payload, size, &mut self.out)?,
            Decoder::Quantum(q) => q.decode_frame(payload, size, &mut self.out)?,
        }
        Ok(())
    }
}

impl Read for FolderReader<'_> {
    /// Fails, rather than returning 0, when the folder ends: callers only read bytes that
    /// a file claims.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let cur: &[u8] = match self.raw {
                Some(r) => r,
                None => &self.out,
            };
            if self.pos < cur.len() {
                let n = (cur.len() - self.pos).min(buf.len());
                buf[..n].copy_from_slice(&cur[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.next_block() {
                Ok(true) => {}
                Ok(false) => return Err(self.cab.end_error(self.folder).into_io()),
                Err(e) => return Err(e.into_io()),
            }
        }
    }
}

impl Archive for Cab {
    fn format(&self) -> &'static Format {
        &FORMAT
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let folder = match self.sources[unit] {
            Source::Folder(fi) => &self.folders[fi],
            Source::Invalid => {
                return Err(Error::corrupt(
                    "file refers to a CAB folder that does not exist",
                ))
            }
        };
        if folder.missing_start {
            let name = self
                .missing
                .clone()
                .or_else(|| self.vols[0].prev.as_deref().map(crate::util::text::ansi))
                .unwrap_or_default();
            return Err(Error::unsupported(format!(
                "file data starts in cabinet {name}, which is missing"
            )));
        }
        let mut r = FolderReader::new(self, folder)?;
        let mut pos = 0u64;
        for &i in &self.units[unit].entries {
            let (off, size) = (self.offsets[i], self.entries[i].size_or_zero());
            if off > pos {
                data::skip(&mut r, off - pos)?;
            }
            let mut take = (&mut r).take(size);
            if f(i, &mut take)? == Flow::Stop {
                return Ok(());
            }
            data::skip(&mut take, u64::MAX)?;
            pos = off + size;
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let mut p = vec![("Physical Size", self.vols[self.opened].size.to_string())];
        if self.vols.len() > 1 {
            let total: u64 = self.vols.iter().map(|v| v.size as u64).sum();
            p.push(("Total Physical Size", total.to_string()));
        }
        // 7-Zip lists each method once, LZX and Quantum with their largest window.
        let mut mask = 0u32;
        let (mut quantum, mut lzx) = (0, 0);
        for f in self.vols.iter().flat_map(|v| &v.folders) {
            mask |= 1 << f.method();
            match f.method() {
                METHOD_QUANTUM => quantum = quantum.max(f.param()),
                METHOD_LZX => lzx = lzx.max(f.param()),
                _ => {}
            }
        }
        let methods: Vec<String> = (0..16u16)
            .filter(|m| mask & (1 << m) != 0)
            .map(|m| method_name(m, if m == METHOD_QUANTUM { quantum } else { lzx }))
            .collect();
        if !methods.is_empty() {
            p.push(("Method", methods.join(" ")));
        }
        let blocks: usize = self.vols.iter().map(|v| v.folders.len()).sum();
        p.push(("Blocks", blocks.to_string()));
        p.push(("Volumes", self.vols.len().to_string()));
        p.push(("Volume Index", self.vols[0].index.to_string()));
        p.push(("ID", self.vols[self.opened].set_id.to_string()));
        if let Some(m) = &self.missing {
            p.insert(0, ("ERROR", format!("Can't open volume: {m}")));
        }
        p
    }

    fn columns(&self) -> Columns {
        Columns {
            crc: false,
            method: true,
            encrypted: false,
            block: true,
        }
    }
}
