//! Parses 7z archives. Input is memory-mapped; pack streams are borrowed slices of the map.

use std::path::Path;

use super::bytes::Reader;
use super::{
    attr, id, Archive, BindPair, Coder, Entry, Folder, StreamsInfo, SIGNATURE,
    SIGNATURE_HEADER_SIZE,
};
use crate::codec::decode::{decode_folder_to_vec, DecodeOptions};
use crate::error::{Error, Result};
use crate::format::Slice;

/// An opened archive: its bytes plus parsed metadata.
pub struct ArchiveFile {
    pub data: Slice,
    pub archive: Archive,
}

impl ArchiveFile {
    pub fn open(path: &Path, password: Option<&str>) -> Result<Self> {
        Self::from_slice(Slice::map_file(path)?, password)
    }

    pub fn from_slice(data: Slice, password: Option<&str>) -> Result<Self> {
        let archive = parse(&data, password)?;
        Ok(ArchiveFile { data, archive })
    }

    /// Pack-stream slices for folder `f`.
    pub fn folder_packs(&self, f: usize) -> Result<Vec<&[u8]>> {
        pack_slices(&self.data, &self.archive, f)
    }

    /// Like `folder_packs`, cut at the end of the file instead of failing (recovery of a
    /// truncated archive). The flag says whether anything was cut.
    pub fn folder_packs_clamped(&self, f: usize) -> (Vec<&[u8]>, bool) {
        let a = &self.archive;
        let d: &[u8] = &self.data;
        let first = a.folder_first_pack[f];
        let n = a.streams.folders[f].packed_streams.len();
        let mut cut = false;
        let packs = (first..first + n)
            .map(|i| {
                let off = a.pack_offsets[i].min(d.len() as u64);
                let end = off.saturating_add(a.streams.pack_sizes[i]);
                if end > d.len() as u64 {
                    cut = true;
                }
                &d[off as usize..end.min(d.len() as u64) as usize]
            })
            .collect();
        (packs, cut)
    }
}

fn pack_slices<'a>(data: &'a [u8], a: &Archive, f: usize) -> Result<Vec<&'a [u8]>> {
    let first = a.folder_first_pack[f];
    let n = a.streams.folders[f].packed_streams.len();
    (first..first + n)
        .map(|i| {
            let off = a.pack_offsets[i];
            let size = a.streams.pack_sizes[i];
            let end = off
                .checked_add(size)
                .ok_or_else(|| Error::corrupt("pack stream overflows"))?;
            if end > data.len() as u64 {
                return Err(Error::corrupt(
                    "archive is truncated (pack stream past end of file)",
                ));
            }
            Ok(&data[off as usize..end as usize])
        })
        .collect()
}

/// Parses archive metadata from the full archive bytes.
pub fn parse(data: &[u8], password: Option<&str>) -> Result<Archive> {
    if data.len() < SIGNATURE_HEADER_SIZE as usize || data[..6] != SIGNATURE {
        return Err(Error::NotArchive);
    }
    if data[6] != 0 {
        return Err(Error::unsupported(format!(
            "7z format version {}.{}",
            data[6], data[7]
        )));
    }
    let start_crc = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if crc32fast::hash(&data[12..32]) != start_crc {
        return Err(Error::corrupt("signature header CRC mismatch"));
    }
    let next_off = u64::from_le_bytes(data[12..20].try_into().unwrap());
    let next_size = u64::from_le_bytes(data[20..28].try_into().unwrap());
    let next_crc = u32::from_le_bytes(data[28..32].try_into().unwrap());
    if next_size == 0 {
        return Ok(Archive {
            physical_size: SIGNATURE_HEADER_SIZE,
            ..Default::default()
        });
    }
    let start = SIGNATURE_HEADER_SIZE
        .checked_add(next_off)
        .ok_or_else(|| Error::corrupt("header offset overflows"))?;
    let end = start
        .checked_add(next_size)
        .ok_or_else(|| Error::corrupt("header size overflows"))?;
    if end > data.len() as u64 {
        return Err(Error::corrupt(format!(
            "archive is truncated: header ends at {end}, file has {} bytes",
            data.len()
        )));
    }
    let raw = &data[start as usize..end as usize];
    if crc32fast::hash(raw) != next_crc {
        return Err(Error::corrupt("header CRC mismatch"));
    }
    parse_header_block(data, raw, password, end, 1 << 32)
}

/// Parses a header block (plain or encoded) that ends at `end`. Decoded headers larger
/// than `limit` are refused.
pub fn parse_header_block(
    data: &[u8],
    raw: &[u8],
    password: Option<&str>,
    end: u64,
    limit: u64,
) -> Result<Archive> {
    let next_size = raw.len() as u64;
    let mut header_encrypted = false;
    let mut current = raw.to_vec();
    for _ in 0..4 {
        let mut r = Reader::new(&current);
        match r.number()? {
            id::HEADER => {
                let mut a = read_header(&mut r)?;
                a.header_encrypted = header_encrypted;
                a.header_size = next_size;
                finalize(&mut a, data.len() as u64)?;
                a.physical_size = a.physical_size.max(end);
                return Ok(a);
            }
            id::ENCODED_HEADER => {
                let si = read_streams_info(&mut r)?;
                let mut tmp = Archive {
                    streams: si,
                    ..Default::default()
                };
                compute_pack_layout(&mut tmp)?;
                let opts = DecodeOptions {
                    password: password.map(str::to_string),
                    threads: 1,
                };
                let mut decoded = Vec::new();
                for f in 0..tmp.streams.folders.len() {
                    let folder = &tmp.streams.folders[f];
                    header_encrypted |= folder.is_encrypted();
                    let packs = pack_slices(data, &tmp, f)?;
                    let out = decode_folder_to_vec(folder, &packs, &opts, limit).map_err(|e| {
                        if folder.is_encrypted() && matches!(e, Error::Corrupt(_)) {
                            Error::WrongPassword
                        } else {
                            e
                        }
                    })?;
                    if let Some(crc) = folder.crc {
                        if crc32fast::hash(&out) != crc {
                            return Err(if folder.is_encrypted() {
                                Error::WrongPassword
                            } else {
                                Error::corrupt("encoded header CRC mismatch")
                            });
                        }
                    }
                    decoded.extend_from_slice(&out);
                }
                current = decoded;
            }
            other => {
                return Err(Error::corrupt(format!(
                    "unexpected header block type {other:#x}"
                )))
            }
        }
    }
    Err(Error::corrupt("too many nested encoded headers"))
}

fn skip_data(r: &mut Reader) -> Result<()> {
    let n = r.count(r.remaining(), "property size")?;
    r.bytes(n)?;
    Ok(())
}

fn read_header(r: &mut Reader) -> Result<Archive> {
    let mut a = Archive::default();
    let mut t = r.number()?;
    if t == id::ARCHIVE_PROPERTIES {
        loop {
            if r.number()? == id::END {
                break;
            }
            skip_data(r)?;
        }
        t = r.number()?;
    }
    if t == id::ADDITIONAL_STREAMS_INFO {
        read_streams_info(r)?;
        t = r.number()?;
    }
    if t == id::MAIN_STREAMS_INFO {
        a.streams = read_streams_info(r)?;
        t = r.number()?;
    }
    if t == id::FILES_INFO {
        a.entries = read_files_info(r)?;
        t = r.number()?;
    }
    if t != id::END {
        return Err(Error::corrupt(format!(
            "unexpected property {t:#x} in header"
        )));
    }
    Ok(a)
}

fn read_streams_info(r: &mut Reader) -> Result<StreamsInfo> {
    let mut si = StreamsInfo::default();
    let mut t = r.number()?;
    if t == id::PACK_INFO {
        read_pack_info(r, &mut si)?;
        t = r.number()?;
    }
    if t == id::UNPACK_INFO {
        read_unpack_info(r, &mut si)?;
        t = r.number()?;
    }
    let mut have_substreams = false;
    if t == id::SUBSTREAMS_INFO {
        read_substreams_info(r, &mut si)?;
        have_substreams = true;
        t = r.number()?;
    }
    if !have_substreams {
        si.num_unpack_streams = vec![1; si.folders.len()];
        si.substream_sizes = si.folders.iter().map(|f| f.unpack_size()).collect();
        si.substream_crcs = si.folders.iter().map(|f| f.crc).collect();
    }
    if t != id::END {
        return Err(Error::corrupt(format!(
            "unexpected property {t:#x} in streams info"
        )));
    }
    Ok(si)
}

fn read_pack_info(r: &mut Reader, si: &mut StreamsInfo) -> Result<()> {
    si.pack_pos = r.number()?;
    let n = r.count(r.remaining(), "pack stream")?;
    loop {
        let t = r.number()?;
        match t {
            id::END => break,
            id::SIZE => {
                si.pack_sizes = (0..n).map(|_| r.number()).collect::<Result<_>>()?;
            }
            id::CRC => si.pack_crcs = r.digests(n)?,
            _ => skip_data(r)?,
        }
    }
    if si.pack_sizes.len() != n {
        return Err(Error::corrupt("pack sizes missing"));
    }
    if si.pack_crcs.is_empty() {
        si.pack_crcs = vec![None; n];
    }
    Ok(())
}

fn read_folder(r: &mut Reader) -> Result<Folder> {
    let num_coders = r.count(64, "coder")?;
    let mut f = Folder::default();
    for _ in 0..num_coders {
        let flags = r.u8()?;
        if flags & 0x80 != 0 {
            return Err(Error::unsupported("alternative coder methods"));
        }
        let id_size = (flags & 0x0F) as usize;
        if id_size > 8 {
            return Err(Error::corrupt("method id too long"));
        }
        let method = r
            .bytes(id_size)?
            .iter()
            .fold(0u64, |acc, &b| (acc << 8) | b as u64);
        let (num_in, num_out) = if flags & 0x10 != 0 {
            (r.count(64, "coder input")?, r.count(64, "coder output")?)
        } else {
            (1, 1)
        };
        let props = if flags & 0x20 != 0 {
            let n = r.count(r.remaining(), "property")?;
            r.bytes(n)?.to_vec()
        } else {
            Vec::new()
        };
        f.coders.push(Coder {
            method,
            num_in,
            num_out,
            props,
        });
    }
    let n_out = f.num_out_total();
    let n_in = f.num_in_total();
    let n_bind = n_out
        .checked_sub(1)
        .ok_or_else(|| Error::corrupt("folder has no outputs"))?;
    for _ in 0..n_bind {
        let in_index = r.count(n_in, "bind pair input")?;
        let out_index = r.count(n_out, "bind pair output")?;
        f.bind_pairs.push(BindPair {
            in_index,
            out_index,
        });
    }
    let n_packed = n_in
        .checked_sub(n_bind)
        .ok_or_else(|| Error::corrupt("folder has more bind pairs than inputs"))?;
    if n_packed == 1 {
        let p = (0..n_in)
            .find(|&i| !f.bind_pairs.iter().any(|bp| bp.in_index == i))
            .ok_or_else(|| Error::corrupt("folder has no packed input"))?;
        f.packed_streams.push(p);
    } else {
        for _ in 0..n_packed {
            f.packed_streams.push(r.count(n_in, "packed stream")?);
        }
    }
    Ok(f)
}

fn read_unpack_info(r: &mut Reader, si: &mut StreamsInfo) -> Result<()> {
    if r.number()? != id::FOLDER {
        return Err(Error::corrupt("expected folder list"));
    }
    let n = r.count(r.remaining(), "folder")?;
    if r.u8()? != 0 {
        return Err(Error::unsupported("external folder data"));
    }
    si.folders = (0..n).map(|_| read_folder(r)).collect::<Result<_>>()?;
    if r.number()? != id::CODERS_UNPACK_SIZE {
        return Err(Error::corrupt("expected coder unpack sizes"));
    }
    for f in &mut si.folders {
        f.unpack_sizes = (0..f.num_out_total())
            .map(|_| r.number())
            .collect::<Result<_>>()?;
    }
    loop {
        match r.number()? {
            id::END => break,
            id::CRC => {
                let crcs = r.digests(n)?;
                for (f, c) in si.folders.iter_mut().zip(crcs) {
                    f.crc = c;
                }
            }
            _ => skip_data(r)?,
        }
    }
    for f in &si.folders {
        f.validate()?;
    }
    Ok(())
}

fn read_substreams_info(r: &mut Reader, si: &mut StreamsInfo) -> Result<()> {
    let nf = si.folders.len();
    let mut nums = vec![1usize; nf];
    let mut t = r.number()?;
    if t == id::NUM_UNPACK_STREAM {
        let limit = r.remaining() + 1;
        for n in nums.iter_mut() {
            *n = r.count(limit, "substream")?;
        }
        t = r.number()?;
    }
    let extra: usize = nums.iter().map(|&n| n.saturating_sub(1)).sum();
    if extra > r.remaining() {
        return Err(Error::corrupt("substream count exceeds header size"));
    }
    let mut sizes = Vec::with_capacity(extra + nf);
    let have_sizes = t == id::SIZE;
    for (f, &n) in si.folders.iter().zip(&nums) {
        if n == 0 {
            continue;
        }
        let total = f.unpack_size();
        let mut sum = 0u64;
        for _ in 1..n {
            if !have_sizes {
                return Err(Error::corrupt("substream sizes missing"));
            }
            let s = r.number()?;
            sum = sum
                .checked_add(s)
                .ok_or_else(|| Error::corrupt("substream sizes overflow"))?;
            sizes.push(s);
        }
        sizes.push(
            total
                .checked_sub(sum)
                .ok_or_else(|| Error::corrupt("substream sizes exceed folder size"))?,
        );
    }
    if have_sizes {
        t = r.number()?;
    }
    let needs_digest = |f: &Folder, n: usize| !(n == 1 && f.crc.is_some());
    let num_digests: usize = si
        .folders
        .iter()
        .zip(&nums)
        .map(|(f, &n)| if needs_digest(f, n) { n } else { 0 })
        .sum();
    let mut crcs: Option<Vec<Option<u32>>> = None;
    loop {
        match t {
            id::END => break,
            id::CRC => {
                let digests = r.digests(num_digests)?;
                let mut it = digests.into_iter();
                let mut out = Vec::with_capacity(sizes.len());
                for (f, &n) in si.folders.iter().zip(&nums) {
                    if needs_digest(f, n) {
                        for _ in 0..n {
                            out.push(it.next().flatten());
                        }
                    } else {
                        out.push(f.crc);
                    }
                }
                crcs = Some(out);
            }
            _ => skip_data(r)?,
        }
        t = r.number()?;
    }
    si.substream_crcs = crcs.unwrap_or_else(|| {
        si.folders
            .iter()
            .zip(&nums)
            .flat_map(|(f, &n)| {
                let single = if n == 1 { f.crc } else { None };
                std::iter::repeat_n(single, n)
            })
            .collect()
    });
    si.num_unpack_streams = nums;
    si.substream_sizes = sizes;
    Ok(())
}

fn read_files_info(r: &mut Reader) -> Result<Vec<Entry>> {
    let n = r.count(r.remaining().saturating_mul(8) + 8, "file")?;
    let mut entries = vec![Entry::default(); n];
    let mut empty_stream = vec![false; n];
    let mut empty_file: Vec<bool> = Vec::new();
    let mut anti: Vec<bool> = Vec::new();
    loop {
        let t = r.number()?;
        if t == id::END {
            break;
        }
        let size = r.count(r.remaining(), "property size")?;
        let mut p = Reader::new(r.bytes(size)?);
        match t {
            id::EMPTY_STREAM => {
                empty_stream = p.bit_vector(n)?;
                let k = empty_stream.iter().filter(|&&b| b).count();
                empty_file = vec![false; k];
                anti = vec![false; k];
            }
            id::EMPTY_FILE => empty_file = p.bit_vector(empty_file.len())?,
            id::ANTI => anti = p.bit_vector(anti.len())?,
            id::NAME => {
                if p.u8()? != 0 {
                    return Err(Error::unsupported("external file names"));
                }
                let raw = p.bytes(p.remaining())?;
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect();
                let mut names = units.split(|&u| u == 0);
                for e in entries.iter_mut() {
                    let name = names
                        .next()
                        .ok_or_else(|| Error::corrupt("file names truncated"))?;
                    e.name = String::from_utf16_lossy(name);
                }
            }
            id::CTIME | id::ATIME | id::MTIME => {
                let defined = p.defined_vector(n)?;
                if p.u8()? != 0 {
                    return Err(Error::unsupported("external timestamps"));
                }
                for (e, d) in entries.iter_mut().zip(defined) {
                    let v = if d { Some(p.u64()?) } else { None };
                    match t {
                        id::CTIME => e.ctime = v,
                        id::ATIME => e.atime = v,
                        _ => e.mtime = v,
                    }
                }
            }
            id::WIN_ATTRIBUTES => {
                let defined = p.defined_vector(n)?;
                if p.u8()? != 0 {
                    return Err(Error::unsupported("external attributes"));
                }
                for (e, d) in entries.iter_mut().zip(defined) {
                    e.attrib = if d { Some(p.u32()?) } else { None };
                }
            }
            _ => {} // kDummy, kStartPos, kComment and unknown properties are skipped.
        }
    }
    let mut ei = 0;
    for (i, e) in entries.iter_mut().enumerate() {
        e.has_stream = !empty_stream[i];
        if !e.has_stream {
            e.is_dir = !empty_file.get(ei).copied().unwrap_or(false);
            e.is_anti = anti.get(ei).copied().unwrap_or(false);
            ei += 1;
        }
    }
    Ok(entries)
}

fn compute_pack_layout(a: &mut Archive) -> Result<()> {
    let si = &a.streams;
    let mut off = SIGNATURE_HEADER_SIZE
        .checked_add(si.pack_pos)
        .ok_or_else(|| Error::corrupt("pack position overflows"))?;
    a.pack_offsets.clear();
    for &s in &si.pack_sizes {
        a.pack_offsets.push(off);
        off = off
            .checked_add(s)
            .ok_or_else(|| Error::corrupt("pack sizes overflow"))?;
    }
    a.physical_size = off;
    a.folder_first_pack.clear();
    let mut k = 0usize;
    for f in &si.folders {
        a.folder_first_pack.push(k);
        k += f.packed_streams.len();
    }
    if k > si.pack_sizes.len() {
        return Err(Error::corrupt(
            "folders reference more pack streams than exist",
        ));
    }
    Ok(())
}

fn finalize(a: &mut Archive, file_len: u64) -> Result<()> {
    compute_pack_layout(a)?;
    let _ = file_len;
    let si = &a.streams;
    let mut folder_entries = vec![Vec::new(); si.folders.len()];
    let mut folder = 0usize;
    let mut in_folder = 0usize;
    let mut stream = 0usize;
    for (i, e) in a.entries.iter_mut().enumerate() {
        if !e.has_stream {
            if e.attrib.is_some_and(|x| x & attr::DIRECTORY != 0) {
                e.is_dir = true;
            }
            continue;
        }
        while folder < si.folders.len() && in_folder >= si.num_unpack_streams[folder] {
            folder += 1;
            in_folder = 0;
        }
        if folder >= si.folders.len() || stream >= si.substream_sizes.len() {
            return Err(Error::corrupt("more files than data streams"));
        }
        e.size = si.substream_sizes[stream];
        e.crc = si.substream_crcs.get(stream).copied().flatten();
        e.folder = Some(folder);
        folder_entries[folder].push(i);
        in_folder += 1;
        stream += 1;
    }
    a.folder_entries = folder_entries;
    Ok(())
}
