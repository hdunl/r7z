//! zip recovery: when the central directory is missing or damaged, the entry list is
//! rebuilt from the local headers in front of each entry's data. The headers found are
//! written out as central directory records and parsed by the normal reader, so names,
//! extra fields, ZIP64 and encryption are handled the same way as in an intact archive.

use flate2::{Decompress, FlushDecompress, Status};

use super::{
    from_central, open_central, u16le, u32le, u64le, CENTRAL_SIG, FLAG_DESCRIPTOR, FLAG_ENCRYPTED,
    LOCAL_SIG,
};
use crate::error::{Error, Result};
use crate::format::data::Slice;
use crate::format::salvage::Salvaged;
use crate::format::{Archive, CodePage};

const DESCRIPTOR_SIG: u32 = 0x0807_4B50;
const EOCD_SIG: u32 = 0x0605_4B50;

/// One entry found by its local header.
#[derive(Clone)]
struct Found {
    at: usize,
    version: u16,
    flags: u16,
    method: u16,
    time: u16,
    date: u16,
    crc: Option<u32>,
    packed: u64,
    size: Option<u64>,
    name: Vec<u8>,
    /// Extra fields without the ZIP64 one (rewritten for the central record).
    extra: Vec<u8>,
    /// The local header has a ZIP64 field, so a data descriptor has 64-bit sizes.
    zip64: bool,
}

pub(super) fn open(data: Slice, code_page: Option<CodePage>) -> Result<Box<dyn Archive>> {
    let why = match open_central(&data, code_page) {
        Ok(z) => return Ok(Box::new(z)),
        Err(e) => e,
    };
    let d: &[u8] = &data;
    let (found, mut notes) = scan(d);
    if found.is_empty() {
        return Err(match why {
            Error::NotArchive => Error::NotArchive,
            e => Error::corrupt(format!("{e}; no local headers were found either")),
        });
    }
    notes.insert(
        0,
        format!(
            "the central directory is unusable ({}); rebuilt the file list from {} local headers",
            reason(&why),
            found.len()
        ),
    );
    let cd = central_records(&found);
    let mut zip = from_central(&data, &cd, found.len() as u64, 0, None, 0, code_page)?;
    for (i, f) in found.iter().enumerate() {
        if f.crc.is_none() {
            zip.entries[i].crc = None;
        }
        if f.size.is_none() {
            zip.entries[i].size = None;
        }
    }
    Ok(Box::new(Salvaged {
        inner: Box::new(zip),
        notes,
    }))
}

fn reason(e: &Error) -> String {
    match e {
        Error::Corrupt(m) => m.clone(),
        other => other.to_string(),
    }
}

fn find_sig(d: &[u8], from: usize, sig: u32) -> Option<usize> {
    let sig = sig.to_le_bytes();
    d.get(from..)?
        .windows(4)
        .position(|w| w == sig)
        .map(|p| from + p)
}

/// Methods a real local header can name (anything else is a false signature match).
fn plausible_method(m: u16) -> bool {
    matches!(m, 0..=20 | 93..=99)
}

/// Parses the local header at `p` when it looks real.
fn local_header(d: &[u8], p: usize) -> Option<(Found, usize)> {
    if p.checked_add(30)? > d.len() || u32le(d, p) != LOCAL_SIG {
        return None;
    }
    let version = u16le(d, p + 4);
    let flags = u16le(d, p + 6);
    let method = u16le(d, p + 8);
    let nlen = u16le(d, p + 26) as usize;
    let xlen = u16le(d, p + 28) as usize;
    if version & 0xFF > 100 || !plausible_method(method) || nlen == 0 || nlen > 4096 {
        return None;
    }
    let start = p + 30 + nlen + xlen;
    if start > d.len() {
        return None;
    }
    let name = d[p + 30..p + 30 + nlen].to_vec();
    if name.contains(&0) {
        return None;
    }
    let raw_extra = &d[p + 30 + nlen..start];
    let mut packed = u32le(d, p + 18) as u64;
    let mut size = u32le(d, p + 22) as u64;
    let mut extra = Vec::with_capacity(raw_extra.len());
    let mut zip64 = false;
    let mut x = 0;
    while x + 4 <= raw_extra.len() {
        let id = u16le(raw_extra, x);
        let len = u16le(raw_extra, x + 2) as usize;
        let Some(body) = raw_extra.get(x + 4..x + 4 + len) else {
            break;
        };
        if id == 0x0001 {
            zip64 = true;
            let mut q = 0;
            for v in [&mut size, &mut packed] {
                if *v == 0xFFFF_FFFF && q + 8 <= body.len() {
                    *v = u64le(body, q);
                    q += 8;
                }
            }
        } else {
            extra.extend_from_slice(&raw_extra[x..x + 4 + len]);
        }
        x += 4 + len;
    }
    let f = Found {
        at: p,
        version,
        flags,
        method,
        time: u16le(d, p + 10),
        date: u16le(d, p + 12),
        crc: Some(u32le(d, p + 14)),
        packed,
        size: Some(size),
        name,
        extra,
        zip64,
    };
    Some((f, start))
}

/// Finds every entry by its local header, in file order, plus notes on what was skipped.
fn scan(d: &[u8]) -> (Vec<Found>, Vec<String>) {
    let mut found = Vec::new();
    let mut notes = Vec::new();
    let mut pos = 0usize;
    let mut covered = 0usize;
    while let Some(p) = find_sig(d, pos, LOCAL_SIG) {
        let Some((mut f, start)) = local_header(d, p) else {
            pos = p + 1;
            continue;
        };
        if p > covered {
            notes.push(if found.is_empty() {
                format!(
                    "{} bytes before the first local header were skipped",
                    p - covered
                )
            } else {
                format!(
                    "{} bytes at offset {covered} belong to no entry (a damaged header?)",
                    p - covered
                )
            });
        }
        let end = data_end(d, &mut f, start, &mut notes);
        pos = end.max(p + 1);
        covered = end;
        found.push(f);
    }
    // What is left is normally the damaged central directory.
    if let Some(cd) = find_sig(d, covered, CENTRAL_SIG).or_else(|| find_sig(d, covered, EOCD_SIG)) {
        if cd > covered {
            notes.push(format!(
                "{} bytes at offset {covered} before the central directory belong to no entry",
                cd - covered
            ));
        }
    }
    (found, notes)
}

/// Works out where `f`'s data ends, filling in sizes and CRC from a data descriptor when
/// the local header leaves them out. Returns the offset just past the entry.
fn data_end(d: &[u8], f: &mut Found, start: usize, notes: &mut Vec<String>) -> usize {
    let name = String::from_utf8_lossy(&f.name).into_owned();
    let deferred = f.flags & FLAG_DESCRIPTOR != 0 && f.packed == 0;
    if !deferred {
        let end = start as u64 + f.packed;
        if end > d.len() as u64 {
            let have = d.len() - start;
            notes.push(format!(
                "{name}: the file ends inside this entry ({have} of {} bytes present)",
                f.packed
            ));
            f.packed = have as u64;
            return d.len();
        }
        let end = end as usize;
        if f.flags & FLAG_DESCRIPTOR == 0 {
            return end;
        }
        // A descriptor follows even when the header has the sizes; step over it.
        let mut probe = f.clone();
        return descriptor_at(d, &mut probe, start, end, f.zip64).unwrap_or(end);
    }
    let zip64 = f.zip64;
    // Deflate marks its own end, so the descriptor sits right after it.
    if f.method == 8 && f.flags & FLAG_ENCRYPTED == 0 {
        if let Some(n) = deflate_end(&d[start..]) {
            let end = start + n;
            if let Some(after) = descriptor_at(d, f, start, end, zip64) {
                return after;
            }
            f.packed = n as u64;
            f.crc = None;
            f.size = None;
            notes.push(format!(
                "{name}: no data descriptor after the data; its CRC is unknown"
            ));
            return end;
        }
    }
    // Otherwise look for a descriptor whose compressed size matches its distance from the
    // data: with a signature anywhere, or without one in front of the next header.
    let mut q = start;
    while let Some(s) = find_sig(d, q, DESCRIPTOR_SIG) {
        if let Some(after) = descriptor_at(d, f, start, s, zip64) {
            return after;
        }
        q = s + 1;
    }
    let mut q = start;
    while let Some(r) = find_sig(d, q, LOCAL_SIG) {
        for back in [24usize, 20, 16, 12] {
            if r >= start + back && descriptor_at(d, f, start, r - back, zip64) == Some(r) {
                return r;
            }
        }
        if local_header(d, r).is_some() {
            break;
        }
        q = r + 1;
    }
    // No end found: the data runs to the next real local header, or to the end of the file.
    let mut q = start;
    let end = loop {
        match find_sig(d, q, LOCAL_SIG) {
            Some(r) if local_header(d, r).is_some() => break r,
            Some(r) => q = r + 1,
            None => break d.len(),
        }
    };
    f.packed = (end - start) as u64;
    f.crc = None;
    f.size = None;
    notes.push(format!(
        "{name}: the end of its data could not be found; it is taken to run to offset {end}"
    ));
    end
}

/// Reads a data descriptor at `at` if its compressed size equals `at - start`; returns the
/// offset just past it.
fn descriptor_at(d: &[u8], f: &mut Found, start: usize, at: usize, zip64: bool) -> Option<usize> {
    let packed = (at - start) as u64;
    let mut p = at;
    if d.get(p..p + 4) == Some(&DESCRIPTOR_SIG.to_le_bytes()) {
        p += 4;
    }
    let crc = u32le(d.get(p..p + 4)?, 0);
    let (csize, usize_, len) = if zip64 {
        let b = d.get(p + 4..p + 20)?;
        (u64le(b, 0), u64le(b, 8), 20)
    } else {
        let b = d.get(p + 4..p + 12)?;
        (u32le(b, 0) as u64, u32le(b, 4) as u64, 12)
    };
    if csize != packed {
        return None;
    }
    f.packed = packed;
    f.crc = Some(crc);
    f.size = Some(usize_);
    Some(p + len)
}

/// Length of the Deflate stream at the start of `d`, if it ends.
fn deflate_end(d: &[u8]) -> Option<usize> {
    let mut z = Decompress::new(false);
    let mut out = vec![0u8; 1 << 16];
    loop {
        let (i0, o0) = (z.total_in(), z.total_out());
        let st = z
            .decompress(&d[i0 as usize..], &mut out, FlushDecompress::None)
            .ok()?;
        if st == Status::StreamEnd {
            return Some(z.total_in() as usize);
        }
        if z.total_in() == i0 && z.total_out() == o0 {
            return None;
        }
    }
}

/// Central directory records for the entries found.
fn central_records(found: &[Found]) -> Vec<u8> {
    let mut cd = Vec::new();
    for f in found {
        let crc = f.crc.unwrap_or(0);
        let size = f.size.unwrap_or(0);
        let big = f.packed >= 0xFFFF_FFFF || size >= 0xFFFF_FFFF || f.at as u64 >= 0xFFFF_FFFF;
        let mut extra = Vec::new();
        if big {
            extra.extend_from_slice(&[1, 0, 24, 0]);
            extra.extend_from_slice(&size.to_le_bytes());
            extra.extend_from_slice(&f.packed.to_le_bytes());
            extra.extend_from_slice(&(f.at as u64).to_le_bytes());
        }
        extra.extend_from_slice(&f.extra);
        let extra = &extra[..extra.len().min(0xFFFF)];
        let narrow = |v: u64| if big { u32::MAX } else { v as u32 };
        let is_dir = f.name.ends_with(b"/") || f.name.ends_with(b"\\");
        cd.extend_from_slice(&CENTRAL_SIG.to_le_bytes());
        cd.extend_from_slice(&20u16.to_le_bytes());
        cd.extend_from_slice(&f.version.to_le_bytes());
        cd.extend_from_slice(&f.flags.to_le_bytes());
        cd.extend_from_slice(&f.method.to_le_bytes());
        cd.extend_from_slice(&f.time.to_le_bytes());
        cd.extend_from_slice(&f.date.to_le_bytes());
        cd.extend_from_slice(&crc.to_le_bytes());
        cd.extend_from_slice(&narrow(f.packed).to_le_bytes());
        cd.extend_from_slice(&narrow(size).to_le_bytes());
        cd.extend_from_slice(&(f.name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        cd.extend_from_slice(&0u16.to_le_bytes()); // comment
        cd.extend_from_slice(&0u16.to_le_bytes()); // disk
        cd.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
        cd.extend_from_slice(&(if is_dir { 0x10u32 } else { 0 }).to_le_bytes());
        cd.extend_from_slice(&narrow(f.at as u64).to_le_bytes());
        cd.extend_from_slice(&f.name);
        cd.extend_from_slice(extra);
    }
    cd
}
