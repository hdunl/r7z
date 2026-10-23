//! Updates to zip archives.
//!
//! An entry the plan keeps is copied byte for byte: its local header, its data, and any data
//! descriptor or WinZip AES trailer. Only the central directory is written again. Its records
//! are the original ones with new offsets, so ZIP64 sizes, AES and NTFS extras and entry
//! comments survive. A renamed entry gets a new local header and central record carrying the
//! new name; its data is still copied as is. New items are written after the kept entries
//! with the same code `zip::write` uses.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use super::{
    central_directory, find_eocd, open_central, u16le, u32le, write_end, write_items, Zip,
    CENTRAL_SIG, FLAG_UTF8, LOCAL_SIG, LOCATOR_SIG,
};
use crate::error::{Error, Result};
use crate::format::data::Slice;
use crate::format::write::WriteOptions;
use crate::ops::create::{Progress, Summary};
use crate::ops::update::{Fate, Outcome, Plan};

const LIMIT32: u64 = 0xFFFF_FFFF;

/// Carries out `plan` on the zip at `archive`, writing the result to `tmp`.
pub(super) fn update(
    archive: &Path,
    tmp: &Path,
    plan: &Plan,
    opts: &WriteOptions,
    progress: &dyn Progress,
) -> Result<Outcome> {
    let data = Slice::map_file(archive)?;
    let zip = open_central(&data, None, false)?;
    let d: &[u8] = &data;
    let n = zip.z.len();
    if plan.fates.len() != n {
        return Err(Error::Other(
            "internal error: the update plan does not match the archive".into(),
        ));
    }
    if zip.offset != 0 {
        return Err(Error::unsupported(
            "updating a zip with data before its first entry (a self-extracting stub)",
        ));
    }
    let cd_start = zip.cd_start.ok_or_else(|| {
        Error::unsupported("updating this zip (its central directory is rebuilt)")
    })?;
    let eocd = find_eocd(d).ok_or_else(|| Error::corrupt("zip end record not found"))?;
    let comment_len = u16le(d, eocd + 20) as usize;
    let comment = &d[eocd + 22..eocd + 22 + comment_len];
    let had64 = eocd >= 20 && u32le(d, eocd - 20) == LOCATOR_SIG;

    // Where each central directory record starts; they are contiguous from cd_start.
    let mut rec_at = Vec::with_capacity(n);
    let mut p = cd_start as usize;
    for _ in 0..n {
        let fixed_ok = p + 46 <= d.len() && u32le(d, p) == CENTRAL_SIG;
        let len = if fixed_ok {
            46 + u16le(d, p + 28) as usize + u16le(d, p + 30) as usize + u16le(d, p + 32) as usize
        } else {
            0
        };
        if !fixed_ok || p + len > d.len() {
            return Err(Error::corrupt("zip central directory entry is damaged"));
        }
        rec_at.push(p);
        p += len;
    }

    // An entry's bytes run from its local header to the next local header (or the central
    // directory). Anything in between belongs to it: a data descriptor, say.
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by_key(|&i| zip.z[i].local_offset);
    let mut ext_end = vec![0usize; n];
    for (k, &i) in order.iter().enumerate() {
        let start = zip.z[i].local_offset;
        let end = order
            .get(k + 1)
            .map_or(cd_start, |&j| zip.z[j].local_offset);
        if end <= start || end > cd_start {
            return Err(Error::unsupported(
                "updating a zip whose entries overlap or lie outside the archive",
            ));
        }
        ext_end[i] = end as usize;
    }

    // Kept encrypted entries must open with the password, or the new archive would hold
    // entries under two passwords. Opening checks the stored verifier; no data is decoded.
    if let Some(pw) = opts.password.as_deref() {
        for i in 0..n {
            if plan.fates[i] != Fate::Drop
                && zip.entries[i].encrypted
                && matches!(zip.reader(i, Some(pw)), Err(Error::WrongPassword))
            {
                return Err(Error::WrongPassword);
            }
        }
    }

    let file = File::create(tmp)
        .map_err(|e| Error::Other(format!("cannot create {}: {e}", tmp.display())))?;
    let mut out = BufWriter::with_capacity(1 << 20, file);
    let mut pos = 0u64;
    let mut cd: Vec<u8> = Vec::new();
    let mut kept = 0u64;
    for i in 0..n {
        let fate = &plan.fates[i];
        if *fate == Fate::Drop {
            continue;
        }
        let start = zip.z[i].local_offset as usize;
        let end = ext_end[i];
        let offset = pos;
        match fate {
            Fate::Rename(name) => {
                pos += rename_local(d, &zip, i, name, start, end, &mut out)?;
                cd.extend(central_record(d, &zip, i, rec_at[i], offset, Some(name))?);
            }
            _ => {
                out.write_all(&d[start..end])?;
                pos += (end - start) as u64;
                cd.extend(central_record(d, &zip, i, rec_at[i], offset, None)?);
            }
        }
        kept += 1;
    }

    let mut summary = Summary {
        threads_used: opts.threads,
        ..Default::default()
    };
    let (written, cd_at) = write_items(&mut out, pos, &plan.add, opts, progress, &mut summary)?;
    cd.extend(central_directory(&written));
    out.write_all(&cd)?;
    write_end(
        &mut out,
        kept + written.len() as u64,
        cd_at,
        cd.len() as u64,
        comment,
        had64,
    )?;
    out.flush()?;
    let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    file.sync_all().ok();
    summary.archive_bytes = file.metadata()?.len();
    Ok(Outcome {
        summary,
        counts: plan.counts,
        repacked: 0,
        changed: true,
    })
}

/// The name as zip stores it: `/` separators, and a trailing `/` on directories.
fn stored_name(name: &str, is_dir: bool) -> Result<Vec<u8>> {
    let mut n = name.replace('\\', "/");
    if is_dir && !n.ends_with('/') {
        n.push('/');
    }
    if n.len() > u16::MAX as usize {
        return Err(Error::usage(format!("name too long for zip: {name}")));
    }
    Ok(n.into_bytes())
}

/// `flags` with the UTF-8 name bit set to match `name`.
fn utf8_flag(flags: u16, name: &[u8]) -> u16 {
    if name.is_ascii() {
        flags & !FLAG_UTF8
    } else {
        flags | FLAG_UTF8
    }
}

/// The extra fields of `extra` that pass `keep`, each copied as it was.
fn retain_fields(extra: &[u8], keep: impl Fn(u16) -> bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(extra.len());
    let mut x = 0usize;
    while x + 4 <= extra.len() {
        let id = u16le(extra, x);
        let end = x + 4 + u16le(extra, x + 2) as usize;
        if end > extra.len() {
            break;
        }
        if keep(id) {
            out.extend_from_slice(&extra[x..end]);
        }
        x = end;
    }
    out
}

/// Writes the local header of renamed entry `i`, then its data and anything after it
/// (`start..end` of the original). Returns the bytes written.
fn rename_local(
    d: &[u8],
    zip: &Zip,
    i: usize,
    name: &str,
    start: usize,
    end: usize,
    out: &mut impl Write,
) -> Result<u64> {
    if start + 30 > d.len() || u32le(d, start) != LOCAL_SIG {
        return Err(Error::corrupt(format!(
            "{}: local header not found",
            zip.entries[i].name
        )));
    }
    let nlen = u16le(d, start + 26) as usize;
    let xlen = u16le(d, start + 28) as usize;
    let hdr_end = start + 30 + nlen + xlen;
    if hdr_end > end {
        return Err(Error::corrupt(format!(
            "{}: local header runs past its data",
            zip.entries[i].name
        )));
    }
    // The Info-ZIP Unicode name would name the old file, so it goes.
    let extra = retain_fields(&d[start + 30 + nlen..hdr_end], |id| id != 0x7075);
    let name = stored_name(name, zip.entries[i].is_dir)?;
    let mut h = d[start..start + 30].to_vec();
    let flags = utf8_flag(u16le(&h, 6), &name);
    h[6..8].copy_from_slice(&flags.to_le_bytes());
    h[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
    h[28..30].copy_from_slice(&(extra.len() as u16).to_le_bytes());
    out.write_all(&h)?;
    out.write_all(&name)?;
    out.write_all(&extra)?;
    out.write_all(&d[hdr_end..end])?;
    Ok((30 + name.len() + extra.len() + (end - hdr_end)) as u64)
}

/// The central directory record for entry `i`, whose original record is at `at` and whose
/// local header now sits at `offset`. `rename` replaces the name.
fn central_record(
    d: &[u8],
    zip: &Zip,
    i: usize,
    at: usize,
    offset: u64,
    rename: Option<&str>,
) -> Result<Vec<u8>> {
    let nlen = u16le(d, at + 28) as usize;
    let xlen = u16le(d, at + 30) as usize;
    let clen = u16le(d, at + 32) as usize;
    let raw_name = &d[at + 46..at + 46 + nlen];
    let extra = &d[at + 46 + nlen..at + 46 + nlen + xlen];
    let comment = &d[at + 46 + nlen + xlen..at + 46 + nlen + xlen + clen];
    let entry = &zip.entries[i];
    let size = entry.size_or_zero();
    let packed = zip.z[i].packed;
    let name = match rename {
        Some(n) => stored_name(n, entry.is_dir)?,
        None => raw_name.to_vec(),
    };
    let need64 = size >= LIMIT32 || packed >= LIMIT32 || offset >= LIMIT32;
    let mut extra_out = Vec::with_capacity(xlen + 12);
    if need64 {
        // Only the fields whose fixed-size counterpart is 0xFFFFFFFF go in the ZIP64 extra.
        let mut body = Vec::with_capacity(24);
        for (v, big) in [
            (size, size >= LIMIT32),
            (packed, packed >= LIMIT32),
            (offset, offset >= LIMIT32),
        ] {
            if big {
                body.extend_from_slice(&v.to_le_bytes());
            }
        }
        extra_out.extend_from_slice(&1u16.to_le_bytes());
        extra_out.extend_from_slice(&(body.len() as u16).to_le_bytes());
        extra_out.extend_from_slice(&body);
    }
    extra_out.extend(retain_fields(extra, |id| {
        id != 0x0001 && (rename.is_none() || id != 0x7075)
    }));
    let fixed32 = |v: u64| if v >= LIMIT32 { u32::MAX } else { v as u32 };
    let mut h = d[at..at + 46].to_vec();
    if need64 && u16le(&h, 6) < 45 {
        h[6..8].copy_from_slice(&45u16.to_le_bytes());
    }
    let flags = if rename.is_some() {
        utf8_flag(u16le(&h, 8), &name)
    } else {
        u16le(&h, 8)
    };
    h[8..10].copy_from_slice(&flags.to_le_bytes());
    h[20..24].copy_from_slice(&fixed32(packed).to_le_bytes());
    h[24..28].copy_from_slice(&fixed32(size).to_le_bytes());
    h[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
    h[30..32].copy_from_slice(&(extra_out.len() as u16).to_le_bytes());
    h[42..46].copy_from_slice(&fixed32(offset).to_le_bytes());
    let mut rec = h;
    rec.extend_from_slice(&name);
    rec.extend_from_slice(&extra_out);
    rec.extend_from_slice(comment);
    Ok(rec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::write::{Kind, WriteOptions};
    use crate::ops::create::{Item, NoProgress};

    /// A zip with one stored file, and its opened form.
    fn one_file_zip(dir: &std::path::Path) -> (Vec<u8>, Zip) {
        let src = dir.join("f.txt");
        std::fs::write(&src, b"data").unwrap();
        let item = Item {
            src,
            name: "f.txt".into(),
            is_dir: false,
            size: 4,
            mtime: None,
            ctime: None,
            atime: None,
            attrib: None,
        };
        let archive = dir.join("one.zip");
        let opts = WriteOptions {
            level: 0,
            threads: 1,
            password: None,
            store: true,
            store_mtime: false,
            store_ctime: false,
            store_atime: false,
            zstd: false,
        };
        crate::format::write::create(&archive, Kind::Zip, &[item], &opts, &NoProgress).unwrap();
        let data = Slice::map_file(&archive).unwrap();
        let zip = open_central(&data, None, false).unwrap();
        (data.to_vec(), zip)
    }

    #[test]
    fn central_record_uses_zip64_for_large_offsets() {
        let dir = std::env::temp_dir().join(format!("r7z-zip-update-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (bytes, zip) = one_file_zip(&dir);
        let at = zip.cd_start.unwrap() as usize;
        let big = 1u64 << 32;
        let rec = central_record(&bytes, &zip, 0, at, big, None).unwrap();
        // Fixed fields: sizes stay as they are, the offset is the marker, the version needed
        // is at least 4.5.
        assert_eq!(
            u32::from_le_bytes(rec[42..46].try_into().unwrap()),
            u32::MAX
        );
        assert_eq!(u32::from_le_bytes(rec[20..24].try_into().unwrap()), 4);
        assert!(u16::from_le_bytes([rec[6], rec[7]]) >= 45);
        // The ZIP64 extra carries the real offset.
        let name_len = u16::from_le_bytes([rec[28], rec[29]]) as usize;
        let extra = &rec[46 + name_len..];
        assert_eq!(u16::from_le_bytes([extra[0], extra[1]]), 0x0001);
        assert_eq!(u16::from_le_bytes([extra[2], extra[3]]), 8);
        assert_eq!(u64::from_le_bytes(extra[4..12].try_into().unwrap()), big);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn small_offsets_keep_plain_fields() {
        let dir = std::env::temp_dir().join(format!("r7z-zip-plain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (bytes, zip) = one_file_zip(&dir);
        let at = zip.cd_start.unwrap() as usize;
        let rec = central_record(&bytes, &zip, 0, at, 17, None).unwrap();
        assert_eq!(u32::from_le_bytes(rec[42..46].try_into().unwrap()), 17);
        let name_len = u16::from_le_bytes([rec[28], rec[29]]) as usize;
        assert_eq!(rec.len(), 46 + name_len);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
