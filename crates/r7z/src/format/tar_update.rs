//! Updates to tar archives, plain or compressed as one stream.
//!
//! The stream is read twice. The first pass finds where each record sits (extension headers,
//! main header, data). The second writes the new stream: records the plan keeps are copied
//! byte for byte, dropped records are skipped, and a renamed entry gets new headers with the
//! same data. New items follow, written with `TarWriter`, and the whole stream is compressed
//! when the archive is `.tar.gz`, `.tar.bz2` or `.tar.xz`.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use super::{octal, parse, pax_records, put_octal, split_ustar, Cursor, Span, TarWriter, BLOCK};
use crate::error::{Error, Result};
use crate::format::data::{read_some, BoxRead, Opener};
use crate::format::write::{Compressor, Sink, WriteOptions};
use crate::ops::create::{Progress, Summary};
use crate::ops::update::{Fate, Outcome, Plan};

/// Carries out `plan` on the tar stream `open` reads, writing the result to `tmp`.
pub(super) fn update(
    open: Opener,
    tmp: &Path,
    plan: &Plan,
    compress: Option<Compressor>,
    opts: &WriteOptions,
    progress: &dyn Progress,
) -> Result<Outcome> {
    let mut first = open()?;
    let mut spans = Vec::new();
    let entries = {
        let mut cur = Cursor {
            r: &mut *first,
            pos: 0,
            cache: None,
            budget: 0,
            lenient: None,
            legacy_links: Vec::new(),
        };
        parse(&mut cur, Some(&mut spans))?.0
    };
    drop(first);
    if entries.len() != plan.fates.len() {
        return Err(Error::Other(
            "internal error: the update plan does not match the archive".into(),
        ));
    }
    let old_end = spans.last().map_or(0, Span::end);
    let total_hint = old_end + plan.add.iter().map(|i| i.size + 1024).sum::<u64>();

    let file = File::create(tmp)
        .map_err(|e| Error::Other(format!("cannot create {}: {e}", tmp.display())))?;
    let sink = Sink::new(
        compress,
        BufWriter::with_capacity(1 << 20, file),
        opts,
        None,
        0,
        total_hint,
    )?;
    let mut tw = TarWriter::new(sink);
    let mut front = Front::new(open()?);
    let mut summary = Summary {
        threads_used: if compress.is_some() { opts.threads } else { 1 },
        ..Default::default()
    };
    for span in &spans {
        match *span {
            Span::Global { start, end } => {
                front.skip_to(start)?;
                front.copy_to(end, &mut tw)?;
            }
            Span::Entry {
                index,
                start,
                data,
                end,
            } => {
                let entry = &entries[index];
                front.skip_to(start)?;
                match &plan.fates[index] {
                    Fate::Drop => front.skip_to(end)?,
                    Fate::Keep => front.copy_to(end, &mut tw)?,
                    Fate::Rename(name) => {
                        let region = front.read_to(data)?;
                        tw.write(&renamed_header(&region, name, entry.is_dir)?)?;
                        front.copy_to(end, &mut tw)?;
                    }
                }
                if !matches!(plan.fates[index], Fate::Drop) && !entry.is_dir {
                    summary.files += 1;
                }
            }
        }
    }

    for it in &plan.add {
        if it.is_dir {
            tw.add_dir(it)?;
            summary.dirs += 1;
            continue;
        }
        let mut f = match File::open(&it.src) {
            Ok(f) => f,
            Err(e) => {
                progress.warn(&format!("cannot open {}: {e}", it.src.display()));
                summary.skipped += 1;
                continue;
            }
        };
        let got = tw.add_file(it, &mut f, &|n| progress.add(n))?;
        if progress.cancelled() {
            return Err(Error::Cancelled);
        }
        summary.files += 1;
        summary.input_bytes += got;
    }

    let sink = tw.finish()?;
    let out = sink.finish()?;
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

/// The old stream, read forward. Positions are offsets in it.
struct Front {
    src: BoxRead,
    pos: u64,
    buf: Vec<u8>,
}

impl Front {
    fn new(src: BoxRead) -> Self {
        Front {
            src,
            pos: 0,
            buf: vec![0u8; 1 << 16],
        }
    }

    /// Moves forward to `end`, writing the bytes to `out`. Going back is an error: the spans
    /// are in stream order.
    fn copy_to<W: Write>(&mut self, end: u64, out: &mut TarWriter<W>) -> Result<()> {
        let mut left = end
            .checked_sub(self.pos)
            .ok_or_else(|| Error::corrupt("tar records out of order"))?;
        while left > 0 {
            let want = left.min(self.buf.len() as u64) as usize;
            let n = read_some(&mut self.src, &mut self.buf[..want])?;
            if n == 0 {
                return Err(Error::corrupt("tar stream ends inside a record"));
            }
            out.write(&self.buf[..n])?;
            left -= n as u64;
        }
        self.pos = end;
        Ok(())
    }

    /// Moves forward to `end`, dropping the bytes.
    fn skip_to(&mut self, end: u64) -> Result<()> {
        let mut left = end
            .checked_sub(self.pos)
            .ok_or_else(|| Error::corrupt("tar records out of order"))?;
        while left > 0 {
            let want = left.min(self.buf.len() as u64) as usize;
            let n = read_some(&mut self.src, &mut self.buf[..want])?;
            if n == 0 {
                return Err(Error::corrupt("tar stream ends inside a record"));
            }
            left -= n as u64;
        }
        self.pos = end;
        Ok(())
    }

    /// The bytes up to `end`, read into memory (extension and main headers, which are small).
    fn read_to(&mut self, end: u64) -> Result<Vec<u8>> {
        let len = end
            .checked_sub(self.pos)
            .filter(|&n| n <= 64 << 20)
            .ok_or_else(|| Error::corrupt("tar header region is implausibly large"))?;
        let mut v = vec![0u8; len as usize];
        let mut got = 0usize;
        while got < v.len() {
            let n = read_some(&mut self.src, &mut v[got..])?;
            if n == 0 {
                return Err(Error::corrupt("tar stream ends inside a header"));
            }
            got += n;
        }
        self.pos = end;
        Ok(v)
    }
}

/// The header bytes for a renamed entry whose old headers are `region` (its extension
/// headers, then its main header). The main header gets the new name in its ustar fields;
/// a `path` record carries it when it does not fit. The other pax records are kept.
fn renamed_header(region: &[u8], name: &str, is_dir: bool) -> Result<Vec<u8>> {
    if region.len() < BLOCK {
        return Err(Error::corrupt("tar header is truncated"));
    }
    let main_at = region.len() - BLOCK;
    let mut main = [0u8; BLOCK];
    main.copy_from_slice(&region[main_at..]);
    let mut records: Vec<(String, Vec<u8>)> = Vec::new();
    let mut p = 0usize;
    while p < main_at {
        let h = &region[p..p + BLOCK];
        let size =
            octal(&h[124..136]).ok_or_else(|| Error::corrupt("bad tar size field"))? as usize;
        let body = p + BLOCK;
        if body + size > main_at {
            return Err(Error::corrupt("tar extension header runs past its entry"));
        }
        if matches!(h[156], b'x' | b'X') {
            // The old name goes; every other record is kept.
            let mut kept: Vec<(String, Vec<u8>)> = pax_records(&region[body..body + size])
                .into_iter()
                .filter(|(k, _)| k.as_str() != "path")
                .collect();
            records.append(&mut kept);
        }
        p = body + size.div_ceil(BLOCK) * BLOCK;
    }
    records.sort_by(|a, b| a.0.cmp(&b.0));

    let name = if is_dir && !name.ends_with('/') {
        format!("{name}/")
    } else {
        name.to_string()
    };
    let fits = name.is_ascii() && split_ustar(name.as_bytes()).is_some();
    if !fits {
        records.push(("path".to_string(), name.as_bytes().to_vec()));
    }
    main[..100].fill(0);
    main[345..500].fill(0);
    match split_ustar(name.as_bytes()).filter(|_| fits) {
        Some((prefix, short)) => {
            main[..short.len()].copy_from_slice(short);
            main[345..345 + prefix.len()].copy_from_slice(prefix);
        }
        None => {
            // A name the ustar fields cannot hold: an ASCII stand-in, as `a` writes.
            let short: Vec<u8> = name.bytes().filter(|b| b.is_ascii()).take(100).collect();
            main[..short.len()].copy_from_slice(&short);
        }
    }
    main[148..156].fill(b' ');
    let sum: u64 = main.iter().map(|&b| b as u64).sum();
    main[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());

    let mut out = Vec::with_capacity(region.len() + 1024);
    if !records.is_empty() {
        let mut data = Vec::new();
        for (k, v) in &records {
            pax_record(&mut data, k, v);
        }
        out.extend_from_slice(&pax_header(data.len() as u64));
        out.extend_from_slice(&data);
        out.resize(
            out.len() + (data.len().div_ceil(BLOCK) * BLOCK - data.len()),
            0,
        );
    }
    out.extend_from_slice(&main);
    Ok(out)
}

/// One pax record: `"<length> <key>=<value>\n"`, the length counting itself.
fn pax_record(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    let mut body = Vec::with_capacity(key.len() + value.len() + 4);
    body.push(b' ');
    body.extend_from_slice(key.as_bytes());
    body.push(b'=');
    body.extend_from_slice(value);
    body.push(b'\n');
    let mut len = body.len() + 1;
    loop {
        let total = len.to_string().len() + body.len();
        if total == len {
            break;
        }
        len = total;
    }
    out.extend_from_slice(len.to_string().as_bytes());
    out.extend_from_slice(&body);
}

/// The header block of a pax extended header carrying `size` bytes of records.
fn pax_header(size: u64) -> [u8; BLOCK] {
    let mut h = [0u8; BLOCK];
    h[..9].copy_from_slice(b"PaxHeader");
    put_octal(&mut h[100..108], 0o644);
    put_octal(&mut h[108..116], 0);
    put_octal(&mut h[116..124], 0);
    put_octal(&mut h[124..136], size);
    put_octal(&mut h[136..148], 0);
    h[156] = b'x';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u64 = h.iter().map(|&b| b as u64).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}
