//! Updates to 7z archives.
//!
//! A folder the plan leaves whole is copied with its packed streams, untouched. A folder
//! that lost an entry is decoded, and its surviving entries are encoded again as one new
//! folder. Renames only change names in the header. New items are compressed as `a`
//! compresses them. The header is rebuilt for every update, so the output is always a
//! complete, consistent archive.

use std::fs::File;
use std::io::{BufWriter, Read, Seek, Write};
use std::path::PathBuf;

use super::{Fate, Outcome, Plan};
use crate::codec::aes::{derive_key, DEFAULT_CYCLES_POWER};
use crate::codec::decode::{folder_reader, DecodeOptions};
use crate::codec::encode::EncMethod;
use crate::error::{Error, Result};
use crate::ops::create::{
    self, is_executable_name, CreateOptions, Feed, FilterMode, FolderResult, Item, Job, MainMethod,
    Progress, Summary,
};
use crate::sevenz::read::ArchiveFile;
use crate::sevenz::{Entry, StreamsInfo, SIGNATURE_HEADER_SIZE};

/// Writes the updated archive for `src_path` to `tmp`.
pub fn write(
    src_path: &std::path::Path,
    tmp: &std::path::Path,
    plan: &Plan,
    opts: &CreateOptions,
    progress: &dyn Progress,
) -> Result<Outcome> {
    let src = ArchiveFile::open(src_path, opts.password.as_deref())?;
    let a = &src.archive;
    if plan.fates.len() != a.entries.len() {
        return Err(Error::Other(
            "internal error: the update plan does not match the archive".into(),
        ));
    }
    let mut opts = opts.clone();
    // An encrypted header stays encrypted.
    opts.encrypt_header |= a.header_encrypted;
    if opts.encrypt_header && opts.password.is_none() {
        return Err(Error::PasswordRequired);
    }
    let key = match &opts.password {
        Some(p) => Some(derive_key(p, &[], DEFAULT_CYCLES_POWER)?),
        None => None,
    };

    // Entries of each folder that survive, in folder order. A folder with a dropped entry
    // is dirty: it is re-encoded, or omitted when nothing in it survives.
    let folders = a.streams.folders.len();
    let mut dirty = vec![false; folders];
    let mut survivors: Vec<Vec<usize>> = vec![Vec::new(); folders];
    for (f, ents) in a.folder_entries.iter().enumerate() {
        for &i in ents {
            if plan.fates[i] == Fate::Drop {
                dirty[f] = true;
            } else {
                survivors[f].push(i);
            }
        }
    }
    for f in 0..folders {
        let decode = dirty[f] && !survivors[f].is_empty();
        if decode && a.streams.folders[f].is_encrypted() && opts.password.is_none() {
            return Err(Error::PasswordRequired);
        }
    }
    if let Some(pw) = &opts.password {
        // Copied encrypted folders keep their own key. Check that this password opens them,
        // so new data is never encrypted under a different password than the old.
        if let Some(f) = (0..folders).find(|&f| !dirty[f] && a.streams.folders[f].is_encrypted()) {
            verify_password(&src, f, pw)?;
        }
    }

    let file = File::create(tmp)
        .map_err(|e| Error::Other(format!("cannot create {}: {e}", tmp.display())))?;
    let mut out = BufWriter::with_capacity(1 << 20, file);
    out.write_all(&[0u8; SIGNATURE_HEADER_SIZE as usize])?;

    let mut si = StreamsInfo::default();
    // Entries without data keep their place ahead of the streams, as `a` writes them.
    let mut entries: Vec<Entry> = Vec::new();
    for (i, e) in a.entries.iter().enumerate() {
        if !e.has_stream {
            entries.extend(kept(e, &plan.fates[i]));
        }
    }
    let mut stream_entries: Vec<Entry> = Vec::new();
    let mut num_streams: Vec<usize> = Vec::new();
    let mut repacked = 0usize;
    let mut input_bytes = 0u64;
    for f in 0..folders {
        if !dirty[f] {
            copy_folder(&src, f, &mut out, &mut si)?;
            let here: Vec<Entry> = a.folder_entries[f]
                .iter()
                .filter_map(|&i| kept(&a.entries[i], &plan.fates[i]))
                .collect();
            num_streams.push(here.len());
            stream_entries.extend(here);
        } else if !survivors[f].is_empty() {
            let (fr, here) = repack(
                &src,
                f,
                &survivors[f],
                plan,
                &opts,
                key.as_ref(),
                &mut out,
                progress,
            )?;
            repacked += 1;
            num_streams.push(fr.streams.len());
            si.folders.push(fr.folder);
            si.pack_sizes.push(fr.pack_size);
            stream_entries.extend(here);
        }
    }

    for it in &plan.add {
        if it.is_dir || it.size == 0 {
            entries.push(create::make_entry(it, &opts, false, 0, None));
        }
    }
    let stream_new: Vec<usize> = (0..plan.add.len())
        .filter(|&i| !(plan.add[i].is_dir || plan.add[i].size == 0))
        .collect();
    let jobs = create::plan_jobs(&plan.add, &stream_new, &opts);
    let (results, _) =
        create::encode_jobs(&jobs, &plan.add, &opts, key.as_ref(), progress, &mut out)?;
    for fr in results {
        num_streams.push(fr.streams.len());
        for &(i, n, crc) in &fr.streams {
            input_bytes += n;
            stream_entries.push(create::make_entry(&plan.add[i], &opts, n > 0, n, Some(crc)));
        }
        si.folders.push(fr.folder);
        si.pack_sizes.push(fr.pack_size);
    }

    si.num_unpack_streams = num_streams;
    si.substream_sizes = stream_entries.iter().map(|e| e.size).collect();
    si.substream_crcs = stream_entries.iter().map(|e| e.crc).collect();
    entries.extend(stream_entries);

    let data_end = out.stream_position()?;
    if si.pack_sizes.iter().sum::<u64>() + SIGNATURE_HEADER_SIZE != data_end {
        return Err(Error::Other(
            "internal error: pack stream sizes do not match output".into(),
        ));
    }
    create::finish_archive(&mut out, &si, &entries, data_end, &opts, key.as_ref())?;
    let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    file.sync_all().ok();
    let archive_bytes = file.metadata()?.len();
    let dirs = entries.iter().filter(|e| e.is_dir).count() as u64;
    let files = entries.len() as u64 - dirs;
    Ok(Outcome {
        summary: Summary {
            files,
            dirs,
            input_bytes,
            archive_bytes,
            folders: si.folders.len(),
            skipped: 0,
            threads_used: opts.threads.max(1),
        },
        counts: plan.counts,
        repacked,
        changed: true,
    })
}

/// `e` as the plan keeps it: unchanged, renamed, or gone.
fn kept(e: &Entry, fate: &Fate) -> Option<Entry> {
    match fate {
        Fate::Drop => None,
        Fate::Keep => Some(e.clone()),
        Fate::Rename(name) => Some(Entry {
            name: name.clone(),
            ..e.clone()
        }),
    }
}

fn new_name(e: &Entry, fate: &Fate) -> String {
    match fate {
        Fate::Rename(name) => name.clone(),
        _ => e.name.clone(),
    }
}

/// Copies folder `f`'s packed streams to `out` unchanged.
fn copy_folder(
    src: &ArchiveFile,
    f: usize,
    out: &mut impl Write,
    si: &mut StreamsInfo,
) -> Result<()> {
    for pack in src.folder_packs(f)? {
        out.write_all(pack)?;
        si.pack_sizes.push(pack.len() as u64);
    }
    si.folders.push(src.archive.streams.folders[f].clone());
    Ok(())
}

/// Decodes folder `f` and encodes its `survivors` as one new folder. The survivors' data is
/// checked against the stored CRCs, which is also how a wrong password shows.
#[allow(clippy::too_many_arguments)]
fn repack(
    src: &ArchiveFile,
    f: usize,
    survivors: &[usize],
    plan: &Plan,
    opts: &CreateOptions,
    key: Option<&[u8; 32]>,
    out: &mut BufWriter<File>,
    progress: &dyn Progress,
) -> Result<(FolderResult, Vec<Entry>)> {
    let a = &src.archive;
    let folder = &a.streams.folders[f];
    let encrypted = folder.is_encrypted();
    let wrong = |e: Error| match e {
        Error::Corrupt(_) if encrypted => Error::WrongPassword,
        other => other,
    };
    let items: Vec<Item> = survivors
        .iter()
        .map(|&i| {
            let e = &a.entries[i];
            Item {
                src: PathBuf::new(),
                name: new_name(e, &plan.fates[i]),
                is_dir: false,
                size: e.size,
                mtime: e.mtime,
                ctime: e.ctime,
                atime: e.atime,
                attrib: e.attrib,
            }
        })
        .collect();
    let threads = opts.threads.max(1);
    let packs = src.folder_packs(f)?;
    let dopts = DecodeOptions {
        password: opts.password.clone(),
        threads,
    };
    // The folder decodes every entry in order, dropped ones included; the survivors' bytes
    // are the rest.
    let segments: Vec<(u64, bool)> = a.folder_entries[f]
        .iter()
        .map(|&i| (a.entries[i].size, plan.fates[i] != Fate::Drop))
        .collect();
    let mut reader = Kept::new(
        folder_reader(folder, &packs, &dopts).map_err(wrong)?,
        segments,
    );
    let job = Job {
        items: (0..items.len()).collect(),
        filter: repack_filter(&items, opts),
        total: items.iter().map(|i| i.size).sum(),
    };
    let folder_key = if encrypted { key } else { None };
    let fr = create::encode_folder(
        &job,
        &items,
        opts,
        folder_key,
        threads,
        out,
        progress,
        Feed::Decoded(&mut reader),
    )
    .map_err(wrong)?;
    for (k, &(_, _, crc)) in fr.streams.iter().enumerate() {
        let e = &a.entries[survivors[k]];
        if e.crc.is_some_and(|expect| expect != crc) {
            return Err(if encrypted {
                Error::WrongPassword
            } else {
                Error::Checksum(format!("{}: data does not match its CRC", e.name))
            });
        }
    }
    let entries = survivors
        .iter()
        .zip(&items)
        .map(|(&i, it)| Entry {
            name: it.name.clone(),
            ..a.entries[i].clone()
        })
        .collect();
    Ok((fr, entries))
}

/// A decoded folder with some entries' bytes left out. `segments` gives each entry's length
/// and whether to keep it, in folder order.
struct Kept<R: Read> {
    inner: R,
    segments: std::vec::IntoIter<(u64, bool)>,
    left: u64,
    keep: bool,
}

impl<R: Read> Kept<R> {
    fn new(inner: R, segments: Vec<(u64, bool)>) -> Self {
        Kept {
            inner,
            segments: segments.into_iter(),
            left: 0,
            keep: false,
        }
    }
}

impl<R: Read> Read for Kept<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.left == 0 {
                let Some((len, keep)) = self.segments.next() else {
                    return Ok(0);
                };
                self.left = len;
                self.keep = keep;
                continue;
            }
            if self.keep {
                let want = (self.left.min(buf.len() as u64)) as usize;
                let n = self.inner.read(&mut buf[..want])?;
                if n == 0 {
                    return Err(std::io::ErrorKind::UnexpectedEof.into());
                }
                self.left -= n as u64;
                return Ok(n);
            }
            let mut scratch = [0u8; 1 << 14];
            let want = (self.left.min(scratch.len() as u64)) as usize;
            let n = self.inner.read(&mut scratch[..want])?;
            if n == 0 {
                return Err(std::io::ErrorKind::UnexpectedEof.into());
            }
            self.left -= n as u64;
        }
    }
}

/// The filter a re-encoded folder gets, decided the way `a` decides it for a folder of
/// these items.
fn repack_filter(items: &[Item], opts: &CreateOptions) -> Option<EncMethod> {
    if opts.method == MainMethod::Copy {
        return None;
    }
    match opts.filter {
        FilterMode::Off => None,
        FilterMode::Bcj => Some(EncMethod::BcjX86),
        FilterMode::Delta(d) => Some(EncMethod::Delta(d)),
        FilterMode::Auto => items
            .iter()
            .any(|i| is_executable_name(&i.name))
            .then_some(EncMethod::BcjX86),
    }
}

/// Decodes the first file of folder `f` and checks it against its CRC. Fails with
/// `WrongPassword` when the password does not open the folder.
fn verify_password(src: &ArchiveFile, f: usize, password: &str) -> Result<()> {
    let a = &src.archive;
    let folder = &a.streams.folders[f];
    let Some(&first) = a.folder_entries[f].iter().find(|&&i| a.entries[i].size > 0) else {
        return Ok(());
    };
    let e = &a.entries[first];
    let Some(expect) = e.crc else {
        return Err(Error::Other(
            "cannot check the password: the first encrypted file has no stored CRC".into(),
        ));
    };
    let wrong = |_: Error| Error::WrongPassword;
    let packs = src.folder_packs(f)?;
    let dopts = DecodeOptions {
        password: Some(password.to_string()),
        threads: 1,
    };
    let mut reader = folder_reader(folder, &packs, &dopts).map_err(wrong)?;
    let mut hasher = crc32fast::Hasher::new();
    let mut left = e.size;
    let mut buf = vec![0u8; 1 << 16];
    while left > 0 {
        let want = left.min(buf.len() as u64) as usize;
        let n = reader
            .read(&mut buf[..want])
            .map_err(|err| wrong(Error::from_codec(err)))?;
        if n == 0 {
            return Err(Error::WrongPassword);
        }
        hasher.update(&buf[..n]);
        left -= n as u64;
    }
    if hasher.finalize() != expect {
        return Err(Error::WrongPassword);
    }
    Ok(())
}
