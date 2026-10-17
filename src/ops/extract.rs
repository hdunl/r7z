//! Extraction and testing for any format. Independent units (7z folders, zip entries)
//! decode in parallel; a single large LZMA2 folder decodes its blocks in parallel instead.

use std::collections::HashSet;
use std::fs::{self, File, FileTimes};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::mpsc::{self, SyncSender};
use std::sync::Mutex;

use rayon::prelude::*;

use crate::error::{Error, Result};
use crate::format::{Archive, Ctx, Entry, Flow, Link};
use crate::sevenz::attr;
use crate::util::time::from_filetime;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overwrite {
    /// Decide per file through `Callbacks::confirm_overwrite`.
    Ask,
    All,
    Skip,
    /// Extract under a new name (`name_1.ext`).
    RenameNew,
    /// Rename the existing file out of the way.
    RenameExisting,
}

#[derive(Clone, Debug)]
pub enum Target {
    /// Decode and verify only.
    Test,
    Disk {
        dir: PathBuf,
        full_paths: bool,
        overwrite: Overwrite,
    },
    Stdout,
}

pub struct ExtractOptions {
    pub password: Option<String>,
    pub threads: usize,
    pub target: Target,
    /// Per-entry selection; `None` selects everything.
    pub selected: Option<Vec<bool>>,
    /// Archive folder (`a/b`) that extracted paths are made relative to, as when extracting
    /// from a subfolder in a file manager. Entries outside it are skipped.
    pub base: Option<String>,
}

pub trait Callbacks: Sync {
    fn add(&self, _bytes: u64) {}
    /// Called before extraction starts for each existing target in `Ask` mode.
    fn confirm_overwrite(&self, _path: &Path) -> OverwriteAnswer {
        OverwriteAnswer::Yes
    }
    fn file_done(&self, _name: &str) {}
    /// Called while planning, before anything is written: `dir` paths are about to be
    /// made, other paths about to be written (`existed`: a file is there now and will be
    /// replaced). An error skips the entry and is reported against it.
    fn will_write(&self, _path: &Path, _dir: bool, _existed: bool) -> Result<()> {
        Ok(())
    }
    /// Polled between data blocks; returning true stops extraction with `Error::Cancelled`.
    fn cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverwriteAnswer {
    Yes,
    No,
    YesAll,
    NoAll,
    Rename,
    Quit,
}

#[derive(Debug, Default)]
pub struct Report {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub errors: Vec<(String, Error)>,
}

pub(crate) enum Action {
    Skip,
    /// `existed`: the target was present before extraction (needs read-only clearing).
    Write {
        path: PathBuf,
        existed: bool,
    },
    Test,
    Stdout,
}

/// What to do with each entry, decided before any data is decoded.
pub(crate) struct Plan {
    pub actions: Vec<Action>,
    /// Entries that belong to some unit (the rest have no data).
    pub in_unit: Vec<bool>,
    pub dirs_to_stamp: Vec<(PathBuf, usize)>,
    /// Entries that cannot be extracted at all (unsafe paths, failed renames).
    pub errors: Vec<(usize, Error)>,
    pub dirs: u64,
    pub skipped: u64,
}

/// Files up to this size are decoded into memory and handed to writer threads, so file
/// creation and close (slow on Windows, where scanners hook close) overlap with decoding.
const SMALL_FILE: u64 = 1 << 20;

/// Turns an archive path into a safe relative path: no roots, drives, `..` or reserved
/// device names, and characters Windows forbids replaced with `_`.
pub fn safe_relative_path(name: &str) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    let parts: Vec<&str> = if cfg!(windows) {
        name.split(['/', '\\']).collect()
    } else {
        name.split('/').collect()
    };
    for part in parts {
        if part.is_empty() || part == "." || part == ".." {
            continue;
        }
        let mut p: String = part.to_string();
        if cfg!(windows) {
            p = p
                .chars()
                .map(|c| {
                    if "<>:\"|?*".contains(c) || (c as u32) < 32 {
                        '_'
                    } else {
                        c
                    }
                })
                .collect();
            let trimmed = p.trim_end_matches([' ', '.']);
            p = if trimmed.is_empty() {
                "_".into()
            } else {
                trimmed.to_string()
            };
            let stem = p.split('.').next().unwrap_or("").to_ascii_uppercase();
            const RESERVED: &[&str] = &[
                "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
                "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8",
                "LPT9",
            ];
            if RESERVED.contains(&stem.as_str()) {
                p.insert(0, '_');
            }
        }
        out.push(p);
    }
    if out.components().all(|c| matches!(c, Component::Normal(_)))
        && out.components().next().is_some()
    {
        Some(out)
    } else {
        None
    }
}

fn unique_name(p: &Path) -> PathBuf {
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = p
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for i in 1.. {
        let cand = p.with_file_name(format!("{stem}_{i}{ext}"));
        if !cand.exists() {
            return cand;
        }
    }
    unreachable!()
}

fn is_data_error(e: &Error) -> bool {
    matches!(e, Error::Corrupt(_) | Error::Checksum(_))
}

/// Resolves every entry's action up front (including overwrite prompts) so decoding never
/// blocks on user input; creates directories.
pub(crate) fn plan(a: &dyn Archive, opts: &ExtractOptions, cb: &dyn Callbacks) -> Result<Plan> {
    let entries = a.entries();
    let selected = |i: usize| opts.selected.as_ref().is_none_or(|s| s[i]);
    let mut plan_errors: Vec<(usize, Error)> = Vec::new();
    let (mut dirs, mut skipped) = (0u64, 0u64);
    let mut in_unit = vec![false; entries.len()];
    for u in a.units() {
        for &i in &u.entries {
            in_unit[i] = true;
        }
    }

    let mut actions: Vec<Action> = Vec::with_capacity(entries.len());
    let mut mode = match &opts.target {
        Target::Disk { overwrite, .. } => *overwrite,
        _ => Overwrite::All,
    };
    let mut dirs_to_stamp: Vec<(PathBuf, usize)> = Vec::new();
    // Directories this run created: files inside them cannot already exist.
    let mut fresh: HashSet<PathBuf> = HashSet::new();
    if let Target::Disk { dir, .. } = &opts.target {
        if !dir.exists() {
            fresh.insert(dir.clone());
        }
    }
    for (i, e) in entries.iter().enumerate() {
        if !selected(i) || e.is_anti {
            actions.push(Action::Skip);
            continue;
        }
        let act = match &opts.target {
            Target::Test => {
                if e.is_dir {
                    Action::Skip
                } else {
                    Action::Test
                }
            }
            Target::Stdout => {
                if e.is_dir {
                    Action::Skip
                } else {
                    Action::Stdout
                }
            }
            Target::Disk {
                dir, full_paths, ..
            } => {
                let name = match &opts.base {
                    Some(base) if !base.is_empty() => {
                        let norm = e.name.replace('\\', "/");
                        let prefix = format!("{}/", base.trim_end_matches('/'));
                        match norm.strip_prefix(&prefix) {
                            Some(rest) if !rest.is_empty() => rest.to_string(),
                            _ => {
                                actions.push(Action::Skip);
                                continue;
                            }
                        }
                    }
                    _ => e.name.clone(),
                };
                let rel = match safe_relative_path(&name) {
                    Some(r) => r,
                    // `.` or `/` as a directory entry is the extraction root itself.
                    None if e.is_dir => {
                        actions.push(Action::Skip);
                        continue;
                    }
                    None => {
                        plan_errors.push((i, Error::Other("unsafe or empty path".into())));
                        actions.push(Action::Skip);
                        continue;
                    }
                };
                let rel = if *full_paths {
                    rel
                } else {
                    if e.is_dir {
                        actions.push(Action::Skip);
                        continue;
                    }
                    PathBuf::from(rel.file_name().unwrap())
                };
                let path = dir.join(rel);
                if e.is_dir {
                    let parent_fresh = path.parent().is_some_and(|p| fresh.contains(p));
                    let existed = !parent_fresh && path.is_dir();
                    if let Err(err) = cb.will_write(&path, true, existed) {
                        plan_errors.push((i, err));
                    } else if let Err(err) = fs::create_dir_all(&path) {
                        plan_errors.push((i, err.into()));
                    } else {
                        if !existed {
                            fresh.insert(path.clone());
                        }
                        dirs += 1;
                        dirs_to_stamp.push((path, i));
                    }
                    actions.push(Action::Skip);
                    continue;
                }
                let mut path = path;
                let parent_fresh = path.parent().is_some_and(|p| fresh.contains(p));
                let mut existed = false;
                if !parent_fresh && path.symlink_metadata().is_ok() {
                    existed = true;
                    let mut decision = mode;
                    if mode == Overwrite::Ask {
                        decision = match cb.confirm_overwrite(&path) {
                            OverwriteAnswer::Yes => Overwrite::All,
                            OverwriteAnswer::No => Overwrite::Skip,
                            OverwriteAnswer::YesAll => {
                                mode = Overwrite::All;
                                Overwrite::All
                            }
                            OverwriteAnswer::NoAll => {
                                mode = Overwrite::Skip;
                                Overwrite::Skip
                            }
                            OverwriteAnswer::Rename => Overwrite::RenameNew,
                            OverwriteAnswer::Quit => {
                                return Err(Error::Other("aborted by user".into()))
                            }
                        };
                    }
                    match decision {
                        Overwrite::Skip => {
                            skipped += 1;
                            actions.push(Action::Skip);
                            continue;
                        }
                        Overwrite::RenameNew => {
                            path = unique_name(&path);
                            existed = false;
                        }
                        Overwrite::RenameExisting => {
                            let moved = unique_name(&path);
                            if let Err(err) = fs::rename(&path, &moved) {
                                plan_errors.push((i, err.into()));
                                actions.push(Action::Skip);
                                continue;
                            }
                            existed = false;
                        }
                        _ => {}
                    }
                }
                if let Err(err) = cb.will_write(&path, false, existed) {
                    plan_errors.push((i, err));
                    actions.push(Action::Skip);
                    continue;
                }
                Action::Write { path, existed }
            }
        };
        actions.push(act);
    }

    Ok(Plan {
        actions,
        in_unit,
        dirs_to_stamp,
        errors: plan_errors,
        dirs,
        skipped,
    })
}

/// Entries outside every unit have no data: empty files. (Hard links are done last.)
pub(crate) fn write_unitless(
    a: &dyn Archive,
    plan: &Plan,
    cb: &dyn Callbacks,
) -> Vec<(usize, Result<()>)> {
    let mut out = Vec::new();
    for (i, e) in a.entries().iter().enumerate() {
        if plan.in_unit[i] || e.is_dir || matches!(e.link, Some(Link::Hard(_))) {
            continue;
        }
        let r = match &plan.actions[i] {
            Action::Write { path, existed } => write_whole(path, *existed, e, &[]),
            Action::Test | Action::Stdout => Ok(()),
            Action::Skip => continue,
        };
        if r.is_ok() {
            cb.file_done(&e.name);
        }
        out.push((i, r));
    }
    out
}

/// Hard links point at entries extracted before.
pub(crate) fn link_hard(a: &dyn Archive, plan: &Plan) -> Vec<(usize, Result<()>)> {
    let entries = a.entries();
    let actions = &plan.actions;
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let Some(Link::Hard(target)) = &e.link else {
            continue;
        };
        let r = match &actions[i] {
            Action::Write { path, existed } => {
                let src =
                    entries
                        .iter()
                        .position(|t| &t.name == target)
                        .and_then(|t| match &actions[t] {
                            Action::Write { path, .. } => Some(path.clone()),
                            _ => None,
                        });
                match src {
                    Some(src) => link_or_copy(&src, path, *existed),
                    None => Err(Error::Other(format!(
                        "hard link target {target} was not extracted"
                    ))),
                }
            }
            Action::Test | Action::Stdout => Ok(()),
            Action::Skip => continue,
        };
        out.push((i, r));
    }
    out
}

/// Directory times last, deepest first, since writing children updates them.
pub(crate) fn stamp_dirs(a: &dyn Archive, plan: Plan) {
    let mut dirs = plan.dirs_to_stamp;
    dirs.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
    for (p, i) in dirs {
        if let Some(mt) = a.entries()[i].mtime {
            let _ = filetime::set_file_mtime(
                &p,
                filetime::FileTime::from_system_time(from_filetime(mt)),
            );
        }
    }
}

pub fn extract(a: &dyn Archive, opts: &ExtractOptions, cb: &dyn Callbacks) -> Result<Report> {
    let entries = a.entries();
    let plan = plan(a, opts, cb)?;
    let mut report = Report {
        dirs: plan.dirs,
        skipped: plan.skipped,
        ..Default::default()
    };
    for (i, err) in &plan.errors {
        report.errors.push((entries[*i].name.clone(), clone_err(err)));
    }
    for (i, r) in write_unitless(a, &plan, cb) {
        match r {
            Ok(()) => report.files += 1,
            Err(err) => report.errors.push((entries[i].name.clone(), err)),
        }
    }
    let actions = &plan.actions;

    let units: Vec<usize> = (0..a.units().len())
        .filter(|&u| {
            a.units()[u]
                .entries
                .iter()
                .any(|&i| !matches!(actions[i], Action::Skip))
        })
        .collect();

    let report = Mutex::new(report);
    let stdout = matches!(opts.target, Target::Stdout);
    let threads = opts.threads.max(1);
    // Spread threads across concurrently decoded units.
    let per_unit = if stdout {
        threads
    } else {
        (threads / units.len().max(1)).max(1)
    };
    let ctx = Ctx {
        password: opts.password.clone(),
        threads: per_unit,
    };
    let to_disk = matches!(opts.target, Target::Disk { .. });
    let check_crc = !a.verifies_data();

    let (tx, rx) = mpsc::sync_channel::<(usize, Vec<u8>)>(64);
    let rx = Mutex::new(rx);
    std::thread::scope(|scope| -> Result<()> {
        let writers = if to_disk { threads.clamp(2, 8) } else { 0 };
        let handles: Vec<_> = (0..writers)
            .map(|_| {
                let (rx, report) = (&rx, &report);
                scope.spawn(move || loop {
                    let job = rx.lock().unwrap().recv();
                    let Ok((i, data)) = job else { return };
                    let e = &entries[i];
                    if let Action::Write { path, existed } = &actions[i] {
                        let r = write_whole(path, *existed, e, &data);
                        let mut rep = report.lock().unwrap();
                        match r {
                            Ok(()) => {
                                rep.files += 1;
                                rep.bytes += data.len() as u64;
                                cb.file_done(&e.name);
                            }
                            Err(err) => rep.errors.push((e.name.clone(), err)),
                        }
                    }
                })
            })
            .collect();
        let sender = if writers > 0 { Some(tx.clone()) } else { None };
        drop(tx);

        let run = |u: usize| {
            let r = decode_unit(a, u, actions, &ctx, check_crc, cb, sender.as_ref());
            let mut rep = report.lock().unwrap();
            rep.files += r.files;
            rep.bytes += r.bytes;
            rep.errors.extend(r.errors);
        };
        if stdout || units.len() <= 1 || threads == 1 {
            units.iter().for_each(|&u| run(u));
        } else {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .map_err(|e| Error::Other(e.to_string()))?;
            pool.install(|| units.par_iter().for_each(|&u| run(u)));
        }
        drop(sender);
        for h in handles {
            let _ = h.join();
        }
        Ok(())
    })?;
    if cb.cancelled() {
        return Err(Error::Cancelled);
    }
    let mut report = report.into_inner().unwrap();

    for (i, r) in link_hard(a, &plan) {
        match r {
            Ok(()) => report.files += 1,
            Err(err) => report.errors.push((entries[i].name.clone(), err)),
        }
    }
    stamp_dirs(a, plan);
    Ok(report)
}

fn link_or_copy(src: &Path, dst: &Path, existed: bool) -> Result<()> {
    if existed {
        clear_readonly(dst);
        let _ = fs::remove_file(dst);
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::hard_link(src, dst).is_err() {
        fs::copy(src, dst)?;
    }
    Ok(())
}

enum Outcome {
    /// Handled here; counts as a finished file.
    Done(u64),
    /// Handed to a writer thread, which reports the result.
    Queued,
    /// Not selected.
    Skipped,
}

fn decode_unit(
    a: &dyn Archive,
    u: usize,
    actions: &[Action],
    ctx: &Ctx,
    check_crc: bool,
    cb: &dyn Callbacks,
    writers: Option<&SyncSender<(usize, Vec<u8>)>>,
) -> Report {
    let unit = &a.units()[u];
    let entries = a.entries();
    let mut rep = Report::default();
    let Some(&last_index) = unit
        .entries
        .iter()
        .rev()
        .find(|&&i| !matches!(actions[i], Action::Skip))
    else {
        return rep;
    };
    // Entries the callback finished (successfully or with a per-file error).
    let mut finished: HashSet<usize> = HashSet::new();
    let mut buf = vec![0u8; 1 << 20];
    let result = a.extract_unit(u, ctx, &mut |i, reader| {
        let e = &entries[i];
        match copy_entry(reader, i, e, &actions[i], &mut buf, check_crc, cb, writers) {
            Ok(Outcome::Done(n)) => {
                rep.files += 1;
                rep.bytes += n;
                cb.file_done(&e.name);
            }
            Ok(Outcome::Queued) | Ok(Outcome::Skipped) => {}
            // A CRC or write error only affects this file; the format skips what is left.
            Err(err @ (Error::Checksum(_) | Error::Io(_))) => {
                let err = if unit.encrypted && matches!(err, Error::Checksum(_)) {
                    Error::WrongPassword
                } else {
                    err
                };
                rep.errors.push((e.name.clone(), err));
            }
            Err(err) => return Err(err),
        }
        finished.insert(i);
        Ok(if i == last_index {
            Flow::Stop
        } else {
            Flow::Continue
        })
    });
    if let Err(err) = result {
        // A data error poisons the rest of the unit (its stream position is lost).
        let err = if unit.encrypted && is_data_error(&err) {
            Error::WrongPassword
        } else {
            err
        };
        for &i in &unit.entries {
            if !matches!(actions[i], Action::Skip) && !finished.contains(&i) {
                rep.errors.push((entries[i].name.clone(), clone_err(&err)));
            }
        }
    }
    rep
}

pub(crate) fn clone_err(e: &Error) -> Error {
    match e {
        Error::Io(x) => Error::Io(io::Error::new(x.kind(), x.to_string())),
        Error::NotArchive => Error::NotArchive,
        Error::Corrupt(m) => Error::Corrupt(m.clone()),
        Error::Unsupported(m) => Error::Unsupported(m.clone()),
        Error::PasswordRequired => Error::PasswordRequired,
        Error::WrongPassword => Error::WrongPassword,
        Error::Checksum(m) => Error::Checksum(m.clone()),
        Error::Usage(m) => Error::Usage(m.clone()),
        Error::Cancelled => Error::Cancelled,
        Error::Other(m) => Error::Other(m.clone()),
    }
}

/// Reads decoded bytes; 0 means the end of the entry. Decoder failures become `Corrupt`
/// so they are not mistaken for destination I/O errors.
pub(crate) fn read_decoded(reader: &mut dyn Read, buf: &mut [u8]) -> Result<usize> {
    loop {
        match reader.read(buf) {
            Ok(n) => return Ok(n),
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                return Err(match Error::from_codec(err) {
                    Error::Io(x) => Error::corrupt(x.to_string()),
                    other => other,
                })
            }
        }
    }
}

fn check_crc(e: &Entry, got: u32) -> Result<()> {
    match e.crc {
        Some(expected) if expected != got => Err(Error::Checksum(format!(
            "{} (expected {expected:08X}, got {got:08X})",
            e.name
        ))),
        _ => Ok(()),
    }
}

fn check_size(e: &Entry, got: u64) -> Result<()> {
    match e.size {
        Some(want) if got < want => Err(Error::corrupt("unexpected end of data")),
        _ => Ok(()),
    }
}

/// Moves one entry's bytes to its destination, verifying size and CRC.
#[allow(clippy::too_many_arguments)]
fn copy_entry(
    reader: &mut dyn Read,
    index: usize,
    e: &Entry,
    action: &Action,
    buf: &mut [u8],
    verify: bool,
    cb: &dyn Callbacks,
    writers: Option<&SyncSender<(usize, Vec<u8>)>>,
) -> Result<Outcome> {
    if matches!(action, Action::Skip) {
        return Ok(Outcome::Skipped);
    }
    let verify = verify && e.crc.is_some();
    // Bytes already read that still have to go to the destination.
    let mut head: Vec<u8> = Vec::new();
    if let (Action::Write { .. }, Some(tx), Some(size)) = (action, writers, e.size) {
        if size <= SMALL_FILE {
            // One byte more than declared tells an exact size from a hint (gzip's ISIZE).
            let mut data = vec![0u8; size as usize + 1];
            let mut filled = 0;
            while filled < data.len() {
                let n = read_decoded(reader, &mut data[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            data.truncate(filled);
            if filled as u64 <= size {
                check_size(e, filled as u64)?;
                if verify {
                    check_crc(e, crc32fast::hash(&data))?;
                }
                cb.add(filled as u64);
                if cb.cancelled() {
                    return Err(Error::Cancelled);
                }
                if tx.send((index, data)).is_err() {
                    return Err(Error::Other("file writer stopped".into()));
                }
                return Ok(Outcome::Queued);
            }
            head = data;
        }
    }
    let mut file = match action {
        Action::Write { path, existed } => Some(BufWriter::with_capacity(
            1 << 20,
            create_file(path, *existed)?,
        )),
        _ => None,
    };
    let mut stdout = if matches!(action, Action::Stdout) {
        Some(io::stdout().lock())
    } else {
        None
    };
    let mut crc = crc32fast::Hasher::new();
    let mut total = 0u64;
    loop {
        let n = if !head.is_empty() {
            let n = head.len();
            buf[..n].copy_from_slice(&head);
            head.clear();
            n
        } else {
            read_decoded(reader, buf)?
        };
        if n == 0 {
            break;
        }
        if verify {
            crc.update(&buf[..n]);
        }
        if let Some(f) = file.as_mut() {
            f.write_all(&buf[..n])?;
        } else if let Some(o) = stdout.as_mut() {
            o.write_all(&buf[..n])?;
        }
        cb.add(n as u64);
        if cb.cancelled() {
            return Err(Error::Cancelled);
        }
        total += n as u64;
    }
    if let Some(o) = stdout.as_mut() {
        o.flush()?;
    }
    check_size(e, total)?;
    if verify {
        check_crc(e, crc.finalize())?;
    }
    if let (Some(f), Action::Write { path, .. }) = (file, action) {
        let f = f.into_inner().map_err(|e| Error::Io(e.into_error()))?;
        finish_file(f, path, e);
    }
    Ok(Outcome::Done(total))
}

/// Creates the target file, making parent directories only when they are missing.
pub(crate) fn create_file(path: &Path, existed: bool) -> Result<File> {
    if existed {
        clear_readonly(path);
    }
    match File::create(path) {
        Ok(f) => Ok(f),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            Ok(File::create(path)?)
        }
        Err(err) => Err(err.into()),
    }
}

fn write_whole(path: &Path, existed: bool, e: &Entry, data: &[u8]) -> Result<()> {
    let mut f = create_file(path, existed)?;
    f.write_all(data)?;
    finish_file(f, path, e);
    Ok(())
}

/// Applies timestamps through the open handle (no second open), closes, then attributes.
pub(crate) fn finish_file(f: File, path: &Path, e: &Entry) {
    let mut times = FileTimes::new();
    let mut any = false;
    if let Some(t) = e.mtime {
        times = times.set_modified(from_filetime(t));
        any = true;
    }
    if let Some(t) = e.atime {
        times = times.set_accessed(from_filetime(t));
        any = true;
    }
    #[cfg(windows)]
    if let Some(t) = e.ctime {
        use std::os::windows::fs::FileTimesExt;
        times = times.set_created(from_filetime(t));
        any = true;
    }
    if any {
        let _ = f.set_times(times);
    }
    drop(f);
    if let Some(a) = e.attrib {
        set_attributes(path, a);
    }
}

fn clear_readonly(p: &Path) {
    if let Ok(m) = fs::metadata(p) {
        let mut perm = m.permissions();
        if perm.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            let _ = fs::set_permissions(p, perm);
        }
    }
}

#[cfg(windows)]
fn set_attributes(p: &Path, a: u32) {
    use std::os::windows::ffi::OsStrExt;
    let bits = a & (attr::READONLY | attr::HIDDEN | attr::SYSTEM | attr::ARCHIVE);
    if bits & (attr::READONLY | attr::HIDDEN | attr::SYSTEM) == 0 {
        return;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn SetFileAttributesW(name: *const u16, attrs: u32) -> i32;
    }
    let w: Vec<u16> = p
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: `w` is a NUL-terminated wide string that outlives the call.
    unsafe {
        SetFileAttributesW(w.as_ptr(), bits);
    }
}

#[cfg(unix)]
fn set_attributes(p: &Path, a: u32) {
    use std::os::unix::fs::PermissionsExt;
    if a & attr::UNIX_EXTENSION != 0 {
        let mode = (a >> 16) & 0o7777;
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(mode));
    } else if a & attr::READONLY != 0 {
        if let Ok(m) = fs::metadata(p) {
            let mut perm = m.permissions();
            perm.set_readonly(true);
            let _ = fs::set_permissions(p, perm);
        }
    }
}

#[cfg(not(any(windows, unix)))]
fn set_attributes(_p: &Path, _a: u32) {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn path_sanitizing() {
        assert_eq!(
            safe_relative_path("a/b/c.txt"),
            Some(PathBuf::from("a").join("b").join("c.txt"))
        );
        assert_eq!(
            safe_relative_path("../../etc/passwd"),
            Some(PathBuf::from("etc").join("passwd"))
        );
        assert_eq!(
            safe_relative_path("/abs/x"),
            Some(PathBuf::from("abs").join("x"))
        );
        assert_eq!(safe_relative_path(".."), None);
        #[cfg(windows)]
        {
            assert_eq!(
                safe_relative_path("C:/x"),
                Some(PathBuf::from("C_").join("x"))
            );
            assert_eq!(
                safe_relative_path("con.txt"),
                Some(PathBuf::from("_con.txt"))
            );
        }
    }
}
