//! Recovery of damaged archives: everything that can still be read is extracted, and every
//! entry gets an outcome (recovered, partial or lost, with the reason) instead of the
//! whole operation failing.
//!
//! The archive is opened with `format::open_recover`, so handlers rebuild what they can
//! (a zip entry list from local headers, a lost 7z header, tar past a bad header) and
//! compressed streams end at their first error. Extraction then keeps the bytes decoded
//! before damage, and in solid 7z blocks resumes at the next LZMA2 dictionary reset, so
//! files after the damaged part are not lost with it.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::sync::Mutex;

use rayon::prelude::*;

use super::extract::{
    create_file, finish_file, link_hard, plan, read_decoded, stamp_dirs, write_unitless, Action,
    Callbacks, ExtractOptions, Target,
};
use crate::error::{Error, Result};
use crate::format::{self, Archive, Ctx, Entry, Flow, OpenRequest, Opened};

/// What became of one entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Complete. `verified` is false when the archive has no checksum for it (a zip entry
    /// whose data descriptor was lost, any tar entry).
    Recovered { verified: bool },
    /// Some data was decoded, but it is incomplete or fails its checksum. `kept` says
    /// whether those bytes were written out.
    Partial {
        bytes: u64,
        kept: bool,
        reason: String,
    },
    /// Nothing usable.
    Lost { reason: String },
}

#[derive(Clone, Debug)]
pub struct EntryOutcome {
    pub index: usize,
    pub name: String,
    pub size: Option<u64>,
    pub outcome: Outcome,
}

#[derive(Debug, Default)]
pub struct RecoverReport {
    /// What opening had to rebuild or skip, and where decoding resumed after damage.
    pub notes: Vec<String>,
    /// One per selected file, in archive order.
    pub entries: Vec<EntryOutcome>,
    pub dirs: u64,
    /// Bytes decoded into recovered and kept partial files.
    pub bytes: u64,
    /// Existing files left alone.
    pub skipped: u64,
}

impl RecoverReport {
    fn count(&self, f: impl Fn(&Outcome) -> bool) -> usize {
        self.entries.iter().filter(|e| f(&e.outcome)).count()
    }
    pub fn recovered(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Recovered { .. }))
    }
    pub fn partial(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Partial { .. }))
    }
    pub fn lost(&self) -> usize {
        self.count(|o| matches!(o, Outcome::Lost { .. }))
    }
    /// Nothing was damaged: every entry came out whole and nothing had to be rebuilt.
    pub fn intact(&self) -> bool {
        self.notes.is_empty() && self.recovered() == self.entries.len()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RecoverOptions {
    /// Write out the readable part of damaged files (under their own names). Otherwise they
    /// are removed (and reported as partial, not kept).
    pub keep_partial: bool,
}

impl Default for RecoverOptions {
    fn default() -> Self {
        RecoverOptions { keep_partial: true }
    }
}

/// Opens `path` for recovery and extracts what can be read.
pub fn recover_file(
    path: &Path,
    password: Option<String>,
    opts: &ExtractOptions,
    rec: RecoverOptions,
    cb: &dyn Callbacks,
) -> Result<RecoverReport> {
    let opened = format::open_recover(
        path,
        &OpenRequest {
            password,
            ..Default::default()
        },
    )?;
    recover(&opened, opts, rec, cb)
}

/// Extracts (or with `Target::Test`, decodes) everything readable from an archive opened
/// with `format::open_recover`. Fails only for problems with the whole run (cancellation,
/// a missing password, an unusable target); damage is reported per entry.
pub fn recover(
    opened: &Opened,
    opts: &ExtractOptions,
    rec: RecoverOptions,
    cb: &dyn Callbacks,
) -> Result<RecoverReport> {
    if matches!(opts.target, Target::Stdout) {
        return Err(Error::usage(
            "recovery writes files; it cannot write to stdout",
        ));
    }
    let a = opened.archive();
    let entries = a.entries();
    let plan = plan(a, opts, cb)?;
    let mut outcomes: Vec<Option<Outcome>> = vec![None; entries.len()];
    for (i, err) in &plan.errors {
        outcomes[*i] = Some(Outcome::Lost {
            reason: describe(err, false),
        });
    }
    for (i, r) in write_unitless(a, &plan, cb) {
        outcomes[i] = Some(match r {
            Ok(()) => Outcome::Recovered { verified: true },
            Err(e) => Outcome::Lost {
                reason: describe(&e, false),
            },
        });
    }

    let units: Vec<usize> = (0..a.units().len())
        .filter(|&u| {
            a.units()[u]
                .entries
                .iter()
                .any(|&i| !matches!(plan.actions[i], Action::Skip))
        })
        .collect();
    let threads = opts.threads.max(1);
    // One thread per unit: a parallel LZMA2 decoder reports an error in a later block
    // before handing over the blocks decoded ahead of it, which would lose those files.
    let ctx = Ctx {
        password: opts.password.clone(),
        threads: 1,
    };
    let shared = Mutex::new((outcomes, 0u64, Vec::<String>::new()));
    let fatal: Mutex<Option<Error>> = Mutex::new(None);
    let run = |u: usize| {
        if fatal.lock().unwrap().is_some() {
            return;
        }
        let r = recover_unit(a, u, &plan.actions, &ctx, rec, cb);
        match r {
            Ok(done) => {
                let mut s = shared.lock().unwrap();
                for (i, o, bytes) in done.outcomes {
                    s.0[i] = Some(o);
                    s.1 += bytes;
                }
                s.2.extend(done.notes);
            }
            Err(e) => {
                fatal.lock().unwrap().get_or_insert(e);
            }
        }
    };
    if units.len() <= 1 || threads == 1 {
        units.iter().for_each(|&u| run(u));
    } else {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| Error::Other(e.to_string()))?;
        pool.install(|| units.par_iter().for_each(|&u| run(u)));
    }
    if let Some(e) = fatal.into_inner().unwrap() {
        return Err(e);
    }
    if cb.cancelled() {
        return Err(Error::Cancelled);
    }
    let (mut outcomes, bytes, resumed) = shared.into_inner().unwrap();
    for (i, r) in link_hard(a, &plan) {
        outcomes[i] = Some(match r {
            Ok(()) => Outcome::Recovered { verified: true },
            Err(e) => Outcome::Lost {
                reason: describe(&e, false),
            },
        });
    }
    let mut report = RecoverReport {
        notes: opened.damage(),
        dirs: plan.dirs,
        skipped: plan.skipped,
        bytes,
        ..Default::default()
    };
    report.notes.extend(resumed);
    for (i, e) in entries.iter().enumerate() {
        if e.is_dir || (matches!(plan.actions[i], Action::Skip) && outcomes[i].is_none()) {
            continue;
        }
        let outcome = outcomes[i].take().unwrap_or_else(|| Outcome::Lost {
            reason: "not reached".into(),
        });
        report.entries.push(EntryOutcome {
            index: i,
            name: e.name.clone(),
            size: e.size,
            outcome,
        });
    }
    stamp_dirs(a, plan);
    Ok(report)
}

/// A reason for the outcome list: the message without the generic prefixes.
fn describe(e: &Error, encrypted: bool) -> String {
    let m = match e {
        Error::Corrupt(m) => m.trim_start_matches("data error: ").to_string(),
        Error::Checksum(_) => "CRC mismatch".into(),
        other => other.to_string(),
    };
    if encrypted && matches!(e, Error::Corrupt(_) | Error::Checksum(_)) {
        format!("wrong password or damaged data ({m})")
    } else {
        m
    }
}

struct UnitResult {
    outcomes: Vec<(usize, Outcome, u64)>,
    notes: Vec<String>,
}

/// Recovers one unit. After a decoding error, decoding resumes at the unit's next restart
/// point past the damage, if it has one.
fn recover_unit(
    a: &dyn Archive,
    u: usize,
    actions: &[Action],
    ctx: &Ctx,
    rec: RecoverOptions,
    cb: &dyn Callbacks,
) -> Result<UnitResult> {
    let unit = &a.units()[u];
    let entries = a.entries();
    let verifies = a.verifies_data();
    let mut res = UnitResult {
        outcomes: Vec::new(),
        notes: Vec::new(),
    };
    let wanted: Vec<usize> = unit
        .entries
        .iter()
        .copied()
        .filter(|&i| !matches!(actions[i], Action::Skip))
        .collect();
    let Some(&last) = wanted.last() else {
        return Ok(res);
    };
    // Where each entry starts in the unit's decoded stream, when sizes are known.
    let starts: Option<HashMap<usize, u64>> = (|| {
        let mut pos = 0u64;
        let mut m = HashMap::with_capacity(unit.entries.len());
        for &i in &unit.entries {
            m.insert(i, pos);
            // Sizes come from the header; a total past u64 means the starts are unknown.
            pos = pos.checked_add(entries[i].size?)?;
        }
        Some(m)
    })();
    let start_of = |i: usize| -> Option<u64> { starts.as_ref()?.get(&i).copied() };
    let mut done: HashSet<usize> = HashSet::new();
    // How far decoding got: an entry's start plus the bytes read from it.
    let mut reached = 0u64;
    let mut buf = vec![0u8; 1 << 20];
    let mut result = {
        let mut f = |i: usize, r: &mut dyn Read| -> Result<Flow> {
            entry_cb(
                i,
                r,
                a,
                actions,
                rec,
                verifies,
                unit.encrypted,
                cb,
                &mut buf,
                &mut res,
                &mut done,
                &mut reached,
                &start_of,
            )?;
            Ok(if i == last {
                Flow::Stop
            } else {
                Flow::Continue
            })
        };
        a.extract_unit(u, ctx, &mut f)
    };
    let mut floor = 0u64;
    while let Err(err) = result {
        if matches!(
            err,
            Error::Cancelled | Error::PasswordRequired | Error::Usage(_)
        ) {
            return Err(err);
        }
        let reason = describe(&err, unit.encrypted);
        let restart = if starts.is_some() {
            a.restart_points(u)
                .into_iter()
                .find(|&r| r > reached.max(floor) && r > 0)
        } else {
            None
        };
        let Some(r) = restart else {
            for &i in &wanted {
                if done.insert(i) {
                    res.outcomes.push((
                        i,
                        Outcome::Lost {
                            reason: reason.clone(),
                        },
                        0,
                    ));
                }
            }
            break;
        };
        let mut skipped = 0;
        for &i in &wanted {
            if start_of(i).is_some_and(|s| s < r) && done.insert(i) {
                skipped += 1;
                res.outcomes.push((
                    i,
                    Outcome::Lost {
                        reason: format!("{reason} (in the damaged part of a solid block)"),
                    },
                    0,
                ));
            }
        }
        if wanted.iter().all(|i| done.contains(i)) {
            break;
        }
        res.notes.push(format!(
            "block {u}: resumed decoding at a dictionary reset {} bytes into the block, past \
             the damage ({skipped} files in between were lost)",
            r
        ));
        floor = r;
        reached = r;
        result = {
            let mut f = |i: usize, rd: &mut dyn Read| -> Result<Flow> {
                entry_cb(
                    i,
                    rd,
                    a,
                    actions,
                    rec,
                    verifies,
                    unit.encrypted,
                    cb,
                    &mut buf,
                    &mut res,
                    &mut done,
                    &mut reached,
                    &start_of,
                )?;
                Ok(if i == last {
                    Flow::Stop
                } else {
                    Flow::Continue
                })
            };
            a.extract_unit_at(u, r, ctx, &mut f)
        };
    }
    Ok(res)
}

/// Saves one entry inside a unit callback. Returns `Err` when the decoder failed, so the
/// format stops reading a stream whose position is lost.
#[allow(clippy::too_many_arguments)]
fn entry_cb(
    i: usize,
    r: &mut dyn Read,
    a: &dyn Archive,
    actions: &[Action],
    rec: RecoverOptions,
    verifies: bool,
    encrypted: bool,
    cb: &dyn Callbacks,
    buf: &mut [u8],
    res: &mut UnitResult,
    done: &mut HashSet<usize>,
    reached: &mut u64,
    start_of: &dyn Fn(usize) -> Option<u64>,
) -> Result<()> {
    if matches!(actions[i], Action::Skip) || done.contains(&i) {
        return Ok(());
    }
    let e = &a.entries()[i];
    let start = start_of(i);
    done.insert(i);
    let (outcome, bytes, broken) = save(r, e, &actions[i], rec, verifies, encrypted, cb, buf)?;
    if let Some(s) = start {
        *reached = s + bytes;
    }
    let written = match &outcome {
        Outcome::Recovered { .. } => bytes,
        Outcome::Partial {
            kept: true, bytes, ..
        } => *bytes,
        _ => 0,
    };
    let good = matches!(outcome, Outcome::Recovered { .. });
    res.outcomes.push((i, outcome, written));
    if good {
        cb.file_done(&e.name);
    }
    match broken {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Copies one entry to its destination. Returns the outcome, the bytes decoded, and the
/// decoder error when the data stream itself broke. `Err` only for cancellation.
#[allow(clippy::too_many_arguments)]
fn save(
    reader: &mut dyn Read,
    e: &Entry,
    action: &Action,
    rec: RecoverOptions,
    verifies: bool,
    encrypted: bool,
    cb: &dyn Callbacks,
    buf: &mut [u8],
) -> Result<(Outcome, u64, Option<Error>)> {
    let path = match action {
        Action::Write { path, existed } => match create_file(path, *existed) {
            Ok(f) => Some((path, BufWriter::with_capacity(1 << 20, f))),
            Err(err) => {
                return Ok((
                    Outcome::Lost {
                        reason: describe(&err, false),
                    },
                    0,
                    None,
                ))
            }
        },
        _ => None,
    };
    let mut file = path;
    let check = !verifies && e.crc.is_some();
    let mut crc = crc32fast::Hasher::new();
    let mut total = 0u64;
    let mut broken: Option<Error> = None;
    loop {
        match read_decoded(reader, buf) {
            Ok(0) => break,
            Ok(n) => {
                if check {
                    crc.update(&buf[..n]);
                }
                if let Some((p, f)) = file.as_mut() {
                    if let Err(err) = f.write_all(&buf[..n]) {
                        let p = p.to_path_buf();
                        drop(file.take());
                        let _ = fs::remove_file(&p);
                        return Ok((
                            Outcome::Lost {
                                reason: describe(&err.into(), false),
                            },
                            total,
                            None,
                        ));
                    }
                }
                total += n as u64;
                cb.add(n as u64);
                if cb.cancelled() {
                    if let Some((p, f)) = file.take() {
                        drop(f);
                        let _ = fs::remove_file(p);
                    }
                    return Err(Error::Cancelled);
                }
            }
            Err(Error::Cancelled) => return Err(Error::Cancelled),
            Err(err) => {
                broken = Some(err);
                break;
            }
        }
    }
    let damage: Option<String> = if let Some(err) = &broken {
        Some(describe(err, encrypted))
    } else if e.size.is_some_and(|want| total < want) {
        Some(format!(
            "the data ends after {total} of {} bytes",
            e.size.unwrap_or(0)
        ))
    } else if check && Some(crc.finalize()) != e.crc {
        Some(if encrypted {
            "wrong password or damaged data (CRC mismatch)".into()
        } else {
            "CRC mismatch: the content is damaged".into()
        })
    } else {
        None
    };
    let keep = damage.is_none() || (rec.keep_partial && total > 0);
    let mut file_err = None;
    if let Some((p, f)) = file {
        if keep {
            match f.into_inner() {
                Ok(f) => finish_file(f, p, e),
                Err(err) => file_err = Some(Error::Io(err.into_error())),
            }
        } else {
            drop(f);
            let _ = fs::remove_file(p);
        }
    }
    if let Some(err) = file_err {
        return Ok((
            Outcome::Lost {
                reason: describe(&err, false),
            },
            total,
            broken,
        ));
    }
    let outcome = match damage {
        None => Outcome::Recovered {
            verified: verifies || e.crc.is_some(),
        },
        Some(reason) if total > 0 => Outcome::Partial {
            bytes: total,
            kept: keep && !matches!(action, Action::Test),
            reason,
        },
        Some(reason) => Outcome::Lost { reason },
    };
    Ok((outcome, total, broken))
}

/// Renders outcomes as `name: reason` lines, grouped when many share a reason (a damaged
/// solid block loses every file after the damage for the same reason).
pub fn summary_lines(report: &RecoverReport, limit: usize) -> Vec<String> {
    let mut groups: Vec<(String, Vec<&str>)> = Vec::new();
    for e in &report.entries {
        let key = match &e.outcome {
            Outcome::Recovered { .. } => continue,
            Outcome::Partial { kept, reason, .. } => {
                format!(
                    "partial ({}): {reason}",
                    if *kept { "kept" } else { "removed" }
                )
            }
            Outcome::Lost { reason } => format!("lost: {reason}"),
        };
        match groups.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => v.push(&e.name),
            None => groups.push((key, vec![&e.name])),
        }
    }
    let mut out = Vec::new();
    for (key, names) in groups {
        if out.len() >= limit {
            out.push("...".into());
            break;
        }
        if names.len() == 1 {
            out.push(format!("{}: {key}", names[0]));
        } else {
            out.push(format!("{} files {key}", names.len()));
            for n in names.iter().take(3) {
                out.push(format!("    {n}"));
            }
            if names.len() > 3 {
                out.push(format!("    and {} more", names.len() - 3));
            }
        }
    }
    out
}
