//! Changing an existing archive: `a` and `u` add or replace entries, `d` deletes them and
//! `rn` renames them.
//!
//! A [`Plan`] says what becomes of each existing entry (kept, renamed or dropped) and which
//! new items are stored. Planning does not depend on the format. Each format writer carries a
//! plan out: 7z copies the folders a plan leaves alone and re-encodes only the solid blocks
//! it touches, zip copies untouched entries byte for byte, and tar rewrites its stream. Every
//! writer fills a temporary file beside the archive, and [`apply`] renames it over the archive
//! only after the writer succeeded, so a failed update leaves the original as it was.

mod sevenz;
mod single;

use std::collections::HashMap;
use std::path::Path;

use super::create::{temp_path, CreateOptions, Item, Progress, Summary};
use crate::error::{Error, Result};
use crate::format::data::{Input, Slice};
use crate::format::write::{Compressor, WriteOptions};
use crate::format::{Entry, Opened};
use crate::util::wildcard::Pattern;

/// What happens to one existing entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fate {
    /// Copied unchanged.
    Keep,
    /// Copied under a new name.
    Rename(String),
    /// Left out of the new archive.
    Drop,
}

/// Which existing entries an added item replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replace {
    /// `a`: every entry with the same name.
    Always,
    /// `u`: the same-named entries, but only when the item is newer than they are.
    IfNewer,
}

/// What a plan does, for the report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub added: u64,
    pub replaced: u64,
    pub deleted: u64,
    pub renamed: u64,
    /// Items `u` left alone because the archive has a copy at least as new.
    pub unchanged: u64,
}

/// The changes an update makes.
#[derive(Debug, Default)]
pub struct Plan {
    /// One per existing entry, in archive order.
    pub fates: Vec<Fate>,
    /// New items to store, with their archive names.
    pub add: Vec<Item>,
    pub counts: Counts,
}

impl Plan {
    fn keeping(existing: usize) -> Plan {
        Plan {
            fates: vec![Fate::Keep; existing],
            ..Plan::default()
        }
    }

    /// True when applying the plan would leave the archive as it is.
    pub fn is_noop(&self) -> bool {
        self.add.is_empty() && self.fates.iter().all(|f| *f == Fate::Keep)
    }
}

/// FILETIME ticks (100 ns) per second.
const FILETIME_PER_SECOND: u64 = 10_000_000;

/// Plans `a` (`Replace::Always`) or `u` (`Replace::IfNewer`): stores `items`, replacing the
/// existing entries of the same name as `replace` says.
pub fn plan_add(existing: &[Entry], items: Vec<Item>, replace: Replace) -> Plan {
    let mut plan = Plan::keeping(existing.len());
    let mut by_name: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, e) in existing.iter().enumerate() {
        by_name.entry(e.name.as_str()).or_default().push(i);
    }
    for item in items {
        let same: &[usize] = by_name.get(item.name.as_str()).map_or(&[], Vec::as_slice);
        if same.is_empty() {
            plan.counts.added += 1;
            plan.add.push(item);
            continue;
        }
        let replaces = match replace {
            Replace::Always => true,
            // A directory has no data to be out of date; `u` only renews files.
            Replace::IfNewer if item.is_dir && same.iter().all(|&i| existing[i].is_dir) => false,
            // Compared to the second: tar stores whole seconds, and zip's DOS times are coarser.
            Replace::IfNewer => {
                let newest = same.iter().filter_map(|&i| existing[i].mtime).max();
                match (item.mtime, newest) {
                    (Some(new), Some(old)) => new / FILETIME_PER_SECOND > old / FILETIME_PER_SECOND,
                    _ => true,
                }
            }
        };
        if replaces {
            for &i in same {
                plan.fates[i] = Fate::Drop;
            }
            plan.counts.replaced += 1;
            plan.add.push(item);
        } else {
            plan.counts.unchanged += 1;
        }
    }
    plan
}

/// Which entries a command applies to: the names it was given (wildcards allowed) and the
/// `-i` and `-x` switches.
#[derive(Debug, Default)]
pub struct Selection {
    include: Vec<Pattern>,
    exclude: Vec<Pattern>,
}

impl Selection {
    pub fn new(names: &[String], include: &[String], exclude: &[String]) -> Self {
        Selection {
            include: names
                .iter()
                .chain(include)
                .map(|s| Pattern::new(s))
                .collect(),
            exclude: exclude.iter().map(|s| Pattern::new(s)).collect(),
        }
    }

    /// True when the selection covers entry `name`. With no include patterns, everything
    /// not excluded is selected.
    pub fn selects(&self, name: &str) -> bool {
        (self.include.is_empty() || self.include.iter().any(|p| p.matches_path(name)))
            && !self.exclude.iter().any(|p| p.matches_path(name))
    }
}

/// Plans `d`: drops every entry the selection covers.
pub fn plan_delete(existing: &[Entry], selection: &Selection) -> Plan {
    let mut plan = Plan::keeping(existing.len());
    for (i, e) in existing.iter().enumerate() {
        if selection.selects(&e.name) {
            plan.fates[i] = Fate::Drop;
            plan.counts.deleted += 1;
        }
    }
    plan
}

/// Plans `rn`: for each `(old, new)` pair, every entry that `old` names moves to `new`.
///
/// `old` names an entry or a directory (its contents move with it). With wildcards it
/// matches the last path component, or the whole path when it contains a `/`; `*` and `?`
/// in `new` then stand for the text the wildcards matched, in order. Pairs apply one after
/// another. Fails when a pair matches nothing or two entries would end up with one name.
pub fn plan_rename(existing: &[Entry], pairs: &[(String, String)]) -> Result<Plan> {
    let mut plan = Plan::keeping(existing.len());
    let mut names: Vec<String> = existing.iter().map(|e| e.name.clone()).collect();
    for (old, new) in pairs {
        let old = old.trim_end_matches('/');
        let new = new.trim_end_matches('/');
        let mut hits = 0usize;
        for name in names.iter_mut() {
            if let Some(renamed) = rename_one(name, old, new) {
                *name = renamed;
                hits += 1;
            }
        }
        if hits == 0 {
            return Err(Error::usage(format!("no entry matches '{old}'")));
        }
    }
    for (i, name) in names.iter().enumerate() {
        if *name != existing[i].name {
            plan.fates[i] = Fate::Rename(name.clone());
            plan.counts.renamed += 1;
        }
    }
    let mut first: HashMap<&str, usize> = HashMap::new();
    for (i, name) in names.iter().enumerate() {
        match first.get(name.as_str()) {
            Some(&j) if plan.fates[i] != Fate::Keep || plan.fates[j] != Fate::Keep => {
                return Err(Error::usage(format!(
                    "renaming would give two entries the name '{name}'"
                )));
            }
            Some(_) => {}
            None => {
                first.insert(name.as_str(), i);
            }
        }
    }
    Ok(plan)
}

/// `name` after one rename pair, or `None` when the pair does not cover it.
fn rename_one(name: &str, old: &str, new: &str) -> Option<String> {
    if !Pattern::is_wild(old) {
        if name == old {
            return Some(new.to_string());
        }
        let rest = name.strip_prefix(old)?.strip_prefix('/')?;
        return Some(format!("{new}/{rest}"));
    }
    let whole_path = old.contains('/');
    let (dir, last) = match name.rsplit_once('/') {
        Some((d, l)) => (Some(d), l),
        None => (None, name),
    };
    let target = if whole_path { name } else { last };
    let p: Vec<char> = old.chars().collect();
    let t: Vec<char> = target.chars().collect();
    let caps = captures(&p, &t)?;
    let renamed = substitute(new, &caps);
    Some(match (whole_path, dir) {
        (false, Some(d)) => format!("{d}/{renamed}"),
        _ => renamed,
    })
}

fn same_char(a: char, b: char) -> bool {
    if cfg!(windows) {
        a.to_lowercase().eq(b.to_lowercase())
    } else {
        a == b
    }
}

/// The text each wildcard of `p` matched in `t`, or `None` when `p` does not match `t`.
/// Dynamic programming over (pattern position, text position), so long names cannot blow up.
fn captures(p: &[char], t: &[char]) -> Option<Vec<String>> {
    let (n, m) = (p.len(), t.len());
    // ok[i][j]: p[i..] matches t[j..].
    let mut ok = vec![vec![false; m + 1]; n + 1];
    ok[n][m] = true;
    for i in (0..n).rev() {
        for j in (0..=m).rev() {
            ok[i][j] = match p[i] {
                '*' => ok[i + 1][j] || (j < m && ok[i][j + 1]),
                '?' => j < m && ok[i + 1][j + 1],
                c => j < m && same_char(c, t[j]) && ok[i + 1][j + 1],
            };
        }
    }
    if !ok[0][0] {
        return None;
    }
    let (mut i, mut j) = (0usize, 0usize);
    let mut caps = Vec::new();
    while i < n {
        match p[i] {
            '*' => {
                let mut k = j;
                while !ok[i + 1][k] {
                    k += 1;
                }
                caps.push(t[j..k].iter().collect());
                i += 1;
                j = k;
            }
            '?' => {
                caps.push(t[j].to_string());
                i += 1;
                j += 1;
            }
            _ => {
                i += 1;
                j += 1;
            }
        }
    }
    Some(caps)
}

/// `new` with each `*` or `?` replaced by the next captured text.
fn substitute(new: &str, caps: &[String]) -> String {
    let mut out = String::with_capacity(new.len());
    let mut next = caps.iter();
    for c in new.chars() {
        match (c, next.clone().next()) {
            ('*' | '?', Some(text)) => {
                out.push_str(text);
                next.next();
            }
            _ => out.push(c),
        }
    }
    out
}

/// Where and how the new data of an update is compressed.
pub enum Settings<'a> {
    SevenZ(&'a CreateOptions),
    Other(&'a WriteOptions),
}

/// What an update did.
#[derive(Debug, Default)]
pub struct Outcome {
    pub summary: Summary,
    pub counts: Counts,
    /// 7z solid blocks that were decoded and encoded again.
    pub repacked: usize,
    /// False when the plan changed nothing and the archive was left alone.
    pub changed: bool,
}

/// Carries out `plan` on the archive at `archive`, which `opened` has parsed. The archive is
/// replaced only when the whole update succeeds.
pub fn apply(
    opened: Opened,
    archive: &Path,
    plan: &Plan,
    settings: Settings<'_>,
    progress: &dyn Progress,
) -> Result<Outcome> {
    if plan.is_noop() {
        return Ok(Outcome {
            counts: plan.counts,
            ..Outcome::default()
        });
    }
    let tmp = temp_path(archive);
    let written = write_temp(&opened, archive, &tmp, plan, &settings, progress);
    // Windows will not replace a file that is still mapped, so release the old archive first.
    drop(opened);
    match written {
        Ok(outcome) => match std::fs::rename(&tmp, archive) {
            Ok(()) => Ok(outcome),
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                Err(Error::Other(format!(
                    "cannot replace {}: {e}",
                    archive.display()
                )))
            }
        },
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn write_temp(
    opened: &Opened,
    archive: &Path,
    tmp: &Path,
    plan: &Plan,
    settings: &Settings<'_>,
    progress: &dyn Progress,
) -> Result<Outcome> {
    let levels = &opened.levels;
    let inner = opened.archive().format().name;
    match (levels.len(), inner, settings) {
        (1, "7z", Settings::SevenZ(opts)) => sevenz::write(archive, tmp, plan, opts, progress),
        (1, "zip", Settings::Other(opts)) => {
            crate::format::zip::update(archive, tmp, plan, opts, progress)
        }
        (1, "tar", Settings::Other(opts)) => {
            let open = Input::Mem(Slice::map_file(archive)?).opener();
            crate::format::tar::update(open, tmp, plan, None, opts, progress)
        }
        (1, "gzip" | "bzip2" | "xz" | "zstd" | "lz4" | "Z", Settings::Other(opts)) => {
            let comp = compressor_named(inner)?;
            single::write(opened, tmp, plan, comp, opts, progress)
        }
        (2, "tar", Settings::Other(opts)) => {
            let comp = compressor_named(levels[0].archive.format().name)?;
            let open = levels[0]
                .archive
                .stream(0)
                .ok_or_else(|| Error::unsupported("the compressed tar has no stream"))?;
            crate::format::tar::update(open, tmp, plan, Some(comp), opts, progress)
        }
        _ => Err(Error::unsupported(format!(
            "r7z cannot update {} archives (7z, zip, tar and compressed tar can be updated)",
            opened.archive().format().name
        ))),
    }
}

fn compressor_named(name: &str) -> Result<Compressor> {
    Ok(match name {
        "gzip" => Compressor::Gzip,
        "bzip2" => Compressor::Bzip2,
        "xz" => Compressor::Xz,
        "zstd" => Compressor::Zstd,
        "lz4" => Compressor::Lz4,
        "Z" => Compressor::Lzw,
        other => return Err(Error::unsupported(format!("{other} compression"))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, is_dir: bool) -> Entry {
        Entry {
            name: name.to_string(),
            is_dir,
            ..Entry::default()
        }
    }

    #[test]
    fn exact_and_directory_renames() {
        assert_eq!(
            rename_one("a.txt", "a.txt", "b.txt").as_deref(),
            Some("b.txt")
        );
        assert_eq!(rename_one("dir/x", "dir", "new").as_deref(), Some("new/x"));
        assert_eq!(rename_one("dirx/y", "dir", "new"), None);
        assert_eq!(rename_one("dir", "dir", "new").as_deref(), Some("new"));
    }

    #[test]
    fn wildcard_renames_keep_the_directory() {
        assert_eq!(
            rename_one("sub/a.txt", "*.txt", "*.bak").as_deref(),
            Some("sub/a.bak")
        );
        assert_eq!(rename_one("sub/a.bin", "*.txt", "*.bak"), None);
        assert_eq!(
            rename_one("sub/file1.txt", "file?.txt", "x-*.md").as_deref(),
            Some("sub/x-1.md")
        );
        assert_eq!(
            rename_one("dir/a.c", "dir/*.c", "dir/*.h").as_deref(),
            Some("dir/a.h")
        );
    }

    #[test]
    fn captures_handle_repeated_stars() {
        let p: Vec<char> = "*a*b*".chars().collect();
        let t: Vec<char> = "xaybzb".chars().collect();
        let caps = captures(&p, &t).unwrap();
        assert_eq!(caps, ["x", "y", "zb"]);
        assert!(captures(&p, &"zzz".chars().collect::<Vec<_>>()).is_none());
    }

    #[test]
    fn plan_add_replaces_by_policy() {
        const SECOND: u64 = FILETIME_PER_SECOND;
        let mut existing = vec![entry("a", false), entry("b", false)];
        existing[0].mtime = Some(100 * SECOND);
        let mut newer = Item {
            src: "x".into(),
            name: "a".into(),
            is_dir: false,
            size: 1,
            mtime: Some(110 * SECOND),
            ctime: None,
            atime: None,
            attrib: None,
        };
        let always = plan_add(&existing, vec![newer.clone()], Replace::Always);
        assert_eq!(always.fates[0], Fate::Drop);
        assert_eq!(always.counts.replaced, 1);
        // `u` replaces an older entry; a copy ten seconds newer on disk is newer.
        let if_newer = plan_add(&existing, vec![newer.clone()], Replace::IfNewer);
        assert_eq!(if_newer.fates[0], Fate::Drop);
        newer.mtime = Some(90 * SECOND);
        let older = plan_add(&existing, vec![newer.clone()], Replace::IfNewer);
        assert_eq!(older.fates[0], Fate::Keep);
        assert_eq!(older.counts.unchanged, 1);
        assert!(older.add.is_empty());
        // Sub-second differences do not count: archives store coarser times.
        newer.mtime = Some(100 * SECOND + 5);
        let same_second = plan_add(&existing, vec![newer], Replace::IfNewer);
        assert_eq!(same_second.fates[0], Fate::Keep);
    }

    #[test]
    fn rename_collisions_are_refused() {
        let existing = vec![entry("a", false), entry("b", false)];
        let pairs = vec![("a".to_string(), "b".to_string())];
        assert!(plan_rename(&existing, &pairs).is_err());
        let pairs = vec![("a".to_string(), "c".to_string())];
        let plan = plan_rename(&existing, &pairs).unwrap();
        assert_eq!(plan.fates[0], Fate::Rename("c".into()));
        assert_eq!(plan.counts.renamed, 1);
    }
}
