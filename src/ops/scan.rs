//! Turns command-line names into archive items, 7-Zip style: relative paths are stored as
//! given, absolute paths by their last component, directories recursively.

use std::collections::HashSet;
use std::fs::{self, Metadata};
use std::path::{Component, Path, PathBuf};

use crate::ops::create::Item;
use crate::sevenz::attr;
use crate::util::time::to_filetime;
use crate::util::wildcard::Pattern;

pub struct Scan {
    pub items: Vec<Item>,
    pub warnings: Vec<String>,
}

/// Archive-side name for an input path: drop roots, drives, `.` and leading `..`.
/// Absolute inputs keep only their final component.
fn archive_name(p: &Path) -> String {
    let absolute = p.is_absolute()
        || p.components()
            .any(|c| matches!(c, Component::Prefix(_) | Component::RootDir));
    if absolute {
        return p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
    }
    let parts: Vec<String> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect();
    parts.join("/")
}

#[cfg(windows)]
fn attributes(m: &Metadata) -> u32 {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0xFFFF
}

#[cfg(unix)]
fn attributes(m: &Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    let mode = m.permissions().mode();
    let mut a = attr::UNIX_EXTENSION | (mode << 16);
    if m.is_dir() {
        a |= attr::DIRECTORY;
    }
    if mode & 0o200 == 0 {
        a |= attr::READONLY;
    }
    a
}

#[cfg(not(any(windows, unix)))]
fn attributes(m: &Metadata) -> u32 {
    if m.is_dir() {
        attr::DIRECTORY
    } else {
        0
    }
}

fn make_item(src: PathBuf, name: String, m: &Metadata) -> Item {
    let mut a = attributes(m);
    if m.is_dir() {
        a |= attr::DIRECTORY;
    }
    Item {
        src,
        name,
        is_dir: m.is_dir(),
        size: if m.is_dir() { 0 } else { m.len() },
        mtime: m.modified().ok().map(to_filetime),
        ctime: m.created().ok().map(to_filetime),
        atime: m.accessed().ok().map(to_filetime),
        attrib: Some(a),
    }
}

struct Ctx<'a> {
    exclude: &'a [Pattern],
    skip: Option<PathBuf>,
    seen: HashSet<String>,
    out: Scan,
}

impl Ctx<'_> {
    fn excluded(&self, name: &str) -> bool {
        self.exclude.iter().any(|p| p.matches_path(name))
    }

    fn push(&mut self, src: PathBuf, name: String, m: &Metadata) {
        if name.is_empty() || self.excluded(&name) {
            return;
        }
        let key = if cfg!(windows) {
            name.to_lowercase()
        } else {
            name.clone()
        };
        if self.seen.insert(key) {
            self.out.items.push(make_item(src, name, m));
        }
    }

    fn walk(&mut self, dir: &Path, prefix: &str, depth: usize) {
        if depth > 256 {
            self.out
                .warnings
                .push(format!("{}: directory nesting too deep", dir.display()));
            return;
        }
        let rd = match fs::read_dir(dir) {
            Ok(r) => r,
            Err(e) => {
                self.out.warnings.push(format!("{}: {e}", dir.display()));
                return;
            }
        };
        let mut children: Vec<_> = rd.filter_map(|e| e.ok()).collect();
        children.sort_by_key(|e| e.file_name());
        for ent in children {
            let path = ent.path();
            let fname = ent.file_name().to_string_lossy().into_owned();
            let name = if prefix.is_empty() {
                fname
            } else {
                format!("{prefix}/{fname}")
            };
            // On Windows the directory listing already carries this metadata, which saves
            // opening every file during the scan.
            match ent.metadata() {
                Ok(m) => self.add_entry(&path, name, m, depth + 1),
                Err(_) => self.add_path(&path, name, depth + 1),
            }
        }
    }

    fn add_path(&mut self, path: &Path, name: String, depth: usize) {
        match fs::symlink_metadata(path) {
            Ok(m) => self.add_entry(path, name, m, depth),
            Err(e) => self.out.warnings.push(format!("{}: {e}", path.display())),
        }
    }

    /// `lm` is the entry's own metadata (links not followed).
    fn add_entry(&mut self, path: &Path, name: String, lm: Metadata, depth: usize) {
        if let Some(skip) = &self.skip {
            if path.file_name() == skip.file_name()
                && fs::canonicalize(path).ok().as_ref() == Some(skip)
            {
                return;
            }
        }
        let m = if lm.file_type().is_symlink() {
            match fs::metadata(path) {
                Ok(m) if m.is_dir() => {
                    // Not following directory links avoids cycles and surprise expansion.
                    self.out
                        .warnings
                        .push(format!("{}: skipping directory link", path.display()));
                    return;
                }
                Ok(m) => m,
                Err(e) => {
                    self.out.warnings.push(format!("{}: {e}", path.display()));
                    return;
                }
            }
        } else {
            lm
        };
        if !name.is_empty() && self.excluded(&name) {
            return;
        }
        self.push(path.to_path_buf(), name.clone(), &m);
        if m.is_dir() {
            self.walk(path, &name, depth);
        }
    }
}

/// Collects items for `names`. `archive` is excluded if it lies inside an input directory.
pub fn scan(names: &[String], recurse: bool, exclude: &[Pattern], archive: &Path) -> Scan {
    let mut ctx = Ctx {
        exclude,
        skip: fs::canonicalize(archive).ok(),
        seen: HashSet::new(),
        out: Scan {
            items: Vec::new(),
            warnings: Vec::new(),
        },
    };
    for raw in names {
        let path = PathBuf::from(raw);
        let file_part = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        if Pattern::is_wild(&file_part) {
            let dir = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            let pat = Pattern::new(&file_part);
            let base = archive_name(&path.parent().map(Path::to_path_buf).unwrap_or_default());
            wild_add(&mut ctx, &dir, &base, &pat, recurse, 0);
            continue;
        }
        if !path.exists() && fs::symlink_metadata(&path).is_err() {
            ctx.out
                .warnings
                .push(format!("{raw}: no such file or directory"));
            continue;
        }
        let name = archive_name(&path);
        if name.is_empty() {
            // `.` or `dir/.`: store the directory's contents at the archive root.
            ctx.walk(&path, "", 0);
        } else {
            ctx.add_path(&path, name, 0);
        }
    }
    ctx.out
}

fn wild_add(ctx: &mut Ctx, dir: &Path, prefix: &str, pat: &Pattern, recurse: bool, depth: usize) {
    let rd = match fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            ctx.out.warnings.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    let mut children: Vec<_> = rd.filter_map(|e| e.ok()).collect();
    children.sort_by_key(|e| e.file_name());
    for ent in children {
        let fname = ent.file_name().to_string_lossy().into_owned();
        let name = if prefix.is_empty() {
            fname.clone()
        } else {
            format!("{prefix}/{fname}")
        };
        let is_dir = ent.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if pat.matches_name(&fname) {
            ctx.add_path(&ent.path(), name.clone(), depth + 1);
        } else if recurse && is_dir && depth < 256 {
            wild_add(ctx, &ent.path(), &name, pat, recurse, depth + 1);
        }
    }
}
