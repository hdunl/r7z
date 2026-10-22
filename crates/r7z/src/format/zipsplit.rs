//! Split zips: `x.z01`, `x.z02`, … and the last part, `x.zip`. Joined in order, the parts
//! are one zip archive: the central directory's offsets count from the first part, which
//! is also how `cat` recombines them (Info-ZIP's `zip -s` output).

use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use super::data::{materialize, Slice};
use crate::error::{Error, Result};

const EOCD: &[u8; 4] = b"PK\x05\x06";
/// An end-of-central-directory record with a maximal comment, plus the signature search.
const TAIL: u64 = 22 + 0xFFFF;

/// The parts of the split zip that `path` belongs to, in order, when `path` is one of its
/// parts (`x.z01`, or the last part `x.zip`, whose end-of-central-directory record names a
/// disk other than the first). `None` for anything else.
pub fn volumes(path: &Path) -> Option<Vec<PathBuf>> {
    let name = path.file_name()?.to_str()?;
    let (stem, ext) = name.rsplit_once('.')?;
    let dir = path.parent().unwrap_or(Path::new(""));
    let last = if ext.eq_ignore_ascii_case("zip") {
        path.to_path_buf()
    } else if is_part_ext(ext) {
        dir.join(format!("{stem}.zip"))
    } else {
        return None;
    };
    if !last_disk_is_not_first(&last) {
        return None;
    }
    let mut parts = Vec::new();
    for n in 1u32.. {
        let p = dir.join(format!("{stem}.z{n:02}"));
        if !p.is_file() {
            break;
        }
        parts.push(p);
    }
    if parts.is_empty() {
        return None;
    }
    parts.push(last);
    Some(parts)
}

/// `z01`, `z02`, …: a `z` and at least two digits.
fn is_part_ext(ext: &str) -> bool {
    let digits = ext.strip_prefix(['z', 'Z']).unwrap_or("");
    digits.len() >= 2 && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Whether the end-of-central-directory record of the file at `path` names a disk after
/// the first: the last part of a split zip does.
fn last_disk_is_not_first(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let Ok(len) = f.metadata().map(|m| m.len()) else {
        return false;
    };
    let from = len.saturating_sub(TAIL);
    let mut tail = Vec::new();
    if f.seek(SeekFrom::Start(from)).is_err() || f.read_to_end(&mut tail).is_err() {
        return false;
    }
    (0..tail.len().saturating_sub(21))
        .rev()
        .find(|&i| &tail[i..i + 4] == EOCD)
        .is_some_and(|i| tail[i + 4] != 0 || tail[i + 5] != 0)
}

/// The parts joined into one buffer, in order.
pub fn join(parts: &[PathBuf]) -> Result<Slice> {
    let mut size = 0u64;
    for p in parts {
        size += fs::metadata(p)?.len();
    }
    let mut chain: Box<dyn Read> = Box::new(std::io::empty());
    for p in parts {
        let f =
            File::open(p).map_err(|e| Error::Other(format!("cannot open {}: {e}", p.display())))?;
        chain = Box::new(chain.chain(f));
    }
    materialize(&mut chain, Some(size))
}
