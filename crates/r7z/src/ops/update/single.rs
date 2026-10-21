//! Updates to single-stream compressed files (`x.gz`, `x.bz2`, `x.xz`), which hold one file.
//! Adding a file replaces the stored content; renaming rewrites the stored name.

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use super::{Fate, Outcome, Plan};
use crate::error::{Error, Result};
use crate::format::write::{self, Compressor, WriteOptions};
use crate::format::Opened;
use crate::ops::create::{Progress, Summary};
use crate::util::time::filetime_to_unix;

pub fn write(
    opened: &Opened,
    tmp: &Path,
    plan: &Plan,
    comp: Compressor,
    opts: &WriteOptions,
    progress: &dyn Progress,
) -> Result<Outcome> {
    let archive = opened.archive();
    let stored = match archive.entries() {
        [e] => e,
        _ => {
            return Err(Error::unsupported(
                "a compressed stream without exactly one entry",
            ))
        }
    };
    let kind = archive.format().name;
    let mut counts = plan.counts;
    let file = BufWriter::with_capacity(
        1 << 20,
        File::create(tmp)
            .map_err(|e| Error::Other(format!("cannot create {}: {e}", tmp.display())))?,
    );
    let (out, total) = match (plan.add.as_slice(), &plan.fates[0]) {
        ([], Fate::Drop) => {
            return Err(Error::usage(format!(
                "cannot delete the only file of a {kind} archive; remove the archive instead"
            )))
        }
        ([], Fate::Rename(new)) => {
            let open = archive
                .stream(0)
                .ok_or_else(|| Error::unsupported("reading the compressed stream"))?;
            let mut src = open()?;
            let mtime = stored
                .mtime
                .map(filetime_to_unix)
                .unwrap_or(0)
                .clamp(0, u32::MAX as i64) as u32;
            write::compress_single(
                file,
                comp,
                opts,
                write::single_name(new),
                if opts.store_mtime { mtime } else { 0 },
                &mut src,
                stored.size_or_zero(),
                &stored.name,
                progress,
            )?
        }
        ([], Fate::Keep) => {
            return Err(Error::Other(
                "internal error: an unchanged archive was rewritten".into(),
            ))
        }
        ([item], _) if !item.is_dir => {
            // The one file replaces whatever the stream held.
            counts.added = 0;
            counts.replaced = 1;
            let mut src = File::open(&item.src)
                .map_err(|e| Error::Other(format!("cannot open {}: {e}", item.src.display())))?;
            write::compress_single(
                file,
                comp,
                opts,
                write::single_name(&item.name),
                write::single_mtime(item, opts),
                &mut src,
                item.size,
                &item.src.display().to_string(),
                progress,
            )?
        }
        ([_], _) => {
            return Err(Error::usage(format!(
                "a {kind} archive holds one file, not a directory; use a .tar.{} archive",
                comp_ext(comp)
            )))
        }
        _ => {
            return Err(Error::usage(format!(
                "a {kind} archive holds one file; use a .tar.{} archive for several files",
                comp_ext(comp)
            )))
        }
    };
    let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
    file.sync_all().ok();
    Ok(Outcome {
        summary: Summary {
            files: 1,
            input_bytes: total,
            archive_bytes: file.metadata()?.len(),
            threads_used: opts.threads,
            ..Summary::default()
        },
        counts,
        repacked: 0,
        changed: true,
    })
}

fn comp_ext(c: Compressor) -> &'static str {
    match c {
        Compressor::Gzip => "gz",
        Compressor::Bzip2 => "bz2",
        Compressor::Xz => "xz",
    }
}
