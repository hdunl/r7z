use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use console::style;

use super::args::Args;
use super::ui::{self, grouped, rate, secs};
use super::{EXIT_FATAL, EXIT_OK, EXIT_WARNING};
use r7z::ops::scan::scan;
use std::collections::{HashMap, HashSet};

use r7z::codec::{can_decode, can_encode, method, method_name};
use r7z::error::{Error, Result};
use r7z::format::write::{self, Kind, WriteOptions};
use r7z::format::{self, find_format, Archive, Format, Link, OpenRequest, Opened, FORMATS};
use r7z::ops::bench;
use r7z::ops::create::Item;
use r7z::ops::create::{
    self, default_solid_limit, level_dict_size, CreateOptions, FilterMode, MainMethod,
};
use r7z::ops::extract::{self, ExtractOptions, Overwrite, Target};
use r7z::ops::hash::{hash_files, HashKind};
use r7z::ops::update::{self, Replace};
use r7z::util::fmt::human_size;
use r7z::util::time::format_filetime;
use r7z::util::wildcard::Pattern;

fn threads(a: &Args) -> usize {
    a.threads.unwrap_or_else(r7z::util::default_threads)
}

fn given_password(a: &Args, confirm: bool) -> Result<Option<String>> {
    match &a.password {
        None => Ok(None),
        Some(Some(p)) => Ok(Some(p.clone())),
        Some(None) => ui::prompt_password(confirm)
            .map(Some)
            .ok_or_else(|| Error::usage("a password is required (-p<password>)")),
    }
}

/// The format forced with `-t`, if any.
fn forced_format(a: &Args) -> Option<&'static Format> {
    a.archive_type.as_deref().and_then(find_format)
}

/// Opens an archive, prompting for a password when the header is encrypted.
fn open(a: &Args, need_data: bool) -> Result<(Opened, Option<String>)> {
    let path = a.archive.as_ref().unwrap();
    if !path.exists() {
        return Err(Error::Other(format!(
            "cannot open {}: file not found",
            path.display()
        )));
    }
    let mut pw = given_password(a, false)?;
    let mut tries = 0;
    loop {
        let req = OpenRequest {
            password: pw.clone(),
            format: forced_format(a),
            code_page: a.code_page,
            split: false,
        };
        let opened = if a.recover {
            format::open_recover(path, &req)
        } else {
            format::open(path, &req)
        };
        match opened {
            Ok(o) => {
                if need_data && pw.is_none() && o.archive().has_encrypted_data() {
                    pw = Some(ui::prompt_password(false).ok_or(Error::PasswordRequired)?);
                }
                return Ok((o, pw));
            }
            Err(Error::PasswordRequired) if pw.is_none() => {
                pw = Some(ui::prompt_password(false).ok_or(Error::PasswordRequired)?);
            }
            Err(Error::WrongPassword)
                if tries < 2 && a.password != Some(pw.clone()) && ui::stderr_tty() =>
            {
                ui::error("wrong password");
                tries += 1;
                pw = Some(ui::prompt_password(false).ok_or(Error::WrongPassword)?);
            }
            Err(Error::NotArchive) => {
                return Err(Error::Other(match forced_format(a) {
                    Some(f) => format!("{} is not a {} archive", path.display(), f.name),
                    None => format!(
                        "{} is not an archive r7z recognizes (run 'r7z i' for supported formats)",
                        path.display()
                    ),
                }));
            }
            Err(e) => return Err(e),
        }
    }
}

fn selection(arc: &dyn Archive, a: &Args) -> Option<Vec<bool>> {
    if a.names.is_empty() && a.include.is_empty() && a.exclude.is_empty() {
        return None;
    }
    let inc: Vec<Pattern> = a
        .names
        .iter()
        .chain(&a.include)
        .map(|s| Pattern::new(s))
        .collect();
    let exc: Vec<Pattern> = a.exclude.iter().map(|s| Pattern::new(s)).collect();
    Some(
        arc.entries()
            .iter()
            .map(|e| {
                (inc.is_empty() || inc.iter().any(|p| p.matches_path(&e.name)))
                    && !exc.iter().any(|p| p.matches_path(&e.name))
            })
            .collect(),
    )
}

/// `a` (`Replace::Always`) and `u` (`Replace::IfNewer`). An existing archive is updated in
/// place; otherwise a new one is created.
pub fn add(a: &Args, replace: Replace) -> Result<i32> {
    let given = a.archive.clone().unwrap();
    if std::fs::metadata(&given).is_ok_and(|m| m.is_file() && m.len() > 0) {
        let (items, warnings) = scan_items(a, &given)?;
        return update_existing(a, &given, replace, items, &warnings);
    }
    let mut archive = given;
    if archive.extension().is_none() {
        let ext = match a.archive_type.as_deref().and_then(find_format) {
            Some(f) if f.name == "gzip" => "gz",
            Some(f) if f.name == "bzip2" => "bz2",
            Some(f) => f.name,
            None => "7z",
        };
        archive.set_extension(ext);
    }
    let kind = write::kind_for(&archive, a.archive_type.as_deref())?;
    let (items, warnings) = scan_items(a, &archive)?;
    let level = a.level.unwrap_or(5);
    if kind != Kind::SevenZ {
        return add_other(a, &archive, kind, &items, level, &warnings);
    }
    let opts = sevenz_options(a, level, given_password(a, true)?)?;
    let total: u64 = items.iter().map(|i| i.size).sum();
    let progress = ui::BarProgress {
        pb: ui::bar(total, !a.no_progress, "Compressing"),
    };
    let t0 = Instant::now();
    let summary = create::create(&archive, &items, &opts, &progress)?;
    let elapsed = t0.elapsed();
    progress.pb.finish_and_clear();
    report_created(&archive, &summary, elapsed);
    Ok(if warnings.is_empty() && summary.skipped == 0 {
        EXIT_OK
    } else {
        EXIT_WARNING
    })
}

/// The items `a` and `u` store for the names and switches on the command line, and the
/// warnings from scanning them.
fn scan_items(a: &Args, archive: &Path) -> Result<(Vec<Item>, Vec<String>)> {
    let names = if a.names.is_empty() {
        vec![".".to_string()]
    } else {
        a.names.clone()
    };
    let exclude: Vec<Pattern> = a.exclude.iter().map(|s| Pattern::new(s)).collect();
    let mut s = scan(&names, a.recurse.unwrap_or(false), &exclude, archive);
    if !a.include.is_empty() {
        let inc: Vec<Pattern> = a.include.iter().map(|p| Pattern::new(p)).collect();
        s.items
            .retain(|it| it.is_dir || inc.iter().any(|p| p.matches_path(&it.name)));
    }
    for w in &s.warnings {
        ui::warn(w);
    }
    if s.items.is_empty() {
        return Err(Error::usage("nothing to add"));
    }
    Ok((s.items, s.warnings))
}

/// `a` or `u` on an archive that exists.
fn update_existing(
    a: &Args,
    archive: &Path,
    replace: Replace,
    items: Vec<Item>,
    warnings: &[String],
) -> Result<i32> {
    let (opened, password) = open(a, true)?;
    let plan = update::plan_add(opened.archive().entries(), items, replace);
    run_update(a, opened, archive, &plan, password, warnings)
}

/// Applies a plan to an opened archive and reports what changed.
fn run_update(
    a: &Args,
    opened: Opened,
    archive: &Path,
    plan: &update::Plan,
    password: Option<String>,
    warnings: &[String],
) -> Result<i32> {
    let format = opened.archive().format().name;
    let level = a.level.unwrap_or(5);
    let total: u64 = plan.add.iter().map(|i| i.size).sum();
    let progress = ui::BarProgress {
        pb: ui::bar(total, !a.no_progress, "Updating"),
    };
    let t0 = Instant::now();
    let outcome = if format == "7z" {
        let opts = sevenz_options(a, level, password)?;
        update::apply(
            opened,
            archive,
            plan,
            update::Settings::SevenZ(&opts),
            &progress,
        )?
    } else {
        let kind = if format == "zip" {
            Kind::Zip
        } else {
            Kind::Tar
        };
        let opts = other_options(a, kind, level, password)?;
        update::apply(
            opened,
            archive,
            plan,
            update::Settings::Other(&opts),
            &progress,
        )?
    };
    let elapsed = t0.elapsed();
    progress.pb.finish_and_clear();
    if outcome.changed {
        report_updated(archive, &outcome, elapsed);
    } else {
        ui::ok(&format!(
            "{} is up to date",
            style(archive.display()).bold()
        ));
    }
    Ok(if warnings.is_empty() && outcome.summary.skipped == 0 {
        EXIT_OK
    } else {
        EXIT_WARNING
    })
}

/// `d`: deletes the entries that the names, `-i` and `-x` select.
pub fn delete(a: &Args) -> Result<i32> {
    if a.names.is_empty() && a.include.is_empty() {
        return Err(Error::usage(
            "nothing to delete: name the entries (wildcards allowed) or give -i",
        ));
    }
    let (opened, password) = open(a, true)?;
    let selection = update::Selection::new(&a.names, &a.include, &a.exclude);
    let plan = update::plan_delete(opened.archive().entries(), &selection);
    if plan.counts.deleted == 0 {
        return Err(Error::Other("no entries match".into()));
    }
    let archive = a.archive.clone().unwrap();
    run_update(a, opened, &archive, &plan, password, &[])
}

/// `rn`: renames entries; the names come in pairs, `old new`.
pub fn rename(a: &Args) -> Result<i32> {
    if a.names.is_empty() || !a.names.len().is_multiple_of(2) {
        return Err(Error::usage(
            "rn takes pairs of names: rn archive old new [old new ...]",
        ));
    }
    let pairs: Vec<(String, String)> = a
        .names
        .chunks(2)
        .map(|c| (c[0].clone(), c[1].clone()))
        .collect();
    let (opened, password) = open(a, false)?;
    let plan = update::plan_rename(opened.archive().entries(), &pairs)?;
    let archive = a.archive.clone().unwrap();
    run_update(a, opened, &archive, &plan, password, &[])
}

/// The 7z settings from the switches, for `a`, `u` and `rn`.
fn sevenz_options(a: &Args, level: u32, password: Option<String>) -> Result<CreateOptions> {
    if let Some(m) = &a.method.other {
        return Err(Error::usage(format!(
            "7z archives use LZMA2, LZMA or Copy (method '{m}' is for zip)"
        )));
    }
    let method = a.method.main.unwrap_or(if level == 0 {
        MainMethod::Copy
    } else {
        MainMethod::Lzma2
    });
    let encrypt_header = a.encrypt_header.unwrap_or(false);
    if encrypt_header && password.is_none() {
        return Err(Error::usage("-mhe=on requires a password (-p)"));
    }
    Ok(CreateOptions {
        level: level.max(1),
        method,
        dict_size: a.method.dict,
        fast_bytes: a.method.fast_bytes,
        block_size: a.method.block,
        threads: threads(a),
        solid_limit: match a.solid {
            Some(None) => None,
            Some(Some(u64::MAX)) | None => Some(default_solid_limit(level)),
            Some(Some(n)) => Some(n),
        },
        filter: a.method.filter.unwrap_or(FilterMode::Auto),
        password,
        encrypt_header,
        compress_header: a.compress_header.unwrap_or(true),
        store_mtime: a.mtime.unwrap_or(true),
        store_ctime: a.ctime.unwrap_or(false),
        store_atime: a.atime.unwrap_or(false),
    })
}

/// The zip, tar and single-stream settings from the switches.
fn other_options(
    a: &Args,
    kind: Kind,
    level: u32,
    password: Option<String>,
) -> Result<WriteOptions> {
    if a.encrypt_header == Some(true) {
        return Err(Error::usage("-mhe applies to 7z archives only"));
    }
    let store = match a.method.other.as_deref() {
        None => a.method.main == Some(MainMethod::Copy) || level == 0,
        Some("copy") | Some("store") => true,
        Some("deflate") | Some("zstd") => false,
        Some(m) => {
            return Err(Error::unsupported(format!(
                "method '{m}' for {kind:?} (r7z writes Deflate, zstd and Store in zip)"
            )))
        }
    };
    if kind != Kind::Zip && (a.method.other.is_some() || a.method.main.is_some()) {
        return Err(Error::usage("-m0 / -mm select zip methods only"));
    }
    if password.is_some() && kind != Kind::Zip {
        return Err(Error::usage("only 7z and zip archives can be encrypted"));
    }
    if a.zip_crypto == Some(false) {
        return Err(Error::unsupported(
            "writing ZipCrypto (weak); r7z encrypts zip with AES-256 (-mem=AES256)",
        ));
    }
    Ok(WriteOptions {
        level,
        threads: threads(a),
        password,
        store,
        zstd: a.method.other.as_deref() == Some("zstd"),
        store_mtime: a.mtime.unwrap_or(true),
        store_ctime: a.ctime.unwrap_or(false),
        store_atime: a.atime.unwrap_or(false),
    })
}

/// `a` for zip, tar and the single-stream compressors.
fn add_other(
    a: &Args,
    archive: &Path,
    kind: Kind,
    items: &[Item],
    level: u32,
    warnings: &[String],
) -> Result<i32> {
    let opts = other_options(a, kind, level, given_password(a, true)?)?;
    let total: u64 = items.iter().map(|i| i.size).sum();
    let progress = ui::BarProgress {
        pb: ui::bar(total, !a.no_progress, "Compressing"),
    };
    let t0 = Instant::now();
    let summary = write::create(archive, kind, items, &opts, &progress)?;
    let elapsed = t0.elapsed();
    progress.pb.finish_and_clear();
    report_created(archive, &summary, elapsed);
    Ok(if warnings.is_empty() && summary.skipped == 0 {
        EXIT_OK
    } else {
        EXIT_WARNING
    })
}

fn report_updated(archive: &Path, o: &update::Outcome, elapsed: std::time::Duration) {
    let c = o.counts;
    let mut parts = vec![format!("{} added", c.added)];
    for (n, label) in [
        (c.replaced, "replaced"),
        (c.deleted, "deleted"),
        (c.renamed, "renamed"),
        (c.unchanged, "unchanged"),
    ] {
        if n > 0 {
            parts.push(format!("{n} {label}"));
        }
    }
    let repacked = if o.repacked > 0 {
        format!(", {} solid blocks re-encoded", o.repacked)
    } else {
        String::new()
    };
    ui::ok(&format!(
        "Updated {}  {}  {}{}  in {}",
        style(archive.display()).bold(),
        parts.join(", "),
        style(human_size(o.summary.archive_bytes)).bold(),
        repacked,
        secs(elapsed),
    ));
    if o.summary.skipped > 0 {
        ui::warn(&format!(
            "{} items could not be read and were skipped",
            o.summary.skipped
        ));
    }
}

fn report_created(
    archive: &Path,
    summary: &r7z::ops::create::Summary,
    elapsed: std::time::Duration,
) {
    let ratio = if summary.input_bytes > 0 {
        format!(
            " ({:.1}%)",
            summary.archive_bytes as f64 * 100.0 / summary.input_bytes as f64
        )
    } else {
        String::new()
    };
    ui::ok(&format!(
        "Created {}  {} files, {} folders  {} → {}{}  in {}  ({}, {} threads)",
        style(archive.display()).bold(),
        grouped(summary.files),
        grouped(summary.dirs),
        human_size(summary.input_bytes),
        style(human_size(summary.archive_bytes)).bold(),
        ratio,
        secs(elapsed),
        rate(summary.input_bytes, elapsed),
        summary.threads_used,
    ));
    if summary.skipped > 0 {
        ui::warn(&format!(
            "{} items could not be read and were skipped",
            summary.skipped
        ));
    }
}

pub fn extract(a: &Args, full_paths: bool, test_only: bool) -> Result<i32> {
    if a.recover {
        return recover(a, full_paths, test_only);
    }
    // Opening counts: for a compressed tar it decompresses the whole stream.
    let t0 = Instant::now();
    let (opened, password) = open(a, true)?;
    let arc = opened.archive();
    let target = if test_only {
        Target::Test
    } else if a.stdout {
        Target::Stdout
    } else {
        let overwrite = if a.yes {
            Overwrite::All
        } else {
            a.overwrite.unwrap_or(Overwrite::Ask)
        };
        Target::Disk {
            dir: a.output_dir.clone().unwrap_or_else(|| PathBuf::from(".")),
            full_paths,
            overwrite,
        }
    };
    let selected = selection(arc, a);
    let total: u64 = arc
        .entries()
        .iter()
        .enumerate()
        .filter(|(i, _)| selected.as_ref().is_none_or(|s| s[*i]))
        .map(|(_, e)| e.size_or_zero())
        .fold(0, u64::saturating_add);
    let verb = if test_only { "Testing" } else { "Extracting" };
    let cb = ui::ExtractUi {
        pb: ui::bar(total, !a.no_progress, verb),
        assume_yes: a.yes,
    };
    let opts = ExtractOptions {
        base: None,
        password,
        threads: threads(a),
        target,
        selected,
    };
    let report = extract::extract(arc, &opts, &cb)?;
    let elapsed = t0.elapsed();
    cb.pb.finish_and_clear();

    if !report.errors.is_empty() {
        if report
            .errors
            .iter()
            .all(|(_, e)| matches!(e, Error::WrongPassword))
        {
            ui::error(&format!(
                "wrong password ({} files could not be decrypted)",
                report.errors.len()
            ));
        } else {
            for (name, e) in report.errors.iter().take(25) {
                ui::error(&format!("{name}: {e}"));
            }
            if report.errors.len() > 25 {
                ui::error(&format!("... and {} more errors", report.errors.len() - 25));
            }
        }
        eprintln!(
            "{} {} errors, {} files OK",
            style("✗").red().bold(),
            report.errors.len(),
            grouped(report.files)
        );
        return Ok(EXIT_FATAL);
    }
    let what = if test_only {
        "Everything is OK"
    } else {
        "Extracted"
    };
    if !a.stdout {
        let dirs = if report.dirs > 0 {
            format!(", {} folders", grouped(report.dirs))
        } else {
            String::new()
        };
        ui::ok(&format!(
            "{what}: {} files{dirs}, {} in {} ({})",
            grouped(report.files),
            human_size(report.bytes),
            secs(elapsed),
            rate(report.bytes, elapsed)
        ));
    }
    if report.skipped > 0 {
        ui::warn(&format!("{} existing files were skipped", report.skipped));
    }
    Ok(EXIT_OK)
}

/// `x -recover`: extracts what is readable from a damaged archive and says what became of
/// the rest.
fn recover(a: &Args, full_paths: bool, test_only: bool) -> Result<i32> {
    use r7z::ops::recover::{self, RecoverOptions};
    if a.stdout {
        return Err(Error::usage(
            "-recover writes files; it cannot be used with -so",
        ));
    }
    let t0 = Instant::now();
    let (opened, password) = open(a, true)?;
    let arc = opened.archive();
    let target = if test_only {
        Target::Test
    } else {
        Target::Disk {
            dir: a.output_dir.clone().unwrap_or_else(|| PathBuf::from(".")),
            full_paths,
            overwrite: if a.yes {
                Overwrite::All
            } else {
                a.overwrite.unwrap_or(Overwrite::Ask)
            },
        }
    };
    let selected = selection(arc, a);
    let total: u64 = arc
        .entries()
        .iter()
        .enumerate()
        .filter(|(i, _)| selected.as_ref().is_none_or(|s| s[*i]))
        .map(|(_, e)| e.size_or_zero())
        .fold(0, u64::saturating_add);
    let cb = ui::ExtractUi {
        pb: ui::bar(total, !a.no_progress, "Recovering"),
        assume_yes: a.yes,
    };
    let opts = ExtractOptions {
        base: None,
        password,
        threads: threads(a),
        target,
        selected,
    };
    let rep = recover::recover(&opened, &opts, RecoverOptions::default(), &cb)?;
    let elapsed = t0.elapsed();
    cb.pb.finish_and_clear();
    for n in &rep.notes {
        ui::warn(n);
    }
    for line in recover::summary_lines(&rep, 40) {
        eprintln!("  {line}");
    }
    let (good, partial, lost) = (rep.recovered(), rep.partial(), rep.lost());
    let verb = if test_only { "Readable" } else { "Recovered" };
    let line = format!(
        "{verb}: {} of {} files, {} in {}{}{}",
        grouped(good as u64),
        grouped(rep.entries.len() as u64),
        human_size(rep.bytes),
        secs(elapsed),
        if partial > 0 {
            format!(", {} partial", grouped(partial as u64))
        } else {
            String::new()
        },
        if lost > 0 {
            format!(", {} lost", grouped(lost as u64))
        } else {
            String::new()
        },
    );
    if rep.skipped > 0 {
        ui::warn(&format!("{} existing files were skipped", rep.skipped));
    }
    if rep.intact() {
        ui::ok(&format!("{line} (no damage found)"));
        Ok(EXIT_OK)
    } else if good == 0 && partial == 0 && !rep.entries.is_empty() {
        eprintln!("{} {line}", style("✗").red().bold());
        Ok(EXIT_FATAL)
    } else {
        ui::warn(&line);
        Ok(EXIT_WARNING)
    }
}

pub fn list(a: &Args) -> Result<i32> {
    let (opened, _) = open(a, false)?;
    let ar = opened.archive();
    let entries = ar.entries();
    let selected = selection(ar, a);
    let path = a.archive.as_ref().unwrap();
    let out = std::io::stdout();
    let mut o = out.lock();
    let tty = std::io::stdout().is_terminal();

    let kv =
        |o: &mut dyn Write, k: &str, v: String| -> std::io::Result<()> { writeln!(o, "{k} = {v}") };
    writeln!(o, "--")?;
    for (n, lvl) in opened.levels.iter().enumerate() {
        if n > 0 {
            writeln!(o, "----")?;
            kv(&mut o, "Path", lvl.name.clone())?;
        } else {
            kv(&mut o, "Path", path.display().to_string())?;
        }
        kv(&mut o, "Type", lvl.archive.format().name.into())?;
        let props = lvl.archive.properties();
        if !props.iter().any(|(k, _)| *k == "Physical Size") {
            if let Some(s) = lvl.physical_size {
                kv(&mut o, "Physical Size", s.to_string())?;
            }
        }
        for (k, v) in props {
            kv(&mut o, k, v)?;
        }
        if let Some(c) = lvl.archive.name_coding() {
            let how = if c.detected { "detected" } else { "-mcp" };
            kv(&mut o, "Code Page", format!("{} ({how})", c.page))?;
        }
    }
    writeln!(o)?;

    let cols = ar.columns();
    let is_sel = |i: usize| selected.as_ref().is_none_or(|s| s[i]);

    if a.technical {
        writeln!(o, "----------")?;
        for (i, e) in entries.iter().enumerate() {
            if !is_sel(i) {
                continue;
            }
            kv(&mut o, "Path", e.name.clone())?;
            kv(
                &mut o,
                "Folder",
                if e.is_dir { "+".into() } else { "-".into() },
            )?;
            kv(
                &mut o,
                "Size",
                e.size.map(|s| s.to_string()).unwrap_or_default(),
            )?;
            kv(
                &mut o,
                "Packed Size",
                e.packed_size.map(|p| p.to_string()).unwrap_or_default(),
            )?;
            kv(
                &mut o,
                "Modified",
                e.mtime.map(format_filetime).unwrap_or_default(),
            )?;
            if let Some(t) = e.ctime {
                kv(&mut o, "Created", format_filetime(t))?;
            }
            if let Some(t) = e.atime {
                kv(&mut o, "Accessed", format_filetime(t))?;
            }
            kv(&mut o, "Attributes", e.attr_string().replace('.', ""))?;
            if cols.crc {
                kv(
                    &mut o,
                    "CRC",
                    e.crc.map(|c| format!("{c:08X}")).unwrap_or_default(),
                )?;
            }
            if cols.encrypted {
                kv(
                    &mut o,
                    "Encrypted",
                    if e.encrypted { "+".into() } else { "-".into() },
                )?;
            }
            if cols.method {
                kv(&mut o, "Method", e.method.clone().unwrap_or_default())?;
            }
            if cols.block {
                kv(
                    &mut o,
                    "Block",
                    e.block.map(|f| f.to_string()).unwrap_or_default(),
                )?;
            }
            match &e.link {
                Some(Link::Symbolic(t)) => kv(&mut o, "Symbolic Link", t.clone())?,
                Some(Link::Hard(t)) => kv(&mut o, "Hard Link", t.clone())?,
                None => {}
            }
            if let Some(c) = &e.comment {
                kv(&mut o, "Comment", c.clone())?;
            }
            writeln!(o)?;
        }
        return Ok(EXIT_OK);
    }

    // A block's packed size is shown on the first listed entry of that block.
    let mut block_packed: HashMap<usize, u64> = HashMap::new();
    for e in entries {
        if let (Some(b), Some(p)) = (e.block, e.packed_size) {
            block_packed.entry(b).or_insert(p);
        }
    }
    let mut block_shown: HashSet<usize> = HashSet::new();
    let rule = "------------------- ----- ------------ ------------  ------------------------";
    writeln!(
        o,
        "   Date      Time    Attr         Size   Compressed  Name"
    )?;
    writeln!(o, "{rule}")?;
    let (mut files, mut dirs, mut size, mut packed_total) = (0u64, 0u64, 0u64, 0u64);
    for (i, e) in entries.iter().enumerate() {
        if !is_sel(i) {
            continue;
        }
        let date = e
            .mtime
            .map(format_filetime)
            .unwrap_or_else(|| " ".repeat(19));
        let packed = match (e.block, e.packed_size) {
            (Some(b), _) if block_shown.insert(b) => block_packed.get(&b).copied(),
            (Some(_), _) => None,
            (None, p) => p,
        };
        let packed = match packed {
            Some(p) => {
                packed_total += p;
                format!("{p:>12}")
            }
            None => " ".repeat(12),
        };
        let name = if e.is_dir && tty {
            style(&e.name).blue().bold().to_string()
        } else {
            e.name.clone()
        };
        let sz = e
            .size
            .map(|s| format!("{s:>12}"))
            .unwrap_or_else(|| " ".repeat(12));
        writeln!(o, "{date} {} {sz} {packed}  {name}", e.attr_string())?;
        if e.is_dir {
            dirs += 1;
        } else {
            files += 1;
            size += e.size_or_zero();
        }
    }
    writeln!(o, "{rule}")?;
    let summary = if dirs > 0 {
        format!("{files} files, {dirs} folders")
    } else {
        format!("{files} files")
    };
    writeln!(
        o,
        "{:19} {:5} {size:>12} {packed_total:>12}  {summary}",
        "", ""
    )?;
    Ok(EXIT_OK)
}

pub fn hash(a: &Args) -> Result<i32> {
    if a.names.is_empty() {
        return Err(Error::usage("no files to hash"));
    }
    let kinds = if a.hashes.is_empty() {
        vec![HashKind::Crc32]
    } else {
        a.hashes.clone()
    };
    let exclude: Vec<Pattern> = a.exclude.iter().map(|s| Pattern::new(s)).collect();
    let s = scan(
        &a.names,
        a.recurse.unwrap_or(false),
        &exclude,
        Path::new(""),
    );
    for w in &s.warnings {
        ui::warn(w);
    }
    let files: Vec<(PathBuf, String)> = s
        .items
        .into_iter()
        .filter(|i| !i.is_dir)
        .map(|i| (i.src, i.name))
        .collect();
    let total: u64 = files
        .iter()
        .filter_map(|(p, _)| std::fs::metadata(p).ok())
        .map(|m| m.len())
        .sum();
    let pb = ui::bar(total, !a.no_progress, "Hashing");
    let t0 = Instant::now();
    let results = hash_files(files, &kinds, threads(a), &|n| pb.inc(n));
    let elapsed = t0.elapsed();
    pb.finish_and_clear();

    let out = std::io::stdout();
    let mut o = out.lock();
    let header: Vec<String> = kinds
        .iter()
        .map(|k| format!("{:<w$}", k.name(), w = k.hex_len()))
        .collect();
    writeln!(o, "{}  {:>12}  Name", header.join("  "), "Size")?;
    let rule: Vec<String> = kinds.iter().map(|k| "-".repeat(k.hex_len())).collect();
    writeln!(
        o,
        "{}  {}  {}",
        rule.join("  "),
        "-".repeat(12),
        "-".repeat(24)
    )?;
    let (mut n, mut bytes, mut errors) = (0u64, 0u64, 0u64);
    for r in &results {
        match &r.digests {
            Ok(d) => {
                writeln!(o, "{}  {:>12}  {}", d.join("  "), r.size, r.display)?;
                n += 1;
                bytes += r.size;
            }
            Err(e) => {
                errors += 1;
                ui::error(&e.to_string());
            }
        }
    }
    writeln!(
        o,
        "{}  {}  {}",
        rule.join("  "),
        "-".repeat(12),
        "-".repeat(24)
    )?;
    drop(o);
    ui::ok(&format!(
        "{} files, {} in {} ({})",
        grouped(n),
        human_size(bytes),
        secs(elapsed),
        rate(bytes, elapsed)
    ));
    Ok(if errors > 0 { EXIT_WARNING } else { EXIT_OK })
}

pub fn bench(a: &Args) -> Result<i32> {
    let level = a.level.unwrap_or(5).max(1);
    let t = threads(a);
    let dict = a.method.dict.unwrap_or_else(|| level_dict_size(level));
    let iterations = a.bench_iterations.unwrap_or(1).max(1);
    println!(
        "{} LZMA2 level {level}, dictionary {}, {} hardware threads",
        style("r7z benchmark:").bold(),
        human_size(dict as u64),
        r7z::util::default_threads()
    );
    let st_size = (dict as usize * 2).clamp(8 << 20, 32 << 20);
    let mt_size = (dict as usize * t).clamp(32 << 20, 512 << 20);
    let data = bench::generate(mt_size.max(st_size), 0x5EED_1234_ABCD_0001);
    println!(
        "{:<8} {:>10} {:>14} {:>14} {:>8}",
        "Threads", "Data", "Compress", "Decompress", "Ratio"
    );
    let mut runs: Vec<(usize, usize)> = vec![(1, st_size)];
    if t > 1 {
        runs.push((t, mt_size));
    }
    for (threads, size) in runs {
        let mut best: Option<bench::BenchResult> = None;
        for _ in 0..iterations {
            let r = bench::run(&data[..size], level, a.method.dict, threads)?;
            best = Some(match best {
                Some(b) if b.compress + b.decompress <= r.compress + r.decompress => b,
                _ => r,
            });
        }
        let r = best.unwrap();
        println!(
            "{:<8} {:>10} {:>9.1} MB/s {:>9.1} MB/s {:>7.1}%",
            r.threads,
            human_size(r.input),
            r.compress_mbps(),
            r.decompress_mbps(),
            r.packed as f64 * 100.0 / r.input as f64
        );
    }
    Ok(EXIT_OK)
}

pub fn info() -> Result<i32> {
    println!(
        "{}",
        style(format!("r7z {}", env!("CARGO_PKG_VERSION"))).bold()
    );
    println!("\nFormats:         read  write  extensions / signature");
    for f in FORMATS {
        let sig = f
            .signatures
            .first()
            .map(|s| {
                let hex: Vec<String> = s.bytes.iter().map(|b| format!("{b:02X}")).collect();
                if s.offset > 0 {
                    format!("offset={} {}", s.offset, hex.join(" "))
                } else {
                    hex.join(" ")
                }
            })
            .unwrap_or_default();
        println!(
            "  {:<14} {:^4}  {:^5}  {}  {}",
            f.name,
            "+",
            if f.write { "+" } else { "-" },
            f.extensions.join(" "),
            sig
        );
    }
    println!("\nCodecs:          decode  encode  id");
    let ids = [
        method::COPY,
        method::LZMA,
        method::LZMA2,
        method::BCJ_X86,
        method::BCJ2,
        method::ARM,
        method::ARMT,
        method::ARM64,
        method::PPC,
        method::SPARC,
        method::IA64,
        method::RISCV,
        method::DELTA,
        method::AES,
        method::PPMD,
        method::BZIP2,
        method::DEFLATE,
    ];
    for id in ids {
        println!(
            "  {:<14} {:^6}  {:^6}  {:X}",
            method_name(id),
            if can_decode(id) { "+" } else { "-" },
            if can_encode(id) { "+" } else { "-" },
            id
        );
    }
    println!("\nHashers (h command):");
    let names: Vec<&str> = HashKind::ALL.iter().map(|k| k.name()).collect();
    println!("  {}", names.join(" "));
    Ok(EXIT_OK)
}

pub fn help() {
    let b = |s: &str| style(s.to_string()).bold();
    println!(
        "{} {}, an archiver that reads and writes 7-Zip formats\n",
        b("r7z"),
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "{} r7z <command> [switches...] <archive> [files...]\n",
        b("Usage:")
    );
    println!("{}", b("Commands:"));
    for (c, d) in [
        ("a", "Add files, replacing same-named entries"),
        ("u", "Update: add files, replacing only older entries"),
        ("d", "Delete entries (wildcards allowed)"),
        ("rn", "Rename entries: old new [old new ...]"),
        ("x", "Extract with full paths"),
        ("e", "Extract without directory names"),
        ("l", "List contents (-slt for technical detail)"),
        ("t", "Test integrity"),
        (
            "h",
            "Hash files (-scrc{CRC32|CRC64|XXH64|MD5|SHA1|SHA256|SHA384|SHA512|SHA3-256|*})",
        ),
        ("b", "Benchmark LZMA2 [iterations]"),
        ("i", "Show supported codecs"),
    ] {
        println!("  {:<4}{d}", style(c).cyan().bold());
    }
    println!("\n{}", b("Switches:"));
    for (s, d) in [
        ("-o{dir}", "Output directory"),
        ("-p{password}", "Password (bare -p prompts)"),
        ("-mx{0-9}", "Compression level (default 5)"),
        ("-mmt{N|on|off}", "Threads (default: all cores)"),
        (
            "-m0={LZMA2|LZMA|Copy}[:d=..][:c=..]",
            "Method, dictionary, LZMA2 block size",
        ),
        ("-md={N|size}", "Dictionary (2^N or 64m)"),
        (
            "-mf={on|off|BCJ|BCJ2|ARM|ARMT|ARM64|PPC|SPARC|IA64|RISCV|Delta:N}",
            "Filter (default: BCJ for executables)",
        ),
        ("-ms={on|off|size}", "Solid mode / solid block size"),
        ("-mhe=on", "Encrypt file names (needs -p)"),
        ("-mhc=off", "Do not compress the header"),
        ("-mtc=on -mta=on", "Store creation / access times"),
        (
            "-x!{wildcard}  -i!{wildcard}",
            "Exclude / include names (also @listfile)",
        ),
        ("-r", "Recurse into subdirectories for wildcards"),
        (
            "-ao{a|s|u|t}",
            "Overwrite: all, skip, rename new, rename existing",
        ),
        ("-y", "Assume yes (overwrite)"),
        ("-so", "Extract to stdout"),
        (
            "-recover",
            "x/e/t: salvage what is readable from a damaged archive",
        ),
        (
            "-mcp={932|936|949|950|1251|...}",
            "Code page of non-Unicode names (default: detected)",
        ),
        ("-slt", "Technical listing"),
        ("-bd", "No progress bar"),
    ] {
        println!("  {:<38}{d}", style(s).green());
    }
    println!("\n{}", b("Examples:"));
    println!("  r7z a backup.7z Documents -mx7");
    println!("  r7z a secret.7z notes -p -mhe=on");
    println!("  r7z a backup.7z newfiles        (adds to an existing backup.7z)");
    println!("  r7z u backup.7z Documents -mx7  (replaces only the files that changed)");
    println!("  r7z d backup.7z \"*.tmp\"");
    println!("  r7z rn backup.7z Documents Docs");
    println!("  r7z x backup.7z -oRestore");
    println!("  r7z x damaged.zip -recover -oRescued");
    println!("  r7z l backup.7z \"*.pdf\"");
}
