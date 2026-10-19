//! Pre-extraction checks: things in an archive a careful person would want to know about
//! before unpacking it.

use std::collections::HashMap;

use crate::format::{Entry, Link};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Note,
    Caution,
    Danger,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub level: Level,
    pub title: String,
    pub detail: String,
    /// Entries involved (indices into the entry list), at most a few dozen.
    pub entries: Vec<usize>,
}

const PROGRAM_EXTS: &[&str] = &[
    "exe",
    "dll",
    "scr",
    "com",
    "pif",
    "msi",
    "msp",
    "bat",
    "cmd",
    "ps1",
    "psm1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "cpl",
    "lnk",
    "jar",
    "reg",
    "sys",
    "appx",
    "msix",
    "application",
    "gadget",
    "inf",
];

const DOCUMENT_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg", "png", "gif",
    "bmp", "mp3", "mp4", "mov", "avi", "csv", "odt", "zip", "rar", "7z", "html", "htm",
];

fn ext_of(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    base.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase())
}

fn second_ext(name: &str) -> Option<String> {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let (stem, _) = base.rsplit_once('.')?;
    stem.rsplit_once('.')
        .map(|(_, e)| e.trim().to_ascii_lowercase())
}

fn escapes_root(path: &str) -> bool {
    let p = path.replace('\\', "/");
    if p.starts_with('/') || p.as_bytes().get(1) == Some(&b':') {
        return true;
    }
    let mut depth: i32 = 0;
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            _ => depth += 1,
        }
    }
    false
}

fn plural(n: usize, one: &str, many: &str, rest: &str) -> String {
    let noun = if n == 1 { one } else { many };
    format!("{n} {noun} {rest}").trim_end().to_string()
}

fn human(n: u64) -> String {
    crate::util::fmt::human_size(n)
}

fn finding(level: Level, title: String, detail: String, entries: Vec<usize>) -> Finding {
    Finding {
        level,
        title,
        detail,
        entries: entries.into_iter().take(40).collect(),
    }
}

pub fn inspect(entries: &[Entry], packed_total: Option<u64>) -> Vec<Finding> {
    let mut out = Vec::new();
    let files: Vec<(usize, &Entry)> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.is_dir && !e.is_anti)
        .collect();

    let outside: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| escapes_root(&e.name))
        .map(|(i, _)| i)
        .collect();
    if !outside.is_empty() {
        out.push(finding(
            Level::Danger,
            plural(outside.len(), "path points", "paths point", "outside the destination"),
            "These names use absolute paths or \"..\" to climb out of the folder you extract to. r7z keeps them inside the destination, but the archive was likely built to overwrite files elsewhere.".into(),
            outside,
        ));
    }

    let rtlo: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.name.contains('\u{202E}'))
        .map(|(i, _)| i)
        .collect();
    if !rtlo.is_empty() {
        out.push(finding(
            Level::Danger,
            "File names hide their real extension".into(),
            "Some names contain a right-to-left override character, a trick that makes \"photo_gnp.exe\" display as \"photo_exe.png\".".into(),
            rtlo,
        ));
    }

    let disguised: Vec<usize> = files
        .iter()
        .filter(|(_, e)| {
            let outer = ext_of(&e.name).unwrap_or_default();
            PROGRAM_EXTS.contains(&outer.as_str())
                && second_ext(&e.name).is_some_and(|inner| DOCUMENT_EXTS.contains(&inner.as_str()))
        })
        .map(|(i, _)| *i)
        .collect();
    if !disguised.is_empty() {
        out.push(finding(
            Level::Danger,
            plural(disguised.len(), "program is", "programs are", "named like a document"),
            "Names such as \"invoice.pdf.exe\" are a common way to get a program opened by mistake.".into(),
            disguised,
        ));
    }

    let links: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(&e.link, Some(Link::Symbolic(t)) if escapes_root(&format!("{}/../{}", e.name, t)) || t.starts_with('/')))
        .map(|(i, _)| i)
        .collect();
    if !links.is_empty() {
        out.push(finding(
            Level::Caution,
            plural(links.len(), "link points", "links point", "outside the archive"),
            "Symbolic links whose targets leave the extracted folder can expose or overwrite other files.".into(),
            links,
        ));
    }

    let total = crate::util::saturating_sum(files.iter().map(|(_, e)| e.size_or_zero()));
    if let Some(packed) = packed_total.filter(|&p| p > 0) {
        let ratio = total as f64 / packed as f64;
        if total > (1 << 30) && ratio > 200.0 {
            out.push(finding(
                Level::Danger,
                format!("Expands {:.0} times, to {}", ratio, human(total)),
                "Ratios this extreme are typical of decompression bombs built to fill a disk."
                    .into(),
                Vec::new(),
            ));
        } else if total > (20u64 << 30) {
            out.push(finding(
                Level::Caution,
                format!("Unpacks to {}", human(total)),
                "Make sure the destination drive has room.".into(),
                Vec::new(),
            ));
        }
    }

    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut clashes = Vec::new();
    for (i, e) in &files {
        let key = e
            .name
            .replace('\\', "/")
            .trim_start_matches("./")
            .to_lowercase();
        if let Some(&first) = seen.get(&key) {
            clashes.push(first);
            clashes.push(*i);
        } else {
            seen.insert(key, *i);
        }
    }
    if !clashes.is_empty() {
        clashes.dedup();
        out.push(finding(
            Level::Caution,
            "Some names differ only in letter case".into(),
            "Windows treats these as the same file, so one would replace the other.".into(),
            clashes,
        ));
    }

    let programs: Vec<usize> = files
        .iter()
        .filter(|(_, e)| ext_of(&e.name).is_some_and(|x| PROGRAM_EXTS.contains(&x.as_str())))
        .map(|(i, _)| *i)
        .collect();
    if !programs.is_empty() {
        out.push(finding(
            Level::Note,
            format!(
                "Contains {}",
                plural(
                    programs.len(),
                    "program or script",
                    "programs or scripts",
                    ""
                )
                .trim_end()
            ),
            "Only run them if you trust where the archive came from.".into(),
            programs,
        ));
    }

    let long: Vec<usize> = files
        .iter()
        .filter(|(_, e)| e.name.chars().count() > 240)
        .map(|(i, _)| *i)
        .collect();
    if !long.is_empty() {
        out.push(finding(
            Level::Note,
            plural(long.len(), "very long path", "very long paths", ""),
            "Some older programs cannot open files with paths this long.".into(),
            long,
        ));
    }

    out.sort_by_key(|f| std::cmp::Reverse(f.level));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(name: &str, size: u64) -> Entry {
        Entry {
            name: name.into(),
            size: Some(size),
            ..Default::default()
        }
    }

    #[test]
    fn flags_the_classics() {
        let entries = vec![
            e("../../evil.dll", 10),
            e("docs/invoice.pdf.exe", 10),
            e("photo\u{202E}gnp.exe", 10),
            e("README.md", 10),
            e("readme.MD", 10),
        ];
        let f = inspect(&entries, Some(50));
        let titles: Vec<&str> = f.iter().map(|x| x.title.as_str()).collect();
        assert!(titles.iter().any(|t| t.contains("outside the destination")));
        assert!(titles.iter().any(|t| t.contains("named like a document")));
        assert!(titles
            .iter()
            .any(|t| t.contains("hide their real extension")));
        assert!(titles.iter().any(|t| t.contains("letter case")));
        assert_eq!(f[0].level, Level::Danger);
    }

    #[test]
    fn quiet_on_ordinary_archives() {
        let entries = vec![e("src/main.rs", 100), e("Cargo.toml", 50)];
        assert!(inspect(&entries, Some(80)).is_empty());
        assert!(!escapes_root("a/../b"));
        assert!(escapes_root("a/../../b"));
    }

    #[test]
    fn detects_bombs() {
        let entries = vec![e("zeros.bin", 10 << 30)];
        let f = inspect(&entries, Some(10 << 20));
        assert!(f
            .iter()
            .any(|x| x.level == Level::Danger && x.title.starts_with("Expands")));
    }
}
