//! Symbolic links in tar archives: a link is made only where it stays inside the
//! extraction, and everywhere else the file holding the target text is written.

use std::fs;
use std::path::{Path, PathBuf};

use r7z::format::{open_bytes, OpenRequest};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};

struct Quiet;
impl Callbacks for Quiet {}

/// One ustar header block.
fn header(name: &str, typeflag: u8, size: usize, linkname: &str) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"00000000000\0");
    h[148..156].copy_from_slice(b"        ");
    h[156] = typeflag;
    h[157..157 + linkname.len()].copy_from_slice(linkname.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn tar(entries: &[(&str, u8, &[u8], &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, kind, data, link) in entries {
        out.extend(header(name, *kind, data.len(), link));
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend([0u8; 1024]);
    out
}

fn extract_to(dir: &Path, data: Vec<u8>) {
    let opened = open_bytes(data, "links.tar", &OpenRequest::default()).unwrap();
    let eo = ExtractOptions {
        base: None,
        password: None,
        threads: 2,
        target: Target::Disk {
            dir: dir.to_path_buf(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    let rep = extract(opened.archive(), &eo, &Quiet).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

fn is_link(p: &PathBuf) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}

#[test]
fn links_stay_links_only_inside_the_extraction() {
    let dir = std::env::temp_dir().join(format!("r7z-links-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let data = tar(&[
        ("d/", b'5', b"", ""),
        ("d/target.txt", b'0', b"hello", ""),
        ("d/link.txt", b'2', b"", "target.txt"),
        ("d/up.txt", b'2', b"", "../../escape.txt"),
        ("d/sibling.txt", b'2', b"", "../d/target.txt"),
        ("abs.txt", b'2', b"", "/etc/passwd"),
        ("d/deep/x.txt", b'2', b"", "../../d/target.txt"),
    ]);
    extract_to(&dir, data);
    assert_eq!(
        fs::read_to_string(dir.join("d/target.txt")).unwrap(),
        "hello"
    );

    // A link that stays inside must read the target when links are possible; without
    // them it is the file holding the target text. Either way it is never a copy of the
    // target's data written under the link's name.
    let link = dir.join("d/link.txt");
    if is_link(&link) {
        assert_eq!(fs::read_link(&link).unwrap(), PathBuf::from("target.txt"));
        assert_eq!(fs::read_to_string(&link).unwrap(), "hello");
    } else {
        assert_eq!(fs::read_to_string(&link).unwrap(), "target.txt");
    }

    // Targets that leave the extraction (or are absolute) stay files with the target text.
    for escaping in ["d/up.txt", "abs.txt"] {
        let p = dir.join(escaping);
        assert!(!is_link(&p), "{escaping} must not be a link");
    }
    assert_eq!(
        fs::read_to_string(dir.join("d/up.txt")).unwrap(),
        "../../escape.txt"
    );
    assert_eq!(
        fs::read_to_string(dir.join("abs.txt")).unwrap(),
        "/etc/passwd"
    );
    assert!(!dir.parent().unwrap().join("escape.txt").exists());
    assert!(!dir.parent().unwrap().join("escape.txt").exists());
    let _ = fs::remove_dir_all(&dir);
}

fn extract_with(dir: &Path, data: Vec<u8>, base: Option<&str>, full_paths: bool) {
    let opened = open_bytes(data, "links.tar", &OpenRequest::default()).unwrap();
    let eo = ExtractOptions {
        base: base.map(str::to_string),
        password: None,
        threads: 2,
        target: Target::Disk {
            dir: dir.to_path_buf(),
            full_paths,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    extract(opened.archive(), &eo, &Quiet).unwrap();
}

/// Whether the link at `p`, if it is one, resolves outside `root`.
fn escapes(root: &Path, p: &Path) -> bool {
    if !is_link(&p.to_path_buf()) {
        return false;
    }
    let target = fs::read_link(p).unwrap();
    let mut at: Vec<_> = p
        .parent()
        .unwrap()
        .strip_prefix(root)
        .unwrap()
        .components()
        .collect();
    for c in target.components() {
        match c {
            std::path::Component::ParentDir => {
                if at.pop().is_none() {
                    return true;
                }
            }
            std::path::Component::Normal(_) => at.push(c),
            std::path::Component::CurDir => {}
            _ => return true,
        }
    }
    false
}

/// The extraction's own path for an entry can be shallower than its archive name: `..`
/// parts are dropped, flat extraction keeps only the file name, and a base folder is
/// stripped. A link's target is judged from where the link really lands.
#[test]
fn links_are_judged_where_they_land() {
    let root = std::env::temp_dir().join(format!("r7z-links-land-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);

    // `..` parts in the name are dropped, so `a/../up.txt` lands at `a/up.txt`.
    let dir = root.join("dotdot");
    fs::create_dir_all(&dir).unwrap();
    extract_with(
        &dir,
        tar(&[("a/../up.txt", b'2', b"", "../../escape.txt")]),
        None,
        true,
    );
    let p = dir.join("a/up.txt");
    assert!(p.symlink_metadata().is_ok());
    assert!(!escapes(&dir, &p), "a/up.txt must not leave the extraction");

    // Flat extraction puts every file at the top.
    let dir = root.join("flat");
    fs::create_dir_all(&dir).unwrap();
    extract_with(
        &dir,
        tar(&[("d/e/flat.txt", b'2', b"", "../../escape.txt")]),
        None,
        false,
    );
    let p = dir.join("flat.txt");
    assert!(p.symlink_metadata().is_ok());
    assert!(!escapes(&dir, &p), "flat.txt must not leave the extraction");

    // A base folder is stripped from the names.
    let dir = root.join("base");
    fs::create_dir_all(&dir).unwrap();
    extract_with(
        &dir,
        tar(&[("d/based.txt", b'2', b"", "../escape.txt")]),
        Some("d"),
        true,
    );
    let p = dir.join("based.txt");
    assert!(p.symlink_metadata().is_ok());
    assert!(
        !escapes(&dir, &p),
        "based.txt must not leave the extraction"
    );

    // Off Windows a backslash is part of a name, not a separator.
    #[cfg(unix)]
    {
        let dir = root.join("backslash");
        fs::create_dir_all(&dir).unwrap();
        extract_with(
            &dir,
            tar(&[
                ("a\\b/name.txt", b'2', b"", "../../escape.txt"),
                ("x/target.txt", b'2', b"", "a\\b/../../../escape.txt"),
            ]),
            None,
            true,
        );
        for p in [dir.join("a\\b/name.txt"), dir.join("x/target.txt")] {
            assert!(p.symlink_metadata().is_ok());
            assert!(
                !escapes(&dir, &p),
                "{} must not leave the extraction",
                p.display()
            );
        }
    }
    let _ = fs::remove_dir_all(&root);
}
