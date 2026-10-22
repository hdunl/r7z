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
