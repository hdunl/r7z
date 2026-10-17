//! Library-level round trips through the public create/extract workflow. These need no
//! external tools; 7-Zip interoperability is covered by scripts/interop.sh.

use std::fs;
use std::path::{Path, PathBuf};

use r7z::format::sevenz::SevenZ;
use r7z::ops::bench::generate;
use r7z::ops::create::{create, CreateOptions, FilterMode, Item, MainMethod, NoProgress};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};
use r7z::sevenz::read::ArchiveFile;
use r7z::Error;

struct Quiet;
impl Callbacks for Quiet {}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-test-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Writes a small tree and returns its items as the CLI scanner would produce them.
fn corpus(root: &Path) -> Vec<Item> {
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("a/text.txt", b"hello world\n".repeat(5000)),
        ("a/b/gen.bin", generate(3 << 20, 7)),
        ("a/b/small", b"x".to_vec()),
        ("a/empty.txt", Vec::new()),
        ("tool.dll", generate(600_000, 11)),
        ("ünï/名前.txt", "héllo".as_bytes().to_vec()),
    ];
    let mut items = Vec::new();
    for d in ["a", "a/b", "a/emptydir", "ünï"] {
        fs::create_dir_all(root.join(d)).unwrap();
        items.push(Item {
            src: root.join(d),
            name: d.to_string(),
            is_dir: true,
            size: 0,
            mtime: Some(133_000_000_000_000_000),
            ctime: None,
            atime: None,
            attrib: Some(0x10),
        });
    }
    for (name, data) in files {
        fs::write(root.join(name), &data).unwrap();
        items.push(Item {
            src: root.join(name),
            name: name.to_string(),
            is_dir: false,
            size: data.len() as u64,
            mtime: Some(133_000_000_000_000_000),
            ctime: None,
            atime: None,
            attrib: Some(0x20),
        });
    }
    items
}

fn roundtrip(label: &str, opts: CreateOptions, password: Option<&str>) {
    let dir = tmp(label);
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join("t.7z");
    let summary = create(&arc, &items, &opts, &NoProgress).unwrap();
    assert_eq!(summary.files, 6, "{label}");
    assert_eq!(summary.dirs, 4, "{label}");

    let af = ArchiveFile::open(&arc, password).unwrap();
    assert_eq!(af.archive.entries.len(), 10, "{label}");
    let out = dir.join("out");
    let eo = ExtractOptions {
        base: None,
        password: password.map(str::to_string),
        threads: 4,
        target: Target::Disk {
            dir: out.clone(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    let rep = extract(&SevenZ::new(af), &eo, &Quiet).unwrap();
    assert!(rep.errors.is_empty(), "{label}: {:?}", rep.errors);
    for it in items.iter().filter(|i| !i.is_dir) {
        let a = fs::read(&it.src).unwrap();
        let b = fs::read(out.join(&it.name)).unwrap();
        assert!(a == b, "{label}: {} differs", it.name);
    }
    assert!(out.join("a/emptydir").is_dir(), "{label}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn default_solid_multithreaded() {
    roundtrip(
        "default",
        CreateOptions {
            threads: 4,
            ..Default::default()
        },
        None,
    );
}

#[test]
fn every_level_single_and_multi_thread() {
    for level in [1, 3, 5, 7, 9] {
        for threads in [1, 4] {
            // Small blocks force several groups and primed sub-blocks.
            let opts = CreateOptions {
                level,
                threads,
                block_size: Some(1 << 20),
                ..Default::default()
            };
            roundtrip(&format!("l{level}t{threads}"), opts, None);
        }
    }
}

#[test]
fn non_solid() {
    roundtrip(
        "nonsolid",
        CreateOptions {
            solid_limit: None,
            threads: 4,
            ..Default::default()
        },
        None,
    );
}

#[test]
fn methods_and_filters() {
    roundtrip(
        "copy",
        CreateOptions {
            method: MainMethod::Copy,
            ..Default::default()
        },
        None,
    );
    roundtrip(
        "lzma",
        CreateOptions {
            method: MainMethod::Lzma,
            ..Default::default()
        },
        None,
    );
    roundtrip(
        "delta",
        CreateOptions {
            filter: FilterMode::Delta(4),
            ..Default::default()
        },
        None,
    );
    roundtrip(
        "bcj",
        CreateOptions {
            filter: FilterMode::Bcj,
            ..Default::default()
        },
        None,
    );
    roundtrip(
        "rawheader",
        CreateOptions {
            compress_header: false,
            ..Default::default()
        },
        None,
    );
}

#[test]
fn encryption() {
    let pw = Some("pässwörd");
    roundtrip(
        "aes",
        CreateOptions {
            password: pw.map(str::to_string),
            ..Default::default()
        },
        pw,
    );
    roundtrip(
        "aes-he",
        CreateOptions {
            password: pw.map(str::to_string),
            encrypt_header: true,
            ..Default::default()
        },
        pw,
    );
}

#[test]
fn encrypted_header_requires_and_checks_password() {
    let dir = tmp("pw");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join("t.7z");
    let opts = CreateOptions {
        password: Some("right".into()),
        encrypt_header: true,
        ..Default::default()
    };
    create(&arc, &items, &opts, &NoProgress).unwrap();
    assert!(matches!(
        ArchiveFile::open(&arc, None),
        Err(Error::PasswordRequired)
    ));
    assert!(matches!(
        ArchiveFile::open(&arc, Some("wrong")),
        Err(Error::WrongPassword)
    ));
    assert!(ArchiveFile::open(&arc, Some("right")).is_ok());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn corruption_is_detected() {
    let dir = tmp("corrupt");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join("t.7z");
    create(
        &arc,
        &items,
        &CreateOptions {
            compress_header: false,
            ..Default::default()
        },
        &NoProgress,
    )
    .unwrap();
    let mut bytes = fs::read(&arc).unwrap();
    bytes[4000] ^= 0x55;
    fs::write(&arc, &bytes).unwrap();
    let af = ArchiveFile::open(&arc, None).unwrap();
    let eo = ExtractOptions {
        base: None,
        password: None,
        threads: 2,
        target: Target::Test,
        selected: None,
    };
    let rep = extract(&SevenZ::new(af), &eo, &Quiet).unwrap();
    assert!(!rep.errors.is_empty());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn rejects_non_archives_and_truncation() {
    let dir = tmp("bad");
    let p = dir.join("x.7z");
    fs::write(&p, b"definitely not an archive, just text").unwrap();
    assert!(matches!(
        ArchiveFile::open(&p, None),
        Err(Error::NotArchive)
    ));
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    create(&p, &items, &CreateOptions::default(), &NoProgress).unwrap();
    let bytes = fs::read(&p).unwrap();
    fs::write(&p, &bytes[..bytes.len() - 10]).unwrap();
    assert!(ArchiveFile::open(&p, None).is_err());
    let _ = fs::remove_dir_all(&dir);
}
