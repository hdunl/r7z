//! Round trips through the writers for zstd, lz4 and Unix compress (`.Z`), and zstd inside
//! zip. Each archive is read back through the public open and extract path.

use std::fs;
use std::path::{Path, PathBuf};

use r7z::format::write::{create, kind_for, WriteOptions};
use r7z::format::{open, Archive, OpenRequest};
use r7z::ops::create::{Item, NoProgress};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};

struct Quiet;
impl Callbacks for Quiet {}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-writers-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// A few files of different kinds, with one directory, as items for `create`.
fn corpus(root: &Path) -> Vec<Item> {
    let mut x = 9u32;
    let noisy: Vec<u8> = (0..300_000)
        .map(|i| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            if i % 3 == 0 {
                (x >> 24) as u8
            } else {
                b"the quick brown fox "[i % 19]
            }
        })
        .collect();
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("d/text.txt", b"hello world\n".repeat(20_000)),
        ("d/noisy.bin", noisy),
        ("d/empty.txt", Vec::new()),
        ("zeros.bin", vec![0u8; 200_000]),
    ];
    let mut items = vec![Item {
        src: root.join("d"),
        name: "d".into(),
        is_dir: true,
        size: 0,
        mtime: None,
        ctime: None,
        atime: None,
        attrib: Some(0x10),
    }];
    fs::create_dir_all(root.join("d")).unwrap();
    for (name, data) in files {
        fs::write(root.join(name), &data).unwrap();
        items.push(Item {
            src: root.join(name),
            name: name.to_string(),
            is_dir: false,
            size: data.len() as u64,
            mtime: None,
            ctime: None,
            atime: None,
            attrib: Some(0x20),
        });
    }
    items
}

fn options(level: u32) -> WriteOptions {
    WriteOptions {
        level,
        threads: 2,
        password: None,
        store: level == 0,
        zstd: false,
        store_mtime: true,
        store_ctime: false,
        store_atime: false,
    }
}

/// Writes `file` (chosen by its name) from the corpus, reads it back and compares.
fn round_trip(file: &str, opts: &WriteOptions) -> String {
    let dir = tmp(&file.replace('.', "_"));
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join(file);
    let kind = kind_for(&arc, None).unwrap();
    // Single-file formats take the one file, tar-based ones the whole corpus.
    let items: Vec<Item> = if matches!(kind, r7z::format::write::Kind::Single(_)) {
        items
            .into_iter()
            .filter(|i| i.name == "d/noisy.bin")
            .collect()
    } else {
        items
    };
    create(&arc, kind, &items, opts, &NoProgress).unwrap();
    let opened = open(&arc, &OpenRequest::default()).unwrap();
    let a: &dyn Archive = opened.archive();
    let out = dir.join("out");
    let eo = ExtractOptions {
        base: None,
        password: None,
        threads: 2,
        target: Target::Disk {
            dir: out.clone(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    let rep = extract(a, &eo, &Quiet).unwrap();
    assert!(rep.errors.is_empty(), "{file}: {:?}", rep.errors);
    for it in items.iter().filter(|i| !i.is_dir) {
        let want = fs::read(&it.src).unwrap();
        let got_path = if matches!(kind, r7z::format::write::Kind::Single(_)) {
            // A single compressed file takes the name of the archive minus its extension.
            fs::read_dir(&out).unwrap().next().unwrap().unwrap().path()
        } else {
            out.join(&it.name)
        };
        assert!(
            fs::read(got_path).unwrap() == want,
            "{file}: {} differs",
            it.name
        );
    }
    let _ = fs::remove_dir_all(&dir);
    a.format().name.to_string()
}

#[test]
fn zstd_streams_and_tars_round_trip_at_every_level() {
    for mx in [0u32, 1, 3, 5, 9] {
        assert_eq!(round_trip("one.zst", &options(mx)), "zstd");
        assert_eq!(round_trip("all.tar.zst", &options(mx)), "tar");
        assert_eq!(round_trip("all.tzst", &options(mx)), "tar");
    }
}

#[test]
fn lz4_streams_and_tars_round_trip() {
    assert_eq!(round_trip("one.lz4", &options(5)), "lz4");
    assert_eq!(round_trip("all.tar.lz4", &options(5)), "tar");
}

#[test]
fn compress_z_streams_and_tars_round_trip() {
    assert_eq!(round_trip("one.Z", &options(5)), "Z");
    assert_eq!(round_trip("all.tar.Z", &options(5)), "tar");
    assert_eq!(round_trip("all.taz", &options(5)), "tar");
}

#[test]
fn zip_members_can_be_zstd() {
    let dir = tmp("zip-zstd");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join("zstd.zip");
    let mut opts = options(5);
    opts.zstd = true;
    create(
        &arc,
        kind_for(&arc, None).unwrap(),
        &items,
        &opts,
        &NoProgress,
    )
    .unwrap();
    let opened = open(&arc, &OpenRequest::default()).unwrap();
    let a = opened.archive();
    let zstd_members = a
        .entries()
        .iter()
        .filter(|e| {
            e.method
                .as_deref()
                .is_some_and(|m| m.to_ascii_lowercase().contains("zstd"))
        })
        .count();
    assert!(zstd_members >= 2, "{zstd_members} zstd members");
    let rep = extract(
        a,
        &ExtractOptions {
            base: None,
            password: None,
            threads: 2,
            target: Target::Test,
            selected: None,
        },
        &Quiet,
    )
    .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    let _ = fs::remove_dir_all(&dir);
}
