//! Split zips: `x.z01`, `x.z02`, … with `x.zip` as the last part. The parts joined in order
//! are one archive, and any of them can be the name it is opened by.

use std::fs;
use std::path::{Path, PathBuf};

use r7z::format::write::{create, kind_for, WriteOptions};
use r7z::format::{open, OpenRequest};
use r7z::ops::create::{Item, NoProgress};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};

struct Quiet;
impl Callbacks for Quiet {}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-split-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn noise(seed: u32, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_add(1).wrapping_mul(2_654_435_761);
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 8) as u8
        })
        .collect()
}

/// A stored zip of six files of 150 KB each, with its contents.
fn zip_bytes(dir: &Path) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let src = dir.join("src");
    fs::create_dir_all(src.join("d")).unwrap();
    let mut files = Vec::new();
    let mut items = Vec::new();
    for i in 0..6 {
        let name = format!("d/f{i}.bin");
        let data = noise(i, 150_000);
        fs::write(src.join(&name), &data).unwrap();
        items.push(Item {
            src: src.join(&name),
            name: name.clone(),
            is_dir: false,
            size: data.len() as u64,
            mtime: None,
            ctime: None,
            atime: None,
            attrib: Some(0x20),
        });
        files.push((name, data));
    }
    let arc = dir.join("whole.zip");
    let opts = WriteOptions {
        level: 0,
        threads: 2,
        password: None,
        store: true,
        zstd: false,
        store_mtime: true,
        store_ctime: false,
        store_atime: false,
    };
    create(
        &arc,
        kind_for(&arc, None).unwrap(),
        &items,
        &opts,
        &NoProgress,
    )
    .unwrap();
    (fs::read(&arc).unwrap(), files)
}

/// Writes `set.z01`, `set.z02`, … and `set.zip` from `zip`, cut at `cuts`. The last part's
/// end-of-central-directory record names it as the last disk, as split zips do.
fn split(dir: &Path, zip: &[u8], cuts: &[usize]) -> PathBuf {
    let mut bounds = vec![0];
    bounds.extend_from_slice(cuts);
    bounds.push(zip.len());
    let last_index = bounds.len() - 2;
    for k in 0..=last_index {
        let mut part = zip[bounds[k]..bounds[k + 1]].to_vec();
        if k == last_index {
            let eocd = part
                .windows(4)
                .rposition(|w| w == b"PK\x05\x06")
                .expect("end of central directory");
            part[eocd + 4..eocd + 6].copy_from_slice(&(last_index as u16).to_le_bytes());
            part[eocd + 6..eocd + 8].copy_from_slice(&(last_index as u16).to_le_bytes());
            fs::write(dir.join("set.zip"), &part).unwrap();
        } else {
            fs::write(dir.join(format!("set.z{:02}", k + 1)), &part).unwrap();
        }
    }
    dir.join("set.zip")
}

fn read_back(path: &Path) -> Vec<(String, Vec<u8>)> {
    let opened = open(path, &OpenRequest::default()).unwrap();
    let a = opened.archive();
    let out = path.with_extension("out");
    let rep = extract(
        a,
        &ExtractOptions {
            base: None,
            password: None,
            threads: 2,
            target: Target::Disk {
                dir: out.clone(),
                full_paths: true,
                overwrite: Overwrite::All,
            },
            selected: None,
        },
        &Quiet,
    )
    .unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    let mut got: Vec<(String, Vec<u8>)> = a
        .entries()
        .iter()
        .filter(|e| !e.is_dir)
        .map(|e| (e.name.clone(), fs::read(out.join(&e.name)).unwrap()))
        .collect();
    got.sort();
    let _ = fs::remove_dir_all(&out);
    got
}

#[test]
fn split_zip_opens_by_its_last_part_and_by_its_first() {
    let dir = tmp("parts");
    let (zip, mut files) = zip_bytes(&dir);
    files.sort();
    let last = split(&dir, &zip, &[100_000, 400_000, 650_000]);
    assert_eq!(read_back(&last), files);
    assert_eq!(read_back(&dir.join("set.z01")), files);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_zip_with_no_split_parts_is_not_joined() {
    let dir = tmp("whole");
    let (zip, mut files) = zip_bytes(&dir);
    files.sort();
    fs::write(dir.join("whole.z09"), b"not a part").unwrap();
    assert_eq!(read_back(&dir.join("whole.zip")), files);
    let _ = fs::remove_dir_all(&dir);
    let _ = zip;
}
