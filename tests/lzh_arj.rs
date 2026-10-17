//! LZH and ARJ reading: checked-in fixtures (Bandizip `-lh7-` and archives from the test
//! encoders in `support/`, all cross-checked with 7-Zip 25.01 where it supports them),
//! in-memory round trips for every method and header level, and damaged-input handling.
//!
//! `cargo test --test lzh_arj -- --ignored gen_fixtures` rewrites the encoder fixtures and
//! the Bandizip input corpus under `target/lzh-arj-corpus`.

mod support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use r7z::format::{open_bytes, Archive, OpenRequest};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};
use support::{write_arj, write_lzh, Member};

struct Quiet;
impl Callbacks for Quiet {}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-lzharj-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// The files every fixture holds (directories end in `/`).
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut noise = Vec::new();
    let mut s = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..1500 {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        noise.push(s as u8);
    }
    vec![
        ("docs/", Vec::new()),
        ("docs/readme.txt", support::sample(12_000, 1)),
        ("docs/empty/", Vec::new()),
        ("data/", Vec::new()),
        ("data/zeros.bin", vec![0; 5000]),
        ("data/noise.bin", noise),
        ("empty.txt", Vec::new()),
        ("big.txt", support::sample(25_000, 2)),
    ]
}

fn members() -> Vec<Member> {
    corpus()
        .into_iter()
        .map(|(n, d)| match n.strip_suffix('/') {
            Some(dir) => Member::dir(dir),
            None => Member::file(n, d),
        })
        .collect()
}

/// Extracts everything to a fresh directory and reads it back: `name -> Some(bytes)` for
/// files, `None` for directories.
fn extract_all(a: &dyn Archive, label: &str) -> Result<BTreeMap<String, Option<Vec<u8>>>, String> {
    let dir = tmp(label);
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 4,
        target: Target::Disk {
            dir: dir.clone(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    let rep = extract(a, &opts, &Quiet).map_err(|e| e.to_string())?;
    if !rep.errors.is_empty() {
        let _ = fs::remove_dir_all(&dir);
        return Err(format!("{:?}", rep.errors));
    }
    let mut out = BTreeMap::new();
    for e in a.entries() {
        let p = dir.join(&e.name);
        let v = if e.is_dir {
            assert!(p.is_dir(), "{label}: {} missing", e.name);
            None
        } else {
            Some(fs::read(&p).unwrap_or_else(|err| panic!("{label}: {}: {err}", e.name)))
        };
        out.insert(e.name.clone(), v);
    }
    let _ = fs::remove_dir_all(&dir);
    Ok(out)
}

/// Decodes and verifies everything without writing files.
fn test_all(a: &dyn Archive) -> Result<(), String> {
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 2,
        target: Target::Test,
        selected: None,
    };
    let rep = extract(a, &opts, &Quiet).map_err(|e| e.to_string())?;
    if rep.errors.is_empty() {
        Ok(())
    } else {
        Err(format!("{:?}", rep.errors))
    }
}

fn expected() -> BTreeMap<String, Option<Vec<u8>>> {
    corpus()
        .into_iter()
        .map(|(n, d)| match n.strip_suffix('/') {
            Some(dir) => (dir.to_string(), None),
            None => (n.to_string(), Some(d)),
        })
        .collect()
}

fn open_mem(bytes: Vec<u8>, name: &str) -> r7z::Result<r7z::format::Opened> {
    open_bytes(bytes, name, &OpenRequest::default())
}

/// Opens, checks the format, entry names/sizes and extracted bytes against the corpus.
fn check_archive(bytes: Vec<u8>, name: &str, format: &str) -> r7z::format::Opened {
    let opened = open_mem(bytes, name).unwrap_or_else(|e| panic!("{name}: {e}"));
    let a = opened.archive();
    assert_eq!(a.format().name, format, "{name}");
    let want = expected();
    let names: Vec<&str> = a.entries().iter().map(|e| e.name.as_str()).collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(
        sorted,
        want.keys().map(|k| k.as_str()).collect::<Vec<_>>(),
        "{name}"
    );
    for e in a.entries() {
        let w = &want[&e.name];
        assert_eq!(e.is_dir, w.is_none(), "{name}: {}", e.name);
        assert_eq!(
            e.size,
            Some(w.as_ref().map_or(0, |d| d.len() as u64)),
            "{name}: {}",
            e.name
        );
    }
    let got = extract_all(a, name).unwrap_or_else(|e| panic!("{name}: {e}"));
    for (k, v) in &want {
        assert!(got[k] == *v, "{name}: {k} differs");
    }
    opened
}

fn read_fixture(rel: &str) -> Vec<u8> {
    fs::read(fixture_dir().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Encoder-made LZH fixtures: (file, header level, method).
const LZH_FIXTURES: &[(&str, u8, &str)] = &[
    ("lzh/level0-lh5.lzh", 0, "lh5"),
    ("lzh/level1-lh6.lzh", 1, "lh6"),
    ("lzh/level2-lh7.lzh", 2, "lh7"),
    ("lzh/level2-lh4.lzh", 2, "lh4"),
    ("lzh/level1-lh0.lzh", 1, "lh0"),
    ("lzh/level3-lh5.lzh", 3, "lh5"),
    ("lzh/level2-lh1.lzh", 2, "lh1"),
    ("lzh/level2-lzs.lzh", 2, "lzs"),
    ("lzh/level2-lz5.lzh", 2, "lz5"),
];

const ARJ_FIXTURES: &[(&str, u8)] = &[("arj/m0.arj", 0), ("arj/m1.arj", 1), ("arj/m4.arj", 4)];

#[test]
#[ignore = "rewrites tests/fixtures; run by hand"]
fn gen_fixtures() {
    let root = fixture_dir();
    fs::create_dir_all(root.join("lzh")).unwrap();
    fs::create_dir_all(root.join("arj")).unwrap();
    for &(file, level, method) in LZH_FIXTURES {
        fs::write(root.join(file), write_lzh(&members(), level, method)).unwrap();
    }
    for &(file, method) in ARJ_FIXTURES {
        fs::write(
            root.join(file),
            write_arj("test.arj", &members(), method, ""),
        )
        .unwrap();
    }
    // Large archives for cross-checking multi-block streams with 7-Zip (not checked in).
    let big_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/lzh-arj-big");
    fs::create_dir_all(&big_dir).unwrap();
    let big = vec![Member::file("big.txt", big_sample())];
    fs::write(big_dir.join("big.txt"), &big[0].data).unwrap();
    for method in ["lh4", "lh5", "lh6", "lh7", "lh1", "lzs", "lz5"] {
        fs::write(
            big_dir.join(format!("{method}.lzh")),
            write_lzh(&big, 2, method),
        )
        .unwrap();
    }
    for method in [1, 4] {
        fs::write(
            big_dir.join(format!("m{method}.arj")),
            write_arj("b.arj", &big, method, ""),
        )
        .unwrap();
    }
    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/lzh-arj-corpus");
    let _ = fs::remove_dir_all(&corpus_dir);
    for (n, d) in corpus() {
        let p = corpus_dir.join(n);
        if n.ends_with('/') {
            fs::create_dir_all(p).unwrap();
        } else {
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, d).unwrap();
        }
    }
}

#[test]
fn bandizip_lh7_fixture() {
    let opened = check_archive(
        read_fixture("lzh/bandizip-lh7.lzh"),
        "bandizip-lh7.lzh",
        "Lzh",
    );
    let a = opened.archive();
    for e in a.entries() {
        let want = if e.is_dir { "-lhd-" } else { "-lh7-" };
        assert_eq!(e.method.as_deref(), Some(want), "{}", e.name);
        assert!(e.mtime.is_some());
        assert_eq!(e.crc, None);
    }
    assert!(a.verifies_data());
}

#[test]
fn lzh_fixtures() {
    for &(file, level, method) in LZH_FIXTURES {
        let bytes = read_fixture(file);
        assert_eq!(
            bytes,
            write_lzh(&members(), level, method),
            "{file} is stale"
        );
        let opened = check_archive(bytes, file, "Lzh");
        let a = opened.archive();
        let readme = a
            .entries()
            .iter()
            .find(|e| e.name == "docs/readme.txt")
            .unwrap();
        assert_eq!(
            readme.method.as_deref(),
            Some(format!("-{method}-").as_str())
        );
        // Level 0/1 store a DOS time (local); levels 1-3 here carry a Unix time.
        let unix = 1_700_000_000u64;
        if level >= 1 {
            assert_eq!(
                readme.mtime,
                Some((unix + 11_644_473_600) * 10_000_000),
                "{file}"
            );
        } else {
            assert!(readme.mtime.is_some());
        }
        if level >= 1 {
            assert_eq!(
                readme.attrib.map(|a| a >> 16),
                Some(if level == 1 { 0o644 } else { 0o755 })
            );
        }
    }
}

#[test]
fn arj_fixtures() {
    for &(file, method) in ARJ_FIXTURES {
        let bytes = read_fixture(file);
        assert_eq!(
            bytes,
            write_arj("test.arj", &members(), method, ""),
            "{file} is stale"
        );
        let opened = check_archive(bytes, file, "Arj");
        let a = opened.archive();
        assert!(!a.verifies_data());
        let readme = a
            .entries()
            .iter()
            .find(|e| e.name == "docs/readme.txt")
            .unwrap();
        assert_eq!(readme.method.as_deref(), Some(method.to_string().as_str()));
        assert_eq!(
            readme.crc,
            Some(crc32fast::hash(&support::sample(12_000, 1)))
        );
        assert_eq!(readme.attrib, Some(0x20));
        assert!(readme.mtime.is_some());
    }
}

#[test]
fn opens_from_disk_by_signature() {
    let path = fixture_dir().join("arj/m4.arj");
    let opened = r7z::format::open(&path, &OpenRequest::default()).unwrap();
    assert_eq!(opened.archive().format().name, "Arj");
    // Detection does not depend on the extension.
    let bytes = read_fixture("lzh/level2-lh7.lzh");
    assert_eq!(
        open_mem(bytes, "noext").unwrap().archive().format().name,
        "Lzh"
    );
    let forced = OpenRequest {
        format: r7z::format::find_format("lha"),
        ..OpenRequest::default()
    };
    let bytes = read_fixture("lzh/level0-lh5.lzh");
    assert_eq!(
        open_bytes(bytes, "x.bin", &forced)
            .unwrap()
            .archive()
            .format()
            .name,
        "Lzh"
    );
}

/// Multi-block, long-distance test data.
fn big_sample() -> Vec<u8> {
    let mut v = support::sample(400_000, 9);
    v.extend(vec![b'z'; 70_000]);
    let head = v[..90_000].to_vec();
    v.extend(head);
    v
}

/// Larger inputs: multi-block streams, long matches, every method and header level.
#[test]
fn round_trips() {
    let big = big_sample();
    let mut runs = support::sample(70_000, 4);
    runs.extend(vec![b'z'; 70_000]);
    runs.extend(support::sample(70_000, 4));
    let files = || {
        vec![
            Member::dir("d"),
            Member::file("d/big.txt", big.clone()),
            Member::file("runs.bin", runs.clone()),
            Member::file("one", vec![7]),
        ]
    };
    for method in ["lh0", "lh1", "lh4", "lh5", "lh6", "lh7", "lzs", "lz5"] {
        for level in 0..=3 {
            let label = format!("{method}-l{level}");
            let opened = open_mem(write_lzh(&files(), level, method), "t.lzh").unwrap();
            let got = extract_all(opened.archive(), &label).unwrap();
            assert!(got["d/big.txt"].as_deref() == Some(&big[..]), "{label}");
            assert!(got["runs.bin"].as_deref() == Some(&runs[..]), "{label}");
            assert!(got["one"].as_deref() == Some(&[7][..]), "{label}");
        }
    }
    for method in 0..=4 {
        let label = format!("arj-m{method}");
        let opened = open_mem(write_arj("t.arj", &files(), method, "note"), "t.arj").unwrap();
        let a = opened.archive();
        assert!(a.properties().contains(&("Comment", "note".to_string())));
        let got = extract_all(a, &label).unwrap();
        assert!(got["d/big.txt"].as_deref() == Some(&big[..]), "{label}");
        assert!(got["runs.bin"].as_deref() == Some(&runs[..]), "{label}");
    }
}

#[test]
fn garbled_and_split_arj_entries_are_unsupported() {
    for (flags, what) in [(0x11u8, "garbled"), (0x14, "volumes"), (0x18, "volumes")] {
        let mut m = Member::file("a.txt", b"secret data".to_vec());
        m.arj_flags = flags;
        let opened = open_mem(write_arj("t.arj", &[m], 1, ""), "t.arj").unwrap();
        let a = opened.archive();
        assert_eq!(a.entries()[0].encrypted, flags & 1 != 0);
        assert!(!a.has_encrypted_data());
        let err = test_all(a).unwrap_err();
        assert!(err.contains("Unsupported") && err.contains(what), "{err}");
    }
}

#[test]
fn not_archives() {
    for (bytes, name) in [
        (b"\x60\xEA\x00".to_vec(), "x.arj"),
        (b"\x60\xEA\x30\x00garbage".to_vec(), "x.arj"),
        (b"ab-lhx".to_vec(), "x.lzh"),
        (Vec::new(), "x.lzh"),
    ] {
        assert!(open_mem(bytes, name).is_err(), "{name}");
    }
}

/// Every truncation fails cleanly, except LZH cuts at an entry boundary (the format has no
/// required terminator), which must list a prefix of the entries and still decode.
#[test]
fn truncated_archives_fail() {
    let mut cases: Vec<(String, Vec<u8>)> = LZH_FIXTURES
        .iter()
        .map(|&(f, _, _)| (f.to_string(), read_fixture(f)))
        .collect();
    cases.push(("bandizip".into(), read_fixture("lzh/bandizip-lh7.lzh")));
    cases.extend(
        ARJ_FIXTURES
            .iter()
            .map(|&(f, _)| (f.to_string(), read_fixture(f))),
    );
    for (name, full) in cases {
        let all = open_mem(full.clone(), &name).unwrap();
        let all_names: Vec<String> = all
            .archive()
            .entries()
            .iter()
            .map(|e| e.name.clone())
            .collect();
        let step = (full.len() / 300).max(1);
        for cut in (0..full.len() - 1).step_by(step).chain([full.len() - 2]) {
            let Ok(opened) = open_mem(full[..cut].to_vec(), &name) else {
                continue;
            };
            let a = opened.archive();
            if test_all(a).is_err() {
                continue;
            }
            let names: Vec<String> = a.entries().iter().map(|e| e.name.clone()).collect();
            assert!(
                name.contains("lzh") || name == "bandizip",
                "{name} cut at {cut} passed"
            );
            assert!(names.len() < all_names.len() || cut == full.len() - 1);
            assert_eq!(names[..], all_names[..names.len()], "{name} cut at {cut}");
        }
    }
}

/// Bit flips never panic; when nothing reports an error, names and sizes are unchanged
/// (the data itself is then covered by its CRC), except where the format has no header
/// checksum (LZH level 1 extended headers).
#[test]
fn bit_flips_fail_or_are_harmless() {
    let mut cases: Vec<(String, Vec<u8>)> = LZH_FIXTURES
        .iter()
        .map(|&(f, _, _)| (f.to_string(), read_fixture(f)))
        .collect();
    cases.push(("bandizip".into(), read_fixture("lzh/bandizip-lh7.lzh")));
    cases.extend(
        ARJ_FIXTURES
            .iter()
            .map(|&(f, _)| (f.to_string(), read_fixture(f))),
    );
    for (name, full) in cases {
        let want: Vec<(String, Option<u64>)> = open_mem(full.clone(), &name)
            .unwrap()
            .archive()
            .entries()
            .iter()
            .map(|e| (e.name.clone(), e.size))
            .collect();
        let step = (full.len() / 400).max(1);
        let mut data_errors = 0;
        for (k, pos) in (0..full.len()).step_by(step).enumerate() {
            let mut bad = full.clone();
            bad[pos] ^= 1 << (k % 8);
            let Ok(opened) = open_mem(bad, &name) else {
                continue;
            };
            let a = opened.archive();
            match test_all(a) {
                Err(_) => data_errors += 1,
                Ok(()) => {
                    let got: Vec<(String, Option<u64>)> = a
                        .entries()
                        .iter()
                        .map(|e| (e.name.clone(), e.size))
                        .collect();
                    // An LZH header size flipped to zero reads as the end marker.
                    if full[pos] ^ (1 << (k % 8)) == 0 && got.len() < want.len() {
                        assert_eq!(got[..], want[..got.len()], "{name}: flip at {pos}");
                        continue;
                    }
                    // Level 1 extended headers have no checksum of their own.
                    if !name.contains("level1") {
                        assert_eq!(got, want, "{name}: flip at {pos} went unnoticed");
                    }
                }
            }
        }
        assert!(data_errors > 0, "{name}");
    }
}

#[test]
fn data_errors_are_typed() {
    let mut bytes = read_fixture("lzh/level0-lh5.lzh");
    // The last byte before the terminator belongs to big.txt's compressed data.
    let n = bytes.len();
    bytes[n - 2] ^= 0x55;
    let opened = open_mem(bytes, "x.lzh").unwrap();
    let err = test_all(opened.archive()).unwrap_err();
    assert!(err.contains("Checksum") || err.contains("Corrupt"), "{err}");
}
