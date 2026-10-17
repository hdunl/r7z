//! CAB reading: makecab fixtures (stored, MSZIP, LZX:15/16/21, reserve fields, a
//! five-cabinet set) and synthetic ones from `fixtures/cab/make_synthetic.py` (Quantum,
//! name encodings, overlapping files). Every fixture except `overlap.cab` was cross-checked
//! against 7-Zip 25.01; damaged inputs must fail cleanly.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use r7z::format::{open, open_bytes, OpenRequest, Opened};
use r7z::ops::extract::{
    extract, safe_relative_path, Callbacks, ExtractOptions, Overwrite, Report, Target,
};
use r7z::Error;

struct Quiet;
impl Callbacks for Quiet {}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/cab")
        .join(name)
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-cab-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn open_path(p: &Path) -> Opened {
    open(p, &OpenRequest::default()).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn run(o: &Opened, target: Target) -> Report {
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 4,
        target,
        selected: None,
    };
    extract(o.archive(), &opts, &Quiet).unwrap()
}

/// Extracts everything and returns `name -> bytes`.
fn extract_all(o: &Opened, label: &str) -> BTreeMap<String, Vec<u8>> {
    let dir = tmp(label);
    let rep = run(
        o,
        Target::Disk {
            dir: dir.clone(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
    );
    assert!(rep.errors.is_empty(), "{label}: {:?}", rep.errors);
    let mut out = BTreeMap::new();
    for e in o.archive().entries() {
        let path = dir.join(safe_relative_path(&e.name).unwrap());
        out.insert(e.name.clone(), fs::read(path).unwrap());
    }
    let _ = fs::remove_dir_all(&dir);
    out
}

fn crc(d: &[u8]) -> u32 {
    crc32fast::hash(d)
}

/// The makecab sources (see the fixture notes in this file's header).
const TEXT: (u64, u32) = (163_890, 0x0e51_1559);
const CODE: (u64, u32) = (70_000, 0xbd0d_48d3);
const RAND: (u64, u32) = (6000, 0x72d2_224f);
const SMALL: (u64, u32) = (10, 0x13e7_f036);
const EMPTY: (u64, u32) = (0, 0);

/// Checks names, sizes, methods, blocks and extracted bytes of a fixture.
fn check(name: &str, want: &[(&str, (u64, u32), &str, usize)]) -> Opened {
    let o = open_path(&fixture(name));
    let a = o.archive();
    assert_eq!(a.format().name, "Cab");
    let got: Vec<_> = a
        .entries()
        .iter()
        .map(|e| (e.name.as_str(), e.size, e.method.as_deref(), e.block))
        .collect();
    let expect: Vec<_> = want
        .iter()
        .map(|(n, (s, _), m, b)| (*n, Some(*s), Some(*m), Some(*b)))
        .collect();
    assert_eq!(got, expect, "{name}");
    let data = extract_all(&o, name);
    for (n, (s, c), _, _) in want {
        assert_eq!(data[*n].len() as u64, *s, "{name}/{n}");
        assert_eq!(crc(&data[*n]), *c, "{name}/{n}");
    }
    assert!(run(&o, Target::Test).errors.is_empty());
    o
}

fn prop(o: &Opened, key: &str) -> Option<String> {
    o.archive()
        .properties()
        .into_iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

#[test]
fn stored() {
    check(
        "none.cab",
        &[
            ("small.txt", SMALL, "None", 0),
            ("empty.txt", EMPTY, "None", 0),
            ("dir/rand.bin", RAND, "None", 0),
        ],
    );
}

#[test]
fn mszip_two_folders() {
    let o = check(
        "mszip.cab",
        &[
            ("text.txt", TEXT, "MSZip", 0),
            ("small.txt", SMALL, "MSZip", 0),
            ("empty.txt", EMPTY, "MSZip", 0),
            ("sub/dir/code.bin", CODE, "MSZip", 1),
            ("rand.bin", RAND, "MSZip", 1),
        ],
    );
    assert_eq!(o.archive().units().len(), 2);
    assert_eq!(prop(&o, "Method").as_deref(), Some("MSZip"));
    assert_eq!(prop(&o, "Blocks").as_deref(), Some("2"));
    let e = &o.archive().entries()[0];
    assert_eq!(e.attr_string(), "....A");
    assert!(e.mtime.is_some() && e.packed_size.is_some());
}

#[test]
fn mszip_with_reserve_fields() {
    check(
        "reserve.cab",
        &[
            ("text.txt", TEXT, "MSZip", 0),
            ("small.txt", SMALL, "MSZip", 0),
        ],
    );
}

#[test]
fn lzx_windows() {
    check(
        "lzx15.cab",
        &[
            ("text.txt", TEXT, "LZX:15", 0),
            ("code.bin", CODE, "LZX:15", 0),
            ("small.txt", SMALL, "LZX:15", 0),
        ],
    );
    check(
        "lzx21.cab",
        &[
            ("code.bin", CODE, "LZX:21", 0),
            ("text.txt", TEXT, "LZX:21", 0),
            ("rand.bin", RAND, "LZX:21", 0),
            ("small.txt", SMALL, "LZX:21", 1),
        ],
    );
}

#[test]
fn mixed_methods() {
    let o = check(
        "mixed.cab",
        &[
            ("small.txt", SMALL, "LZX:16", 0),
            ("rand.bin", RAND, "MSZip", 1),
            ("empty.txt", EMPTY, "None", 2),
            ("s2.txt", SMALL, "None", 2),
        ],
    );
    assert_eq!(prop(&o, "Method").as_deref(), Some("None MSZip LZX:16"));
}

#[test]
fn quantum() {
    for name in ["quantum10.cab", "quantum21.cab"] {
        let bits = &name[7..9];
        let m = format!("Quantum:{bits}");
        let o = check(
            name,
            &[
                ("text.txt", (40_520, 0x6c23_ac94), &m, 0),
                ("noise.bin", (3000, 0xd698_6f97), &m, 0),
                ("dir/mixed.bin", (16_048, 0xf329_138e), &m, 0),
                ("rev.bin", (16_825, 0x120e_4ae9), &m, 1),
            ],
        );
        assert_eq!(o.archive().entries()[2].attr_string(), ".R..A");
    }
}

const SPAN_SET: &[(&str, (u64, u32), &str, usize)] = &[
    ("rand.bin", RAND, "MSZip", 0),
    ("small.txt", SMALL, "MSZip", 0),
    ("code.bin", CODE, "MSZip", 0),
    ("r2.bin", RAND, "MSZip", 1),
];

#[test]
fn multi_cabinet_set_from_any_volume() {
    for i in 1..=5 {
        let o = check(&format!("span{i}.cab"), SPAN_SET);
        assert_eq!(prop(&o, "Volumes").as_deref(), Some("5"));
        assert_eq!(prop(&o, "Volume Index").as_deref(), Some("0"));
        assert_eq!(prop(&o, "Total Physical Size").as_deref(), Some("37197"));
        assert_eq!(o.archive().units().len(), 2);
    }
}

fn copy_volumes(label: &str, which: &[usize]) -> PathBuf {
    let dir = tmp(label);
    for i in which {
        let n = format!("span{i}.cab");
        fs::copy(fixture(&n), dir.join(&n)).unwrap();
    }
    dir
}

fn errors_by_name(o: &Opened) -> BTreeMap<String, String> {
    run(o, Target::Test)
        .errors
        .into_iter()
        .map(|(n, e)| {
            assert!(matches!(e, Error::Unsupported(_)), "{n}: {e}");
            (n, e.to_string())
        })
        .collect()
}

#[test]
fn missing_volumes_fail_cleanly() {
    let dir = copy_volumes("missing", &[1, 3, 4, 5]);
    // span1 alone: every file needs span2.
    let o = open_path(&dir.join("span1.cab"));
    let names: Vec<_> = o
        .archive()
        .entries()
        .iter()
        .map(|e| e.name.clone())
        .collect();
    assert_eq!(names, ["rand.bin", "small.txt", "code.bin"]);
    let errs = errors_by_name(&o);
    assert_eq!(errs.len(), 3);
    assert!(errs["code.bin"].contains("span2.cab"), "{errs:?}");
    // span4 onwards: code.bin started in an earlier cabinet; r2.bin is whole.
    let o = open_path(&dir.join("span4.cab"));
    assert_eq!(prop(&o, "Volumes").as_deref(), Some("2"));
    let e = o.archive().entries();
    assert_eq!((e[0].name.as_str(), e[0].block), ("code.bin", None));
    assert_eq!((e[1].name.as_str(), e[1].block), ("r2.bin", Some(0)));
    let errs = errors_by_name(&o);
    assert_eq!(errs.keys().collect::<Vec<_>>(), ["code.bin"]);
    let _ = fs::remove_dir_all(&dir);

    // From memory there are no siblings to follow.
    let o = open_bytes(
        fs::read(fixture("span3.cab")).unwrap(),
        "span3.cab",
        &OpenRequest::default(),
    )
    .unwrap();
    assert_eq!(o.archive().entries().len(), 1);
    assert_eq!(errors_by_name(&o).len(), 1);
}

#[test]
fn names_attributes_and_times() {
    let o = open_path(&fixture("names.cab"));
    let e = o.archive().entries();
    let names: Vec<_> = e.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names[..4],
        ["plain.txt", "same.txt", "baddate.txt", "dir/naïve 名.txt"]
    );
    // A non-UTF-8 name is decoded in the ANSI code page; only its ASCII part is fixed.
    assert!(
        names[4].starts_with("caf") && names[4].ends_with("txt"),
        "{}",
        names[4]
    );
    assert_eq!(e[4].attr_string(), ".RHSA");
    assert_eq!(e[2].mtime, None);
    assert_eq!(
        e[0].mtime,
        r7z::util::time::dos_to_filetime((46 << 9) | (10 << 5) | 17, (13 << 11) | (37 << 5) | 21)
    );
    let body = [
        &b"0123456789".repeat(50)[..],
        b"UTF8 named\n",
        b"cp1252 named\n",
    ]
    .concat();
    let data = extract_all(&o, "names");
    assert_eq!(data["plain.txt"], body[..500]);
    assert_eq!(data["same.txt"], body[..500]);
    assert_eq!(data["dir/naïve 名.txt"], body[500..511]);
    assert_eq!(data[names[4]], body[511..]);
}

#[test]
fn overlapping_files() {
    let o = open_path(&fixture("overlap.cab"));
    let body = [
        &b"0123456789".repeat(50)[..],
        b"UTF8 named\n",
        b"cp1252 named\n",
    ]
    .concat();
    let data = extract_all(&o, "overlap");
    for (n, off, len) in [
        ("a.txt", 0, 300),
        ("b.txt", 200, 300),
        ("c.txt", 500, 24),
        ("d.txt", 250, 50),
    ] {
        assert_eq!(data[n], body[off..off + len], "{n}");
    }
}

const ALL: &[&str] = &[
    "none.cab",
    "mszip.cab",
    "reserve.cab",
    "lzx15.cab",
    "lzx21.cab",
    "mixed.cab",
    "quantum10.cab",
    "quantum21.cab",
    "names.cab",
    "span3.cab",
];

/// Opens and test-extracts damaged bytes; returns whether anything failed.
fn damaged(data: Vec<u8>) -> bool {
    match open_bytes(data, "x.cab", &OpenRequest::default()) {
        Err(_) => true,
        Ok(o) => !run(&o, Target::Test).errors.is_empty(),
    }
}

#[test]
fn truncation_is_an_error() {
    for name in ALL {
        let full = fs::read(fixture(name)).unwrap();
        let mut cut = 0;
        while cut < full.len() {
            assert!(damaged(full[..cut].to_vec()), "{name} cut at {cut}");
            cut += 1 + cut / 7;
        }
    }
}

#[test]
fn bit_flips_never_panic() {
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut detected = 0;
    let mut total = 0;
    for name in ALL {
        let full = fs::read(fixture(name)).unwrap();
        for _ in 0..300 {
            let mut d = full.clone();
            for _ in 0..1 + next() % 3 {
                let at = (next() % d.len() as u64) as usize;
                d[at] ^= 1 << (next() % 8);
            }
            total += 1;
            detected += damaged(d) as usize;
        }
    }
    // Flips in names, dates or attributes are undetectable; data flips hit checksums.
    assert!(detected * 2 > total, "{detected}/{total}");
}

#[test]
fn data_flips_are_detected() {
    // Every makecab block carries a checksum, so any flip in block data is caught.
    let full = fs::read(fixture("lzx21.cab")).unwrap();
    for at in (200..full.len()).step_by(97) {
        let mut d = full.clone();
        d[at] ^= 0x10;
        assert!(damaged(d), "flip at {at}");
    }
}

/// Zeroes every CFDATA checksum so damaged block data reaches the decoders. Returns the
/// byte ranges of the block payloads.
fn strip_checksums(d: &mut [u8]) -> Vec<std::ops::Range<usize>> {
    let u16_at = |d: &[u8], i: usize| u16::from_le_bytes([d[i], d[i + 1]]) as usize;
    let u32_at =
        |d: &[u8], i: usize| u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]) as usize;
    let (folders, flags) = (u16_at(d, 26), u16_at(d, 30));
    let (mut at, mut folder_res, mut data_res) = (36, 0, 0);
    if flags & 4 != 0 {
        (folder_res, data_res) = (d[38] as usize, d[39] as usize);
        at = 40 + u16_at(d, 36);
    }
    for _ in 0..[0, 2, 2, 4][flags & 3] {
        at += d[at..].iter().position(|&b| b == 0).unwrap() + 1;
    }
    let mut payloads = Vec::new();
    for f in 0..folders {
        let rec = at + f * (8 + folder_res);
        let mut b = u32_at(d, rec);
        for _ in 0..u16_at(d, rec + 4) {
            d[b..b + 4].fill(0);
            let len = u16_at(d, b + 4);
            let start = b + 8 + data_res;
            payloads.push(start..start + len);
            b = start + len;
        }
    }
    payloads
}

#[test]
fn damaged_compressed_data_never_panics() {
    let rounds: usize = std::env::var("R7Z_CAB_FUZZ")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150);
    let mut seed = 0x2545_F491_4F6C_DD1Du64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for name in [
        "mszip.cab",
        "lzx15.cab",
        "lzx21.cab",
        "mixed.cab",
        "quantum10.cab",
        "quantum21.cab",
    ] {
        let mut clean = fs::read(fixture(name)).unwrap();
        let payloads = strip_checksums(&mut clean);
        assert!(!damaged(clean.clone()), "{name} without checksums");
        for _ in 0..rounds {
            let mut d = clean.clone();
            let p = &payloads[(next() % payloads.len() as u64) as usize];
            for _ in 0..1 + next() % 4 {
                if p.is_empty() {
                    break;
                }
                let at = p.start + (next() % p.len() as u64) as usize;
                d[at] = if next() % 4 == 0 {
                    next() as u8
                } else {
                    d[at] ^ (1 << (next() % 8))
                };
            }
            damaged(d);
        }
    }
}
