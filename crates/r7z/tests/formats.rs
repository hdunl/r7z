//! Round trips and fixture reads for zip, tar, the stream compressors and the small
//! container formats, through the format layer (`format::open` + `ops::extract`).
//! Fixtures in tests/fixtures/streams were made with bsdtar 3.8, GNU tar 1.34, xz 5.4,
//! coreutils base64 and Python's zipfile (see scripts/interop.sh for the live cross-checks
//! against 7-Zip).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use r7z::format::write::{create, kind_for, Kind, WriteOptions};
use r7z::format::{open, open_bytes, Archive, Link, OpenRequest};
use r7z::ops::bench::generate;
use r7z::ops::create::{Item, NoProgress};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};
use r7z::Error;

struct Quiet;
impl Callbacks for Quiet {}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-fmt-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/streams")
        .join(name)
}

/// A tree with a large file (streamed path in zip), Unicode and long names, an empty file
/// and an empty directory.
fn corpus(root: &Path) -> Vec<Item> {
    let long = format!("{}/{}.txt", "d".repeat(70), "f".repeat(90));
    let files: Vec<(String, Vec<u8>)> = vec![
        ("a/text.txt".into(), b"hello world\n".repeat(5000)),
        ("a/big.bin".into(), generate(20 << 20, 3)),
        (
            "a/random.bin".into(),
            (0..300_000u32)
                .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
                .collect(),
        ),
        ("a/empty.txt".into(), Vec::new()),
        ("ünï/名前.txt".into(), "héllo".as_bytes().to_vec()),
        (long.clone(), b"long name".to_vec()),
    ];
    let mut items = Vec::new();
    for d in ["a", "a/emptydir", "ünï", &"d".repeat(70)] {
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
        fs::write(root.join(&name), &data).unwrap();
        items.push(Item {
            src: root.join(&name),
            name,
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

fn opts(level: u32, password: Option<&str>) -> WriteOptions {
    WriteOptions {
        level,
        threads: 4,
        password: password.map(str::to_string),
        store: false,
        zstd: false,
        store_mtime: true,
        store_ctime: false,
        store_atime: false,
    }
}

fn extract_to(a: &dyn Archive, out: &Path, password: Option<&str>) -> r7z::ops::extract::Report {
    let eo = ExtractOptions {
        base: None,
        password: password.map(str::to_string),
        threads: 4,
        target: Target::Disk {
            dir: out.to_path_buf(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    extract(a, &eo, &Quiet).unwrap()
}

fn test_all(a: &dyn Archive, password: Option<&str>) -> r7z::ops::extract::Report {
    let eo = ExtractOptions {
        base: None,
        password: password.map(str::to_string),
        threads: 4,
        target: Target::Test,
        selected: None,
    };
    extract(a, &eo, &Quiet).unwrap()
}

fn roundtrip(file: &str, level: u32, password: Option<&str>, expect_type: &str) {
    let dir = tmp(&file.replace('.', "_"));
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join(file);
    let kind = kind_for(&arc, None).unwrap();
    let summary = create(&arc, kind, &items, &opts(level, password), &NoProgress).unwrap();
    assert_eq!(summary.files, 6, "{file}");

    let req = OpenRequest {
        password: password.map(str::to_string),
        format: None,
        ..Default::default()
    };
    let opened = open(&arc, &req).unwrap();
    let a = opened.archive();
    assert_eq!(a.format().name, expect_type, "{file}");
    assert_eq!(a.entries().len(), 10, "{file}");
    let t = test_all(a, password);
    assert!(t.errors.is_empty(), "{file}: {:?}", t.errors);
    let out = dir.join("out");
    let rep = extract_to(a, &out, password);
    assert!(rep.errors.is_empty(), "{file}: {:?}", rep.errors);
    for it in items.iter().filter(|i| !i.is_dir) {
        let a = fs::read(&it.src).unwrap();
        let b = fs::read(out.join(&it.name)).unwrap();
        assert!(a == b, "{file}: {} differs", it.name);
    }
    assert!(out.join("a/emptydir").is_dir(), "{file}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn zip_deflate_store_and_aes() {
    roundtrip("t.zip", 5, None, "zip");
    roundtrip("t0.zip", 0, None, "zip");
    roundtrip("t9.zip", 9, None, "zip");
    roundtrip("enc.zip", 5, Some("pässword"), "zip");
}

#[test]
fn tar_and_single_step_compressed_tar() {
    roundtrip("t.tar", 5, None, "tar");
    roundtrip("t.tar.gz", 5, None, "tar");
    roundtrip("t.tgz", 1, None, "tar");
    roundtrip("t.tar.bz2", 5, None, "tar");
    roundtrip("t.tar.xz", 1, None, "tar");
}

#[test]
fn compressed_tar_lists_both_levels() {
    let dir = tmp("levels");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join("x.tar.gz");
    create(
        &arc,
        Kind::TarIn(r7z::format::write::Compressor::Gzip),
        &items,
        &opts(5, None),
        &NoProgress,
    )
    .unwrap();
    let o = open(&arc, &OpenRequest::default()).unwrap();
    let names: Vec<&str> = o.levels.iter().map(|l| l.archive.format().name).collect();
    assert_eq!(names, ["gzip", "tar"]);
    // Forcing the stream type stops at the compressor: one entry, the tar.
    let only = open(
        &arc,
        &OpenRequest {
            password: None,
            format: r7z::format::find_format("gzip"),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(only.levels.len(), 1);
    assert_eq!(only.archive().entries()[0].name, "x.tar");
    let _ = fs::remove_dir_all(&dir);
}

fn single(file: &str) {
    let dir = tmp(&file.replace('.', "_"));
    let data = generate(3 << 20, 9);
    let src = dir.join("data.bin");
    fs::write(&src, &data).unwrap();
    let items = vec![Item {
        src: src.clone(),
        name: "data.bin".into(),
        is_dir: false,
        size: data.len() as u64,
        mtime: Some(133_000_000_000_000_000),
        ctime: None,
        atime: None,
        attrib: Some(0x20),
    }];
    let arc = dir.join(file);
    let kind = kind_for(&arc, None).unwrap();
    assert!(matches!(kind, Kind::Single(_)), "{file}");
    create(&arc, kind, &items, &opts(5, None), &NoProgress).unwrap();
    let o = open(&arc, &OpenRequest::default()).unwrap();
    let a = o.archive();
    assert_eq!(a.entries().len(), 1);
    let out = dir.join("out");
    let rep = extract_to(a, &out, None);
    assert!(rep.errors.is_empty(), "{file}: {:?}", rep.errors);
    let name = &a.entries()[0].name;
    assert_eq!(fs::read(out.join(name)).unwrap(), data, "{file}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn single_file_streams() {
    single("data.bin.gz");
    single("data.bin.bz2");
    single("data.bin.xz");
}

/// Extracts every entry into memory: name -> bytes.
fn read_all(a: &dyn Archive) -> HashMap<String, Vec<u8>> {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = tmp(&format!("read-{}-{n}", a.format().name));
    let rep = extract_to(a, &dir, None);
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    let mut m = HashMap::new();
    for e in a.entries().iter().filter(|e| !e.is_dir) {
        m.insert(e.name.clone(), fs::read(dir.join(&e.name)).unwrap());
    }
    let _ = fs::remove_dir_all(&dir);
    m
}

#[test]
fn stream_fixtures() {
    let numbers = fs::read(fixture("numbers.txt")).unwrap();
    for (file, ty) in [
        ("numbers.txt.zst", "zstd"),
        ("numbers.txt.Z", "Z"),
        ("numbers.txt.lzma", "lzma"),
        ("numbers.txt.lzma86", "lzma86"),
        ("numbers.txt.b64", "Base64"),
    ] {
        let o =
            open(&fixture(file), &OpenRequest::default()).unwrap_or_else(|e| panic!("{file}: {e}"));
        let a = o.archive();
        assert_eq!(a.format().name, ty);
        assert_eq!(a.entries()[0].name, "numbers.txt", "{file}");
        let got = read_all(a);
        assert_eq!(got["numbers.txt"], numbers, "{file}");
    }
    for file in ["tree.tar.zst", "tree.tar.Z"] {
        let o = open(&fixture(file), &OpenRequest::default()).unwrap();
        assert_eq!(o.archive().format().name, "tar", "{file}");
        let got = read_all(o.archive());
        assert_eq!(got["numbers.txt"], numbers, "{file}");
        assert_eq!(got["sub/hello.txt"], b"hello fixture\n", "{file}");
    }
}

#[test]
fn lz4_frames() {
    let data = generate(1 << 20, 4);
    let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
    enc.write_all(&data).unwrap();
    let mut lz = enc.finish().unwrap();
    // A second concatenated frame.
    let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
    enc.write_all(b"tail").unwrap();
    lz.extend(enc.finish().unwrap());
    let o = open_bytes(lz, "data.lz4", &OpenRequest::default()).unwrap();
    let a = o.archive();
    assert_eq!(a.format().name, "lz4");
    let got = read_all(a);
    let mut want = data;
    want.extend_from_slice(b"tail");
    assert_eq!(got["data"], want);
}

#[test]
fn lzma86_with_bcj() {
    // x86 code-like data: E8 calls with small relative targets.
    let mut data = Vec::new();
    for i in 0..200_000u32 {
        data.extend_from_slice(&[0x55, 0xE8]);
        data.extend_from_slice(&(i % 4096).to_le_bytes());
        data.extend_from_slice(&[0x8B, 0xEC]);
    }
    let mut bcj = lzma_rust2::filter::bcj::BcjWriter::new_x86(Vec::new(), 0);
    bcj.write_all(&data).unwrap();
    let filtered = bcj.finish().unwrap();
    assert_ne!(filtered, data);
    let opts = lzma_rust2::LzmaOptions::with_preset(6);
    let mut w =
        lzma_rust2::LzmaWriter::new_use_header(Vec::new(), &opts, Some(filtered.len() as u64))
            .unwrap();
    w.write_all(&filtered).unwrap();
    let mut file = vec![1u8];
    file.extend(w.finish().unwrap());
    let o = open_bytes(file, "code.lzma86", &OpenRequest::default()).unwrap();
    assert_eq!(o.archive().format().name, "lzma86");
    assert_eq!(read_all(o.archive())["code"], data);
}

#[test]
fn lz4_legacy_frames() {
    let data = generate(9 << 20, 6);
    let mut lz = 0x184C_2102u32.to_le_bytes().to_vec();
    for chunk in data.chunks(8 << 20) {
        let c = lz4_flex::block::compress(chunk);
        lz.extend_from_slice(&(c.len() as u32).to_le_bytes());
        lz.extend_from_slice(&c);
    }
    let o = open_bytes(lz, "vmlinux.lz4", &OpenRequest::default()).unwrap();
    assert_eq!(read_all(o.archive())["vmlinux"], data);
}

#[test]
fn zip64_and_unicode_fixture() {
    let o = open(&fixture("zip64.zip"), &OpenRequest::default()).unwrap();
    let a = o.archive();
    let names: Vec<&str> = a.entries().iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["big/numbers.txt", "ünïcødé/名前.txt", "empty"]);
    assert!(a.entries()[2].is_dir);
    let got = read_all(a);
    assert_eq!(
        got["big/numbers.txt"],
        fs::read(fixture("numbers.txt")).unwrap()
    );
    assert_eq!(got["ünïcødé/名前.txt"], b"unicode name\n");
}

#[test]
fn tar_gnu_and_pax_sparse() {
    let mut want = vec![0u8; 41 * 65536];
    want.extend_from_slice(b"end\n");
    let gnu = open(&fixture("gnu-sparse-longname.tar"), &OpenRequest::default()).unwrap();
    let got = read_all(gnu.archive());
    assert_eq!(got["sparse.bin"], want);
    assert_eq!(got[&format!("{}.txt", "n".repeat(120))], b"x");
    let pax = open(&fixture("pax-sparse.tar"), &OpenRequest::default()).unwrap();
    let e = &pax.archive().entries()[0];
    assert_eq!(e.name, "sparse.bin");
    assert_eq!(e.size, Some(want.len() as u64));
    assert_eq!(read_all(pax.archive())["sparse.bin"], want);
}

#[test]
fn ihex_blocks() {
    let o = open(&fixture("blocks.ihex"), &OpenRequest::default()).unwrap();
    let a = o.archive();
    let sizes: Vec<u64> = a.entries().iter().map(|e| e.size.unwrap()).collect();
    assert_eq!(sizes, [64, 12, 5]);
    let got = read_all(a);
    assert_eq!(got["0"], (0u8..64).collect::<Vec<_>>());
    assert_eq!(got["1"], b"hello world!");
    assert_eq!(got["2"], b"upper");
}

#[test]
fn split_volumes_join() {
    let dir = tmp("split");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join("whole.zip");
    create(&arc, Kind::Zip, &items, &opts(1, None), &NoProgress).unwrap();
    let bytes = fs::read(&arc).unwrap();
    let parts = bytes.chunks(bytes.len() / 3 + 1);
    for (i, p) in parts.enumerate() {
        fs::write(dir.join(format!("vol.zip.{:03}", i + 1)), p).unwrap();
    }
    let o = open(&dir.join("vol.zip.001"), &OpenRequest::default()).unwrap();
    assert_eq!(o.levels[0].archive.format().name, "Split");
    assert_eq!(o.archive().format().name, "zip");
    let t = test_all(o.archive(), None);
    assert!(t.errors.is_empty(), "{:?}", t.errors);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn tar_links_and_symlinks() {
    // A hand-built ustar: a file, a hard link to it and a symlink.
    fn header(name: &str, typ: u8, size: usize, link: &str) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[136..148].copy_from_slice(b"14000000000\0");
        h[156] = typ;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }
    let mut t = header("f.txt", b'0', 5, "");
    t.extend_from_slice(b"hello");
    t.resize(1024, 0);
    t.extend(header("hard.txt", b'1', 0, "f.txt"));
    t.extend(header("sym.txt", b'2', 0, "f.txt"));
    t.resize(t.len() + 1024, 0);
    let o = open_bytes(t, "l.tar", &OpenRequest::default()).unwrap();
    let a = o.archive();
    assert_eq!(a.entries()[1].link, Some(Link::Hard("f.txt".into())));
    assert_eq!(a.entries()[2].link, Some(Link::Symbolic("f.txt".into())));
    let got = read_all(a);
    assert_eq!(got["hard.txt"], b"hello");
    // Where the platform allows links, the symlink reads its target; otherwise it is the
    // file holding the target's name.
    let sym = &got["sym.txt"];
    assert!(sym == b"hello" || sym == b"f.txt", "{sym:?}");
}

#[test]
fn damage_is_detected() {
    let dir = tmp("damage");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    for file in ["d.zip", "d.tar.gz", "d.tar.xz", "d.tar.bz2"] {
        let arc = dir.join(file);
        create(
            &arc,
            kind_for(&arc, None).unwrap(),
            &items,
            &opts(1, None),
            &NoProgress,
        )
        .unwrap();
        let good = fs::read(&arc).unwrap();
        // Flip a byte inside the compressed data.
        let mut bad = good.clone();
        let at = bad.len() / 3;
        bad[at] ^= 0x55;
        let r = open_bytes(bad, file, &OpenRequest::default());
        let failed = match r {
            Err(_) => true,
            Ok(o) => !test_all(o.archive(), None).errors.is_empty(),
        };
        assert!(failed, "{file}: corruption not detected");
        // Truncation.
        let cut = good[..good.len() / 2].to_vec();
        let r = open_bytes(cut, file, &OpenRequest::default());
        let failed = match r {
            Err(_) => true,
            Ok(o) => !test_all(o.archive(), None).errors.is_empty(),
        };
        assert!(failed, "{file}: truncation not detected");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn zip_password_errors() {
    let dir = tmp("zippw");
    let src = dir.join("src");
    fs::create_dir_all(&src).unwrap();
    let items = corpus(&src);
    let arc = dir.join("p.zip");
    create(
        &arc,
        Kind::Zip,
        &items,
        &opts(1, Some("right")),
        &NoProgress,
    )
    .unwrap();
    let o = open(&arc, &OpenRequest::default()).unwrap();
    assert!(o.archive().has_encrypted_data());
    let rep = test_all(o.archive(), Some("wrong"));
    assert!(!rep.errors.is_empty());
    assert!(
        rep.errors
            .iter()
            .all(|(_, e)| matches!(e, Error::WrongPassword)),
        "{:?}",
        rep.errors
    );
    let rep = test_all(o.archive(), None);
    assert!(
        rep.errors
            .iter()
            .all(|(_, e)| matches!(e, Error::PasswordRequired)),
        "{:?}",
        rep.errors
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn not_an_archive() {
    let r = open_bytes(
        b"just some text, not an archive".to_vec(),
        "x.bin",
        &OpenRequest::default(),
    );
    assert!(matches!(r, Err(Error::NotArchive)));
}
