//! Recovery of damaged archives (`ops::recover`). Every fixture is built here and then
//! damaged on purpose: truncated, central directory zeroed, header lost, bytes changed in
//! the middle of a solid block, a tar header destroyed.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use r7z::codec::lzma2scan;
use r7z::ops::bench::generate;
use r7z::ops::create::{create, CreateOptions, Item, MainMethod, NoProgress};
use r7z::ops::extract::{Callbacks, ExtractOptions, Overwrite, Target};
use r7z::ops::recover::{recover_file, Outcome, RecoverOptions, RecoverReport};
use r7z::sevenz::read::ArchiveFile;

struct Quiet;
impl Callbacks for Quiet {}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-recover-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn to_disk(out: &Path) -> ExtractOptions {
    ExtractOptions {
        base: None,
        password: None,
        threads: 4,
        target: Target::Disk {
            dir: out.to_path_buf(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    }
}

/// Writes `bytes` as `name` in `dir`, recovers it into `dir/out`.
fn run(dir: &Path, name: &str, bytes: &[u8]) -> RecoverReport {
    let path = dir.join(name);
    fs::write(&path, bytes).unwrap();
    recover_file(
        &path,
        None,
        &to_disk(&dir.join("out")),
        RecoverOptions::default(),
        &Quiet,
    )
    .unwrap()
}

fn outcome<'a>(rep: &'a RecoverReport, name: &str) -> &'a Outcome {
    &rep.entries
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("{name} not in report: {:?}", rep.entries))
        .outcome
}

fn recovered(rep: &RecoverReport, name: &str) -> bool {
    matches!(outcome(rep, name), Outcome::Recovered { .. })
}

fn text(n: usize, seed: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut s = seed;
    while v.len() < n {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        v.extend_from_slice(format!("line {} value {}\n", s >> 40, (s >> 20) & 0xFFF).as_bytes());
    }
    v.truncate(n);
    v
}

// ---------------------------------------------------------------------------------------
// zip

struct ZipFile<'a> {
    name: &'a str,
    data: Vec<u8>,
    deflate: bool,
    descriptor: bool,
}

/// A zip written by hand so the tests control descriptors and layout. Returns the bytes
/// and the offset of the central directory.
fn zip(files: &[ZipFile]) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for f in files {
        let crc = crc32fast::hash(&f.data);
        let body = if f.deflate {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
            e.write_all(&f.data).unwrap();
            e.finish().unwrap()
        } else {
            f.data.clone()
        };
        let method: u16 = if f.deflate { 8 } else { 0 };
        let flags: u16 = if f.descriptor { 8 } else { 0 };
        let at = out.len() as u32;
        let (hcrc, hp, hs) = if f.descriptor {
            (0, 0, 0)
        } else {
            (crc, body.len() as u32, f.data.len() as u32)
        };
        out.extend_from_slice(b"PK\x03\x04");
        out.extend_from_slice(&20u16.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&[0, 0x60, 0x21, 0x59]); // a DOS time and date
        out.extend_from_slice(&hcrc.to_le_bytes());
        out.extend_from_slice(&hp.to_le_bytes());
        out.extend_from_slice(&hs.to_le_bytes());
        out.extend_from_slice(&(f.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(f.name.as_bytes());
        out.extend_from_slice(&body);
        if f.descriptor {
            out.extend_from_slice(b"PK\x07\x08");
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        }
        central.extend_from_slice(b"PK\x01\x02");
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        central.extend_from_slice(&flags.to_le_bytes());
        central.extend_from_slice(&method.to_le_bytes());
        central.extend_from_slice(&[0, 0x60, 0x21, 0x59]);
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&(body.len() as u32).to_le_bytes());
        central.extend_from_slice(&(f.data.len() as u32).to_le_bytes());
        central.extend_from_slice(&(f.name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&at.to_le_bytes());
        central.extend_from_slice(f.name.as_bytes());
    }
    let cd = out.len();
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(files.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&(cd as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    (out, cd)
}

fn zip_files() -> Vec<ZipFile<'static>> {
    vec![
        ZipFile {
            name: "docs/a.txt",
            data: text(40_000, 1),
            deflate: true,
            descriptor: false,
        },
        ZipFile {
            name: "docs/b.bin",
            data: generate(30_000, 2),
            deflate: false,
            descriptor: true,
        },
        ZipFile {
            name: "c.txt",
            data: text(50_000, 3),
            deflate: true,
            descriptor: true,
        },
        ZipFile {
            name: "d.raw",
            data: generate(20_000, 4),
            deflate: false,
            descriptor: false,
        },
    ]
}

fn check_files(dir: &Path, files: &[ZipFile], names: &[&str]) {
    for f in files.iter().filter(|f| names.contains(&f.name)) {
        let got = fs::read(dir.join("out").join(f.name)).unwrap();
        assert!(got == f.data, "{} differs", f.name);
    }
}

#[test]
fn zip_zeroed_central_directory() {
    let dir = tmp("zip-zeroed-cd");
    let files = zip_files();
    let (mut bytes, cd) = zip(&files);
    // Zero the central directory and the end record.
    let len = bytes.len();
    bytes[cd..len].fill(0);
    let rep = run(&dir, "z.zip", &bytes);
    assert_eq!(rep.entries.len(), 4, "{:?}", rep.entries);
    for f in &files {
        assert_eq!(
            outcome(&rep, f.name),
            &Outcome::Recovered { verified: true },
            "{}",
            f.name
        );
    }
    check_files(
        &dir,
        &files,
        &["docs/a.txt", "docs/b.bin", "c.txt", "d.raw"],
    );
    assert!(
        rep.notes[0].contains("rebuilt the file list from 4 local headers"),
        "{:?}",
        rep.notes
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn zip_truncated_inside_last_entry() {
    let dir = tmp("zip-truncated");
    let files = zip_files();
    let (bytes, cd) = zip(&files);
    // Cut 5000 bytes into the stored last entry: everything after it (the central
    // directory) is gone.
    let d_start = cd - files[3].data.len();
    let cut = &bytes[..d_start + 5000];
    let rep = run(&dir, "z.zip", cut);
    for name in ["docs/a.txt", "docs/b.bin", "c.txt"] {
        assert!(recovered(&rep, name), "{name}: {:?}", outcome(&rep, name));
    }
    check_files(&dir, &files, &["docs/a.txt", "docs/b.bin", "c.txt"]);
    match outcome(&rep, "d.raw") {
        Outcome::Partial { bytes, kept, .. } => {
            assert_eq!(*bytes, 5000);
            assert!(kept);
        }
        o => panic!("d.raw: {o:?}"),
    }
    let got = fs::read(dir.join("out/d.raw")).unwrap();
    assert_eq!(&got[..], &files[3].data[..5000]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn zip_damaged_entry_without_central_directory() {
    let dir = tmp("zip-damaged-entry");
    let files = zip_files();
    let (mut bytes, cd) = zip(&files);
    bytes.truncate(cd);
    // Change bytes in the middle of the first entry's Deflate data.
    let a_start = 30 + files[0].name.len();
    for b in &mut bytes[a_start + 3000..a_start + 3008] {
        *b ^= 0x5A;
    }
    let rep = run(&dir, "z.zip", &bytes);
    assert!(!recovered(&rep, "docs/a.txt"), "{:?}", rep.entries);
    for name in ["docs/b.bin", "c.txt", "d.raw"] {
        assert!(recovered(&rep, name), "{name}: {:?}", outcome(&rep, name));
    }
    check_files(&dir, &files, &["docs/b.bin", "c.txt", "d.raw"]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn zip_intact_reports_no_damage() {
    let dir = tmp("zip-intact");
    let files = zip_files();
    let (bytes, _) = zip(&files);
    let rep = run(&dir, "z.zip", &bytes);
    assert!(rep.intact(), "{:?} {:?}", rep.notes, rep.entries);
    assert_eq!(rep.recovered(), 4);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// 7z

/// Files written to disk and archived as one solid 7z with 1 MiB LZMA2 blocks, so the
/// solid block has dictionary resets to restart from.
fn sevenz(dir: &Path, files: &[(String, Vec<u8>)], solid: bool) -> Vec<u8> {
    let src = dir.join("src");
    let mut items = Vec::new();
    for (name, data) in files {
        let p = src.join(name);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, data).unwrap();
        items.push(Item {
            src: p,
            name: name.clone(),
            is_dir: false,
            size: data.len() as u64,
            mtime: Some(133_000_000_000_000_000),
            ctime: None,
            atime: None,
            attrib: Some(0x20),
        });
    }
    let arc = dir.join("built.7z");
    let opts = CreateOptions {
        level: 3,
        method: MainMethod::Lzma2,
        block_size: Some(1 << 20),
        threads: 4,
        solid_limit: if solid { Some(1 << 40) } else { None },
        ..Default::default()
    };
    create(&arc, &items, &opts, &NoProgress).unwrap();
    let _ = fs::remove_dir_all(&src);
    fs::read(&arc).unwrap()
}

fn many_files(n: usize, size: usize) -> Vec<(String, Vec<u8>)> {
    (0..n)
        .map(|i| (format!("f{i:02}.txt"), text(size, 100 + i as u64)))
        .collect()
}

#[test]
fn sevenz_damage_in_solid_block_resumes_after_it() {
    let dir = tmp("7z-solid");
    let files = many_files(14, 300_000);
    let mut bytes = sevenz(&dir, &files, true);
    let af = ArchiveFile::from_slice(r7z::format::Slice::from_vec(bytes.clone()), None).unwrap();
    assert_eq!(af.archive.streams.folders.len(), 1);
    let pack = af.folder_packs(0).unwrap()[0];
    let restarts = lzma2scan::restart_points(pack);
    assert!(restarts.len() >= 3, "{restarts:?}");
    // Damage the middle of the second LZMA2 block.
    let (p1, u1) = restarts[0];
    let (p2, u2) = restarts[1];
    let at = 32 + (p1 + (p2 - p1) / 2) as usize;
    for b in &mut bytes[at..at + 16] {
        *b = !*b;
    }
    let rep = run(&dir, "solid.7z", &bytes);
    // Files decoded in archive order; their offsets in the solid stream.
    let order: Vec<&str> = af.archive.folder_entries[0]
        .iter()
        .map(|&i| af.archive.entries[i].name.as_str())
        .collect();
    let mut pos = 0u64;
    let mut lost_inside = 0;
    for name in order {
        let size = files.iter().find(|f| f.0 == name).unwrap().1.len() as u64;
        let (start, end) = (pos, pos + size);
        pos = end;
        if end <= u1 || start >= u2 {
            assert!(
                recovered(&rep, name),
                "{name} [{start},{end}): {:?}",
                outcome(&rep, name)
            );
            let got = fs::read(dir.join("out").join(name)).unwrap();
            assert!(
                got == files.iter().find(|f| f.0 == name).unwrap().1,
                "{name}"
            );
        } else if !recovered(&rep, name) {
            lost_inside += 1;
        }
    }
    assert!(lost_inside >= 1, "{:?}", rep.entries);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn sevenz_zeroed_start_header() {
    let dir = tmp("7z-start-header");
    let files = many_files(5, 50_000);
    let mut bytes = sevenz(&dir, &files, true);
    // An interrupted write leaves the start header zeroed; the signature is gone too.
    bytes[..32].fill(0);
    let rep = run(&dir, "nostart.7z", &bytes);
    assert_eq!(rep.recovered(), 5, "{:?} {:?}", rep.notes, rep.entries);
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("found the archive header by scanning")),
        "{:?}",
        rep.notes
    );
    for (name, data) in &files {
        assert!(
            fs::read(dir.join("out").join(name)).unwrap() == *data,
            "{name}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn sevenz_truncated_header_lost() {
    let dir = tmp("7z-truncated");
    let data = text(3_000_000, 9);
    let files = vec![("disk.img".to_string(), data.clone())];
    let bytes = sevenz(&dir, &files, true);
    // Cut half way through the packed data: the header at the end is gone.
    let cut = &bytes[..bytes.len() / 2];
    let rep = run(&dir, "disk.img.7z", cut);
    assert_eq!(rep.entries.len(), 1, "{:?}", rep.entries);
    assert_eq!(rep.entries[0].name, "disk.img");
    assert!(rep.notes[0].contains("header is lost"), "{:?}", rep.notes);
    let got =
        fs::read(dir.join("out/disk.img")).unwrap_or_else(|e| panic!("{e}: {:?}", rep.entries));
    assert!(got.len() > 500_000, "only {} bytes", got.len());
    assert!(
        data.starts_with(&got),
        "recovered bytes are not a prefix of the original"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn sevenz_non_solid_damage_stays_in_one_file() {
    let dir = tmp("7z-non-solid");
    let files = many_files(4, 80_000);
    let mut bytes = sevenz(&dir, &files, false);
    let af = ArchiveFile::from_slice(r7z::format::Slice::from_vec(bytes.clone()), None).unwrap();
    assert_eq!(af.archive.streams.folders.len(), 4);
    let victim = af.archive.folder_entries[1][0];
    let victim_name = af.archive.entries[victim].name.clone();
    let off = af.archive.pack_offsets[af.archive.folder_first_pack[1]] as usize + 500;
    for b in &mut bytes[off..off + 8] {
        *b = !*b;
    }
    let rep = run(&dir, "ns.7z", &bytes);
    assert!(!recovered(&rep, &victim_name), "{:?}", rep.entries);
    for (name, data) in files.iter().filter(|f| f.0 != victim_name) {
        assert!(recovered(&rep, name), "{name}: {:?}", outcome(&rep, name));
        assert!(
            fs::read(dir.join("out").join(name)).unwrap() == *data,
            "{name}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------------------
// tar and single-stream compressors

fn tar_header(name: &str, size: usize) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..108].copy_from_slice(b"0000644\0");
    h[108..116].copy_from_slice(b"0000000\0");
    h[116..124].copy_from_slice(b"0000000\0");
    h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    h[136..148].copy_from_slice(b"14000000000\0");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].fill(b' ');
    let sum: u32 = h.iter().map(|&b| b as u32).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

fn tar(files: &[(&str, Vec<u8>)]) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::new();
    let mut at = Vec::new();
    for (name, data) in files {
        at.push(out.len());
        out.extend_from_slice(&tar_header(name, data.len()));
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.extend_from_slice(&[0; 1024]);
    (out, at)
}

fn tar_files() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("one.txt", text(10_000, 21)),
        ("two.txt", text(20_000, 22)),
        ("three.txt", text(30_000, 23)),
        ("four.txt", text(40_000, 24)),
    ]
}

#[test]
fn tar_resumes_at_next_header() {
    let dir = tmp("tar-header");
    let files = tar_files();
    let (mut bytes, at) = tar(&files);
    bytes[at[1]..at[1] + 512].fill(0x41);
    let rep = run(&dir, "t.tar", &bytes);
    let names: Vec<&str> = rep.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, ["one.txt", "three.txt", "four.txt"]);
    assert_eq!(rep.recovered(), 3);
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains(&format!("header at offset {}", at[1]))),
        "{:?}",
        rep.notes
    );
    for (name, data) in files.iter().filter(|f| f.0 != "two.txt") {
        assert!(
            fs::read(dir.join("out").join(name)).unwrap() == *data,
            "{name}"
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn truncated_tar_gz_keeps_what_decoded() {
    let dir = tmp("tgz");
    let files = tar_files();
    let (bytes, at) = tar(&files);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
    gz.write_all(&bytes).unwrap();
    let gz = gz.finish().unwrap();
    // Find a cut that lands inside the third file's data once decompressed.
    let third = (at[2] + 512) as u64..(at[2] + 512 + files[2].1.len()) as u64;
    let mut cut = gz.len() / 2;
    let decoded_len = |n: usize| {
        let mut d = flate2::read::GzDecoder::new(&gz[..n]);
        let mut out = Vec::new();
        let _ = std::io::Read::read_to_end(&mut d, &mut out);
        out.len() as u64
    };
    while !third.contains(&decoded_len(cut)) {
        cut = if decoded_len(cut) < third.start {
            cut + 64
        } else {
            cut - 64
        };
    }
    let rep = run(&dir, "t.tar.gz", &gz[..cut]);
    assert!(recovered(&rep, "one.txt"));
    assert!(recovered(&rep, "two.txt"));
    match outcome(&rep, "three.txt") {
        Outcome::Partial {
            bytes, kept: true, ..
        } => assert!(*bytes > 0),
        o => panic!("three.txt: {o:?}"),
    }
    assert!(rep.entries.iter().all(|e| e.name != "four.txt"));
    assert!(
        rep.notes
            .iter()
            .any(|n| n.contains("decoding stopped after")),
        "{:?}",
        rep.notes
    );
    let got = fs::read(dir.join("out/three.txt")).unwrap();
    assert!(files[2].1.starts_with(&got));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn truncated_bzip2_keeps_decoded_prefix() {
    let dir = tmp("bz2");
    let data = generate(3 << 20, 5);
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(1));
    e.write_all(&data).unwrap();
    let bz = e.finish().unwrap();
    let rep = run(&dir, "blob.bin.bz2", &bz[..bz.len() * 2 / 3]);
    match outcome(&rep, "blob.bin") {
        Outcome::Partial {
            bytes, kept: true, ..
        } => assert!(*bytes >= 1 << 20, "{bytes}"),
        o => panic!("{o:?}"),
    }
    let got = fs::read(dir.join("out/blob.bin")).unwrap();
    assert!(data.starts_with(&got));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn partial_files_can_be_dropped() {
    let dir = tmp("drop-partial");
    let files = zip_files();
    let (bytes, cd) = zip(&files);
    let cut = &bytes[..cd - 1000];
    let path = dir.join("z.zip");
    fs::write(&path, cut).unwrap();
    let rep = recover_file(
        &path,
        None,
        &to_disk(&dir.join("out")),
        RecoverOptions {
            keep_partial: false,
        },
        &Quiet,
    )
    .unwrap();
    assert!(matches!(
        outcome(&rep, "d.raw"),
        Outcome::Partial { kept: false, .. }
    ));
    assert!(!dir.join("out/d.raw").exists());
    assert!(recovered(&rep, "c.txt"));
    let _ = fs::remove_dir_all(&dir);
}
