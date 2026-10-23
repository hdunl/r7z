//! PE resource trees and self-extracting archives, against small PE and zip images that
//! these tests write. The PE writer lays out a `.rsrc` section the way the linker does (one
//! directory per level, string names, data entries pointing at their bytes), so the reader
//! sees the same structures a real executable has.

use std::collections::BTreeMap;

use r7z::format::{self, find_format, Archive, Ctx, Flow, OpenRequest, Opened};
use r7z::Error;

/// A resource directory entry's name.
#[derive(Clone)]
enum Name {
    Id(u32),
    Str(&'static str),
}

/// A resource tree node: a directory, or the bytes of a data entry.
enum Res {
    Dir(Vec<(Name, Res)>),
    Data(Vec<u8>),
}

/// Lays out resource directories, names and data after the section's base RVA.
struct Emitter {
    buf: Vec<u8>,
    base_rva: u32,
}

impl Emitter {
    fn put_u16(&mut self, at: usize, v: u16) {
        self.buf[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    /// Emits a directory and everything below it; returns its offset in the section.
    fn dir(&mut self, entries: &[(Name, Res)]) -> usize {
        let at = self.buf.len();
        self.buf.resize(at + 16 + 8 * entries.len(), 0);
        let named = entries
            .iter()
            .filter(|(n, _)| matches!(n, Name::Str(_)))
            .count();
        self.put_u16(at + 12, named as u16);
        self.put_u16(at + 14, (entries.len() - named) as u16);
        for (k, (name, child)) in entries.iter().enumerate() {
            let name_field = match name {
                Name::Id(id) => *id,
                Name::Str(s) => {
                    let off = self.buf.len();
                    let units: Vec<u16> = s.encode_utf16().collect();
                    self.buf
                        .extend_from_slice(&(units.len() as u16).to_le_bytes());
                    for u in units {
                        self.buf.extend_from_slice(&u.to_le_bytes());
                    }
                    0x8000_0000 | off as u32
                }
            };
            let target = match child {
                Res::Dir(sub) => 0x8000_0000 | self.dir(sub) as u32,
                Res::Data(bytes) => {
                    let entry = self.buf.len();
                    self.buf.resize(entry + 16, 0);
                    while !self.buf.len().is_multiple_of(8) {
                        self.buf.push(0);
                    }
                    let data = self.buf.len();
                    self.buf.extend_from_slice(bytes);
                    self.put_u32(entry, self.base_rva + data as u32);
                    self.put_u32(entry + 4, bytes.len() as u32);
                    entry as u32
                }
            };
            self.put_u32(at + 16 + 8 * k, name_field);
            self.put_u32(at + 20 + 8 * k, target);
        }
        at
    }
}

/// The `.rsrc` section bytes for a resource tree rooted at `root`.
fn rsrc(root: &[(Name, Res)], base_rva: u32) -> Vec<u8> {
    let mut e = Emitter {
        buf: Vec::new(),
        base_rva,
    };
    e.dir(root);
    e.buf
}

fn put16(d: &mut [u8], at: usize, v: u16) {
    d[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(d: &mut [u8], at: usize, v: u32) {
    d[at..at + 4].copy_from_slice(&v.to_le_bytes());
}

/// A PE32+ image: one `.text` section, plus a `.rsrc` section when `resources` is given,
/// and `overlay` appended after the section data.
fn pe_image(resources: Option<Vec<(Name, Res)>>, overlay: &[u8]) -> Vec<u8> {
    const HEADERS: usize = 0x400;
    let rsrc_data = resources.map(|r| rsrc(&r, 0x2000));
    let mut d = vec![0u8; HEADERS];
    d[0..2].copy_from_slice(b"MZ");
    put32(&mut d, 0x3c, 0x80);
    d[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    let sections = if rsrc_data.is_some() { 2 } else { 1 };
    put16(&mut d, coff, 0x8664);
    put16(&mut d, coff + 2, sections);
    put16(&mut d, coff + 16, 240);
    put16(&mut d, coff + 18, 0x0022);
    let opt = coff + 20;
    put16(&mut d, opt, 0x20b);
    put32(&mut d, opt + 16, 0x1000);
    put32(&mut d, opt + 32, 0x1000);
    put32(&mut d, opt + 36, 0x200);
    put32(&mut d, opt + 56, 0x4000);
    put32(&mut d, opt + 60, HEADERS as u32);
    put32(&mut d, opt + 108, 16);
    let table = opt + 240;
    let section_data: Vec<u8> = vec![0x90; 0x200];
    let write_section = |d: &mut Vec<u8>, slot: usize, name: &[u8], va: u32, body: &[u8]| {
        let raw_at = d.len();
        let raw_size = body.len().div_ceil(0x200) * 0x200;
        let h = table + 40 * slot;
        d[h..h + name.len()].copy_from_slice(name);
        put32(d, h + 8, body.len() as u32);
        put32(d, h + 12, va);
        put32(d, h + 16, raw_size as u32);
        put32(d, h + 20, raw_at as u32);
        put32(d, h + 36, 0x4000_0040);
        d.extend_from_slice(body);
        d.resize(raw_at + raw_size, 0);
    };
    write_section(&mut d, 0, b".text", 0x1000, &section_data);
    if let Some(r) = &rsrc_data {
        write_section(&mut d, 1, b".rsrc", 0x2000, r);
        // Data directory 2 is the resource table.
        let dirs = opt + 112;
        put32(&mut d, dirs + 16, 0x2000);
        put32(&mut d, dirs + 20, r.len() as u32);
    }
    d.extend_from_slice(overlay);
    d
}

/// A VS_VERSIONINFO-style block: the key, an optional value, and child blocks.
fn block(key: &str, text: bool, value: &[u8], children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; 6];
    let mut value_words = value.len();
    b[4..6].copy_from_slice(&(text as u16).to_le_bytes());
    for u in key.encode_utf16().chain(std::iter::once(0)) {
        b.extend_from_slice(&u.to_le_bytes());
    }
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b.extend_from_slice(value);
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    for c in children {
        b.extend_from_slice(c);
    }
    if text {
        value_words = value.len() / 2;
    }
    let len = b.len() as u16;
    b[0..2].copy_from_slice(&len.to_le_bytes());
    b[2..4].copy_from_slice(&(value_words as u16).to_le_bytes());
    b
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn version_resource() -> Vec<u8> {
    let mut fixed = vec![0u8; 52];
    fixed[0..4].copy_from_slice(&0xFEEF_04BDu32.to_le_bytes());
    fixed[8..12].copy_from_slice(&0x0001_0002u32.to_le_bytes());
    fixed[12..16].copy_from_slice(&0x0003_0004u32.to_le_bytes());
    fixed[16..20].copy_from_slice(&0x0005_0006u32.to_le_bytes());
    fixed[20..24].copy_from_slice(&0x0007_0008u32.to_le_bytes());
    let company = block("CompanyName", true, &utf16z("Example Corp"), &[]);
    let table = block("040904b0", false, &[], &[company]);
    let info = block("StringFileInfo", false, &[], &[table]);
    block("VS_VERSION_INFO", false, &fixed, &[info])
}

fn icon_group() -> Vec<u8> {
    let mut g = vec![0, 0, 1, 0, 2, 0];
    // width, height, colors, reserved, planes, bit count, size, ID.
    g.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0, 6, 0, 0, 0, 1, 0]);
    g.extend_from_slice(&[32, 32, 0, 0, 1, 0, 32, 0, 7, 0, 0, 0, 2, 0]);
    g
}

fn ico_bytes() -> Vec<u8> {
    let mut v = vec![0, 0, 1, 0, 2, 0];
    v.extend_from_slice(&[16, 16, 0, 0, 1, 0, 32, 0, 6, 0, 0, 0, 0x26, 0, 0, 0]);
    v.extend_from_slice(&[32, 32, 0, 0, 1, 0, 32, 0, 7, 0, 0, 0, 0x2c, 0, 0, 0]);
    v.extend_from_slice(b"ICON-A");
    v.extend_from_slice(b"ICON-BB");
    v
}

const MANIFEST: &[u8] = b"<?xml version=\"1.0\"?><assembly/>";

fn sample_resources() -> Vec<(Name, Res)> {
    vec![
        (
            Name::Id(3),
            Res::Dir(vec![
                (
                    Name::Id(1),
                    Res::Dir(vec![(Name::Id(1033), Res::Data(b"ICON-A".to_vec()))]),
                ),
                (
                    Name::Id(2),
                    Res::Dir(vec![(Name::Id(1033), Res::Data(b"ICON-BB".to_vec()))]),
                ),
            ]),
        ),
        (
            Name::Id(14),
            Res::Dir(vec![(
                Name::Id(1),
                Res::Dir(vec![(Name::Id(1033), Res::Data(icon_group()))]),
            )]),
        ),
        (
            Name::Id(16),
            Res::Dir(vec![(
                Name::Id(1),
                Res::Dir(vec![(Name::Id(1033), Res::Data(version_resource()))]),
            )]),
        ),
        (
            Name::Id(24),
            Res::Dir(vec![(
                Name::Id(1),
                Res::Dir(vec![(Name::Id(1033), Res::Data(MANIFEST.to_vec()))]),
            )]),
        ),
        (
            Name::Id(10),
            Res::Dir(vec![(
                Name::Str("CUSTOM"),
                Res::Dir(vec![(Name::Id(1033), Res::Data(vec![1, 2, 3]))]),
            )]),
        ),
    ]
}

fn pe_forced() -> OpenRequest {
    OpenRequest {
        format: find_format("PE"),
        ..Default::default()
    }
}

fn open_pe(data: Vec<u8>, name: &str) -> r7z::Result<Opened> {
    format::open_bytes(data, name, &pe_forced())
}

/// Every file's bytes, by name, decoded unit by unit.
fn contents(a: &dyn Archive) -> r7z::Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for u in 0..a.units().len() {
        a.extract_unit(u, &Ctx::default(), &mut |i, r| {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(Error::from)?;
            out.insert(a.entries()[i].name.clone(), v);
            Ok(Flow::Continue)
        })?;
    }
    Ok(out)
}

#[test]
fn resource_tree_lists_folders_and_converted_resources() {
    let o = open_pe(pe_image(Some(sample_resources()), &[]), "app.exe").unwrap();
    let a = o.archive();
    assert_eq!(a.format().name, "PE");
    let names: Vec<&str> = a.entries().iter().map(|e| e.name.as_str()).collect();
    for dir in [
        "RT_GROUP_ICON",
        "RT_GROUP_ICON/1",
        "RT_MANIFEST/1",
        "RT_RCDATA/CUSTOM",
    ] {
        assert!(names.contains(&dir), "missing folder {dir}: {names:?}");
    }
    // Icon images are part of the group's .ico, so they are not listed on their own.
    assert!(!names.iter().any(|n| n.starts_with("RT_ICON")), "{names:?}");
    let got = contents(a).unwrap();
    assert_eq!(got["RT_GROUP_ICON/1/1033.ico"], ico_bytes());
    assert_eq!(got["RT_MANIFEST/1/1033.manifest"], MANIFEST);
    assert_eq!(got["RT_RCDATA/CUSTOM/1033.bin"], vec![1, 2, 3]);
    assert_eq!(
        String::from_utf8(got["RT_VERSION/1/1033.txt"].clone()).unwrap(),
        "FileVersion=1.2.3.4\nProductVersion=5.6.7.8\nCompanyName=Example Corp\n"
    );
    let e = a
        .entries()
        .iter()
        .find(|e| e.name == "RT_GROUP_ICON/1/1033.ico")
        .unwrap();
    assert_eq!(e.size, Some(ico_bytes().len() as u64));
}

#[test]
fn an_executable_without_resources_lists_nothing() {
    let o = open_pe(pe_image(None, &[]), "plain.exe").unwrap();
    assert!(o.archive().entries().is_empty());
}

#[test]
fn a_plain_executable_is_not_detected_as_an_archive() {
    let data = pe_image(Some(sample_resources()), &[]);
    let r = format::open_bytes(data, "app.exe", &OpenRequest::default());
    assert!(matches!(r, Err(Error::NotArchive)));
}

#[test]
fn not_a_pe_file_is_refused() {
    let r = open_pe(b"MZ this is not a PE file".to_vec(), "x.exe").map(|_| ());
    assert!(
        matches!(r, Err(Error::NotArchive | Error::Corrupt(_))),
        "{r:?}"
    );
}

/// A stored (uncompressed) zip with one file.
fn stored_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let crc = crc32fast::hash(data);
    let n = name.len() as u16;
    let mut z = Vec::new();
    z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    z.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&n.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z.extend_from_slice(name.as_bytes());
    z.extend_from_slice(data);
    let cd = z.len() as u32;
    z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    z.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    z.extend_from_slice(&crc.to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&(data.len() as u32).to_le_bytes());
    z.extend_from_slice(&n.to_le_bytes());
    // Extra and comment lengths, disk, attributes and the local header offset.
    z.extend_from_slice(&[0; 16]);
    z.extend_from_slice(name.as_bytes());
    let cd_size = z.len() as u32 - cd;
    z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    z.extend_from_slice(&[0, 0, 0, 0, 1, 0, 1, 0]);
    z.extend_from_slice(&cd_size.to_le_bytes());
    z.extend_from_slice(&cd.to_le_bytes());
    z.extend_from_slice(&[0, 0]);
    z
}

fn sfx_file() -> Vec<u8> {
    pe_image(None, &stored_zip("hello.txt", b"hello"))
}

#[test]
fn self_extractor_opens_as_the_archive_inside() {
    let o = format::open_bytes(sfx_file(), "setup.exe", &OpenRequest::default()).unwrap();
    let a = o.archive();
    assert_eq!(a.format().name, "zip");
    assert_eq!(contents(a).unwrap()["hello.txt"], b"hello");
}

#[test]
fn an_executable_with_an_unknown_overlay_is_not_an_archive() {
    let data = pe_image(None, b"not an archive, just appended bytes");
    let r = format::open_bytes(data, "tool.exe", &OpenRequest::default());
    assert!(matches!(r, Err(Error::NotArchive)));
}

#[test]
fn forced_pe_lists_a_self_extractor_as_an_empty_resource_tree() {
    let o = open_pe(sfx_file(), "setup.exe").unwrap();
    assert!(o.archive().entries().is_empty());
}

/// Writes the fixtures under tests/fixtures/pe/ (run with `--ignored`).
#[test]
#[ignore]
fn write_fixtures() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pe");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("resources.exe"),
        pe_image(Some(sample_resources()), &[]),
    )
    .unwrap();
    std::fs::write(dir.join("sfx-zip.exe"), sfx_file()).unwrap();
}

/// Every damaged input must open or fail without a panic, and listing and extraction must
/// not panic either.
fn try_damaged(data: Vec<u8>, name: &str) {
    if let Ok(o) = format::open_bytes(data.clone(), name, &pe_forced()) {
        let _ = contents(o.archive());
    }
    if let Ok(o) = format::open_bytes(data, name, &OpenRequest::default()) {
        let _ = contents(o.archive());
    }
}

#[test]
fn truncated_images_fail_without_panicking() {
    for (name, data) in [
        ("app.exe", pe_image(Some(sample_resources()), &[])),
        ("setup.exe", sfx_file()),
    ] {
        for len in 0..data.len() {
            try_damaged(data[..len].to_vec(), name);
        }
    }
}

#[test]
fn bit_flips_never_panic() {
    for (name, data) in [
        ("app.exe", pe_image(Some(sample_resources()), &[])),
        ("setup.exe", sfx_file()),
    ] {
        for i in 0..data.len() {
            for bit in [0x01, 0x80] {
                let mut d = data.clone();
                d[i] ^= bit;
                try_damaged(d, name);
            }
        }
    }
}
