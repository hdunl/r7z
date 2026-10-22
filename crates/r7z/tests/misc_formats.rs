//! cpio, ar, rpm and xar readers against fixtures made by bsdtar 3.8.9 (and small
//! hand-built archives for variants it cannot write), whose listings and extracted bytes
//! were checked against 7-Zip 25.01.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use r7z::format::data::BoxRead;
use r7z::format::{self, Archive, Ctx, Flow, Input, Link, OpenOptions, OpenRequest, Opened};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};
use r7z::Error;

struct Quiet;
impl Callbacks for Quiet {}

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(rel)
}

fn open(rel: &str) -> Opened {
    format::open(&fixture(rel), &OpenRequest::default()).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn names(a: &dyn Archive) -> Vec<&str> {
    a.entries().iter().map(|e| e.name.as_str()).collect()
}

fn entry<'a>(a: &'a dyn Archive, name: &str) -> &'a format::Entry {
    a.entries()
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no entry {name}"))
}

fn prop(a: &dyn Archive, key: &str) -> Option<String> {
    a.properties()
        .into_iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// Decodes every unit through the handler contract.
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

fn test_archive(a: &dyn Archive) -> r7z::Result<usize> {
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 1,
        target: Target::Test,
        selected: None,
    };
    let rep = extract(a, &opts, &Quiet)?;
    match rep.errors.into_iter().next() {
        Some((_, e)) => Err(e),
        None => Ok(rep.files as usize),
    }
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-misc-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    d
}

fn extract_to(a: &dyn Archive, dir: &Path) {
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 4,
        target: Target::Disk {
            dir: dir.to_path_buf(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    let rep = extract(a, &opts, &Quiet).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
}

fn data_bin() -> Vec<u8> {
    (0..3000u32)
        .map(|i| ((i * i + 7 * i) % 256) as u8)
        .collect()
}

const HELLO: &[u8] = b"hello world\n";

// ---------------------------------------------------------------- cpio

const CPIO_NAMES: &[&str] = &[
    "hello.txt",
    "hard.txt",
    "link.txt",
    "dir",
    "dir/data.bin",
    "dir/empty",
    "dir/sub",
    "dir/sub/deep.txt",
];

fn check_cpio_tree(dir: &Path) {
    assert_eq!(fs::read(dir.join("hello.txt")).unwrap(), HELLO);
    assert_eq!(fs::read(dir.join("hard.txt")).unwrap(), HELLO);
    // A symlink reads its target where links can be made; elsewhere it is the file holding
    // the target's name.
    let link = fs::read(dir.join("link.txt")).unwrap();
    assert!(link == HELLO || link == b"hello.txt", "{link:?}");
    assert_eq!(fs::read(dir.join("dir/data.bin")).unwrap(), data_bin());
    assert_eq!(fs::read(dir.join("dir/empty")).unwrap(), b"");
    assert_eq!(fs::read(dir.join("dir/sub/deep.txt")).unwrap(), b"deep\n");
}

#[test]
fn cpio_variants() {
    for (file, sub_type, padded) in [
        ("newc.cpio", "New ASCII", 4),
        ("crc.cpio", "New CRC", 4),
        ("odc.cpio", "Portable ASCII", 1),
        ("bin_le.cpio", "Binary LE", 2),
        ("bin_be.cpio", "Binary BE", 2),
    ] {
        let o = open(&format!("cpio/{file}"));
        let a = o.archive();
        assert_eq!(a.format().name, "Cpio");
        assert_eq!(names(a), CPIO_NAMES, "{file}");
        assert_eq!(prop(a, "SubType").as_deref(), Some(sub_type), "{file}");
        let len = fs::metadata(fixture(&format!("cpio/{file}")))
            .unwrap()
            .len();
        assert_eq!(prop(a, "Physical Size"), Some(len.to_string()), "{file}");

        let link = entry(a, "link.txt");
        assert_eq!(
            link.link,
            Some(Link::Symbolic("hello.txt".into())),
            "{file}"
        );
        assert_eq!(link.size, Some(9));
        assert_eq!(link.packed_size, Some(9u64.next_multiple_of(padded)));
        let dir = entry(a, "dir");
        assert!(dir.is_dir);
        assert_eq!(dir.attrib.unwrap() & 0x10, 0x10);
        assert_eq!((dir.attrib.unwrap() >> 16) & 0o170000, 0o040000);
        let data = entry(a, "dir/data.bin");
        assert_eq!(data.size, Some(3000));
        // 2024-01-02 03:04:05 UTC.
        assert_eq!(
            data.mtime,
            Some((1_704_164_645 + 11_644_473_600) * 10_000_000)
        );

        // New ASCII hard links: the last member carries the data.
        let hello = entry(a, "hello.txt");
        if padded == 4 {
            assert_eq!(hello.link, Some(Link::Hard("hard.txt".into())), "{file}");
            assert_eq!(hello.size, Some(12));
            assert_eq!(hello.packed_size, Some(0));
        } else {
            assert_eq!(hello.link, None, "{file}");
        }

        let c = contents(a).unwrap();
        assert_eq!(c["hard.txt"], HELLO);
        assert_eq!(c["link.txt"], b"hello.txt");
        assert_eq!(c["dir/data.bin"], data_bin());
        assert_eq!(test_archive(a).unwrap(), 6, "{file}");

        let out = tmp(file);
        extract_to(a, &out);
        check_cpio_tree(&out);
        let _ = fs::remove_dir_all(&out);
    }
}

fn gunzip(path: &Path) -> Vec<u8> {
    let mut v = Vec::new();
    flate2::read::GzDecoder::new(fs::File::open(path).unwrap())
        .read_to_end(&mut v)
        .unwrap();
    v
}

#[test]
fn cpio_from_a_sequential_stream() {
    let gz = fixture("cpio/newc.cpio.gz");
    let opener: format::Opener = Arc::new(move || {
        let f = fs::File::open(&gz)?;
        Ok(Box::new(flate2::read::GzDecoder::new(f)) as BoxRead)
    });
    let input = Input::Stream {
        open: opener,
        size_hint: None,
    };
    let a = (format::cpio::FORMAT.open)(input, &OpenOptions::default()).unwrap();
    assert_eq!(names(&*a), CPIO_NAMES);
    assert_eq!(
        entry(&*a, "link.txt").link,
        Some(Link::Symbolic("hello.txt".into()))
    );
    let c = contents(&*a).unwrap();
    assert_eq!(c["dir/data.bin"], data_bin());
    assert_eq!(c["dir/sub/deep.txt"], b"deep\n");
    let out = tmp("cpio-stream");
    extract_to(&*a, &out);
    check_cpio_tree(&out);
    let _ = fs::remove_dir_all(&out);

    // The same bytes in memory list identically.
    let plain = format::open_bytes(
        gunzip(&fixture("cpio/newc.cpio.gz")),
        "x.cpio",
        &OpenRequest::default(),
    )
    .unwrap();
    assert_eq!(names(plain.archive()), CPIO_NAMES);
}

#[test]
fn cpio_crc_checksum_is_verified() {
    let mut data = fs::read(fixture("cpio/crc.cpio")).unwrap();
    let at = data.windows(5).position(|w| w == b"deep\n").unwrap();
    data[at] ^= 0x20;
    let o = format::open_bytes(data, "crc.cpio", &OpenRequest::default()).unwrap();
    assert!(matches!(test_archive(o.archive()), Err(Error::Checksum(_))));
}

// ---------------------------------------------------------------- ar

#[test]
fn ar_bsd_long_names() {
    let o = open("ar/bsd.ar");
    let a = o.archive();
    assert_eq!(a.format().name, "Ar");
    assert_eq!(
        names(a),
        [
            "hello.txt",
            "a_very_long_member_name_here.txt",
            "with space.txt",
            "data.bin"
        ]
    );
    assert_eq!(prop(a, "SubType").as_deref(), Some("ar:BSD"));
    let c = contents(a).unwrap();
    assert_eq!(c["hello.txt"], HELLO);
    assert_eq!(c["a_very_long_member_name_here.txt"], b"long one\n");
    assert_eq!(c["with space.txt"], b"sp\n");
    assert_eq!(c["data.bin"], data_bin());
    let e = entry(a, "data.bin");
    assert_eq!(e.mtime, Some((1_704_164_645 + 11_644_473_600) * 10_000_000));
    assert_eq!(e.attrib, Some(0x8000 | (0o100666 << 16)));
}

// ---------------------------------------------------------------- generated ar archives
//
// These archives are built here instead of being checked in as binaries, so every byte of
// them can be read and reviewed. They follow what GNU ar, BSD ar and Microsoft's lib.exe
// write (symbol tables, long-name tables, member headers), with short text standing in for
// object code.

const AR_MTIME: &str = "1704164645";

/// One member: the 60-byte header, then the data, padded to an even length.
fn ar_member(name: &str, mtime: &str, owner: &str, mode: &str, data: &[u8]) -> Vec<u8> {
    let mut m = format!(
        "{name:<16}{mtime:<12}{owner:<6}{owner:<6}{mode:<8}{:<10}`\n",
        data.len()
    )
    .into_bytes();
    m.extend_from_slice(data);
    if data.len() % 2 == 1 {
        m.push(b'\n');
    }
    m
}

fn ar(members: &[Vec<u8>]) -> Vec<u8> {
    [b"!<arch>\n".to_vec(), members.concat()].concat()
}

fn file_member(name: &str, data: &[u8]) -> Vec<u8> {
    ar_member(name, AR_MTIME, "0", "100644", data)
}

/// Big-endian symbol counts and member offsets (GNU and the first lib.exe linker member),
/// followed by the NUL-terminated names.
fn be_symbol_table(width: usize, offsets: &[u64], names: &[&str]) -> Vec<u8> {
    let be = |v: u64| v.to_be_bytes()[8 - width..].to_vec();
    let mut t = be(offsets.len() as u64);
    for &o in offsets {
        t.extend(be(o));
    }
    for n in names {
        t.extend_from_slice(n.as_bytes());
        t.push(0);
    }
    t
}

/// The members GNU ar writes after its symbol table: a long-name table ("//"), a short
/// name, a long name ("/0"), the same short name twice, and another long name ("/29").
fn gnu_members() -> Vec<Vec<u8>> {
    vec![
        ar_member(
            "//",
            "",
            "",
            "",
            b"a_rather_long_member_name.o/\nanother_very_long_name.txt/\n",
        ),
        file_member("short.o/", b"OBJ1OBJ1OBJ1"),
        file_member("/0", b"long data\n"),
        file_member("dup.txt/", b"first\n"),
        file_member("dup.txt/", b"second\n"),
        file_member("/29", &[b'x'; 33]),
    ]
}

/// GNU ar with a 32-bit symbol table ("/").
fn gnu_a() -> Vec<u8> {
    let symbols = be_symbol_table(4, &[0xE0, 0x128, 0x1F4], &["func_a", "func_b", "data_c"]);
    let mut m = vec![ar_member("/", "0", "0", "0", &symbols)];
    m.extend(gnu_members());
    ar(&m)
}

/// GNU ar with a 64-bit symbol table ("/SYM64/").
fn gnu64_a() -> Vec<u8> {
    let symbols = be_symbol_table(8, &[0xF0, 0x138, 0x204], &["func_a", "func_b", "data_c"]);
    let mut m = vec![ar_member("/SYM64/", "0", "0", "0", &symbols)];
    m.extend(gnu_members());
    ar(&m)
}

/// BSD ar: names longer than 16 bytes or containing spaces are stored as "#1/<len>" with
/// the name at the start of the data, and the symbol table is "__.SYMDEF" (little-endian
/// ranlib entries of string index and member offset, then the string table).
fn bsd_symdef_a() -> Vec<u8> {
    let le = |v: u32| v.to_le_bytes();
    let mut symdef = b"__.SYMDEF\0\0\0".to_vec();
    symdef.extend(le(16));
    for (strx, offset) in [(0, 0x70), (4, 0xB8)] {
        symdef.extend(le(strx));
        symdef.extend(le(offset));
    }
    symdef.extend(le(8));
    symdef.extend_from_slice(b"_f1\0_g2\0");
    ar(&[
        file_member("#1/12", &symdef),
        file_member("short.o", b"OBJ1OBJ1OBJ1"),
        file_member("#1/28", b"a_rather_long_member_name.o\0long data\n"),
        file_member("odd", b"abc"),
    ])
}

/// A Microsoft import library: two linker members (big-endian then little-endian with
/// sorted names), a long-name table, three import members named after the DLL, and an
/// object with a long name ("/0").
fn demo_lib() -> Vec<u8> {
    let first = be_symbol_table(
        4,
        &[0x1B0, 0x214, 0x214, 0x27E, 0x27E, 0x2DC],
        &[
            "__IMPORT_DESCRIPTOR_demo",
            "__imp_DemoFunc",
            "DemoFunc",
            "__imp_Other",
            "Other",
            "LongSym",
        ],
    );
    let mut second = Vec::new();
    second.extend(4u32.to_le_bytes());
    for o in [0x1B0u32, 0x214, 0x27E, 0x2DC] {
        second.extend(o.to_le_bytes());
    }
    second.extend(6u32.to_le_bytes());
    for i in [2u16, 4, 3, 1, 2, 3] {
        second.extend(i.to_le_bytes());
    }
    for n in [
        "DemoFunc",
        "LongSym",
        "Other",
        "__IMPORT_DESCRIPTOR_demo",
        "__imp_DemoFunc",
        "__imp_Other",
    ] {
        second.extend_from_slice(n.as_bytes());
        second.push(0);
    }
    let import = |data: &[u8]| ar_member("demo.dll/", "-1", "0", "0", data);
    ar(&[
        ar_member("/", AR_MTIME, "0", "0", &first),
        ar_member("/", AR_MTIME, "0", "0", &second),
        ar_member("//", AR_MTIME, "0", "0", b"a_long_object_file_name.obj\0"),
        import(&(0..40).collect::<Vec<u8>>()),
        import(&(50..95).collect::<Vec<u8>>()),
        import(&[1; 33]),
        ar_member("/0", "-1", "0", "0", b"obj data"),
    ])
}

/// A ustar archive of (path, contents) pairs; `None` contents make a directory.
fn ustar(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in entries {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        let (mode, kind, size) = match data {
            Some(d) => ("0000666", b'0', d.len()),
            None => ("0000777", b'5', 0),
        };
        let mut field = |at: usize, s: &str| h[at..at + s.len()].copy_from_slice(s.as_bytes());
        field(100, mode);
        field(108, "0000000");
        field(116, "0000000");
        field(124, &format!("{size:011o}"));
        field(136, &format!("{:011o}", 1_792_214_046u64));
        field(257, "ustar\x0000");
        h[156] = kind;
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| b as u32).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        out.extend_from_slice(&h);
        if let Some(d) = data {
            out.extend_from_slice(d);
            out.resize(out.len().next_multiple_of(512), 0);
        }
    }
    out.resize(out.len() + 1024, 0);
    out
}

/// A Debian package: "debian-binary", a gzip-compressed control archive and an
/// xz-compressed data archive.
fn hello_deb() -> Vec<u8> {
    use std::io::Write;
    let control = ustar(&[(
        "./control",
        Some(b"Package: hello\nVersion: 1.0\nArchitecture: all\nMaintainer: Test <t@example.com>\nDescription: test\n"),
    )]);
    let data = ustar(&[
        ("./usr/", None),
        ("./usr/share/", None),
        ("./usr/share/doc/", None),
        ("./usr/share/doc/hello/", None),
        ("./usr/share/doc/hello/README", Some(b"hello deb\n")),
    ]);
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    gz.write_all(&control).unwrap();
    let mut xz =
        lzma_rust2::XzWriter::new(Vec::new(), lzma_rust2::XzOptions::with_preset(6)).unwrap();
    xz.write_all(&data).unwrap();
    ar(&[
        file_member("debian-binary", b"2.0\n"),
        file_member("control.tar.gz", &gz.finish().unwrap()),
        file_member("data.tar.xz", &xz.finish().unwrap()),
    ])
}

fn open_generated(name: &str, data: Vec<u8>) -> Opened {
    format::open_bytes(data, name, &OpenRequest::default())
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

#[test]
fn ar_gnu_symbol_table_and_name_table() {
    let o = open_generated("gnu.a", gnu_a());
    let a = o.archive();
    assert_eq!(
        names(a),
        [
            "1.txt",
            "short.o",
            "a_rather_long_member_name.o",
            "1.dup.txt",
            "2.dup.txt",
            "another_very_long_name.txt"
        ]
    );
    assert_eq!(prop(a, "SubType").as_deref(), Some("a"));
    let c = contents(a).unwrap();
    assert_eq!(
        c["1.txt"],
        b"short.o    func_a\na_rather_long_member_name.o    func_b\nanother_very_long_name.txt    data_c\n"
    );
    assert_eq!(c["1.dup.txt"], b"first\n");
    assert_eq!(c["2.dup.txt"], b"second\n");
    assert_eq!(entry(a, "1.txt").mtime, None);
    assert_eq!(test_archive(a).unwrap(), 6);

    // 7-Zip does not parse 64-bit tables: it lists them raw.
    let o = open_generated("gnu64.a", gnu64_a());
    let a = o.archive();
    assert_eq!(names(a)[0], "/SYM64");
    assert_eq!(entry(a, "/SYM64").size, Some(53));
    assert_eq!(prop(a, "SubType").as_deref(), Some("ar"));
}

#[test]
fn ar_bsd_symdef() {
    let o = open_generated("bsd_symdef.a", bsd_symdef_a());
    let a = o.archive();
    assert_eq!(
        names(a),
        ["1.txt", "short.o", "a_rather_long_member_name.o", "odd"]
    );
    assert_eq!(prop(a, "SubType").as_deref(), Some("a:BSD"));
    let c = contents(a).unwrap();
    assert_eq!(
        c["1.txt"],
        b"short.o    _f1\na_rather_long_member_name.o    _g2\n"
    );
    assert_eq!(c["odd"], b"abc");
}

#[test]
fn ar_microsoft_import_library() {
    let o = open_generated("demo.lib", demo_lib());
    let a = o.archive();
    assert_eq!(
        names(a),
        [
            "1.txt",
            "2.txt",
            "1.demo.dll",
            "2.demo.dll",
            "3.demo.dll",
            "a_long_object_file_name.obj"
        ]
    );
    assert_eq!(prop(a, "SubType").as_deref(), Some("lib"));
    let c = contents(a).unwrap();
    let first = String::from_utf8(c["1.txt"].clone()).unwrap();
    assert!(
        first.starts_with("1.demo.dll    __IMPORT_DESCRIPTOR_demo\n2.demo.dll    __imp_DemoFunc\n")
    );
    let second = String::from_utf8(c["2.txt"].clone()).unwrap();
    assert!(second.starts_with("2.demo.dll    DemoFunc\na_long_object_file_name.obj    LongSym\n"));
    assert_eq!(c["2.demo.dll"], (50..95).collect::<Vec<u8>>());
    assert_eq!(entry(a, "1.demo.dll").mtime, None);
}

#[test]
fn ar_debian_package() {
    // By default a deb opens through its data.tar.* member, as in 7-Zip.
    let o = open_generated("hello_1.0_all.deb", hello_deb());
    let kinds: Vec<&str> = o.levels.iter().map(|l| l.archive.format().name).collect();
    assert_eq!(kinds, ["Ar", "xz", "tar"]);
    assert!(names(o.archive()).contains(&"usr/share/doc/hello/README"));
    // `-tar` shows the members.
    let forced = OpenRequest {
        format: format::find_format("ar"),
        ..OpenRequest::default()
    };
    let o = format::open_bytes(hello_deb(), "hello_1.0_all.deb", &forced).unwrap();
    let a = o.archive();
    assert_eq!(names(a), ["control.tar.gz", "data.tar.xz"]);
    assert_eq!(prop(a, "SubType").as_deref(), Some("deb"));
    let c = contents(a).unwrap();
    assert_eq!(&c["data.tar.xz"][..6], b"\xFD7zXZ\0");
    assert_eq!(&c["control.tar.gz"][..2], b"\x1F\x8B");
}

// ---------------------------------------------------------------- rpm

/// One rpm header structure: (tag, type, value) entries over a data store.
fn rpm_header(tags: &[(u32, u32, &[u8], u32)]) -> Vec<u8> {
    let (mut index, mut store) = (Vec::new(), Vec::new());
    for &(tag, ty, val, count) in tags {
        if ty == 4 {
            while store.len() % 4 != 0 {
                store.push(0);
            }
        }
        for v in [tag, ty, store.len() as u32, count] {
            index.extend_from_slice(&v.to_be_bytes());
        }
        store.extend_from_slice(val);
    }
    let mut h = vec![0x8E, 0xAD, 0xE8, 0x01, 0, 0, 0, 0];
    h.extend_from_slice(&(tags.len() as u32).to_be_bytes());
    h.extend_from_slice(&(store.len() as u32).to_be_bytes());
    h.extend(index);
    h.extend(store);
    h
}

/// A minimal binary package: lead, header-style signature (SIZE, MD5), main header.
fn build_rpm(payload: &[u8], compressor: &str) -> Vec<u8> {
    let mut lead = vec![0xED, 0xAB, 0xEE, 0xDB, 3, 0, 0, 0, 0, 1];
    let mut name = b"hello-1.0-1".to_vec();
    name.resize(66, 0);
    lead.extend(name);
    lead.extend_from_slice(&[0, 1, 0, 5]);
    lead.resize(96, 0);
    let s = |v: &str| [v.as_bytes(), b"\0"].concat();
    let (n, v, r, sum, os, arch, fmt, comp, flags) = (
        s("hello"),
        s("1.0"),
        s("1"),
        s("A test package"),
        s("linux"),
        s("noarch"),
        s("cpio"),
        s(compressor),
        s("9"),
    );
    let time = 1_700_000_000u32.to_be_bytes();
    let main = rpm_header(&[
        (1000, 6, &n, 1),
        (1001, 6, &v, 1),
        (1002, 6, &r, 1),
        (1004, 9, &sum, 1),
        (1006, 4, &time, 1),
        (1021, 6, &os, 1),
        (1022, 6, &arch, 1),
        (1124, 6, &fmt, 1),
        (1125, 6, &comp, 1),
        (1126, 6, &flags, 1),
    ]);
    let size = ((main.len() + payload.len()) as u32).to_be_bytes();
    let mut sig = rpm_header(&[(1000, 4, &size, 1), (1004, 7, &[0x11; 16], 16)]);
    while !sig.len().is_multiple_of(8) {
        sig.push(0);
    }
    [lead, sig, main, payload.to_vec()].concat()
}

#[test]
fn rpm_lists_its_payload() {
    let payload = fs::read(fixture("rpm/payload.cpio.gz")).unwrap();
    let rpm = build_rpm(&payload, "gzip");
    let o = open_generated("hello-1.0-1.noarch.rpm", rpm.clone());
    let a = o.levels[0].archive.clone();
    assert_eq!(a.format().name, "Rpm");
    assert_eq!(names(&*a), ["hello-1.0-1.noarch.cpio.gz"]);
    let e = &a.entries()[0];
    assert_eq!(e.size, Some(payload.len() as u64));
    assert_eq!(e.mtime, Some((1_700_000_000 + 11_644_473_600) * 10_000_000));
    assert_eq!(
        prop(&*a, "Headers Size"),
        Some((rpm.len() - payload.len()).to_string())
    );
    assert_eq!(prop(&*a, "CPU").as_deref(), Some("noarch"));
    assert_eq!(prop(&*a, "Host OS").as_deref(), Some("linux"));
    assert_eq!(prop(&*a, "Name").as_deref(), Some("hello"));
    assert_eq!(contents(&*a).unwrap()[&e.name], payload);
    let mut streamed = Vec::new();
    let open_payload = a.stream(0).unwrap();
    open_payload().unwrap().read_to_end(&mut streamed).unwrap();
    assert_eq!(streamed, payload);

    // The compressor names the payload's extension.
    let xz = build_rpm(b"\xFD7zXZ\0rest", "xz");
    let o = format::open_bytes(xz, "p.rpm", &OpenRequest::default()).unwrap();
    assert_eq!(
        names(o.levels[0].archive.as_ref()),
        ["hello-1.0-1.noarch.cpio.xz"]
    );
}

// ---------------------------------------------------------------- xar

#[test]
fn xar_tree_links_and_toc() {
    let o = open("xar/gzip.xar");
    let a = o.archive();
    assert_eq!(a.format().name, "Xar");
    assert_eq!(
        names(a),
        [
            "hello.txt",
            "hard.txt",
            "link.txt",
            "dir",
            "dir/data.bin",
            "dir/empty",
            "dir/sub",
            "dir/sub/deep.txt",
            "[TOC].xml"
        ]
    );
    assert!(a.verifies_data());
    assert_eq!(prop(a, "Method").as_deref(), Some("SHA1"));
    assert_eq!(
        entry(a, "hard.txt").link,
        Some(Link::Hard("hello.txt".into()))
    );
    assert_eq!(
        entry(a, "link.txt").link,
        Some(Link::Symbolic("hello.txt".into()))
    );
    assert_eq!(
        entry(a, "dir/data.bin").method.as_deref(),
        Some("zlib sha1 sha1")
    );
    assert_eq!(entry(a, "dir/empty").size, None);
    let t = entry(a, "dir/sub/deep.txt").mtime.unwrap();
    assert_eq!(t, (1_704_164_645 + 11_644_473_600) * 10_000_000);
    let c = contents(a).unwrap();
    assert_eq!(c["hello.txt"], HELLO);
    assert_eq!(c["dir/data.bin"], data_bin());
    assert!(c["[TOC].xml"].starts_with(b"<?xml"));
    assert_eq!(
        c["[TOC].xml"].len() as u64,
        entry(a, "[TOC].xml").size.unwrap()
    );

    let out = tmp("xar");
    extract_to(a, &out);
    assert_eq!(fs::read(out.join("hard.txt")).unwrap(), HELLO);
    let link = fs::read(out.join("link.txt")).unwrap();
    assert!(link == HELLO || link == b"hello.txt", "{link:?}");
    assert_eq!(fs::read(out.join("dir/sub/deep.txt")).unwrap(), b"deep\n");
    assert_eq!(fs::read(out.join("dir/empty")).unwrap(), b"");
    let _ = fs::remove_dir_all(&out);
}

#[test]
fn xar_every_encoding() {
    for (file, method) in [
        ("none.xar", "octet-stream sha1 sha1"),
        ("gzip.xar", "zlib sha1 sha1"),
        ("bzip2.xar", "bzip2 sha1 sha1"),
        ("xz.xar", "xz sha1 sha1"),
        ("lzma.xar", "lzma sha1 sha1"),
        ("md5.xar", "zlib md5 md5"),
    ] {
        let o = open(&format!("xar/{file}"));
        let a = o.archive();
        assert_eq!(
            entry(a, "hello.txt").method.as_deref(),
            Some(method),
            "{file}"
        );
        let c = contents(a).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(c["hello.txt"], HELLO, "{file}");
        if file != "md5.xar" {
            assert_eq!(c["dir/data.bin"], data_bin(), "{file}");
        }
        test_archive(a).unwrap_or_else(|e| panic!("{file}: {e}"));
    }
    assert_eq!(
        prop(open("xar/md5.xar").archive(), "Method").as_deref(),
        Some("MD5")
    );
}

#[test]
fn xar_checksums_are_verified() {
    // Stored data: flip a byte of the file, then the extracted checksum fails.
    let mut data = fs::read(fixture("xar/none.xar")).unwrap();
    let at = data.windows(HELLO.len()).position(|w| w == HELLO).unwrap();
    data[at] ^= 1;
    let o = format::open_bytes(data, "x.xar", &OpenRequest::default()).unwrap();
    assert!(matches!(test_archive(o.archive()), Err(Error::Checksum(_))));

    // A damaged table of contents fails its heap checksum (or does not inflate).
    let mut data = fs::read(fixture("xar/gzip.xar")).unwrap();
    data[40] ^= 0x10;
    assert!(format::open_bytes(data, "x.xar", &OpenRequest::default()).is_err());
}

// ---------------------------------------------------------------- damage

/// Every checked-in fixture and every generated archive, as (name, bytes).
fn all_fixtures() -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for dir in ["cpio", "ar", "rpm", "xar"] {
        for e in fs::read_dir(fixture(dir)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x != "gz") {
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                v.push((name, fs::read(&p).unwrap()));
            }
        }
    }
    let payload = fs::read(fixture("rpm/payload.cpio.gz")).unwrap();
    for (name, data) in [
        ("gnu.a", gnu_a()),
        ("gnu64.a", gnu64_a()),
        ("bsd_symdef.a", bsd_symdef_a()),
        ("demo.lib", demo_lib()),
        ("hello_1.0_all.deb", hello_deb()),
        ("hello-1.0-1.noarch.rpm", build_rpm(&payload, "gzip")),
    ] {
        v.push((name.to_string(), data));
    }
    v
}

/// Opens and tests damaged bytes; any outcome but a panic is acceptable here.
fn try_damaged(data: Vec<u8>, name: &str) -> r7z::Result<()> {
    let o = format::open_bytes(data, name, &OpenRequest::default())?;
    for lvl in &o.levels {
        test_archive(&*lvl.archive)?;
    }
    Ok(())
}

#[test]
fn truncated_inputs_fail_without_panicking() {
    for (name, data) in all_fixtures() {
        let whole = format::open_bytes(data.clone(), &name, &OpenRequest::default()).unwrap();
        let outer = &whole.levels[0].archive;
        let physical: usize = prop(&**outer, "Physical Size").unwrap().parse().unwrap();
        // ar has no end marker: a cut at a member boundary is a smaller valid archive.
        let has_end = outer.format().name != "Ar";
        for len in 0..data.len() {
            let r = try_damaged(data[..len].to_vec(), &name);
            if has_end && len < physical {
                assert!(r.is_err(), "{name}: truncation to {len} bytes was accepted");
            }
        }
        for len in [data.len() / 2, physical - 2] {
            let r = try_damaged(data[..len].to_vec(), &name);
            assert!(r.is_err(), "{name}: truncation to {len} bytes was accepted");
        }
    }
}

#[test]
fn bit_flips_never_panic() {
    for (name, data) in all_fixtures() {
        for i in 0..data.len() {
            for bit in [0x01, 0x80] {
                let mut d = data.clone();
                d[i] ^= bit;
                let _ = try_damaged(d, &name);
            }
        }
    }
}
