//! WIM reading: fixtures written by the test encoders (validated with 7-Zip, whose
//! `7z t` checks every blob's SHA-1), a WIM written by 7-Zip itself, a real Windows WIM
//! when present, codec round trips and damaged inputs.

mod wimkit;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use r7z::format::{self, Archive, Ctx, Flow, Link, OpenRequest};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Overwrite, Target};
use wimkit::{build, data, Method, Node, Spec};

struct Quiet;
impl Callbacks for Quiet {}

const T0: u64 = 133_500_000_000_000_000;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wim")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-wim-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Reparse data of a relative symbolic link.
fn symlink(target: &str) -> Vec<u8> {
    let t: Vec<u8> = target
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let mut d = Vec::new();
    for v in [0u16, t.len() as u16, t.len() as u16, t.len() as u16] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(&1u32.to_le_bytes());
    d.extend_from_slice(&t);
    d.extend_from_slice(&t);
    d
}

/// Reparse data of a junction (mount point).
fn junction(target: &str) -> Vec<u8> {
    let sub: Vec<u8> = format!("\\??\\{target}")
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let print: Vec<u8> = target
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let mut d = Vec::new();
    for v in [
        0u16,
        sub.len() as u16,
        sub.len() as u16 + 2,
        print.len() as u16,
    ] {
        d.extend_from_slice(&v.to_le_bytes());
    }
    d.extend_from_slice(&sub);
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(&print);
    d.extend_from_slice(&[0, 0]);
    d
}

/// The standard test tree: nested and empty directories, multi-chunk compressible and
/// incompressible files, x86 code, samples, duplicates, hard links, an empty file,
/// alternate streams, a symbolic link, a junction and a Unicode name.
fn tree(seed: u64) -> Vec<Node> {
    let readme = data::text(40_000, seed);
    let notes = data::text(5_000, seed + 1);
    let mut v = vec![
        Node::dir("bin", T0),
        Node::dir("docs", T0 + 1),
        Node::dir("docs/deep", T0 + 2),
        Node::dir("empty", T0 + 3),
        Node::file("bin/tool.exe", data::x86(40_000, seed + 2), T0 + 10_000_000),
        Node::file(
            "bin/samples.raw",
            data::samples(16_000, seed + 3),
            T0 + 20_000_000,
        ),
        Node::file("docs/readme.txt", readme.clone(), T0 + 30_000_000),
        Node::file("docs/copy.txt", readme, T0 + 40_000_000),
        Node::file("docs/deep/notes.txt", notes.clone(), T0 + 50_000_000),
        Node::file("docs/hardlink.txt", notes, T0 + 50_000_000),
        Node::file("random.bin", data::random(3_000, seed + 4), T0 + 60_000_000),
        Node::file("empty.txt", Vec::new(), T0 + 70_000_000),
        Node::file("tiny", b"x".to_vec(), T0 + 80_000_000),
        Node::file(
            "ünïcödé 名前.txt",
            "héllo wörld\n".repeat(20).into_bytes(),
            T0 + 90_000_000,
        ),
    ];
    for n in v.iter_mut() {
        if n.path.ends_with("notes.txt") || n.path.ends_with("hardlink.txt") {
            n.link_group = 0x1234;
        }
        if n.path == "docs/readme.txt" {
            n.streams = vec![
                ("meta".into(), data::text(300, seed + 5)),
                (
                    "Zone.Identifier".into(),
                    b"[ZoneTransfer]\r\nZoneId=3\r\n".to_vec(),
                ),
            ];
        }
    }
    let mut link = Node::file("link", Vec::new(), T0 + 100_000_000);
    link.attrib = 0x20 | 0x400;
    link.reparse = Some((0xA000_000C, symlink("docs\\readme.txt")));
    v.push(link);
    let mut j = Node::dir("junction", T0 + 110_000_000);
    j.attrib = 0x10 | 0x400;
    j.reparse = Some((0xA000_0003, junction("C:\\Windows")));
    v.push(j);
    v
}

/// Every fixture: file name and the spec it was written from.
fn fixtures() -> Vec<(&'static str, Spec)> {
    let mut v = Vec::new();
    v.push(("xpress.wim", Spec::new(vec![tree(1)], Method::Xpress)));
    let mut s = Spec::new(vec![tree(2)], Method::Xpress);
    s.chunk_bits = 12;
    v.push(("xpress-4k.wim", s));
    let mut s = Spec::new(vec![tree(3)], Method::Lzx);
    s.style = 2;
    v.push(("lzx.wim", s));
    let mut s = Spec::new(vec![tree(4)], Method::Lzx);
    s.style = 1;
    s.chunk_bits = 16;
    v.push(("lzx-64k.wim", s));
    v.push(("lzms.wim", Spec::new(vec![tree(5)], Method::Lzms)));
    let mut s = Spec::new(vec![tree(6)], Method::Lzms);
    s.solid = Some((Method::Lzms, 16, 2));
    v.push(("solid.esd", s));
    let mut s = Spec::new(vec![tree(7)], Method::Lzx);
    s.solid = Some((Method::Lzx, 15, 1));
    s.style = 2;
    v.push(("solid-lzx.esd", s));
    let mut second = tree(8);
    second.retain(|n| !n.path.starts_with("bin"));
    second.push(Node::file("only-in-2.txt", data::text(2_000, 80), T0 + 5));
    let mut s = Spec::new(vec![tree(8), second], Method::Lzx);
    s.orphans = vec![data::text(1_000, 99)];
    v.push(("multi.wim", s));
    let mut s = Spec::new(vec![tree(9)], Method::Xpress);
    s.parts = 3;
    v.push(("split.swm", s));
    v
}

fn spec_of(name: &str) -> Spec {
    fixtures().into_iter().find(|(n, _)| *n == name).unwrap().1
}

/// The parts of a built spec with their file names.
fn named_parts(name: &str, spec: &Spec) -> Vec<(String, Vec<u8>)> {
    build(spec)
        .into_iter()
        .enumerate()
        .map(|(i, d)| {
            let n = if i == 0 {
                name.to_string()
            } else {
                let (stem, ext) = name.rsplit_once('.').unwrap();
                format!("{stem}{}.{ext}", i + 1)
            };
            (n, d)
        })
        .collect()
}

/// Regenerates the fixtures (then check them with `7z t`).
#[test]
#[ignore]
fn generate_fixtures() {
    let dir = fixture_dir();
    fs::create_dir_all(&dir).unwrap();
    for (name, spec) in fixtures() {
        for (n, d) in named_parts(name, &spec) {
            fs::write(dir.join(n), d).unwrap();
        }
    }
}

/// The checked-in fixtures are exactly what the encoders produce, so the 7-Zip check of
/// the fixtures covers the encoders used by the round-trip tests below.
#[test]
fn fixtures_are_current() {
    for (name, spec) in fixtures() {
        for (n, d) in named_parts(name, &spec) {
            let path = fixture_dir().join(&n);
            let on_disk = fs::read(&path).unwrap_or_else(|e| panic!("{n}: {e}"));
            assert!(on_disk == d, "{n} differs from the encoder output");
            assert!(d.len() < 100_000, "{n} is {} bytes", d.len());
        }
    }
}

/// Decodes every unit, keyed by entry name.
fn contents(a: &dyn Archive) -> HashMap<String, Vec<u8>> {
    let mut out = HashMap::new();
    for threads in [1, 4] {
        let ctx = Ctx {
            password: None,
            threads,
        };
        for u in 0..a.units().len() {
            a.extract_unit(u, &ctx, &mut |i, r| {
                let mut v = Vec::new();
                r.read_to_end(&mut v).map_err(r7z::Error::from)?;
                out.insert(a.entries()[i].name.clone(), v);
                Ok(Flow::Continue)
            })
            .unwrap_or_else(|e| panic!("unit {u}: {e}"));
        }
    }
    out
}

/// An entry the archive must list: name, data (None for a directory), mtime and link
/// target.
type Expected = (String, Option<Vec<u8>>, u64, Option<String>);

fn expected(nodes: &[Node], prefix: &str) -> Vec<Expected> {
    let mut v = Vec::new();
    for n in nodes {
        let name = format!("{prefix}{}", n.path);
        let link = n.reparse.as_ref().map(|(tag, d)| {
            let target = if *tag == 0xA000_000C {
                "docs\\readme.txt"
            } else {
                "C:\\Windows"
            };
            assert!(!d.is_empty());
            target.to_string()
        });
        let data = match (&link, &n.data) {
            (Some(t), Some(_)) => Some(t.clone().into_bytes()),
            (_, d) => d.clone(),
        };
        v.push((name.clone(), data, n.times[2], link));
        for (s, d) in &n.streams {
            v.push((format!("{name}:{s}"), Some(d.clone()), n.times[2], None));
        }
    }
    v
}

fn check_image(a: &dyn Archive, got: &HashMap<String, Vec<u8>>, nodes: &[Node], prefix: &str) {
    for (name, data, mtime, link) in expected(nodes, prefix) {
        let e = a
            .entries()
            .iter()
            .find(|e| e.name == name)
            .unwrap_or_else(|| panic!("{name} not listed"));
        assert_eq!(e.mtime, Some(mtime), "{name}");
        assert_eq!(e.link.clone(), link.map(Link::Symbolic), "{name}");
        match data {
            None => assert!(e.is_dir, "{name}"),
            Some(d) => {
                assert!(!e.is_dir, "{name}");
                assert_eq!(e.size, Some(d.len() as u64), "{name}");
                let g = got.get(&name).map(Vec::as_slice).unwrap_or(&[]);
                assert!(g == d.as_slice(), "{name}: data differs");
            }
        }
    }
}

fn open_fixture(name: &str) -> format::Opened {
    format::open(&fixture_dir().join(name), &OpenRequest::default())
        .unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn check_fixture(name: &str) {
    let spec = spec_of(name);
    let o = open_fixture(name);
    let a = o.archive();
    assert_eq!(a.format().name, "wim");
    assert!(a.verifies_data());
    let got = contents(a);
    if spec.images.len() == 1 {
        check_image(a, &got, &spec.images[0], "");
        // Directories first, then files by blob: 7-Zip's order.
        let first_file = a.entries().iter().position(|e| !e.is_dir).unwrap();
        assert!(
            a.entries()[first_file..].iter().all(|e| !e.is_dir),
            "{name}"
        );
    } else {
        for (i, img) in spec.images.iter().enumerate() {
            check_image(a, &got, img, &format!("{}/", i + 1));
            assert!(a
                .entries()
                .iter()
                .any(|e| e.is_dir && e.name == (i + 1).to_string()));
        }
        let xml = got.get("[1].xml").expect("XML listed");
        assert_eq!(&xml[..2], &[0xFF, 0xFE]);
    }
    for o in &spec.orphans {
        assert!(
            got.values().any(|v| v == o),
            "{name}: orphan blob not listed"
        );
        assert!(a.entries().iter().any(|e| e.name.starts_with("[DELETED]/")));
    }
}

#[test]
fn xpress() {
    check_fixture("xpress.wim");
    check_fixture("xpress-4k.wim");
}

#[test]
fn lzx() {
    check_fixture("lzx.wim");
    check_fixture("lzx-64k.wim");
}

#[test]
fn lzms() {
    check_fixture("lzms.wim");
}

#[test]
fn solid() {
    check_fixture("solid.esd");
    check_fixture("solid-lzx.esd");
    let o = open_fixture("solid.esd");
    let a = o.archive();
    // One unit per solid resource, plus the symbolic link's target text.
    assert_eq!(a.units().len(), 2 + 1);
    let props = a.properties();
    let get = |k: &str| props.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
    assert_eq!(get("Version").as_deref(), Some("0.14"));
    let methods: Vec<String> = a
        .entries()
        .iter()
        .filter_map(|e| e.method.clone())
        .collect();
    assert!(methods.iter().all(|m| m == "LZMS:16"), "{methods:?}");
}

#[test]
fn multiple_images() {
    check_fixture("multi.wim");
    let o = open_fixture("multi.wim");
    let names: Vec<&str> = o
        .archive()
        .entries()
        .iter()
        .map(|e| e.name.as_str())
        .collect();
    // Image roots are directories, sorted with the others as 7-Zip does.
    assert_eq!(names[0], "1");
    let two = names.iter().position(|&n| n == "2").unwrap();
    assert!(names[..two].iter().all(|n| n.starts_with('1')));
    assert!(names.contains(&"2/only-in-2.txt"));
}

#[test]
fn split_set() {
    check_fixture("split.swm");
    let o = open_fixture("split.swm");
    let props = o.archive().properties();
    assert!(props.contains(&("Multivolume", "+".into())));
    assert!(props.contains(&("Volumes", "3".into())));

    // A missing part and a later part opened alone are reported, not misread.
    let dir = tmp("split");
    for (n, d) in named_parts("split.swm", &spec_of("split.swm")) {
        if n != "split3.swm" {
            fs::write(dir.join(&n), d).unwrap();
        }
    }
    let err = format::open(&dir.join("split.swm"), &OpenRequest::default())
        .err()
        .unwrap();
    assert!(matches!(err, r7z::Error::Unsupported(_)), "{err}");
    let err = format::open(&dir.join("split2.swm"), &OpenRequest::default())
        .err()
        .unwrap();
    assert!(matches!(err, r7z::Error::Unsupported(_)), "{err}");
    let bytes = fs::read(fixture_dir().join("split.swm")).unwrap();
    let err = format::open_bytes(bytes, "split.swm", &OpenRequest::default())
        .err()
        .unwrap();
    assert!(matches!(err, r7z::Error::Unsupported(_)), "{err}");
}

/// A WIM written by `7z a -twim` (uncompressed, with a duplicate file, an empty file and
/// an empty directory).
#[test]
fn seven_zip_made() {
    let o = open_fixture("7z-copy.wim");
    let a = o.archive();
    let names: Vec<&str> = a.entries().iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "emptydir",
            "sub",
            "sub/deep",
            "empty.bin",
            "a.txt",
            "sub/a_copy.txt",
            "rand.bin",
            "sub/deep/x"
        ]
    );
    let got = contents(a);
    let text = "hello world\n".repeat(1500).into_bytes();
    assert_eq!(got["a.txt"], text);
    assert_eq!(got["sub/a_copy.txt"], text);
    assert_eq!(got["sub/deep/x"], b"x");
    assert_eq!(a.entries()[4].size, Some(18_000));
    assert_eq!(a.entries()[4].method.as_deref(), Some("Copy"));
    assert!(a.properties().contains(&("Method", "Copy:15".into())));

    // Through the generic extractor to disk.
    let out = tmp("7z-made");
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 4,
        target: Target::Disk {
            dir: out.clone(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    let rep = extract(a, &opts, &Quiet).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    assert_eq!(rep.files, 5);
    assert_eq!(fs::read(out.join("sub/a_copy.txt")).unwrap(), text);
    assert!(out.join("emptydir").is_dir());
    assert_eq!(fs::read(out.join("empty.bin")).unwrap().len(), 0);
}

/// A real compressed WIM shipped with Windows (XPRESS metadata), when present.
#[test]
fn windows_wim() {
    let p = Path::new("C:/Windows/System32/DrtmAuthTxt.wim");
    if !p.exists() {
        eprintln!("skipped: {} not present", p.display());
        return;
    }
    let o = format::open(p, &OpenRequest::default()).unwrap();
    let a = o.archive();
    assert!(a.entries().len() > 10);
    assert!(a.properties().contains(&("Method", "XPress:15".into())));
    let got = contents(a);
    assert_eq!(got.len(), a.entries().iter().filter(|e| !e.is_dir).count());
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
    assert!(rep.errors.is_empty());
}

#[test]
fn extract_to_disk() {
    let o = open_fixture("lzx.wim");
    let out = tmp("lzx-disk");
    let opts = ExtractOptions {
        base: None,
        password: None,
        threads: 4,
        target: Target::Disk {
            dir: out.clone(),
            full_paths: true,
            overwrite: Overwrite::All,
        },
        selected: None,
    };
    let rep = extract(o.archive(), &opts, &Quiet).unwrap();
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    let spec = spec_of("lzx.wim");
    for n in &spec.images[0] {
        let p = out.join(&n.path);
        match (&n.data, &n.reparse) {
            (Some(d), None) => assert_eq!(&fs::read(&p).unwrap(), d, "{}", n.path),
            (None, _) => assert!(p.is_dir(), "{}", n.path),
            _ => {}
        }
    }
    let mt = fs::metadata(out.join("tiny")).unwrap().modified().unwrap();
    assert_eq!(mt, r7z::util::time::from_filetime(T0 + 80_000_000).unwrap());
}

/// Every encoder/decoder pair over awkward inputs, through whole WIMs.
#[test]
fn codec_round_trips() {
    let inputs: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"a".to_vec(),
        vec![0u8; 100_000],
        data::random(70_000, 5),
        data::text(200_000, 6),
        data::x86(90_000, 7),
        data::samples(66_000, 8),
        (0..=255u8).cycle().take(65_537).collect(),
    ];
    // Method, chunk bits, encoder style, solid layout.
    type Combo = (Method, u32, u32, Option<(Method, u32, usize)>);
    let combos: Vec<Combo> = vec![
        (Method::Xpress, 15, 0, None),
        (Method::Xpress, 16, 0, None),
        (Method::Xpress, 13, 0, None),
        (Method::Lzx, 15, 0, None),
        (Method::Lzx, 15, 1, None),
        (Method::Lzx, 15, 2, None),
        (Method::Lzx, 17, 2, None),
        (Method::Lzms, 15, 0, None),
        (Method::Lzms, 18, 0, None),
        (Method::Lzms, 15, 0, Some((Method::Lzms, 17, 3))),
        (Method::Xpress, 15, 0, Some((Method::Xpress, 14, 2))),
    ];
    for (m, bits, style, solid) in combos {
        let nodes: Vec<Node> = inputs
            .iter()
            .enumerate()
            .map(|(i, d)| Node::file(&format!("f{i}"), d.clone(), T0))
            .collect();
        let mut spec = Spec::new(vec![nodes], m);
        spec.chunk_bits = bits;
        spec.style = style;
        spec.solid = solid;
        let wim = build(&spec).remove(0);
        // R7Z_WIM_DUMP=dir keeps the archives for checking with 7-Zip.
        if let Ok(dir) = std::env::var("R7Z_WIM_DUMP") {
            let n = format!("{m:?}-{bits}-{style}-{}.wim", solid.map_or(0, |s| s.1));
            fs::write(Path::new(&dir).join(n), &wim).unwrap();
        }
        let o = format::open_bytes(wim, "t.wim", &OpenRequest::default()).unwrap();
        let got = contents(o.archive());
        for (i, d) in inputs.iter().enumerate() {
            let g = got.get(&format!("f{i}")).map(Vec::as_slice).unwrap_or(&[]);
            assert!(
                g == d.as_slice(),
                "{m:?}/{bits}/{style}/{solid:?}: f{i} differs"
            );
        }
    }
}

/// Damaged archives fail with errors (or decode with data errors), never panic.
#[test]
fn damaged_inputs() {
    for name in [
        "xpress.wim",
        "lzx.wim",
        "lzms.wim",
        "solid.esd",
        "multi.wim",
    ] {
        let good = fs::read(fixture_dir().join(name)).unwrap();
        let try_open = |d: Vec<u8>| -> bool {
            match format::open_bytes(d, name, &OpenRequest::default()) {
                Err(_) => false,
                Ok(o) => {
                    let a = o.archive();
                    let ctx = Ctx {
                        password: None,
                        threads: 2,
                    };
                    let mut ok = true;
                    for u in 0..a.units().len() {
                        let r = a.extract_unit(u, &ctx, &mut |_, r| {
                            let mut v = Vec::new();
                            r.read_to_end(&mut v).map_err(r7z::Error::from)?;
                            Ok(Flow::Continue)
                        });
                        ok &= r.is_ok();
                    }
                    ok
                }
            }
        };
        let step = (good.len() / 97).max(1);
        for cut in (0..good.len()).step_by(step) {
            assert!(
                !try_open(good[..cut].to_vec()),
                "{name} truncated to {cut} passed"
            );
        }
        let mut x = 0x9E37_79B9u32;
        for _ in 0..300 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let mut d = good.clone();
            let at = x as usize % d.len();
            d[at] ^= 1 << (x >> 29);
            // Flips in unused header bytes or padding may be harmless; only panics or
            // hangs would fail here.
            let _ = try_open(d);
        }
    }
}

fn xorshift(x: &mut u64) -> u64 {
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

/// Mutated and random chunks through every decoder: errors are fine, panics are not.
/// `R7Z_WIM_FUZZ=n` runs n rounds instead of the default.
#[test]
fn fuzz_decoders() {
    use r7z::codec::{lzms::LzmsDecoder, lzx_wim::LzxDecoder, xpress::XpressDecoder};
    let rounds: usize = std::env::var("R7Z_WIM_FUZZ")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(150);
    let samples = [
        data::text(30_000, 1),
        data::x86(32_768, 2),
        data::samples(20_000, 3),
    ];
    let mut xp = XpressDecoder::new();
    let mut lzx = LzxDecoder::new();
    let mut lzms = LzmsDecoder::new();
    let mut seed = 0x1234_5678_9abc_def1u64;
    for (k, plain) in samples.iter().enumerate() {
        let packed = [
            wimkit::xpress::compress(plain),
            wimkit::lzx::compress(plain, 15, k as u32),
            wimkit::lzms::compress(plain),
        ];
        for _ in 0..rounds {
            for (m, good) in packed.iter().enumerate() {
                let mut d = good.clone();
                match xorshift(&mut seed) % 3 {
                    0 => {
                        for _ in 0..1 + xorshift(&mut seed) % 8 {
                            let at = xorshift(&mut seed) as usize % d.len();
                            d[at] ^= 1 << (xorshift(&mut seed) % 8);
                        }
                    }
                    1 => d.truncate(xorshift(&mut seed) as usize % d.len()),
                    _ => d = data::random(xorshift(&mut seed) as usize % 3000, xorshift(&mut seed)),
                }
                let mut out = vec![0u8; plain.len()];
                let _ = match m {
                    0 => xp.decompress(&d, &mut out),
                    1 => lzx.decompress(&d, &mut out, 15),
                    _ => lzms.decompress(&d, &mut out),
                };
            }
        }
    }
}

/// Bit flips in the metadata, lookup table and XML (the end of each fixture).
#[test]
fn damaged_metadata() {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for name in [
        "xpress.wim",
        "lzms.wim",
        "solid.esd",
        "multi.wim",
        "7z-copy.wim",
    ] {
        let good = fs::read(fixture_dir().join(name)).unwrap();
        let tail = good.len() / 3;
        for _ in 0..400 {
            let mut d = good.clone();
            for _ in 0..1 + xorshift(&mut seed) % 3 {
                let at = good.len() - 1 - xorshift(&mut seed) as usize % tail;
                d[at] ^= 1 << (xorshift(&mut seed) % 8);
            }
            if let Ok(o) = format::open_bytes(d, name, &OpenRequest::default()) {
                let a = o.archive();
                let ctx = Ctx {
                    password: None,
                    threads: 1,
                };
                for u in 0..a.units().len() {
                    let _ = a.extract_unit(u, &ctx, &mut |_, r| {
                        let mut v = Vec::new();
                        r.read_to_end(&mut v).map_err(r7z::Error::from)?;
                        Ok(Flow::Continue)
                    });
                }
            }
        }
    }
}

/// Builds large WIMs for timing: `R7Z_WIM_BENCH_SRC` (directory of files, read up to
/// 160 MB) and `R7Z_WIM_BENCH_OUT` (output directory).
#[test]
#[ignore]
fn build_bench_wims() {
    let (Ok(src), Ok(out)) = (
        std::env::var("R7Z_WIM_BENCH_SRC"),
        std::env::var("R7Z_WIM_BENCH_OUT"),
    ) else {
        return;
    };
    let mut nodes = Vec::new();
    let mut total = 0usize;
    let mut entries: Vec<_> = fs::read_dir(&src).unwrap().flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        if total > 160 << 20 {
            break;
        }
        if let Ok(d) = fs::read(e.path()) {
            if e.path().is_file() && !d.is_empty() {
                total += d.len();
                nodes.push(Node::file(&e.file_name().to_string_lossy(), d, T0));
            }
        }
    }
    let variants: Vec<(&str, Spec)> = vec![
        ("xpress", Spec::new(vec![nodes.clone()], Method::Xpress)),
        ("lzx", Spec::new(vec![nodes.clone()], Method::Lzx)),
        ("lzms", Spec::new(vec![nodes.clone()], Method::Lzms)),
        ("solid", {
            let mut s = Spec::new(vec![nodes], Method::Lzms);
            s.solid = Some((Method::Lzms, 20, 2));
            s
        }),
    ];
    for (n, s) in variants {
        fs::write(
            Path::new(&out).join(format!("{n}.wim")),
            build(&s).remove(0),
        )
        .unwrap();
    }
}

/// Raw decoder speed over `R7Z_WIM_BENCH_SRC` files (first 48 MB), 32 KiB chunks.
#[test]
#[ignore]
fn decoder_speed() {
    use r7z::codec::{lzms::LzmsDecoder, lzx_wim::LzxDecoder, xpress::XpressDecoder};
    let Ok(src) = std::env::var("R7Z_WIM_BENCH_SRC") else {
        return;
    };
    let mut all = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(&src).unwrap().flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        if all.len() > 48 << 20 {
            break;
        }
        if e.path().is_file() {
            all.extend(fs::read(e.path()).unwrap_or_default());
        }
    }
    let chunks: Vec<&[u8]> = all.chunks(32768).collect();
    for m in 0..3 {
        let packed: Vec<Vec<u8>> = chunks
            .iter()
            .map(|c| match m {
                0 => wimkit::xpress::compress(c),
                1 => wimkit::lzx::compress(c, 15, 0),
                _ => wimkit::lzms::compress(c),
            })
            .collect();
        let mut xp = XpressDecoder::new();
        let mut lzx = LzxDecoder::new();
        let mut lzms = LzmsDecoder::new();
        let mut out = vec![0u8; 32768];
        let t = std::time::Instant::now();
        for (c, p) in chunks.iter().zip(&packed) {
            let o = &mut out[..c.len()];
            match m {
                0 => xp.decompress(p, o).unwrap(),
                1 => lzx.decompress(p, o, 15).unwrap(),
                _ => lzms.decompress(p, o).unwrap(),
            }
        }
        let s = t.elapsed().as_secs_f64();
        eprintln!(
            "{}: {:.0} MB/s",
            ["xpress", "lzx", "lzms"][m],
            all.len() as f64 / s / 1e6
        );
    }
}
