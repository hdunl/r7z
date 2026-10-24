//! Inno Setup installers.
//!
//! The fixtures in `tests/fixtures/inno/` were compiled with Inno Setup 5.6.1 (ANSI and
//! Unicode, setup data format 5.5.7) and 6.7.3 (format 6.7.0) from synthetic files: a
//! 20 KiB text, a CSV, the `pe/resources.exe` fixture (which Inno stores with its x86 call
//! filter), an empty file and, in Unicode installers, `тест.txt`. Every script also
//! installs the text a second time under another name. `inno6-components` adds types,
//! components and a German-only file; `inno6-password` encrypts the files (password
//! `test123`); `inno6-spanned` keeps its file data in `setup-1.bin`, which is not included.
//!
//! The installers are stored gzipped and cut short: the setup program Inno appends last is
//! removed, and in the 6.7 ones the 900 KiB loader is zeroed except its `MZ` signature
//! and offset table, which is all the reader uses of it. The 5.6.1 ones keep their loader.

use std::fs;
use std::io::Read;
use std::path::Path;

use r7z::format::{self, Archive, Ctx, Flow, OpenRequest, Opened};
use r7z::Error;

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/inno")
        .join(format!("{name}.bin.gz"));
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(fs::File::open(path).unwrap())
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn open(bytes: Vec<u8>) -> r7z::Result<Opened> {
    format::open_bytes(bytes, "setup.exe", &OpenRequest::default())
}

fn prop(a: &dyn Archive, key: &str) -> Option<String> {
    a.properties()
        .into_iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// Every entry's bytes, by decoding every unit; failed units are left out.
fn contents(a: &dyn Archive) -> (Vec<Option<Vec<u8>>>, Vec<Error>) {
    let mut out = vec![None; a.entries().len()];
    let mut errors = Vec::new();
    for u in 0..a.units().len() {
        let r = a.extract_unit(u, &Ctx::default(), &mut |i, r| {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(Error::from)?;
            out[i] = Some(v);
            Ok(Flow::Continue)
        });
        if let Err(e) = r {
            errors.push(e);
        }
    }
    (out, errors)
}

const PLAIN: &[(&str, &str)] = &[
    ("inno5-ansi-lzma-solid", "5.5.7"),
    ("inno5-zip", "5.5.7"),
    ("inno6-lzma2-solid", "6.7.0"),
    ("inno6-lzma", "6.7.0"),
    ("inno6-bzip", "6.7.0"),
    ("inno6-none", "6.7.0"),
    ("inno6-zip", "6.7.0"),
    ("inno6-components", "6.7.0"),
];

#[test]
fn installers_list_and_extract_their_files() {
    let tool =
        fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pe/resources.exe"))
            .unwrap();
    for &(name, version) in PLAIN {
        let o = open(fixture(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let a = o.archive();
        assert_eq!(a.format().name, "Inno", "{name}");
        assert_eq!(
            prop(a, "SubType").as_deref(),
            Some(format!("Inno Setup {version}").as_str()),
            "{name}"
        );
        let (data, errors) = contents(a);
        assert!(errors.is_empty(), "{name}: {errors:?}");
        let get = |n: &str| {
            let i = a
                .entries()
                .iter()
                .position(|e| e.name == n)
                .unwrap_or_else(|| panic!("{name}: no {n}"));
            assert_eq!(
                a.entries()[i].size,
                Some(data[i].as_ref().unwrap().len() as u64)
            );
            data[i].clone().unwrap()
        };
        let readme = get("app/readme.txt");
        assert_eq!(readme.len(), 20544, "{name}");
        assert_eq!(get("app/docs/readme-copy.txt"), readme, "{name}");
        assert_eq!(get("app/bin/tool.exe"), tool, "{name}: call filter");
        assert_eq!(get("app/data/table.csv").len(), 8245, "{name}");
        assert!(get("app/empty.txt").is_empty(), "{name}");
        if !name.contains("ansi") {
            assert_eq!(get("app/тест.txt").len(), 710, "{name}");
        }
        if name.contains("components") {
            assert_eq!(get("app/lang/readme-de.txt"), readme, "{name}");
        }
    }
}

#[test]
fn solid_installers_are_one_unit() {
    let o = open(fixture("inno6-lzma2-solid")).unwrap();
    assert_eq!(o.archive().units().len(), 1);
    assert_eq!(prop(o.archive(), "Solid").as_deref(), Some("+"));
    // Without solid compression each file is a chunk; the copy of the text shares its
    // original's.
    let o = open(fixture("inno6-zip")).unwrap();
    let a = o.archive();
    assert_eq!(a.units().len(), a.entries().len() - 1);
    let block = |n: &str| a.entries().iter().find(|e| e.name == n).unwrap().block;
    assert_eq!(block("app/readme.txt"), block("app/docs/readme-copy.txt"));
}

#[test]
fn encrypted_and_spanned_installers_list_but_do_not_extract() {
    let o = open(fixture("inno6-password")).unwrap();
    assert!(o.archive().entries().iter().all(|e| e.encrypted));
    let (_, errors) = contents(o.archive());
    assert!(
        errors.iter().any(|e| e.to_string().contains("encrypted")),
        "{errors:?}"
    );

    let o = open(fixture("inno6-spanned")).unwrap();
    assert_eq!(o.archive().entries().len(), 6);
    let (_, errors) = contents(o.archive());
    assert!(
        errors.iter().all(|e| e.to_string().contains("setup-N.bin")),
        "{errors:?}"
    );
}

/// Cuts and flipped bits are reported or harmless, never a panic; an installer that still
/// extracts lists what the original does.
#[test]
fn damaged_installers_fail_cleanly() {
    for &(name, _) in &PLAIN[..3] {
        let full = fixture(name);
        let want: Vec<(String, Option<u64>)> = open(full.clone())
            .unwrap()
            .archive()
            .entries()
            .iter()
            .map(|e| (e.name.clone(), e.size))
            .collect();
        // The loader stub is zeros or code the reader never reads; damage after it.
        let from = full.len() * 2 / 3;
        let step = ((full.len() - from) / 200).max(1);
        for (k, pos) in (from..full.len()).step_by(step).enumerate() {
            let _ = open(full[..pos].to_vec()).map(|o| contents(o.archive()));
            let mut bad = full.clone();
            bad[pos] ^= 1 << (k % 8);
            let Ok(o) = open(bad) else { continue };
            let (_, errors) = contents(o.archive());
            if errors.is_empty() {
                let got: Vec<(String, Option<u64>)> = o
                    .archive()
                    .entries()
                    .iter()
                    .map(|e| (e.name.clone(), e.size))
                    .collect();
                assert_eq!(got, want, "{name}: flip at {pos} went unnoticed");
            }
        }
    }
}
