//! RAR reading: RAR 4 (2.9/3.x LZ, PPMd, VM filters, encryption, volumes) and RAR 5.
//!
//! The fixtures under `tests/fixtures/rar/` were made with WinRAR 6.21 from a small corpus
//! of synthetic files (text, noise, zeros, a WAV tone, a BMP gradient, E8-rich code, a
//! Unicode name, a directory and an empty file); no third-party content is included. Each
//! `rar4-*` archive is RAR 4 and each `rar5-*` one RAR 5. Their extracted bytes were checked
//! byte-for-byte against the corpus with 7-Zip 25.01. The archive names say what each one
//! exercises:
//!
//! - `store`, `lz`, `solid`: stored, compressed, and solid units;
//! - `ppm`: PPMd (variant H) blocks, forced with `-mct+`;
//! - `e8`, `delta`, `audio`, `rgb`: the standard VM filters, forced with `-mce+` and friends;
//! - `encdata`, `enchdr`: file-data and header encryption (password `pw123`);
//! - `part`, `oldvol`: multi-volume sets (`.partNN.rar` and `.rNN`);
//! - `comment`, `rr`: archive comments and recovery records, which must be skipped.

use std::fs;
use std::path::{Path, PathBuf};

use r7z::format::{open, open_bytes, Archive, OpenRequest, Opened};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Target};

struct Quiet;
impl Callbacks for Quiet {}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar")
        .join(name)
}

fn open_fixture(name: &str, password: Option<&str>) -> r7z::Result<Opened> {
    open(
        &fixture(name),
        &OpenRequest {
            password: password.map(str::to_string),
            ..Default::default()
        },
    )
}

/// Decodes and verifies every entry; the format checks CRC32 and BLAKE2sp as it reads.
fn test_all(a: &dyn Archive, password: Option<&str>) -> Result<(), String> {
    let opts = ExtractOptions {
        base: None,
        password: password.map(str::to_string),
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

/// Archives that hold the whole corpus without a password.
const CORPUS: &[&str] = &[
    "rar4-lz.rar",
    "rar4-solid.rar",
    "rar5-lz.rar",
    "rar5-solid.rar",
];

/// Single-method archives and the other plain ones.
const SINGLE: &[&str] = &[
    "rar4-store.rar",
    "rar4-ppm.rar",
    "rar4-e8.rar",
    "rar4-delta.rar",
    "rar4-audio.rar",
    "rar4-rgb.rar",
    "rar4-comment.rar",
    "rar4-rr.rar",
    "rar5-store.rar",
    "rar5-e8.rar",
    "rar5-delta.rar",
    "rar5-comment.rar",
    "rar5-rr.rar",
];

const ENCRYPTED: &[&str] = &[
    "rar4-encdata.rar",
    "rar4-enchdr.rar",
    "rar5-encdata.rar",
    "rar5-enchdr.rar",
];

#[test]
fn plain_fixtures_extract_and_verify() {
    for name in CORPUS.iter().chain(SINGLE) {
        let o = open_fixture(name, None).unwrap_or_else(|e| panic!("{name}: {e}"));
        test_all(o.archive(), None).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn corpus_archives_list_every_member_with_its_kind() {
    for name in CORPUS {
        let o = open_fixture(name, None).unwrap();
        let entries = o.archive().entries();
        let find = |n: &str| entries.iter().find(|e| e.name == n);
        for want in ["text.txt", "tone.wav", "image.bmp", "code.bin", "empty.txt"] {
            assert!(find(want).is_some(), "{name}: missing {want}");
        }
        assert!(find("naïve-日本.txt").is_some(), "{name}: unicode name");
        assert!(find("dir").is_some_and(|e| e.is_dir), "{name}: directory");
        assert_eq!(find("empty.txt").unwrap().size, Some(0), "{name}");
        assert_eq!(find("text.txt").unwrap().size, Some(8216), "{name}");
    }
}

#[test]
fn encrypted_archives_need_and_accept_the_password() {
    for name in ENCRYPTED {
        // Without a password, file data fails to extract; with -hp the listing fails too.
        match open_fixture(name, None) {
            Err(e) => assert!(e.to_string().contains("password"), "{name}: {e}"),
            Ok(o) => {
                let err = test_all(o.archive(), None).unwrap_err();
                assert!(
                    err.contains("password") || err.contains("Password"),
                    "{name}: {err}"
                );
            }
        }
        let o = open_fixture(name, Some("pw123")).unwrap_or_else(|e| panic!("{name}: {e}"));
        test_all(o.archive(), Some("pw123")).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn wrong_password_is_reported() {
    for name in ENCRYPTED {
        let failed = match open_fixture(name, Some("nope")) {
            Err(_) => true,
            Ok(o) => test_all(o.archive(), Some("nope")).is_err(),
        };
        assert!(failed, "{name}: wrong password accepted");
    }
}

#[test]
fn split_sets_open_from_the_first_part() {
    for name in ["rar4-part.part1.rar", "rar5-part.part1.rar"] {
        let o = open_fixture(name, None).unwrap_or_else(|e| panic!("{name}: {e}"));
        test_all(o.archive(), None).unwrap_or_else(|e| panic!("{name}: {e}"));
        let names: Vec<&str> = o
            .archive()
            .entries()
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(
            names.contains(&"text.txt") && names.contains(&"noise.bin"),
            "{name}"
        );
    }
}

#[test]
fn old_style_volume_sets_open_from_the_rar_file() {
    let o = open_fixture("rar4-oldvol.rar", None).unwrap();
    test_all(o.archive(), None).unwrap();
}

#[test]
fn a_split_file_without_its_next_volume_fails_to_extract() {
    let bytes = fs::read(fixture("rar4-part.part1.rar")).unwrap();
    let o = open_bytes(bytes, "rar4-part.part1.rar", &OpenRequest::default()).unwrap();
    assert!(test_all(o.archive(), None).is_err());
}

/// Cuts never pass silently: an archive that still opens and verifies lists a prefix of
/// the original entries.
#[test]
fn truncated_archives_fail_or_list_a_prefix() {
    for name in CORPUS.iter().chain(SINGLE).chain(ENCRYPTED) {
        let full = fs::read(fixture(name)).unwrap();
        let pw = ENCRYPTED.contains(name).then_some("pw123");
        let want: Vec<String> = open_fixture(name, pw)
            .unwrap()
            .archive()
            .entries()
            .iter()
            .map(|e| e.name.clone())
            .collect();
        let step = (full.len() / 150).max(1);
        for cut in (0..full.len()).step_by(step) {
            let req = OpenRequest {
                password: pw.map(str::to_string),
                ..Default::default()
            };
            let Ok(o) = open_bytes(full[..cut].to_vec(), name, &req) else {
                continue;
            };
            if test_all(o.archive(), pw).is_err() {
                continue;
            }
            let got: Vec<String> = o
                .archive()
                .entries()
                .iter()
                .map(|e| e.name.clone())
                .collect();
            assert!(
                got.len() < want.len() || cut + 1 >= full.len(),
                "{name} cut at {cut} passed"
            );
            assert_eq!(got[..], want[..got.len()], "{name} cut at {cut}");
        }
    }
}

/// A flipped bit is reported by the header or data checks. A flip that verifies must not
/// change what the archive lists.
#[test]
fn bit_flips_are_reported_or_harmless() {
    for name in CORPUS.iter().chain(SINGLE).chain(ENCRYPTED) {
        let full = fs::read(fixture(name)).unwrap();
        let pw = ENCRYPTED.contains(name).then_some("pw123");
        let req = OpenRequest {
            password: pw.map(str::to_string),
            ..Default::default()
        };
        let want: Vec<(String, Option<u64>)> = open_bytes(full.clone(), name, &req)
            .unwrap()
            .archive()
            .entries()
            .iter()
            .map(|e| (e.name.clone(), e.size))
            .collect();
        let step = (full.len() / 300).max(1);
        for (k, pos) in (0..full.len()).step_by(step).enumerate() {
            let mut bad = full.clone();
            bad[pos] ^= 1 << (k % 8);
            let Ok(o) = open_bytes(bad, name, &req) else {
                continue;
            };
            if test_all(o.archive(), pw).is_ok() {
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

#[test]
fn not_archives_are_refused_without_panicking() {
    let junk = b"Rar!\x1A\x07\x00 not really an archive".to_vec();
    if let Ok(o) = open_bytes(junk, "x.rar", &OpenRequest::default()) {
        let _ = test_all(o.archive(), None);
    }
}
