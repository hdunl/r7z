//! Updating existing archives: `a`/`u` (add and replace), `d` (delete) and `rn` (rename) for
//! 7z, zip, tar and the compressed tars, plus single-file gzip. Results are read back with
//! r7z's own reader, which checks CRCs. 7-Zip cross-checks run by hand (see the PR notes).

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use r7z::format::write::{self, Compressor, Kind, WriteOptions};
use r7z::format::{self, Ctx, Flow, OpenRequest};
use r7z::ops::create::{self, CreateOptions, Item, NoProgress, Progress};
use r7z::ops::update::{self, Replace, Selection, Settings};
use r7z::sevenz::read::ArchiveFile;
use r7z::Error;

/// A time 2022-ish, in FILETIME ticks.
const T0: u64 = 133_000_000_000_000_000;
/// Ten seconds later.
const T1: u64 = T0 + 100_000_000;

/// A scratch directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("r7z-update-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }

    /// Writes a file under the scratch directory and returns its item (name `rel`).
    fn file(&self, rel: &str, data: &[u8], mtime: u64) -> Item {
        let src = self.path(rel);
        if let Some(parent) = src.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&src, data).unwrap();
        Item {
            src,
            name: rel.to_string(),
            is_dir: false,
            size: data.len() as u64,
            mtime: Some(mtime),
            ctime: None,
            atime: None,
            attrib: Some(0x20),
        }
    }

    fn dir(&self, rel: &str, mtime: u64) -> Item {
        fs::create_dir_all(self.path(rel)).unwrap();
        Item {
            src: self.path(rel),
            name: rel.to_string(),
            is_dir: true,
            size: 0,
            mtime: Some(mtime),
            ctime: None,
            atime: None,
            attrib: Some(0x10),
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The files of an archive by name, with their contents. Directories are not included.
fn read_back(path: &Path, password: Option<&str>) -> r7z::Result<BTreeMap<String, Vec<u8>>> {
    let opened = format::open(
        path,
        &OpenRequest {
            password: password.map(str::to_string),
            ..Default::default()
        },
    )?;
    let arc = opened.arc();
    let ctx = Ctx {
        password: password.map(str::to_string),
        threads: 1,
    };
    let mut files = BTreeMap::new();
    for unit in 0..arc.units().len() {
        arc.extract_unit(unit, &ctx, &mut |i, r: &mut dyn Read| {
            let mut data = Vec::new();
            r.read_to_end(&mut data).map_err(Error::from_codec)?;
            files.insert(arc.entries()[i].name.clone(), data);
            Ok(Flow::Continue)
        })?;
    }
    Ok(files)
}

/// Every entry name, directories included.
fn names(path: &Path, password: Option<&str>) -> r7z::Result<Vec<String>> {
    let opened = format::open(
        path,
        &OpenRequest {
            password: password.map(str::to_string),
            ..Default::default()
        },
    )?;
    Ok(opened
        .archive()
        .entries()
        .iter()
        .map(|e| e.name.clone())
        .collect())
}

fn expect(pairs: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
    pairs
        .iter()
        .map(|(n, d)| (n.to_string(), d.to_vec()))
        .collect()
}

fn cfg_7z(solid: bool, password: Option<&str>, encrypt_header: bool) -> CreateOptions {
    CreateOptions {
        level: 1,
        threads: 2,
        password: password.map(str::to_string),
        encrypt_header,
        solid_limit: if solid { Some(u64::MAX) } else { None },
        ..CreateOptions::default()
    }
}

fn cfg_other(password: Option<&str>) -> WriteOptions {
    WriteOptions {
        level: 1,
        threads: 2,
        password: password.map(str::to_string),
        store: false,
        store_mtime: true,
        store_ctime: false,
        store_atime: false,
    }
}

/// Applies `plan` to a 7z archive.
fn update_7z(
    path: &Path,
    plan: &update::Plan,
    opts: &CreateOptions,
) -> r7z::Result<update::Outcome> {
    let opened = format::open(
        path,
        &OpenRequest {
            password: opts.password.clone(),
            ..Default::default()
        },
    )?;
    update::apply(opened, path, plan, Settings::SevenZ(opts), &NoProgress)
}

/// Applies `plan` to a zip, tar or single-stream archive.
fn update_other(
    path: &Path,
    plan: &update::Plan,
    opts: &WriteOptions,
) -> r7z::Result<update::Outcome> {
    let opened = format::open(
        path,
        &OpenRequest {
            password: opts.password.clone(),
            ..Default::default()
        },
    )?;
    update::apply(opened, path, plan, Settings::Other(opts), &NoProgress)
}

fn entries_of(path: &Path) -> Vec<format::Entry> {
    format::open(path, &OpenRequest::default())
        .unwrap()
        .archive()
        .entries()
        .to_vec()
}

fn tree(s: &Scratch) -> Vec<Item> {
    vec![
        s.dir("src", T0),
        s.file("src/a.txt", b"alpha\n", T0),
        s.file("src/b.txt", b"beta\n", T0),
        s.dir("src/sub", T0),
        s.file("src/sub/c.bin", &pseudo(300_000, 1), T0),
    ]
}

/// Deterministic, poorly compressible bytes.
fn pseudo(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

#[test]
fn sevenz_solid_add_replace_delete_rename() {
    let s = Scratch::new("7z-solid");
    let archive = s.path("a.7z");
    let opts = cfg_7z(true, None, false);
    create::create(&archive, &tree(&s), &opts, &NoProgress).unwrap();
    let c_bin = pseudo(300_000, 1);

    // `a` adds a new file into the solid archive without touching the others.
    let plan = update::plan_add(
        &entries_of(&archive),
        vec![s.file("new.txt", b"fresh\n", T0)],
        Replace::Always,
    );
    let out = update_7z(&archive, &plan, &opts).unwrap();
    assert!(out.changed);
    assert_eq!(
        out.repacked, 0,
        "adding must not re-encode existing folders"
    );
    assert_eq!(
        read_back(&archive, None).unwrap(),
        expect(&[
            ("src/a.txt", b"alpha\n"),
            ("src/b.txt", b"beta\n"),
            ("src/sub/c.bin", c_bin.as_slice()),
            ("new.txt", b"fresh\n"),
        ])
    );

    // `u` replaces only the file that is newer on disk.
    let plan = update::plan_add(
        &entries_of(&archive),
        vec![
            s.file("src/a.txt", b"alpha, older copy\n", T0 - 100_000_000),
            s.file("src/b.txt", b"beta, edited\n", T1),
        ],
        Replace::IfNewer,
    );
    assert_eq!(plan.counts.unchanged, 1);
    assert_eq!(plan.counts.replaced, 1);
    update_7z(&archive, &plan, &opts).unwrap();
    assert_eq!(
        read_back(&archive, None).unwrap()["src/b.txt"],
        b"beta, edited\n"
    );
    assert_eq!(read_back(&archive, None).unwrap()["src/a.txt"], b"alpha\n");

    // `d` drops one file from the solid block; the survivors are re-encoded.
    let plan = update::plan_delete(
        &entries_of(&archive),
        &Selection::new(&["src/sub/c.bin".into()], &[], &[]),
    );
    let out = update_7z(&archive, &plan, &opts).unwrap();
    assert_eq!(out.repacked, 1);
    let files = read_back(&archive, None).unwrap();
    assert!(!files.contains_key("src/sub/c.bin"));
    assert_eq!(files.len(), 3);

    // `rn` moves a directory and its contents; no data is re-encoded.
    let plan = update::plan_rename(
        &entries_of(&archive),
        &[("src".to_string(), "moved".to_string())],
    )
    .unwrap();
    let out = update_7z(&archive, &plan, &opts).unwrap();
    assert_eq!(out.repacked, 0);
    assert_eq!(
        read_back(&archive, None).unwrap(),
        expect(&[
            ("moved/a.txt", b"alpha\n"),
            ("moved/b.txt", b"beta, edited\n"),
            ("new.txt", b"fresh\n"),
        ])
    );
    assert!(names(&archive, None)
        .unwrap()
        .contains(&"moved/sub".to_string()));
}

#[test]
fn sevenz_untouched_folders_are_copied_verbatim() {
    let s = Scratch::new("7z-copy");
    let archive = s.path("n.7z");
    let items = vec![
        s.file("x.bin", &pseudo(50_000, 2), T0),
        s.file("y.bin", &pseudo(50_000, 3), T0),
        s.file("z.bin", &pseudo(50_000, 4), T0),
    ];
    let opts = cfg_7z(false, None, false);
    create::create(&archive, &items, &opts, &NoProgress).unwrap();
    let before = folder_bytes(&archive);

    let plan = update::plan_delete(
        &entries_of(&archive),
        &Selection::new(&["y.bin".into()], &[], &[]),
    );
    let out = update_7z(&archive, &plan, &opts).unwrap();
    assert_eq!(
        out.repacked, 0,
        "a folder without the deleted file is not re-encoded"
    );
    let after = folder_bytes(&archive);
    assert_eq!(after.get("x.bin"), before.get("x.bin"));
    assert_eq!(after.get("z.bin"), before.get("z.bin"));
    assert!(!after.contains_key("y.bin"));
}

/// The packed bytes of each file's folder, by file name.
fn folder_bytes(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let file = ArchiveFile::open(path, None).unwrap();
    let a = &file.archive;
    let mut out = BTreeMap::new();
    for (f, ents) in a.folder_entries.iter().enumerate() {
        let packs = file.folder_packs(f).unwrap();
        let bytes: Vec<u8> = packs.concat();
        for &i in ents {
            out.insert(a.entries[i].name.clone(), bytes.clone());
        }
    }
    out
}

#[test]
fn sevenz_encrypted_data_keeps_its_password() {
    let s = Scratch::new("7z-enc");
    let archive = s.path("e.7z");
    let opts = cfg_7z(true, Some("secret"), false);
    create::create(&archive, &tree(&s), &opts, &NoProgress).unwrap();

    let plan = update::plan_add(
        &entries_of(&archive),
        vec![s.file("new.txt", b"fresh\n", T0)],
        Replace::Always,
    );
    update_7z(&archive, &plan, &opts).unwrap();
    assert_eq!(
        read_back(&archive, Some("secret")).unwrap()["new.txt"],
        b"fresh\n"
    );

    // A wrong password stops a deletion before anything is written.
    let before = fs::read(&archive).unwrap();
    let plan = update::plan_delete(
        &entries_of(&archive),
        &Selection::new(&["src/a.txt".into()], &[], &[]),
    );
    let wrong = cfg_7z(true, Some("wrong"), false);
    let err = update_7z(&archive, &plan, &wrong).unwrap_err();
    assert!(matches!(err, Error::WrongPassword), "got {err:?}");
    assert_eq!(fs::read(&archive).unwrap(), before);

    // Without a password a deletion cannot decode the folder.
    let err = update_7z(&archive, &plan, &cfg_7z(true, None, false)).unwrap_err();
    assert!(matches!(err, Error::PasswordRequired), "got {err:?}");

    let plan = update::plan_delete(
        &entries_of(&archive),
        &Selection::new(&["src/a.txt".into()], &[], &[]),
    );
    update_7z(&archive, &plan, &opts).unwrap();
    let files = read_back(&archive, Some("secret")).unwrap();
    assert!(!files.contains_key("src/a.txt"));
    assert_eq!(files["src/b.txt"], b"beta\n");
}

#[test]
fn sevenz_encrypted_header_stays_encrypted() {
    let s = Scratch::new("7z-hdr");
    let archive = s.path("h.7z");
    let opts = cfg_7z(true, Some("secret"), true);
    create::create(&archive, &tree(&s), &opts, &NoProgress).unwrap();
    assert!(ArchiveFile::open(&archive, None).is_err());

    // The update is written without asking for `-mhe`: the header keeps its encryption.
    let plan = update::plan_add(
        &entries_of_secret(&archive),
        vec![s.file("new.txt", b"fresh\n", T0)],
        Replace::Always,
    );
    update_7z(&archive, &plan, &cfg_7z(true, Some("secret"), false)).unwrap();
    assert!(ArchiveFile::open(&archive, None).is_err());
    assert!(read_back(&archive, Some("secret"))
        .unwrap()
        .contains_key("new.txt"));
}

fn entries_of_secret(path: &Path) -> Vec<format::Entry> {
    format::open(
        path,
        &OpenRequest {
            password: Some("secret".into()),
            ..Default::default()
        },
    )
    .unwrap()
    .archive()
    .entries()
    .to_vec()
}

/// Fails on the first check after `after` polls, so an update stops in the middle.
struct CancelAfter {
    polls: AtomicUsize,
    after: usize,
}

impl Progress for CancelAfter {
    fn cancelled(&self) -> bool {
        self.polls.fetch_add(1, Ordering::Relaxed) >= self.after
    }
}

#[test]
fn sevenz_failure_mid_update_keeps_the_original() {
    let s = Scratch::new("7z-fail");
    // Three incompressible files in one solid block.
    let items = vec![
        s.file("one.bin", &pseudo(100_000, 5), T0),
        s.file("two.bin", &pseudo(100_000, 6), T0),
        s.file("three.bin", &pseudo(100_000, 7), T0),
    ];
    let opts = cfg_7z(true, None, false);

    // A damaged block: `two.bin` no longer matches its CRC once the block is decoded.
    let damaged = s.path("damaged.7z");
    create::create(&damaged, &items, &opts, &NoProgress).unwrap();
    let mut bytes = fs::read(&damaged).unwrap();
    for b in &mut bytes[32 + 150_000..32 + 150_064] {
        *b ^= 0x5A;
    }
    fs::write(&damaged, &bytes).unwrap();
    let plan = update::plan_delete(
        &entries_of(&damaged),
        &Selection::new(&["one.bin".into()], &[], &[]),
    );
    assert!(update_7z(&damaged, &plan, &opts).is_err());
    assert_eq!(fs::read(&damaged).unwrap(), bytes);
    assert_no_temp_files(&s);

    // Cancelling part way through leaves the original as it was.
    let healthy = s.path("healthy.7z");
    create::create(&healthy, &items, &opts, &NoProgress).unwrap();
    let before = fs::read(&healthy).unwrap();
    let opened = format::open(&healthy, &OpenRequest::default()).unwrap();
    let plan = update::plan_delete(
        &entries_of(&healthy),
        &Selection::new(&["three.bin".into()], &[], &[]),
    );
    let progress = CancelAfter {
        polls: AtomicUsize::new(0),
        after: 0,
    };
    let err =
        update::apply(opened, &healthy, &plan, Settings::SevenZ(&opts), &progress).unwrap_err();
    assert!(matches!(err, Error::Cancelled), "got {err:?}");
    assert_eq!(fs::read(&healthy).unwrap(), before);
    assert_no_temp_files(&s);
}

fn assert_no_temp_files(s: &Scratch) {
    for entry in fs::read_dir(&s.0).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        assert!(!name.contains(".r7z-tmp-"), "left behind: {name}");
    }
}

#[test]
fn zip_update_copies_unchanged_entries_byte_for_byte() {
    let s = Scratch::new("zip-copy");
    let archive = s.path("z.zip");
    let items = vec![
        s.file("a.txt", &pseudo(4000, 8), T0),
        s.file("b.txt", &pseudo(5000, 9), T0),
        s.file("c.txt", &pseudo(6000, 10), T0),
    ];
    write::create(&archive, Kind::Zip, &items, &cfg_other(None), &NoProgress).unwrap();
    let before = local_entries(&fs::read(&archive).unwrap());

    let plan = update::plan_delete(
        &entries_of(&archive),
        &Selection::new(&["a.txt".into()], &[], &[]),
    );
    update_other(&archive, &plan, &cfg_other(None)).unwrap();
    let after = local_entries(&fs::read(&archive).unwrap());
    assert_eq!(after.get("b.txt"), before.get("b.txt"));
    assert!(!after.contains_key("a.txt"));

    // Renaming keeps the data; only the local header changes.
    let plan = update::plan_rename(
        &entries_of(&archive),
        &[("c.txt".to_string(), "renamed/c.txt".to_string())],
    )
    .unwrap();
    update_other(&archive, &plan, &cfg_other(None)).unwrap();
    let renamed = local_entries(&fs::read(&archive).unwrap());
    let old_c = &before["c.txt"];
    let new_c = &renamed["renamed/c.txt"];
    let old_data = &old_c[30 + "c.txt".len()..];
    let new_data = &new_c[30 + "renamed/c.txt".len()..];
    assert_eq!(old_data, new_data);
    assert_eq!(
        read_back(&archive, None).unwrap(),
        expect(&[
            ("b.txt", pseudo(5000, 9).as_slice()),
            ("renamed/c.txt", pseudo(6000, 10).as_slice()),
        ])
    );

    // Adding and replacing.
    let plan = update::plan_add(
        &entries_of(&archive),
        vec![
            s.file("b.txt", b"b, newer\n", T1),
            s.file("d.txt", b"d\n", T0),
        ],
        Replace::IfNewer,
    );
    update_other(&archive, &plan, &cfg_other(None)).unwrap();
    assert_eq!(
        read_back(&archive, None).unwrap(),
        expect(&[
            ("b.txt", b"b, newer\n"),
            ("renamed/c.txt", pseudo(6000, 10).as_slice()),
            ("d.txt", b"d\n"),
        ])
    );
}

/// The bytes of each zip entry's local header and data, by name. Entries written by r7z have
/// no data descriptors, so the sizes in the local headers are exact.
fn local_entries(data: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut p = 0usize;
    while p + 30 <= data.len() && data[p..p + 4] == [0x50, 0x4B, 3, 4] {
        let u16_at = |q: usize| u16::from_le_bytes([data[q], data[q + 1]]) as usize;
        let csize = u32::from_le_bytes(data[p + 18..p + 22].try_into().unwrap()) as usize;
        let nlen = u16_at(p + 26);
        let xlen = u16_at(p + 28);
        let name = String::from_utf8_lossy(&data[p + 30..p + 30 + nlen]).into_owned();
        let end = p + 30 + nlen + xlen + csize;
        out.insert(name, data[p..end].to_vec());
        p = end;
    }
    out
}

#[test]
fn zip_aes_updates_with_the_password() {
    let s = Scratch::new("zip-aes");
    let archive = s.path("e.zip");
    let opts = cfg_other(Some("secret"));
    write::create(&archive, Kind::Zip, &tree(&s), &opts, &NoProgress).unwrap();

    let plan = update::plan_add(
        &entries_of(&archive),
        vec![s.file("new.txt", b"fresh\n", T0)],
        Replace::Always,
    );
    update_other(&archive, &plan, &opts).unwrap();
    assert_eq!(
        read_back(&archive, Some("secret")).unwrap()["new.txt"],
        b"fresh\n"
    );

    let before = fs::read(&archive).unwrap();
    let plan = update::plan_delete(
        &entries_of(&archive),
        &Selection::new(&["src/a.txt".into()], &[], &[]),
    );
    let err = update_other(&archive, &plan, &cfg_other(Some("wrong"))).unwrap_err();
    assert!(matches!(err, Error::WrongPassword), "got {err:?}");
    assert_eq!(fs::read(&archive).unwrap(), before);

    update_other(&archive, &plan, &opts).unwrap();
    assert!(!read_back(&archive, Some("secret"))
        .unwrap()
        .contains_key("src/a.txt"));
}

#[test]
fn zip64_archive_with_many_entries_updates() {
    // More entries than the 16-bit end-of-directory count holds: ZIP64 end records.
    let s = Scratch::new("zip64");
    let archive = s.path("many.zip");
    let items: Vec<Item> = (0..70_000)
        .map(|i| Item {
            src: s.path("."),
            name: format!("d{i}"),
            is_dir: true,
            size: 0,
            mtime: Some(T0),
            ctime: None,
            atime: None,
            attrib: Some(0x10),
        })
        .collect();
    write::create(&archive, Kind::Zip, &items, &cfg_other(None), &NoProgress).unwrap();
    assert_eq!(entries_of(&archive).len(), 70_000);

    let plan = update::plan_delete(
        &entries_of(&archive),
        &Selection::new(&["d5".into()], &[], &[]),
    );
    let plan = {
        let mut p = plan;
        p.add.push(s.file("new.txt", b"new\n", T0));
        p.counts.added += 1;
        p
    };
    update_other(&archive, &plan, &cfg_other(None)).unwrap();
    let names = names(&archive, None).unwrap();
    assert_eq!(names.len(), 70_000);
    assert!(!names.contains(&"d5".to_string()));
    assert!(names.contains(&"new.txt".to_string()));
    assert_eq!(read_back(&archive, None).unwrap()["new.txt"], b"new\n");
}

#[test]
fn tar_family_updates_in_every_compression() {
    let kinds = [
        ("plain.tar", Kind::Tar),
        ("gz.tar.gz", Kind::TarIn(Compressor::Gzip)),
        ("bz.tar.bz2", Kind::TarIn(Compressor::Bzip2)),
        ("xz.tar.xz", Kind::TarIn(Compressor::Xz)),
    ];
    for (file, kind) in kinds {
        let s = Scratch::new(file);
        let archive = s.path(file);
        write::create(&archive, kind, &tree(&s), &cfg_other(None), &NoProgress).unwrap();
        let original = read_back(&archive, None).unwrap();

        let plan = update::plan_add(
            &entries_of(&archive),
            vec![
                s.file("src/a.txt", b"alpha, replaced\n", T1),
                s.file("new.txt", b"fresh\n", T0),
            ],
            Replace::IfNewer,
        );
        update_other(&archive, &plan, &cfg_other(None)).unwrap();
        let files = read_back(&archive, None).unwrap();
        assert_eq!(files["src/a.txt"], b"alpha, replaced\n", "{file}");
        assert_eq!(files["new.txt"], b"fresh\n", "{file}");
        assert_eq!(files["src/b.txt"], original["src/b.txt"], "{file}");

        let plan = update::plan_delete(
            &entries_of(&archive),
            &Selection::new(&["src/sub/c.bin".into()], &[], &[]),
        );
        update_other(&archive, &plan, &cfg_other(None)).unwrap();
        assert!(!read_back(&archive, None)
            .unwrap()
            .contains_key("src/sub/c.bin"));

        // A long name only a pax header can carry.
        let long = format!("{}/renamed.txt", "deep/".repeat(40).trim_end_matches('/'));
        let plan = update::plan_rename(
            &entries_of(&archive),
            &[("src/b.txt".to_string(), long.clone())],
        )
        .unwrap();
        update_other(&archive, &plan, &cfg_other(None)).unwrap();
        let files = read_back(&archive, None).unwrap();
        assert_eq!(files[&long], b"beta\n", "{file}");
        assert!(!files.contains_key("src/b.txt"), "{file}");
        assert_eq!(files["src/a.txt"], b"alpha, replaced\n", "{file}");
    }
}

#[test]
fn single_stream_gzip_replaces_and_renames_its_file() {
    let s = Scratch::new("gz");
    let archive = s.path("one.gz");
    let items = vec![s.file("notes.txt", b"first\n", T0)];
    write::create(
        &archive,
        Kind::Single(Compressor::Gzip),
        &items,
        &cfg_other(None),
        &NoProgress,
    )
    .unwrap();

    let plan = update::plan_add(
        &entries_of(&archive),
        vec![s.file("other.txt", b"second\n", T1)],
        Replace::Always,
    );
    update_other(&archive, &plan, &cfg_other(None)).unwrap();
    assert_eq!(
        read_back(&archive, None).unwrap(),
        expect(&[("other.txt", b"second\n")])
    );

    let plan = update::plan_rename(
        &entries_of(&archive),
        &[("other.txt".to_string(), "renamed.txt".to_string())],
    )
    .unwrap();
    update_other(&archive, &plan, &cfg_other(None)).unwrap();
    assert_eq!(
        read_back(&archive, None).unwrap(),
        expect(&[("renamed.txt", b"second\n")])
    );

    // The only file of a single-stream archive cannot be deleted.
    let plan = update::plan_delete(
        &entries_of(&archive),
        &Selection::new(&["renamed.txt".into()], &[], &[]),
    );
    assert!(matches!(
        update_other(&archive, &plan, &cfg_other(None)),
        Err(Error::Usage(_))
    ));
}

#[test]
fn planning_rejects_bad_renames_and_empty_deletes() {
    let s = Scratch::new("plan");
    let archive = s.path("p.zip");
    let items = vec![s.file("a", b"1", T0), s.file("b", b"2", T0)];
    write::create(&archive, Kind::Zip, &items, &cfg_other(None), &NoProgress).unwrap();
    let list = entries_of(&archive);
    // Renaming onto an existing name.
    assert!(update::plan_rename(&list, &[("a".into(), "b".into())]).is_err());
    // A pair that matches nothing.
    assert!(update::plan_rename(&list, &[("zzz".into(), "y".into())]).is_err());
    // Deleting nothing shows in the counts.
    let none = update::plan_delete(&list, &Selection::new(&["nope".into()], &[], &[]));
    assert_eq!(none.counts.deleted, 0);
    // A wildcard renames every match, keeping the text the wildcard matched.
    let plan = update::plan_rename(&list, &[("?".into(), "x-*".into())]).unwrap();
    assert_eq!(plan.counts.renamed, 2);
    assert_eq!(plan.fates[0], update::Fate::Rename("x-a".into()));
}

#[test]
fn cli_adds_updates_deletes_and_renames() {
    let s = Scratch::new("cli");
    let src = s.path("src");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("one.txt"), b"one\n").unwrap();
    fs::write(src.join("sub/two.txt"), b"two\n").unwrap();
    let archive = s.path("cli.7z");
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_r7z"))
            .current_dir(&s.0)
            .args(args)
            .output()
            .unwrap()
    };
    let out = run(&["a", "cli.7z", "src", "-bd"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    fs::write(s.path("extra.txt"), b"extra\n").unwrap();
    let out = run(&["a", "cli.7z", "extra.txt", "-bd"]);
    assert!(out.status.success());
    let out = run(&["d", "cli.7z", "src/sub/two.txt", "-bd"]);
    assert!(out.status.success());
    let out = run(&["rn", "cli.7z", "src/one.txt", "uno.txt", "-bd"]);
    assert!(out.status.success());
    // Nothing matches: a usage error, and the archive is untouched.
    let before = fs::read(&archive).unwrap();
    let out = run(&["rn", "cli.7z", "missing", "x", "-bd"]);
    assert_eq!(out.status.code(), Some(7));
    assert_eq!(fs::read(&archive).unwrap(), before);

    assert_eq!(
        read_back(&archive, None).unwrap(),
        expect(&[("uno.txt", b"one\n"), ("extra.txt", b"extra\n")])
    );
    let out = run(&["t", "cli.7z"]);
    assert!(out.status.success());
}
