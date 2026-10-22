//! Disk images through the format registry: virtual disks (VHD, VHDX, VMDK, QCOW2), partition
//! tables (MBR, GPT) and file systems (FAT, exFAT, NTFS, ext). Inputs are built in memory by
//! `build.rs`, or are the committed fixtures in tests/fixtures/disk:
//!
//! - the FAT, MBR, GPT, VHD, VHDX, VMDK and QCOW2 fixtures are written from build.rs by
//!   `cargo test --test disk -- --ignored regenerate_fixtures`;
//! - `ntfs-testfs1.img.gz` is the `testfs1` image of ColinFinck/ntfs (Apache-2.0,
//!   testdata/testfs1 at commit 47ae0168f6c607208b27c61ed89b4ffac9a3c99a, sha256
//!   e3612c18...4eb9, made by testdata/create-testfs1.sh with mkntfs -c 512);
//! - the `ext*.img.gz` images come from tests/fixtures/disk/make_ext.sh (e2fsprogs 1.46.5).
//!
//! Every result here was also checked against 7-Zip 25.01 where it reads the format.

mod build;

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use build as b;
use r7z::format::{self, Archive, Ctx, Flow, Link, OpenRequest, Opened};
use r7z::Error;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/disk")
}

fn fixture(name: &str) -> Vec<u8> {
    fs::read(fixtures().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn open(data: Vec<u8>, name: &str) -> r7z::Result<Opened> {
    format::open_bytes(data, name, &OpenRequest::default())
}

/// The format of each level, outermost first.
fn types(o: &Opened) -> Vec<&'static str> {
    o.levels.iter().map(|l| l.archive.format().name).collect()
}

/// Every unit's bytes, by entry name.
fn contents(a: &dyn Archive) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    for u in 0..a.units().len() {
        a.extract_unit(u, &Ctx::default(), &mut |i, r| {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(Error::from)?;
            out.insert(a.entries()[i].name.clone(), v);
            Ok(Flow::Continue)
        })
        .unwrap();
    }
    out
}

fn names(a: &dyn Archive) -> Vec<String> {
    a.entries().iter().map(|e| e.name.clone()).collect()
}

fn prop(a: &dyn Archive, key: &str) -> Option<String> {
    a.properties()
        .into_iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
}

/// The files of a FAT or exFAT volume built by build.rs.
fn check_volume_files(a: &dyn Archive) {
    let got = contents(a);
    assert_eq!(
        got.get("HELLO.TXT").map(Vec::as_slice),
        Some(b::HELLO),
        "HELLO.TXT"
    );
    assert_eq!(
        got.get(b::LONG_NAME).map(Vec::as_slice),
        Some(b::LONG),
        "long name"
    );
    assert_eq!(
        got.get("SUB/NESTED.TXT").map(Vec::as_slice),
        Some(b::NESTED),
        "SUB/NESTED.TXT"
    );
    let entries = a.entries();
    assert!(entries.iter().any(|e| e.name == "SUB" && e.is_dir));
}

// ---------------------------------------------------------------------------------------
// File systems on their own

#[test]
fn fat12_fixture_has_long_names_and_a_nested_folder() {
    let o = open(fixture("fat12-floppy.img.gz"), "fat12-floppy.img.gz").unwrap();
    assert_eq!(types(&o), ["gzip", "FAT"]);
    let a = o.archive();
    assert_eq!(prop(a, "File System").as_deref(), Some("FAT12"));
    check_volume_files(a);
}

#[test]
fn fat16_and_fat32_volumes_round_trip() {
    for (bits, sectors) in [(16u8, 16384usize), (32, 70_000)] {
        let vol = b::fat_volume(bits, sectors, 1);
        let o = open(vol, "volume.img").unwrap();
        let a = o.archive();
        assert_eq!(prop(a, "File System").unwrap(), format!("FAT{bits}"));
        check_volume_files(a);
    }
}

#[test]
fn real_fat16_and_fat32_images_from_mkfs() {
    // rust-fatfs's test images (MIT), made by mkfs.fat: long names, a 14000-byte file and
    // nested folders. 7-Zip extracts them byte for byte the same.
    for file in ["fat16-mkfs.img.gz", "fat32-mkfs.img.gz"] {
        let o = open(fixture(file), file).unwrap();
        assert_eq!(types(&o), ["gzip", "FAT"], "{file}");
        let got = contents(o.archive());
        assert_eq!(got["long.txt"].len(), 14000, "{file}");
        assert_eq!(got["short.txt"].len(), 14, "{file}");
        assert_eq!(got["very/long/path/test.txt"].len(), 14, "{file}");
        assert_eq!(
            got["very-long-dir-name/very-long-file-name.txt"].len(),
            14,
            "{file}"
        );
    }
}

#[test]
fn exfat_volume_round_trips_files_and_folders() {
    let o = open(b::exfat_volume(512), "volume.img").unwrap();
    assert_eq!(types(&o), ["exFAT"]);
    check_volume_files(o.archive());
}

#[test]
fn ntfs_testfs1_sample_has_the_expected_files() {
    let o = open(fixture("ntfs-testfs1.img.gz"), "ntfs-testfs1.img.gz").unwrap();
    assert_eq!(types(&o), ["gzip", "NTFS"]);
    let a = o.archive();
    let got = contents(a);
    assert_eq!(got["file-with-12345"], b"12345");
    assert_eq!(got["1000-bytes-file"], b"12345".repeat(200));
    assert!(got["empty-file"].is_empty());
    // Sparse: data at the start and at byte 500000, zeros between.
    let sparse = &got["sparse-file"];
    assert_eq!(sparse.len(), 500_005);
    assert_eq!(&sparse[..5], b"12345");
    assert!(sparse[5..500_000].iter().all(|&x| x == 0));
    assert_eq!(&sparse[500_000..], b"11111");
    // Directories with an index that needs INDEX_ALLOCATION blocks.
    let names = names(a);
    assert!(names.iter().any(|n| n == "many_subdirs/512"));
    assert!(names.iter().any(|n| n == "$MFT"));
}

fn pattern(text: &str, len: usize) -> Vec<u8> {
    text.as_bytes().iter().copied().cycle().take(len).collect()
}

#[test]
fn ext_fixtures_match_the_tree_they_were_made_from() {
    let big = pattern("indirect block data 0123456789\n", 102_400);
    let mut sparse = vec![0u8; 1 << 20];
    for i in 0..16 {
        let line = format!("page {i}\n");
        sparse[i * 16_384..i * 16_384 + 4096].copy_from_slice(&pattern(&line, 4096));
    }
    for name in [
        "ext2-indirect",
        "ext3-journal",
        "ext4-extents",
        "ext4-inline",
    ] {
        let file = format!("{name}.img.gz");
        let o = open(fixture(&file), &file).unwrap();
        assert_eq!(types(&o), ["gzip", "Ext"], "{name}");
        let a = o.archive();
        let got = contents(a);
        assert_eq!(got["big.txt"], big, "{name}: big.txt (indirect blocks)");
        // The inline image is made without the sparse file (see make_ext.sh).
        if name != "ext4-inline" {
            assert_eq!(got["sparse.bin"], sparse, "{name}: sparse.bin");
        }
        assert_eq!(got["small.txt"], b"short\n");
        // Inline data: 12 bytes in the inode, and 100 bytes with 40 in an extended attribute.
        assert_eq!(got["tiny.txt"], b"tiny inline\n");
        assert_eq!(got["medium.txt"], vec![b'q'; 100]);
        assert!(got["dir/sub/empty"].is_empty());
        let fast = a.entries().iter().find(|e| e.name == "fast-link").unwrap();
        assert_eq!(fast.link, Some(Link::Symbolic("small.txt".into())));
        assert_eq!(got["fast-link"], b"small.txt");
        let slow = a.entries().iter().find(|e| e.name == "slow-link").unwrap();
        assert_eq!(slow.link, Some(Link::Symbolic("a".repeat(100))));
    }
}

// ---------------------------------------------------------------------------------------
// Partition tables

#[test]
fn mbr_partitions_are_listed_and_named_like_seven_zip() {
    let vol = b::fat_volume(12, 128, 1);
    let o = open(b::mbr_disk(&vol), "disk.img").unwrap();
    assert_eq!(types(&o), ["MBR", "FAT"]);

    let o = open(fixture("mbr-fat12.img.gz"), "mbr-fat12.img.gz").unwrap();
    assert_eq!(types(&o), ["gzip", "MBR", "FAT"]);
    check_volume_files(o.archive());

    let junk = vec![0x5Au8; 2048];
    let o = open(b::mbr_extended_disk(&vol, &junk), "disk.img").unwrap();
    assert_eq!(types(&o), ["MBR"]);
    assert_eq!(names(o.archive()), ["0.fat", "1.fat", "2.img"]);
    assert_eq!(contents(o.archive())["2.img"], junk);
}

#[test]
fn gpt_partitions_carry_their_labels() {
    let vol = b::fat_volume(12, 128, 1);
    let o = open(fixture("gpt-fat12.img.gz"), "gpt-fat12.img.gz").unwrap();
    assert_eq!(types(&o), ["gzip", "GPT", "FAT"]);
    check_volume_files(o.archive());

    let junk = vec![0xA5u8; 4096];
    let o = open(
        b::gpt_disk(&[
            ("Basic data partition", b::BASIC_DATA, &vol),
            ("", b::LINUX_DATA, &junk),
        ]),
        "disk.img",
    )
    .unwrap();
    assert_eq!(types(&o), ["GPT"]);
    assert_eq!(names(o.archive()), ["0.Basic data partition.fat", "1.img"]);
    assert_eq!(contents(o.archive())["1.img"], junk);
}

// ---------------------------------------------------------------------------------------
// Virtual disks

#[test]
fn virtual_disks_hold_the_same_file_system() {
    let vol = b::fat_volume(12, 128, 1);
    let disk = b::mbr_disk(&vol);
    let cases: Vec<(&str, Vec<u8>, &[&str])> = vec![
        ("fixed.vhd", b::vhd_fixed(&disk), &["VHD", "MBR", "FAT"]),
        (
            "dynamic.vhd",
            b::vhd_dynamic(&disk, 65536),
            &["VHD", "MBR", "FAT"],
        ),
        ("disk.vhdx", b::vhdx(&disk, false), &["VHDX", "MBR", "FAT"]),
        (
            "disk.vmdk",
            b::vmdk_sparse(&disk, false),
            &["VMDK", "MBR", "FAT"],
        ),
        (
            "stream.vmdk",
            b::vmdk_sparse(&disk, true),
            &["VMDK", "MBR", "FAT"],
        ),
        (
            "plain.qcow2",
            b::qcow2(&disk, &[], &[], None),
            &["QCOW2", "MBR", "FAT"],
        ),
        (
            "zlib.qcow2",
            b::qcow2(&disk, &[0, 3, 5], &[], None),
            &["QCOW2", "MBR", "FAT"],
        ),
    ];
    for (name, data, want) in cases {
        let o = open(data, name).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(types(&o), want, "{name}");
        check_volume_files(o.archive());
    }
}

#[test]
fn virtual_disk_fixtures_hold_the_same_file_system() {
    for name in [
        "vhd-fixed.vhd.gz",
        "vhd-dynamic.vhd.gz",
        "vhdx.vhdx.gz",
        "vmdk-sparse.vmdk.gz",
        "vmdk-stream.vmdk.gz",
        "qcow2-plain.qcow2.gz",
        "qcow2-zlib.qcow2.gz",
    ] {
        let o = open(fixture(name), name).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(types(&o).contains(&"FAT"), "{name}: {:?}", types(&o));
        check_volume_files(o.archive());
    }
    // A descriptor names its flat extent beside it.
    let dir = scratch("descriptor");
    fs::write(dir.join("vmdk-flat.vmdk"), fixture("vmdk-flat.vmdk")).unwrap();
    fs::write(
        dir.join("vmdk-flat-extent-flat.vmdk"),
        fixture("vmdk-flat-extent-flat.vmdk"),
    )
    .unwrap();
    let o = format::open(&dir.join("vmdk-flat.vmdk"), &OpenRequest::default()).unwrap();
    assert_eq!(types(&o)[..2], ["VMDK", "MBR"]);
    check_volume_files(o.archive());
    let _ = fs::remove_dir_all(&dir);
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("r7z-disk-{}-{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn differencing_vhd_without_its_parent_is_a_clear_error() {
    let child = b::vhd_diff(1 << 20, "base.vhd");
    let err = open(child, "child.vhd")
        .err()
        .expect("opened without its parent");
    let msg = err.to_string();
    assert!(msg.contains("parent"), "{msg}");
}

#[test]
fn differencing_vhd_reads_unstored_sectors_from_its_parent() {
    let vol = b::fat_volume(12, 128, 1);
    let disk = b::mbr_disk(&vol);
    let dir = scratch("diff");
    fs::write(dir.join("base.vhd"), b::vhd_dynamic(&disk, 65536)).unwrap();
    fs::write(
        dir.join("child.vhd"),
        b::vhd_diff(disk.len() as u64, "base.vhd"),
    )
    .unwrap();
    let o = format::open(&dir.join("child.vhd"), &OpenRequest::default()).unwrap();
    assert_eq!(types(&o), ["VHD", "MBR", "FAT"]);
    check_volume_files(o.archive());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn qcow2_backing_file_is_listed_and_its_clusters_are_refused() {
    let disk = b::mbr_disk(&b::fat_volume(12, 128, 1));
    let data = b::qcow2(&disk, &[], &[0], Some("base.qcow2"));
    let o = open(data, "layer.qcow2").unwrap();
    let qcow = o.levels.last().unwrap().archive.clone();
    assert_eq!(qcow.format().name, "QCOW2");
    assert_eq!(prop(&*qcow, "Backing File").as_deref(), Some("base.qcow2"));
    let err = qcow
        .extract_unit(0, &Ctx::default(), &mut |_, r| {
            let mut v = Vec::new();
            r.read_to_end(&mut v).map_err(Error::from)?;
            Ok(Flow::Continue)
        })
        .expect_err("read an unstored cluster");
    assert!(err.to_string().contains("base.qcow2"), "{err}");
}

#[test]
fn vhdx_with_an_unreplayed_log_is_refused() {
    let disk = b::mbr_disk(&b::fat_volume(12, 128, 1));
    let err = open(b::vhdx(&disk, true), "log.vhdx")
        .err()
        .expect("opened a dirty log");
    assert!(err.to_string().to_lowercase().contains("log"), "{err}");
}

#[test]
fn sparse_virtual_disk_reads_zeros_without_storing_them() {
    // A terabyte of unallocated blocks: only the allocation table is in the file.
    let size = 1u64 << 40;
    let data = b::vhd_sparse(size, 1 << 20);
    assert!(data.len() < 8 << 20, "the table is {} bytes", data.len());
    let o = open(data, "huge.vhd").unwrap();
    let disk = o.levels.last().unwrap().archive.clone();
    assert_eq!(disk.entries()[0].size, Some(size));
    // Read a megabyte far into the disk, straight from the image source.
    let src = disk.volume(0).unwrap();
    let mut buf = vec![0xFFu8; 1 << 20];
    src.read_at(500 << 30, &mut buf).unwrap();
    assert!(buf.iter().all(|&x| x == 0));
}

// ---------------------------------------------------------------------------------------
// Damage: truncations and bit flips never panic

/// The raw images whose damage is checked: name and bytes.
fn damage_inputs() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let vol = b::fat_volume(12, 128, 1);
    let disk = b::mbr_disk(&vol);
    out.push(("disk.img".to_string(), disk.clone()));
    out.push(("fixed.vhd".to_string(), b::vhd_fixed(&disk)));
    out.push(("dynamic.vhd".to_string(), b::vhd_dynamic(&disk, 65536)));
    out.push(("vmdk.vmdk".to_string(), b::vmdk_sparse(&disk, false)));
    out.push(("stream.vmdk".to_string(), b::vmdk_sparse(&disk, true)));
    out.push((
        "zlib.qcow2".to_string(),
        b::qcow2(&disk, &[0, 3], &[], None),
    ));
    out.push(("exfat.img".to_string(), b::exfat_volume(512)));
    out.push((
        "gpt.img".to_string(),
        b::gpt_disk(&[("", b::BASIC_DATA, &vol)]),
    ));
    out.push((
        "extended.img".to_string(),
        b::mbr_extended_disk(&vol, &[7u8; 1024]),
    ));
    out
}

fn damaged_open(data: Vec<u8>, name: &str) {
    if let Ok(o) = open(data, name) {
        for lvl in &o.levels {
            let a = &*lvl.archive;
            for u in 0..a.units().len() {
                let _ = a.extract_unit(u, &Ctx::default(), &mut |_, r| {
                    let mut v = Vec::new();
                    r.read_to_end(&mut v).map_err(Error::from)?;
                    Ok(Flow::Continue)
                });
            }
        }
    }
}

#[test]
fn truncated_disk_images_never_panic() {
    for (name, data) in damage_inputs() {
        let step = (data.len() / 256).max(1);
        for len in (0..data.len()).step_by(step) {
            damaged_open(data[..len].to_vec(), &name);
        }
        damaged_open(data[..data.len() - 1].to_vec(), &name);
    }
}

#[test]
fn bit_flipped_disk_images_never_panic() {
    for (name, data) in damage_inputs() {
        // Every byte of the first KiB (the headers), then a sample of the rest.
        let positions = (0..data.len()).filter(|&i| i < 1024 || i % 503 == 0);
        for i in positions {
            for bit in [0x01u8, 0x80] {
                let mut d = data.clone();
                d[i] ^= bit;
                damaged_open(d, &name);
            }
        }
    }
}

#[test]
fn fixtures_survive_truncation_and_flips() {
    for name in ["mbr-fat12.img.gz", "gpt-two.img.gz", "vhd-dynamic.vhd.gz"] {
        let raw = gunzip(&fixture(name));
        let inner = name.trim_end_matches(".gz");
        for len in (0..raw.len()).step_by((raw.len() / 128).max(1)) {
            damaged_open(raw[..len].to_vec(), inner);
        }
        for i in (0..raw.len()).step_by((raw.len() / 512).max(1)) {
            let mut d = raw.clone();
            d[i] ^= 0x10;
            damaged_open(d, inner);
        }
    }
}

fn gunzip(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(gz)
        .read_to_end(&mut out)
        .unwrap();
    out
}

// ---------------------------------------------------------------------------------------
// Fixture regeneration (run by hand; the committed fixtures come from here)

#[test]
#[ignore = "writes tests/fixtures/disk; run with --ignored"]
fn regenerate_fixtures() {
    let dir = fixtures();
    let put = |name: &str, data: &[u8]| {
        fs::write(dir.join(name), data).unwrap();
        println!("{name} {}", data.len());
    };
    let vol = b::fat_volume(12, 128, 1);
    let junk = vec![0xA5u8; 4096];
    let disk = b::mbr_disk(&vol);
    put("fat12-floppy.img.gz", &b::gzip(&vol));
    put("mbr-fat12.img.gz", &b::gzip(&disk));
    put(
        "mbr-extended.img.gz",
        &b::gzip(&b::mbr_extended_disk(&vol, &junk)),
    );
    put(
        "gpt-fat12.img.gz",
        &b::gzip(&b::gpt_disk(&[(
            "Basic data partition",
            b::BASIC_DATA,
            &vol,
        )])),
    );
    put(
        "gpt-two.img.gz",
        &b::gzip(&b::gpt_disk(&[
            ("Basic data partition", b::BASIC_DATA, &vol),
            ("", b::LINUX_DATA, &junk),
        ])),
    );
    put("fat16.img.gz", &b::gzip(&b::fat_volume(16, 16384, 1)));
    // fat16-mkfs and fat32-mkfs are rust-fatfs's images (commit 38b3a79, MIT), not built here.
    put("exfat.img.gz", &b::gzip(&b::exfat_volume(512)));
    put("vhd-fixed.vhd.gz", &b::gzip(&b::vhd_fixed(&disk)));
    put(
        "vhd-dynamic.vhd.gz",
        &b::gzip(&b::vhd_dynamic(&disk, 65536)),
    );
    put("vhdx.vhdx.gz", &b::gzip(&b::vhdx(&disk, false)));
    put(
        "vmdk-sparse.vmdk.gz",
        &b::gzip(&b::vmdk_sparse(&disk, false)),
    );
    put(
        "vmdk-stream.vmdk.gz",
        &b::gzip(&b::vmdk_sparse(&disk, true)),
    );
    put(
        "qcow2-plain.qcow2.gz",
        &b::gzip(&b::qcow2(&disk, &[], &[], None)),
    );
    put(
        "qcow2-zlib.qcow2.gz",
        &b::gzip(&b::qcow2(&disk, &[0, 3, 5], &[], None)),
    );
    put(
        "qcow2-backing.qcow2.gz",
        &b::gzip(&b::qcow2(&disk, &[], &[0], Some("base.qcow2"))),
    );
    // A descriptor names its flat extent beside it, so this pair is stored as it is.
    put("vmdk-flat-extent-flat.vmdk", &disk);
    put(
        "vmdk-flat.vmdk",
        &b::vmdk_descriptor("vmdk-flat-extent-flat.vmdk", disk.len() / 512),
    );
}
