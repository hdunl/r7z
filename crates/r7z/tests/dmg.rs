//! Apple disk image (UDIF) tests. Images are built here by a test-only writer that stores
//! chunks in every supported codec, so no image fixtures are committed.

use std::collections::HashMap;
use std::io::{Read, Write};

use r7z::codec::{adc, lzfse};
use r7z::format::{open_bytes, Archive, Ctx, Flow, OpenRequest, Opened};
use r7z::Error;

const SECTOR: usize = 512;

/// The chunk kinds the writer can emit.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Raw,
    Zero,
    Zlib,
    Bzip2,
    Adc,
    Lzfse,
    /// A chunk type this reader does not know.
    Unknown,
}

/// The mix of kinds for a multi-codec image.
const MIXED: &[Kind] = &[
    Kind::Raw,
    Kind::Zlib,
    Kind::Zero,
    Kind::Bzip2,
    Kind::Adc,
    Kind::Lzfse,
];

fn be32(out: &mut [u8], at: usize, v: u32) {
    out[at..at + 4].copy_from_slice(&v.to_be_bytes());
}

fn be64(out: &mut [u8], at: usize, v: u64) {
    out[at..at + 8].copy_from_slice(&v.to_be_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for k in 0..4 {
            if k <= c.len() {
                s.push(T[((n >> (18 - 6 * k)) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

/// A greedy ADC encoder: literal runs, short copies (3 to 18 bytes, distance below 1024),
/// and long copies (4 to 67 bytes, distance below 65536), found through a hash chain.
fn adc_encode(data: &[u8]) -> Vec<u8> {
    fn flush(out: &mut Vec<u8>, lits: &mut Vec<u8>) {
        for run in lits.chunks(128) {
            out.push(0x80 | (run.len() - 1) as u8);
            out.extend_from_slice(run);
        }
        lits.clear();
    }
    let mut out = Vec::new();
    let mut lits = Vec::new();
    let mut heads: HashMap<[u8; 3], Vec<usize>> = HashMap::new();
    let mut i = 0;
    while i < data.len() {
        let mut best = (0usize, 0usize);
        if i + 3 <= data.len() {
            if let Some(cands) = heads.get(&[data[i], data[i + 1], data[i + 2]]) {
                let max = 67.min(data.len() - i);
                for &j in cands.iter().rev().take(64) {
                    let dist = i - j;
                    if dist > 65536 {
                        break;
                    }
                    let len = (0..max).take_while(|&k| data[j + k] == data[i + k]).count();
                    if len > best.0 {
                        best = (len, dist);
                    }
                }
            }
        }
        let (len, dist) = best;
        let step = if len >= 3 && dist <= 1024 && len <= 18 {
            flush(&mut out, &mut lits);
            let offset = dist - 1;
            out.push((((len - 3) << 2) | (offset >> 8)) as u8);
            out.push((offset & 0xFF) as u8);
            len
        } else if len >= 4 {
            flush(&mut out, &mut lits);
            let offset = dist - 1;
            out.push(0x40 | (len - 4) as u8);
            out.extend_from_slice(&(offset as u16).to_be_bytes());
            len
        } else {
            lits.push(data[i]);
            1
        };
        for p in i..i + step {
            if p + 3 <= data.len() {
                heads
                    .entry([data[p], data[p + 1], data[p + 2]])
                    .or_default()
                    .push(p);
            }
        }
        i += step;
    }
    flush(&mut out, &mut lits);
    out
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn bzip2(data: &[u8]) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn lzfse(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    lzfse_rust::encode_bytes(data, &mut out).unwrap();
    out
}

/// A block table (`mish`) for partition `index`, which starts at disk sector `first` and
/// has `sectors` sectors. `runs` holds (type, first sector, sector count, compressed offset,
/// compressed length), with sector numbers relative to the partition.
fn mish(
    index: usize,
    first: u64,
    sectors: u64,
    checksum: u32,
    runs: &[(u32, u64, u64, u64, u64)],
) -> Vec<u8> {
    let mut m = vec![0u8; 204 + 40 * runs.len()];
    m[..4].copy_from_slice(b"mish");
    be32(&mut m, 4, 1);
    be64(&mut m, 8, first);
    be64(&mut m, 16, sectors);
    be32(&mut m, 32, 2056);
    be32(&mut m, 36, index as u32);
    be32(&mut m, 64, 2);
    be32(&mut m, 68, 32);
    be32(&mut m, 72, checksum);
    be32(&mut m, 200, runs.len() as u32);
    for (i, &(kind, first, count, off, len)) in runs.iter().enumerate() {
        let at = 204 + 40 * i;
        be32(&mut m, at, kind);
        be64(&mut m, at + 8, first);
        be64(&mut m, at + 16, count);
        be64(&mut m, at + 24, off);
        be64(&mut m, at + 32, len);
    }
    m
}

/// Builds a UDIF image of the named partitions. Chunk `c` of each partition uses
/// `kinds[c % kinds.len()]`, and a chunk that is not all zeros is stored raw in place of a
/// zero chunk.
fn build(parts: &[(&str, Vec<u8>)], kinds: &[Kind], chunk_sectors: usize) -> Vec<u8> {
    let mut fork = Vec::new();
    let mut blocks: Vec<(String, Vec<u8>)> = Vec::new();
    let mut disk = 0u64;
    for (pi, (name, data)) in parts.iter().enumerate() {
        let mut padded = data.clone();
        padded.resize(data.len().div_ceil(SECTOR) * SECTOR, 0);
        let sectors = (padded.len() / SECTOR) as u64;
        let mut runs = Vec::new();
        let mut first = 0u64;
        for (ci, chunk) in padded.chunks(chunk_sectors * SECTOR).enumerate() {
            let count = (chunk.len() / SECTOR) as u64;
            let mut kind = kinds[(pi + ci) % kinds.len()];
            if matches!(kind, Kind::Zero) && chunk.iter().any(|&b| b != 0) {
                kind = Kind::Raw;
            }
            let (typ, packed): (u32, Vec<u8>) = match kind {
                Kind::Raw => (1, chunk.to_vec()),
                Kind::Zero => (2, Vec::new()),
                Kind::Zlib => (0x8000_0005, zlib(chunk)),
                Kind::Bzip2 => (0x8000_0006, bzip2(chunk)),
                Kind::Adc => (0x8000_0004, adc_encode(chunk)),
                Kind::Lzfse => (0x8000_0007, lzfse(chunk)),
                Kind::Unknown => (0x8000_0008, Vec::new()),
            };
            let off = fork.len() as u64;
            runs.push((typ, first, count, off, packed.len() as u64));
            fork.extend_from_slice(&packed);
            first += count;
        }
        runs.push((0xFFFF_FFFF, first, 0, fork.len() as u64, 0));
        blocks.push((
            name.to_string(),
            mish(pi, disk, sectors, crc32(&padded), &runs),
        ));
        disk += sectors;
    }

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"x.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n<key>resource-fork</key>\n<dict>\n\
         <key>blkx</key>\n<array>\n",
    );
    for (i, (name, table)) in blocks.iter().enumerate() {
        let data: String = base64(table)
            .as_bytes()
            .chunks(68)
            .map(|l| format!("{}\n", std::str::from_utf8(l).unwrap()))
            .collect();
        xml += &format!(
            "<dict>\n<key>Attributes</key>\n<string>0x0050</string>\n\
             <key>CFName</key>\n<string>{name}</string>\n\
             <key>Data</key>\n<data>\n{data}</data>\n\
             <key>ID</key>\n<string>{i}</string>\n\
             <key>Name</key>\n<string>{name}</string>\n</dict>\n"
        );
    }
    xml += "</array>\n</dict>\n</dict>\n</plist>\n";

    let xml_at = fork.len();
    let mut image = fork.clone();
    image.extend_from_slice(xml.as_bytes());

    let mut koly = vec![0u8; 512];
    koly[..4].copy_from_slice(b"koly");
    be32(&mut koly, 4, 4);
    be32(&mut koly, 8, 512);
    be32(&mut koly, 12, 1);
    be64(&mut koly, 32, fork.len() as u64);
    be32(&mut koly, 56, 1);
    be32(&mut koly, 60, 1);
    be32(&mut koly, 80, 2);
    be32(&mut koly, 84, 32);
    be32(&mut koly, 88, crc32(&fork));
    be64(&mut koly, 216, xml_at as u64);
    be64(&mut koly, 224, xml.len() as u64);
    be64(&mut koly, 492, disk);
    image.extend_from_slice(&koly);
    image
}

/// Deterministic test bytes: text, noise and zeros in runs of `run` bytes.
fn sample(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let text = b"the quick brown fox jumps over the lazy dog; ";
    (0..len)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            match (i / 1500) % 4 {
                0 => (x >> 24) as u8,
                1 => text[i % text.len()],
                2 => 0,
                _ => (i % 251) as u8,
            }
        })
        .collect()
}

fn open(bytes: Vec<u8>) -> r7z::Result<Opened> {
    open_bytes(bytes, "test.dmg", &OpenRequest::default())
}

fn open_ok(bytes: Vec<u8>) -> Opened {
    match open(bytes) {
        Ok(o) => o,
        Err(e) => panic!("open failed: {e}"),
    }
}

/// Every byte of unit `unit`, read through the extraction path.
fn extract(a: &dyn Archive, unit: usize) -> r7z::Result<Vec<u8>> {
    let mut out = Vec::new();
    a.extract_unit(unit, &Ctx::default(), &mut |_, r: &mut dyn Read| {
        r.read_to_end(&mut out)?;
        Ok(Flow::Continue)
    })?;
    Ok(out)
}

fn three_partitions(seed: u64) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("Apple_partition_map", sample(2048, seed)),
        ("Apple_HFS", sample(30 * SECTOR + 77, seed + 1)),
        ("Apple_Free", vec![0u8; 17 * SECTOR]),
    ]
}

#[test]
fn lists_partitions_and_selects_the_hfs_volume() {
    let parts = three_partitions(1);
    let image = build(&parts, MIXED, 8);
    let opened = open_ok(image);
    let a = opened.archive();
    let names: Vec<&str> = a.entries().iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "0.Apple_partition_map.img",
            "1.Apple_HFS.img",
            "2.Apple_Free.img"
        ]
    );
    let sizes: Vec<u64> = a.entries().iter().map(|e| e.size_or_zero()).collect();
    assert_eq!(sizes, [2048, 31 * 512, 17 * 512]);
    assert!(a.entries().iter().all(|e| !e.is_dir));
    assert_eq!(a.units().len(), 3);
    assert_eq!(a.main_entry(), Some(1));
    assert!(!a.verifies_data());
}

#[test]
fn no_hfs_partition_means_no_main_entry() {
    let parts = [("Apple_partition_map", sample(1024, 2))];
    let opened = open_ok(build(&parts, MIXED, 8));
    assert_eq!(opened.archive().main_entry(), None);
}

#[test]
fn extracts_every_partition_exactly() {
    for chunk_sectors in [1usize, 8, 2048] {
        let parts = three_partitions(3);
        let opened = open_ok(build(&parts, MIXED, chunk_sectors));
        let a = opened.archive();
        for (i, (_, data)) in parts.iter().enumerate() {
            let got = extract(a, i).unwrap();
            let mut want = data.clone();
            want.resize(got.len(), 0);
            assert_eq!(
                got, want,
                "partition {i}, chunks of {chunk_sectors} sectors"
            );
        }
    }
}

#[test]
fn random_reads_cross_chunk_boundaries() {
    let parts = three_partitions(4);
    let opened = open_ok(build(&parts, MIXED, 3));
    let a = opened.archive();
    let mut x = 0x2545_F491u64;
    for (i, (_, data)) in parts.iter().enumerate() {
        let vol = a.volume(i).expect("partition view");
        let mut full = data.clone();
        full.resize(vol.size() as usize, 0);
        assert_eq!(vol.size(), full.len() as u64);
        for _ in 0..200 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let off = (x % (full.len() as u64 + 1)) as usize;
            let len = ((x >> 20) % 6000) as usize;
            let len = len.min(full.len() - off);
            let mut buf = vec![0u8; len];
            vol.read_at(off as u64, &mut buf).unwrap();
            assert_eq!(
                buf,
                full[off..off + len],
                "partition {i} at {off} len {len}"
            );
        }
        // Past the end is an error, not a short read.
        let mut buf = [0u8; 4];
        assert!(vol.read_at(vol.size() - 2, &mut buf).is_err());
    }
}

#[test]
fn each_codec_round_trips_on_its_own() {
    let data = sample(40 * SECTOR, 5);
    for kind in [Kind::Raw, Kind::Zlib, Kind::Bzip2, Kind::Adc, Kind::Lzfse] {
        let parts = [("Apple_HFS", data.clone())];
        let opened = open_ok(build(&parts, &[kind], 4));
        assert_eq!(extract(opened.archive(), 0).unwrap(), data, "{kind:?}");
    }
}

#[test]
fn adc_codec_round_trips_its_encoder_output() {
    for seed in 0..6 {
        let data = sample(20_000 + seed as usize * 333, seed);
        let enc = adc_encode(&data);
        let mut out = vec![0u8; data.len()];
        adc::decode(&enc, &mut out).unwrap();
        assert_eq!(out, data, "seed {seed}");
    }
    // Repetitive data exercises the long copies.
    let data: Vec<u8> = b"abcdefgh".iter().copied().cycle().take(9000).collect();
    let enc = adc_encode(&data);
    assert!(enc.len() < data.len() / 4);
    let mut out = vec![0u8; data.len()];
    adc::decode(&enc, &mut out).unwrap();
    assert_eq!(out, data);
}

#[test]
fn lzfse_codec_decodes_chunks_of_every_size() {
    for n in [1usize, 511, 512, 4096, 65_536] {
        let data = sample(n, n as u64);
        let enc = lzfse(&data);
        let mut out = vec![0u8; data.len()];
        lzfse::decode(&enc, &mut out).unwrap();
        assert_eq!(out, data, "{n} bytes");
    }
}

#[test]
fn encrypted_images_need_a_password() {
    let mut image = build(&three_partitions(6), MIXED, 8);
    image[..8].copy_from_slice(b"encrcdsa");
    let req = OpenRequest::default();
    match open_bytes(image.clone(), "secret.dmg", &req) {
        Err(Error::PasswordRequired) => {}
        other => panic!("expected PasswordRequired, got {:?}", other.err()),
    }
    let with_password = OpenRequest {
        password: Some("not-used".into()),
        ..OpenRequest::default()
    };
    match open_bytes(image, "secret.dmg", &with_password) {
        Err(Error::Unsupported(_)) => {}
        other => panic!("expected Unsupported, got {:?}", other.err()),
    }
}

#[test]
fn unknown_chunk_types_are_unsupported() {
    let parts = [("Apple_HFS", sample(8 * SECTOR, 7))];
    let image = build(&parts, &[Kind::Raw, Kind::Unknown], 4);
    match open(image) {
        Err(Error::Unsupported(_)) => {}
        other => panic!("expected Unsupported, got {:?}", other.err()),
    }
}

#[test]
fn bytes_without_a_trailer_are_not_a_disk_image() {
    let junk = sample(4096, 8);
    assert!(matches!(open(junk), Err(Error::NotArchive)));
    assert!(matches!(open(vec![1, 2, 3]), Err(Error::NotArchive)));
}

#[test]
fn damaged_images_never_panic() {
    let parts = three_partitions(9);
    let image = build(&parts, MIXED, 4);
    let read_some = |bytes: Vec<u8>| {
        let Ok(opened) = open(bytes) else { return };
        let a = opened.archive();
        for i in 0..a.entries().len() {
            let Some(vol) = a.volume(i) else { continue };
            // Bounded reads: a damaged size must not make the test allocate or stream forever.
            let len = (vol.size() as usize).min(1 << 20);
            let mut buf = vec![0u8; len];
            let _ = vol.read_at(0, &mut buf);
        }
    };
    for cut in (0..image.len()).step_by(37) {
        read_some(image[..cut].to_vec());
    }
    for at in (0..image.len()).step_by(29) {
        for bit in [0u8, 3, 7] {
            let mut bad = image.clone();
            bad[at] ^= 1 << bit;
            read_some(bad);
        }
    }
}

#[test]
fn damaged_chunk_data_is_an_error_or_different_bytes() {
    // Flip a byte inside the first compressed chunk (zlib): the stream must not decode as
    // the original bytes.
    let data = sample(8 * SECTOR, 10);
    let parts = [("Apple_HFS", data.clone())];
    let mut image = build(&parts, &[Kind::Zlib], 4);
    image[20] ^= 0x55;
    let opened = open_ok(image);
    let got = extract(opened.archive(), 0);
    assert!(got.map_or(true, |g| g != data));
}

/// Writes images for cross-checking with 7-Zip into the directory named by `R7Z_DMG_OUT`.
#[test]
#[ignore = "writes cross-check images; set R7Z_DMG_OUT to a directory"]
fn dump_images_for_7zip() {
    let Some(dir) = std::env::var_os("R7Z_DMG_OUT") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    // Not an HFS name, so 7-Zip lists the partitions as plain items instead of opening them.
    let parts = [
        ("Scratch", sample(2048, 11)),
        ("Scratch two", sample(30 * SECTOR + 77, 12)),
        ("Scratch three", vec![0u8; 17 * SECTOR]),
    ];
    std::fs::write(dir.join("mixed.dmg"), build(&parts, MIXED, 8)).unwrap();
    for (name, kind) in [
        ("raw", Kind::Raw),
        ("zlib", Kind::Zlib),
        ("bzip2", Kind::Bzip2),
        ("adc", Kind::Adc),
        ("lzfse", Kind::Lzfse),
    ] {
        let image = build(&[("Scratch", sample(64 * SECTOR, 13))], &[kind], 16);
        std::fs::write(dir.join(format!("{name}.dmg")), image).unwrap();
    }
    // All-zero partitions, one codec per image: zero chunks against stored zeros.
    for (name, kind) in [
        ("zeros-zero", Kind::Zero),
        ("zeros-raw", Kind::Raw),
        ("zeros-zlib", Kind::Zlib),
        ("zeros-bzip2", Kind::Bzip2),
        ("zeros-adc", Kind::Adc),
        ("zeros-lzfse", Kind::Lzfse),
    ] {
        let image = build(&[("Scratch", vec![0u8; 17 * SECTOR])], &[kind], 8);
        std::fs::write(dir.join(format!("{name}.dmg")), image).unwrap();
    }
}
