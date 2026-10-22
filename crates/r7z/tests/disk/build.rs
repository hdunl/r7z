//! Builders for disk images: FAT12/16/32 with long names, exFAT, MBR (with an extended
//! partition), GPT, VHD (fixed, dynamic and differencing), VHDX, VMDK (sparse, stream
//! optimized and descriptor) and QCOW2 (uncompressed, zlib and backing). Each follows the
//! public specification of its format. The tests build their inputs here, and the committed
//! fixtures are written from the same code by `regenerate_fixtures` (see main.rs).

use std::io::Write;

use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
use flate2::{Compression, Crc};

pub const SECTOR: usize = 512;
const MB: usize = 1 << 20;

/// The files every FAT and exFAT volume here holds: `HELLO.TXT`, a long-named file, and a
/// folder `SUB` with `NESTED.TXT` inside.
pub const HELLO: &[u8] = b"hello\n";
pub const LONG_NAME: &str = "A long file name.txt";
pub const LONG: &[u8] = b"long name file\n";
pub const NESTED: &[u8] = b"nested text\n";

pub const BASIC_DATA: &str = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
pub const LINUX_DATA: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

pub fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut z = ZlibEncoder::new(Vec::new(), Compression::best());
    z.write_all(data).unwrap();
    z.finish().unwrap()
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = Crc::new();
    c.update(data);
    c.sum()
}

/// The checksum the VHD footer and dynamic header store: the ones' complement of the byte sum.
fn ones_complement(data: &[u8]) -> u32 {
    !data.iter().fold(0u32, |a, &b| a.wrapping_add(u32::from(b)))
}

// ---------------------------------------------------------------------------------------
// FAT12, FAT16, FAT32

fn short_checksum(short: &[u8; 11]) -> u8 {
    short
        .iter()
        .fold(0u8, |s, &c| (s >> 1).wrapping_add(s << 7).wrapping_add(c))
}

fn dir_entry(name: &[u8; 11], attr: u8, first: u32, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    e[22..24].copy_from_slice(&0x6000u16.to_le_bytes());
    e[24..26].copy_from_slice(&0x5A21u16.to_le_bytes());
    e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

/// The long-name entries for `name`, highest sequence first, as they sit on disk.
fn lfn_entries(name: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
    let mut units: Vec<u16> = name.encode_utf16().collect();
    units.push(0);
    while !units.len().is_multiple_of(13) {
        units.push(0xFFFF);
    }
    let parts: Vec<&[u16]> = units.chunks(13).collect();
    let offsets = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
    let mut out = Vec::new();
    for seq in (1..=parts.len()).rev() {
        let mut e = [0u8; 32];
        e[0] = seq as u8 | if seq == parts.len() { 0x40 } else { 0 };
        for (c, &at) in parts[seq - 1].iter().zip(offsets.iter()) {
            e[at..at + 2].copy_from_slice(&c.to_le_bytes());
        }
        e[11] = 0x0F;
        e[13] = short_checksum(short);
        out.push(e);
    }
    out
}

/// Writes FAT entry `c` of a `bits`-wide table.
fn set_fat(table: &mut [u8], bits: u8, c: usize, v: u32) {
    match bits {
        12 => {
            let at = c * 3 / 2;
            let v = v as u16;
            if c.is_multiple_of(2) {
                table[at] = v as u8;
                table[at + 1] = (table[at + 1] & 0xF0) | ((v >> 8) as u8 & 0x0F);
            } else {
                table[at] = (table[at] & 0x0F) | ((v << 4) as u8 & 0xF0);
                table[at + 1] = (v >> 4) as u8;
            }
        }
        16 => table[2 * c..2 * c + 2].copy_from_slice(&(v as u16).to_le_bytes()),
        _ => table[4 * c..4 * c + 4].copy_from_slice(&v.to_le_bytes()),
    }
}

/// A FAT12, FAT16 or FAT32 volume of `sectors` sectors with `spc` sectors per cluster. The
/// root is at cluster 2 on FAT32 and a fixed area otherwise.
pub fn fat_volume(bits: u8, sectors: usize, spc: usize) -> Vec<u8> {
    let root_entries: usize = if bits == 32 { 0 } else { 112 };
    let fats = 2;
    let reserved = if bits == 32 { 32 } else { 1 };
    let root_sectors = (root_entries * 32).div_ceil(SECTOR);
    // The FAT size depends on the cluster count, which depends on the FAT size.
    let mut fat_sectors = 1;
    loop {
        let clusters = (sectors - reserved - fats * fat_sectors - root_sectors) / spc;
        let bytes = match bits {
            12 => (clusters + 2) * 3 / 2 + 1,
            16 => (clusters + 2) * 2,
            _ => (clusters + 2) * 4,
        };
        let need = bytes.div_ceil(SECTOR);
        if need <= fat_sectors {
            break;
        }
        fat_sectors = need;
    }

    let mut img = vec![0u8; sectors * SECTOR];
    let mut boot = [0u8; SECTOR];
    boot[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    boot[3..11].copy_from_slice(b"MSWIN4.1");
    boot[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    boot[13] = spc as u8;
    boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
    boot[16] = fats as u8;
    boot[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
    if sectors < 65536 {
        boot[19..21].copy_from_slice(&(sectors as u16).to_le_bytes());
    }
    boot[21] = 0xF8;
    boot[24..26].copy_from_slice(&63u16.to_le_bytes());
    boot[26..28].copy_from_slice(&255u16.to_le_bytes());
    if bits == 32 {
        // The FAT32 extended block: sizes, root cluster, then drive, boot signature, label
        // and type at 64, 66, 71 and 82.
        boot[32..36].copy_from_slice(&(sectors as u32).to_le_bytes());
        boot[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
        boot[44..48].copy_from_slice(&2u32.to_le_bytes());
        // FSInfo at sector 1, and a copy of the boot sector and FSInfo at sector 6.
        boot[48..50].copy_from_slice(&1u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6u16.to_le_bytes());
        boot[64] = 0x80;
        boot[66] = 0x29;
        boot[71..82].copy_from_slice(b"R7ZFAT32   ");
        boot[82..90].copy_from_slice(b"FAT32   ");
    } else {
        boot[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
        boot[36] = 0x80;
        boot[38] = 0x29;
        boot[43..54].copy_from_slice(b"R7ZFAT12   ");
        boot[54..62].copy_from_slice(if bits == 12 { b"FAT12   " } else { b"FAT16   " });
    }
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    put(&mut img, 0, &boot);
    if bits == 32 {
        let mut info = [0u8; SECTOR];
        info[0..4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        info[488..492].copy_from_slice(&u32::MAX.to_le_bytes());
        info[492..496].copy_from_slice(&u32::MAX.to_le_bytes());
        info[508..512].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
        put(&mut img, SECTOR, &info);
        put(&mut img, 6 * SECTOR, &boot);
        put(&mut img, 7 * SECTOR, &info);
    }

    // Clusters: the FAT32 root (2), then HELLO.TXT, the long name, SUB and NESTED.TXT.
    let mut next = 2usize;
    let mut take = || {
        next += 1;
        next - 1
    };
    let root_cluster = if bits == 32 { take() } else { 0 };
    let (hello, long, sub, nested) = (take(), take(), take(), take());
    let cluster_bytes = spc * SECTOR;
    let data_start = (reserved + fats * fat_sectors + root_sectors) * SECTOR;
    let at = |c: usize| data_start + (c - 2) * cluster_bytes;

    let eoc = match bits {
        12 => 0xFFF,
        16 => 0xFFFF,
        _ => 0x0FFF_FFFF,
    };
    // Entry 0 holds the media byte in its low bits, entry 1 the end-of-chain marker.
    let mut table = vec![0u8; fat_sectors * SECTOR];
    set_fat(&mut table, bits, 0, eoc & !0x07 | 0xF8);
    set_fat(&mut table, bits, 1, eoc);
    let mut chained = vec![hello, long, sub, nested];
    if bits == 32 {
        chained.push(root_cluster);
    }
    for c in chained {
        set_fat(&mut table, bits, c, eoc);
    }
    for k in 0..fats {
        put(&mut img, (reserved + k * fat_sectors) * SECTOR, &table);
    }

    let short_long = *b"ALONGF~1TXT";
    let mut sub_dir = vec![0u8; cluster_bytes];
    sub_dir[..32].copy_from_slice(&dir_entry(b".          ", 0x10, sub as u32, 0));
    sub_dir[32..64].copy_from_slice(&dir_entry(b"..         ", 0x10, 0, 0));
    sub_dir[64..96].copy_from_slice(&dir_entry(
        b"NESTED  TXT",
        0x20,
        nested as u32,
        NESTED.len() as u32,
    ));
    let mut root = Vec::new();
    root.extend_from_slice(&dir_entry(
        b"HELLO   TXT",
        0x20,
        hello as u32,
        HELLO.len() as u32,
    ));
    for e in lfn_entries(LONG_NAME, &short_long) {
        root.extend_from_slice(&e);
    }
    root.extend_from_slice(&dir_entry(
        &short_long,
        0x20,
        long as u32,
        LONG.len() as u32,
    ));
    root.extend_from_slice(&dir_entry(b"SUB        ", 0x10, sub as u32, 0));
    if bits == 32 {
        put(&mut img, at(root_cluster), &root);
    } else {
        put(&mut img, (reserved + fats * fat_sectors) * SECTOR, &root);
    }
    put(&mut img, at(hello), HELLO);
    put(&mut img, at(long), LONG);
    put(&mut img, at(sub), &sub_dir);
    put(&mut img, at(nested), NESTED);
    img
}

// ---------------------------------------------------------------------------------------
// exFAT

fn exfat_name_hash(name: &[u16]) -> u16 {
    let mut h: u16 = 0;
    for &c in name {
        let up = if (u16::from(b'a')..=u16::from(b'z')).contains(&c) {
            c - 32
        } else {
            c
        };
        for b in up.to_le_bytes() {
            h = h.rotate_right(1).wrapping_add(u16::from(b));
        }
    }
    h
}

/// A directory entry set for one file or folder: the file, its stream extension and its
/// name entries.
fn exfat_set(name: &str, folder: bool, first: u32, size: u64, contiguous: bool) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let names = units.len().div_ceil(15);
    let mut set = vec![0u8; 32 * (2 + names)];
    set[0] = 0x85;
    set[1] = (1 + names) as u8;
    let attr: u16 = if folder { 0x10 } else { 0x20 };
    set[4..6].copy_from_slice(&attr.to_le_bytes());
    let stamp: u32 = (0x5A21 << 16) | 0x6000;
    for at in [8, 12, 16] {
        set[at..at + 4].copy_from_slice(&stamp.to_le_bytes());
    }
    let s = 32;
    set[s] = 0xC0;
    set[s + 1] = 0x01 | if contiguous { 0x02 } else { 0 };
    set[s + 3] = units.len() as u8;
    set[s + 4..s + 6].copy_from_slice(&exfat_name_hash(&units).to_le_bytes());
    set[s + 8..s + 16].copy_from_slice(&size.to_le_bytes());
    set[s + 20..s + 24].copy_from_slice(&first.to_le_bytes());
    set[s + 24..s + 32].copy_from_slice(&size.to_le_bytes());
    for (k, chunk) in units.chunks(15).enumerate() {
        let at = 64 + 32 * k;
        set[at] = 0xC1;
        for (i, c) in chunk.iter().enumerate() {
            set[at + 2 + 2 * i..at + 4 + 2 * i].copy_from_slice(&c.to_le_bytes());
        }
    }
    let mut sum: u16 = 0;
    for (i, &b) in set.iter().enumerate() {
        if i != 2 && i != 3 {
            sum = sum.rotate_right(1).wrapping_add(u16::from(b));
        }
    }
    set[2..4].copy_from_slice(&sum.to_le_bytes());
    set
}

/// An exFAT volume of `sectors` sectors with 2 KiB clusters and one FAT: the root, HELLO.TXT
/// (contiguous), a long-named file (chained), SUB and NESTED.TXT.
pub fn exfat_volume(sectors: usize) -> Vec<u8> {
    // The up-case table takes 64 clusters (clusters 8 to 71), one entry per UTF-16 unit.
    let shift_cluster = 2u8;
    let cluster_bytes = SECTOR << shift_cluster;
    let fat_offset = 32usize;
    let clusters = (sectors - 64) >> shift_cluster;
    let fat_len = ((clusters + 2) * 4).div_ceil(SECTOR);
    let heap = fat_offset + fat_len;
    let mut img = vec![0u8; sectors * SECTOR];
    let mut boot = [0u8; SECTOR];
    boot[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    boot[3..11].copy_from_slice(b"EXFAT   ");
    boot[72..80].copy_from_slice(&(sectors as u64).to_le_bytes());
    boot[80..84].copy_from_slice(&(fat_offset as u32).to_le_bytes());
    boot[84..88].copy_from_slice(&(fat_len as u32).to_le_bytes());
    boot[88..92].copy_from_slice(&(heap as u32).to_le_bytes());
    boot[92..96].copy_from_slice(&(clusters as u32).to_le_bytes());
    boot[96..100].copy_from_slice(&4u32.to_le_bytes());
    boot[104..106].copy_from_slice(&0x0100u16.to_le_bytes());
    boot[108] = 9;
    boot[109] = shift_cluster;
    boot[110] = 1;
    boot[111] = 0x80;
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    put(&mut img, 0, &boot);
    // Extended boot sectors 1 to 8 end in the boot signature; sectors 9 and 10 are reserved;
    // sector 11 repeats the checksum of the boot sectors (all but VolumeFlags and
    // PercentInUse).
    for s in 1..=8 {
        img[s * SECTOR + 510..s * SECTOR + 512].copy_from_slice(&[0x55, 0xAA]);
    }
    let mut sum: u32 = 0;
    for (i, &b) in img[..SECTOR]
        .iter()
        .chain(img[SECTOR..9 * SECTOR].iter())
        .enumerate()
    {
        if i == 106 || i == 107 || i == 112 {
            continue;
        }
        sum = sum.rotate_right(1).wrapping_add(u32::from(b));
    }
    for k in 0..SECTOR / 4 {
        put(&mut img, 11 * SECTOR + 4 * k, &sum.to_le_bytes());
    }
    let cluster_at = |c: usize| heap * SECTOR + (c - 2) * cluster_bytes;

    // Clusters: 2 = HELLO.TXT, 3 = the long name, 4 = the root, 5 = SUB, 6 = NESTED.TXT,
    // 7 = the allocation bitmap of clusters 2 to 7, 8 to 71 = the up-case table.
    let mut fat = vec![0u32; clusters + 2];
    fat[0] = 0xFFFF_FFF8;
    fat[1] = 0xFFFF_FFFF;
    for c in [3, 4, 5, 6, 7, 71] {
        fat[c] = 0xFFFF_FFFF;
    }
    for (c, entry) in fat.iter_mut().enumerate().take(71).skip(8) {
        *entry = c as u32 + 1;
    }
    let upcase: Vec<u8> = (0..=0xFFFFu32)
        .flat_map(|u| {
            let up = if (b'a' as u32..=b'z' as u32).contains(&u) {
                u - 32
            } else {
                u
            };
            (up as u16).to_le_bytes()
        })
        .collect();
    let mut table_sum: u32 = 0;
    for &b in &upcase {
        table_sum = table_sum.rotate_right(1).wrapping_add(u32::from(b));
    }
    for (k, chunk) in upcase.chunks(cluster_bytes).enumerate() {
        put(&mut img, cluster_at(8 + k), chunk);
    }
    let mut bitmap = [0u8; 1];
    bitmap[0] = 0b0011_1111;
    put(&mut img, cluster_at(7), &bitmap);
    for (i, &v) in fat.iter().enumerate() {
        put(&mut img, fat_offset * SECTOR + 4 * i, &v.to_le_bytes());
    }
    // The allocation bitmap entry (type 0x81), then the files.
    let mut root = Vec::new();
    let mut map = [0u8; 32];
    map[0] = 0x81;
    map[20..24].copy_from_slice(&7u32.to_le_bytes());
    map[24..32].copy_from_slice(&((clusters as u64).div_ceil(8)).to_le_bytes());
    root.extend_from_slice(&map);
    let mut case = [0u8; 32];
    case[0] = 0x82;
    case[4..8].copy_from_slice(&table_sum.to_le_bytes());
    case[20..24].copy_from_slice(&8u32.to_le_bytes());
    case[24..32].copy_from_slice(&(upcase.len() as u64).to_le_bytes());
    root.extend_from_slice(&case);
    root.extend(exfat_set("HELLO.TXT", false, 2, HELLO.len() as u64, true));
    root.extend(exfat_set(LONG_NAME, false, 3, LONG.len() as u64, false));
    root.extend(exfat_set("SUB", true, 5, cluster_bytes as u64, false));
    put(&mut img, cluster_at(4), &root);
    put(&mut img, cluster_at(2), HELLO);
    put(&mut img, cluster_at(3), LONG);
    put(
        &mut img,
        cluster_at(5),
        &exfat_set("NESTED.TXT", false, 6, NESTED.len() as u64, false),
    );
    put(&mut img, cluster_at(6), NESTED);
    img
}

// ---------------------------------------------------------------------------------------
// MBR and GPT

/// A sector with up to four primary entries: (status, type, first LBA, sectors).
pub fn mbr_sector(entries: &[(u8, u8, u32, u32)]) -> [u8; SECTOR] {
    let mut s = [0u8; SECTOR];
    for (i, &(status, typ, start, count)) in entries.iter().enumerate() {
        let e = 446 + 16 * i;
        s[e] = status;
        s[e + 1..e + 4].copy_from_slice(&[0x01, 0x01, 0x00]);
        s[e + 4] = typ;
        s[e + 5..e + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        s[e + 8..e + 12].copy_from_slice(&start.to_le_bytes());
        s[e + 12..e + 16].copy_from_slice(&count.to_le_bytes());
    }
    s[510..512].copy_from_slice(&[0x55, 0xAA]);
    s
}

/// A disk whose one primary partition holds `volume`, starting at sector 63.
pub fn mbr_disk(volume: &[u8]) -> Vec<u8> {
    let start = 63;
    let vs = volume.len() / SECTOR;
    let mut img = vec![0u8; (start + vs) * SECTOR];
    put(
        &mut img,
        0,
        &mbr_sector(&[(0x80, 0x01, start as u32, vs as u32)]),
    );
    put(&mut img, start * SECTOR, volume);
    img
}

/// A primary FAT partition (`volume`) and an extended partition holding a FAT and a junk
/// partition, chained through two EBRs. The logical partitions are the second and third
/// partitions listed, as 7-Zip lists them.
pub fn mbr_extended_disk(volume: &[u8], junk: &[u8]) -> Vec<u8> {
    let vs = volume.len() / SECTOR;
    let js = junk.len() / SECTOR;
    let ext = 63 + vs;
    let ebr2 = vs + 2;
    let total = ext + ebr2 + 1 + js;
    let mut img = vec![0u8; total * SECTOR];
    put(
        &mut img,
        0,
        &mbr_sector(&[
            (0x80, 0x01, 63, vs as u32),
            (0, 0x05, ext as u32, (total - ext) as u32),
        ]),
    );
    put(&mut img, 63 * SECTOR, volume);
    put(
        &mut img,
        ext * SECTOR,
        &mbr_sector(&[
            (0, 0x01, 1, vs as u32),
            (0, 0x05, ebr2 as u32, (1 + js) as u32),
        ]),
    );
    put(&mut img, (ext + 1) * SECTOR, volume);
    let at2 = ext + ebr2;
    put(
        &mut img,
        at2 * SECTOR,
        &mbr_sector(&[(0, 0x83, 1, js as u32)]),
    );
    put(&mut img, (at2 + 1) * SECTOR, junk);
    img
}

fn guid_le(text: &str) -> [u8; 16] {
    let parts: Vec<&str> = text.split('-').collect();
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&u32::from_str_radix(parts[0], 16).unwrap().to_le_bytes());
    out[4..6].copy_from_slice(&u16::from_str_radix(parts[1], 16).unwrap().to_le_bytes());
    out[6..8].copy_from_slice(&u16::from_str_radix(parts[2], 16).unwrap().to_le_bytes());
    let tail = format!("{}{}", parts[3], parts[4]);
    for i in 0..8 {
        out[8 + i] = u8::from_str_radix(&tail[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// A GPT disk: a protective MBR, the header and entries at LBA 1 and 2, and backups at the
/// end. Each partition is `(label, type GUID, data)`, placed from LBA 2048 on.
pub fn gpt_disk(parts: &[(&str, &str, &[u8])]) -> Vec<u8> {
    let mut placed = Vec::new();
    let mut cursor = 2048usize;
    for &(label, typ, data) in parts {
        let count = data.len() / SECTOR;
        placed.push((label, typ, cursor, count, data));
        cursor += count;
    }
    let last = cursor + 33;
    let total = last + 1;
    let mut img = vec![0u8; total * SECTOR];
    put(
        &mut img,
        0,
        &mbr_sector(&[(0, 0xEE, 1, (total - 1) as u32)]),
    );
    let mut entries = vec![0u8; 128 * 128];
    for (i, &(label, typ, start, count, data)) in placed.iter().enumerate() {
        let e = &mut entries[128 * i..128 * (i + 1)];
        e[0..16].copy_from_slice(&guid_le(typ));
        e[16..32].copy_from_slice(&guid_le(&format!(
            "1A2B3C4D-0000-4000-8000-00000000000{:X}",
            i + 1
        )));
        e[32..40].copy_from_slice(&(start as u64).to_le_bytes());
        e[40..48].copy_from_slice(&((start + count - 1) as u64).to_le_bytes());
        for (k, u) in label.encode_utf16().enumerate() {
            e[56 + 2 * k..58 + 2 * k].copy_from_slice(&u.to_le_bytes());
        }
        put(&mut img, start * SECTOR, data);
    }
    let header = |this: usize, other: usize, entries_lba: usize| {
        let mut h = [0u8; 92];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&(this as u64).to_le_bytes());
        h[32..40].copy_from_slice(&(other as u64).to_le_bytes());
        h[40..48].copy_from_slice(&34u64.to_le_bytes());
        h[48..56].copy_from_slice(&((last - 33) as u64).to_le_bytes());
        h[56..72].copy_from_slice(&guid_le("5C1D2E3F-1111-4222-8333-444455556666"));
        h[72..80].copy_from_slice(&(entries_lba as u64).to_le_bytes());
        h[80..84].copy_from_slice(&128u32.to_le_bytes());
        h[84..88].copy_from_slice(&128u32.to_le_bytes());
        h[88..92].copy_from_slice(&crc32(&entries).to_le_bytes());
        let sum = crc32(&h);
        h[16..20].copy_from_slice(&sum.to_le_bytes());
        h
    };
    put(&mut img, SECTOR, &header(1, last, 2));
    put(&mut img, 2 * SECTOR, &entries);
    put(&mut img, (last - 32) * SECTOR, &entries);
    put(&mut img, last * SECTOR, &header(last, 1, last - 32));
    img
}

// ---------------------------------------------------------------------------------------
// VHD

fn vhd_footer(size: u64, kind: u32, data_offset: u64) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[0..8].copy_from_slice(b"conectix");
    f[8..12].copy_from_slice(&2u32.to_be_bytes());
    f[12..16].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    f[16..24].copy_from_slice(&data_offset.to_be_bytes());
    f[28..32].copy_from_slice(b"r7z ");
    f[36..40].copy_from_slice(b"Wi2k");
    f[40..48].copy_from_slice(&size.to_be_bytes());
    f[48..56].copy_from_slice(&size.to_be_bytes());
    f[56..58].copy_from_slice(&((size / SECTOR as u64 / 16 / 63) as u16).to_be_bytes());
    f[58] = 16;
    f[59] = 63;
    f[60..64].copy_from_slice(&kind.to_be_bytes());
    f[68..84].copy_from_slice(&[0x11; 16]);
    let sum = ones_complement(&f);
    f[64..68].copy_from_slice(&sum.to_be_bytes());
    f
}

/// A fixed disk: the raw bytes, then the footer.
pub fn vhd_fixed(disk: &[u8]) -> Vec<u8> {
    let mut out = disk.to_vec();
    out.extend_from_slice(&vhd_footer(disk.len() as u64, 2, u64::MAX));
    out
}

/// A dynamic disk with `block`-byte blocks. A block that is all zeros is not stored.
pub fn vhd_dynamic(disk: &[u8], block: usize) -> Vec<u8> {
    dynamic(disk.len() as u64, block, 3, None, |b| {
        let lo = (b * block).min(disk.len());
        let hi = ((b + 1) * block).min(disk.len());
        let chunk = &disk[lo..hi];
        chunk.iter().any(|&x| x != 0).then(|| chunk.to_vec())
    })
}

/// A dynamic disk of `size` bytes with no blocks stored: every read is zeros.
pub fn vhd_sparse(size: u64, block: usize) -> Vec<u8> {
    dynamic(size, block, 3, None, |_| None)
}

/// A differencing disk of `size` bytes whose parent is named `parent`, with no blocks of its
/// own.
pub fn vhd_diff(size: u64, parent: &str) -> Vec<u8> {
    dynamic(size, MB, 4, Some(parent), |_| None)
}

/// Lays out a dynamic or differencing disk: the footer copy, the dynamic header, the
/// allocation table, the parent name (for a differencing disk), the stored blocks (each with
/// its sector bitmap), and the footer.
fn dynamic(
    size: u64,
    block: usize,
    kind: u32,
    parent: Option<&str>,
    mut block_data: impl FnMut(usize) -> Option<Vec<u8>>,
) -> Vec<u8> {
    let blocks = (size as usize).div_ceil(block);
    let bitmap = ((block / SECTOR).div_ceil(8)).div_ceil(SECTOR) * SECTOR;
    let bat_at = 1536;
    let bat_len = (blocks * 4).div_ceil(SECTOR) * SECTOR;
    let name: Vec<u8> = parent
        .map(|p| p.encode_utf16().flat_map(|u| u.to_le_bytes()).collect())
        .unwrap_or_default();
    let name_at = bat_at + bat_len;
    let name_len = name.len().div_ceil(SECTOR) * SECTOR;
    let blocks_at = name_at + name_len;

    let mut out = vec![0u8; blocks_at];
    put(&mut out, 0, &vhd_footer(size, kind, 512));
    let mut hdr = [0u8; 1024];
    hdr[0..8].copy_from_slice(b"cxsparse");
    hdr[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    hdr[16..24].copy_from_slice(&(bat_at as u64).to_be_bytes());
    hdr[24..28].copy_from_slice(&0x0001_0000u32.to_be_bytes());
    hdr[28..32].copy_from_slice(&(blocks as u32).to_be_bytes());
    hdr[32..36].copy_from_slice(&(block as u32).to_be_bytes());
    if parent.is_some() {
        // Parent locator 0: the platform code, the data space in sectors, the data length
        // in bytes, then the data's offset in the file.
        hdr[576..580].copy_from_slice(b"W2ru");
        hdr[580..584].copy_from_slice(&((name_len / SECTOR) as u32).to_be_bytes());
        hdr[584..588].copy_from_slice(&(name.len() as u32).to_be_bytes());
        hdr[592..600].copy_from_slice(&(name_at as u64).to_be_bytes());
    }
    let sum = ones_complement(
        &hdr[..36]
            .iter()
            .chain(&hdr[40..])
            .copied()
            .collect::<Vec<u8>>(),
    );
    hdr[36..40].copy_from_slice(&sum.to_be_bytes());
    put(&mut out, 512, &hdr);
    put(&mut out, name_at, &name);

    let mut bat = vec![0u8; bat_len];
    let mut stored = Vec::new();
    for b in 0..blocks {
        match block_data(b) {
            None => bat[4 * b..4 * b + 4].copy_from_slice(&u32::MAX.to_be_bytes()),
            Some(chunk) => {
                let sector = (blocks_at + stored.len()) / SECTOR;
                bat[4 * b..4 * b + 4].copy_from_slice(&(sector as u32).to_be_bytes());
                let mut blk = vec![0u8; bitmap + block];
                for i in 0..chunk.len() / SECTOR {
                    blk[i / 8] |= 0x80 >> (i % 8);
                }
                blk[bitmap..bitmap + chunk.len()].copy_from_slice(&chunk);
                stored.extend_from_slice(&blk);
            }
        }
    }
    put(&mut out, bat_at, &bat);
    out.extend_from_slice(&stored);
    out.extend_from_slice(&vhd_footer(size, kind, 512));
    out
}

// ---------------------------------------------------------------------------------------
// VHDX

fn vhdx_guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> [u8; 16] {
    let mut g = [0u8; 16];
    g[0..4].copy_from_slice(&d1.to_le_bytes());
    g[4..6].copy_from_slice(&d2.to_le_bytes());
    g[6..8].copy_from_slice(&d3.to_le_bytes());
    g[8..16].copy_from_slice(&d4);
    g
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// A VHDX disk with 1 MiB blocks. With `log`, the header carries a log GUID and length, which
/// marks a log that was not replayed.
pub fn vhdx(disk: &[u8], log: bool) -> Vec<u8> {
    let size = disk.len().div_ceil(MB) * MB;
    let (meta_at, bat_at, data_at) = (2 * MB, 3 * MB, 4 * MB);
    let mut out = vec![0u8; data_at + size];
    out[0..8].copy_from_slice(b"vhdxfile");

    let mut h = vec![0u8; 4096];
    h[0..4].copy_from_slice(b"head");
    h[8..16].copy_from_slice(&1u64.to_le_bytes());
    h[16..32].copy_from_slice(&[0x33; 16]);
    if log {
        h[48..64].copy_from_slice(&[0x55; 16]);
        h[68..72].copy_from_slice(&4096u32.to_le_bytes());
    }
    h[66..68].copy_from_slice(&1u16.to_le_bytes());
    let sum = crc32c(&h);
    h[4..8].copy_from_slice(&sum.to_le_bytes());
    put(&mut out, 0x10000, &h);
    put(&mut out, 0x20000, &h);

    let bat_guid = vhdx_guid(
        0x2DC2_7766,
        0xF623,
        0x4200,
        [0x9D, 0x64, 0x11, 0x5E, 0x9B, 0xFD, 0x4A, 0x08],
    );
    let meta_guid = vhdx_guid(
        0x8B7C_A206,
        0x4790,
        0x4B9A,
        [0xB8, 0xFE, 0x57, 0x5F, 0x05, 0x0F, 0x88, 0x6E],
    );
    let mut region = vec![0u8; 65536];
    region[0..4].copy_from_slice(b"regi");
    region[8..12].copy_from_slice(&2u32.to_le_bytes());
    for (i, (guid, at)) in [(bat_guid, bat_at), (meta_guid, meta_at)]
        .into_iter()
        .enumerate()
    {
        let e = 16 + 32 * i;
        region[e..e + 16].copy_from_slice(&guid);
        region[e + 16..e + 24].copy_from_slice(&(at as u64).to_le_bytes());
        region[e + 24..e + 28].copy_from_slice(&0x10000u32.to_le_bytes());
        region[e + 28..e + 32].copy_from_slice(&1u32.to_le_bytes());
    }
    let sum = crc32c(&region);
    region[4..8].copy_from_slice(&sum.to_le_bytes());
    put(&mut out, 0x30000, &region);
    put(&mut out, 0x40000, &region);

    let items: [([u8; 16], usize, Vec<u8>); 3] = [
        (
            vhdx_guid(
                0xCAA1_6737,
                0xFA36,
                0x4D43,
                [0xB3, 0xB6, 0x33, 0xF0, 0xAA, 0x44, 0xE7, 0x6B],
            ),
            0x1000,
            [(MB as u32).to_le_bytes(), [0; 4]].concat(),
        ),
        (
            vhdx_guid(
                0x2FA5_4224,
                0xCD1B,
                0x4876,
                [0xB2, 0x11, 0x5D, 0xBE, 0xD8, 0x3B, 0xF4, 0xB8],
            ),
            0x1010,
            (size as u64).to_le_bytes().to_vec(),
        ),
        (
            vhdx_guid(
                0x8141_BF1D,
                0xA96F,
                0x4347,
                [0xAD, 0xF6, 0xC4, 0xE2, 0xFF, 0xD2, 0x9A, 0x83],
            ),
            0x1020,
            512u32.to_le_bytes().to_vec(),
        ),
    ];
    let mut meta = vec![0u8; 65536];
    meta[0..8].copy_from_slice(b"metadata");
    meta[10..12].copy_from_slice(&(items.len() as u16).to_le_bytes());
    for (i, (guid, at, value)) in items.iter().enumerate() {
        let e = 32 + 32 * i;
        meta[e..e + 16].copy_from_slice(guid);
        meta[e + 16..e + 20].copy_from_slice(&(*at as u32).to_le_bytes());
        meta[e + 20..e + 24].copy_from_slice(&(value.len() as u32).to_le_bytes());
        meta[*at..*at + value.len()].copy_from_slice(value);
    }
    put(&mut out, meta_at, &meta);

    let mut bat = vec![0u8; 65536];
    for b in 0..size / MB {
        let lo = (b * MB).min(disk.len());
        let hi = ((b + 1) * MB).min(disk.len());
        let chunk = &disk[lo..hi];
        if chunk.iter().all(|&x| x == 0) {
            continue;
        }
        let file_at = data_at + b * MB;
        let entry = ((file_at as u64) >> 20 << 20) | 6;
        bat[8 * b..8 * b + 8].copy_from_slice(&entry.to_le_bytes());
        put(&mut out, file_at, chunk);
    }
    put(&mut out, bat_at, &bat);
    out
}

// ---------------------------------------------------------------------------------------
// VMDK

/// A monolithic sparse disk with 4 KiB grains, or a stream-optimized one whose grains are
/// zlib-compressed behind markers. A grain of zeros is not stored.
pub fn vmdk_sparse(disk: &[u8], stream: bool) -> Vec<u8> {
    const GRAIN: usize = 8;
    const GTES: usize = 512;
    let cap = disk.len() / SECTOR;
    let grains = cap.div_ceil(GRAIN);
    let gts = grains.div_ceil(GTES);
    let gt_bytes = gts * GTES * 4;
    let flags: u32 = if stream { 0x3_0001 } else { 0x3 };
    // Sector 1 is never a grain: a grain table entry of 1 means a zeroed grain.
    let mut out = vec![
        0u8;
        if stream {
            2 * SECTOR
        } else {
            (2 + gt_bytes / SECTOR) * SECTOR
        }
    ];
    let mut gt = vec![0u8; gt_bytes];
    for g in 0..grains {
        let lo = g * GRAIN * SECTOR;
        let hi = ((g + 1) * GRAIN * SECTOR).min(disk.len());
        let mut chunk = disk[lo..hi].to_vec();
        chunk.resize(GRAIN * SECTOR, 0);
        if chunk.iter().all(|&x| x == 0) {
            continue;
        }
        gt[4 * g..4 * g + 4].copy_from_slice(&((out.len() / SECTOR) as u32).to_le_bytes());
        if stream {
            let payload = zlib(&chunk);
            let mut marker = Vec::new();
            marker.extend_from_slice(&((g * GRAIN) as u64).to_le_bytes());
            marker.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            marker.extend_from_slice(&payload);
            marker.resize(marker.len().div_ceil(SECTOR) * SECTOR, 0);
            out.extend_from_slice(&marker);
        } else {
            out.extend_from_slice(&chunk);
        }
    }
    let header = |gd_offset: u64| {
        let mut h = vec![0u8; SECTOR];
        h[0..4].copy_from_slice(b"KDMV");
        h[4..8].copy_from_slice(&1u32.to_le_bytes());
        h[8..12].copy_from_slice(&flags.to_le_bytes());
        h[12..20].copy_from_slice(&(cap as u64).to_le_bytes());
        h[20..28].copy_from_slice(&(GRAIN as u64).to_le_bytes());
        h[44..48].copy_from_slice(&(GTES as u32).to_le_bytes());
        h[56..64].copy_from_slice(&gd_offset.to_le_bytes());
        h[73..77].copy_from_slice(b"\n \r\n");
        h[77..79].copy_from_slice(&(if stream { 1u16 } else { 0 }).to_le_bytes());
        h
    };
    if !stream {
        out[SECTOR..SECTOR + 4].copy_from_slice(&2u32.to_le_bytes());
        put(&mut out, 2 * SECTOR, &gt);
        put(&mut out, 0, &header(1));
        return out;
    }
    // Stream layout: the header, the markers, the grain tables, the directory, then a footer
    // copy of the header and an end-of-stream marker. The header's directory is "at end".
    let gt_at = out.len() / SECTOR;
    out.extend_from_slice(&gt);
    let gd_at = out.len() / SECTOR;
    let mut gd = vec![0u8; SECTOR];
    gd[0..4].copy_from_slice(&(gt_at as u32).to_le_bytes());
    out.extend_from_slice(&gd);
    put(&mut out, 0, &header(u64::MAX));
    out.extend_from_slice(&header(gd_at as u64));
    out.extend_from_slice(&[0u8; SECTOR]);
    out
}

/// The descriptor of a monolithic flat disk whose one extent `flat` holds `sectors` sectors.
pub fn vmdk_descriptor(flat: &str, sectors: usize) -> Vec<u8> {
    format!(
        "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\n\
         createType=\"monolithicFlat\"\n\n# Extent description\nRW {sectors} FLAT \"{flat}\" 0\n\n\
         # The Disk Data Base\n#DDB\n"
    )
    .into_bytes()
}

// ---------------------------------------------------------------------------------------
// QCOW2

/// A QCOW2 version 3 image with 4 KiB clusters. `deflate` lists clusters stored as raw
/// deflate streams; `unallocated` clusters have no table entry; `backing` names a backing
/// file, whose clusters are not stored here.
pub fn qcow2(
    disk: &[u8],
    deflate: &[usize],
    unallocated: &[usize],
    backing: Option<&str>,
) -> Vec<u8> {
    const CS: usize = 4096;
    let n = disk.len().div_ceil(CS);
    let per = CS / 8;
    let l1_entries = n.div_ceil(per);
    let mut out = vec![0u8; 2 * CS];
    let mut l2_at = Vec::new();
    for _ in 0..l1_entries {
        l2_at.push(out.len());
        out.extend(std::iter::repeat_n(0u8, CS));
    }
    let mut l1 = vec![0u8; CS];
    for (t, &at) in l2_at.iter().enumerate() {
        l1[8 * t..8 * t + 8].copy_from_slice(&((at as u64) | (1 << 63)).to_be_bytes());
    }
    let mut l2 = vec![vec![0u8; CS]; l1_entries];
    for i in 0..n {
        if unallocated.contains(&i) {
            continue;
        }
        let lo = i * CS;
        let mut chunk = disk[lo..((i + 1) * CS).min(disk.len())].to_vec();
        chunk.resize(CS, 0);
        let (t, k) = (i / per, i % per);
        if deflate.contains(&i) {
            let mut z = Vec::new();
            let mut e = DeflateEncoder::new(&mut z, Compression::best());
            e.write_all(&chunk).unwrap();
            e.finish().unwrap();
            let sectors = z.len().div_ceil(512);
            let at = out.len();
            z.resize(CS, 0);
            out.extend_from_slice(&z);
            let shift = 62 - (12 - 8);
            let entry = (1u64 << 62) | (((sectors - 1) as u64) << shift) | at as u64;
            l2[t][8 * k..8 * k + 8].copy_from_slice(&entry.to_be_bytes());
            continue;
        }
        if chunk.iter().all(|&x| x == 0) {
            continue;
        }
        let at = out.len();
        out.extend_from_slice(&chunk);
        l2[t][8 * k..8 * k + 8].copy_from_slice(&((at as u64) | (1 << 63)).to_be_bytes());
    }
    for (t, &at) in l2_at.iter().enumerate() {
        out[at..at + CS].copy_from_slice(&l2[t]);
    }
    out[CS..2 * CS].copy_from_slice(&l1);
    let mut h = vec![0u8; CS];
    h[0..4].copy_from_slice(b"QFI\xfb");
    h[4..8].copy_from_slice(&3u32.to_be_bytes());
    let backing_at = if backing.is_some() { 512u64 } else { 0 };
    h[8..16].copy_from_slice(&backing_at.to_be_bytes());
    h[16..20].copy_from_slice(&(backing.map_or(0, |b| b.len()) as u32).to_be_bytes());
    h[20..24].copy_from_slice(&12u32.to_be_bytes());
    h[24..32].copy_from_slice(&(disk.len() as u64).to_be_bytes());
    h[36..40].copy_from_slice(&(l1_entries as u32).to_be_bytes());
    h[40..48].copy_from_slice(&(CS as u64).to_be_bytes());
    h[96..100].copy_from_slice(&4u32.to_be_bytes());
    h[100..104].copy_from_slice(&104u32.to_be_bytes());
    out[0..CS].copy_from_slice(&h);
    // The backing name sits in the header cluster, after the fixed header fields.
    if let Some(b) = backing {
        out[512..512 + b.len()].copy_from_slice(b.as_bytes());
    }
    out
}
