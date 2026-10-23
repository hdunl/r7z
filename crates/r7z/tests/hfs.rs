//! HFS+ and HFSX reads, against volumes written by a small builder below. The builder lays out
//! the catalog and attribute B-trees over scattered blocks (so forks need extents overflow
//! records), decmpfs data in attributes and resource forks, symbolic and hard links, and the
//! private folders that hard links point into.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use flate2::write::ZlibEncoder;
use flate2::Compression;

use r7z::format::data::Slice;
use r7z::format::{self, Archive, Ctx, Flow, Input, Link, OpenOptions, OpenRequest, ReadAt};
use r7z::{Error, Result};

const BS: usize = 512;
/// B-tree node size, a multiple of the allocation block size (Apple's trees use 4 KiB or more).
const NODE: usize = 4096;
const PER_NODE: usize = NODE / BS;
const TOTAL: u32 = 2048;
const DESC: usize = 14;
const LEAF: u8 = 0xFF;
const INDEX: u8 = 0;
const HEADER: u8 = 1;
const DATA_FORK: u8 = 0;
const RSRC_FORK: u8 = 0xFF;
const CATALOG_FILE: u32 = 4;
const ATTRIBUTES_FILE: u32 = 8;
const EXTENTS_FILE: u32 = 3;
const ALLOCATION_FILE: u32 = 6;
const ROOT_ID: u32 = 2;
/// 2001-01-01T00:00:00Z in HFS+ seconds, and the FILETIME for the same instant.
const MODIFIED: u32 = 3_061_152_000;
const MODIFIED_FILETIME: u64 = 126_227_808_000_000_000;

// ------------------------------------------------------------------ builder

#[derive(Clone, Default)]
struct Item {
    cnid: u32,
    parent: u32,
    name: &'static str,
    dir: bool,
    mode: u16,
    typ: [u8; 4],
    creator: [u8; 4],
    /// BSD special field: the hard-link number for a link proxy.
    special: u32,
    data: Vec<u8>,
    rsrc: Vec<u8>,
    /// Places the data blocks with gaps between them, so the fork has one extent per block.
    scatter: bool,
    /// decmpfs type, uncompressed size and inline payload (empty for resource-fork types).
    decmpfs: Option<(u32, u64, Vec<u8>)>,
}

fn dir(cnid: u32, parent: u32, name: &'static str) -> Item {
    Item {
        cnid,
        parent,
        name,
        dir: true,
        mode: 0o40755,
        ..Item::default()
    }
}

fn file(cnid: u32, parent: u32, name: &'static str, data: &[u8]) -> Item {
    Item {
        cnid,
        parent,
        name,
        mode: 0o100644,
        typ: *b"TEXT",
        creator: *b"ttxt",
        data: data.to_vec(),
        ..Item::default()
    }
}

/// A fork's extents, one `(start, count)` per run of consecutive blocks.
fn runs(blocks: &[u32]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for &b in blocks {
        match out.last_mut() {
            Some((s, c)) if *s + *c == b => *c += 1,
            _ => out.push((b, 1)),
        }
    }
    out
}

/// An extents overflow record: fork type, file ID, first block, eight extents.
type Overflow = (u8, u32, u32, Vec<(u32, u32)>);

/// The 80-byte fork record for `blocks`; extents past the eighth go to `over`.
fn fork_data(
    size: u64,
    blocks: &[u32],
    file_id: u32,
    fork: u8,
    over: &mut Vec<Overflow>,
) -> [u8; 80] {
    let mut out = [0u8; 80];
    out[..8].copy_from_slice(&size.to_be_bytes());
    out[12..16].copy_from_slice(&(blocks.len() as u32).to_be_bytes());
    let mut before = 0u32;
    for (i, chunk) in runs(blocks).chunks(8).enumerate() {
        if i == 0 {
            for (k, &(s, c)) in chunk.iter().enumerate() {
                out[16 + 8 * k..20 + 8 * k].copy_from_slice(&s.to_be_bytes());
                out[20 + 8 * k..24 + 8 * k].copy_from_slice(&c.to_be_bytes());
            }
        } else {
            over.push((fork, file_id, before, chunk.to_vec()));
        }
        before += chunk.iter().map(|e| e.1).sum::<u32>();
    }
    out
}

/// Block allocator over the volume. Scattered allocations leave a gap after each block.
struct Image {
    img: Vec<u8>,
    used: Vec<bool>,
    next: u32,
}

impl Image {
    fn new() -> Image {
        let mut used = vec![false; TOTAL as usize];
        for b in [0usize, 1, 2, 3, TOTAL as usize - 2, TOTAL as usize - 1] {
            used[b] = true;
        }
        Image {
            img: vec![0; TOTAL as usize * BS],
            used,
            next: 4,
        }
    }

    fn alloc(&mut self, n: usize, scattered: bool) -> Vec<u32> {
        let step = if scattered { 2 } else { 1 };
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            assert!(self.next < TOTAL - 2, "test volume is full");
            out.push(self.next);
            self.used[self.next as usize] = true;
            self.next += step;
        }
        out
    }

    fn write(&mut self, blocks: &[u32], bytes: &[u8]) {
        for (i, &b) in blocks.iter().enumerate() {
            let src = &bytes[(i * BS).min(bytes.len())..((i + 1) * BS).min(bytes.len())];
            let at = b as usize * BS;
            self.img[at..at + src.len()].copy_from_slice(src);
        }
    }

    /// Writes each B-tree node into its run of blocks; returns the blocks in node order.
    fn place_nodes(&mut self, nodes: &[Vec<u8>], scattered: bool) -> Vec<u32> {
        let blocks = self.alloc(nodes.len() * PER_NODE, scattered);
        for (n, run) in nodes.iter().zip(blocks.chunks(PER_NODE)) {
            self.write(run, n);
        }
        blocks
    }
}

fn record(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut r = key.to_vec();
    if r.len() % 2 == 1 {
        r.push(0);
    }
    r.extend_from_slice(data);
    r
}

fn key_of(item: &[u8]) -> &[u8] {
    let n = 2 + u16::from_be_bytes([item[0], item[1]]) as usize;
    &item[..n]
}

/// Groups encoded records into nodes, each with room for its offset table.
fn group(items: &[Vec<u8>]) -> Vec<Vec<usize>> {
    let mut groups = vec![Vec::new()];
    let mut used = 0;
    for (i, it) in items.iter().enumerate() {
        let count = groups.last().unwrap().len();
        if count > 0 && DESC + used + it.len() + 2 * (count + 2) > NODE {
            groups.push(Vec::new());
            used = 0;
        }
        let count = groups.last().unwrap().len();
        assert!(
            DESC + used + it.len() + 2 * (count + 2) <= NODE,
            "record larger than a node"
        );
        used += it.len();
        groups.last_mut().unwrap().push(i);
    }
    groups
}

fn node(kind: u8, f_link: u32, b_link: u32, height: u8, recs: &[Vec<u8>]) -> Vec<u8> {
    let mut n = vec![0u8; NODE];
    n[..4].copy_from_slice(&f_link.to_be_bytes());
    n[4..8].copy_from_slice(&b_link.to_be_bytes());
    n[8] = kind;
    n[9] = height;
    n[10..12].copy_from_slice(&(recs.len() as u16).to_be_bytes());
    let mut at = DESC;
    for (i, r) in recs.iter().enumerate() {
        let off = NODE - 2 * (i + 1);
        n[off..off + 2].copy_from_slice(&(at as u16).to_be_bytes());
        n[at..at + r.len()].copy_from_slice(r);
        at += r.len();
    }
    let off = NODE - 2 * (recs.len() + 1);
    n[off..off + 2].copy_from_slice(&(at as u16).to_be_bytes());
    n
}

/// A B-tree's nodes, with node 0 the header, from sorted `(key, data)` records.
struct Tree {
    nodes: Vec<Vec<u8>>,
}

fn build_tree(records: &[(Vec<u8>, Vec<u8>)]) -> Tree {
    assert!(!records.is_empty());
    let mut nodes: Vec<Vec<u8>> = vec![Vec::new()];
    let mut items: Vec<Vec<u8>> = records.iter().map(|(k, d)| record(k, d)).collect();
    let mut kind = LEAF;
    let mut depth = 1u16;
    let mut first_leaf = 0;
    let mut leaves = 0;
    let root;
    loop {
        let groups = group(&items);
        let first = nodes.len() as u32;
        if kind == LEAF {
            first_leaf = first;
            leaves = groups.len() as u32;
        }
        let mut next_items = Vec::new();
        for (gi, g) in groups.iter().enumerate() {
            let num = first + gi as u32;
            let recs: Vec<Vec<u8>> = g.iter().map(|&i| items[i].clone()).collect();
            let f_link = if gi + 1 < groups.len() { num + 1 } else { 0 };
            let b_link = if gi > 0 { num - 1 } else { 0 };
            nodes.push(node(kind, f_link, b_link, depth as u8, &recs));
            next_items.push(record(key_of(&items[g[0]]), &num.to_be_bytes()));
        }
        if groups.len() == 1 {
            root = first;
            break;
        }
        items = next_items;
        kind = INDEX;
        depth += 1;
    }
    let total = nodes.len();
    let mut map = vec![0u8; total.div_ceil(8)];
    for n in 0..total {
        map[n / 8] |= 0x80 >> (n % 8);
    }
    let mut hdr = Vec::with_capacity(106);
    hdr.extend_from_slice(&depth.to_be_bytes());
    hdr.extend_from_slice(&root.to_be_bytes());
    hdr.extend_from_slice(&(records.len() as u32).to_be_bytes());
    hdr.extend_from_slice(&first_leaf.to_be_bytes());
    hdr.extend_from_slice(&(first_leaf + leaves - 1).to_be_bytes());
    hdr.extend_from_slice(&(NODE as u16).to_be_bytes());
    // The longest key length field (the bytes after the two-byte length itself).
    let max_key = records.iter().map(|(k, _)| k.len() - 2).max().unwrap_or(0);
    hdr.extend_from_slice(&(max_key as u16).to_be_bytes());
    hdr.extend_from_slice(&(total as u32).to_be_bytes());
    hdr.extend_from_slice(&0u32.to_be_bytes());
    hdr.extend_from_slice(&0u16.to_be_bytes());
    hdr.extend_from_slice(&0u32.to_be_bytes());
    hdr.extend_from_slice(&[0, 0xCF]);
    hdr.extend_from_slice(&6u32.to_be_bytes());
    hdr.extend_from_slice(&[0u8; 64]);
    assert_eq!(hdr.len(), 106);
    nodes[0] = node(HEADER, 0, 0, 0, &[hdr, vec![0u8; 128], map]);
    Tree { nodes }
}

fn catalog_key(parent: u32, name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut k = ((6 + 2 * units.len()) as u16).to_be_bytes().to_vec();
    k.extend_from_slice(&parent.to_be_bytes());
    k.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        k.extend_from_slice(&u.to_be_bytes());
    }
    k
}

fn attr_key(file_id: u32, name: &str) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut k = ((12 + 2 * units.len()) as u16).to_be_bytes().to_vec();
    k.extend_from_slice(&[0, 0]);
    k.extend_from_slice(&file_id.to_be_bytes());
    k.extend_from_slice(&0u32.to_be_bytes());
    k.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        k.extend_from_slice(&u.to_be_bytes());
    }
    k
}

fn folder_data(it: &Item) -> Vec<u8> {
    let mut d = vec![0u8; 88];
    d[..2].copy_from_slice(&1u16.to_be_bytes());
    d[8..12].copy_from_slice(&it.cnid.to_be_bytes());
    for at in [12, 16, 24] {
        d[at..at + 4].copy_from_slice(&MODIFIED.to_be_bytes());
    }
    d[42..44].copy_from_slice(&it.mode.to_be_bytes());
    d
}

fn file_data(it: &Item, data: &[u8; 80], rsrc: &[u8; 80]) -> Vec<u8> {
    let mut d = vec![0u8; 248];
    d[..2].copy_from_slice(&2u16.to_be_bytes());
    d[8..12].copy_from_slice(&it.cnid.to_be_bytes());
    for at in [12, 16, 20, 24] {
        d[at..at + 4].copy_from_slice(&MODIFIED.to_be_bytes());
    }
    d[42..44].copy_from_slice(&it.mode.to_be_bytes());
    d[44..48].copy_from_slice(&it.special.to_be_bytes());
    d[48..52].copy_from_slice(&it.typ);
    d[52..56].copy_from_slice(&it.creator);
    d[88..168].copy_from_slice(data);
    d[168..248].copy_from_slice(rsrc);
    d
}

fn thread_data(it: &Item) -> Vec<u8> {
    let units: Vec<u16> = it.name.encode_utf16().collect();
    let mut d = (if it.dir { 3u16 } else { 4u16 }).to_be_bytes().to_vec();
    d.extend_from_slice(&[0, 0]);
    d.extend_from_slice(&it.parent.to_be_bytes());
    d.extend_from_slice(&(units.len() as u16).to_be_bytes());
    for u in units {
        d.extend_from_slice(&u.to_be_bytes());
    }
    d
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// LZVN with literals only: large and small literal opcodes, then the end-of-stream opcode.
fn lzvn_literals(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.len() >= 16 {
            let n = rest.len().min(271);
            out.extend_from_slice(&[0xE0, (n - 16) as u8]);
            out.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
        } else {
            out.push(0xE0 | rest.len() as u8);
            out.extend_from_slice(rest);
            rest = &[];
        }
    }
    out.push(0x06);
    out
}

/// A decmpfs resource fork: a block count, then the offset and size of each block (offsets
/// from the start of the fork), then the blocks. r7z lists these files but does not decode
/// them (see the decmpfs module), so this layout only has to be stable.
fn resource_fork(blocks: &[Vec<u8>]) -> Vec<u8> {
    let mut out = (blocks.len() as u32).to_le_bytes().to_vec();
    let mut pos = 4 + 8 * blocks.len();
    for b in blocks {
        out.extend_from_slice(&(pos as u32).to_le_bytes());
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        pos += b.len();
    }
    for b in blocks {
        out.extend_from_slice(b);
    }
    out
}

/// The decmpfs attribute value: `fpmc`, the type, the uncompressed size, then the payload.
fn decmpfs_value(method: u32, size: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = b"fpmc".to_vec();
    v.extend_from_slice(&method.to_le_bytes());
    v.extend_from_slice(&size.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

/// Pseudo-random bytes that do not compress.
fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            (x >> 16) as u8
        })
        .collect()
}

fn pattern(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i / 7 % 13) as u8 + b'a').collect()
}

const HELLO: &[u8] = b"hello world\n";
const HARD: &[u8] = b"hard link data\n";
const Z3_TEXT: &[u8] = b"compressed inline text, repeated. ";
const Z3RAW_TEXT: &[u8] = b"stored raw inline text\n";
const Z7_TEXT: &[u8] = b"lzvn inline text\n";
const Z5_SIZE: u64 = 1234;

fn z3_text() -> Vec<u8> {
    Z3_TEXT.repeat(40)
}

fn z4_data() -> Vec<u8> {
    let mut v = noise(65536, 7);
    v.extend(pattern(34464));
    v
}

fn z8_data() -> Vec<u8> {
    let mut v = noise(65536, 9);
    v.extend(pattern(4000));
    v
}

/// The sample tree: nested Unicode names, a fragmented file, a symbolic link, a hard link,
/// decmpfs files of each supported type plus one unsupported type, a reserved CNID and the
/// private folders.
fn sample_items() -> Vec<Item> {
    let frag: Vec<u8> = (0..5732).map(|i| (i * 31 % 251) as u8).collect();
    let z3 = z3_text();
    let mut z3_payload = Vec::new();
    z3_payload.extend(zlib(&z3));
    let mut z3raw = vec![0xFF];
    z3raw.extend_from_slice(Z3RAW_TEXT);
    let z4_blocks = vec![{
        let mut raw = vec![0xFF];
        raw.extend_from_slice(&z4_data()[..65536]);
        raw
    }];
    let mut z4_blocks = z4_blocks;
    z4_blocks.push(zlib(&z4_data()[65536..]));
    let z8_blocks = vec![{
        let mut raw = vec![0xFF];
        raw.extend_from_slice(&z8_data()[..65536]);
        raw
    }];
    let mut z8_blocks = z8_blocks;
    z8_blocks.push(lzvn_literals(&z8_data()[65536..]));

    let mut frag_item = file(20, 2, "frag.bin", &frag);
    frag_item.scatter = true;

    let mut link = file(21, 2, "link", b"hello.txt");
    link.typ = *b"slnk";
    link.creator = *b"rhap";
    link.mode = 0o120777;

    let hard = Item {
        cnid: 22,
        parent: 2,
        name: "hard.txt",
        mode: 0o100644,
        typ: *b"hlnk",
        creator: *b"hfs+",
        special: 7,
        ..Item::default()
    };

    let mut z3_item = file(23, 2, "z3.txt", b"");
    z3_item.decmpfs = Some((3, z3.len() as u64, z3_payload));
    let mut z3raw_item = file(24, 2, "z3raw.txt", b"");
    z3raw_item.decmpfs = Some((3, Z3RAW_TEXT.len() as u64, z3raw));
    let mut z4_item = file(25, 2, "z4.bin", b"");
    z4_item.rsrc = resource_fork(&z4_blocks);
    z4_item.scatter = true;
    z4_item.decmpfs = Some((4, z4_data().len() as u64, Vec::new()));
    let z7_payload = lzvn_literals(Z7_TEXT);
    let mut z7_item = file(26, 2, "z7.txt", b"");
    z7_item.decmpfs = Some((7, Z7_TEXT.len() as u64, z7_payload));
    let mut z8_item = file(27, 2, "z8.bin", b"");
    z8_item.rsrc = resource_fork(&z8_blocks);
    z8_item.decmpfs = Some((8, z8_data().len() as u64, Vec::new()));
    let mut z5_item = file(28, 2, "z5.bin", b"");
    z5_item.decmpfs = Some((5, Z5_SIZE, Vec::new()));

    vec![
        dir(16, 2, "Ünïcødé 文件"),
        dir(17, 16, "inner"),
        file(18, 17, "emoji 😀.txt", b"emoji\n"),
        file(19, 2, "hello.txt", HELLO),
        frag_item,
        link,
        hard,
        z3_item,
        z3raw_item,
        z4_item,
        z7_item,
        z8_item,
        z5_item,
        file(29, 2, "empty.txt", b""),
        file(14, 2, "skipme", b"reserved CNID, never listed"),
        dir(40, 2, "\0\0\0\0HFS+ Private Data"),
        file(41, 40, "iNode7", HARD),
        dir(42, 2, "\0\0\0\0HFS+ Private Directory Data\r"),
    ]
    .into_iter()
    .collect()
}

/// Writes a volume holding `items`; `hfsx` selects the HFSX signature.
fn build(items: &[Item], hfsx: bool) -> Vec<u8> {
    let mut img = Image::new();
    let mut over: Vec<Overflow> = Vec::new();
    let mut data_fd = vec![[0u8; 80]; items.len()];
    let mut rsrc_fd = vec![[0u8; 80]; items.len()];
    for (i, it) in items.iter().enumerate() {
        if it.dir {
            continue;
        }
        let blocks = img.alloc(it.data.len().div_ceil(BS), it.scatter);
        img.write(&blocks, &it.data);
        data_fd[i] = fork_data(it.data.len() as u64, &blocks, it.cnid, DATA_FORK, &mut over);
        let blocks = img.alloc(it.rsrc.len().div_ceil(BS), it.scatter);
        img.write(&blocks, &it.rsrc);
        rsrc_fd[i] = fork_data(it.rsrc.len() as u64, &blocks, it.cnid, RSRC_FORK, &mut over);
    }

    // Attributes: decmpfs headers, and a quarantine attribute that must be ignored.
    let mut attrs: Vec<(u32, &str, Vec<u8>)> = Vec::new();
    for it in items {
        if let Some((method, size, payload)) = &it.decmpfs {
            attrs.push((
                it.cnid,
                "com.apple.decmpfs",
                decmpfs_value(*method, *size, payload),
            ));
        }
    }
    attrs.push((19, "com.apple.quarantine", b"0081;00000000;Test;".to_vec()));
    attrs.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    let attr_records: Vec<(Vec<u8>, Vec<u8>)> = attrs
        .iter()
        .map(|(fid, name, value)| {
            let mut d = 0x10u32.to_be_bytes().to_vec();
            d.extend_from_slice(&[0u8; 8]);
            d.extend_from_slice(&(value.len() as u32).to_be_bytes());
            d.extend_from_slice(value);
            (attr_key(*fid, name), d)
        })
        .collect();
    let attr_tree = build_tree(&attr_records);
    let blocks = img.place_nodes(&attr_tree.nodes, true);
    let attr_fd = fork_data(
        (attr_tree.nodes.len() * NODE) as u64,
        &blocks,
        ATTRIBUTES_FILE,
        DATA_FORK,
        &mut over,
    );

    // Catalog: a folder or file record and a thread record per item, in parent and name order.
    // The root folder (CNID 2, parent 1, empty name) is always present.
    let root = dir(ROOT_ID, 1, "");
    let mut cat: Vec<(u32, String, Vec<u8>, Vec<u8>)> = Vec::new();
    cat.push((1, String::new(), catalog_key(1, ""), folder_data(&root)));
    cat.push((
        ROOT_ID,
        String::new(),
        catalog_key(ROOT_ID, ""),
        thread_data(&root),
    ));
    for (i, it) in items.iter().enumerate() {
        let data = if it.dir {
            folder_data(it)
        } else {
            file_data(it, &data_fd[i], &rsrc_fd[i])
        };
        cat.push((
            it.parent,
            it.name.to_string(),
            catalog_key(it.parent, it.name),
            data,
        ));
        cat.push((
            it.cnid,
            String::new(),
            catalog_key(it.cnid, ""),
            thread_data(it),
        ));
    }
    cat.sort_by(|a, b| (a.0, &a.1).cmp(&(b.0, &b.1)));
    let cat_records: Vec<(Vec<u8>, Vec<u8>)> = cat.into_iter().map(|(_, _, k, d)| (k, d)).collect();
    let catalog = build_tree(&cat_records);
    let blocks = img.place_nodes(&catalog.nodes, true);
    let cat_fd = fork_data(
        (catalog.nodes.len() * NODE) as u64,
        &blocks,
        CATALOG_FILE,
        DATA_FORK,
        &mut over,
    );

    // Extents overflow tree, then the allocation bitmap, both in contiguous blocks.
    over.sort_by_key(|a| (a.0, a.1, a.2));
    let ext_records: Vec<(Vec<u8>, Vec<u8>)> = over
        .iter()
        .map(|(fork, fid, start, exts)| {
            let mut key = vec![0, 10, *fork, 0];
            key.extend_from_slice(&fid.to_be_bytes());
            key.extend_from_slice(&start.to_be_bytes());
            let mut data = Vec::new();
            for k in 0..8 {
                let (s, c) = exts.get(k).copied().unwrap_or((0, 0));
                data.extend_from_slice(&s.to_be_bytes());
                data.extend_from_slice(&c.to_be_bytes());
            }
            (key, data)
        })
        .collect();
    let ext_tree = build_tree(&ext_records);
    let ext_blocks = img.place_nodes(&ext_tree.nodes, false);
    let mut ignored = Vec::new();
    let ext_fd = fork_data(
        (ext_tree.nodes.len() * NODE) as u64,
        &ext_blocks,
        EXTENTS_FILE,
        DATA_FORK,
        &mut ignored,
    );
    assert!(ignored.is_empty());

    let bitmap_len = (TOTAL as usize).div_ceil(8);
    let map_blocks = img.alloc(bitmap_len.div_ceil(BS), false);
    let mut bitmap = vec![0u8; bitmap_len];
    for (b, used) in img.used.iter().enumerate() {
        if *used {
            bitmap[b / 8] |= 0x80 >> (b % 8);
        }
    }
    img.write(&map_blocks, &bitmap);
    let alloc_fd = fork_data(
        bitmap_len as u64,
        &map_blocks,
        ALLOCATION_FILE,
        DATA_FORK,
        &mut ignored,
    );

    let folders = items.iter().filter(|it| it.dir).count() as u32;
    let files = items.len() as u32 - folders;
    let free = img.used.iter().filter(|u| !**u).count() as u32;
    let next_id = items.iter().map(|it| it.cnid).max().unwrap_or(0) + 1;
    let mut h = [0u8; 512];
    h[..2].copy_from_slice(if hfsx { b"HX" } else { b"H+" });
    h[2..4].copy_from_slice(&(if hfsx { 5u16 } else { 4 }).to_be_bytes());
    // Unmounted cleanly (bit 8), then counts, free blocks and the next free CNID.
    h[4..8].copy_from_slice(&0x100u32.to_be_bytes());
    h[8..12].copy_from_slice(b"10.0");
    for at in [16, 20, 28] {
        h[at..at + 4].copy_from_slice(&MODIFIED.to_be_bytes());
    }
    h[32..36].copy_from_slice(&files.to_be_bytes());
    h[36..40].copy_from_slice(&folders.to_be_bytes());
    h[40..44].copy_from_slice(&(BS as u32).to_be_bytes());
    h[44..48].copy_from_slice(&TOTAL.to_be_bytes());
    h[48..52].copy_from_slice(&free.to_be_bytes());
    h[64..68].copy_from_slice(&next_id.to_be_bytes());
    h[112..192].copy_from_slice(&alloc_fd);
    h[192..272].copy_from_slice(&ext_fd);
    h[272..352].copy_from_slice(&cat_fd);
    h[352..432].copy_from_slice(&attr_fd);
    img.img[1024..1536].copy_from_slice(&h);
    let end = img.img.len();
    img.img[end - 1024..end - 512].copy_from_slice(&h);
    img.img
}

fn sample(hfsx: bool) -> Vec<u8> {
    build(&sample_items(), hfsx)
}

// ------------------------------------------------------------------ helpers

fn open_bytes(bytes: Vec<u8>) -> Result<format::Opened> {
    format::open_bytes(bytes, "volume.hfs", &OpenRequest::default())
}

/// Opens through the handler directly, so damaged headers reach its checks.
fn open_direct(bytes: Vec<u8>) -> Result<Box<dyn Archive>> {
    (format::hfs::FORMAT.open)(Input::Mem(Slice::from_vec(bytes)), &OpenOptions::default())
}

/// Each unit's bytes, or the error it failed with.
fn extract_each(a: &dyn Archive) -> BTreeMap<String, Result<Vec<u8>>> {
    let mut out = BTreeMap::new();
    for u in 0..a.units().len() {
        let name = a.entries()[a.units()[u].entries[0]].name.clone();
        let mut got = Vec::new();
        let r = a.extract_unit(u, &Ctx::default(), &mut |_, r| {
            r.read_to_end(&mut got).map_err(Error::from)?;
            Ok(Flow::Continue)
        });
        out.insert(name, r.map(|_| got));
    }
    out
}

fn listing(a: &dyn Archive) -> Vec<(String, bool, u64)> {
    let mut v: Vec<_> = a
        .entries()
        .iter()
        .map(|e| (e.name.clone(), e.is_dir, e.size_or_zero()))
        .collect();
    v.sort();
    v
}

fn entry<'a>(a: &'a dyn Archive, name: &str) -> &'a format::Entry {
    a.entries()
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no entry {name:?}"))
}

/// Reader over bytes that counts what was read.
struct Probe {
    data: Slice,
    read: Mutex<u64>,
}

impl ReadAt for Probe {
    fn size(&self) -> u64 {
        ReadAt::size(&self.data)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        *self.read.lock().unwrap() += buf.len() as u64;
        self.data.read_at(offset, buf)
    }
}

// ------------------------------------------------------------------ tests

#[test]
fn lists_visible_tree_only() {
    let bytes = sample(false);
    let o = open_bytes(bytes).unwrap();
    let a = o.archive();
    assert_eq!(a.format().name, "HFS");
    let names: Vec<String> = a.entries().iter().map(|e| e.name.clone()).collect();
    assert!(!names.iter().any(|n| n.contains('\0') || n == "skipme"));
    assert!(!names.iter().any(|n| n.contains("iNode")));
    let mut want = vec![
        ("Ünïcødé 文件".to_string(), true, 0),
        ("Ünïcødé 文件/inner".to_string(), true, 0),
        ("Ünïcødé 文件/inner/emoji 😀.txt".to_string(), false, 6),
        ("empty.txt".to_string(), false, 0),
        ("frag.bin".to_string(), false, 5732),
        ("hard.txt".to_string(), false, HARD.len() as u64),
        ("hello.txt".to_string(), false, 12),
        ("link".to_string(), false, 9),
        ("z3.txt".to_string(), false, (Z3_TEXT.len() * 40) as u64),
        ("z3raw.txt".to_string(), false, Z3RAW_TEXT.len() as u64),
        ("z4.bin".to_string(), false, 100_000),
        ("z5.bin".to_string(), false, Z5_SIZE),
        ("z7.txt".to_string(), false, Z7_TEXT.len() as u64),
        ("z8.bin".to_string(), false, 69_536),
    ];
    want.sort();
    assert_eq!(listing(a), want);
    assert!(a.damage().is_empty(), "{:?}", a.damage());
}

#[test]
fn resource_fork_decmpfs_lists_but_fails_to_extract() {
    let o = open_bytes(sample(false)).unwrap();
    let a = o.archive();
    let got = extract_each(a);
    for name in ["z4.bin", "z8.bin"] {
        let err = got[name].as_ref().unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)), "{name}: {err}");
    }
}

#[test]
fn extracts_every_file_exactly() {
    let o = open_bytes(sample(false)).unwrap();
    let got = extract_each(o.archive());
    let frag: Vec<u8> = (0..5732).map(|i| (i * 31 % 251) as u8).collect();
    let want: Vec<(&str, Vec<u8>)> = vec![
        ("Ünïcødé 文件/inner/emoji 😀.txt", b"emoji\n".to_vec()),
        ("empty.txt", Vec::new()),
        ("frag.bin", frag),
        ("hard.txt", HARD.to_vec()),
        ("hello.txt", HELLO.to_vec()),
        ("link", b"hello.txt".to_vec()),
        ("z3.txt", z3_text()),
        ("z3raw.txt", Z3RAW_TEXT.to_vec()),
        ("z7.txt", Z7_TEXT.to_vec()),
    ];
    for (name, bytes) in want {
        let data = got[name].as_ref().unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(data, &bytes, "{name}");
    }
}

#[test]
fn unsupported_decmpfs_lists_but_fails_to_extract() {
    let o = open_bytes(sample(false)).unwrap();
    let a = o.archive();
    let e = entry(a, "z5.bin");
    assert_eq!(e.method.as_deref(), Some("decmpfs/type5"));
    let err = extract_each(a).remove("z5.bin").unwrap().unwrap_err();
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

#[test]
fn decmpfs_methods_and_sizes() {
    let o = open_bytes(sample(false)).unwrap();
    let a = o.archive();
    assert_eq!(entry(a, "z3.txt").method.as_deref(), Some("decmpfs/zlib"));
    assert_eq!(entry(a, "z4.bin").method.as_deref(), Some("decmpfs/type4"));
    assert_eq!(entry(a, "z7.txt").method.as_deref(), Some("decmpfs/lzvn"));
    assert_eq!(entry(a, "z8.bin").method.as_deref(), Some("decmpfs/type8"));
    assert_eq!(entry(a, "hello.txt").method, None);
}

#[test]
fn symlink_and_hard_link() {
    let o = open_bytes(sample(false)).unwrap();
    let a = o.archive();
    match &entry(a, "link").link {
        Some(Link::Symbolic(t)) => assert_eq!(t, "hello.txt"),
        other => panic!("link is {other:?}"),
    }
    assert!(entry(a, "hard.txt").link.is_none());
    assert_eq!(extract_each(a)["hard.txt"].as_ref().unwrap(), HARD);
}

#[test]
fn hard_link_without_target_is_broken_on_extract() {
    let mut items = sample_items();
    items.retain(|i| i.cnid != 41);
    let o = open_bytes(build(&items, false)).unwrap();
    let a = o.archive();
    let err = extract_each(a).remove("hard.txt").unwrap().unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
}

#[test]
fn times_modes_and_format_property() {
    let o = open_bytes(sample(true)).unwrap();
    let a = o.archive();
    let hello = entry(a, "hello.txt");
    assert_eq!(hello.mtime, Some(MODIFIED_FILETIME));
    let attrib = hello.attrib.unwrap();
    assert_ne!(attrib & 0x8000, 0);
    assert_eq!(attrib >> 16, 0o100644);
    assert_eq!(entry(a, "Ünïcødé 文件").attrib.unwrap() & 0x10, 0x10);
    let format = a
        .properties()
        .into_iter()
        .find(|(k, _)| *k == "Format")
        .unwrap();
    assert_eq!(format.1, "HFSX");
}

#[test]
fn reads_on_demand_through_a_volume() {
    let bytes = sample(false);
    let total = bytes.len() as u64;
    let probe = Arc::new(Probe {
        data: Slice::from_vec(bytes),
        read: Mutex::new(0),
    });
    let a =
        (format::hfs::FORMAT.open)(Input::Volume(probe.clone()), &OpenOptions::default()).unwrap();
    assert_eq!(a.entries().len(), 14);
    let read_by_listing = *probe.read.lock().unwrap();
    assert!(
        read_by_listing < total / 4,
        "{read_by_listing} of {total} bytes"
    );
    let got = extract_each(a.as_ref());
    assert_eq!(got["hello.txt"].as_ref().unwrap(), HELLO);
}

#[test]
fn not_an_hfs_volume() {
    assert!(matches!(
        open_bytes(vec![0u8; 4096]),
        Err(Error::NotArchive)
    ));
    assert!(matches!(
        open_bytes(b"H+ but far too short".to_vec()),
        Err(Error::NotArchive)
    ));
}

#[test]
fn wrapper_volume_is_reported_unsupported() {
    let mut bytes = sample(false);
    bytes[1024..1026].copy_from_slice(b"BD");
    let req = OpenRequest {
        format: format::find_format("hfs"),
        ..OpenRequest::default()
    };
    let err = format::open_bytes(bytes, "volume.hfs", &req).err().unwrap();
    assert!(matches!(err, Error::Unsupported(_)), "{err}");
}

#[test]
fn damaged_headers_and_metadata_fail_cleanly() {
    let good = sample(false);
    let mut failed = 0;
    for at in 1024..1536 {
        for flip in [0x01u8, 0x80, 0xFF] {
            let mut bytes = good.clone();
            bytes[at] ^= flip;
            if let Ok(a) = open_direct(bytes) {
                for r in extract_each(a.as_ref()).into_values() {
                    failed += usize::from(r.is_err());
                }
            } else {
                failed += 1;
            }
        }
    }
    assert!(failed > 0);
}

#[test]
fn damaged_volume_bytes_never_panic() {
    let good = sample(false);
    let mut seen_errors = 0usize;
    let mut at = 0usize;
    while at < good.len() {
        let mut bytes = good.clone();
        bytes[at] = bytes[at].wrapping_add(0x5D);
        if let Ok(a) = open_direct(bytes) {
            seen_errors += extract_each(a.as_ref())
                .values()
                .filter(|r| r.is_err())
                .count();
        } else {
            seen_errors += 1;
        }
        at += 997;
    }
    assert!(seen_errors > 0);
}

#[test]
fn truncated_volumes_fail_cleanly() {
    let good = sample(false);
    for len in (0..good.len()).step_by(4099) {
        let bytes = good[..len].to_vec();
        if let Ok(a) = open_direct(bytes) {
            let _ = extract_each(a.as_ref());
        }
    }
}

/// Writes the sample volume to `R7Z_HFS_IMAGE` for the 7-Zip cross-check. Run with
/// `--ignored`.
#[test]
#[ignore]
fn write_cross_check_image() {
    let path = std::env::var("R7Z_HFS_IMAGE").expect("set R7Z_HFS_IMAGE");
    std::fs::write(path, sample(false)).unwrap();
}

/// The LZVN encoder used by the tests must agree with the reference decoder.
#[test]
fn literal_lzvn_round_trips() {
    for n in [0usize, 1, 15, 16, 17, 270, 271, 272, 5000] {
        let data = pattern(n);
        let enc = lzvn_literals(&data);
        let mut out = vec![0u8; n];
        let got = lzvn::decode_into(&enc, &mut out).unwrap();
        assert_eq!(got, n);
        assert_eq!(out, data);
    }
}
