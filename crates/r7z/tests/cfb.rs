//! Compound File Binary reading: Windows Installer style packages (packed stream names,
//! an embedded cabinet, storages, mini-stream and regular streams, 512- and 4096-byte
//! sectors, DIFAT chains), built by the small writer below. The checked-in fixture
//! `fixtures/cfb/installer.msi` comes from that writer, and its listing and extracted bytes
//! were compared with 7-Zip 25.01 (`7z l -slt -tcompound`, `7z x -tcompound`). The rules
//! the reader follows (entry order, packed names, `[N]` escapes, packed sizes, the single
//! cabinet that nests, the extension) were checked the same way against the MSI and MSP
//! files of a Windows installation. Damaged inputs must fail cleanly.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use r7z::format::{self, cfb, Archive, Ctx, Flow, Input, OpenOptions, OpenRequest, Opened};
use r7z::ops::extract::{extract, Callbacks, ExtractOptions, Target};
use r7z::Error;

// ---------------------------------------------------------------------------------------
// A small CFB writer

const END: u32 = 0xFFFF_FFFE;
const FREE: u32 = 0xFFFF_FFFF;
const FATSECT: u32 = 0xFFFF_FFFD;
const DIFSECT: u32 = 0xFFFF_FFFC;
const CUTOFF: usize = 4096;

enum Item {
    Stream(Vec<u8>),
    Storage(Vec<Node>),
}

struct Node {
    name: Vec<u16>,
    item: Item,
    ctime: u64,
    mtime: u64,
}

/// Windows Installer's packed form of `name` (a leading `!` is the table marker).
fn pack(name: &str) -> Vec<u16> {
    const T: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
    let idx = |c: char| {
        T.find(c)
            .unwrap_or_else(|| panic!("{c:?} cannot be packed")) as u16
    };
    let mut out = Vec::new();
    let rest = match name.strip_prefix('!') {
        Some(r) => {
            out.push(0x4840);
            r
        }
        None => name,
    };
    let chars: Vec<char> = rest.chars().collect();
    for pair in chars.chunks(2) {
        match pair {
            [a, b] => out.push(0x3800 + idx(*a) + (idx(*b) << 6)),
            [a] => out.push(0x4800 + idx(*a)),
            _ => unreachable!(),
        }
    }
    out
}

fn units(name: &str) -> Vec<u16> {
    name.encode_utf16().collect()
}

/// A stream with a Windows Installer packed name.
fn msi(name: &str, data: Vec<u8>) -> Node {
    node(pack(name), Item::Stream(data))
}

/// A stream with a literal name.
fn stream(name: &str, data: Vec<u8>) -> Node {
    node(units(name), Item::Stream(data))
}

fn storage(name: &str, children: Vec<Node>) -> Node {
    node(units(name), Item::Storage(children))
}

fn node(name: Vec<u16>, item: Item) -> Node {
    Node {
        name,
        item,
        ctime: 0,
        mtime: 0,
    }
}

impl Node {
    fn times(mut self, ctime: u64, mtime: u64) -> Node {
        self.ctime = ctime;
        self.mtime = mtime;
        self
    }
}

#[derive(Clone, Copy, Default)]
struct Opt {
    /// 4096-byte sectors (version 4) instead of 512.
    v4: bool,
    /// Alternate the sectors of the big streams, so no chain is consecutive.
    interleave: bool,
}

struct Ent {
    name: Vec<u16>,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    ctime: u64,
    mtime: u64,
    start: u32,
    size: u64,
}

impl Ent {
    fn unused() -> Ent {
        Ent {
            name: Vec::new(),
            kind: 0,
            left: FREE,
            right: FREE,
            child: FREE,
            ctime: 0,
            mtime: 0,
            start: 0,
            size: 0,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        let mut b = vec![0u8; 128];
        for (i, u) in self.name.iter().enumerate() {
            b[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        let len = if self.name.is_empty() {
            0
        } else {
            self.name.len() as u16 * 2 + 2
        };
        b[64..66].copy_from_slice(&len.to_le_bytes());
        b[66] = self.kind;
        b[67] = 1; // black
        b[68..72].copy_from_slice(&self.left.to_le_bytes());
        b[72..76].copy_from_slice(&self.right.to_le_bytes());
        b[76..80].copy_from_slice(&self.child.to_le_bytes());
        b[100..108].copy_from_slice(&self.ctime.to_le_bytes());
        b[108..116].copy_from_slice(&self.mtime.to_le_bytes());
        b[116..120].copy_from_slice(&self.start.to_le_bytes());
        b[120..128].copy_from_slice(&self.size.to_le_bytes());
        b
    }
}

/// CFB's name order: shorter first, then by upper-cased code units.
fn sort_key(name: &[u16]) -> (usize, Vec<u16>) {
    let up = |u: u16| {
        if (b'a' as u16..=b'z' as u16).contains(&u) {
            u - 32
        } else {
            u
        }
    };
    (name.len(), name.iter().map(|&u| up(u)).collect())
}

/// Makes the sorted siblings `ents[lo..hi]` a balanced binary tree; returns its root.
fn link(ents: &mut [Ent], lo: usize, hi: usize) -> u32 {
    if lo >= hi {
        return FREE;
    }
    let mid = (lo + hi) / 2;
    let left = link(ents, lo, mid);
    let right = link(ents, mid + 1, hi);
    ents[mid].left = left;
    ents[mid].right = right;
    mid as u32
}

type Streams<'a> = Vec<(usize, &'a [u8])>;

/// Appends the entries of `nodes` (and below) to `ents`; returns the sibling tree's root.
fn flatten<'a>(
    nodes: &'a [Node],
    path: &str,
    ents: &mut Vec<Ent>,
    streams: &mut Streams<'a>,
    index: &mut BTreeMap<String, usize>,
) -> u32 {
    let mut order: Vec<usize> = (0..nodes.len()).collect();
    order.sort_by_key(|&i| sort_key(&nodes[i].name));
    let base = ents.len();
    for &i in &order {
        let n = &nodes[i];
        let (kind, size) = match &n.item {
            Item::Stream(d) => (2, d.len() as u64),
            Item::Storage(_) => (1, 0),
        };
        ents.push(Ent {
            name: n.name.clone(),
            kind,
            ctime: n.ctime,
            mtime: n.mtime,
            size,
            ..Ent::unused()
        });
        let label = String::from_utf16_lossy(&n.name);
        index.insert(format!("{path}{label}"), ents.len() - 1);
    }
    let root = link(ents, base, base + nodes.len());
    for (k, &i) in order.iter().enumerate() {
        let label = String::from_utf16_lossy(&nodes[i].name);
        match &nodes[i].item {
            Item::Stream(d) => streams.push((base + k, d)),
            Item::Storage(children) => {
                let child = flatten(children, &format!("{path}{label}/"), ents, streams, index);
                ents[base + k].child = child;
            }
        }
    }
    root
}

/// A built file plus where its tables are, so tests can damage them.
struct Built {
    bytes: Vec<u8>,
    ss: usize,
    dir_sectors: Vec<u32>,
    fat_sectors: Vec<u32>,
    mini_fat_sector: Option<u32>,
    /// Entry number by path label (packed names show as their packed units).
    entry: BTreeMap<String, usize>,
    start: BTreeMap<String, u32>,
}

impl Built {
    fn sector_at(&self, s: u32) -> usize {
        (s as usize + 1) * self.ss
    }

    fn entry_at(&self, i: usize) -> usize {
        let per = self.ss / 128;
        self.sector_at(self.dir_sectors[i / per]) + (i % per) * 128
    }

    fn set_u32(&mut self, at: usize, v: u32) {
        self.bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn set_fat(&mut self, i: u32, v: u32) {
        let per = (self.ss / 4) as u32;
        let at = self.sector_at(self.fat_sectors[(i / per) as usize]) + (i % per) as usize * 4;
        self.set_u32(at, v);
    }

    fn set_mini_fat(&mut self, i: u32, v: u32) {
        let at = self.sector_at(self.mini_fat_sector.unwrap()) + i as usize * 4;
        self.set_u32(at, v);
    }

    /// Overwrites a field of directory entry `i` (offsets as in the specification).
    fn set_field(&mut self, i: usize, field: usize, v: u32) {
        let at = self.entry_at(i) + field;
        self.set_u32(at, v);
    }
}

fn build(root: &[Node], o: Opt) -> Built {
    let ss = if o.v4 { 4096 } else { 512 };
    let per = ss / 4;
    let mut ents = vec![Ent {
        name: units("Root Entry"),
        kind: 5,
        ..Ent::unused()
    }];
    let mut streams: Streams = Vec::new();
    let mut entry = BTreeMap::new();
    let child = flatten(root, "", &mut ents, &mut streams, &mut entry);
    ents[0].child = child;

    // Mini stream and regular streams.
    let mut mini: Vec<u8> = Vec::new();
    let mut mini_fat: Vec<u32> = Vec::new();
    let mut bigs: Vec<(usize, &[u8], usize)> = Vec::new();
    for &(e, d) in &streams {
        if d.is_empty() {
            ents[e].start = END;
        } else if d.len() < CUTOFF {
            ents[e].start = mini_fat.len() as u32;
            let n = d.len().div_ceil(64);
            for k in 0..n {
                mini_fat.push(if k + 1 < n {
                    mini_fat.len() as u32 + 1
                } else {
                    END
                });
            }
            mini.extend_from_slice(d);
            mini.resize(mini_fat.len() * 64, 0);
        } else {
            bigs.push((e, d, d.len().div_ceil(ss)));
        }
    }
    let mut owners: Vec<(usize, usize)> = Vec::new();
    if o.interleave {
        for r in 0..bigs.iter().map(|b| b.2).max().unwrap_or(0) {
            for (b, big) in bigs.iter().enumerate() {
                if r < big.2 {
                    owners.push((b, r));
                }
            }
        }
    } else {
        for (b, big) in bigs.iter().enumerate() {
            owners.extend((0..big.2).map(|r| (b, r)));
        }
    }
    let at = |b: usize, r: usize| owners.iter().position(|&x| x == (b, r)).unwrap() as u32;

    let nb = owners.len();
    let nm = mini.len().div_ceil(ss);
    let nmf = (mini_fat.len() * 4).div_ceil(ss);
    let nd = (ents.len() * 128).div_ceil(ss);
    let (first_mini, first_mini_fat) = (nb, nb + nm);
    let first_dir = first_mini_fat + nmf;
    let first_fat = first_dir + nd;
    let mut f = 1;
    let difat_for = |f: usize| f.saturating_sub(109).div_ceil(per - 1);
    while f * per < nb + nm + nmf + nd + f + difat_for(f) {
        f += 1;
    }
    let n_difat = difat_for(f);
    let first_difat = first_fat + f;
    let total = first_difat + n_difat;

    let mut fat = vec![FREE; f * per];
    let chain = |fat: &mut Vec<u32>, first: usize, n: usize| {
        for k in 0..n {
            fat[first + k] = if k + 1 < n {
                (first + k + 1) as u32
            } else {
                END
            };
        }
    };
    for (b, big) in bigs.iter().enumerate() {
        for r in 0..big.2 {
            fat[at(b, r) as usize] = if r + 1 < big.2 { at(b, r + 1) } else { END };
        }
        ents[big.0].start = at(b, 0);
    }
    chain(&mut fat, first_mini, nm);
    chain(&mut fat, first_mini_fat, nmf);
    chain(&mut fat, first_dir, nd);
    for k in 0..f {
        fat[first_fat + k] = FATSECT;
    }
    for k in 0..n_difat {
        fat[first_difat + k] = DIFSECT;
    }
    ents[0].start = if nm > 0 { first_mini as u32 } else { END };
    ents[0].size = mini.len() as u64;

    let start: BTreeMap<String, u32> = entry
        .iter()
        .map(|(k, &e)| (k.clone(), ents[e].start))
        .collect();

    // Header.
    let mut out = vec![0u8; (total + 1) * ss];
    let put32 =
        |out: &mut Vec<u8>, at: usize, v: u32| out[at..at + 4].copy_from_slice(&v.to_le_bytes());
    out[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    out[24..26].copy_from_slice(&0x3Eu16.to_le_bytes());
    out[26..28].copy_from_slice(&(if o.v4 { 4u16 } else { 3 }).to_le_bytes());
    out[28..30].copy_from_slice(&0xFFFEu16.to_le_bytes());
    out[30..32].copy_from_slice(&(if o.v4 { 12u16 } else { 9 }).to_le_bytes());
    out[32..34].copy_from_slice(&6u16.to_le_bytes());
    put32(&mut out, 40, if o.v4 { nd as u32 } else { 0 });
    put32(&mut out, 44, f as u32);
    put32(&mut out, 48, first_dir as u32);
    put32(&mut out, 56, CUTOFF as u32);
    put32(
        &mut out,
        60,
        if nmf > 0 { first_mini_fat as u32 } else { END },
    );
    put32(&mut out, 64, nmf as u32);
    put32(
        &mut out,
        68,
        if n_difat > 0 { first_difat as u32 } else { END },
    );
    put32(&mut out, 72, n_difat as u32);
    let fat_sectors: Vec<u32> = (0..f).map(|k| (first_fat + k) as u32).collect();
    for k in 0..109 {
        put32(
            &mut out,
            76 + 4 * k,
            fat_sectors.get(k).copied().unwrap_or(FREE),
        );
    }

    // Sectors.
    let sector = |s: usize| (s + 1) * ss;
    for (b, big) in bigs.iter().enumerate() {
        for r in 0..big.2 {
            let part = &big.1[r * ss..((r + 1) * ss).min(big.1.len())];
            let o = sector(at(b, r) as usize);
            out[o..o + part.len()].copy_from_slice(part);
        }
    }
    out[sector(first_mini)..sector(first_mini) + mini.len()].copy_from_slice(&mini);
    for (k, v) in mini_fat.iter().enumerate() {
        put32(&mut out, sector(first_mini_fat) + k * 4, *v);
    }
    for k in 0..nmf * per - mini_fat.len() {
        put32(
            &mut out,
            sector(first_mini_fat) + (mini_fat.len() + k) * 4,
            FREE,
        );
    }
    ents.resize_with(nd * ss / 128, Ent::unused);
    for (i, e) in ents.iter().enumerate() {
        let o = sector(first_dir) + i * 128;
        out[o..o + 128].copy_from_slice(&e.bytes());
    }
    for (k, v) in fat.iter().enumerate() {
        put32(&mut out, sector(first_fat) + k * 4, *v);
    }
    for k in 0..n_difat {
        let o = sector(first_difat + k);
        for j in 0..per - 1 {
            let v = fat_sectors
                .get(109 + k * (per - 1) + j)
                .copied()
                .unwrap_or(FREE);
            put32(&mut out, o + j * 4, v);
        }
        let next = if k + 1 < n_difat {
            (first_difat + k + 1) as u32
        } else {
            END
        };
        put32(&mut out, o + (per - 1) * 4, next);
    }

    Built {
        bytes: out,
        ss,
        dir_sectors: (0..nd).map(|k| (first_dir + k) as u32).collect(),
        fat_sectors,
        mini_fat_sector: (nmf > 0).then_some(first_mini_fat as u32),
        entry,
        start,
    }
}

// ---------------------------------------------------------------------------------------
// A stored cabinet

const CAB_DATE: u16 = (41 << 9) | (8 << 5) | 13;
const CAB_TIME: u16 = (16 << 11) | (48 << 5) | 22;

/// One stored folder holding `files` in one data block (their total stays under 32 KiB).
fn make_cab(files: &[(&str, &[u8])]) -> Vec<u8> {
    let data: Vec<u8> = files.iter().flat_map(|(_, d)| d.iter().copied()).collect();
    assert!(data.len() < 32768);
    let mut recs = Vec::new();
    let mut offset = 0u32;
    for (name, d) in files {
        recs.extend((d.len() as u32).to_le_bytes());
        recs.extend(offset.to_le_bytes());
        recs.extend(0u16.to_le_bytes());
        recs.extend(CAB_DATE.to_le_bytes());
        recs.extend(CAB_TIME.to_le_bytes());
        recs.extend(0x20u16.to_le_bytes());
        recs.extend(name.bytes());
        recs.push(0);
        offset += d.len() as u32;
    }
    let files_at = 36 + 8;
    let data_at = files_at + recs.len();
    let total = data_at + 8 + data.len();
    let mut out = b"MSCF".to_vec();
    out.extend(0u32.to_le_bytes());
    out.extend((total as u32).to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend((files_at as u32).to_le_bytes());
    out.extend(0u32.to_le_bytes());
    out.extend([3u8, 1]);
    out.extend(1u16.to_le_bytes());
    out.extend((files.len() as u16).to_le_bytes());
    out.extend([0u8; 6]);
    out.extend((data_at as u32).to_le_bytes());
    out.extend(1u16.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out.extend(recs);
    out.extend(0u32.to_le_bytes());
    out.extend((data.len() as u16).to_le_bytes());
    out.extend((data.len() as u16).to_le_bytes());
    out.extend(data);
    out
}

// ---------------------------------------------------------------------------------------
// Test helpers

struct Quiet;
impl Callbacks for Quiet {}

/// Deterministic bytes that differ by `tag` and position.
fn bytes(tag: u8, len: usize) -> Vec<u8> {
    (0..len as u32)
        .map(|i| {
            (i.wrapping_mul(2_654_435_761)
                .wrapping_add(u32::from(tag) * 977)
                >> 13) as u8
        })
        .collect()
}

fn fixture_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cfb/installer.msi")
}

fn compound() -> OpenRequest {
    OpenRequest {
        format: Some(&cfb::FORMAT),
        ..Default::default()
    }
}

/// Opens as exactly a compound file (no nested archive).
fn open_cfb(data: Vec<u8>, name: &str) -> Opened {
    format::open_bytes(data, name, &compound()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn names(a: &dyn Archive) -> Vec<&str> {
    a.entries().iter().map(|e| e.name.as_str()).collect()
}

fn entry<'a>(a: &'a dyn Archive, name: &str) -> &'a format::Entry {
    a.entries()
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no entry {name}: {:?}", names(a)))
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

/// Compares bytes without printing them: the length and the first difference.
#[track_caller]
fn assert_bytes(got: &[u8], want: &[u8], what: &str) {
    let diff = got.iter().zip(want).position(|(a, b)| a != b);
    assert!(
        got.len() == want.len() && diff.is_none(),
        "{what}: {} bytes, expected {}, first difference at {diff:?}",
        got.len(),
        want.len()
    );
}

#[track_caller]
fn assert_contents(got: &BTreeMap<String, Vec<u8>>, want: &BTreeMap<String, Vec<u8>>, what: &str) {
    assert_eq!(
        got.keys().collect::<Vec<_>>(),
        want.keys().collect::<Vec<_>>(),
        "{what}"
    );
    for (name, data) in want {
        assert_bytes(&got[name], data, &format!("{what}: {name}"));
    }
}

/// The extractor's test run over every level.
fn test_levels(o: &Opened) -> r7z::Result<()> {
    for lvl in &o.levels {
        let opts = ExtractOptions {
            base: None,
            password: None,
            threads: 1,
            target: Target::Test,
            selected: None,
        };
        let rep = extract(&*lvl.archive, &opts, &Quiet)?;
        if let Some((_, e)) = rep.errors.into_iter().next() {
            return Err(e);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// The sample package

fn tiny_cab() -> Vec<u8> {
    make_cab(&[
        ("readme.txt", b"installed by a package\n"),
        ("bin/tool.dat", &bytes(9, 300)),
        ("empty.txt", b""),
    ])
}

/// What the checked-in fixture holds: tables and properties in the mini stream, a regular
/// stream, a small cabinet, and storages with children.
fn sample() -> Vec<Node> {
    vec![
        msi("!_Tables", bytes(1, 46)),
        msi("!Property", bytes(2, 40)),
        msi("!Media", bytes(3, 14)),
        msi("!File", bytes(4, 100)),
        stream("\u{5}SummaryInformation", bytes(5, 572)),
        msi("Binary.Probe.bin", bytes(6, 4100)),
        msi("media1.cab", tiny_cab()),
        storage(
            "Sub",
            vec![
                stream("inner.txt", bytes(7, 24)),
                storage("Deeper", vec![stream("leaf.bin", bytes(8, 4096))])
                    .times(133_000_000_000_000_000, 133_000_000_050_000_000),
                stream("empty", Vec::new()),
            ],
        )
        .times(133_000_000_100_000_000, 133_000_000_200_000_000),
    ]
}

fn sample_contents() -> BTreeMap<String, Vec<u8>> {
    [
        ("!_Tables", bytes(1, 46)),
        ("!Property", bytes(2, 40)),
        ("!Media", bytes(3, 14)),
        ("!File", bytes(4, 100)),
        ("[5]SummaryInformation", bytes(5, 572)),
        ("Binary.Probe.bin", bytes(6, 4100)),
        ("media1.cab", tiny_cab()),
        ("Sub/inner.txt", bytes(7, 24)),
        ("Sub/Deeper/leaf.bin", bytes(8, 4096)),
    ]
    .into_iter()
    .map(|(n, d)| (n.to_string(), d))
    .collect()
}

fn sample_file(o: Opt) -> Vec<u8> {
    build(&sample(), o).bytes
}

#[test]
fn fixture_is_what_the_writer_makes() {
    let path = fixture_path();
    if std::env::var_os("R7Z_REGEN_CFB_FIXTURE").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, sample_file(Opt::default())).unwrap();
    }
    let on_disk = fs::read(&path).unwrap();
    assert!(on_disk.len() < 20_000, "{} bytes", on_disk.len());
    assert!(
        on_disk == sample_file(Opt::default()),
        "fixtures/cfb/installer.msi is stale: rerun with R7Z_REGEN_CFB_FIXTURE=1"
    );
}

/// The listing 7-Zip gives the fixture (`7z l -slt -tcompound`): each entry, its left and
/// right subtrees, then a storage's children; sizes packed to the mini or regular sector.
#[test]
fn fixture_listing() {
    let o = open_cfb(fs::read(fixture_path()).unwrap(), "installer.msi");
    let a = o.archive();
    assert_eq!(a.format().name, "Compound");
    let got: Vec<(&str, bool, Option<u64>, Option<u64>)> = a
        .entries()
        .iter()
        .map(|e| (e.name.as_str(), e.is_dir, e.size, e.packed_size))
        .collect();
    let want: Vec<(&str, bool, Option<u64>, Option<u64>)> = vec![
        ("!_Tables", false, Some(46), Some(64)),
        ("!Media", false, Some(14), Some(64)),
        ("!File", false, Some(100), Some(128)),
        ("Sub", true, None, None),
        ("Sub/Deeper", true, None, None),
        ("Sub/empty", false, Some(0), Some(0)),
        ("Sub/inner.txt", false, Some(24), Some(64)),
        ("Sub/Deeper/leaf.bin", false, Some(4096), Some(4096)),
        ("media1.cab", false, Some(457), Some(512)),
        ("Binary.Probe.bin", false, Some(4100), Some(4608)),
        ("!Property", false, Some(40), Some(64)),
        ("[5]SummaryInformation", false, Some(572), Some(576)),
    ];
    assert_eq!(got, want);
    assert_eq!(prop(a, "Extension").as_deref(), Some("msi"));
    assert_eq!(prop(a, "Cluster Size").as_deref(), Some("512"));
    assert_eq!(prop(a, "Sector Size").as_deref(), Some("64"));
    assert_eq!(
        prop(a, "Physical Size"),
        Some(fs::metadata(fixture_path()).unwrap().len().to_string())
    );
    assert_eq!(prop(a, "Tail Size"), None);
    assert_eq!(prop(a, "ERROR"), None);
    assert_eq!(prop(a, "Warning"), None);
    // Storages carry times; streams of an installer package do not.
    let sub = entry(a, "Sub");
    assert_eq!(
        (sub.ctime, sub.mtime),
        (Some(133_000_000_100_000_000), Some(133_000_000_200_000_000))
    );
    assert!(sub.attr_string().starts_with('D'));
    assert_eq!(entry(a, "!File").mtime, None);
    assert_eq!(entry(a, "Sub/inner.txt").attr_string(), ".....");
}

#[test]
fn fixture_contents() {
    let o = open_cfb(fs::read(fixture_path()).unwrap(), "installer.msi");
    assert_contents(
        &contents(o.archive()).unwrap(),
        &sample_contents(),
        "package",
    );
    test_levels(&o).unwrap();
    // Empty streams and storages are outside every unit.
    let a = o.archive();
    let unitless: Vec<_> = (0..a.entries().len())
        .filter(|i| !a.units().iter().any(|u| u.entries.contains(i)))
        .map(|i| a.entries()[i].name.as_str())
        .collect();
    assert_eq!(unitless, ["Sub", "Sub/Deeper", "Sub/empty"]);
}

#[test]
fn small_reads_cross_every_sector_boundary() {
    for v4 in [false, true] {
        let o = open_cfb(
            sample_file(Opt {
                v4,
                ..Opt::default()
            }),
            "p.msi",
        );
        let a = o.archive();
        let mut got = BTreeMap::new();
        for u in 0..a.units().len() {
            a.extract_unit(u, &Ctx::default(), &mut |i, r| {
                let mut v = Vec::new();
                let mut buf = [0u8; 7];
                loop {
                    let n = r.read(&mut buf).map_err(Error::from)?;
                    if n == 0 {
                        break;
                    }
                    v.extend_from_slice(&buf[..n]);
                }
                got.insert(a.entries()[i].name.clone(), v);
                Ok(Flow::Continue)
            })
            .unwrap();
        }
        assert_contents(&got, &sample_contents(), &format!("v4={v4}"));
    }
}

#[test]
fn version_4_package_has_the_same_listing_and_bytes() {
    let v3 = open_cfb(sample_file(Opt::default()), "p.msi");
    let v4 = open_cfb(
        sample_file(Opt {
            v4: true,
            ..Opt::default()
        }),
        "p.msi",
    );
    assert_eq!(names(v3.archive()), names(v4.archive()));
    assert_eq!(prop(v4.archive(), "Cluster Size").as_deref(), Some("4096"));
    assert_eq!(prop(v4.archive(), "Sector Size").as_deref(), Some("64"));
    // Packed sizes follow the sector size: 4100 bytes take two 4096-byte sectors.
    assert_eq!(
        entry(v4.archive(), "Binary.Probe.bin").packed_size,
        Some(8192)
    );
    assert_eq!(
        entry(v4.archive(), "Sub/Deeper/leaf.bin").packed_size,
        Some(4096)
    );
    assert_contents(&contents(v4.archive()).unwrap(), &sample_contents(), "v4");
    test_levels(&v4).unwrap();
}

// ---------------------------------------------------------------------------------------
// Entry order

#[test]
fn entries_follow_the_directory_tree_not_the_sort_order() {
    // Siblings a..e sort as a tree rooted at c (b, a to its left; e, d to its right).
    // 7-Zip lists a node, its left subtree, its right subtree, then a storage's children.
    let tree = vec![
        stream("a", vec![1]),
        storage("b", vec![stream("y", vec![2])]),
        storage("c", vec![stream("x", vec![3])]),
        stream("d", vec![4]),
        stream("e", vec![5]),
    ];
    let o = open_cfb(build(&tree, Opt::default()).bytes, "t.bin");
    assert_eq!(names(o.archive()), ["c", "b", "a", "b/y", "e", "d", "c/x"]);
    assert_eq!(prop(o.archive(), "Extension").as_deref(), Some("compound"));
    let data = contents(o.archive()).unwrap();
    assert_eq!(data["b/y"], [2]);
    assert_eq!(data["c/x"], [3]);
    assert_eq!(data["d"], [4]);
}

// ---------------------------------------------------------------------------------------
// Names

#[test]
fn packed_and_literal_names() {
    let tree = vec![
        // Two characters per unit, one for an odd tail, then the table marker.
        msi("!Registry", vec![1]),
        msi("Icon.idle.exe", vec![2]),
        // One unit outside the packed range keeps the whole name literal.
        node(vec![0x4192, 0x4472, 0x4841], Item::Stream(vec![3])),
        node(vec![0x4840, u16::from(b'P'), 0x4800], Item::Stream(vec![4])),
        stream("tab\u{1}ctl\u{1f}", vec![5]),
        stream("caf\u{e9} \u{1f600}", vec![6]),
    ];
    let o = open_cfb(build(&tree, Opt::default()).bytes, "n.msi");
    let mut got = names(o.archive());
    got.sort();
    let mut want = vec![
        "!Registry",
        "Icon.idle.exe",
        "\u{4192}\u{4472}\u{4841}",
        "\u{4840}P\u{4800}",
        "tab[1]ctl[31]",
        "caf\u{e9} \u{1f600}",
    ];
    want.sort();
    assert_eq!(got, want);
}

#[test]
fn an_empty_name_is_the_archive_name() {
    let tree = vec![
        node(Vec::new(), Item::Stream(vec![7, 7])),
        stream("x", vec![1]),
    ];
    let data = build(&tree, Opt::default()).bytes;
    let o = open_cfb(data.clone(), "pkg.msi");
    assert!(names(o.archive()).contains(&"pkg"));
    assert_eq!(contents(o.archive()).unwrap()["pkg"], [7, 7]);
    let o = open_cfb(data, "");
    assert!(names(o.archive()).contains(&"[no name]"));
}

#[test]
fn names_stop_at_the_first_nul_whatever_the_length_field_says() {
    let mut b = build(&[stream("abc", vec![1])], Opt::default());
    let at = b.entry_at(b.entry["abc"]);
    b.bytes[at + 64..at + 66].copy_from_slice(&0u16.to_le_bytes());
    let o = open_cfb(b.bytes, "n.bin");
    assert_eq!(names(o.archive()), ["abc"]);
}

// ---------------------------------------------------------------------------------------
// Properties

fn single(name: Vec<u16>) -> Vec<Node> {
    vec![node(name, Item::Stream(vec![1, 2, 3]))]
}

#[test]
fn the_extension_comes_from_the_first_telling_entry() {
    let ext = |tree: Vec<Node>| {
        let o = open_cfb(build(&tree, Opt::default()).bytes, "x.bin");
        prop(o.archive(), "Extension").unwrap()
    };
    assert_eq!(ext(single(units("Contents"))), "compound");
    assert_eq!(ext(single(pack("!_Tables"))), "msi");
    assert_eq!(ext(single(pack("Foo"))), "msi");
    assert_eq!(ext(single(pack("!MsiPatchMetadata"))), "msp");
    assert_eq!(ext(single(units("WordDocument"))), "doc");
    assert_eq!(ext(single(units("Workbook"))), "xls");
    assert_eq!(ext(single(units("PowerPoint Document"))), "ppt");
    // A packed name that spells an Office stream is still only an installer name.
    assert_eq!(ext(single(pack("Workbook"))), "msi");
    // Of several, the entry that comes first in the directory (by number) decides, and a
    // document or patch beats the installer default. Siblings are numbered shortest name
    // first, then their storages' children.
    assert_eq!(
        ext(vec![
            node(pack("!_Tables"), Item::Stream(vec![1])),
            node(pack("!MsiPatchMetadata"), Item::Stream(vec![2]))
        ]),
        "msp"
    );
    let nested = |first: &str, second: &str| {
        vec![
            storage("s", vec![stream(second, vec![2])]),
            stream(first, vec![1]),
        ]
    };
    assert_eq!(ext(nested("Workbook", "WordDocument")), "xls");
    assert_eq!(ext(nested("WordDocument", "Workbook")), "doc");
    assert_eq!(ext(nested("WordDocument", "PowerPoint Document")), "doc");
}

#[test]
fn a_tail_and_a_truncation_are_reported() {
    let data = sample_file(Opt::default());
    let whole = open_cfb(data.clone(), "p.msi");
    assert_eq!(
        prop(whole.archive(), "Physical Size"),
        Some(data.len().to_string())
    );

    let mut tail = data.clone();
    tail.extend([0u8; 1000]);
    let o = open_cfb(tail, "p.msi");
    assert_eq!(
        prop(o.archive(), "Physical Size"),
        Some(data.len().to_string())
    );
    assert_eq!(prop(o.archive(), "Tail Size").as_deref(), Some("1000"));
    assert!(prop(o.archive(), "Warning").is_some());
    assert_contents(
        &contents(o.archive()).unwrap(),
        &sample_contents(),
        "package",
    );

    // The FAT is the last sector: a file cut inside it still lists what its tables reach.
    let o = open_cfb(data[..data.len() - 100].to_vec(), "p.msi");
    assert_eq!(
        prop(o.archive(), "Physical Size"),
        Some(data.len().to_string())
    );
    assert_eq!(
        prop(o.archive(), "ERROR").as_deref(),
        Some("Unexpected end of archive")
    );
}

// ---------------------------------------------------------------------------------------
// Streams: sizes, fragmentation, many FAT sectors

#[test]
fn the_cutoff_decides_between_mini_and_regular_streams() {
    let tree = vec![
        stream("m4095", bytes(1, 4095)),
        stream("r4096", bytes(2, 4096)),
        stream("m1", bytes(3, 1)),
        stream("m64", bytes(4, 64)),
        stream("m65", bytes(5, 65)),
        stream("r4097", bytes(6, 4097)),
    ];
    let o = open_cfb(build(&tree, Opt::default()).bytes, "s.bin");
    let a = o.archive();
    for (n, packed) in [
        ("m4095", 4096),
        ("r4096", 4096),
        ("m1", 64),
        ("m64", 64),
        ("m65", 128),
        ("r4097", 4608),
    ] {
        assert_eq!(entry(a, n).packed_size, Some(packed), "{n}");
    }
    let data = contents(a).unwrap();
    assert_bytes(&data["m4095"], &bytes(1, 4095), "m4095");
    assert_bytes(&data["r4096"], &bytes(2, 4096), "r4096");
    assert_bytes(&data["m65"], &bytes(5, 65), "m65");
    assert_bytes(&data["r4097"], &bytes(6, 4097), "r4097");
}

#[test]
fn fragmented_chains_read_in_order() {
    let tree = vec![
        stream("one", bytes(1, 20_000)),
        stream("two", bytes(2, 33_333)),
        stream("three", bytes(3, 5_000)),
        stream("tiny", bytes(4, 700)),
    ];
    for v4 in [false, true] {
        let o = open_cfb(
            build(
                &tree,
                Opt {
                    v4,
                    interleave: true,
                },
            )
            .bytes,
            "f.bin",
        );
        let data = contents(o.archive()).unwrap();
        assert_bytes(&data["one"], &bytes(1, 20_000), &format!("one v4={v4}"));
        assert_bytes(&data["two"], &bytes(2, 33_333), &format!("two v4={v4}"));
        assert_bytes(&data["three"], &bytes(3, 5_000), &format!("three v4={v4}"));
        assert_bytes(&data["tiny"], &bytes(4, 700), &format!("tiny v4={v4}"));
    }
}

#[test]
fn more_than_109_fat_sectors_use_the_difat_chain() {
    // 109 FAT sectors of 128 entries cover 13,952 sectors of 512 bytes (7.1 MB).
    let big = bytes(9, 7_400_000);
    let tree = vec![stream("big", big.clone()), stream("after", bytes(2, 5_000))];
    let built = build(&tree, Opt::default());
    assert!(built.fat_sectors.len() > 109);
    let o = open_cfb(built.bytes, "big.bin");
    let a = o.archive();
    assert_eq!(entry(a, "big").size, Some(big.len() as u64));
    let data = contents(a).unwrap();
    assert_bytes(&data["big"], &big, "big");
    assert_bytes(&data["after"], &bytes(2, 5_000), "after");
    assert_eq!(prop(a, "ERROR"), None);
}

#[test]
fn the_high_half_of_a_version_3_size_is_ignored() {
    let mut b = build(&[stream("s", bytes(1, 600))], Opt::default());
    let at = b.entry_at(b.entry["s"]);
    b.set_u32(at + 124, 0xDEAD_BEEF);
    let o = open_cfb(b.bytes, "s.bin");
    assert_eq!(entry(o.archive(), "s").size, Some(600));
    assert_bytes(&contents(o.archive()).unwrap()["s"], &bytes(1, 600), "s");
}

// ---------------------------------------------------------------------------------------
// Times

#[test]
fn times_are_filetimes_and_zero_is_unknown() {
    let tree = vec![
        stream("a", vec![1]).times(0, 133_100_000_000_000_000),
        storage("b", Vec::new()).times(133_200_000_000_000_000, 0),
    ];
    let o = open_cfb(build(&tree, Opt::default()).bytes, "t.bin");
    let (a, b) = (entry(o.archive(), "a"), entry(o.archive(), "b"));
    assert_eq!((a.ctime, a.mtime), (None, Some(133_100_000_000_000_000)));
    assert_eq!((b.ctime, b.mtime), (Some(133_200_000_000_000_000), None));
    assert!(b.is_dir);
}

// ---------------------------------------------------------------------------------------
// The embedded cabinet

fn cab_entries(o: &Opened) -> Vec<(String, Option<u64>)> {
    o.archive()
        .entries()
        .iter()
        .map(|e| (e.name.clone(), e.size))
        .collect()
}

#[test]
fn the_only_cabinet_opens_as_a_nested_archive() {
    let o = format::open_bytes(
        sample_file(Opt::default()),
        "p.msi",
        &OpenRequest::default(),
    )
    .unwrap();
    assert_eq!(o.levels.len(), 2);
    assert_eq!(o.levels[0].archive.format().name, "Compound");
    assert_eq!(o.levels[1].archive.format().name, "Cab");
    assert_eq!(o.levels[1].name, "media1.cab");
    assert_eq!(
        cab_entries(&o),
        [
            ("readme.txt".to_string(), Some(23)),
            ("bin/tool.dat".to_string(), Some(300)),
            ("empty.txt".to_string(), Some(0)),
        ]
    );
    let data = contents(o.archive()).unwrap();
    assert_eq!(data["readme.txt"], b"installed by a package\n");
    assert_bytes(&data["bin/tool.dat"], &bytes(9, 300), "tool.dat");
    test_levels(&o).unwrap();
    // The package's own streams stay reachable by forcing the type.
    let flat = open_cfb(sample_file(Opt::default()), "p.msi");
    assert_eq!(flat.levels.len(), 1);
    assert!(names(flat.archive()).contains(&"media1.cab"));
}

#[test]
fn a_regular_stream_cabinet_nests_from_either_sector_size() {
    // The repository's stored cabinet is 6143 bytes: a regular stream.
    let cab = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cab/none.cab"))
        .unwrap();
    let direct = format::open_bytes(cab.clone(), "none.cab", &OpenRequest::default()).unwrap();
    let want = cab_entries(&direct);
    for opt in [
        Opt::default(),
        Opt {
            v4: true,
            ..Opt::default()
        },
        Opt {
            interleave: true,
            ..Opt::default()
        },
    ] {
        let tree = vec![
            msi("!Media", vec![1; 14]),
            msi("Data1.cab", cab.clone()),
            msi("f.bin", bytes(1, 9000)),
        ];
        let o =
            format::open_bytes(build(&tree, opt).bytes, "p.msi", &OpenRequest::default()).unwrap();
        assert_eq!(o.levels.len(), 2);
        assert_eq!(cab_entries(&o), want);
        assert_contents(
            &contents(o.archive()).unwrap(),
            &contents(direct.archive()).unwrap(),
            "cabinet",
        );
    }
}

fn nests(tree: Vec<Node>) -> bool {
    let o = format::open_bytes(
        build(&tree, Opt::default()).bytes,
        "p.msi",
        &OpenRequest::default(),
    )
    .unwrap();
    o.levels.len() == 2
}

#[test]
fn only_one_packed_cab_and_no_exe_makes_a_main_entry() {
    let cab = tiny_cab();
    let table = || msi("!Media", vec![1; 14]);
    assert!(nests(vec![table(), msi("a.cab", cab.clone())]));
    assert!(nests(vec![table(), msi("Setup.CAB", cab.clone())]));
    assert!(nests(vec![table(), msi(".cab", cab.clone())]));
    assert!(nests(vec![
        table(),
        msi("a.cab", cab.clone()),
        msi("Binary.x", vec![1; 70])
    ]));
    // Two cabinets, or a cabinet beside an executable stream, leave the choice open.
    assert!(!nests(vec![
        table(),
        msi("a.cab", cab.clone()),
        msi("b.cab", cab.clone())
    ]));
    assert!(!nests(vec![
        table(),
        msi("a.cab", cab.clone()),
        msi("Icon.x.exe", vec![1; 70])
    ]));
    assert!(!nests(vec![
        table(),
        msi("a.cab", cab.clone()),
        msi("Icon.x.EXE", vec![1; 70])
    ]));
    // A name that is not packed is not a candidate, and neither is another extension.
    assert!(!nests(vec![table(), stream("a.cab", cab.clone())]));
    assert!(nests(vec![
        table(),
        msi("a.cab", cab.clone()),
        stream("b.cab", cab.clone())
    ]));
    assert!(nests(vec![
        table(),
        msi("a.cab", cab.clone()),
        stream("c.exe", vec![1; 70])
    ]));
    assert!(!nests(vec![table(), msi("a.zip", cab.clone())]));
    assert!(!nests(vec![table(), msi("cab", cab.clone())]));
    assert!(!nests(vec![table(), msi("a.cab1", cab.clone())]));
    // A lone executable is not opened (7-Zip would try it as a PE file).
    assert!(!nests(vec![
        table(),
        msi("Icon.x.exe", vec![b'M', b'Z', 0, 0])
    ]));
    // A patch keeps its cabinet in a stream whose name does not end in .cab.
    assert!(!nests(vec![
        msi("!MsiPatchMetadata", vec![1; 20]),
        msi("PCW_CAB_ACR", cab.clone())
    ]));
}

#[test]
fn a_cabinet_stream_that_is_not_a_cabinet_stays_flat() {
    let o = format::open_bytes(
        build(
            &[msi("!Media", vec![1; 14]), msi("a.cab", vec![7; 100])],
            Opt::default(),
        )
        .bytes,
        "p.msi",
        &OpenRequest::default(),
    )
    .unwrap();
    assert_eq!(o.levels.len(), 1);
    assert!(names(o.archive()).contains(&"a.cab"));
}

#[test]
fn the_cabinet_stream_opens_through_the_archive_contract() {
    let built = build(&sample(), Opt::default());
    let input = Input::Mem(format::Slice::from_vec(built.bytes));
    let a = (cfb::FORMAT.open)(input, &OpenOptions::default()).unwrap();
    let main = a.main_entry().expect("main entry");
    assert_eq!(a.entries()[main].name, "media1.cab");
    let mut raw = Vec::new();
    (a.stream(main).expect("stream"))()
        .unwrap()
        .read_to_end(&mut raw)
        .unwrap();
    assert_bytes(&raw, &tiny_cab(), "cabinet stream");
    // Storages are not streams.
    let sub = a.entries().iter().position(|e| e.name == "Sub").unwrap();
    assert!(a.stream(sub).is_none());
}

// ---------------------------------------------------------------------------------------
// Damaged files

#[test]
fn a_chain_that_loops_ends_in_an_error() {
    let tree = vec![
        stream("big", bytes(1, 20_000)),
        stream("ok", bytes(2, 9_000)),
    ];
    let mut b = build(&tree, Opt::default());
    let start = b.start["big"];
    b.set_fat(start + 3, start + 1);
    let o = open_cfb(b.bytes, "l.bin");
    let Err(err) = contents(o.archive()) else {
        panic!("the loop was not detected");
    };
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
}

#[test]
fn chains_that_end_early_or_break_end_in_errors() {
    let tree = vec![
        stream("big", bytes(1, 20_000)),
        stream("ok", bytes(2, 9_000)),
    ];
    for link in [END, FREE, FATSECT, 0x0FFF_FFFF] {
        let mut b = build(&tree, Opt::default());
        let start = b.start["big"];
        b.set_fat(start + 5, link);
        let o = open_cfb(b.bytes, "l.bin");
        assert!(
            matches!(contents(o.archive()), Err(Error::Corrupt(_))),
            "link {link:#x}"
        );
        // The neighbouring stream is unaffected.
        let a = o.archive();
        let unit = a
            .units()
            .iter()
            .position(|u| a.entries()[u.entries[0]].name == "ok")
            .unwrap();
        let mut got = Vec::new();
        a.extract_unit(unit, &Ctx::default(), &mut |_, r| {
            r.read_to_end(&mut got).map_err(Error::from)?;
            Ok(Flow::Continue)
        })
        .unwrap();
        assert_bytes(&got, &bytes(2, 9_000), "ok");
    }
}

#[test]
fn a_mini_chain_that_loops_or_leaves_the_mini_stream_is_an_error() {
    let tree = vec![stream("m", bytes(1, 500)), stream("n", bytes(2, 300))];
    let mut b = build(&tree, Opt::default());
    let start = b.start["m"];
    b.set_mini_fat(start + 2, start);
    let o = open_cfb(b.bytes, "m.bin");
    assert!(matches!(contents(o.archive()), Err(Error::Corrupt(_))));

    let mut b = build(&tree, Opt::default());
    let start = b.start["m"];
    b.set_mini_fat(start + 1, 0x00FF_FFF0);
    let o = open_cfb(b.bytes, "m.bin");
    assert!(matches!(contents(o.archive()), Err(Error::Corrupt(_))));
}

#[test]
fn a_declared_size_the_file_cannot_hold_does_not_allocate_or_hang() {
    for v4 in [false, true] {
        let tree = [stream("big", bytes(1, 20_000)), stream("m", bytes(2, 100))];
        let mut b = build(
            &tree,
            Opt {
                v4,
                ..Opt::default()
            },
        );
        let at = b.entry_at(b.entry["big"]);
        b.set_u32(at + 120, 0xFFFF_FFF0);
        b.set_u32(at + 124, if v4 { 0x4000_0000 } else { 0 });
        let at = b.entry_at(b.entry["m"]);
        b.set_u32(at + 120, u32::MAX);
        b.set_u32(at + 124, u32::MAX);
        let o = open_cfb(b.bytes, "h.bin");
        assert!(entry(o.archive(), "big").size.unwrap() > 20_000);
        assert!(contents(o.archive()).is_err());
        assert!(test_levels(&o).is_err());
    }
}

#[test]
fn a_loop_in_the_directory_tree_gives_a_partial_listing() {
    let tree = vec![
        stream("a", vec![1]),
        stream("b", vec![2]),
        stream("c", vec![3]),
        stream("d", vec![4]),
        stream("e", vec![5]),
    ];
    let mut b = build(&tree, Opt::default());
    // Point d's right link back at the tree's root (c).
    b.set_field(b.entry["d"], 72, b.entry["c"] as u32);
    // And a storage's child back at itself.
    let o = open_cfb(b.bytes, "d.bin");
    let a = o.archive();
    assert_eq!(names(a), ["c", "b", "a", "e", "d"]);
    assert!(a
        .properties()
        .iter()
        .any(|(k, v)| *k == "Warning" && v.contains("loop")));
    test_levels(&o).unwrap();

    let mut b = build(&[storage("s", vec![stream("x", vec![1])])], Opt::default());
    b.set_field(b.entry["s"], 76, b.entry["s"] as u32);
    let o = open_cfb(b.bytes, "d.bin");
    assert_eq!(names(o.archive()), ["s"]);
}

#[test]
fn deeply_nested_storages_are_cut_off() {
    let mut tree = vec![stream("leaf", vec![1])];
    for i in 0..100 {
        tree = vec![storage(&format!("s{i}"), tree)];
    }
    let o = open_cfb(build(&tree, Opt::default()).bytes, "deep.bin");
    let a = o.archive();
    assert!(a.entries().len() < 100);
    assert!(a.properties().iter().any(|(k, _)| *k == "Warning"));
}

#[test]
fn unusable_headers_are_rejected() {
    let good = sample_file(Opt::default());
    // Not the signature at all.
    assert!(matches!(
        format::open_bytes(vec![0u8; 2000], "x.msi", &compound()),
        Err(Error::NotArchive)
    ));
    // The signature but a short header.
    for n in [8, 100, 511] {
        assert!(matches!(
            format::open_bytes(good[..n].to_vec(), "x.msi", &compound()),
            Err(Error::Corrupt(_))
        ));
    }
    let patched = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut d = good.clone();
        f(&mut d);
        format::open_bytes(d, "x.msi", &compound())
    };
    assert!(patched(&|d| d[28] = 0).is_err()); // byte order
    assert!(patched(&|d| d[26] = 9).is_err()); // version
    assert!(patched(&|d| d[30] = 13).is_err()); // sector shift
    assert!(patched(&|d| d[32] = 0).is_err()); // mini sector shift
    assert!(patched(&|d| d[32] = 10).is_err());
    assert!(patched(&|d| d[44..48].copy_from_slice(&0u32.to_le_bytes())).is_err()); // no FAT
    assert!(patched(&|d| d[48..52].copy_from_slice(&END.to_le_bytes())).is_err()); // no directory
    assert!(patched(&|d| d[48..52].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes())).is_err());
    // A made-up DIFAT or mini FAT never hangs or allocates by its claimed size.
    for field in [64usize, 68, 72, 60, 56, 40] {
        for v in [0u32, 1, 7, 0xFFFF, 0x7FFF_FFFF, u32::MAX] {
            let _ = patched(&|d| d[field..field + 4].copy_from_slice(&v.to_le_bytes()));
        }
    }
}

/// Opens damaged bytes and reads every stream through the handler contract; any outcome
/// but a panic is acceptable. A file that opens must list only entries of the original
/// (when `whole` is given). `deep` also runs the extractor over every level of the
/// default open, which descends into a cabinet.
fn try_damaged(data: Vec<u8>, whole: Option<&[String]>, deep: bool) -> r7z::Result<()> {
    let o = format::open_bytes(data.clone(), "d.msi", &compound())?;
    if let Some(whole) = whole {
        for n in names(o.archive()) {
            assert!(whole.iter().any(|w| w == n), "{n} is not in the original");
        }
    }
    let _ = contents(o.archive());
    if deep {
        let _ = test_levels(&o);
        if let Ok(o) = format::open_bytes(data, "d.msi", &OpenRequest::default()) {
            let _ = test_levels(&o);
        }
    }
    Ok(())
}

fn damage_corpus() -> Vec<(String, Vec<u8>)> {
    let msp = vec![
        msi("!MsiPatchMetadata", bytes(1, 60)),
        msi("PCW_CAB_ACR", tiny_cab()),
        storage(
            "TGT_1ToUPG_1",
            vec![msi("!File", bytes(2, 200)), msi("!Upgrade", bytes(3, 90))],
        )
        .times(133_000_000_000_000_000, 133_000_000_000_000_000),
        storage("#TGT_1ToUPG_1", vec![stream("Patch.a.1", bytes(4, 5000))]),
    ];
    vec![
        ("installer.msi".into(), fs::read(fixture_path()).unwrap()),
        (
            "sample-v4.msi".into(),
            sample_file(Opt {
                v4: true,
                ..Opt::default()
            }),
        ),
        ("patch.msp".into(), build(&msp, Opt::default()).bytes),
        (
            "fragmented.msi".into(),
            build(
                &sample(),
                Opt {
                    interleave: true,
                    ..Opt::default()
                },
            )
            .bytes,
        ),
    ]
}

#[test]
fn truncated_files_fail_or_list_less() {
    for (name, data) in damage_corpus() {
        let whole: Vec<String> = names(open_cfb(data.clone(), &name).archive())
            .into_iter()
            .map(String::from)
            .collect();
        let physical: usize = prop(open_cfb(data.clone(), &name).archive(), "Physical Size")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(physical, data.len(), "{name}");
        for len in 0..data.len() {
            let r = try_damaged(
                data[..len].to_vec(),
                Some(&whole),
                len % 16 == 0 || len < 600,
            );
            if len < 512 {
                assert!(r.is_err(), "{name}: {len} bytes were accepted");
            }
            // A file that opens short of the extent its FAT accounts for says so (a cut
            // through the FAT itself can shrink that extent below the length).
            if let Ok(o) = format::open_bytes(data[..len].to_vec(), &name, &compound()) {
                let physical: usize = prop(o.archive(), "Physical Size").unwrap().parse().unwrap();
                assert!(
                    physical <= len || prop(o.archive(), "ERROR").is_some(),
                    "{name}: {len}"
                );
            }
        }
    }
}

#[test]
fn bit_flips_never_panic() {
    for (name, data) in damage_corpus() {
        // The fragmented sample differs from the fixture only in its FAT; the version 4
        // sample is 28 KiB of mostly padding, so past its header only every third byte is
        // flipped (every field is wider than that).
        if name == "fragmented.msi" {
            continue;
        }
        let step = if data.len() > 20_000 { 3 } else { 1 };
        for i in (0..data.len()).filter(|&i| i < 512 || i % step == 0) {
            for mask in [0x01u8, 0x80] {
                let mut d = data.clone();
                d[i] ^= mask;
                let _ = try_damaged(d, None, i < 512 || i % 16 == 0);
            }
        }
    }
}

/// Fixed pseudo-random damage over the structural sectors: many bytes at once.
#[test]
fn scrambled_tables_never_panic() {
    for (name, data) in damage_corpus() {
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let limit = data.len().min(16 * 1024);
        for _ in 0..300 {
            let mut d = data.clone();
            for _ in 0..(next() % 12 + 1) {
                let at = (next() as usize) % limit;
                d[at] = next() as u8;
            }
            let _ = try_damaged(d, None, true);
        }
        let _ = name;
    }
}

/// Writes the generated samples for comparison with other tools:
/// `R7Z_DUMP_CFB_SAMPLES=dir cargo test --test cfb dump_samples`.
#[test]
#[ignore = "writes samples for other tools; set R7Z_DUMP_CFB_SAMPLES"]
fn dump_samples() {
    let Some(dir) = std::env::var_os("R7Z_DUMP_CFB_SAMPLES") else {
        return;
    };
    fs::create_dir_all(&dir).unwrap();
    for (name, data) in damage_corpus() {
        fs::write(Path::new(&dir).join(name), data).unwrap();
    }
    let cab = fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cab/none.cab"))
        .unwrap();
    let tree = vec![
        msi("!Media", vec![1; 14]),
        msi("Data1.cab", cab),
        msi("f.bin", bytes(1, 9000)),
    ];
    fs::write(
        Path::new(&dir).join("regular-cab.msi"),
        build(&tree, Opt::default()).bytes,
    )
    .unwrap();
    fs::write(
        Path::new(&dir).join("regular-cab-v4.msi"),
        build(
            &tree,
            Opt {
                v4: true,
                ..Opt::default()
            },
        )
        .bytes,
    )
    .unwrap();
    let big = vec![
        stream("big", bytes(9, 7_400_000)),
        stream("after", bytes(2, 5_000)),
    ];
    fs::write(
        Path::new(&dir).join("difat.bin"),
        build(&big, Opt::default()).bytes,
    )
    .unwrap();
}
