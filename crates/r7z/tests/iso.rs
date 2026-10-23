//! ISO 9660 images: a small test-only writer makes images with plain ISO names, Joliet,
//! Rock Ridge (names, modes, times, symlinks), El Torito boot images and files split over
//! several extents. The tests read them back through the format layer and compare the
//! listings and bytes with what the writer was given.

use std::collections::BTreeMap;

use r7z::format::{open_bytes, Archive, Ctx, Entry, Flow, Link, OpenRequest, Opened};
use r7z::Error;

const SECTOR: usize = 2048;

/// One node of the tree the writer lays out.
enum Node {
    /// A directory and its children.
    Dir(&'static str, Vec<Node>),
    /// A file, whose data is split into extents of the given pieces.
    File(&'static str, Vec<Vec<u8>>),
    /// A symlink and its target (Rock Ridge only; Joliet images list it as an empty file).
    Link(&'static str, &'static str),
}

fn file(name: &'static str, data: &[u8]) -> Node {
    Node::File(name, vec![data.to_vec()])
}

#[derive(Clone, Copy, Default)]
struct Opts {
    joliet: bool,
    rock_ridge: bool,
}

/// El Torito boot images as (media type, data). Each length is a multiple of 512.
type Boot<'a> = &'a [(u8, Vec<u8>)];

/// Extents chosen by the layout pass, all as (sector, byte length).
#[derive(Default)]
struct Lay {
    /// Directory path to its extent, in the primary tree and in the Joliet tree.
    dirs: BTreeMap<String, (u32, u32)>,
    jdirs: BTreeMap<String, (u32, u32)>,
    /// File path to the extents of its pieces.
    files: BTreeMap<String, Vec<(u32, u32)>>,
    /// The boot catalog's sector and the boot images as (media, sector, sector count).
    catalog: u32,
    boot: Vec<(u8, u32, u32)>,
    /// The next free sector.
    next: u32,
    /// File data to write at each sector.
    writes: Vec<(u32, Vec<u8>)>,
}

impl Lay {
    fn alloc(&mut self, bytes: usize) -> u32 {
        let at = self.next;
        self.next += bytes.div_ceil(SECTOR) as u32;
        at
    }

    /// A directory's extent, or a dummy one while sizes are being measured.
    fn dir_ext(&self, path: &str, joliet: bool) -> (u32, u32) {
        let map = if joliet { &self.jdirs } else { &self.dirs };
        map.get(path).copied().unwrap_or((0, 0))
    }
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{path}/{name}")
    }
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(p, _)| p)
}

/// The primary identifier of a file or directory: uppercase, with ";1" for files.
fn iso_ident(name: &str, dir: bool) -> Vec<u8> {
    let mut s: String = name
        .to_ascii_uppercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .take(30)
        .collect();
    if !dir {
        s.push_str(";1");
    }
    s.into_bytes()
}

fn ucs2(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

/// Seven-byte directory record date: 2024-01-02 03:04:05, GMT.
const DATE: [u8; 7] = [124, 1, 2, 3, 4, 5, 0];

fn susp_name(name: &str) -> Vec<u8> {
    let mut out = b"NM".to_vec();
    out.push((5 + name.len()) as u8);
    out.push(1);
    out.push(0);
    out.extend_from_slice(name.as_bytes());
    out
}

fn susp_px(mode: u32) -> Vec<u8> {
    let mut out = b"PX".to_vec();
    out.push(36);
    out.push(1);
    for v in [mode, 1, 1000, 1000] {
        out.extend_from_slice(&v.to_le_bytes());
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

fn susp_tf() -> Vec<u8> {
    let mut out = b"TF".to_vec();
    out.push(12);
    out.push(1);
    out.push(0x02); // modification time only, short form
    out.extend_from_slice(&DATE);
    out
}

/// A symlink target as SL components: "" leads with root, "." is current, ".." is parent.
fn susp_sl(target: &str) -> Vec<u8> {
    let mut comps = Vec::new();
    for part in target.split('/') {
        match part {
            "" => comps.extend_from_slice(&[0x08, 0]),
            "." => comps.extend_from_slice(&[0x02, 0]),
            ".." => comps.extend_from_slice(&[0x04, 0]),
            text => {
                comps.push(0);
                comps.push(text.len() as u8);
                comps.extend_from_slice(text.as_bytes());
            }
        }
    }
    let mut out = b"SL".to_vec();
    out.push((5 + comps.len()) as u8);
    out.push(1);
    out.push(0);
    out.extend_from_slice(&comps);
    out
}

/// The system use area of a record: the root's `SP` marker, then `parts`, padded to an
/// even length. Empty without Rock Ridge.
fn sys_area(opts: Opts, parts: Vec<Vec<u8>>, root: bool) -> Vec<u8> {
    if !opts.rock_ridge {
        return Vec::new();
    }
    let mut out = Vec::new();
    if root {
        out.extend_from_slice(&[b'S', b'P', 7, 1, 0xBE, 0xEF, 0]);
    }
    for p in parts {
        out.extend_from_slice(&p);
    }
    if out.len() % 2 == 1 {
        out.push(0);
    }
    out
}

/// One directory record. The identifier is padded so the record stays even.
fn record(lba: u32, len: u32, dir: bool, more: bool, ident: &[u8], sys: &[u8]) -> Vec<u8> {
    let pad = usize::from(ident.len().is_multiple_of(2));
    let total = 33 + ident.len() + pad + sys.len();
    let mut r = vec![0u8; total];
    r[0] = total as u8;
    r[2..6].copy_from_slice(&lba.to_le_bytes());
    r[6..10].copy_from_slice(&lba.to_be_bytes());
    r[10..14].copy_from_slice(&len.to_le_bytes());
    r[14..18].copy_from_slice(&len.to_be_bytes());
    r[18..25].copy_from_slice(&DATE);
    r[25] = (u8::from(dir) << 1) | (u8::from(more) << 7);
    r[28..30].copy_from_slice(&1u16.to_le_bytes());
    r[30..32].copy_from_slice(&1u16.to_be_bytes());
    r[32] = ident.len() as u8;
    r[33..33 + ident.len()].copy_from_slice(ident);
    r[33 + ident.len() + pad..].copy_from_slice(sys);
    r
}

/// Packs records into whole sectors, never letting one cross a sector boundary.
fn pack(records: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for r in records {
        if out.len() % SECTOR + r.len() > SECTOR {
            out.resize(out.len().next_multiple_of(SECTOR), 0);
        }
        out.extend_from_slice(r);
    }
    out.resize(out.len().max(1).next_multiple_of(SECTOR), 0);
    out
}

/// The records of directory `path`, "." and ".." first. Their sizes do not depend on the
/// extents, so sizes can be measured before the layout is known.
fn dir_records(children: &[Node], path: &str, opts: Opts, joliet: bool, lay: &Lay) -> Vec<Vec<u8>> {
    let root = path.is_empty();
    let (own_lba, own_len) = lay.dir_ext(path, joliet);
    let (parent_lba, _) = lay.dir_ext(parent_of(path), joliet);
    let dot_sys = if joliet {
        Vec::new()
    } else {
        sys_area(opts, Vec::new(), root)
    };
    let mut recs = vec![
        record(own_lba, own_len, true, false, &[0], &dot_sys),
        record(parent_lba, own_len, true, false, &[1], &[]),
    ];
    for child in children {
        match child {
            Node::Dir(name, _) => {
                let cpath = join(path, name);
                let (lba, len) = lay.dir_ext(&cpath, joliet);
                let (ident, sys) = names(joliet, name, true, opts, || {
                    vec![susp_name(name), susp_px(0o040755), susp_tf()]
                });
                recs.push(record(lba, len, true, false, &ident, &sys));
            }
            Node::File(name, pieces) => {
                let cpath = join(path, name);
                let exts = lay
                    .files
                    .get(&cpath)
                    .cloned()
                    .unwrap_or_else(|| pieces.iter().map(|p| (0, p.len() as u32)).collect());
                let (ident, sys) = names(joliet, name, false, opts, || {
                    vec![susp_name(name), susp_px(0o100644), susp_tf()]
                });
                for (k, &(lba, len)) in exts.iter().enumerate() {
                    let more = k + 1 < exts.len();
                    recs.push(record(lba, len, false, more, &ident, &sys));
                }
            }
            Node::Link(name, target) => {
                // A symlink needs Rock Ridge. Joliet records it as an empty file with no
                // extent, which the Rock Ridge pass matches by (extent, length, date).
                if !opts.rock_ridge {
                    continue;
                }
                let (ident, sys) = if joliet {
                    (ucs2(name), Vec::new())
                } else {
                    let sys = sys_area(
                        opts,
                        vec![susp_name(name), susp_sl(target), susp_tf()],
                        false,
                    );
                    (iso_ident(name, false), sys)
                };
                recs.push(record(0, 0, false, false, &ident, &sys));
            }
        }
    }
    recs
}

/// The identifier and system use area of a file or directory record.
fn names(
    joliet: bool,
    name: &str,
    dir: bool,
    opts: Opts,
    parts: impl FnOnce() -> Vec<Vec<u8>>,
) -> (Vec<u8>, Vec<u8>) {
    if joliet {
        (ucs2(name), Vec::new())
    } else {
        (iso_ident(name, dir), sys_area(opts, parts(), false))
    }
}

/// Allocates the extents of one tree: each directory before its children, and file data
/// in the primary tree only (the Joliet tree shares it).
fn assign(children: &[Node], path: &str, opts: Opts, lay: &mut Lay, joliet: bool) {
    for child in children {
        match child {
            Node::Dir(name, kids) => {
                let cpath = join(path, name);
                let len = pack(&dir_records(kids, &cpath, opts, joliet, lay)).len();
                let at = lay.alloc(len);
                let map = if joliet {
                    &mut lay.jdirs
                } else {
                    &mut lay.dirs
                };
                map.insert(cpath.clone(), (at, len as u32));
                assign(kids, &cpath, opts, lay, joliet);
            }
            Node::File(name, pieces) if !joliet => {
                let cpath = join(path, name);
                let mut exts = Vec::new();
                for piece in pieces {
                    let at = if piece.is_empty() {
                        lay.next
                    } else {
                        let at = lay.alloc(piece.len());
                        lay.writes.push((at, piece.clone()));
                        at
                    };
                    exts.push((at, piece.len() as u32));
                }
                lay.files.insert(cpath, exts);
            }
            _ => {}
        }
    }
}

/// Writes every directory of one tree, the root included, to `out`.
fn write_dirs(
    children: &[Node],
    path: &str,
    opts: Opts,
    lay: &Lay,
    joliet: bool,
    out: &mut Vec<(u32, Vec<u8>)>,
) {
    let (at, _) = lay.dir_ext(path, joliet);
    out.push((at, pack(&dir_records(children, path, opts, joliet, lay))));
    for child in children {
        if let Node::Dir(name, kids) = child {
            write_dirs(kids, &join(path, name), opts, lay, joliet, out);
        }
    }
}

/// Lays out and writes an image.
fn build(root: &[Node], opts: Opts, boot: Option<Boot<'_>>) -> Vec<u8> {
    // Sectors 0-15 are the system area and 16-19 hold the descriptors.
    let mut lay = Lay {
        next: 20,
        ..Lay::default()
    };
    let root_len = pack(&dir_records(root, "", opts, false, &lay)).len();
    let at = lay.alloc(root_len);
    lay.dirs.insert(String::new(), (at, root_len as u32));
    assign(root, "", opts, &mut lay, false);
    if opts.joliet {
        let jlen = pack(&dir_records(root, "", opts, true, &lay)).len();
        let jat = lay.alloc(jlen);
        lay.jdirs.insert(String::new(), (jat, jlen as u32));
        assign(root, "", opts, &mut lay, true);
    }
    if let Some(images) = boot {
        lay.catalog = lay.alloc(SECTOR);
        for (media, data) in images {
            let at = lay.alloc(data.len());
            lay.writes.push((at, data.clone()));
            lay.boot.push((*media, at, (data.len() / 512) as u32));
        }
    }

    let mut pieces: Vec<(u32, Vec<u8>)> = Vec::new();
    write_dirs(root, "", opts, &lay, false, &mut pieces);
    if opts.joliet {
        write_dirs(root, "", opts, &lay, true, &mut pieces);
    }
    if boot.is_some() {
        pieces.push((lay.catalog, boot_catalog(&lay)));
    }
    let mut img = vec![0u8; lay.next as usize * SECTOR];
    for (sector, bytes) in pieces.iter().chain(lay.writes.iter()) {
        let at = *sector as usize * SECTOR;
        img[at..at + bytes.len()].copy_from_slice(bytes);
    }

    // Volume descriptors: primary, boot record, Joliet supplementary, terminator.
    let total = lay.next;
    let mut vds = vec![primary_descriptor(total, &lay, root_len as u32)];
    if boot.is_some() {
        let mut br = descriptor_header(0);
        br[7..7 + 23].copy_from_slice(b"EL TORITO SPECIFICATION");
        br[71..75].copy_from_slice(&lay.catalog.to_le_bytes());
        vds.push(br);
    }
    if opts.joliet {
        vds.push(joliet_descriptor(total, &lay, lay.jdirs[""].1));
    }
    let mut term = descriptor_header(255);
    term.truncate(SECTOR);
    vds.push(term);
    for (i, vd) in vds.iter().enumerate() {
        let at = (16 + i) * SECTOR;
        img[at..at + SECTOR].copy_from_slice(vd);
    }
    img
}

/// A volume descriptor sector: type, "CD001", version 1, and blanks.
fn descriptor_header(kind: u8) -> Vec<u8> {
    let mut v = vec![b' '; SECTOR];
    v[0] = kind;
    v[1..6].copy_from_slice(b"CD001");
    v[6] = 1;
    v
}

fn put_u32_both(v: &mut [u8], at: usize, value: u32) {
    v[at..at + 4].copy_from_slice(&value.to_le_bytes());
    v[at + 4..at + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_u16_both(v: &mut [u8], at: usize, value: u16) {
    v[at..at + 2].copy_from_slice(&value.to_le_bytes());
    v[at + 2..at + 4].copy_from_slice(&value.to_be_bytes());
}

/// The root record inside a volume descriptor (34 bytes at offset 156).
fn root_record(lba: u32, len: u32) -> Vec<u8> {
    record(lba, len, true, false, &[0], &[])
}

fn primary_descriptor(total: u32, lay: &Lay, root_len: u32) -> Vec<u8> {
    let mut v = descriptor_header(1);
    v[0] = 1;
    v[40..72].copy_from_slice(&padded(b"TESTVOL", b' ', 32));
    put_u32_both(&mut v, 80, total);
    put_u16_both(&mut v, 120, 1);
    put_u16_both(&mut v, 124, 1);
    put_u16_both(&mut v, 128, SECTOR as u16);
    let (lba, _) = lay.dir_ext("", false);
    v[156..190].copy_from_slice(&root_record(lba, root_len));
    v[813..830].copy_from_slice(b"2024010203040500\0");
    v[830..847].copy_from_slice(b"2024010203040500\0");
    v
}

fn joliet_descriptor(total: u32, lay: &Lay, root_len: u32) -> Vec<u8> {
    let mut v = descriptor_header(2);
    v[88..91].copy_from_slice(b"%/E");
    let name: Vec<u8> = ucs2("TESTVOL");
    v[40..40 + name.len()].copy_from_slice(&name);
    put_u32_both(&mut v, 80, total);
    put_u16_both(&mut v, 120, 1);
    put_u16_both(&mut v, 124, 1);
    put_u16_both(&mut v, 128, SECTOR as u16);
    let (lba, _) = lay.dir_ext("", true);
    v[156..190].copy_from_slice(&root_record(lba, root_len));
    v
}

fn padded(s: &[u8], fill: u8, n: usize) -> Vec<u8> {
    let mut out = vec![fill; n];
    out[..s.len()].copy_from_slice(s);
    out
}

/// The El Torito boot catalog: a validation entry, the first image's entry, and a section
/// header and entry for each further image.
fn boot_catalog(lay: &Lay) -> Vec<u8> {
    let mut cat = vec![0u8; SECTOR];
    cat[0] = 1;
    cat[4..8].copy_from_slice(b"TEST");
    cat[30] = 0x55;
    cat[31] = 0xAA;
    // The validation checksum makes the 16-bit words of the entry sum to zero.
    let sum = cat[..32].as_chunks::<2>().0.iter().fold(0u16, |s, w| {
        s.wrapping_add(u16::from_le_bytes(*w))
    });
    cat[28..30].copy_from_slice(&0u16.wrapping_sub(sum).to_le_bytes());
    let mut at = 32;
    for (i, &(media, sector, count)) in lay.boot.iter().enumerate() {
        if i == 1 {
            cat[at] = 0x91;
            cat[at + 1] = 0xEF;
            cat[at + 2..at + 4].copy_from_slice(&1u16.to_le_bytes());
            at += 32;
        }
        cat[at] = 0x88;
        cat[at + 1] = media;
        cat[at + 6..at + 8].copy_from_slice(&(count as u16).to_le_bytes());
        cat[at + 8..at + 12].copy_from_slice(&sector.to_le_bytes());
        at += 32;
    }
    cat
}

fn opened(bytes: Vec<u8>, name: &str) -> Opened {
    open_bytes(bytes, name, &OpenRequest::default()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn names_of(a: &dyn Archive) -> Vec<String> {
    a.entries().iter().map(|e| e.name.clone()).collect()
}

fn entry<'a>(a: &'a dyn Archive, name: &str) -> &'a Entry {
    a.entries()
        .iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("no entry {name}; have {:?}", names_of(a)))
}

/// Decodes every unit, keyed by entry name.
fn contents(a: &dyn Archive) -> Result<BTreeMap<String, Vec<u8>>, Error> {
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

/// Nested directories, an empty file, a file over three extents, and an empty directory.
fn sample_tree() -> Vec<Node> {
    vec![
        file("README.TXT", b"hello from the root\n"),
        Node::Dir(
            "DOCS",
            vec![
                file("NOTES.TXT", &b"note\n".repeat(1000)),
                Node::File(
                    "SPLIT.BIN",
                    vec![vec![1u8; 4096], vec![2u8; 2048], vec![3u8; 512]],
                ),
                file("EMPTY.DAT", b""),
            ],
        ),
        Node::Dir("EMPTY", vec![]),
        Node::Dir(
            "DEEP",
            vec![Node::Dir("ER", vec![file("LAST.TXT", b"deepest\n")])],
        ),
    ]
}

fn sample_expected() -> BTreeMap<String, Vec<u8>> {
    let mut split = vec![1u8; 4096];
    split.extend(vec![2u8; 2048]);
    split.extend(vec![3u8; 512]);
    BTreeMap::from([
        ("README.TXT".to_string(), b"hello from the root\n".to_vec()),
        ("DOCS/NOTES.TXT".to_string(), b"note\n".repeat(1000)),
        ("DOCS/SPLIT.BIN".to_string(), split),
        ("DOCS/EMPTY.DAT".to_string(), Vec::new()),
        ("DEEP/ER/LAST.TXT".to_string(), b"deepest\n".to_vec()),
    ])
}

#[test]
fn plain_iso_lists_and_extracts() {
    let o = opened(build(&sample_tree(), Opts::default(), None), "plain.iso");
    let a = o.archive();
    assert_eq!(a.format().name, "Iso");
    for d in ["DOCS", "EMPTY", "DEEP", "DEEP/ER"] {
        assert!(entry(a, d).is_dir, "{d} is a directory");
    }
    assert_eq!(entry(a, "DOCS/NOTES.TXT").size, Some(5000));
    assert_eq!(entry(a, "DOCS/SPLIT.BIN").size, Some(4096 + 2048 + 512));
    assert_eq!(entry(a, "DOCS/EMPTY.DAT").size, Some(0));
    let got = contents(a).unwrap();
    for (name, bytes) in sample_expected() {
        assert_eq!(got.get(&name), Some(&bytes), "{name}");
    }
    assert!(o.damage().is_empty());
    assert!(!o
        .archive()
        .properties()
        .iter()
        .any(|(k, _)| *k == "Rock Ridge"));
}

#[test]
fn rock_ridge_names_modes_symlinks_and_times() {
    let mut tree = sample_tree();
    tree.push(Node::File(
        "Long Name With Spaces.txt",
        vec![b"long\n".to_vec()],
    ));
    tree.push(Node::Link("link.txt", "DOCS/NOTES.TXT"));
    tree.push(Node::Link("up", "../README.TXT"));
    let o = opened(
        build(
            &tree,
            Opts {
                rock_ridge: true,
                ..Opts::default()
            },
            None,
        ),
        "rr.iso",
    );
    let a = o.archive();
    assert!(a
        .properties()
        .iter()
        .any(|(k, v)| *k == "Rock Ridge" && v == "Yes"));
    let n = entry(a, "Long Name With Spaces.txt");
    assert_eq!(n.size, Some(5));
    assert_eq!(n.attrib.unwrap() >> 16, 0o100644, "mode from PX");
    assert!(entry(a, "DOCS").attrib.unwrap() & 0x10 != 0);
    assert!(entry(a, "DOCS").mtime.is_some());
    assert_eq!(
        entry(a, "link.txt").link,
        Some(Link::Symbolic("DOCS/NOTES.TXT".into()))
    );
    assert_eq!(
        entry(a, "up").link,
        Some(Link::Symbolic("../README.TXT".into()))
    );
    // A symlink extracts as its target text.
    let got = contents(a).unwrap();
    assert_eq!(got["link.txt"], b"DOCS/NOTES.TXT");
    assert_eq!(got["up"], b"../README.TXT");
    assert_eq!(got["Long Name With Spaces.txt"], b"long\n");
    for (name, bytes) in sample_expected() {
        assert_eq!(got.get(&name), Some(&bytes), "{name}");
    }
}

#[test]
fn joliet_names_win_and_keep_rock_ridge_fields() {
    let mut tree = sample_tree();
    tree.push(Node::File("Ünïcode Name.txt", vec![b"unicode\n".to_vec()]));
    tree.push(Node::Link("link.txt", "DOCS/NOTES.TXT"));
    let o = opened(
        build(
            &tree,
            Opts {
                joliet: true,
                rock_ridge: true,
            },
            None,
        ),
        "joliet.iso",
    );
    let a = o.archive();
    assert!(a.properties().iter().any(|(k, _)| *k == "Joliet"));
    assert_eq!(entry(a, "Ünïcode Name.txt").size, Some(8));
    // The symlink comes from its Rock Ridge record, matched by extent, length and date.
    assert_eq!(
        entry(a, "link.txt").link,
        Some(Link::Symbolic("DOCS/NOTES.TXT".into()))
    );
    let got = contents(a).unwrap();
    assert_eq!(got["Ünïcode Name.txt"], b"unicode\n");
    for (name, bytes) in sample_expected() {
        assert_eq!(got.get(&name), Some(&bytes), "{name}");
    }
}

#[test]
fn el_torito_boot_images_are_listed() {
    let boot = [
        (0u8, vec![0xEBu8; 4096]),
        (4u8, (0..2048u32).map(|i| i as u8).collect::<Vec<u8>>()),
    ];
    let o = opened(
        build(&sample_tree(), Opts::default(), Some(&boot[..])),
        "boot.iso",
    );
    let a = o.archive();
    assert!(a.properties().iter().any(|(k, _)| *k == "El Torito"));
    assert_eq!(entry(a, "[BOOT]/Boot-NoEmul.img").size, Some(4096));
    assert_eq!(entry(a, "[BOOT]/Boot-HardDisk.img").size, Some(2048));
    assert!(
        !a.entries().iter().any(|e| e.name == "[BOOT]"),
        "no folder entry, as 7-Zip"
    );
    let got = contents(a).unwrap();
    assert_eq!(got["[BOOT]/Boot-NoEmul.img"], vec![0xEBu8; 4096]);
    assert_eq!(
        got["[BOOT]/Boot-HardDisk.img"],
        (0..2048u32).map(|i| i as u8).collect::<Vec<u8>>()
    );
    assert_eq!(got["DOCS/NOTES.TXT"].len(), 5000);
}

#[test]
fn not_an_iso_is_rejected() {
    assert!(open_bytes(vec![0x42; 40_000], "x.iso", &OpenRequest::default()).is_err());
}

#[test]
fn damaged_images_never_panic() {
    let boot = [(0u8, vec![0x90u8; 1024])];
    let mut tree = sample_tree();
    tree.push(Node::Link("link.txt", "DOCS/NOTES.TXT"));
    let good = build(
        &tree,
        Opts {
            joliet: true,
            rock_ridge: true,
        },
        Some(&boot[..]),
    );
    // Truncation: the open fails, or extracting some entry does.
    for cut in [good.len() / 2, 40_000, 33_000, SECTOR * 17] {
        let bad = good[..cut.min(good.len())].to_vec();
        if let Ok(o) = open_bytes(bad, "t.iso", &OpenRequest::default()) {
            let _ = contents(o.archive());
        }
    }
    // Bit flips across the image, descriptors and directories included.
    let mut step = 1;
    while step < good.len() {
        let mut bad = good.clone();
        bad[step] ^= 0x5A;
        if let Ok(o) = open_bytes(bad, "f.iso", &OpenRequest::default()) {
            let _ = contents(o.archive());
        }
        step = step * 3 + 7;
    }
}

/// A committed fixture from `tests/fixtures/iso` (written by `make_fixtures.py`).
fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/iso")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

#[test]
fn fixtures_list_as_7zip_does() {
    // Listings checked against 7-Zip 25.01 (`7z l -slt`) on the same files.
    let o = opened(fixture("plain.iso"), "plain.iso");
    let mut names = names_of(o.archive());
    names.sort();
    assert_eq!(names, ["EMPTY.DAT", "HELLO.TXT", "SUB", "SUB/DEEP.TXT"]);

    let o = opened(fixture("joliet-rock-ridge.iso"), "joliet-rock-ridge.iso");
    let a = o.archive();
    let mut names = names_of(a);
    names.sort();
    assert_eq!(
        names,
        [
            "hello.txt",
            "link.txt",
            "sub",
            "sub/a file with a long name that goes on.md"
        ]
    );
    assert_eq!(
        entry(a, "link.txt").link,
        Some(Link::Symbolic("/hello.txt".into()))
    );

    let o = opened(fixture("el-torito.iso"), "el-torito.iso");
    let mut names = names_of(o.archive());
    names.sort();
    assert_eq!(
        names,
        [
            "BOOT.CAT",
            "BOOT.IMG",
            "HELLO.TXT",
            "[BOOT]/Boot-NoEmul.img"
        ]
    );
    assert_eq!(
        entry(o.archive(), "[BOOT]/Boot-NoEmul.img").size,
        Some(2048)
    );
}

#[test]
fn fixtures_survive_truncation_and_bit_flips() {
    for name in ["plain.iso", "joliet-rock-ridge.iso", "el-torito.iso"] {
        let good = fixture(name);
        assert!(open_bytes(good[..SECTOR * 16].to_vec(), name, &OpenRequest::default()).is_err());
        for cut in (SECTOR * 16..good.len()).step_by(997) {
            if let Ok(o) = open_bytes(good[..cut].to_vec(), name, &OpenRequest::default()) {
                let _ = contents(o.archive());
            }
        }
        for at in (0..good.len()).step_by(211) {
            let mut bad = good.clone();
            bad[at] ^= 0xA5;
            if let Ok(o) = open_bytes(bad, name, &OpenRequest::default()) {
                let _ = contents(o.archive());
            }
        }
    }
}
