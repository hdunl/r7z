//! RAR archives, read only: RAR 1.5-4.x and RAR 5 layouts, multi-volume sets (`.partNN.rar`
//! and `.rNN`), solid units, and both header and data encryption.
//!
//! The headers of every volume are scanned into [`Member`] records that carry their packed
//! data as slices of the volumes. A solid run of files is one unit: its packed data is one
//! stream, decoded in order by a single decoder.
//!
//! The RAR 4 layout is in [`v4`], the RAR 5 layout in [`v5`]. Decoding lives in
//! `codec::rar3` and `codec::rar5`.

mod crypt;
mod v4;
mod v5;

use std::collections::VecDeque;
use std::io::{self, Read};
use std::path::Path;

use crc32fast::Hasher as Crc32;

use super::data::{Input, Slice};
use super::{Archive, Columns, Ctx, Entry, EntryFn, Flow, Format, OpenOptions, Signature, Unit};
use crate::codec::rar2::Lz2;
use crate::codec::rar3::Lz3;
use crate::error::{Error, Result};
use crate::util::blake2sp::Blake2sp;
use crypt::{rar3_key, Cbc};

pub const FORMAT: Format = Format {
    name: "rar",
    aliases: &["rar4", "rar5"],
    extensions: &["rar", "r00"],
    signatures: &[
        Signature::at(0, b"Rar!\x1A\x07\x00"),
        Signature::at(0, b"Rar!\x1A\x07\x01\x00"),
    ],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

/// How a file's packed data is encrypted.
#[derive(Clone, Debug)]
pub enum Crypt {
    /// RAR 3: AES-128 with the key derived from the password and this per-file salt.
    Rar3 { salt: [u8; 8] },
    /// RAR 1.5 and 2.0: the original ciphers, which use no salt. Listed, not decrypted.
    Legacy,
    /// RAR 5: AES-256 with per-file salt, IV and round count, and an optional check value.
    /// With `mac` the stored CRC32 and BLAKE2sp are keyed by the password's hash key.
    Rar5 {
        salt: [u8; 16],
        iv: [u8; 16],
        lg2: u8,
        check: Option<[u8; 8]>,
        mac: bool,
    },
}

/// One file as the headers describe it. Continuations in later volumes are appended to
/// `packed` and reflected in `crc`.
#[derive(Clone)]
pub struct Member {
    pub name: String,
    pub is_dir: bool,
    /// Unpacked size.
    pub size: u64,
    /// Packed data, in stream order, one slice per volume it spans.
    pub packed: Vec<Slice>,
    pub mtime: Option<u64>,
    pub attrib: Option<u32>,
    /// CRC32 of the unpacked data.
    pub crc: Option<u32>,
    /// BLAKE2sp of the unpacked data (RAR 5).
    pub blake2: Option<[u8; 32]>,
    /// Compression method, 0 for stored.
    pub method: u8,
    /// RAR 4: unpack version; RAR 5: algorithm version.
    pub version: u8,
    /// The data continues the previous member's decoder state.
    pub solid: bool,
    /// Dictionary size in bytes.
    pub dict: u64,
    pub crypt: Option<Crypt>,
    /// The file's last part is in a volume that is missing.
    pub incomplete: bool,
}

/// What a header scan of the volumes found.
#[derive(Default)]
pub struct Scan {
    pub members: Vec<Member>,
    pub solid: bool,
    pub volume: bool,
    pub first_volume: bool,
    /// The last volume says another one follows, but none was given.
    pub missing_volume: bool,
}

pub struct Rar {
    version: u8,
    members: Vec<Member>,
    entries: Vec<Entry>,
    units: Vec<Unit>,
    volumes: usize,
    solid: bool,
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let first = input.into_mem()?;
    let v5 = first.starts_with(b"Rar!\x1A\x07\x01\x00");
    let multi = if v5 {
        v5::peek_volume(&first)?
    } else {
        v4::peek_volume(&first)
    };
    let volumes = load_volumes(first, opts, multi)?;
    // A missing volume still lists; the members that need it fail to extract.
    let scan = if v5 {
        v5::scan(&volumes, opts.password.as_deref())?
    } else {
        v4::scan(&volumes, opts.password.as_deref())?
    };
    let version = if v5 { 5 } else { 4 };
    let units = build_units(&scan.members);
    let mut entries = Vec::with_capacity(scan.members.len());
    for (i, m) in scan.members.iter().enumerate() {
        let unit = units.iter().position(|u| u.entries.contains(&i));
        entries.push(entry_of(m, unit, version));
    }
    Ok(Box::new(Rar {
        version,
        members: scan.members,
        entries,
        units,
        volumes: volumes.len(),
        solid: scan.solid,
    }))
}

/// Volume `1` followed by the others of its set, found by file name.
fn load_volumes(first: Slice, opts: &OpenOptions, multi: bool) -> Result<Vec<Slice>> {
    let mut vols = vec![first];
    if !multi {
        return Ok(vols);
    }
    let Some(path) = opts.path.as_deref() else {
        return Ok(vols);
    };
    let dir = path.parent().unwrap_or(Path::new("")).to_path_buf();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some((stem, width, number)) = part_name(&name) {
        for k in number + 1.. {
            let p = dir.join(format!("{stem}.part{k:0width$}.rar"));
            if !p.is_file() {
                break;
            }
            vols.push(Slice::map_file(&p)?);
        }
    } else if let Some(stem) = name.strip_suffix(".rar").or(name.strip_suffix(".RAR")) {
        for k in 0usize.. {
            let p = dir.join(format!("{stem}.r{k:02}"));
            if !p.is_file() {
                break;
            }
            vols.push(Slice::map_file(&p)?);
        }
    }
    Ok(vols)
}

/// `name.partNN.rar` → (`name`, digits, NN).
fn part_name(name: &str) -> Option<(&str, usize, usize)> {
    let lower = name.to_ascii_lowercase();
    let stem_part = lower.strip_suffix(".rar")?;
    let idx = stem_part.rfind(".part")?;
    let digits = &stem_part[idx + 5..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let number: usize = digits.parse().ok()?;
    Some((&name[..idx], digits.len(), number))
}

fn build_units(members: &[Member]) -> Vec<Unit> {
    let mut units: Vec<Unit> = Vec::new();
    let mut open = false;
    for (i, m) in members.iter().enumerate() {
        if m.is_dir {
            units.push(Unit {
                entries: vec![i],
                encrypted: false,
            });
            open = false;
            continue;
        }
        match units.last_mut() {
            Some(u) if m.solid && open => {
                u.entries.push(i);
                u.encrypted |= m.crypt.is_some();
            }
            _ => {
                units.push(Unit {
                    entries: vec![i],
                    encrypted: m.crypt.is_some(),
                });
                open = true;
            }
        }
    }
    units
}

fn entry_of(m: &Member, unit: Option<usize>, version: u8) -> Entry {
    let packed: u64 = m.packed.iter().map(|s| s.len() as u64).sum();
    let method = if m.is_dir {
        None
    } else if m.method == 0 {
        Some("Store".to_string())
    } else if version == 4 {
        Some(format!("RAR{}:m{}", m.version / 10, m.method))
    } else {
        Some(format!("m{}", m.method))
    };
    Entry {
        name: m.name.clone(),
        is_dir: m.is_dir,
        size: Some(m.size),
        packed_size: Some(packed),
        mtime: m.mtime,
        ctime: None,
        atime: None,
        attrib: m.attrib,
        crc: m.crc,
        method,
        encrypted: m.crypt.is_some(),
        is_anti: false,
        block: unit,
        link: None,
        comment: None,
        raw_name: None,
    }
}

/// Packed data of consecutive members as one stream. An encrypted member's parts share one
/// CBC chain: the first part carries the cipher, and later parts take it over.
struct Segments {
    segs: VecDeque<Seg>,
}

struct Seg {
    data: Slice,
    pos: usize,
    cbc: Option<Cbc>,
    /// Continues the encrypted chain of the part before it.
    same_chain: bool,
}

impl Read for Segments {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            let Some(seg) = self.segs.front_mut() else {
                return Ok(0);
            };
            let left = seg.data.len() - seg.pos;
            if left == 0 {
                let done = self.segs.pop_front().unwrap();
                if let (Some(cbc), Some(next)) = (done.cbc, self.segs.front_mut()) {
                    if next.same_chain {
                        next.cbc = Some(cbc);
                    }
                }
                continue;
            }
            // Encrypted parts are whole cipher blocks, so each read ends on a block.
            let mut n = left.min(out.len());
            if seg.cbc.is_some() {
                n &= !15;
                if n == 0 {
                    return Err(io::Error::other("read buffer smaller than a cipher block"));
                }
            }
            out[..n].copy_from_slice(&seg.data[seg.pos..seg.pos + n]);
            if let Some(cbc) = seg.cbc.as_mut() {
                cbc.decrypt(&mut out[..n]);
            }
            seg.pos += n;
            return Ok(n);
        }
    }
}

/// Verifies an entry's CRC32 or BLAKE2sp as its bytes are read.
struct Checked<'a> {
    inner: &'a mut dyn Read,
    name: &'a str,
    left: u64,
    crc: Option<u32>,
    blake: Option<[u8; 32]>,
    crc_state: Crc32,
    b2: Option<Blake2sp>,
    done: bool,
    /// RAR 5 hash key when the stored checksums are in their MAC form.
    mac: Option<[u8; 32]>,
}

impl<'a> Checked<'a> {
    fn new(inner: &'a mut dyn Read, m: &'a Member) -> Self {
        Checked {
            inner,
            name: &m.name,
            left: m.size,
            crc: m.crc,
            blake: m.blake2,
            crc_state: Crc32::new(),
            b2: m.blake2.map(|_| Blake2sp::new()),
            done: m.size == 0,
            mac: None,
        }
    }

    /// Compares against checksums stored in their RAR 5 MAC form under `hash_key`.
    fn with_mac(mut self, hash_key: Option<[u8; 32]>) -> Self {
        self.mac = hash_key;
        self
    }

    fn verify(&mut self) -> io::Result<()> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        if let Some(want) = self.crc {
            let mut got = self.crc_state.clone().finalize();
            if let Some(k) = &self.mac {
                got = crypt::rar5_mac_crc(k, got);
            }
            if got != want {
                return Err(Error::Checksum(format!(
                    "{} (expected {want:08X}, got {got:08X})",
                    self.name
                ))
                .into_io());
            }
        }
        if let (Some(want), Some(h)) = (self.blake, self.b2.take()) {
            let mut got = h.finalize();
            if let Some(k) = &self.mac {
                got = crypt::rar5_mac_digest(k, &got);
            }
            if got != want {
                return Err(Error::Checksum(format!("{} (BLAKE2sp)", self.name)).into_io());
            }
        }
        Ok(())
    }
}

impl Read for Checked<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.left == 0 {
            self.verify()?;
            return Ok(0);
        }
        let want = buf.len().min(self.left as usize);
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(Error::corrupt(format!("{}: unexpected end of data", self.name)).into_io());
        }
        self.crc_state.update(&buf[..n]);
        if let Some(h) = self.b2.as_mut() {
            h.update(&buf[..n]);
        }
        self.left -= n as u64;
        if self.left == 0 {
            self.verify()?;
        }
        Ok(n)
    }
}

/// Adapts the LZ decoder to `Read`.
struct Lz3Read<'a>(&'a mut Lz3);

impl Read for Lz3Read<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(Error::into_io)
    }
}

impl Archive for Rar {
    fn format(&self) -> &'static Format {
        &FORMAT
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, unit: usize, ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let u = &self.units[unit];
        let members: Vec<&Member> = u.entries.iter().map(|&i| &self.members[i]).collect();
        if members.iter().any(|m| m.incomplete) {
            return Err(Error::corrupt("a file's data is in a missing volume"));
        }
        if members[0].is_dir {
            f(u.entries[0], &mut io::empty())?;
            return Ok(());
        }
        if self.version == 5 {
            return v5::extract_unit(&u.entries, &members, ctx, f);
        }
        if members[0].method != 0 && members[0].version < 29 {
            return extract_old(&u.entries, &members, f);
        }
        if members[0].method == 0 && members.len() > 1 {
            return Err(Error::corrupt("stored RAR members in a solid unit"));
        }
        // Keys for every encrypted member, derived once per salt.
        let mut keys: Vec<Option<Cbc>> = Vec::with_capacity(members.len());
        for m in &members {
            keys.push(match &m.crypt {
                None => None,
                Some(c) => Some(self.cipher(c, ctx)?),
            });
        }
        let mut segs = VecDeque::new();
        for (m, cbc) in members.iter().zip(keys.iter()) {
            for (k, part) in m.packed.iter().enumerate() {
                if cbc.is_some() && part.len() % 16 != 0 {
                    return Err(Error::corrupt("encrypted RAR data is not block aligned"));
                }
                segs.push_back(Seg {
                    data: part.clone(),
                    pos: 0,
                    cbc: if k == 0 { cbc.clone() } else { None },
                    same_chain: k > 0,
                });
            }
        }
        let mut stream = Segments { segs };
        if members[0].method == 0 {
            let m = members[0];
            let mut r = Checked::new(&mut stream, m);
            f(u.entries[0], &mut r)?;
            drain(&mut r)?;
            return Ok(());
        }
        // A window holds the whole unit when it fits within the dictionary, so filter blocks
        // never wrap; otherwise it is the dictionary itself.
        let total: u64 = u.entries.iter().map(|&i| self.members[i].size).sum();
        let dict = members.iter().map(|m| m.dict).max().unwrap_or(1 << 16);
        let win = if total <= dict {
            (total + 1024).max(1 << 16).next_power_of_two()
        } else {
            dict.next_power_of_two()
        } as usize;
        let mut lz = Lz3::new(Box::new(stream), win);
        for (&i, m) in u.entries.iter().zip(members.iter()) {
            lz.begin(m.size);
            let mut inner = Lz3Read(&mut lz);
            let mut r = Checked::new(&mut inner, m);
            let flow = f(i, &mut r)?;
            drain(&mut r)?;
            if flow == Flow::Stop {
                break;
            }
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![
            (
                "Version",
                format!("RAR {}", if self.version == 5 { "5" } else { "4" }),
            ),
            ("Volumes", self.volumes.to_string()),
        ];
        if self.solid {
            out.push(("Solid", "+".into()));
        }
        out
    }

    fn columns(&self) -> Columns {
        Columns {
            crc: true,
            method: true,
            encrypted: true,
            block: true,
        }
    }

    fn verifies_data(&self) -> bool {
        true
    }
}

impl Rar {
    /// The decryption state of one member for password `ctx`.
    fn cipher(&self, c: &Crypt, ctx: &Ctx) -> Result<Cbc> {
        if matches!(c, Crypt::Legacy) {
            return Err(Error::unsupported("RAR 1.5 and 2.0 encryption"));
        }
        let pw = ctx.password.as_deref().ok_or(Error::PasswordRequired)?;
        match c {
            Crypt::Legacy => unreachable!(),
            Crypt::Rar3 { salt } => {
                let (key, iv) = rar3_key(pw, salt);
                Ok(Cbc::aes128(&key, iv))
            }
            Crypt::Rar5 {
                salt,
                iv,
                lg2,
                check,
                ..
            } => {
                let keys = crypt::rar5_keys(pw, salt, *lg2)?;
                if check.is_some_and(|c| c != keys.check) {
                    return Err(Error::WrongPassword);
                }
                Ok(Cbc::aes256(&keys.key, *iv))
            }
        }
    }
}

/// Extracts a unit of RAR 1.5 or 2.0 members. Each member's packed data is a stream of
/// its own, decoded with the model the members before it in a solid unit left behind.
fn extract_old(entries: &[usize], members: &[&Member], f: &mut EntryFn<'_>) -> Result<()> {
    if members.iter().any(|m| m.crypt.is_some()) {
        return Err(Error::unsupported("RAR 1.5 and 2.0 encryption"));
    }
    let version = members[0].version;
    if version != 15 && version != 20 && version != 26 {
        return Err(Error::unsupported(format!(
            "RAR {}.{} compression (unpack version {version})",
            version / 10,
            version % 10
        )));
    }
    let dict = members.iter().map(|m| m.dict).max().unwrap_or(1 << 16);
    let win = usize::try_from(dict.max(1 << 16).next_power_of_two())
        .map_err(|_| Error::unsupported("RAR dictionary larger than the address space"))?;
    let mut lz = Lz2::new(version, win);
    for (k, (&i, m)) in entries.iter().zip(members).enumerate() {
        if m.version != version || m.method == 0 {
            return Err(Error::corrupt("mixed RAR versions in a solid unit"));
        }
        let packed: u64 = m.packed.iter().map(|p| p.len() as u64).sum();
        let segs = m
            .packed
            .iter()
            .map(|p| Seg {
                data: p.clone(),
                pos: 0,
                cbc: None,
                same_chain: false,
            })
            .collect();
        lz.begin(
            Box::new(Segments { segs }),
            packed,
            m.size,
            k > 0 && m.solid,
        )?;
        let mut inner = Lz2Read(&mut lz);
        let mut r = Checked::new(&mut inner, m);
        let flow = f(i, &mut r)?;
        drain(&mut r)?;
        if flow == Flow::Stop {
            break;
        }
    }
    Ok(())
}

struct Lz2Read<'a>(&'a mut Lz2);

impl Read for Lz2Read<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf).map_err(Error::into_io)
    }
}

/// Reads the rest of an entry so the next entry of a solid unit starts in the right place.
fn drain(r: &mut dyn Read) -> Result<()> {
    let mut buf = [0u8; 1 << 14];
    loop {
        if r.read(&mut buf).map_err(Error::from_codec)? == 0 {
            return Ok(());
        }
    }
}
