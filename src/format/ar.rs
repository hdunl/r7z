//! Unix `ar` archives: System V/GNU (`//` name table, `/123` references), BSD (`#1/len`
//! names), Debian packages and Microsoft `.lib` libraries. One unit per member.
//!
//! Like 7-Zip, symbol tables (`/`, `__.SYMDEF`) are presented as generated text files
//! `1.txt` and `2.txt` listing `member    symbol` lines, the `//` table is hidden, runs of
//! equal member names get `1.`, `2.` prefixes, and a `.deb` hides `debian-binary`.

use super::{
    Archive, Ctx, Entry, EntryFn, Flow, Format, Input, OpenOptions, Signature, Slice, Unit,
};
use crate::error::{Error, Result};
use crate::util::time::unix_to_filetime;

pub const FORMAT: Format = Format {
    name: "Ar",
    aliases: &[],
    extensions: &["ar", "a", "deb", "udeb", "lib"],
    signatures: &[Signature::at(0, SIGNATURE)],
    detect: None,
    write: false,
    stream: false,
    sequential: false,
    open,
};

const SIGNATURE: &[u8] = b"!<arch>\n";
const HEADER: usize = 60;
/// Longest BSD `#1/len` name 7-Zip accepts.
const MAX_BSD_NAME: u64 = 1 << 12;

/// One member header, with the name as stored (after long-name resolution).
#[derive(Clone, Debug)]
struct Member {
    name: Vec<u8>,
    header_pos: u64,
    data_pos: u64,
    size: u64,
    mtime: u32,
    mode: u32,
    /// Index into the generated symbol-table texts.
    text: Option<usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ar,
    ALib,
    Deb,
    Lib,
}

fn trim_spaces(b: &[u8]) -> &[u8] {
    let n = b.iter().rposition(|&c| c != b' ').map_or(0, |p| p + 1);
    &b[..n]
}

/// A space-padded number field; empty and `-1` mean zero.
fn number(b: &[u8], radix: u32) -> Option<u64> {
    let t = trim_spaces(b);
    if t.is_empty() || t == b"-1" {
        return Some(0);
    }
    if !t.iter().all(|c| (*c as char).is_digit(radix)) {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(t).ok()?, radix).ok()
}

fn number32(b: &[u8], radix: u32) -> Option<u32> {
    number(b, radix).and_then(|v| u32::try_from(v).ok())
}

/// Parses the header at `pos`; `None` ends the member list (7-Zip stops there too).
fn parse_member(data: &[u8], pos: usize, bsd: &mut bool) -> Option<(Member, u64)> {
    let h = data.get(pos..pos + HEADER)?;
    if &h[58..60] != b"`\n" || h[..58].contains(&0) {
        return None;
    }
    let long_len = if h.starts_with(b"#1/") {
        number(&h[3..16], 10)?
    } else {
        0
    };
    let long_len = if long_len >= MAX_BSD_NAME {
        0
    } else {
        long_len
    };
    let mtime = number32(&h[16..28], 10)?;
    number32(&h[28..34], 10)?;
    number32(&h[34..40], 10)?;
    let mode = number32(&h[40..48], 8)?;
    let field_size = number(&h[48..58], 10)?;
    let mut m = Member {
        name: trim_spaces(&h[..16]).to_vec(),
        header_pos: pos as u64,
        data_pos: (pos + HEADER) as u64,
        size: field_size,
        mtime,
        mode,
        text: None,
    };
    if long_len != 0 && long_len <= field_size {
        let start = pos + HEADER;
        let name = data.get(start..start + long_len as usize)?;
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        m.name = name[..end].to_vec();
        m.data_pos += long_len;
        m.size -= long_len;
        *bsd = true;
    }
    // Members are padded to an even length (the size field counts a BSD name too).
    let next = (pos + HEADER) as u64 + field_size + (field_size & 1);
    Some((m, next))
}

fn data_of<'a>(data: &'a [u8], m: &Member) -> Option<&'a [u8]> {
    let end = m.data_pos.checked_add(m.size)?;
    data.get(m.data_pos as usize..usize::try_from(end).ok()?)
}

/// Resolves `/123` names through the `//` table; returns the table's index.
fn resolve_long_names(data: &[u8], members: &mut [Member]) -> Result<Option<usize>> {
    let Some(ti) = members.iter().position(|m| m.name == b"//") else {
        return Ok(None);
    };
    let table = data_of(data, &members[ti]).ok_or_else(|| Error::corrupt("ar name table"))?;
    for m in members.iter_mut() {
        let Some(digits) = m.name.strip_prefix(b"/") else {
            continue;
        };
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            continue;
        }
        let Some(start) = std::str::from_utf8(digits)
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .filter(|&s| s < table.len())
        else {
            continue;
        };
        let len = table[start..]
            .iter()
            .position(|&c| c == 0 || c == b'\n')
            .ok_or_else(|| Error::corrupt("ar name table"))?;
        m.name = table[start..start + len].to_vec();
    }
    Ok(Some(ti))
}

/// Prefixes runs of equal adjacent names with `1.`, `2.`, ...
fn number_duplicates(members: &mut [Member]) {
    let mut same: Vec<Option<u32>> = vec![None; members.len()];
    for i in 1..members.len() {
        if members[i].name.first() != Some(&b'/') && members[i].name == members[i - 1].name {
            let prev = *same[i - 1].get_or_insert(0);
            same[i] = Some(prev + 1);
        }
    }
    for (m, s) in members.iter_mut().zip(same) {
        if let Some(s) = s {
            let mut name = format!("{}.", s + 1).into_bytes();
            name.extend_from_slice(&m.name);
            m.name = name;
        }
    }
}

fn display_name(raw: &[u8]) -> &[u8] {
    raw.strip_suffix(b"/").unwrap_or(raw)
}

fn be32(p: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(p.get(at..at + 4)?.try_into().ok()?))
}

fn le32(p: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(p.get(at..at + 4)?.try_into().ok()?))
}

fn get32(p: &[u8], at: usize, be: bool) -> Option<u32> {
    if be {
        be32(p, at)
    } else {
        le32(p, at)
    }
}

/// Builds the text listing of one symbol table, or `None` if it does not parse.
struct SymbolText<'a> {
    members: &'a [Member],
    text: Vec<u8>,
}

impl SymbolText<'_> {
    /// Appends `member    symbol` for the member whose header is at `offset`; the symbol is
    /// the NUL-terminated string at `names[*pos]`, and `*pos` moves past it.
    fn add(&mut self, offset: u32, names: &[u8], pos: &mut usize) -> Option<()> {
        let i = self
            .members
            .binary_search_by_key(&u64::from(offset), |m| m.header_pos)
            .ok()?;
        let len = names.get(*pos..)?.iter().position(|&c| c == 0)?;
        self.text
            .extend_from_slice(display_name(&self.members[i].name));
        self.text.extend_from_slice(b"    ");
        self.text.extend_from_slice(&names[*pos..*pos + len]);
        self.text.push(b'\n');
        *pos += len + 1;
        Some(())
    }
}

/// Parses member `idx` as a symbol table, as 7-Zip's `ParseLibSymbols` does. Returns the
/// text, the archive kind it implies, and whether it is the BSD flavor.
fn parse_symbols(
    data: &[u8],
    members: &[Member],
    idx: usize,
    tables_so_far: usize,
) -> Option<Option<(Vec<u8>, Kind, bool)>> {
    let m = &members[idx];
    let is_gnu = m.name == b"/";
    if !is_gnu && m.name != b"__.SYMDEF" && m.name != b"__.SYMDEF SORTED" {
        return Some(None);
    }
    if m.size > 1 << 30 || m.size < 4 {
        return Some(None);
    }
    let p = data_of(data, m)?;
    let size = p.len();
    let mut st = SymbolText {
        members,
        text: Vec::new(),
    };
    let (pos, kind, bsd) = if !is_gnu {
        let mut found = None;
        for be in [false, true] {
            st.text.clear();
            let table = get32(p, 0, be)? as usize;
            if size - 4 < table || table & 7 != 0 {
                continue;
            }
            let names_start = 4 + table;
            let Some(names_size) = get32(p, names_start, be) else {
                continue;
            };
            let names_start = names_start + 4;
            if names_start + names_size as usize != size {
                continue;
            }
            let names = &p[names_start..];
            let all = (0..table / 8).all(|k| {
                let at = 4 + k * 8;
                let mut name_pos = get32(p, at, be).unwrap_or(u32::MAX) as usize;
                let offset = get32(p, at + 4, be).unwrap_or(u32::MAX);
                st.add(offset, names, &mut name_pos).is_some()
            });
            if all {
                found = Some(());
                break;
            }
        }
        found?;
        (size, Kind::ALib, true)
    } else if tables_so_far == 0 {
        // GNU / first linker member: big-endian count, offsets, then names.
        let n = be32(p, 0)? as usize;
        if n > (size - 4) / 4 {
            return None;
        }
        let mut pos = 4 + 4 * n;
        for k in 0..n {
            st.add(be32(p, 4 + 4 * k)?, p, &mut pos)?;
        }
        (pos, Kind::ALib, false)
    } else {
        // Microsoft second linker member: member offsets, then 1-based 16-bit indices.
        let members_n = le32(p, 0)? as usize;
        if members_n > (size - 4) / 4 {
            return None;
        }
        let mut pos = 4 + 4 * members_n;
        let syms = le32(p, pos)? as usize;
        pos += 4;
        if syms > (size - pos) / 2 {
            return None;
        }
        let index_start = pos;
        pos += 2 * syms;
        for k in 0..syms {
            let at = index_start + 2 * k;
            let index = u16::from_le_bytes([p[at], p[at + 1]]) as usize;
            if index == 0 || index > members_n {
                return None;
            }
            st.add(le32(p, index * 4)?, p, &mut pos)?;
        }
        (pos, Kind::Lib, false)
    };
    // Linux tables may be padded to an even size.
    if pos != size && pos + (pos & 1) != size {
        return None;
    }
    Some(Some((st.text, kind, bsd)))
}

pub struct Ar {
    data: Slice,
    entries: Vec<Entry>,
    /// Per entry: the member's data range, or the generated text.
    sources: Vec<Source>,
    units: Vec<Unit>,
    sub_type: String,
    physical_size: u64,
    warning: Option<&'static str>,
    /// A deb's `data.tar.*` member.
    main: Option<usize>,
}

enum Source {
    Data(u64, u64),
    Text(Vec<u8>),
}

fn open(input: Input, _opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let data = input.into_mem()?;
    if !data.starts_with(SIGNATURE) {
        return Err(Error::NotArchive);
    }
    let mut members = Vec::new();
    let mut bsd = false;
    let mut pos = SIGNATURE.len() as u64;
    while let Some((m, next)) = usize::try_from(pos)
        .ok()
        .and_then(|p| parse_member(&data, p, &mut bsd))
    {
        members.push(m);
        pos = next;
    }
    let len = data.len() as u64;
    if pos < len && len - pos < HEADER as u64 && data[pos as usize..].iter().any(|&b| b != b'\n') {
        return Err(Error::corrupt("ar archive ends inside a member header"));
    }
    if members.is_empty() && pos != len {
        return Err(Error::NotArchive);
    }

    let mut warning = None;
    let names_table = match resolve_long_names(&data, &mut members) {
        Ok(t) => t,
        Err(_) => {
            warning = Some("Long file names parsing error");
            None
        }
    };
    number_duplicates(&mut members);
    let mut kind = Kind::Ar;
    let mut texts: Vec<Vec<u8>> = Vec::new();
    for i in 0..members.len().min(2) {
        match parse_symbols(&data, &members, i, texts.len()) {
            Some(Some((text, k, is_bsd))) => {
                members[i].text = Some(texts.len());
                texts.push(text);
                kind = k;
                bsd |= is_bsd;
            }
            Some(None) => {}
            None => warning = Some("Library symbols information error"),
        }
    }
    if let Some(t) = names_table {
        members.remove(t);
    }
    if kind == Kind::Ar && members.first().is_some_and(|m| m.name == b"debian-binary") {
        kind = Kind::Deb;
        members.remove(0);
    }

    let mut entries = Vec::with_capacity(members.len());
    let mut sources = Vec::with_capacity(members.len());
    let mut units = Vec::new();
    for (i, m) in members.into_iter().enumerate() {
        let (name, source, attrib) = match m.text {
            Some(t) => (
                if t == 0 { "1.txt" } else { "2.txt" }.to_string(),
                Source::Text(std::mem::take(&mut texts[t])),
                None,
            ),
            None => (
                String::from_utf8_lossy(display_name(&m.name)).into_owned(),
                Source::Data(m.data_pos, m.size),
                Some(0x8000 | ((m.mode & 0xFFFF) << 16)),
            ),
        };
        let size = match &source {
            Source::Text(t) => t.len() as u64,
            Source::Data(_, s) => *s,
        };
        entries.push(Entry {
            name,
            size: Some(size),
            packed_size: Some(size),
            mtime: (m.mtime != 0).then(|| unix_to_filetime(m.mtime as i64)),
            attrib,
            ..Default::default()
        });
        if size > 0 {
            units.push(Unit {
                entries: vec![i],
                encrypted: false,
            });
        }
        sources.push(source);
    }
    let mut sub_type = match kind {
        Kind::Ar => "ar",
        Kind::ALib => "a",
        Kind::Deb => "deb",
        Kind::Lib => "lib",
    }
    .to_string();
    if bsd {
        sub_type.push_str(":BSD");
    }
    let main = (kind == Kind::Deb)
        .then(|| {
            entries
                .iter()
                .position(|e: &Entry| e.name.starts_with("data.tar"))
        })
        .flatten();
    Ok(Box::new(Ar {
        main,
        data,
        entries,
        sources,
        units,
        sub_type,
        physical_size: pos.min(len),
        warning,
    }))
}

impl Archive for Ar {
    fn format(&self) -> &'static Format {
        &FORMAT
    }

    fn entries(&self) -> &[Entry] {
        &self.entries
    }

    fn units(&self) -> &[Unit] {
        &self.units
    }

    fn extract_unit(&self, unit: usize, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        for &i in &self.units[unit].entries {
            let flow = match &self.sources[i] {
                Source::Text(t) => f(i, &mut t.as_slice())?,
                // A truncated member yields what is there; the extractor reports the
                // shortfall against the recorded size.
                Source::Data(off, size) => {
                    f(i, &mut self.data.sub_clamped(*off..off + size).reader())?
                }
            };
            if flow == Flow::Stop {
                break;
            }
        }
        Ok(())
    }

    fn stream(&self, i: usize) -> Option<super::Opener> {
        match &self.sources[i] {
            Source::Data(off, size) => {
                let s = self.data.sub_clamped(*off..off + size);
                Some(std::sync::Arc::new(move || {
                    Ok(Box::new(s.reader()) as super::BoxRead)
                }))
            }
            Source::Text(_) => None,
        }
    }

    fn main_entry(&self) -> Option<usize> {
        self.main
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let mut p = vec![
            ("Physical Size", self.physical_size.to_string()),
            ("SubType", self.sub_type.clone()),
        ];
        if let Some(w) = self.warning {
            p.push(("Warning", w.into()));
        }
        p
    }
}
