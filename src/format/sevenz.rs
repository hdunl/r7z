//! 7z on the format layer: one unit per folder.

use std::io::Read;

use super::data::Slice;
use super::{
    Archive, Columns, Ctx, Entry, EntryFn, Flow, Format, Input, OpenOptions, Signature, Unit,
};
use crate::codec::decode::{folder_reader, folder_reader_at, restart_pack, DecodeOptions};
use crate::codec::{describe_coder, describe_folder, lzma2scan};
use crate::error::{Error, Result};
use crate::sevenz::read::ArchiveFile;
use crate::sevenz::{salvage, SIGNATURE, SIGNATURE_HEADER_SIZE};

pub const FORMAT: Format = Format {
    name: "7z",
    aliases: &[],
    extensions: &["7z"],
    signatures: &[Signature::at(0, &SIGNATURE)],
    detect: None,
    write: true,
    stream: false,
    sequential: false,
    open,
};

pub struct SevenZ {
    pub file: ArchiveFile,
    entries: Vec<Entry>,
    units: Vec<Unit>,
    /// Set by a recovery open: what was worked around. Pack streams cut off by the end of
    /// the file then decode as far as they go instead of failing.
    salvage: Option<Vec<String>>,
}

fn open(input: Input, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    let data = input.into_mem()?;
    if opts.recover {
        return open_damaged(data, opts);
    }
    let file = ArchiveFile::from_slice(data, opts.password.as_deref())?;
    Ok(Box::new(SevenZ::new(file)))
}

fn open_damaged(data: Slice, opts: &OpenOptions) -> Result<Box<dyn Archive>> {
    match salvage::parse_damaged(&data, opts.password.as_deref()) {
        Ok((archive, mut notes)) => {
            let mut z = SevenZ::new(ArchiveFile { data, archive });
            for f in 0..z.units.len() {
                if z.file.folder_packs_clamped(f).1 {
                    notes.push(format!("block {f} is cut off by the end of the file"));
                }
            }
            z.salvage = Some(notes);
            Ok(Box::new(z))
        }
        Err(e @ (Error::PasswordRequired | Error::WrongPassword | Error::Unsupported(_))) => Err(e),
        Err(e) => RawStreams::open(data, &opts.name).ok_or(e),
    }
}

impl SevenZ {
    pub fn new(file: ArchiveFile) -> Self {
        let a = &file.archive;
        let mut first_in_folder = vec![usize::MAX; a.streams.folders.len()];
        for (f, ents) in a.folder_entries.iter().enumerate() {
            if let Some(&first) = ents.first() {
                first_in_folder[f] = first;
            }
        }
        let methods: Vec<String> = a.streams.folders.iter().map(describe_folder).collect();
        let entries = a
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let folder = e.folder.map(|f| &a.streams.folders[f]);
                Entry {
                    name: e.name.clone(),
                    raw_name: None,
                    is_dir: e.is_dir,
                    size: Some(e.size),
                    packed_size: match e.folder {
                        Some(f) if first_in_folder[f] == i => Some(a.packed_size_of_folder(f)),
                        Some(_) => None,
                        None => Some(0),
                    },
                    mtime: e.mtime,
                    ctime: e.ctime,
                    atime: e.atime,
                    attrib: e.attrib,
                    crc: e.crc,
                    method: e.folder.map(|f| methods[f].clone()),
                    encrypted: folder.is_some_and(|f| f.is_encrypted()),
                    is_anti: e.is_anti,
                    block: e.folder,
                    link: None,
                    comment: None,
                }
            })
            .collect();
        let units = a
            .folder_entries
            .iter()
            .zip(&a.streams.folders)
            .map(|(ents, f)| Unit {
                entries: ents.clone(),
                encrypted: f.is_encrypted(),
            })
            .collect();
        SevenZ {
            file,
            entries,
            units,
            salvage: None,
        }
    }

    fn packs(&self, unit: usize) -> Result<Vec<&[u8]>> {
        if self.salvage.is_some() {
            Ok(self.file.folder_packs_clamped(unit).0)
        } else {
            self.file.folder_packs(unit)
        }
    }

    /// (packed, unpacked) dictionary resets of a folder that can restart.
    fn restarts(&self, unit: usize) -> Vec<(u64, u64)> {
        let folder = &self.file.archive.streams.folders[unit];
        if restart_pack(folder).is_none() {
            return Vec::new();
        }
        match self.packs(unit) {
            Ok(p) if p.len() == 1 => lzma2scan::restart_points(p[0]),
            _ => Vec::new(),
        }
    }

    fn methods(&self) -> String {
        let mut seen = Vec::<String>::new();
        for f in &self.file.archive.streams.folders {
            for c in f.coders.iter().rev() {
                let d = describe_coder(c);
                if !seen.contains(&d) {
                    seen.push(d);
                }
            }
        }
        seen.join(" ")
    }
}

impl Archive for SevenZ {
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
        let a = &self.file.archive;
        let folder = &a.streams.folders[unit];
        let packs = self.packs(unit)?;
        let dopts = DecodeOptions {
            password: ctx.password.clone(),
            threads: ctx.threads,
        };
        let mut reader = folder_reader(folder, &packs, &dopts)?;
        for &i in &a.folder_entries[unit] {
            let mut take = (&mut reader).take(a.entries[i].size);
            if f(i, &mut take)? == Flow::Stop {
                break;
            }
            // Solid data: whatever the caller did not read must still be decoded.
            super::data::skip(&mut take, u64::MAX)?;
        }
        Ok(())
    }

    fn properties(&self) -> Vec<(&'static str, String)> {
        let a = &self.file.archive;
        let mut p = vec![
            ("Physical Size", a.physical_size.to_string()),
            ("Headers Size", a.header_size.to_string()),
        ];
        let methods = self.methods();
        if !methods.is_empty() {
            p.push(("Method", methods));
        }
        p.push(("Solid", if a.is_solid() { "+" } else { "-" }.into()));
        p.push(("Blocks", a.streams.folders.len().to_string()));
        if a.header_encrypted {
            p.push(("Encrypted Header", "+".into()));
        }
        p
    }

    fn columns(&self) -> Columns {
        Columns {
            crc: true,
            method: true,
            encrypted: true,
            block: true,
        }
    }

    fn has_encrypted_data(&self) -> bool {
        self.file.archive.has_encrypted_data()
    }

    fn damage(&self) -> Vec<String> {
        self.salvage.clone().unwrap_or_default()
    }

    fn restart_points(&self, unit: usize) -> Vec<u64> {
        self.restarts(unit).into_iter().map(|(_, u)| u).collect()
    }

    fn extract_unit_at(&self, unit: usize, at: u64, _ctx: &Ctx, f: &mut EntryFn<'_>) -> Result<()> {
        let a = &self.file.archive;
        let (packed, _) = self
            .restarts(unit)
            .into_iter()
            .find(|&(_, u)| u == at)
            .ok_or_else(|| Error::corrupt("no restart point there"))?;
        let packs = self.packs(unit)?;
        let mut reader = folder_reader_at(&a.streams.folders[unit], packs[0], packed, at)?;
        let mut pos = at;
        let mut start = 0u64;
        for &i in &a.folder_entries[unit] {
            let size = a.entries[i].size;
            let begin = start;
            start += size;
            if begin < at {
                continue;
            }
            if super::data::skip(&mut reader, begin - pos)? != begin - pos {
                return Err(Error::corrupt("unexpected end of data"));
            }
            let mut take = (&mut reader).take(size);
            let flow = f(i, &mut take)?;
            super::data::skip(&mut take, u64::MAX)?;
            pos = start;
            if flow == Flow::Stop {
                break;
            }
        }
        Ok(())
    }
}

/// What is left of a 7z archive whose header is gone: the packed data decoded as raw LZMA2
/// (or LZMA) streams, one entry per stream, without names or file boundaries.
struct RawStreams {
    data: Slice,
    entries: Vec<Entry>,
    units: Vec<Unit>,
    streams: Vec<(usize, usize)>,
    lzma2: bool,
    dict: u32,
    notes: Vec<String>,
}

impl RawStreams {
    fn open(data: Slice, archive_name: &str) -> Option<Box<dyn Archive>> {
        let lo = SIGNATURE_HEADER_SIZE as usize;
        let first = *data.get(lo)?;
        let lzma2 = first == 0x01 || first >= 0xE0;
        if !lzma2 && first != 0x00 {
            return None;
        }
        let mut streams = Vec::new();
        if lzma2 {
            let mut p = lo;
            while p < data.len() && (data[p] == 0x01 || data[p] >= 0xE0) {
                match lzma2scan::stream_len(&data[p..]) {
                    Some(n) => {
                        streams.push((p, p + n));
                        p += n;
                    }
                    None => {
                        streams.push((p, data.len()));
                        break;
                    }
                }
            }
        } else {
            streams.push((lo, data.len()));
        }
        let base = archive_name
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(archive_name);
        let stem = match base.rsplit_once('.') {
            Some((s, ext)) if ext.eq_ignore_ascii_case("7z") && !s.is_empty() => s,
            _ if base.is_empty() => "data",
            _ => base,
        };
        let names: Vec<String> = if streams.len() == 1 {
            vec![if stem.contains('.') {
                stem.to_string()
            } else {
                format!("{stem}.bin")
            }]
        } else {
            (1..=streams.len())
                .map(|k| format!("{stem}.block{k}.bin"))
                .collect()
        };
        let entries: Vec<Entry> = names
            .into_iter()
            .zip(&streams)
            .map(|(name, &(s, e))| Entry {
                name,
                packed_size: Some((e - s) as u64),
                method: Some(if lzma2 { "LZMA2" } else { "LZMA" }.into()),
                ..Default::default()
            })
            .collect();
        let units = (0..entries.len())
            .map(|i| Unit {
                entries: vec![i],
                encrypted: false,
            })
            .collect();
        // The dictionary size was in the lost header; this covers what 7-Zip writes by
        // default and anything up to the size of the file.
        let dict = (data.len() as u64)
            .next_power_of_two()
            .clamp(64 << 20, 1536 << 20) as u32;
        let notes = vec![format!(
            "the archive header is lost, so file names and boundaries are unknown; the packed \
             data was decoded as {} raw {} stream{} (data from a BCJ-filtered archive stays \
             filtered)",
            streams.len(),
            if lzma2 { "LZMA2" } else { "LZMA" },
            if streams.len() == 1 { "" } else { "s" }
        )];
        Some(Box::new(RawStreams {
            data,
            entries,
            units,
            streams,
            lzma2,
            dict,
            notes,
        }))
    }
}

impl Archive for RawStreams {
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
        let (s, e) = self.streams[unit];
        let src = &self.data[s..e];
        let mut r: Box<dyn Read + '_> = if self.lzma2 {
            Box::new(lzma_rust2::Lzma2Reader::new(src, self.dict, None))
        } else {
            // 7-Zip's default literal/position settings; the real ones were in the header.
            Box::new(
                lzma_rust2::LzmaReader::new_with_props(src, u64::MAX, 0x5D, self.dict, None)
                    .map_err(super::data::data_err)?,
            )
        };
        f(self.units[unit].entries[0], &mut r)?;
        Ok(())
    }

    fn damage(&self) -> Vec<String> {
        self.notes.clone()
    }
}
