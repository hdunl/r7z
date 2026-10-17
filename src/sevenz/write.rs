//! Serializes 7z headers.

use super::bytes::{write_bit_vector, write_defined_vector, write_digests, write_number};
use super::{id, Entry, Folder, StreamsInfo, SIGNATURE, VERSION_MAJOR, VERSION_MINOR};

pub fn signature_header(next_offset: u64, next_size: u64, next_crc: u32) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..6].copy_from_slice(&SIGNATURE);
    h[6] = VERSION_MAJOR;
    h[7] = VERSION_MINOR;
    h[12..20].copy_from_slice(&next_offset.to_le_bytes());
    h[20..28].copy_from_slice(&next_size.to_le_bytes());
    h[28..32].copy_from_slice(&next_crc.to_le_bytes());
    let start_crc = crc32fast::hash(&h[12..32]);
    h[8..12].copy_from_slice(&start_crc.to_le_bytes());
    h
}

fn write_folder(out: &mut Vec<u8>, f: &Folder) {
    write_number(out, f.coders.len() as u64);
    for c in &f.coders {
        let id_bytes = c.method.to_be_bytes();
        let skip = id_bytes.iter().take_while(|&&b| b == 0).count().min(7);
        let id = &id_bytes[skip..];
        let complex = c.num_in != 1 || c.num_out != 1;
        let mut flags = id.len() as u8;
        if complex {
            flags |= 0x10;
        }
        if !c.props.is_empty() {
            flags |= 0x20;
        }
        out.push(flags);
        out.extend_from_slice(id);
        if complex {
            write_number(out, c.num_in as u64);
            write_number(out, c.num_out as u64);
        }
        if !c.props.is_empty() {
            write_number(out, c.props.len() as u64);
            out.extend_from_slice(&c.props);
        }
    }
    for bp in &f.bind_pairs {
        write_number(out, bp.in_index as u64);
        write_number(out, bp.out_index as u64);
    }
    if f.packed_streams.len() > 1 {
        for &p in &f.packed_streams {
            write_number(out, p as u64);
        }
    }
}

pub fn write_streams_info(out: &mut Vec<u8>, si: &StreamsInfo, substreams: bool) {
    if !si.pack_sizes.is_empty() {
        write_number(out, id::PACK_INFO);
        write_number(out, si.pack_pos);
        write_number(out, si.pack_sizes.len() as u64);
        write_number(out, id::SIZE);
        for &s in &si.pack_sizes {
            write_number(out, s);
        }
        write_number(out, id::END);
    }
    if !si.folders.is_empty() {
        write_number(out, id::UNPACK_INFO);
        write_number(out, id::FOLDER);
        write_number(out, si.folders.len() as u64);
        out.push(0); // not external
        for f in &si.folders {
            write_folder(out, f);
        }
        write_number(out, id::CODERS_UNPACK_SIZE);
        for f in &si.folders {
            for &s in &f.unpack_sizes {
                write_number(out, s);
            }
        }
        if si.folders.iter().any(|f| f.crc.is_some()) {
            write_number(out, id::CRC);
            let crcs: Vec<Option<u32>> = si.folders.iter().map(|f| f.crc).collect();
            write_digests(out, &crcs);
        }
        write_number(out, id::END);
    }
    if substreams && !si.folders.is_empty() {
        write_number(out, id::SUBSTREAMS_INFO);
        if si.num_unpack_streams.iter().any(|&n| n != 1) {
            write_number(out, id::NUM_UNPACK_STREAM);
            for &n in &si.num_unpack_streams {
                write_number(out, n as u64);
            }
        }
        if si.num_unpack_streams.iter().any(|&n| n > 1) {
            write_number(out, id::SIZE);
            let mut k = 0;
            for &n in &si.num_unpack_streams {
                for j in 0..n {
                    if j + 1 < n {
                        write_number(out, si.substream_sizes[k]);
                    }
                    k += 1;
                }
            }
        }
        let mut digests = Vec::new();
        let mut k = 0;
        for (f, &n) in si.folders.iter().zip(&si.num_unpack_streams) {
            if n == 1 && f.crc.is_some() {
                k += 1;
                continue;
            }
            digests.extend_from_slice(&si.substream_crcs[k..k + n]);
            k += n;
        }
        if digests.iter().any(|d| d.is_some()) {
            write_number(out, id::CRC);
            write_digests(out, &digests);
        }
        write_number(out, id::END);
    }
    write_number(out, id::END);
}

fn write_prop(out: &mut Vec<u8>, prop: u64, data: &[u8]) {
    write_number(out, prop);
    write_number(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn write_times(out: &mut Vec<u8>, prop: u64, values: Vec<Option<u64>>) {
    if values.iter().all(|v| v.is_none()) {
        return;
    }
    let mut d = Vec::with_capacity(values.len() * 8 + 2);
    let defined: Vec<bool> = values.iter().map(|v| v.is_some()).collect();
    write_defined_vector(&mut d, &defined);
    d.push(0);
    for v in values.into_iter().flatten() {
        d.extend_from_slice(&v.to_le_bytes());
    }
    write_prop(out, prop, &d);
}

pub fn write_files_info(out: &mut Vec<u8>, entries: &[Entry]) {
    write_number(out, id::FILES_INFO);
    write_number(out, entries.len() as u64);

    let empty_stream: Vec<bool> = entries.iter().map(|e| !e.has_stream).collect();
    if empty_stream.iter().any(|&b| b) {
        let mut d = Vec::new();
        write_bit_vector(&mut d, &empty_stream);
        write_prop(out, id::EMPTY_STREAM, &d);
        let empty_file: Vec<bool> = entries
            .iter()
            .filter(|e| !e.has_stream)
            .map(|e| !e.is_dir)
            .collect();
        if empty_file.iter().any(|&b| b) {
            let mut d = Vec::new();
            write_bit_vector(&mut d, &empty_file);
            write_prop(out, id::EMPTY_FILE, &d);
        }
        let anti: Vec<bool> = entries
            .iter()
            .filter(|e| !e.has_stream)
            .map(|e| e.is_anti)
            .collect();
        if anti.iter().any(|&b| b) {
            let mut d = Vec::new();
            write_bit_vector(&mut d, &anti);
            write_prop(out, id::ANTI, &d);
        }
    }

    let mut names = vec![0u8];
    for e in entries {
        for u in e.name.encode_utf16() {
            names.extend_from_slice(&u.to_le_bytes());
        }
        names.extend_from_slice(&[0, 0]);
    }
    write_prop(out, id::NAME, &names);

    write_times(out, id::CTIME, entries.iter().map(|e| e.ctime).collect());
    write_times(out, id::ATIME, entries.iter().map(|e| e.atime).collect());
    write_times(out, id::MTIME, entries.iter().map(|e| e.mtime).collect());

    if entries.iter().any(|e| e.attrib.is_some()) {
        let defined: Vec<bool> = entries.iter().map(|e| e.attrib.is_some()).collect();
        let mut d = Vec::new();
        write_defined_vector(&mut d, &defined);
        d.push(0);
        for a in entries.iter().filter_map(|e| e.attrib) {
            d.extend_from_slice(&a.to_le_bytes());
        }
        write_prop(out, id::WIN_ATTRIBUTES, &d);
    }
    write_number(out, id::END);
}

pub fn write_header(si: &StreamsInfo, entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::new();
    write_number(&mut out, id::HEADER);
    if !si.folders.is_empty() {
        write_number(&mut out, id::MAIN_STREAMS_INFO);
        write_streams_info(&mut out, si, true);
    }
    if !entries.is_empty() {
        write_files_info(&mut out, entries);
    }
    write_number(&mut out, id::END);
    out
}

pub fn write_encoded_header(si: &StreamsInfo) -> Vec<u8> {
    let mut out = Vec::new();
    write_number(&mut out, id::ENCODED_HEADER);
    write_streams_info(&mut out, si, false);
    out
}
