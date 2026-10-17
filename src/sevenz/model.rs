//! In-memory model of a 7z archive's metadata.

use crate::codec::method;
use crate::error::{Error, Result};

/// One coder in a folder. In 7z terms "in" streams are on the packed side and "out" streams
/// on the unpacked side, from the decoder's point of view.
#[derive(Debug, Clone)]
pub struct Coder {
    pub method: u64,
    pub num_in: usize,
    pub num_out: usize,
    pub props: Vec<u8>,
}

/// Connects a coder's in-stream to another coder's out-stream.
#[derive(Debug, Clone, Copy)]
pub struct BindPair {
    pub in_index: usize,
    pub out_index: usize,
}

/// A folder is an independently decodable coder graph over one or more pack streams.
#[derive(Debug, Clone, Default)]
pub struct Folder {
    pub coders: Vec<Coder>,
    pub bind_pairs: Vec<BindPair>,
    /// In-stream indices fed directly from pack streams, in pack-stream order.
    pub packed_streams: Vec<usize>,
    /// One size per out-stream.
    pub unpack_sizes: Vec<u64>,
    pub crc: Option<u32>,
}

impl Folder {
    pub fn num_in_total(&self) -> usize {
        self.coders.iter().map(|c| c.num_in).sum()
    }

    pub fn num_out_total(&self) -> usize {
        self.coders.iter().map(|c| c.num_out).sum()
    }

    /// The out-stream that is not consumed by any bind pair: the folder's final output.
    pub fn main_out(&self) -> Option<usize> {
        (0..self.num_out_total()).find(|&o| !self.bind_pairs.iter().any(|bp| bp.out_index == o))
    }

    pub fn unpack_size(&self) -> u64 {
        self.main_out()
            .and_then(|o| self.unpack_sizes.get(o).copied())
            .unwrap_or(0)
    }

    /// Coder index owning `out`, plus the global index of that coder's first in-stream.
    pub fn coder_of_out(&self, out: usize) -> Option<(usize, usize)> {
        let mut out_base = 0;
        let mut in_base = 0;
        for (i, c) in self.coders.iter().enumerate() {
            if out < out_base + c.num_out {
                return Some((i, in_base));
            }
            out_base += c.num_out;
            in_base += c.num_in;
        }
        None
    }

    pub fn is_encrypted(&self) -> bool {
        self.coders.iter().any(|c| c.method == method::AES)
    }

    /// Structural checks so graph traversal can trust indices.
    pub fn validate(&self) -> Result<()> {
        let n_in = self.num_in_total();
        let n_out = self.num_out_total();
        if self.coders.is_empty() || self.coders.len() > 64 {
            return Err(Error::corrupt("folder coder count out of range"));
        }
        if self.unpack_sizes.len() != n_out {
            return Err(Error::corrupt("folder unpack size count mismatch"));
        }
        if self.bind_pairs.len() + 1 != n_out {
            return Err(Error::corrupt("folder bind pair count mismatch"));
        }
        let mut in_used = vec![false; n_in];
        let mut out_used = vec![false; n_out];
        for bp in &self.bind_pairs {
            if bp.in_index >= n_in || bp.out_index >= n_out {
                return Err(Error::corrupt("bind pair index out of range"));
            }
            if in_used[bp.in_index] || out_used[bp.out_index] {
                return Err(Error::corrupt("bind pair reuses a stream"));
            }
            in_used[bp.in_index] = true;
            out_used[bp.out_index] = true;
        }
        for &p in &self.packed_streams {
            if p >= n_in || in_used[p] {
                return Err(Error::corrupt("packed stream index invalid"));
            }
            in_used[p] = true;
        }
        if in_used.iter().any(|u| !u) {
            return Err(Error::corrupt("folder has an unconnected input"));
        }
        // Reject cycles: every coder must reach the main output.
        let main = self
            .main_out()
            .ok_or_else(|| Error::corrupt("folder has no output"))?;
        let mut seen = vec![false; self.coders.len()];
        let mut stack = vec![main];
        while let Some(o) = stack.pop() {
            let (ci, in_base) = self
                .coder_of_out(o)
                .ok_or_else(|| Error::corrupt("bad out index"))?;
            if seen[ci] {
                return Err(Error::corrupt("folder coder graph has a cycle"));
            }
            seen[ci] = true;
            for s in in_base..in_base + self.coders[ci].num_in {
                if let Some(bp) = self.bind_pairs.iter().find(|bp| bp.in_index == s) {
                    stack.push(bp.out_index);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct StreamsInfo {
    pub pack_pos: u64,
    pub pack_sizes: Vec<u64>,
    pub pack_crcs: Vec<Option<u32>>,
    pub folders: Vec<Folder>,
    /// Substream count per folder.
    pub num_unpack_streams: Vec<usize>,
    /// Sizes of every substream across all folders.
    pub substream_sizes: Vec<u64>,
    pub substream_crcs: Vec<Option<u32>>,
}

#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub name: String,
    pub has_stream: bool,
    pub is_dir: bool,
    pub is_anti: bool,
    pub size: u64,
    pub crc: Option<u32>,
    pub mtime: Option<u64>,
    pub ctime: Option<u64>,
    pub atime: Option<u64>,
    pub attrib: Option<u32>,
    /// Folder holding this entry's data.
    pub folder: Option<usize>,
}

impl Entry {
    pub fn attr_string(&self) -> String {
        use super::attr;
        let a = self.attrib.unwrap_or(0);
        let d = self.is_dir || a & attr::DIRECTORY != 0;
        format!(
            "{}{}{}{}{}",
            if d { 'D' } else { '.' },
            if a & attr::READONLY != 0 { 'R' } else { '.' },
            if a & attr::HIDDEN != 0 { 'H' } else { '.' },
            if a & attr::SYSTEM != 0 { 'S' } else { '.' },
            if a & attr::ARCHIVE != 0 { 'A' } else { '.' },
        )
    }
}

#[derive(Debug, Default)]
pub struct Archive {
    pub streams: StreamsInfo,
    pub entries: Vec<Entry>,
    /// Absolute file offset of each pack stream.
    pub pack_offsets: Vec<u64>,
    /// First pack-stream index of each folder.
    pub folder_first_pack: Vec<usize>,
    /// Entry indices of each folder in stream order.
    pub folder_entries: Vec<Vec<usize>>,
    pub header_encrypted: bool,
    /// Total size of the archive as described by its headers.
    pub physical_size: u64,
    /// Size of the (possibly encoded) header block.
    pub header_size: u64,
}

impl Archive {
    pub fn is_solid(&self) -> bool {
        self.folder_entries.iter().any(|e| e.len() > 1)
    }

    pub fn packed_size_of_folder(&self, f: usize) -> u64 {
        let first = self.folder_first_pack[f];
        let n = self.streams.folders[f].packed_streams.len();
        self.streams.pack_sizes[first..first + n].iter().sum()
    }

    pub fn has_encrypted_data(&self) -> bool {
        self.streams.folders.iter().any(|f| f.is_encrypted())
    }
}
