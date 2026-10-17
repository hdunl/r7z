//! `b` command: in-memory LZMA2 compression and decompression benchmark.

use std::time::{Duration, Instant};

use crate::codec::encode::{EncMethod, FolderEncoder};
use crate::codec::{decode::folder_reader, decode::DecodeOptions};
use crate::error::{Error, Result};
use crate::ops::create::{CreateOptions, MainMethod};

/// Deterministic LZ-style test data: literal runs mixed with back-references, roughly the
/// 2-4x compressibility of typical files.
pub fn generate(size: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    let mut next = || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let mut out = Vec::with_capacity(size);
    while out.len() < size {
        let r = next();
        if out.len() < 64 || r % 4 == 0 {
            let run = 1 + (r >> 8) as usize % 24;
            for _ in 0..run {
                let v = next();
                // Skewed alphabet: text-like literal distribution.
                out.push(b' ' + ((v % 64) as u8 & ((v >> 6) as u8 | 0x1F)));
            }
        } else {
            let max = out.len();
            // Mostly local references with a tail of long ones, like real files.
            let reach = match r % 20 {
                0..=13 => 4 << 10,
                14..=18 => 1 << 20,
                _ => 16 << 20,
            };
            let dist = 1 + (r >> 16) as usize % max.min(reach);
            let len = 3 + (r >> 40) as usize % 40;
            let start = out.len() - dist;
            for k in 0..len {
                let b = out[start + k % dist];
                out.push(b);
            }
        }
    }
    out.truncate(size);
    out
}

pub struct BenchResult {
    pub label: String,
    pub threads: u32,
    pub input: u64,
    pub packed: u64,
    pub compress: Duration,
    pub decompress: Duration,
}

impl BenchResult {
    pub fn compress_mbps(&self) -> f64 {
        self.input as f64 / self.compress.as_secs_f64() / 1e6
    }
    pub fn decompress_mbps(&self) -> f64 {
        self.input as f64 / self.decompress.as_secs_f64() / 1e6
    }
}

/// Runs one compress + decompress cycle with the archive-creation code path.
pub fn run(data: &[u8], level: u32, dict: Option<u32>, threads: usize) -> Result<BenchResult> {
    let opts = CreateOptions {
        level,
        dict_size: dict,
        method: MainMethod::Lzma2,
        threads,
        ..Default::default()
    };
    let method = crate::ops::create::bench_method(&opts, data.len() as u64, threads);
    let workers = match &method {
        EncMethod::Lzma2 { par, .. } => par.map(|p| p.workers as u32).unwrap_or(1),
        _ => 1,
    };
    let mut packed = Vec::with_capacity(data.len() / 2);
    let t0 = Instant::now();
    let mut enc = FolderEncoder::new(std::slice::from_ref(&method), &mut packed)?;
    for chunk in data.chunks(1 << 20) {
        std::io::Write::write_all(&mut enc, chunk).map_err(Error::from_codec)?;
    }
    let (folder, _) = enc.finish()?;
    let compress = t0.elapsed();

    let t1 = Instant::now();
    let dopts = DecodeOptions {
        password: None,
        threads,
    };
    let mut r = folder_reader(&folder, &[&packed], &dopts)?;
    let mut out = vec![0u8; data.len()];
    crate::util::read_full(&mut r, &mut out).map_err(Error::from_codec)?;
    let decompress = t1.elapsed();
    if out != data {
        return Err(Error::Other("benchmark round-trip mismatch".into()));
    }
    let dict_label = match &method {
        EncMethod::Lzma2 { opts, .. } => crate::util::fmt::dict_label(opts.dict_size as u64),
        _ => String::new(),
    };
    Ok(BenchResult {
        label: format!("LZMA2:{dict_label} mx{level}"),
        threads: workers,
        input: data.len() as u64,
        packed: packed.len() as u64,
        compress,
        decompress,
    })
}
