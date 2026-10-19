//! Builds a `Read` pipeline for a folder's coder graph.

use std::io::{self, Read};

use lzma_rust2::filter::bcj::BcjReader;
use lzma_rust2::filter::bcj2::Bcj2Reader;
use lzma_rust2::filter::delta::DeltaReader;
use lzma_rust2::{Lzma2Reader, Lzma2ReaderMt, LzmaReader};

use super::aes::AesReader;
use super::{lzma2_dict_from_prop, lzma2scan, method, method_name};
use crate::error::{Error, Result};
use crate::sevenz::{Coder, Folder};

pub type BoxRead<'a> = Box<dyn Read + Send + 'a>;

#[derive(Clone, Debug, Default)]
pub struct DecodeOptions {
    pub password: Option<String>,
    /// Threads available to this folder's decoder (LZMA2 block parallelism).
    pub threads: usize,
}

/// A reader over the folder's final output. `packs` are the folder's pack streams in order.
pub fn folder_reader<'a>(
    folder: &Folder,
    packs: &[&'a [u8]],
    opts: &DecodeOptions,
) -> Result<BoxRead<'a>> {
    folder.validate()?;
    if packs.len() != folder.packed_streams.len() {
        return Err(Error::corrupt("pack stream count mismatch"));
    }
    let main = folder
        .main_out()
        .ok_or_else(|| Error::corrupt("folder has no output"))?;
    build_out(folder, main, packs, opts)
}

fn build_out<'a>(
    folder: &Folder,
    out: usize,
    packs: &[&'a [u8]],
    opts: &DecodeOptions,
) -> Result<BoxRead<'a>> {
    let (ci, in_base) = folder
        .coder_of_out(out)
        .ok_or_else(|| Error::corrupt("bad coder output index"))?;
    let coder = &folder.coders[ci];
    if coder.num_out != 1 {
        return Err(Error::unsupported("coders with several outputs"));
    }
    let mut inputs: Vec<BoxRead<'a>> = Vec::with_capacity(coder.num_in);
    let mut raw: Option<&'a [u8]> = None;
    for s in in_base..in_base + coder.num_in {
        if let Some(bp) = folder.bind_pairs.iter().find(|bp| bp.in_index == s) {
            inputs.push(build_out(folder, bp.out_index, packs, opts)?);
        } else {
            let k = folder
                .packed_streams
                .iter()
                .position(|&p| p == s)
                .ok_or_else(|| Error::corrupt("unbound coder input"))?;
            raw = Some(packs[k]);
            inputs.push(Box::new(packs[k]));
        }
    }
    let raw = if coder.num_in == 1 { raw } else { None };
    let size = folder.unpack_sizes[out];
    Ok(Box::new(
        coder_reader(coder, inputs, raw, size, opts)?.take(size),
    ))
}

/// The pack stream feeding an LZMA2 coder at the bottom of a chain of one-input,
/// size-preserving filters, the only shape that can restart at a dictionary reset.
pub fn restart_pack(folder: &Folder) -> Option<usize> {
    if folder.packed_streams.len() != 1 || folder.is_encrypted() {
        return None;
    }
    let mut out = folder.main_out()?;
    loop {
        let (ci, in_base) = folder.coder_of_out(out)?;
        let c = &folder.coders[ci];
        if c.num_in != 1 || c.num_out != 1 {
            return None;
        }
        match folder.bind_pairs.iter().find(|bp| bp.in_index == in_base) {
            Some(bp) if is_branch_filter(c.method) => out = bp.out_index,
            None if c.method == method::LZMA2 => return Some(0),
            _ => return None,
        }
    }
}

fn is_branch_filter(m: u64) -> bool {
    matches!(
        m,
        method::BCJ_X86
            | method::ARM
            | method::ARMT
            | method::ARM64
            | method::PPC
            | method::SPARC
            | method::IA64
            | method::RISCV
    )
}

/// A reader over the folder's output from unpacked offset `unpacked`, where the LZMA2
/// pack stream has a dictionary reset at `packed` (see `lzma2scan::restart_points`).
/// Only for folders `restart_pack` accepts.
pub fn folder_reader_at<'a>(
    folder: &Folder,
    pack: &'a [u8],
    packed: u64,
    unpacked: u64,
) -> Result<BoxRead<'a>> {
    restart_pack(folder).ok_or_else(|| Error::unsupported("restart in this folder"))?;
    let main = folder
        .main_out()
        .ok_or_else(|| Error::corrupt("folder has no output"))?;
    reader_at(folder, main, pack, packed, unpacked)
}

fn reader_at<'a>(
    folder: &Folder,
    out: usize,
    pack: &'a [u8],
    packed: u64,
    unpacked: u64,
) -> Result<BoxRead<'a>> {
    let (ci, in_base) = folder
        .coder_of_out(out)
        .ok_or_else(|| Error::corrupt("bad coder output index"))?;
    let c = &folder.coders[ci];
    let size = folder.unpack_sizes[out].saturating_sub(unpacked);
    let p = &c.props;
    if c.method == method::LZMA2 {
        let dict = p
            .first()
            .and_then(|&b| lzma2_dict_from_prop(b))
            .ok_or_else(|| Error::corrupt("LZMA2 dictionary property invalid"))?;
        let from = pack.get(packed as usize..).unwrap_or_default();
        return Ok(Box::new(Lzma2Reader::new(from, dict, None).take(size)));
    }
    let bp = folder
        .bind_pairs
        .iter()
        .find(|bp| bp.in_index == in_base)
        .ok_or_else(|| Error::corrupt("unbound coder input"))?;
    let input = reader_at(folder, bp.out_index, pack, packed, unpacked)?;
    // Branch filters convert addresses relative to the stream position, so they start at
    // the restart offset.
    let start = bcj_start(p).wrapping_add(unpacked as usize);
    let r: BoxRead<'a> = match c.method {
        method::BCJ_X86 => Box::new(BcjReader::new_x86(input, start)),
        method::ARM => Box::new(BcjReader::new_arm(input, start)),
        method::ARMT => Box::new(BcjReader::new_arm_thumb(input, start)),
        method::ARM64 => Box::new(BcjReader::new_arm64(input, start)),
        method::PPC => Box::new(BcjReader::new_ppc(input, start)),
        method::SPARC => Box::new(BcjReader::new_sparc(input, start)),
        method::IA64 => Box::new(BcjReader::new_ia64(input, start)),
        method::RISCV => Box::new(BcjReader::new_riscv(input, start)),
        _ => return Err(Error::unsupported("restart in this folder")),
    };
    Ok(Box::new(r.take(size)))
}

/// Codec input is an in-memory slice, so any I/O error from a decoder is a data error.
fn codec_err(e: io::Error) -> Error {
    match Error::from_codec(e) {
        Error::Io(x) => Error::corrupt(x.to_string()),
        other => other,
    }
}

fn bcj_start(props: &[u8]) -> usize {
    if props.len() >= 4 {
        u32::from_le_bytes(props[..4].try_into().unwrap()) as usize
    } else {
        0
    }
}

fn coder_reader<'a>(
    coder: &Coder,
    mut inputs: Vec<BoxRead<'a>>,
    raw: Option<&'a [u8]>,
    out_size: u64,
    opts: &DecodeOptions,
) -> Result<BoxRead<'a>> {
    let p = &coder.props;
    let single = |inputs: &mut Vec<BoxRead<'a>>| -> Result<BoxRead<'a>> {
        if inputs.len() != 1 {
            return Err(Error::corrupt(format!(
                "{} expects one input",
                method_name(coder.method)
            )));
        }
        Ok(inputs.pop().unwrap())
    };
    Ok(match coder.method {
        method::COPY => single(&mut inputs)?,
        method::LZMA => {
            if p.len() < 5 {
                return Err(Error::corrupt("LZMA properties truncated"));
            }
            let dict = u32::from_le_bytes(p[1..5].try_into().unwrap());
            let input = single(&mut inputs)?;
            Box::new(
                LzmaReader::new_with_props(input, out_size, p[0], dict, None).map_err(codec_err)?,
            )
        }
        method::LZMA2 => {
            let dict = p
                .first()
                .and_then(|&b| lzma2_dict_from_prop(b))
                .ok_or_else(|| Error::corrupt("LZMA2 dictionary property invalid"))?;
            let input = single(&mut inputs)?;
            match raw {
                // Parallel decode only pays off when the stream has independent blocks.
                Some(data)
                    if opts.threads > 1 && lzma2scan::count_blocks(data, 2).unwrap_or(0) >= 2 =>
                {
                    Box::new(Lzma2ReaderMt::new(data, dict, None, opts.threads as u32))
                }
                _ => Box::new(Lzma2Reader::new(input, dict, None)),
            }
        }
        method::BCJ_X86 => Box::new(BcjReader::new_x86(single(&mut inputs)?, bcj_start(p))),
        method::ARM => Box::new(BcjReader::new_arm(single(&mut inputs)?, bcj_start(p))),
        method::ARMT => Box::new(BcjReader::new_arm_thumb(single(&mut inputs)?, bcj_start(p))),
        method::ARM64 => Box::new(BcjReader::new_arm64(single(&mut inputs)?, bcj_start(p))),
        method::PPC => Box::new(BcjReader::new_ppc(single(&mut inputs)?, bcj_start(p))),
        method::SPARC => Box::new(BcjReader::new_sparc(single(&mut inputs)?, bcj_start(p))),
        method::IA64 => Box::new(BcjReader::new_ia64(single(&mut inputs)?, bcj_start(p))),
        method::RISCV => Box::new(BcjReader::new_riscv(single(&mut inputs)?, bcj_start(p))),
        method::DELTA => {
            let dist = p.first().map(|&b| b as usize + 1).unwrap_or(1);
            Box::new(DeltaReader::new(single(&mut inputs)?, dist))
        }
        method::BCJ2 => {
            if inputs.len() != 4 {
                return Err(Error::corrupt("BCJ2 expects four inputs"));
            }
            Box::new(Bcj2Reader::try_new(inputs, out_size).map_err(codec_err)?)
        }
        method::PPMD => {
            if p.len() < 5 {
                return Err(Error::corrupt("PPMd properties truncated"));
            }
            let order = p[0] as u32;
            let mem = u32::from_le_bytes(p[1..5].try_into().unwrap());
            Box::new(
                ppmd_rust::Ppmd7Decoder::new(single(&mut inputs)?, order, mem)
                    .map_err(|e| Error::corrupt(format!("PPMd: {e}")))?,
            )
        }
        method::BZIP2 => Box::new(bzip2::read::MultiBzDecoder::new(single(&mut inputs)?)),
        method::DEFLATE => Box::new(flate2::read::DeflateDecoder::new(single(&mut inputs)?)),
        method::DEFLATE64 => Box::new(deflate64::Deflate64Decoder::new(single(&mut inputs)?)),
        method::AES => Box::new(AesReader::new(
            single(&mut inputs)?,
            p,
            opts.password.as_deref(),
        )?),
        other => {
            let name = method_name(other);
            return Err(Error::unsupported(if name == "?" {
                format!("compression method {other:X}")
            } else {
                format!("compression method {name}")
            }));
        }
    })
}

/// Decodes a whole folder into memory (used for encoded headers).
pub fn decode_folder_to_vec(
    folder: &Folder,
    packs: &[&[u8]],
    opts: &DecodeOptions,
    limit: u64,
) -> Result<Vec<u8>> {
    let size = folder.unpack_size();
    if size > limit {
        return Err(Error::corrupt("encoded header is implausibly large"));
    }
    let mut r = folder_reader(folder, packs, opts)?;
    let mut out = Vec::with_capacity(size as usize);
    r.read_to_end(&mut out).map_err(codec_err)?;
    if out.len() as u64 != size {
        return Err(Error::corrupt("folder ended early"));
    }
    Ok(out)
}
