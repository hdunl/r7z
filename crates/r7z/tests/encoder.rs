//! The threaded match finder must produce exactly the stream the single-threaded encoder
//! produces for the same writes, for any group size. (The encoder's own output depends on
//! how the input is split into writes, so the comparison always uses one split.)

use std::io::{Read, Write};
use std::num::NonZeroU64;

use lzma_rust2::Lzma2Reader;
use r7z::codec::lzenc::{Lzma2Options, Lzma2Writer, LzmaOptions};
use r7z::ops::bench::generate;

fn encode(opts: &Lzma2Options, data: &[u8], threaded: bool, piece: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if threaded {
        let mut w = Lzma2Writer::new_threaded(&mut out, opts.clone()).unwrap();
        for part in data.chunks(piece) {
            w.write_all(part).unwrap();
        }
        w.finish().unwrap();
    } else {
        let mut w = Lzma2Writer::new(&mut out, opts.clone());
        for part in data.chunks(piece) {
            w.write_all(part).unwrap();
        }
        w.finish().unwrap();
    }
    out
}

fn options(dict: u32, nice_len: u32, group: u64) -> Lzma2Options {
    let mut lz = LzmaOptions::with_preset(9);
    lz.dict_size = dict;
    lz.nice_len = nice_len;
    Lzma2Options {
        lzma_options: lz,
        chunk_size: NonZeroU64::new(group),
    }
}

#[test]
fn threaded_stream_is_identical_to_inline() {
    let mut data = generate(3 << 20, 5);
    data.extend_from_slice(&b"let total = a + b; return total * 2;\n".repeat(30_000));
    data.extend_from_slice(&generate(1 << 20, 9));
    // One group, several groups with a small dictionary, and a nice length that makes
    // matches end early.
    for (dict, nice, group) in [
        (1u32 << 24, 273, 1u64 << 26),
        (1 << 20, 273, 1 << 20),
        (1 << 16, 32, 300 << 10),
    ] {
        let opts = options(dict, nice, group);
        // Odd write sizes exercise the window's partial copies.
        for piece in [65_536, 12_345] {
            let inline = encode(&opts, &data, false, piece);
            let threaded = encode(&opts, &data, true, piece);
            assert!(
                inline == threaded,
                "dict {dict} nice {nice} group {group} piece {piece}"
            );

            let mut back = Vec::new();
            Lzma2Reader::new(&threaded[..], dict, None)
                .read_to_end(&mut back)
                .unwrap();
            assert!(
                back == data,
                "dict {dict} nice {nice} group {group} does not decode"
            );
        }
    }
}

#[test]
fn threaded_handles_tiny_inputs() {
    for len in [0usize, 1, 2, 273, 274, 4096] {
        let data = generate(len, len as u64 + 1);
        let opts = options(1 << 20, 273, 1 << 20);
        let inline = encode(&opts, &data, false, 7);
        let threaded = encode(&opts, &data, true, 7);
        assert!(inline == threaded, "len {len}");
    }
}
