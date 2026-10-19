//! `h` command: file hashing, parallel across files.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use rayon::prelude::*;
use sha2::Digest;

use crate::error::{Error, Result};
use crate::util::crc64::Crc64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashKind {
    Crc32,
    Crc64,
    Xxh64,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
}

impl HashKind {
    pub const ALL: [HashKind; 9] = [
        HashKind::Crc32,
        HashKind::Crc64,
        HashKind::Xxh64,
        HashKind::Md5,
        HashKind::Sha1,
        HashKind::Sha256,
        HashKind::Sha384,
        HashKind::Sha512,
        HashKind::Sha3_256,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_uppercase().replace('-', "").as_str() {
            "CRC32" | "CRC" => HashKind::Crc32,
            "CRC64" => HashKind::Crc64,
            "XXH64" => HashKind::Xxh64,
            "MD5" => HashKind::Md5,
            "SHA1" => HashKind::Sha1,
            "SHA256" => HashKind::Sha256,
            "SHA384" => HashKind::Sha384,
            "SHA512" => HashKind::Sha512,
            "SHA3256" | "SHA3" => HashKind::Sha3_256,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            HashKind::Crc32 => "CRC32",
            HashKind::Crc64 => "CRC64",
            HashKind::Xxh64 => "XXH64",
            HashKind::Md5 => "MD5",
            HashKind::Sha1 => "SHA1",
            HashKind::Sha256 => "SHA256",
            HashKind::Sha384 => "SHA384",
            HashKind::Sha512 => "SHA512",
            HashKind::Sha3_256 => "SHA3-256",
        }
    }

    pub fn hex_len(self) -> usize {
        match self {
            HashKind::Crc32 => 8,
            HashKind::Crc64 | HashKind::Xxh64 => 16,
            HashKind::Md5 => 32,
            HashKind::Sha1 => 40,
            HashKind::Sha256 | HashKind::Sha3_256 => 64,
            HashKind::Sha384 => 96,
            HashKind::Sha512 => 128,
        }
    }
}

enum State {
    Crc32(crc32fast::Hasher),
    Crc64(Crc64),
    Xxh64(Box<xxhash_rust::xxh64::Xxh64>),
    Md5(md5::Md5),
    Sha1(sha1::Sha1),
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Sha3(sha3::Sha3_256),
}

impl State {
    fn new(k: HashKind) -> Self {
        match k {
            HashKind::Crc32 => State::Crc32(crc32fast::Hasher::new()),
            HashKind::Crc64 => State::Crc64(Crc64::new()),
            HashKind::Xxh64 => State::Xxh64(Box::new(xxhash_rust::xxh64::Xxh64::new(0))),
            HashKind::Md5 => State::Md5(md5::Md5::new()),
            HashKind::Sha1 => State::Sha1(sha1::Sha1::new()),
            HashKind::Sha256 => State::Sha256(sha2::Sha256::new()),
            HashKind::Sha384 => State::Sha384(sha2::Sha384::new()),
            HashKind::Sha512 => State::Sha512(sha2::Sha512::new()),
            HashKind::Sha3_256 => State::Sha3(sha3::Sha3_256::new()),
        }
    }
    fn update(&mut self, d: &[u8]) {
        match self {
            State::Crc32(h) => h.update(d),
            State::Crc64(h) => h.update(d),
            State::Xxh64(h) => h.update(d),
            State::Md5(h) => h.update(d),
            State::Sha1(h) => h.update(d),
            State::Sha256(h) => h.update(d),
            State::Sha384(h) => h.update(d),
            State::Sha512(h) => h.update(d),
            State::Sha3(h) => h.update(d),
        }
    }
    fn hex(self) -> String {
        match self {
            State::Crc32(h) => format!("{:08X}", h.finalize()),
            State::Crc64(h) => format!("{:016X}", h.finalize()),
            State::Xxh64(h) => format!("{:016X}", h.digest()),
            State::Md5(h) => to_hex(&h.finalize()),
            State::Sha1(h) => to_hex(&h.finalize()),
            State::Sha256(h) => to_hex(&h.finalize()),
            State::Sha384(h) => to_hex(&h.finalize()),
            State::Sha512(h) => to_hex(&h.finalize()),
            State::Sha3(h) => to_hex(&h.finalize()),
        }
    }
}

fn to_hex(b: &[u8]) -> String {
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            s.push_str(&format!("{x:02x}"));
            s
        })
}

pub struct FileHash {
    pub path: PathBuf,
    pub display: String,
    pub size: u64,
    pub digests: Result<Vec<String>>,
}

/// Hashes each file with every requested algorithm in one pass over its data.
pub fn hash_files(
    files: Vec<(PathBuf, String)>,
    kinds: &[HashKind],
    threads: usize,
    on_bytes: &(dyn Fn(u64) + Sync),
) -> Vec<FileHash> {
    let work = |(path, display): (PathBuf, String)| -> FileHash {
        let mut size = 0u64;
        let digests = (|| -> Result<Vec<String>> {
            let mut f =
                File::open(&path).map_err(|e| Error::Other(format!("{}: {e}", path.display())))?;
            let mut states: Vec<State> = kinds.iter().map(|&k| State::new(k)).collect();
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = match f.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(Error::Other(format!("{}: {e}", path.display()))),
                };
                for s in states.iter_mut() {
                    s.update(&buf[..n]);
                }
                size += n as u64;
                on_bytes(n as u64);
            }
            Ok(states.into_iter().map(State::hex).collect())
        })();
        FileHash {
            path,
            display,
            size,
            digests,
        }
    };
    if threads <= 1 || files.len() <= 1 {
        files.into_iter().map(work).collect()
    } else {
        match rayon::ThreadPoolBuilder::new().num_threads(threads).build() {
            Ok(pool) => pool.install(|| files.into_par_iter().map(work).collect()),
            Err(_) => files.into_iter().map(work).collect(),
        }
    }
}
