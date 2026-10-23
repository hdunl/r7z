//! RAR encryption: key derivation and CBC decryption.
//!
//! RAR 3 (AES-128) derives its key and IV from the password and an 8-byte salt by hashing
//! the password, the salt and a round counter 262144 times with SHA-1. RAR 5 (AES-256)
//! uses PBKDF2-HMAC-SHA256 with `2^lg2` rounds; three values come from that: the key, a
//! hash key, and a password check value.

use aes::cipher::consts::U16;
use aes::cipher::{Array, BlockCipherDecrypt, KeyInit};
use aes::{Aes128, Aes256};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::error::{Error, Result};

type Block = Array<u8, U16>;

/// CBC decryption of a stream in whole 16-byte blocks. The IV is the previous ciphertext
/// block, so one `Cbc` decrypts consecutive chunks of the same stream.
#[derive(Clone)]
pub enum Cbc {
    Aes128(Box<Aes128>, [u8; 16]),
    Aes256(Box<Aes256>, [u8; 16]),
}

impl Cbc {
    pub fn aes128(key: &[u8; 16], iv: [u8; 16]) -> Cbc {
        Cbc::Aes128(Box::new(Aes128::new(&Array::from(*key))), iv)
    }

    pub fn aes256(key: &[u8; 32], iv: [u8; 16]) -> Cbc {
        Cbc::Aes256(Box::new(Aes256::new(&Array::from(*key))), iv)
    }

    /// Decrypts `data` in place; its length must be a multiple of 16.
    pub fn decrypt(&mut self, data: &mut [u8]) {
        let (blocks, _) = Block::slice_as_chunks_mut(data);
        if blocks.is_empty() {
            return;
        }
        let mut cipher_text: Vec<[u8; 16]> = blocks.iter().map(|b| (*b).into()).collect();
        match self {
            Cbc::Aes128(c, iv) => {
                c.decrypt_blocks(blocks);
                chain(blocks, iv, &mut cipher_text);
            }
            Cbc::Aes256(c, iv) => {
                c.decrypt_blocks(blocks);
                chain(blocks, iv, &mut cipher_text);
            }
        }
    }
}

/// XORs each decrypted block with the ciphertext block before it.
fn chain(blocks: &mut [Block], iv: &mut [u8; 16], cipher_text: &mut [[u8; 16]]) {
    let mut prev = *iv;
    for (blk, ct) in blocks.iter_mut().zip(cipher_text.iter()) {
        for (b, p) in blk.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev = *ct;
    }
    *iv = prev;
}

/// RAR 3 key and IV for `password` (UTF-16LE encoded, as RAR hashes it) and `salt`.
pub fn rar3_key(password: &str, salt: &[u8; 8]) -> ([u8; 16], [u8; 16]) {
    let mut raw = Vec::with_capacity(password.len() * 2 + 8);
    for u in password.encode_utf16() {
        raw.extend_from_slice(&u.to_le_bytes());
    }
    raw.extend_from_slice(salt);
    let mut h = Sha1::new();
    // One IV byte every 0x4000 rounds. The key and IV are built from the hash directly
    // rather than filled into zeroed arrays.
    let mut iv = Vec::with_capacity(16);
    for i in 0u32..0x4_0000 {
        h.update(&raw);
        h.update([i as u8, (i >> 8) as u8, (i >> 16) as u8]);
        if i % 0x4000 == 0 {
            iv.push(h.clone().finalize()[19]);
        }
    }
    let d = h.finalize();
    // The first 16 digest bytes, each 4-byte word reversed.
    let key: [u8; 16] = std::array::from_fn(|k| d[4 * (k / 4) + 3 - k % 4]);
    let iv: [u8; 16] = iv.try_into().expect("16 rounds of 0x4000 give 16 IV bytes");
    (key, iv)
}

/// The values a RAR 5 password yields for one salt and iteration count.
pub struct Rar5Keys {
    pub key: [u8; 32],
    pub hash_key: [u8; 32],
    /// The 8-byte check value folded from the password's third derivation.
    pub check: [u8; 8],
}

/// PBKDF2-HMAC-SHA256 derivations for RAR 5 (UTF-8 password): the key with `2^lg2`
/// rounds, the hash key with 16 more, and the password check value with 32 more. The three
/// are points of one PBKDF2 chain, so it is computed once.
pub fn rar5_keys(password: &str, salt: &[u8; 16], lg2: u8) -> Result<Rar5Keys> {
    if lg2 > 24 {
        return Err(Error::unsupported("RAR 5 key derivation count"));
    }
    let rounds = 1u32 << lg2;
    let prf = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(password.as_bytes())
        .map_err(|_| Error::unsupported("RAR 5 password"))?;
    let mut u: [u8; 32] = prf
        .clone()
        .chain_update(salt)
        .chain_update(1u32.to_be_bytes())
        .finalize()
        .into_bytes()
        .into();
    let mut acc = u;
    // Taken from the chain as it passes them; `rounds` is at least 1, so both are set.
    let (mut key, mut hash_key) = (None, None);
    for i in 1..=rounds + 32 {
        if i > 1 {
            u = prf.clone().chain_update(u).finalize().into_bytes().into();
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        if i == rounds {
            key = Some(acc);
        } else if i == rounds + 16 {
            hash_key = Some(acc);
        }
    }
    let key = key.expect("the chain passes `rounds`");
    let hash_key = hash_key.expect("the chain passes `rounds + 16`");
    // The last value folded to 8 bytes: byte k is the XOR of bytes k, k+8, k+16 and k+24.
    let check: [u8; 8] =
        std::array::from_fn(|k| acc.iter().skip(k).step_by(8).fold(0, |c, b| c ^ b));
    Ok(Rar5Keys {
        key,
        hash_key,
        check,
    })
}

/// RAR 5 checksum of an encrypted file whose crypt record has the MAC flag: the stored
/// CRC32 is HMAC-SHA256 of the plain CRC (little endian) under the hash key, folded to 32
/// bits.
pub fn rar5_mac_crc(hash_key: &[u8; 32], crc: u32) -> u32 {
    let d = rar5_mac(hash_key, &crc.to_le_bytes());
    d.iter()
        .enumerate()
        .fold(0u32, |v, (i, &b)| v ^ (u32::from(b) << ((i & 3) * 8)))
}

/// The MAC form of a RAR 5 BLAKE2sp digest: HMAC-SHA256 of the plain digest.
pub fn rar5_mac_digest(hash_key: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    rar5_mac(hash_key, digest)
}

fn rar5_mac(hash_key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(hash_key)
        .expect("HMAC takes any key length")
        .chain_update(data)
        .finalize()
        .into_bytes()
        .into()
}
