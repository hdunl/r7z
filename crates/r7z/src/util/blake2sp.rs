//! BLAKE2sp: eight BLAKE2s leaves fed round-robin with 64-byte blocks, and a BLAKE2s root
//! over their 32-byte digests. RAR 5 stores this digest for each file.

const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

const LEAVES: usize = 8;

#[inline(always)]
fn mix(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// One BLAKE2s compression of a 64-byte block into the chaining value `h`. `t` counts the
/// bytes hashed so far in this node, including this block.
fn compress(h: &mut [u32; 8], block: &[u8; 64], t: u64, last: bool, last_node: bool) {
    let mut m = [0u32; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;
    if last {
        v[14] = !v[14];
    }
    if last_node {
        v[15] = !v[15];
    }
    for s in &SIGMA {
        mix(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        mix(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        mix(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        mix(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        mix(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        mix(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        mix(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        mix(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// The chaining value of a node with the BLAKE2sp parameter block: digest length 32,
/// fanout 8, depth 2, the given node offset and node depth, inner length 32.
fn start(offset: u32, node_depth: u8) -> [u32; 8] {
    let mut h = IV;
    h[0] ^= 32 | (8 << 16) | (2 << 24);
    h[2] ^= offset;
    h[3] ^= (node_depth as u32) << 16 | (32 << 24);
    h
}

fn digest_bytes(h: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, w) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// A leaf BLAKE2s node. It holds back its most recent block, since that block is the last
/// one only if no more input for this leaf follows.
#[derive(Clone)]
struct Leaf {
    h: [u32; 8],
    /// Bytes compressed so far, not counting the held block.
    t: u64,
    held: [u8; 64],
    held_len: usize,
}

impl Leaf {
    fn new(index: u32) -> Self {
        Leaf {
            h: start(index, 0),
            t: 0,
            held: [0; 64],
            held_len: 0,
        }
    }

    /// Adds the next block of this leaf. A full block is always followed by more input for
    /// the leaf, so the held one is not the last and gets compressed now.
    fn push(&mut self, block: &[u8], len: usize) {
        if self.held_len == 64 {
            self.t += 64;
            let held = self.held;
            compress(&mut self.h, &held, self.t, false, false);
        }
        self.held = [0; 64];
        self.held[..len].copy_from_slice(&block[..len]);
        self.held_len = len;
    }

    fn finish(mut self, last_node: bool) -> [u8; 32] {
        self.t += self.held_len as u64;
        let held = self.held;
        compress(&mut self.h, &held, self.t, true, last_node);
        digest_bytes(&self.h)
    }
}

/// Incremental BLAKE2sp hasher.
#[derive(Clone)]
pub struct Blake2sp {
    leaves: [Leaf; LEAVES],
    pending: [u8; 64],
    plen: usize,
    /// Full blocks dispatched so far; block `k` goes to leaf `k % 8`.
    blocks: usize,
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sp {
    pub fn new() -> Self {
        Blake2sp {
            leaves: std::array::from_fn(|i| Leaf::new(i as u32)),
            pending: [0; 64],
            plen: 0,
            blocks: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (64 - self.plen).min(data.len());
            self.pending[self.plen..self.plen + take].copy_from_slice(&data[..take]);
            self.plen += take;
            data = &data[take..];
            if self.plen == 64 {
                let block = self.pending;
                self.leaves[self.blocks % LEAVES].push(&block, 64);
                self.blocks += 1;
                self.plen = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 32] {
        // The partial tail is the final block of its leaf. Input that ends exactly on a
        // block boundary has no tail: its last full block is already held by its leaf.
        if self.plen > 0 || self.blocks == 0 {
            let pending = self.pending;
            let len = self.plen;
            self.leaves[self.blocks % LEAVES].push(&pending, len);
        }
        let mut root = start(0, 1);
        let mut digests = [0u8; 8 * 32];
        for (i, leaf) in self.leaves.into_iter().enumerate() {
            digests[32 * i..32 * i + 32].copy_from_slice(&leaf.finish(i == LEAVES - 1));
        }
        // The root hashes 256 bytes: four blocks, the last one final and last-node.
        for (k, block) in digests.as_chunks::<64>().0.iter().enumerate() {
            let t = 64 * (k as u64 + 1);
            compress(&mut root, block, t, k == 3, k == 3);
        }
        digest_bytes(&root)
    }
}

/// Digest of `data` in one call.
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2sp::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8]) -> String {
        d.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn empty_input_matches_reference() {
        assert_eq!(
            hex(&digest(b"")),
            "dd0e891776933f43c7d032b08a917e25741f8aa9a12c12e1cac8801500f2ca4f"
        );
    }

    #[test]
    fn chunked_updates_match_one_shot() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i * 31 % 251) as u8).collect();
        for step in [1, 7, 63, 64, 65, 200] {
            let mut h = Blake2sp::new();
            for c in data.chunks(step) {
                h.update(c);
            }
            assert_eq!(h.finalize(), digest(&data), "step {step}");
        }
        // Boundary cases: exact multiples of the block size.
        for n in [63, 64, 128, 512, 513] {
            let mut h = Blake2sp::new();
            h.update(&data[..n]);
            assert_eq!(h.finalize(), digest(&data[..n]));
        }
    }
}
