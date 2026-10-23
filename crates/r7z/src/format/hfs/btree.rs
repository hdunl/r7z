//! HFS+ B-trees: the header node and node map, the leaf walk that lists catalog and attribute
//! records, and the exact-key search the extents overflow tree needs. Nodes are read one at a
//! time into a reusable buffer.

use std::cmp::Ordering;

use super::be::Be;
use super::volume::Fork;
use crate::error::{Error, Result};
use crate::format::ReadAt;

const LEAF: i8 = -1;
const INDEX: i8 = 0;
const HEADER: i8 = 1;
const MAP: i8 = 2;
/// Bytes before the first record of a node.
const DESCRIPTOR: usize = 14;
/// Node sizes accepted (powers of two).
const MIN_NODE: usize = 512;
const MAX_NODE: usize = 65536;
/// Deepest root-to-leaf path a search follows.
const MAX_DEPTH: usize = 64;

/// A node's descriptor.
struct Desc {
    f_link: u32,
    kind: i8,
    count: usize,
}

fn desc(node: &[u8]) -> Result<Desc> {
    let mut r = Be::at(node, 0);
    let f_link = r.u32()?;
    r.skip(4)?; // backward link
    let kind = r.u8()? as i8;
    r.skip(1)?; // height
    let count = usize::from(r.u16()?);
    if DESCRIPTOR + 2 * (count + 1) > node.len() {
        return Err(Error::corrupt("HFS+ B-tree node claims too many records"));
    }
    Ok(Desc {
        f_link,
        kind,
        count,
    })
}

/// Record `i` of a node: its offset in the node, and its bytes up to the offset table.
fn record(node: &[u8], count: usize, i: usize) -> Result<(usize, &[u8])> {
    if i >= count {
        return Err(Error::corrupt("HFS+ B-tree record index is out of range"));
    }
    let table = node.len() - 2 * (count + 1);
    let start = usize::from(Be::at(node, node.len() - 2 * (i + 1)).u16()?);
    if start < DESCRIPTOR || start > table {
        return Err(Error::corrupt("HFS+ B-tree record offset is out of range"));
    }
    Ok((start, &node[start..table]))
}

/// Splits a record into its key (including the two-byte length) and its data. Keys are
/// padded to an even length.
pub fn split_key(rec: &[u8]) -> Result<(&[u8], &[u8])> {
    let key_end = 2 + usize::from(Be::at(rec, 0).u16()?);
    let data = key_end + key_end % 2;
    if data > rec.len() {
        return Err(Error::corrupt("HFS+ B-tree key runs past its record"));
    }
    Ok((&rec[..key_end], &rec[data..]))
}

/// A leaf record, with its byte offset in the tree's fork.
pub struct Rec<'a> {
    pub at: u64,
    pub bytes: &'a [u8],
}

/// A B-tree whose nodes are read from its fork.
pub struct BTree {
    fork: Fork,
    node_size: usize,
    total_nodes: u32,
    root: u32,
    first_leaf: u32,
    /// Allocation bits, one per node, most significant bit first.
    bitmap: Vec<u8>,
}

impl BTree {
    /// Reads the header node and the node map.
    pub fn open(src: &dyn ReadAt, fork: Fork) -> Result<BTree> {
        // The node size is in the header record, so it is read before the node.
        let mut start = [0u8; DESCRIPTOR + 20];
        fork.read_at(src, 0, &mut start)?;
        let node_size = usize::from(Be::at(&start, DESCRIPTOR + 18).u16()?);
        if !node_size.is_power_of_two() || !(MIN_NODE..=MAX_NODE).contains(&node_size) {
            return Err(Error::corrupt(format!(
                "HFS+ B-tree node size {node_size} is not valid"
            )));
        }
        let mut node = vec![0u8; node_size];
        fork.read_at(src, 0, &mut node)?;
        let head = desc(&node)?;
        if head.kind != HEADER || head.count < 3 {
            return Err(Error::corrupt("HFS+ B-tree header node is malformed"));
        }
        let (_, rec) = record(&node, head.count, 0)?;
        let mut h = Be::at(rec, 0);
        h.skip(2)?; // depth
        let root = h.u32()?;
        h.skip(4)?; // leaf record count
        let first_leaf = h.u32()?;
        h.skip(4)?; // last leaf
        if usize::from(h.u16()?) != node_size {
            return Err(Error::corrupt(
                "HFS+ B-tree header disagrees with its node size",
            ));
        }
        h.skip(2)?; // maximum key length
        let total_nodes = h.u32()?;
        if total_nodes == 0 || u64::from(total_nodes) * node_size as u64 > fork.size() {
            return Err(Error::corrupt(
                "HFS+ B-tree claims more nodes than its fork holds",
            ));
        }
        if root >= total_nodes || first_leaf >= total_nodes {
            return Err(Error::corrupt("HFS+ B-tree root or first leaf is out of range"));
        }

        // The header's map record covers the first nodes; map nodes continue it.
        let (_, map) = record(&node, head.count, 2)?;
        let mut bitmap = map.to_vec();
        let mut link = head.f_link;
        let mut maps_left = fork.size() / node_size as u64;
        while (bitmap.len() as u64) * 8 < u64::from(total_nodes) && link != 0 {
            maps_left = maps_left
                .checked_sub(1)
                .ok_or_else(|| Error::corrupt("HFS+ B-tree node map is cyclic"))?;
            if link >= total_nodes {
                return Err(Error::corrupt("HFS+ B-tree map node is out of range"));
            }
            fork.read_at(src, u64::from(link) * node_size as u64, &mut node)?;
            let m = desc(&node)?;
            if m.kind != MAP {
                return Err(Error::corrupt("HFS+ B-tree node map chain reaches a non-map node"));
            }
            bitmap.extend_from_slice(record(&node, m.count, 0)?.1);
            link = m.f_link;
        }
        if (bitmap.len() as u64) * 8 < u64::from(total_nodes) {
            return Err(Error::corrupt("HFS+ B-tree node map is too short"));
        }
        Ok(BTree {
            fork,
            node_size,
            total_nodes,
            root,
            first_leaf,
            bitmap,
        })
    }

    /// Reads `buf.len()` bytes of the tree's fork from `pos`.
    pub fn read_at(&self, src: &dyn ReadAt, pos: u64, buf: &mut [u8]) -> Result<()> {
        self.fork.read_at(src, pos, buf)
    }

    /// Calls `f` with every leaf record in key order, following the forward links.
    pub fn for_each_record(
        &self,
        src: &dyn ReadAt,
        mut f: impl FnMut(Rec<'_>) -> Result<()>,
    ) -> Result<()> {
        let mut buf = Vec::new();
        let mut n = self.first_leaf;
        let mut visited = 0u64;
        while n != 0 {
            visited += 1;
            if visited > u64::from(self.total_nodes) {
                return Err(Error::corrupt("HFS+ B-tree leaf chain loops"));
            }
            let d = self.read_node(src, n, &mut buf)?;
            if d.kind != LEAF {
                return Err(Error::corrupt(
                    "HFS+ B-tree leaf chain reaches a node that is not a leaf",
                ));
            }
            for i in 0..d.count {
                let (start, bytes) = record(&buf, d.count, i)?;
                let at = u64::from(n) * self.node_size as u64 + start as u64;
                f(Rec { at, bytes })?;
            }
            n = d.f_link;
        }
        Ok(())
    }

    /// The data of the record whose key equals `want`, found by searching from the root.
    /// `key_of` reads a key (with its length) as an ordered value.
    pub fn find<K: Ord>(
        &self,
        src: &dyn ReadAt,
        key_of: impl Fn(&[u8]) -> Result<K>,
        want: &K,
    ) -> Result<Option<Vec<u8>>> {
        if self.root == 0 {
            return Ok(None);
        }
        let mut buf = Vec::new();
        let mut n = self.root;
        for _ in 0..MAX_DEPTH {
            let d = self.read_node(src, n, &mut buf)?;
            if d.kind == LEAF {
                for i in 0..d.count {
                    let (_, rec) = record(&buf, d.count, i)?;
                    let (key, data) = split_key(rec)?;
                    match key_of(key)?.cmp(want) {
                        Ordering::Less => {}
                        Ordering::Equal => return Ok(Some(data.to_vec())),
                        Ordering::Greater => break,
                    }
                }
                return Ok(None);
            }
            if d.kind != INDEX {
                return Err(Error::corrupt(
                    "HFS+ B-tree search reached a node that is neither index nor leaf",
                ));
            }
            // An index record names the child whose keys start at its key.
            let mut child = None;
            for i in 0..d.count {
                let (_, rec) = record(&buf, d.count, i)?;
                let (key, data) = split_key(rec)?;
                if key_of(key)?.cmp(want) == Ordering::Greater {
                    break;
                }
                child = Some(Be::at(data, 0).u32()?);
            }
            n = child.ok_or_else(|| {
                Error::corrupt("HFS+ B-tree index has no key at or before the search key")
            })?;
        }
        Err(Error::corrupt("HFS+ B-tree is deeper than its search allows"))
    }

    /// Reads node `n` into `buf` and parses its descriptor. Only nodes marked in use are read.
    fn read_node(&self, src: &dyn ReadAt, n: u32, buf: &mut Vec<u8>) -> Result<Desc> {
        if n >= self.total_nodes || !self.allocated(n) {
            return Err(Error::corrupt(format!("HFS+ B-tree node {n} is not in use")));
        }
        buf.resize(self.node_size, 0);
        self.fork
            .read_at(src, u64::from(n) * self.node_size as u64, buf)?;
        desc(buf)
    }

    fn allocated(&self, n: u32) -> bool {
        self.bitmap
            .get(n as usize / 8)
            .is_some_and(|b| b & (0x80 >> (n % 8)) != 0)
    }
}
