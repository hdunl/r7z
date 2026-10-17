//! What the main list shows. Disk folders and archive folders produce the same `Row`, so
//! sorting, filtering, selection and preview work the same in both.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use r7z::format::Entry;

use crate::icons::{classify, FileClass};

pub const ROOT: usize = 0;

pub struct Node {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    /// The archive entry this node shows; synthesized folders have none.
    pub entry: Option<usize>,
    pub size: u64,
    pub packed: u64,
    pub mtime: Option<u64>,
    pub encrypted: bool,
    pub parent: usize,
    pub children: Vec<usize>,
    /// Files at or below this node.
    pub files: u64,
}

/// A folder tree over an archive's flat entry list. Formats store paths, so intermediate
/// folders are synthesized and sizes are summed bottom-up.
pub struct Tree {
    pub nodes: Vec<Node>,
}

impl Tree {
    pub fn build(entries: &[Entry], root_name: &str) -> Tree {
        let mut nodes = vec![Node {
            name: root_name.to_string(),
            path: String::new(),
            is_dir: true,
            entry: None,
            size: 0,
            packed: 0,
            mtime: None,
            encrypted: false,
            parent: ROOT,
            children: Vec::new(),
            files: 0,
        }];
        let mut dirs: HashMap<String, usize> = HashMap::new();
        for (i, e) in entries.iter().enumerate() {
            if e.is_anti {
                continue;
            }
            let norm = e.name.replace('\\', "/");
            let mut parts: Vec<&str> = norm
                .split('/')
                .filter(|p| !p.is_empty() && *p != "." && *p != "..")
                .collect();
            if parts.is_empty() {
                if e.is_dir {
                    continue;
                }
                parts.push("(unnamed)");
            }
            let mut parent = ROOT;
            let mut path = String::new();
            for (k, part) in parts.iter().enumerate() {
                if !path.is_empty() {
                    path.push('/');
                }
                path.push_str(part);
                let last = k + 1 == parts.len();
                if last && !e.is_dir {
                    let idx = nodes.len();
                    nodes.push(Node {
                        name: part.to_string(),
                        path: path.clone(),
                        is_dir: false,
                        entry: Some(i),
                        size: e.size_or_zero(),
                        packed: e.packed_size.unwrap_or(0),
                        mtime: e.mtime,
                        encrypted: e.encrypted,
                        parent,
                        children: Vec::new(),
                        files: 1,
                    });
                    nodes[parent].children.push(idx);
                    break;
                }
                let key = path.to_lowercase();
                let idx = match dirs.get(&key) {
                    Some(&d) => d,
                    None => {
                        let idx = nodes.len();
                        nodes.push(Node {
                            name: part.to_string(),
                            path: path.clone(),
                            is_dir: true,
                            entry: None,
                            size: 0,
                            packed: 0,
                            mtime: None,
                            encrypted: false,
                            parent,
                            children: Vec::new(),
                            files: 0,
                        });
                        nodes[parent].children.push(idx);
                        dirs.insert(key, idx);
                        idx
                    }
                };
                if last {
                    nodes[idx].entry = Some(i);
                    nodes[idx].mtime = e.mtime;
                }
                parent = idx;
            }
        }
        // Children always come after their parents, so one reverse pass sums the totals.
        for i in (1..nodes.len()).rev() {
            let (size, packed, files, enc, p) = {
                let n = &nodes[i];
                (n.size, n.packed, n.files, n.encrypted, n.parent)
            };
            let parent = &mut nodes[p];
            parent.size += size;
            parent.packed += packed;
            parent.files += files;
            parent.encrypted |= enc;
        }
        Tree { nodes }
    }

    /// Entry indices at or below `node`.
    pub fn collect_entries(&self, node: usize, out: &mut Vec<usize>) {
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let n = &self.nodes[n];
            if let Some(e) = n.entry {
                out.push(e);
            }
            stack.extend(n.children.iter().copied());
        }
    }

    /// Nodes from the root down to `node`.
    pub fn ancestry(&self, mut node: usize) -> Vec<usize> {
        let mut v = vec![node];
        while node != ROOT {
            node = self.nodes[node].parent;
            v.push(node);
        }
        v.reverse();
        v
    }

    pub fn dir_count(&self) -> usize {
        self.nodes.iter().skip(1).filter(|n| n.is_dir).count()
    }

    /// Bytes per file class at or below `node`.
    pub fn class_sizes(&self, node: usize) -> Vec<(FileClass, u64, u64)> {
        let mut by: HashMap<FileClass, (u64, u64)> = HashMap::new();
        let mut stack = vec![node];
        while let Some(n) = stack.pop() {
            let nd = &self.nodes[n];
            if !nd.is_dir {
                let e = by.entry(classify(&nd.name)).or_default();
                e.0 += nd.size;
                e.1 += 1;
            }
            stack.extend(nd.children.iter().copied());
        }
        let mut v: Vec<(FileClass, u64, u64)> =
            by.into_iter().map(|(c, (s, n))| (c, s, n)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1));
        v
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    Disk(PathBuf),
    Node(usize),
}

#[derive(Clone, Debug)]
pub struct Row {
    pub name: String,
    /// Shown instead of the name in search results.
    pub detail: Option<String>,
    pub is_dir: bool,
    pub size: Option<u64>,
    pub packed: Option<u64>,
    pub mtime: Option<u64>,
    pub encrypted: bool,
    pub class: FileClass,
    pub hidden: bool,
    /// Hidden and system both set (FOUND.000, System Volume Information).
    pub protected: bool,
    pub target: Target,
}

impl Row {
    pub fn is_archive(&self) -> bool {
        !self.is_dir && self.class == FileClass::Archive
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SortCol {
    Name,
    Modified,
    Kind,
    Size,
    Packed,
}

pub fn sort_rows(rows: &mut [Row], col: SortCol, asc: bool) {
    rows.sort_by(|x, y| {
        let dirs = y.is_dir.cmp(&x.is_dir);
        let ord = match col {
            SortCol::Name => natural_cmp(&x.name, &y.name),
            SortCol::Modified => x.mtime.cmp(&y.mtime),
            SortCol::Kind => {
                crate::icons::extension(&x.name).cmp(&crate::icons::extension(&y.name))
            }
            SortCol::Size => x.size.cmp(&y.size),
            SortCol::Packed => x.packed.cmp(&y.packed),
        };
        let ord = ord.then_with(|| natural_cmp(&x.name, &y.name));
        dirs.then(if asc { ord } else { ord.reverse() })
    });
}

/// Case-insensitive comparison that orders digit runs by value ("file2" before "file10").
pub fn natural_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let (mut ai, mut bi) = (a.chars().peekable(), b.chars().peekable());
    loop {
        match (ai.peek().copied(), bi.peek().copied()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) if x.is_ascii_digit() && y.is_ascii_digit() => {
                let mut na = String::new();
                while let Some(c) = ai.peek().copied().filter(char::is_ascii_digit) {
                    na.push(c);
                    ai.next();
                }
                let mut nb = String::new();
                while let Some(c) = bi.peek().copied().filter(char::is_ascii_digit) {
                    nb.push(c);
                    bi.next();
                }
                let ta = na.trim_start_matches('0');
                let tb = nb.trim_start_matches('0');
                let o = ta.len().cmp(&tb.len()).then_with(|| ta.cmp(tb));
                if o != Ordering::Equal {
                    return o;
                }
            }
            (Some(x), Some(y)) => {
                let o = x.to_lowercase().cmp(y.to_lowercase());
                if o != Ordering::Equal {
                    return o;
                }
                ai.next();
                bi.next();
            }
        }
    }
}

#[cfg(windows)]
fn is_hidden(m: &std::fs::Metadata, name: &str) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x6 != 0 || name.starts_with('$')
}

#[cfg(not(windows))]
fn is_hidden(_m: &std::fs::Metadata, name: &str) -> bool {
    name.starts_with('.')
}

/// Hidden system entries (chkdsk's FOUND.000, System Volume Information). Explorer never
/// hides these unless protected files are shown too.
#[cfg(windows)]
fn is_protected(m: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    m.file_attributes() & 0x6 == 0x6
}

#[cfg(not(windows))]
fn is_protected(_m: &std::fs::Metadata) -> bool {
    false
}

/// Lists a disk folder. Unreadable entries are left out.
pub fn list_dir(dir: &Path) -> std::io::Result<Vec<Row>> {
    let mut rows = Vec::new();
    for ent in std::fs::read_dir(dir)? {
        let Ok(ent) = ent else { continue };
        let name = ent.file_name().to_string_lossy().into_owned();
        let Ok(meta) = ent.metadata() else { continue };
        let is_dir = meta.is_dir();
        rows.push(Row {
            class: if is_dir {
                FileClass::Other
            } else {
                classify(&name)
            },
            hidden: is_hidden(&meta, &name),
            protected: is_protected(&meta),
            size: if is_dir { None } else { Some(meta.len()) },
            packed: None,
            mtime: meta.modified().ok().map(r7z::util::time::to_filetime),
            encrypted: false,
            detail: None,
            is_dir,
            target: Target::Disk(ent.path()),
            name,
        });
    }
    Ok(rows)
}

pub fn node_row(t: &Tree, n: usize, with_path: bool) -> Row {
    let nd = &t.nodes[n];
    Row {
        name: nd.name.clone(),
        detail: if with_path {
            Some(nd.path.clone())
        } else {
            None
        },
        is_dir: nd.is_dir,
        size: Some(nd.size),
        packed: if nd.packed > 0 { Some(nd.packed) } else { None },
        mtime: nd.mtime,
        encrypted: nd.encrypted,
        class: if nd.is_dir {
            FileClass::Other
        } else {
            classify(&nd.name)
        },
        hidden: false,
        protected: false,
        target: Target::Node(n),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, dir: bool, size: u64) -> Entry {
        Entry {
            name: name.into(),
            is_dir: dir,
            size: Some(size),
            ..Default::default()
        }
    }

    #[test]
    fn synthesizes_folders_and_aggregates() {
        let entries = vec![
            entry("a/b/c.txt", false, 10),
            entry("a/d.txt", false, 5),
            entry("a", true, 0),
            entry("top.bin", false, 1),
        ];
        let t = Tree::build(&entries, "x.zip");
        let root = &t.nodes[ROOT];
        assert_eq!(root.size, 16);
        assert_eq!(root.files, 3);
        let a = root
            .children
            .iter()
            .copied()
            .find(|&c| t.nodes[c].name == "a")
            .unwrap();
        assert_eq!(t.nodes[a].entry, Some(2));
        assert_eq!(t.nodes[a].size, 15);
        let mut v = Vec::new();
        t.collect_entries(a, &mut v);
        v.sort();
        assert_eq!(v, vec![0, 1, 2]);
    }

    #[test]
    fn natural_order() {
        let mut v = vec!["file10", "File2", "file1", "a"];
        v.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(v, vec!["a", "file1", "File2", "file10"]);
    }

    #[test]
    fn hostile_names_stay_inside_the_tree() {
        let entries = vec![
            entry("../../x.txt", false, 1),
            entry("/abs/y", false, 1),
            entry("", false, 1),
        ];
        let t = Tree::build(&entries, "x");
        assert_eq!(t.nodes[ROOT].files, 3);
    }
}
