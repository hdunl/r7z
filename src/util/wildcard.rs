//! 7-Zip-style wildcard matching: `*` and `?`, case-insensitive on Windows.
//! Paths are compared with `/` separators.

#[derive(Debug, Clone)]
pub struct Pattern {
    chars: Vec<char>,
    /// True when the pattern contains a separator and must match the full path.
    has_dir: bool,
}

impl Pattern {
    pub fn new(p: &str) -> Self {
        let norm: String = p.replace('\\', "/");
        let norm = norm.trim_start_matches("./").to_string();
        let chars: Vec<char> = fold(&norm).chars().collect();
        let has_dir = chars.contains(&'/');
        Pattern { chars, has_dir }
    }

    pub fn is_wild(s: &str) -> bool {
        s.contains('*') || s.contains('?')
    }

    /// Matches an archive path. Patterns without a separator match the file name of any
    /// component sequence end (like `*.txt` matching `a/b/c.txt`), patterns with one match
    /// the full path or a leading directory prefix of it.
    pub fn matches_path(&self, path: &str) -> bool {
        let path = fold(&path.replace('\\', "/"));
        let pc: Vec<char> = path.chars().collect();
        if self.has_dir {
            if wild_match(&self.chars, &pc) {
                return true;
            }
            // `dir/sub` also selects everything below it.
            for (i, &c) in pc.iter().enumerate() {
                if c == '/' && wild_match(&self.chars, &pc[..i]) {
                    return true;
                }
            }
            false
        } else {
            // Match any single component (so `docs` selects `docs/...`, `*.txt` selects files).
            pc.split(|&c| c == '/')
                .any(|comp| wild_match(&self.chars, comp))
        }
    }

    /// Matches only the last component of a path.
    pub fn matches_name(&self, name: &str) -> bool {
        let n: Vec<char> = fold(name).chars().collect();
        wild_match(&self.chars, &n)
    }
}

fn fold(s: &str) -> String {
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

/// Iterative glob match with backtracking on the last `*`.
pub fn wild_match(p: &[char], s: &[char]) -> bool {
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while si < s.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == s[si]) {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi;
            mark = si;
            pi += 1;
        } else if star != usize::MAX {
            pi = star + 1;
            mark += 1;
            si = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basics() {
        assert!(Pattern::new("*.txt").matches_path("a/b/c.txt"));
        assert!(!Pattern::new("*.txt").matches_path("a/b/c.txt.bak"));
        assert!(Pattern::new("docs").matches_path("docs/readme.md"));
        assert!(Pattern::new("a/b").matches_path("a/b/c.txt"));
        assert!(!Pattern::new("a/b").matches_path("a/bc/c.txt"));
        assert!(Pattern::new("f?le*").matches_name("file123"));
    }
}
