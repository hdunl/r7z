//! 7-Zip-compatible command line: `r7z <command> [<switches>...] <archive> [<files>...]`.
//! Switches may appear anywhere until `--`. Values are glued (`-oout`, `-mx9`, `-psecret`).

use std::path::PathBuf;

use r7z::codec::Branch;
use r7z::error::{Error, Result};
use r7z::format::CodePage;
use r7z::ops::create::{FilterMode, MainMethod};
use r7z::ops::extract::Overwrite;
use r7z::ops::hash::HashKind;
use r7z::util::fmt::parse_size;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    /// `a`: add, replacing entries of the same name.
    Add,
    /// `u`: add, replacing only entries the new files are newer than.
    Update,
    /// `d`: delete the entries named.
    Delete,
    /// `rn`: rename entries, given as `old new` pairs.
    Rename,
    Extract {
        full_paths: bool,
    },
    List,
    Test,
    Hash,
    Bench,
    Info,
    Help,
    Version,
}

#[derive(Debug, Default, Clone)]
pub struct MethodSpec {
    pub main: Option<MainMethod>,
    pub filter: Option<FilterMode>,
    pub dict: Option<u32>,
    pub fast_bytes: Option<u32>,
    pub block: Option<u64>,
    /// A method name only zip uses (`deflate`, `zstd`, `store` given as `-mm=`).
    pub other: Option<String>,
}

#[derive(Debug)]
pub struct Args {
    pub command: Command,
    pub archive: Option<PathBuf>,
    pub names: Vec<String>,
    pub output_dir: Option<PathBuf>,
    /// `Some(None)` means `-p` without a value: prompt.
    pub password: Option<Option<String>>,
    pub yes: bool,
    pub overwrite: Option<Overwrite>,
    pub recurse: Option<bool>,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub level: Option<u32>,
    pub threads: Option<usize>,
    pub method: MethodSpec,
    pub encrypt_header: Option<bool>,
    pub compress_header: Option<bool>,
    /// `Some(None)` = non-solid.
    pub solid: Option<Option<u64>>,
    pub mtime: Option<bool>,
    pub ctime: Option<bool>,
    pub atime: Option<bool>,
    pub technical: bool,
    pub hashes: Vec<HashKind>,
    pub no_progress: bool,
    pub stdout: bool,
    pub timing: bool,
    pub bench_iterations: Option<u32>,
    /// `-t{type}`.
    pub archive_type: Option<String>,
    /// `-mem=`: `Some(true)` AES-256, `Some(false)` ZipCrypto.
    pub zip_crypto: Option<bool>,
    /// `-mcp=`: code page for names an archive does not mark as Unicode.
    pub code_page: Option<CodePage>,
    /// `-recover`: salvage what is readable from a damaged archive (`x`, `e`, `t`).
    pub recover: bool,
}

fn parse_bool(v: &str, sw: &str) -> Result<bool> {
    match v.to_ascii_lowercase().as_str() {
        "" | "on" | "+" | "1" | "true" => Ok(true),
        "off" | "-" | "0" | "false" => Ok(false),
        _ => Err(Error::usage(format!(
            "bad value for {sw}: '{v}' (use on/off)"
        ))),
    }
}

/// 7-Zip dictionary syntax: a bare number is a power of two, otherwise a size with suffix.
fn parse_dict(v: &str) -> Result<u32> {
    let v = v.trim();
    let bytes = if v.chars().all(|c| c.is_ascii_digit()) {
        let p: u32 = v
            .parse()
            .map_err(|_| Error::usage(format!("bad dictionary size '{v}'")))?;
        if p > 31 {
            return Err(Error::usage(format!("dictionary 2^{p} is too large")));
        }
        1u64 << p
    } else {
        parse_size(v).ok_or_else(|| Error::usage(format!("bad dictionary size '{v}'")))?
    };
    if !(4096..=(3u64 << 29)).contains(&bytes) {
        return Err(Error::usage("dictionary must be between 4 KiB and 1.5 GiB"));
    }
    Ok(bytes as u32)
}

fn parse_filter(v: &str) -> Result<FilterMode> {
    let lower = v.to_ascii_lowercase();
    Ok(match lower.as_str() {
        "" | "on" | "+" => FilterMode::Auto,
        "off" | "-" => FilterMode::Off,
        "bcj" | "x86" => FilterMode::Bcj,
        "bcj2" => FilterMode::Bcj2,
        _ if Branch::from_name(&lower).is_some() => {
            FilterMode::Branch(Branch::from_name(&lower).unwrap())
        }
        _ if lower.starts_with("delta") => {
            let d = lower.trim_start_matches("delta").trim_start_matches(':');
            let d: u32 = if d.is_empty() {
                1
            } else {
                d.parse()
                    .map_err(|_| Error::usage(format!("bad delta distance '{d}'")))?
            };
            if !(1..=256).contains(&d) {
                return Err(Error::usage("delta distance must be 1..256"));
            }
            FilterMode::Delta(d)
        }
        _ => {
            return Err(Error::usage(format!(
                "unsupported filter '{v}' (supported: on, off, BCJ, BCJ2, ARM, ARMT, ARM64, PPC, SPARC, IA64, RISCV, Delta:N)"
            )))
        }
    })
}

/// `-m0=LZMA2:d=24:fb=64:c=64m`, `-m0=BCJ`, `-m1=LZMA`.
fn parse_method(v: &str, spec: &mut MethodSpec) -> Result<()> {
    let mut parts = v.split(':');
    let name = parts.next().unwrap_or("").to_ascii_lowercase();
    match name.as_str() {
        "lzma2" => spec.main = Some(MainMethod::Lzma2),
        "lzma" => spec.main = Some(MainMethod::Lzma),
        "copy" => spec.main = Some(MainMethod::Copy),
        "deflate" | "store" | "zstd" => spec.other = Some(name.clone()),
        "bcj" | "x86" => spec.filter = Some(FilterMode::Bcj),
        "bcj2" => spec.filter = Some(FilterMode::Bcj2),
        n if n.starts_with("delta") => spec.filter = Some(parse_filter(v)?),
        other => match Branch::from_name(other) {
            Some(b) => spec.filter = Some(FilterMode::Branch(b)),
            None => {
                return Err(Error::usage(format!(
                    "unsupported method '{other}' (r7z writes LZMA2, LZMA, Copy, BCJ, BCJ2, ARM, Delta; Deflate and zstd in zip)"
                )))
            }
        },
    }
    for p in parts {
        let (k, val) = p
            .split_once('=')
            .unwrap_or((&p[..1.min(p.len())], &p[1.min(p.len())..]));
        match k.to_ascii_lowercase().as_str() {
            "d" => spec.dict = Some(parse_dict(val)?),
            "fb" => {
                spec.fast_bytes = Some(
                    val.parse()
                        .map_err(|_| Error::usage(format!("bad fb '{val}'")))?,
                )
            }
            "c" => {
                spec.block = Some(
                    parse_size(val)
                        .ok_or_else(|| Error::usage(format!("bad block size '{val}'")))?,
                )
            }
            "mt" | "x" | "lc" | "lp" | "pb" | "mf" => {}
            other => return Err(Error::usage(format!("unknown method parameter '{other}'"))),
        }
    }
    Ok(())
}

fn parse_m(body: &str, a: &mut Args) -> Result<()> {
    let (key, val) = match body.split_once('=') {
        Some((k, v)) => (k.to_ascii_lowercase(), v.to_string()),
        None => {
            let lower = body.to_ascii_lowercase();
            let split = lower
                .find(|c: char| c.is_ascii_digit())
                .unwrap_or(lower.len());
            (lower[..split].to_string(), body[split..].to_string())
        }
    };
    match key.as_str() {
        "x" => {
            let l: u32 = if val.is_empty() {
                5
            } else {
                val.parse()
                    .map_err(|_| Error::usage(format!("bad level '{val}'")))?
            };
            if l > 9 {
                return Err(Error::usage("compression level must be 0..9"));
            }
            a.level = Some(l);
        }
        "mt" => {
            a.threads = Some(match val.to_ascii_lowercase().as_str() {
                "" | "on" | "+" => r7z::util::default_threads(),
                "off" | "-" => 1,
                n => n
                    .parse::<usize>()
                    .map_err(|_| Error::usage(format!("bad thread count '{n}'")))?
                    .max(1),
            })
        }
        "0" | "1" | "2" | "3" | "m" => parse_method(&val, &mut a.method)?,
        "em" => {
            a.zip_crypto = Some(match val.to_ascii_lowercase().as_str() {
                "aes256" | "aes-256" => true,
                "zipcrypto" => false,
                v => {
                    return Err(Error::usage(format!(
                        "unsupported zip encryption '{v}' (use AES256)"
                    )))
                }
            })
        }
        "cp" => {
            a.code_page = Some(CodePage::parse(&val).ok_or_else(|| {
                Error::usage(format!("unsupported code page '{val}' (e.g. -mcp=932)"))
            })?)
        }
        "cu" => {}
        "f" => a.method.filter = Some(parse_filter(&val)?),
        "he" => a.encrypt_header = Some(parse_bool(&val, "-mhe")?),
        "hc" => a.compress_header = Some(parse_bool(&val, "-mhc")?),
        "s" => {
            let lower = val.to_ascii_lowercase();
            a.solid = Some(match lower.as_str() {
                "" | "on" | "+" => Some(u64::MAX),
                "off" | "-" => None,
                "e" => Some(u64::MAX),
                v => Some(
                    parse_size(v)
                        .ok_or_else(|| Error::usage(format!("bad solid block size '{val}'")))?,
                ),
            })
        }
        "d" => a.method.dict = Some(parse_dict(&val)?),
        "fb" => {
            a.method.fast_bytes = Some(
                val.parse()
                    .map_err(|_| Error::usage(format!("bad fb '{val}'")))?,
            )
        }
        "c" | "bs" => {
            a.method.block = Some(
                parse_size(&val).ok_or_else(|| Error::usage(format!("bad block size '{val}'")))?,
            )
        }
        "tm" => a.mtime = Some(parse_bool(&val, "-mtm")?),
        "tc" => a.ctime = Some(parse_bool(&val, "-mtc")?),
        "ta" => a.atime = Some(parse_bool(&val, "-mta")?),
        "qs" | "tr" => {}
        _ => return Err(Error::usage(format!("unsupported switch -m{body}"))),
    }
    Ok(())
}

/// `-x!*.tmp`, `-xr!build`, `-x@list.txt`, `-i!src/*`.
fn parse_wild(body: &str, out: &mut Vec<String>) -> Result<()> {
    let mut s = body;
    // Recursion modifiers (r, r-, r0) are accepted; r7z patterns already match at any depth.
    if let Some(rest) = s.strip_prefix(['r', 'R']) {
        s = rest.trim_start_matches(['-', '0']);
    }
    if let Some(p) = s.strip_prefix('!') {
        out.push(p.to_string());
    } else if let Some(list) = s.strip_prefix('@') {
        out.extend(read_list_file(list)?);
    } else {
        return Err(Error::usage(format!(
            "bad wildcard switch '{body}' (use -x!pattern or -x@listfile)"
        )));
    }
    Ok(())
}

pub fn read_list_file(path: &str) -> Result<Vec<String>> {
    let data = std::fs::read(path)
        .map_err(|e| Error::usage(format!("cannot read list file {path}: {e}")))?;
    let text = if data.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = data[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(data.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&data))
            .into_owned()
    };
    Ok(text
        .lines()
        .map(|l| l.trim().trim_matches('"').to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

fn parse_command(s: &str) -> Option<Command> {
    Some(match s.to_ascii_lowercase().as_str() {
        "a" | "add" => Command::Add,
        "u" | "update" => Command::Update,
        "d" | "delete" => Command::Delete,
        "rn" => Command::Rename,
        "x" | "extract" => Command::Extract { full_paths: true },
        "e" => Command::Extract { full_paths: false },
        "l" | "list" | "ls" => Command::List,
        "t" | "test" => Command::Test,
        "h" | "hash" => Command::Hash,
        "b" | "bench" | "benchmark" => Command::Bench,
        "i" | "info" => Command::Info,
        "help" | "-h" | "--help" | "/?" | "-?" => Command::Help,
        "--version" | "-v" | "-V" | "version" => Command::Version,
        _ => return None,
    })
}

pub fn parse(argv: Vec<String>) -> Result<Args> {
    let mut a = Args {
        command: Command::Help,
        archive: None,
        names: Vec::new(),
        output_dir: None,
        password: None,
        yes: false,
        overwrite: None,
        recurse: None,
        include: Vec::new(),
        exclude: Vec::new(),
        level: None,
        threads: None,
        method: MethodSpec::default(),
        encrypt_header: None,
        compress_header: None,
        solid: None,
        mtime: None,
        ctime: None,
        atime: None,
        technical: false,
        hashes: Vec::new(),
        no_progress: false,
        stdout: false,
        timing: false,
        bench_iterations: None,
        archive_type: None,
        zip_crypto: None,
        code_page: None,
        recover: false,
    };
    let mut positional: Vec<String> = Vec::new();
    let mut switches_done = false;
    let mut command: Option<Command> = None;
    for arg in argv {
        if command.is_none() {
            if let Some(c) = parse_command(&arg) {
                command = Some(c);
                continue;
            }
        }
        if switches_done || !arg.starts_with('-') || arg == "-" {
            if let Some(list) = arg.strip_prefix('@').filter(|_| !switches_done) {
                positional.extend(read_list_file(list)?);
            } else {
                positional.push(arg);
            }
            continue;
        }
        if arg == "--" {
            switches_done = true;
            continue;
        }
        if arg == "--help" {
            command = Some(Command::Help);
            continue;
        }
        let body = &arg[1..];
        let lower = body.to_ascii_lowercase();
        let first = lower.chars().next().unwrap_or(' ');
        match first {
            'o' => a.output_dir = Some(PathBuf::from(&body[1..])),
            'p' => {
                a.password = Some(if body.len() > 1 {
                    Some(body[1..].to_string())
                } else {
                    None
                })
            }
            'y' => a.yes = true,
            'r' if lower == "recover" => a.recover = true,
            'r' => a.recurse = Some(!lower.ends_with('-')),
            't' => {
                let t = &lower[1..];
                if !t.is_empty() && t != "*" && t != "#" {
                    if r7z::format::find_format(t).is_none() {
                        return Err(Error::usage(format!(
                            "unknown archive type '{t}' (run 'r7z i' for the list)"
                        )));
                    }
                    a.archive_type = Some(t.to_string());
                }
            }
            'm' => parse_m(&body[1..], &mut a)?,
            'x' => parse_wild(&body[1..], &mut a.exclude)?,
            'i' => parse_wild(&body[1..], &mut a.include)?,
            'a' if lower.starts_with("ao") => {
                a.overwrite = Some(match &lower[2..] {
                    "a" => Overwrite::All,
                    "s" => Overwrite::Skip,
                    "u" => Overwrite::RenameNew,
                    "t" => Overwrite::RenameExisting,
                    v => {
                        return Err(Error::usage(format!(
                            "bad overwrite mode -ao{v} (use a, s, u or t)"
                        )))
                    }
                })
            }
            'b' => match lower.as_str() {
                "bd" => a.no_progress = true,
                "bt" => a.timing = true,
                s if s.starts_with("bb") || s.starts_with("bs") => {}
                _ => return Err(Error::usage(format!("unsupported switch -{body}"))),
            },
            's' => {
                match lower.as_str() {
                    "slt" => a.technical = true,
                    "so" => a.stdout = true,
                    s if s.starts_with("scrc") => {
                        let v = &body[4..];
                        if v.is_empty() || v == "*" {
                            if v == "*" {
                                a.hashes = HashKind::ALL.to_vec();
                            } else {
                                a.hashes.push(HashKind::Crc32);
                            }
                        } else {
                            for name in v.split(',') {
                                a.hashes.push(HashKind::parse(name).ok_or_else(|| {
                                    Error::usage(format!("unknown hash '{name}'"))
                                })?);
                            }
                        }
                    }
                    s if s.starts_with("scc")
                        || s.starts_with("scs")
                        || s == "ssc"
                        || s == "ssc-"
                        || s == "spd"
                        || s == "ssw" => {}
                    _ => return Err(Error::usage(format!("unsupported switch -{body}"))),
                }
            }
            _ => return Err(Error::usage(format!("unknown switch -{body}"))),
        }
    }
    a.command = command.unwrap_or(Command::Help);
    match a.command {
        Command::Add
        | Command::Update
        | Command::Delete
        | Command::Rename
        | Command::Extract { .. }
        | Command::List
        | Command::Test => {
            if positional.is_empty() {
                return Err(Error::usage("missing archive name"));
            }
            a.archive = Some(PathBuf::from(positional.remove(0)));
            a.names = positional;
        }
        Command::Bench => {
            if let Some(p) = positional.first() {
                a.bench_iterations = Some(
                    p.parse()
                        .map_err(|_| Error::usage(format!("bad iteration count '{p}'")))?,
                );
            }
        }
        _ => a.names = positional,
    }
    Ok(a)
}
