//! Updates from the GitHub releases of r7z.
//!
//! Every release carries `r7z-update.txt`, a short manifest naming the release zip with its
//! size and SHA-256, and `r7z-update.sig`, an Ed25519 signature of the manifest's exact
//! bytes made with the release key. Nothing downloaded is used until that signature checks
//! out against the public key compiled in below and the version is newer than this build,
//! so an altered download, a hijacked release or an older build is refused.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use r7z::error::{Error, Result};

const REPO: &str = "hdunl/r7z";

/// Public half of the release signing key.
const RELEASE_KEY: &str = "281b0c26996e9342c9e1f12e2d3d71c57d57e5325d6e6c7d4259eb2e662ee5c9";

const MANIFEST_LIMIT: u64 = 4 << 10;
const ZIP_LIMIT: u64 = 256 << 20;

/// When a file from a release zip is installed in the folder r7z-gui.exe runs from.
#[derive(Clone, Copy, PartialEq)]
enum When {
    /// Always; the zip must have it.
    Required,
    /// Only to replace a copy that is already there (the command line tool).
    Replace,
    /// Whenever the zip has it, also when it is missing: parts of the app that older
    /// releases did not ship (the Windows 11 menu).
    Bundled,
}

/// The files a release may install, with the first bytes each must start with.
const PARTS: [(&str, When, &[u8]); 4] = [
    ("r7z-gui.exe", When::Required, b"MZ"),
    ("r7z.exe", When::Replace, b"MZ"),
    ("r7z_shell.dll", When::Bundled, b"MZ"),
    ("r7z-shell.msix", When::Bundled, b"PK"),
];

pub const CURRENT: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug, PartialEq)]
pub struct Manifest {
    pub version: String,
    pub file: String,
    pub size: u64,
    pub sha256: [u8; 32],
}

impl Manifest {
    pub fn release_url(&self) -> String {
        release_page(&self.version)
    }

    fn download_url(&self) -> String {
        format!(
            "https://github.com/{REPO}/releases/download/v{}/{}",
            self.version, self.file
        )
    }
}

pub fn release_page(version: &str) -> String {
    format!("https://github.com/{REPO}/releases/tag/v{version}")
}

pub enum Check {
    UpToDate,
    Available(Manifest),
}

fn bad(what: &str) -> Error {
    Error::Other(format!("the update manifest is invalid ({what})"))
}

fn hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != N * 2 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (digit(s[2 * i])? << 4) | digit(s[2 * i + 1])?;
    }
    Some(out)
}

/// `major.minor.patch`, nothing else.
pub fn parse_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.split('.').map(|p| {
        if p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()) {
            None
        } else {
            p.parse().ok()
        }
    });
    let v = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(v)
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

pub fn parse_manifest(text: &str) -> Result<Manifest> {
    let mut lines = text.lines();
    if lines.next() != Some("r7z-update 1") {
        return Err(bad("unknown format"));
    }
    let (mut version, mut file, mut size, mut sha256) = (None, None, None, None);
    for line in lines {
        let Some((key, value)) = line.split_once(' ') else {
            continue;
        };
        match key {
            "version" => version = Some(value.to_string()),
            "file" => file = Some(value.to_string()),
            "size" => size = value.parse::<u64>().ok(),
            "sha256" => sha256 = hex::<32>(value),
            _ => {}
        }
    }
    let version = version.ok_or_else(|| bad("no version"))?;
    parse_version(&version).ok_or_else(|| bad("version"))?;
    let file = file.ok_or_else(|| bad("no file"))?;
    let plain_name = file
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    if !plain_name || file.starts_with('.') || !file.ends_with(".zip") {
        return Err(bad("file name"));
    }
    let size = size
        .filter(|&s| s > 0 && s <= ZIP_LIMIT)
        .ok_or_else(|| bad("size"))?;
    let sha256 = sha256.ok_or_else(|| bad("sha256"))?;
    Ok(Manifest {
        version,
        file,
        size,
        sha256,
    })
}

/// Checks `sig` (hex) over the exact manifest bytes, then parses the manifest.
pub fn verify(manifest: &[u8], sig: &str, key: &[u8; 32]) -> Result<Manifest> {
    let invalid = || Error::Other("the update's signature is not valid".into());
    let sig = hex::<64>(sig.trim()).ok_or_else(invalid)?;
    let key = VerifyingKey::from_bytes(key).map_err(|_| invalid())?;
    key.verify_strict(manifest, &Signature::from_bytes(&sig))
        .map_err(|_| invalid())?;
    let text = std::str::from_utf8(manifest).map_err(|_| bad("not text"))?;
    parse_manifest(text)
}

fn release_key() -> [u8; 32] {
    hex(RELEASE_KEY).expect("release key")
}

/// HTTPS only, through Windows' own TLS (SChannel) and certificate store, which Windows
/// Update keeps current.
fn agent() -> ureq::Agent {
    use ureq::tls::{RootCerts, TlsConfig, TlsProvider};
    ureq::Agent::config_builder()
        .https_only(true)
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::NativeTls)
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_recv_response(Some(Duration::from_secs(30)))
        .timeout_global(Some(Duration::from_secs(15 * 60)))
        .user_agent(concat!("r7z/", env!("CARGO_PKG_VERSION")))
        .build()
        .new_agent()
}

fn net(e: ureq::Error) -> Error {
    match e {
        ureq::Error::StatusCode(404) => Error::Other("no release has been published yet".into()),
        ureq::Error::StatusCode(code) => Error::Other(format!("GitHub answered with HTTP {code}")),
        other => Error::Other(format!("could not reach GitHub ({other})")),
    }
}

/// Downloads at most `limit` bytes; anything longer is an error.
fn get(agent: &ureq::Agent, url: &str, limit: u64, cancel: &AtomicBool) -> Result<Vec<u8>> {
    let resp = agent.get(url).call().map_err(net)?;
    let mut reader = resp.into_body().into_reader().take(limit + 1);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 << 10];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(Error::Cancelled);
        }
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n]);
    }
    if out.len() as u64 > limit {
        return Err(Error::Other(format!("{url} is larger than expected")));
    }
    Ok(out)
}

/// Fetches and verifies the latest release's manifest.
fn latest(agent: &ureq::Agent, cancel: &AtomicBool) -> Result<Manifest> {
    let base = format!("https://github.com/{REPO}/releases/latest/download");
    let manifest = get(
        agent,
        &format!("{base}/r7z-update.txt"),
        MANIFEST_LIMIT,
        cancel,
    )?;
    let sig = get(agent, &format!("{base}/r7z-update.sig"), 1024, cancel)?;
    let sig = String::from_utf8_lossy(&sig);
    verify(&manifest, &sig, &release_key())
}

pub fn check(cancel: &AtomicBool) -> Result<Check> {
    let m = latest(&agent(), cancel)?;
    Ok(if is_newer(&m.version, CURRENT) {
        Check::Available(m)
    } else {
        Check::UpToDate
    })
}

fn install_dir() -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| Error::Other("cannot tell where r7z is installed".into()))
}

/// Downloads the release zip named by a verified manifest, checks its size and hash, and
/// installs its files next to this program; with `only_missing`, just the files this copy
/// lacks. Returns the names installed.
fn download_zip_and_install(
    agent: &ureq::Agent,
    m: &Manifest,
    only_missing: bool,
    cancel: &AtomicBool,
) -> Result<Vec<String>> {
    let zip = get(agent, &m.download_url(), m.size, cancel)?;
    if zip.len() as u64 != m.size || Sha256::digest(&zip).as_slice() != m.sha256 {
        return Err(Error::Other(
            "the downloaded update does not match its signed checksum".into(),
        ));
    }
    let tmp = std::env::temp_dir().join(format!("r7z-update-{}.zip", std::process::id()));
    std::fs::write(&tmp, &zip)?;
    let result = install_parts(&tmp, &install_dir()?, only_missing);
    let _ = std::fs::remove_file(&tmp);
    result
}

/// Installs a newer release. Returns the version installed.
pub fn download_and_install(m: &Manifest, cancel: &AtomicBool) -> Result<String> {
    download_zip_and_install(&agent(), m, false, cancel).map(|_| m.version.clone())
}

/// Adds the files of this version's release that this copy lacks, such as the Windows 11
/// menu on a copy that an older version updated: those only replaced files that were
/// already there. Uses the same signed manifest and checks as an update.
pub fn install_missing(cancel: &AtomicBool) -> Result<Vec<String>> {
    let agent = agent();
    let m = latest(&agent, cancel)?;
    if m.version != CURRENT {
        return Err(Error::Other(format!(
            "r7z {} is available; updating to it brings these files too",
            m.version
        )));
    }
    download_zip_and_install(&agent, &m, true, cancel)
}

pub fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

/// Installs the files in `zip` into `dir` (with `only_missing`, just the ones `dir` lacks).
/// A running program can be renamed on Windows but not overwritten, so each existing file
/// moves to `name.old` first (removed on the next start) and the new file takes its name.
/// Any failure puts the old files back.
fn install_parts(zip: &Path, dir: &Path, only_missing: bool) -> Result<Vec<String>> {
    let opened = r7z::format::open(zip, &Default::default())?;
    let a = opened.archive();
    let stage = || -> Result<Vec<(PathBuf, PathBuf)>> {
        let mut out = Vec::new();
        for (name, when, magic) in PARTS {
            let target = dir.join(name);
            if (when == When::Replace && !target.exists()) || (only_missing && target.exists()) {
                continue;
            }
            let index = a.entries().iter().position(|e| {
                !e.is_dir
                    && e.name
                        .rsplit('/')
                        .next()
                        .is_some_and(|n| n.eq_ignore_ascii_case(name))
            });
            let Some(index) = index else {
                if when == When::Required {
                    return Err(Error::Other(format!("the update has no {name}")));
                }
                continue;
            };
            let data = r7z::ops::peek::read_entry(a, index, None, ZIP_LIMIT as usize, &|| false)?;
            if data.truncated || !data.data.starts_with(magic) {
                return Err(Error::Other(format!(
                    "{name} in the update is not what it should be"
                )));
            }
            let new = sibling(&target, ".new");
            std::fs::write(&new, &data.data)
                .map_err(|e| Error::Other(format!("cannot write to {} ({e})", dir.display())))?;
            out.push((target, new));
        }
        Ok(out)
    };
    let staged = match stage() {
        Ok(s) => s,
        Err(e) => {
            for (name, _, _) in PARTS {
                let _ = std::fs::remove_file(sibling(&dir.join(name), ".new"));
            }
            return Err(e);
        }
    };
    let mut swapped: Vec<&(PathBuf, PathBuf)> = Vec::new();
    for pair in &staged {
        let (target, new) = pair;
        let old = sibling(target, ".old");
        let _ = std::fs::remove_file(&old);
        let moved = !target.exists() || std::fs::rename(target, &old).is_ok();
        if moved && std::fs::rename(new, target).is_ok() {
            swapped.push(pair);
            continue;
        }
        if moved && old.exists() {
            let _ = std::fs::rename(&old, target);
        }
        for (t, _) in swapped.iter().rev() {
            let o = sibling(t, ".old");
            let _ = std::fs::remove_file(t);
            let _ = std::fs::rename(&o, t);
        }
        for (_, n) in &staged {
            let _ = std::fs::remove_file(n);
        }
        return Err(Error::Other(format!(
            "could not replace {}; nothing was changed",
            target.display()
        )));
    }
    Ok(staged
        .iter()
        .filter_map(|(t, _)| t.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect())
}

/// Removes what an earlier update left behind (`*.old`, unfinished `*.new`).
/// The files a release installs next to `r7z-gui.exe`.
pub fn release_files() -> Vec<&'static str> {
    PARTS.iter().map(|(name, _, _)| *name).collect()
}

pub fn cleanup() {
    let Ok(dir) = install_dir() else { return };
    for (name, _, _) in PARTS {
        let target = dir.join(name);
        let _ = std::fs::remove_file(sibling(&target, ".old"));
        let _ = std::fs::remove_file(sibling(&target, ".new"));
    }
}

/// Starts the (updated) program again; the caller then closes this window.
pub fn relaunch() -> Result<()> {
    std::process::Command::new(std::env::current_exe()?).spawn()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(text: &str) -> (Vec<u8>, String, [u8; 32]) {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let sig = key.sign(text.as_bytes()).to_bytes();
        let hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
        (
            text.as_bytes().to_vec(),
            hex,
            key.verifying_key().to_bytes(),
        )
    }

    /// A stored (uncompressed) zip of every file in `src`.
    fn write_zip(src: &Path, zip: &Path) {
        let mut out = Vec::new();
        let mut central = Vec::new();
        let mut count = 0u16;
        for ent in std::fs::read_dir(src).unwrap() {
            let ent = ent.unwrap();
            let name = ent.file_name().to_string_lossy().into_owned();
            let data = std::fs::read(ent.path()).unwrap();
            let crc = crc32fast::hash(&data);
            let offset = out.len() as u32;
            let fixed = |v: &mut Vec<u8>| {
                v.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
                v.extend_from_slice(&crc.to_le_bytes());
                v.extend_from_slice(&(data.len() as u32).to_le_bytes());
                v.extend_from_slice(&(data.len() as u32).to_le_bytes());
                v.extend_from_slice(&(name.len() as u16).to_le_bytes());
                v.extend_from_slice(&[0, 0]);
            };
            out.extend_from_slice(b"PK\x03\x04");
            fixed(&mut out);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&data);
            central.extend_from_slice(b"PK\x01\x02\x14\x00");
            fixed(&mut central);
            central.extend_from_slice(&[0; 10]);
            central.extend_from_slice(&offset.to_le_bytes());
            central.extend_from_slice(name.as_bytes());
            count += 1;
        }
        let cd_offset = out.len() as u32;
        out.extend_from_slice(&central);
        out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&(central.len() as u32).to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        std::fs::write(zip, out).unwrap();
    }

    const GOOD: &str = "r7z-update 1\nversion 0.2.0\nfile r7z-0.2.0-windows-x64.zip\nsize 1234\nsha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n";

    #[test]
    fn accepts_a_signed_manifest() {
        let (m, sig, key) = signed(GOOD);
        let parsed = verify(&m, &sig, &key).unwrap();
        assert_eq!(parsed.version, "0.2.0");
        assert_eq!(parsed.size, 1234);
        assert_eq!(parsed.sha256, [0xaa; 32]);
    }

    #[test]
    fn refuses_a_changed_manifest_or_other_key() {
        let (mut m, sig, key) = signed(GOOD);
        assert!(verify(&m, &sig, &release_key()).is_err());
        m[20] ^= 1;
        assert!(verify(&m, &sig, &key).is_err());
        assert!(verify(GOOD.as_bytes(), "00", &key).is_err());
    }

    #[test]
    fn refuses_unsafe_file_names_and_sizes() {
        for bad in [
            GOOD.replace("r7z-0.2.0-windows-x64.zip", "../r7z.zip"),
            GOOD.replace("r7z-0.2.0-windows-x64.zip", "r7z.exe"),
            GOOD.replace("size 1234", "size 0"),
            GOOD.replace("size 1234", "size 99999999999"),
            GOOD.replace("version 0.2.0", "version 0.2"),
            GOOD.replace("r7z-update 1", "r7z-update 2"),
        ] {
            assert!(parse_manifest(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn only_newer_versions_count() {
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
        assert!(!is_newer("1.0", "0.1.0"));
        assert!(!is_newer("1.0.0-beta", "0.1.0"));
    }

    #[test]
    fn bundled_parts_are_added_and_repairs_only_fill_gaps() {
        let root = std::env::temp_dir().join(format!("r7z-bundled-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("app");
        let src = root.join("src");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(dir.join("r7z-gui.exe"), b"MZ installed gui").unwrap();
        std::fs::write(src.join("r7z-gui.exe"), b"MZ release gui").unwrap();
        std::fs::write(src.join("r7z_shell.dll"), b"MZ shell").unwrap();
        std::fs::write(src.join("r7z-shell.msix"), b"PK package").unwrap();
        let zip = root.join("u.zip");
        write_zip(&src, &zip);

        // A repair adds what is missing and leaves the running program alone.
        let done = install_parts(&zip, &dir, true).unwrap();
        assert_eq!(done, ["r7z_shell.dll", "r7z-shell.msix"]);
        assert_eq!(
            std::fs::read(dir.join("r7z-gui.exe")).unwrap(),
            b"MZ installed gui"
        );
        assert_eq!(
            std::fs::read(dir.join("r7z-shell.msix")).unwrap(),
            b"PK package"
        );

        // A package that isn't one is refused, and nothing is left half done.
        std::fs::remove_file(dir.join("r7z-shell.msix")).unwrap();
        std::fs::write(src.join("r7z-shell.msix"), b"MZ not a package").unwrap();
        write_zip(&src, &zip);
        assert!(install_parts(&zip, &dir, true).is_err());
        assert!(!dir.join("r7z-shell.msix").exists());
        assert!(!dir.join("r7z-shell.msix.new").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn installs_and_rolls_back() {
        let root = std::env::temp_dir().join(format!("r7z-update-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let dir = root.join("app");
        let src = root.join("src");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(dir.join("r7z-gui.exe"), b"MZ old gui").unwrap();
        std::fs::write(src.join("r7z-gui.exe"), b"MZ new gui").unwrap();
        std::fs::write(src.join("r7z.exe"), b"MZ new cli").unwrap();
        let zip = root.join("u.zip");
        write_zip(&src, &zip);

        let done = install_parts(&zip, &dir, false).unwrap();
        assert_eq!(done, ["r7z-gui.exe"]);
        assert_eq!(
            std::fs::read(dir.join("r7z-gui.exe")).unwrap(),
            b"MZ new gui"
        );
        assert_eq!(
            std::fs::read(dir.join("r7z-gui.exe.old")).unwrap(),
            b"MZ old gui"
        );
        assert!(
            !dir.join("r7z.exe").exists(),
            "the CLI is only updated when present"
        );

        std::fs::write(src.join("r7z-gui.exe"), b"not a program").unwrap();
        write_zip(&src, &zip);
        assert!(install_parts(&zip, &dir, false).is_err());
        assert_eq!(
            std::fs::read(dir.join("r7z-gui.exe")).unwrap(),
            b"MZ new gui"
        );
        assert!(!dir.join("r7z-gui.exe.new").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Checks a packaged release the way installed copies will: the signature against the
    /// built-in key, the zip against the manifest, and an install into a scratch folder.
    /// `R7Z_RELEASE_DIR=dist cargo test --release -p r7z-gui -- --ignored packaged_release`
    #[test]
    #[ignore = "needs a packaged release in R7Z_RELEASE_DIR"]
    fn packaged_release() {
        let Some(dir) = std::env::var_os("R7Z_RELEASE_DIR").map(PathBuf::from) else {
            eprintln!("skipped: set R7Z_RELEASE_DIR");
            return;
        };
        let manifest = std::fs::read(dir.join("r7z-update.txt")).unwrap();
        let sig = std::fs::read_to_string(dir.join("r7z-update.sig")).unwrap();
        let m = verify(&manifest, &sig, &release_key()).unwrap();
        assert_eq!(m.version, CURRENT);
        let zip = dir.join(&m.file);
        let data = std::fs::read(&zip).unwrap();
        assert_eq!(data.len() as u64, m.size);
        assert_eq!(Sha256::digest(&data).as_slice(), m.sha256);
        let scratch =
            std::env::temp_dir().join(format!("r7z-release-check-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).unwrap();
        std::fs::write(scratch.join("r7z-gui.exe"), b"MZ").unwrap();
        std::fs::write(scratch.join("r7z.exe"), b"MZ").unwrap();
        let done = install_parts(&zip, &scratch, false).unwrap();
        assert!(done.iter().any(|n| n == "r7z-gui.exe") && done.iter().any(|n| n == "r7z.exe"));
        // The Windows 11 menu parts come along even though the folder had none.
        assert!(done.iter().any(|n| n == "r7z_shell.dll"), "{done:?}");
        assert!(
            std::fs::metadata(scratch.join("r7z-gui.exe"))
                .unwrap()
                .len()
                > 1 << 20
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
