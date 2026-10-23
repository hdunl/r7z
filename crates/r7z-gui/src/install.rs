//! Installing r7z for the current user. Installing copies the program to
//! `%LOCALAPPDATA%\Programs\r7z` and registers that copy with Windows: a Start menu
//! shortcut (which Windows search finds), an entry in Settings → Installed apps whose
//! Uninstall button runs `r7z-gui --uninstall`, App Paths so `r7z` works from Run, "Open
//! with" for archive types, and the right-click menus. Everything is written under HKCU and
//! the user's own folders, so no administrator rights are needed. Settings in
//! `%APPDATA%\r7z` are left alone by both.

use std::path::{Path, PathBuf};

/// Where r7z is installed, as recorded in its Installed apps entry.
#[derive(Clone, PartialEq)]
pub enum State {
    NotInstalled,
    /// `here` is true when this running program is the installed copy.
    Installed {
        dir: PathBuf,
        here: bool,
    },
}

#[cfg(windows)]
const UNINSTALL_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\r7z";

/// Archive types offered in "Open with" and Settings → Default apps. Formats r7z reads
/// that are mostly something else (documents, Android packages, libraries) are left out.
#[cfg(windows)]
const EXTENSIONS: &[&str] = &[
    "7z", "zip", "tar", "gz", "tgz", "bz2", "tbz", "tbz2", "xz", "txz", "zst", "tzst", "lz4",
    "lzma", "z", "taz", "cab", "cpio", "arj", "lzh", "lha", "rpm", "deb", "xar", "wim", "swm",
    "esd", "001", "msi", "msp", "chm",
];

/// The folder installing copies r7z into.
pub fn target_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA").map(|d| PathBuf::from(d).join("Programs").join("r7z"))
}

fn this_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

#[cfg(windows)]
pub fn state() -> State {
    let Some(dir) = reg_get(UNINSTALL_KEY, "InstallLocation").map(PathBuf::from) else {
        return State::NotInstalled;
    };
    let here = this_dir().is_some_and(|d| same_dir(&d, &dir));
    State::Installed { dir, here }
}

/// Copies this program into [`target_dir`], registers the copy, and returns the path of
/// the installed `r7z-gui.exe`.
#[cfg(windows)]
pub fn install() -> Result<PathBuf, String> {
    let from = this_dir().ok_or("cannot tell where r7z is running from")?;
    let dir = target_dir().ok_or("LOCALAPPDATA is not set")?;
    if !same_dir(&from, &dir) {
        copy_files(&from, &dir)?;
    }
    let exe = dir.join("r7z-gui.exe");
    register(&exe, &dir)?;
    // The right-click menus point at the installed copy from now on.
    if !crate::shell::install_explorer_for(&exe) {
        return Err("couldn't add the right-click menu entries".into());
    }
    // Without it (Windows 10, or no package next to this copy) r7z is still installed;
    // the entries are then under "Show more options".
    let _ = crate::shell::move_modern_menu(&dir);
    changed_associations();
    Ok(exe)
}

/// Files of a release that belong in the install folder. Programs that are running can't
/// be overwritten but can be renamed, so an existing file moves aside to `name.old` (the
/// updater's cleanup removes those on the next start) before the new one is copied in.
#[cfg(windows)]
fn copy_files(from: &Path, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("can't create {}: {e}", dir.display()))?;
    let mut names: Vec<String> = crate::update::release_files()
        .iter()
        .map(|s| s.to_string())
        .collect();
    names.extend(["README.md".to_string(), "LICENSE".to_string()]);
    for name in names {
        let src = from.join(&name);
        if !src.is_file() {
            continue;
        }
        let dst = dir.join(&name);
        if dst.exists() {
            let old = crate::update::sibling(&dst, ".old");
            let _ = std::fs::remove_file(&old);
            std::fs::rename(&dst, &old)
                .map_err(|e| format!("can't replace {}: {e}", dst.display()))?;
        }
        std::fs::copy(&src, &dst).map_err(|e| format!("can't copy {name}: {e}"))?;
    }
    // Development builds carry the Windows 11 menu as a loose package folder.
    let package = from.join("package");
    if package.is_dir() {
        let to = dir.join("package");
        std::fs::create_dir_all(&to).map_err(|e| e.to_string())?;
        for entry in std::fs::read_dir(&package).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.path().is_file() {
                std::fs::copy(entry.path(), to.join(entry.file_name()))
                    .map_err(|e| format!("can't copy the menu package: {e}"))?;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn register(exe: &Path, dir: &Path) -> Result<(), String> {
    use crate::shell::ps_path;
    let size_kb: u64 = std::fs::read_dir(dir)
        .map(|it| {
            it.filter_map(|e| e.ok()?.metadata().ok())
                .filter(|m| m.is_file())
                .map(|m| m.len())
                .sum::<u64>()
                / 1024
        })
        .unwrap_or(0);
    let exts = EXTENSIONS
        .iter()
        .map(|e| format!("'.{e}'"))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
$exe = {exe}; $dir = {dir}; $open = '"' + $exe + '" "%1"'
function Key($path) {{ New-Item -Path $path -Force | Out-Null; $path }}
function Default($path, $value) {{ Set-ItemProperty -LiteralPath (Key $path) -Name '(default)' -Value $value }}

$lnk = Join-Path ([Environment]::GetFolderPath('Programs')) 'r7z.lnk'
$s = (New-Object -ComObject WScript.Shell).CreateShortcut($lnk)
$s.TargetPath = $exe; $s.WorkingDirectory = $dir; $s.IconLocation = "$exe,0"
$s.Description = 'Open, extract and create archives'; $s.Save()

$u = Key 'HKCU:\{uninstall}'
$v = @{{ DisplayName = 'r7z'; DisplayVersion = '{version}'; Publisher = 'hdunl'
  DisplayIcon = "$exe,0"; InstallLocation = $dir; UninstallString = '"' + $exe + '" --uninstall'
  QuietUninstallString = '"' + $exe + '" --uninstall --quiet'
  URLInfoAbout = 'https://github.com/hdunl/r7z'; HelpLink = 'https://github.com/hdunl/r7z/issues'
  InstallDate = (Get-Date -Format yyyyMMdd) }}
foreach ($k in $v.Keys) {{ Set-ItemProperty -LiteralPath $u -Name $k -Value $v[$k] }}
foreach ($k in 'NoModify', 'NoRepair') {{ New-ItemProperty -LiteralPath $u -Name $k -Value 1 -PropertyType DWord -Force | Out-Null }}
New-ItemProperty -LiteralPath $u -Name EstimatedSize -Value {size_kb} -PropertyType DWord -Force | Out-Null

Default 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\r7z-gui.exe' $exe
Default 'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\r7z.exe' (Join-Path $dir 'r7z.exe')

Default 'HKCU:\Software\Classes\r7z.archive' 'Archive'
Default 'HKCU:\Software\Classes\r7z.archive\DefaultIcon' "$exe,0"
Default 'HKCU:\Software\Classes\r7z.archive\shell\open\command' $open
$app = Key 'HKCU:\Software\Classes\Applications\r7z-gui.exe'
Set-ItemProperty -LiteralPath $app -Name FriendlyAppName -Value 'r7z'
Default "$app\shell\open\command" $open
$types = Key "$app\SupportedTypes"
$cap = Key 'HKCU:\Software\r7z\Capabilities'
Set-ItemProperty -LiteralPath $cap -Name ApplicationName -Value 'r7z'
Set-ItemProperty -LiteralPath $cap -Name ApplicationDescription -Value 'Open, extract and create archives'
Set-ItemProperty -LiteralPath $cap -Name ApplicationIcon -Value "$exe,0"
$assoc = Key "$cap\FileAssociations"
foreach ($e in @({exts})) {{
  Set-ItemProperty -LiteralPath $types -Name $e -Value ''
  Set-ItemProperty -LiteralPath $assoc -Name $e -Value 'r7z.archive'
  Set-ItemProperty -LiteralPath (Key "HKCU:\Software\Classes\$e\OpenWithProgids") -Name 'r7z.archive' -Value ''
}}
Set-ItemProperty -LiteralPath (Key 'HKCU:\Software\RegisteredApplications') -Name 'r7z' -Value 'Software\r7z\Capabilities'
"#,
        exe = ps_path(exe),
        dir = ps_path(dir),
        uninstall = UNINSTALL_KEY,
        version = crate::update::CURRENT,
    );
    crate::shell::powershell(&script)
        .map(drop)
        .map_err(|e| format!("couldn't register r7z with Windows: {e}"))
}

/// Removes everything installing added. When the installed copy is the one running, its
/// folder is deleted a moment after this program exits.
#[cfg(windows)]
pub fn uninstall() -> Result<(), String> {
    let state = state();
    crate::shell::uninstall_explorer();
    let _ = crate::shell::uninstall_modern_menu();
    let exts = EXTENSIONS
        .iter()
        .map(|e| format!("'.{e}'"))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        r#"$ErrorActionPreference = 'SilentlyContinue'
Remove-Item -LiteralPath (Join-Path ([Environment]::GetFolderPath('Programs')) 'r7z.lnk') -Force
foreach ($k in 'HKCU:\{uninstall}',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\r7z-gui.exe',
  'HKCU:\Software\Microsoft\Windows\CurrentVersion\App Paths\r7z.exe',
  'HKCU:\Software\Classes\r7z.archive',
  'HKCU:\Software\Classes\Applications\r7z-gui.exe',
  'HKCU:\Software\r7z') {{ Remove-Item -LiteralPath $k -Recurse -Force }}
Remove-ItemProperty -LiteralPath 'HKCU:\Software\RegisteredApplications' -Name 'r7z' -Force
foreach ($e in @({exts})) {{
  Remove-ItemProperty -LiteralPath "HKCU:\Software\Classes\$e\OpenWithProgids" -Name 'r7z.archive' -Force
}}
"#,
        uninstall = UNINSTALL_KEY,
    );
    crate::shell::powershell(&script)
        .map_err(|e| format!("couldn't remove r7z's registration: {e}"))?;
    changed_associations();
    if let State::Installed { dir, here } = state {
        // Only the folder installing made is ever deleted, never a folder r7z was merely
        // run from.
        if target_dir().is_some_and(|t| same_dir(&t, &dir)) {
            if here {
                delete_after_exit(&dir);
            } else {
                let _ = std::fs::remove_dir_all(&dir);
            }
        }
    }
    Ok(())
}

/// After an update the installed copy is newer than its Installed apps entry says.
#[cfg(windows)]
pub fn refresh() {
    if let State::Installed { here: true, .. } = state() {
        if reg_get(UNINSTALL_KEY, "DisplayVersion").as_deref() != Some(crate::update::CURRENT) {
            let key = format!(r"HKCU\{UNINSTALL_KEY}");
            let version = crate::update::CURRENT;
            crate::shell::reg(&["add", &key, "/v", "DisplayVersion", "/d", version, "/f"]);
        }
    }
}

/// A program can't delete the folder it runs from, so a hidden `cmd` waits for this one
/// to exit and removes it.
#[cfg(windows)]
fn delete_after_exit(dir: &Path) {
    use std::os::windows::process::CommandExt;
    // cmd has its own quoting: with /c, the outer pair of quotes is removed and the rest
    // runs as typed, so the line is passed raw rather than escaped the C way.
    let script = format!(
        "\"ping -n 4 127.0.0.1 >nul & rd /s /q \"{}\"\"",
        dir.display()
    );
    let _ = std::process::Command::new("cmd")
        .arg("/c")
        .raw_arg(script)
        .current_dir(std::env::temp_dir())
        .creation_flags(0x0800_0000)
        .spawn();
}

/// Tells Explorer that "Open with" and file type icons changed.
#[cfg(windows)]
fn changed_associations() {
    #[link(name = "shell32")]
    extern "system" {
        fn SHChangeNotify(event: i32, flags: u32, a: *const u8, b: *const u8);
    }
    const SHCNE_ASSOCCHANGED: i32 = 0x0800_0000;
    // SAFETY: SHCNE_ASSOCCHANGED takes no items; both pointers may be null.
    unsafe { SHChangeNotify(SHCNE_ASSOCCHANGED, 0, std::ptr::null(), std::ptr::null()) };
}

/// Reads a string value under HKEY_CURRENT_USER.
#[cfg(windows)]
fn reg_get(key: &str, name: &str) -> Option<String> {
    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            hkey: isize,
            subkey: *const u16,
            value: *const u16,
            flags: u32,
            kind: *mut u32,
            data: *mut u16,
            size: *mut u32,
        ) -> i32;
    }
    const HKEY_CURRENT_USER: isize = 0x8000_0001_u32 as i32 as isize;
    const RRF_RT_REG_SZ: u32 = 0x2;
    let key: Vec<u16> = key.encode_utf16().chain([0]).collect();
    let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let mut buf = vec![0u16; 1024];
    let mut size = (buf.len() * 2) as u32;
    // SAFETY: the strings are NUL-terminated, `buf` holds `size` bytes, and the call writes
    // at most that many.
    let rc = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut size,
        )
    };
    if rc != 0 {
        return None;
    }
    let len = (size as usize / 2).saturating_sub(1).min(buf.len());
    Some(String::from_utf16_lossy(&buf[..len])).filter(|s| !s.is_empty())
}

#[cfg(not(windows))]
pub fn state() -> State {
    State::NotInstalled
}
#[cfg(not(windows))]
pub fn install() -> Result<PathBuf, String> {
    Err("installing is only for Windows".into())
}
#[cfg(not(windows))]
pub fn uninstall() -> Result<(), String> {
    Err("installing is only for Windows".into())
}
#[cfg(not(windows))]
pub fn refresh() {}
