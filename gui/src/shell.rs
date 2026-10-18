//! Operating-system glue: launching files, Explorer integration, small settings files.

use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(windows)]
fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Opens a file or folder with its default handler.
#[cfg(windows)]
pub fn open_path(p: &Path) {
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(
            hwnd: isize,
            op: *const u16,
            file: *const u16,
            params: *const u16,
            dir: *const u16,
            show: i32,
        ) -> isize;
    }
    let op = wide(std::ffi::OsStr::new("open"));
    let file = wide(p.as_os_str());
    // SAFETY: both strings are NUL-terminated and outlive the call; null pointers are allowed.
    unsafe {
        ShellExecuteW(
            0,
            op.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        );
    }
}

#[cfg(not(windows))]
pub fn open_path(p: &Path) {
    let _ = Command::new(if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    })
    .arg(p)
    .spawn();
}

pub fn config_dir() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("r7z"))
}

pub fn load_recent() -> Vec<PathBuf> {
    let Some(d) = config_dir() else {
        return Vec::new();
    };
    std::fs::read_to_string(d.join("recent.txt"))
        .map(|s| {
            s.lines()
                .filter(|l| !l.is_empty())
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

pub fn save_recent(list: &[PathBuf]) {
    if let Some(d) = config_dir() {
        let _ = std::fs::create_dir_all(&d);
        let text = list.iter().fold(String::new(), |mut s, p| {
            s.push_str(&p.display().to_string());
            s.push('\n');
            s
        });
        let _ = std::fs::write(d.join("recent.txt"), text);
    }
}

pub fn load_setting(key: &str) -> Option<String> {
    let d = config_dir()?;
    let s = std::fs::read_to_string(d.join("settings.txt")).ok()?;
    s.lines()
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .map(|(_, v)| v.trim().to_string())
}

pub fn save_setting(key: &str, value: &str) {
    let Some(d) = config_dir() else { return };
    let _ = std::fs::create_dir_all(&d);
    let path = d.join("settings.txt");
    let mut lines: Vec<String> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.split_once('=').is_none_or(|(k, _)| k.trim() != key))
        .map(str::to_string)
        .collect();
    lines.push(format!("{key}={value}"));
    let _ = std::fs::write(path, lines.join("\n") + "\n");
}

/// Per-process scratch folder for files opened from an archive.
pub fn temp_dir() -> PathBuf {
    std::env::temp_dir().join(format!("r7z-gui-{}", std::process::id()))
}

/// Backups of files replaced by an extract, one folder per job. Kept apart from
/// `temp_dir()`, which is removed when the app closes; `undo::prune` decides what goes.
pub fn undo_backups() -> PathBuf {
    std::env::temp_dir().join("r7z-undo")
}

#[cfg(windows)]
pub fn reg(args: &[&str]) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    Command::new("reg")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Explorer context-menu verbs, registered per user (HKCU, no administrator rights).
#[cfg(windows)]
const VERBS: &[(&str, &str, &str, &str)] = &[
    ("*", "r7z.open", "Open with r7z", ""),
    (
        "*",
        "r7z.extracthere",
        "Extract here (r7z)",
        "--extract-here ",
    ),
    (
        "*",
        "r7z.extractto",
        "Extract to folder (r7z)",
        "--extract-to ",
    ),
    ("*", "r7z.add", "Add to archive… (r7z)", "--add "),
    ("Directory", "r7z.add", "Add to archive… (r7z)", "--add "),
];

#[cfg(windows)]
pub fn explorer_installed() -> bool {
    reg(&["query", r"HKCU\Software\Classes\*\shell\r7z.open"])
}

#[cfg(windows)]
pub fn install_explorer() -> bool {
    std::env::current_exe().is_ok_and(|exe| install_explorer_for(&exe))
}

/// Adds the classic menu verbs, starting `exe`.
#[cfg(windows)]
pub fn install_explorer_for(exe: &Path) -> bool {
    let exe = exe.display().to_string();
    let mut ok = true;
    for (class, key, label, flag) in VERBS {
        let base = format!(r"HKCU\Software\Classes\{class}\shell\{key}");
        let cmd = format!("\"{exe}\" {flag}\"%1\"");
        ok &= reg(&["add", &base, "/v", "MUIVerb", "/d", label, "/f"]);
        ok &= reg(&["add", &base, "/v", "Icon", "/d", &exe, "/f"]);
        ok &= reg(&["add", &format!(r"{base}\command"), "/ve", "/d", &cmd, "/f"]);
    }
    ok
}

#[cfg(windows)]
pub fn uninstall_explorer() -> bool {
    let mut ok = true;
    for (class, key, _, _) in VERBS {
        let base = format!(r"HKCU\Software\Classes\{class}\shell\{key}");
        if reg(&["query", &base]) {
            ok &= reg(&["delete", &base, "/f"]);
        }
    }
    ok
}

#[cfg(not(windows))]
pub fn explorer_installed() -> bool {
    false
}
#[cfg(not(windows))]
pub fn install_explorer() -> bool {
    false
}
#[cfg(not(windows))]
pub fn uninstall_explorer() -> bool {
    false
}

/// Whether r7z is in Windows 11's main context menu, which (unlike the classic menu)
/// only shows commands from packaged apps: r7z registers a sparse package that points at
/// `r7z_shell.dll` next to the program.
#[derive(Clone, Debug, PartialEq)]
pub enum ModernMenu {
    Installed,
    /// This copy of r7z can register it.
    Available,
    /// The menu's files are missing from this copy (it was updated by a version that only
    /// replaced existing files); they can be fetched from this version's release.
    Missing,
    /// It cannot be registered; the reason is shown in Settings.
    Unavailable(String),
}

#[cfg(windows)]
pub fn powershell(script: &str) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(err
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty())
            .unwrap_or("PowerShell failed")
            .to_string())
    }
}

/// A path as a single-quoted PowerShell string.
#[cfg(windows)]
pub fn ps_path(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', "''"))
}

#[cfg(windows)]
fn reg_value(key: &str, name: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = Command::new("reg")
        .args(["query", key, "/v", name])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.trim_start().starts_with(name))?;
    line.split_whitespace().last().map(str::to_string)
}

#[cfg(windows)]
fn windows_11() -> bool {
    reg_value(
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
        "CurrentBuild",
    )
    .and_then(|b| b.parse::<u32>().ok())
    .is_some_and(|b| b >= 22000)
}

#[cfg(windows)]
fn developer_mode() -> bool {
    reg_value(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock",
        "AllowDevelopmentWithoutDevLicense",
    )
    .is_some_and(|v| v == "0x1")
}

/// The package next to this program: a signed `r7z-shell.msix` (releases) or the loose
/// `package\AppxManifest.xml` of a development build, which needs Developer Mode.
#[cfg(windows)]
fn modern_menu_package() -> Result<(PathBuf, bool), ModernMenu> {
    let dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
        .ok_or_else(|| ModernMenu::Unavailable("cannot tell where r7z is installed".into()))?;
    modern_menu_package_in(&dir)
}

#[cfg(windows)]
fn modern_menu_package_in(dir: &Path) -> Result<(PathBuf, bool), ModernMenu> {
    if !dir.join("r7z_shell.dll").is_file() {
        return Err(ModernMenu::Missing);
    }
    let msix = dir.join("r7z-shell.msix");
    if msix.is_file() {
        return Ok((msix, true));
    }
    let loose = dir.join("package").join("AppxManifest.xml");
    if loose.is_file() && developer_mode() {
        return Ok((loose, false));
    }
    Err(ModernMenu::Missing)
}

#[cfg(windows)]
pub fn modern_menu_status() -> ModernMenu {
    if !windows_11() {
        return ModernMenu::Unavailable("Windows 10 has only the classic menu.".into());
    }
    let installed =
        powershell("(Get-AppxPackage -Name r7z).Name").is_ok_and(|out| out.trim() == "r7z");
    if installed {
        return ModernMenu::Installed;
    }
    match modern_menu_package() {
        Ok(_) => ModernMenu::Available,
        Err(state) => state,
    }
}

/// Fetches the Windows 11 menu files this copy lacks from this version's release (with
/// the same signed-manifest checks as updates), then registers the menu.
#[cfg(windows)]
pub fn get_modern_menu() -> ModernMenu {
    match crate::update::install_missing(&std::sync::atomic::AtomicBool::new(false)) {
        Ok(_) => install_modern_menu(),
        Err(e) => ModernMenu::Unavailable(format!("Couldn't get the Windows 11 menu: {e}")),
    }
}

#[cfg(windows)]
pub fn install_modern_menu() -> ModernMenu {
    let (package, signed) = match modern_menu_package() {
        Ok(p) => p,
        Err(state) => return state,
    };
    let dir = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(Path::to_path_buf))
        .unwrap_or_default();
    register_modern_menu(&package, signed, &dir, false)
}

/// Points the Windows 11 menu at the copy of r7z in `dir`, replacing a registration for
/// another folder.
#[cfg(windows)]
pub fn move_modern_menu(dir: &Path) -> ModernMenu {
    if !windows_11() {
        return ModernMenu::Unavailable("Windows 10 has only the classic menu.".into());
    }
    match modern_menu_package_in(dir) {
        Ok((package, signed)) => register_modern_menu(&package, signed, dir, true),
        Err(state) => state,
    }
}

#[cfg(windows)]
fn register_modern_menu(package: &Path, signed: bool, dir: &Path, replace: bool) -> ModernMenu {
    let remove = if replace {
        "Get-AppxPackage -Name r7z | Remove-AppxPackage; "
    } else {
        ""
    };
    let add = if signed { "-Path" } else { "-Register" };
    let script = format!(
        "{remove}Add-AppxPackage {add} {} -ExternalLocation {}",
        ps_path(package),
        ps_path(dir)
    );
    match powershell(&script) {
        Ok(_) => modern_menu_status(),
        Err(e) => ModernMenu::Unavailable(format!("Windows refused the menu package: {e}")),
    }
}

#[cfg(windows)]
pub fn uninstall_modern_menu() -> ModernMenu {
    let _ = powershell("Get-AppxPackage -Name r7z | Remove-AppxPackage");
    modern_menu_status()
}

#[cfg(not(windows))]
pub fn modern_menu_status() -> ModernMenu {
    ModernMenu::Unavailable("Only on Windows 11.".into())
}
#[cfg(not(windows))]
pub fn install_modern_menu() -> ModernMenu {
    modern_menu_status()
}
#[cfg(not(windows))]
pub fn uninstall_modern_menu() -> ModernMenu {
    modern_menu_status()
}
#[cfg(not(windows))]
pub fn get_modern_menu() -> ModernMenu {
    modern_menu_status()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Known {
    Home,
    Desktop,
    Downloads,
    Documents,
    Pictures,
}

/// The real location of a user folder (follows OneDrive and policy redirection).
#[cfg(windows)]
pub fn known_folder(k: Known) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    #[repr(C)]
    struct Guid(u32, u16, u16, [u8; 8]);
    #[link(name = "shell32")]
    extern "system" {
        fn SHGetKnownFolderPath(
            id: *const Guid,
            flags: u32,
            token: isize,
            out: *mut *mut u16,
        ) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(p: *mut std::ffi::c_void);
    }
    let id = match k {
        Known::Home => Guid(
            0x5E6C858F,
            0x0E22,
            0x4760,
            [0x9A, 0xFE, 0xEA, 0x33, 0x17, 0xB6, 0x71, 0x73],
        ),
        Known::Desktop => Guid(
            0xB4BFCC3A,
            0xDB2C,
            0x424C,
            [0xB0, 0x29, 0x7F, 0xE9, 0x9A, 0x87, 0xC6, 0x41],
        ),
        Known::Downloads => Guid(
            0x374DE290,
            0x123F,
            0x4565,
            [0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B],
        ),
        Known::Documents => Guid(
            0xFDD39AD0,
            0x238F,
            0x46AF,
            [0xAD, 0xB4, 0x6C, 0x85, 0x48, 0x03, 0x69, 0xC7],
        ),
        Known::Pictures => Guid(
            0x33E28130,
            0x4E1E,
            0x4676,
            [0x83, 0x5A, 0x98, 0x39, 0x5C, 0x3B, 0xC3, 0xBB],
        ),
    };
    let mut out: *mut u16 = std::ptr::null_mut();
    // SAFETY: `out` receives a CoTaskMem string that is freed below; the GUID outlives the call.
    unsafe {
        let hr = SHGetKnownFolderPath(&id, 0, 0, &mut out);
        if hr != 0 || out.is_null() {
            if !out.is_null() {
                CoTaskMemFree(out.cast());
            }
            return None;
        }
        let len = (0..).take_while(|&i| *out.add(i) != 0).count();
        let s = std::ffi::OsString::from_wide(std::slice::from_raw_parts(out, len));
        CoTaskMemFree(out.cast());
        Some(PathBuf::from(s))
    }
}

#[cfg(not(windows))]
pub fn known_folder(k: Known) -> Option<PathBuf> {
    let home = PathBuf::from(std::env::var_os("HOME")?);
    Some(match k {
        Known::Home => home,
        Known::Desktop => home.join("Desktop"),
        Known::Downloads => home.join("Downloads"),
        Known::Documents => home.join("Documents"),
        Known::Pictures => home.join("Pictures"),
    })
}

pub struct Drive {
    pub root: PathBuf,
    pub label: String,
    pub free: u64,
    pub total: u64,
}

#[cfg(windows)]
pub fn drives() -> Vec<Drive> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn GetLogicalDrives() -> u32;
        fn GetDriveTypeW(root: *const u16) -> u32;
        fn GetDiskFreeSpaceExW(
            root: *const u16,
            avail: *mut u64,
            total: *mut u64,
            free: *mut u64,
        ) -> i32;
        fn GetVolumeInformationW(
            root: *const u16,
            name: *mut u16,
            name_len: u32,
            serial: *mut u32,
            max_comp: *mut u32,
            flags: *mut u32,
            fs: *mut u16,
            fs_len: u32,
        ) -> i32;
    }
    let mut out = Vec::new();
    // SAFETY: plain Win32 queries with NUL-terminated inputs and correctly sized out buffers.
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let root = format!("{}:\\", (b'A' + i as u8) as char);
        let w: Vec<u16> = std::ffi::OsStr::new(&root)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let kind = unsafe { GetDriveTypeW(w.as_ptr()) };
        // 2 removable, 3 fixed, 4 network; skip optical drives and unknown types.
        if !matches!(kind, 2..=4) {
            continue;
        }
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        if unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut avail, &mut total, &mut free) } == 0 {
            continue;
        }
        let mut name = [0u16; 128];
        let ok = unsafe {
            GetVolumeInformationW(
                w.as_ptr(),
                name.as_mut_ptr(),
                name.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        let label = if ok != 0 {
            let len = name.iter().position(|&c| c == 0).unwrap_or(0);
            String::from_utf16_lossy(&name[..len])
        } else {
            String::new()
        };
        out.push(Drive {
            root: PathBuf::from(&root),
            label,
            free: avail,
            total,
        });
    }
    out
}

#[cfg(not(windows))]
pub fn drives() -> Vec<Drive> {
    vec![Drive {
        root: PathBuf::from("/"),
        label: String::new(),
        free: 0,
        total: 0,
    }]
}

/// Asks Windows to draw the title bar dark or light to match the app (Windows 10 1809+).
#[cfg(windows)]
pub fn set_title_bar_dark(hwnd: isize, dark: bool) {
    #[link(name = "dwmapi")]
    extern "system" {
        fn DwmSetWindowAttribute(
            hwnd: isize,
            attr: u32,
            value: *const std::ffi::c_void,
            size: u32,
        ) -> i32;
    }
    let v: i32 = dark as i32;
    // SAFETY: DWMWA_USE_IMMERSIVE_DARK_MODE (20) takes a BOOL; the pointer is valid for the call.
    unsafe {
        DwmSetWindowAttribute(hwnd, 20, (&v as *const i32).cast(), 4);
    }
}

#[cfg(not(windows))]
pub fn set_title_bar_dark(_hwnd: isize, _dark: bool) {}

pub fn crash_log_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("crash.log"))
}

/// A blocking native message box, used when the app cannot continue.
#[cfg(windows)]
pub fn fatal_box(title: &str, text: &str) {
    #[link(name = "user32")]
    extern "system" {
        fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, kind: u32) -> i32;
    }
    let t = wide(std::ffi::OsStr::new(text));
    let c = wide(std::ffi::OsStr::new(title));
    // SAFETY: NUL-terminated strings that outlive the call. MB_ICONERROR | MB_OK.
    unsafe {
        MessageBoxW(0, t.as_ptr(), c.as_ptr(), 0x10);
    }
}

#[cfg(not(windows))]
pub fn fatal_box(title: &str, text: &str) {
    eprintln!("{title}: {text}");
}

/// Shows `p` selected in Explorer.
pub fn reveal(p: &Path) {
    if cfg!(windows) {
        let _ = Command::new("explorer")
            .arg(format!("/select,{}", p.display()))
            .spawn();
    } else {
        open_path(p.parent().unwrap_or(p));
    }
}

/// Removes scratch folders left by earlier runs that were killed. Only folders untouched
/// for half a day are removed, so a second running instance is never affected. Also drops
/// undo records beyond the last few and the backups that belonged to them.
pub fn sweep_stale_temp() {
    if let Some(store) = crate::undo::Store::user() {
        crate::undo::prune(&store);
    }
    let mine = temp_dir();
    let Ok(rd) = std::fs::read_dir(std::env::temp_dir()) else {
        return;
    };
    for e in rd.flatten() {
        let path = e.path();
        let stale = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age.as_secs() > 12 * 3600);
        if e.file_name().to_string_lossy().starts_with("r7z-gui-") && path != mine && stale {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}
