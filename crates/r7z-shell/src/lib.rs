//! The r7z entry in the Windows 11 context menu. Explorer loads this DLL through the r7z
//! package (see `package/AppxManifest.xml`) and asks the command below for its title,
//! icon, state and sub-commands. Each sub-command starts `r7z-gui.exe`, which sits next to
//! this DLL, with the selected paths.
#![cfg(windows)]

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::ffi::OsStringExt;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;
#[cfg(not(test))]
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_FAIL, E_NOTIMPL, E_POINTER, E_UNEXPECTED,
    HINSTANCE, HMODULE, S_FALSE, S_OK,
};
use windows::Win32::System::Com::{CoTaskMemFree, IBindCtx, IClassFactory, IClassFactory_Impl};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::UI::Shell::{
    IEnumExplorerCommand, IEnumExplorerCommand_Impl, IExplorerCommand, IExplorerCommand_Impl,
    IShellItemArray, SHStrDupW, ECF_DEFAULT, ECF_HASSUBCOMMANDS, ECF_ISSEPARATOR, ECS_ENABLED,
    ECS_HIDDEN, SIGDN_FILESYSPATH,
};
use windows_core::{implement, Interface, Ref, BOOL, GUID, HRESULT, HSTRING, PWSTR};

/// Registered in the package manifest for the `r7z` verb (`package/AppxManifest.xml`, or
/// `package/store/AppxManifest.xml` for the Microsoft Store build).
#[cfg(not(feature = "store"))]
const CLSID_R7Z_MENU: GUID = GUID::from_u128(0xf0cd81fa_1491_4776_a237_812d0f379e9d);
#[cfg(feature = "store")]
const CLSID_R7Z_MENU: GUID = GUID::from_u128(0x66a1bda9_0c76_42ff_aad9_95b64d70eb8b);

static MODULE: OnceLock<usize> = OnceLock::new();

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Root,
    Open,
    ExtractHere,
    ExtractTo,
    Test,
    Convert,
    Separator,
    Add7z,
    AddZip,
    Add,
}

/// The submenu, in order. Entries that don't apply to the selection are hidden.
const SUBMENU: [Kind; 9] = [
    Kind::Open,
    Kind::ExtractHere,
    Kind::ExtractTo,
    Kind::Test,
    Kind::Convert,
    Kind::Separator,
    Kind::Add7z,
    Kind::AddZip,
    Kind::Add,
];

/// The folder this DLL was loaded from, which also holds `r7z-gui.exe`.
fn install_dir() -> Option<PathBuf> {
    let module = HMODULE(*MODULE.get()? as *mut c_void);
    let mut buf = vec![0u16; 1024];
    let n = unsafe { GetModuleFileNameW(Some(module), &mut buf) } as usize;
    if n == 0 || n >= buf.len() {
        return None;
    }
    PathBuf::from(String::from_utf16_lossy(&buf[..n]))
        .parent()
        .map(Path::to_path_buf)
}

fn gui_exe() -> Option<PathBuf> {
    Some(install_dir()?.join("r7z-gui.exe"))
}

/// File-system paths of the selected items; items without one (Control Panel, Recycle
/// Bin contents) are left out.
fn selected(items: Ref<IShellItemArray>) -> Vec<PathBuf> {
    let Some(items) = items.as_ref() else {
        return Vec::new();
    };
    let count = unsafe { items.GetCount() }.unwrap_or(0);
    (0..count)
        .filter_map(|i| unsafe {
            let name = items
                .GetItemAt(i)
                .ok()?
                .GetDisplayName(SIGDN_FILESYSPATH)
                .ok()?;
            // From the UTF-16 itself: a name that isn't valid Unicode is still a path.
            let path = std::ffi::OsString::from_wide(name.as_wide());
            CoTaskMemFree(Some(name.0 as *const c_void));
            Some(PathBuf::from(path))
        })
        .collect()
}

/// Whether r7z opens files with this name, by the extensions in its format table.
fn is_archive(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let by_name = r7z::format::EXTENSIONS.iter().any(|exts| {
        exts.iter()
            .any(|e| name.ends_with(&format!(".{}", e.trim_start_matches('.').to_lowercase())))
    });
    // A program is an archive only when it carries an installer or self-extractor payload.
    by_name || (name.ends_with(".exe") && exe_payload(path))
}

/// Plain reads of a bounded part of the file: a full scan of a large program would freeze
/// the menu, and a mapped file that vanishes from a share or USB drive would crash Explorer.
fn exe_payload(path: &Path) -> bool {
    let Ok(file) = File::open(path) else {
        return false;
    };
    #[cfg(test)]
    tests::SNIFFS.with(|n| n.set(n.get() + 1));
    #[cfg(test)]
    let file = tests::Counted(file);
    let mut file = file;
    r7z::format::exe_may_have_payload_bounded(&mut file).unwrap_or(false)
}

/// A selection with each item's size and modified time, so a file changed since is looked
/// at again.
type Selection = Vec<(PathBuf, Option<(u64, Option<SystemTime>)>)>;

fn selection(paths: &[PathBuf]) -> Selection {
    paths
        .iter()
        .map(|p| {
            let meta = std::fs::metadata(p).ok();
            (p.clone(), meta.map(|m| (m.len(), m.modified().ok())))
        })
        .collect()
}

/// The last selection asked about and whether it is all archives: Explorer asks the root
/// and then each entry about the same selection.
fn with_last<T>(f: impl FnOnce(&mut Option<(Selection, bool)>) -> T) -> T {
    #[cfg(not(test))]
    {
        static LAST: Mutex<Option<(Selection, bool)>> = Mutex::new(None);
        f(&mut LAST.lock().unwrap_or_else(PoisonError::into_inner))
    }
    // Tests run in parallel, each with its own last selection.
    #[cfg(test)]
    {
        thread_local!(static LAST: std::cell::RefCell<Option<(Selection, bool)>> =
            const { std::cell::RefCell::new(None) });
        LAST.with_borrow_mut(f)
    }
}

/// Whether every selected item is an archive r7z opens, worked out once per selection.
fn archives(paths: &[PathBuf]) -> bool {
    if paths.is_empty() {
        return false;
    }
    let key = selection(paths);
    if let Some(known) = with_last(|last| last.as_ref().filter(|l| l.0 == key).map(|l| l.1)) {
        return known;
    }
    // Not under the lock, so another thread's menu does not wait for these reads.
    let answer = paths.iter().all(|p| is_archive(p));
    with_last(|last| *last = Some((key, answer)));
    answer
}

/// Runs a COM method's body and turns a panic into a failed call: a panic that unwound into
/// Explorer's frames would abort Explorer.
fn guard<T>(body: impl FnOnce() -> windows_core::Result<T>) -> windows_core::Result<T> {
    std::panic::catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|_| Err(E_UNEXPECTED.into()))
}

fn guard_hr(body: impl FnOnce() -> HRESULT) -> HRESULT {
    std::panic::catch_unwind(AssertUnwindSafe(body)).unwrap_or(E_UNEXPECTED)
}

fn is_7z(path: &Path) -> bool {
    path.extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("7z"))
}

fn dup(s: &str) -> windows_core::Result<PWSTR> {
    unsafe { SHStrDupW(&HSTRING::from(s)) }
}

#[implement(IExplorerCommand)]
struct Command {
    kind: Kind,
}

/// Whether a Windows display language reads Simplified Chinese. Traditional Chinese readers
/// get English rather than the wrong script.
fn chinese_language(id: u16) -> bool {
    matches!(id, 0x0804 | 0x1004 | 0x0004 | 0x7804)
}

/// The menu runs inside Explorer, so it follows Windows and not the app's own Language
/// setting, which a Store install keeps in storage only the app can read.
fn windows_is_chinese() -> bool {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetUserDefaultUILanguage() -> u16;
    }
    // SAFETY: takes no arguments and only returns a language ID.
    chinese_language(unsafe { GetUserDefaultUILanguage() })
}

fn title(kind: Kind, paths: &[PathBuf], chinese: bool) -> String {
    let base = || r7z::util::archive_base_name(paths);
    let stem = |one: &PathBuf| {
        one.file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    };
    if chinese {
        return match kind {
            Kind::Root => "r7z".into(),
            Kind::Open if paths.iter().all(|p| p.is_dir()) => "在 r7z 中打开".into(),
            Kind::Open => "用 r7z 打开".into(),
            Kind::ExtractHere => "解压到此处".into(),
            Kind::ExtractTo => match paths {
                [one] => format!("解压到“{}\\”", stem(one)),
                _ => "解压到…".into(),
            },
            Kind::Test => "测试压缩包".into(),
            Kind::Convert => "转换为 .7z".into(),
            Kind::Separator => String::new(),
            Kind::Add7z => format!("添加到“{}.7z”", base()),
            Kind::AddZip => format!("添加到“{}.zip”", base()),
            Kind::Add => "添加到压缩包…".into(),
        };
    }
    match kind {
        Kind::Root => "r7z".into(),
        Kind::Open if paths.iter().all(|p| p.is_dir()) => "Open in r7z".into(),
        Kind::Open => "Open with r7z".into(),
        Kind::ExtractHere => "Extract here".into(),
        Kind::ExtractTo => match paths {
            [one] => format!("Extract to \"{}\\\"", stem(one)),
            _ => "Extract to…".into(),
        },
        Kind::Test => "Test archive".into(),
        Kind::Convert => "Convert to .7z".into(),
        Kind::Separator => String::new(),
        Kind::Add7z => format!("Add to \"{}.7z\"", base()),
        Kind::AddZip => format!("Add to \"{}.zip\"", base()),
        Kind::Add => "Add to archive…".into(),
    }
}

impl Command {
    fn title(&self, paths: &[PathBuf]) -> String {
        title(self.kind, paths, windows_is_chinese())
    }

    fn visible(&self, paths: &[PathBuf]) -> bool {
        // Asked only by the entries that depend on it, since it may read the files.
        let one_archive = || paths.len() == 1 && archives(paths);
        let one_folder = || paths.len() == 1 && paths[0].is_dir();
        match self.kind {
            Kind::Root | Kind::Add7z | Kind::AddZip | Kind::Add => !paths.is_empty(),
            Kind::Open => one_folder() || one_archive(),
            Kind::ExtractHere | Kind::ExtractTo => archives(paths),
            Kind::Test => one_archive(),
            Kind::Convert => one_archive() && !is_7z(&paths[0]),
            // Splits the entries for what is selected from the ones that make an archive.
            Kind::Separator => one_folder() || archives(paths),
        }
    }
}

impl IExplorerCommand_Impl for Command_Impl {
    fn GetTitle(&self, items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        guard(|| dup(&self.title(&selected(items))))
    }

    fn GetIcon(&self, _items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        guard(|| {
            let exe = gui_exe().ok_or_else(|| windows_core::Error::from(E_FAIL))?;
            dup(&format!("{},0", exe.display()))
        })
    }

    fn GetToolTip(&self, _items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetCanonicalName(&self) -> windows_core::Result<GUID> {
        Err(E_NOTIMPL.into())
    }

    fn GetState(&self, items: Ref<IShellItemArray>, _slow: BOOL) -> windows_core::Result<u32> {
        guard(|| {
            let state = if self.visible(&selected(items)) {
                ECS_ENABLED
            } else {
                ECS_HIDDEN
            };
            Ok(state.0 as u32)
        })
    }

    fn Invoke(
        &self,
        items: Ref<IShellItemArray>,
        _bind: Ref<IBindCtx>,
    ) -> windows_core::Result<()> {
        guard(|| {
            let paths = selected(items);
            let exe = gui_exe().ok_or_else(|| windows_core::Error::from(E_FAIL))?;
            let flag = match self.kind {
                Kind::Root | Kind::Separator => return Ok(()),
                Kind::Open => None,
                Kind::ExtractHere => Some("--extract-here"),
                Kind::ExtractTo => Some("--extract-to"),
                Kind::Test => Some("--test"),
                Kind::Convert => Some("--convert"),
                Kind::Add7z => Some("--add-7z"),
                Kind::AddZip => Some("--add-zip"),
                Kind::Add => Some("--add"),
            };
            let mut cmd = std::process::Command::new(exe);
            cmd.args(flag).args(&paths);
            cmd.spawn()
                .map(drop)
                .map_err(|_| windows_core::Error::from(E_FAIL))
        })
    }

    fn GetFlags(&self) -> windows_core::Result<u32> {
        guard(|| {
            let flags = match self.kind {
                Kind::Root => ECF_HASSUBCOMMANDS,
                Kind::Separator => ECF_ISSEPARATOR,
                _ => ECF_DEFAULT,
            };
            Ok(flags.0 as u32)
        })
    }

    fn EnumSubCommands(&self) -> windows_core::Result<IEnumExplorerCommand> {
        guard(|| {
            if self.kind != Kind::Root {
                return Err(E_NOTIMPL.into());
            }
            Ok(SubCommands {
                items: SUBMENU
                    .into_iter()
                    .map(|kind| Command { kind }.into())
                    .collect(),
                pos: AtomicUsize::new(0),
            }
            .into())
        })
    }
}

#[implement(IEnumExplorerCommand)]
struct SubCommands {
    items: Vec<IExplorerCommand>,
    pos: AtomicUsize,
}

impl IEnumExplorerCommand_Impl for SubCommands_Impl {
    fn Next(&self, count: u32, out: *mut Option<IExplorerCommand>, fetched: *mut u32) -> HRESULT {
        guard_hr(|| {
            if out.is_null() {
                return E_POINTER;
            }
            let mut n = 0usize;
            while n < count as usize {
                let at = self.pos.load(Ordering::Relaxed);
                let Some(item) = self.items.get(at) else {
                    break;
                };
                // SAFETY: Explorer passes room for `count` interface pointers.
                unsafe { out.add(n).write(Some(item.clone())) };
                self.pos.store(at + 1, Ordering::Relaxed);
                n += 1;
            }
            if !fetched.is_null() {
                // SAFETY: checked for null above; Explorer owns the location.
                unsafe { fetched.write(n as u32) };
            }
            if n == count as usize {
                S_OK
            } else {
                S_FALSE
            }
        })
    }

    fn Skip(&self, count: u32) -> windows_core::Result<()> {
        guard(|| {
            let at = self.pos.load(Ordering::Relaxed) + count as usize;
            self.pos.store(at.min(self.items.len()), Ordering::Relaxed);
            Ok(())
        })
    }

    fn Reset(&self) -> windows_core::Result<()> {
        guard(|| {
            self.pos.store(0, Ordering::Relaxed);
            Ok(())
        })
    }

    fn Clone(&self) -> windows_core::Result<IEnumExplorerCommand> {
        guard(|| {
            Ok(SubCommands {
                items: self.items.clone(),
                pos: AtomicUsize::new(self.pos.load(Ordering::Relaxed)),
            }
            .into())
        })
    }
}

#[implement(IClassFactory)]
struct Factory;

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<windows_core::IUnknown>,
        iid: *const GUID,
        object: *mut *mut c_void,
    ) -> windows_core::Result<()> {
        guard(|| {
            if object.is_null() || iid.is_null() {
                return Err(E_POINTER.into());
            }
            // SAFETY: checked for null above.
            unsafe { object.write(std::ptr::null_mut()) };
            if outer.is_some() {
                return Err(CLASS_E_NOAGGREGATION.into());
            }
            let command: IExplorerCommand = Command { kind: Kind::Root }.into();
            // SAFETY: `iid` and `object` are valid per the IClassFactory contract.
            unsafe { command.query(iid, object).ok() }
        })
    }

    fn LockServer(&self, _lock: BOOL) -> windows_core::Result<()> {
        Ok(())
    }
}

/// COM entry point: hands out the class factory for the r7z menu command.
///
/// # Safety
/// Called by COM with valid pointers, as for every in-process server.
#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    clsid: *const GUID,
    iid: *const GUID,
    object: *mut *mut c_void,
) -> HRESULT {
    guard_hr(|| {
        if clsid.is_null() || iid.is_null() || object.is_null() {
            return E_POINTER;
        }
        unsafe { object.write(std::ptr::null_mut()) };
        if unsafe { *clsid } != CLSID_R7Z_MENU {
            return CLASS_E_CLASSNOTAVAILABLE;
        }
        let factory: IClassFactory = Factory.into();
        unsafe { factory.query(iid, object) }
    })
}

/// The DLL stays loaded for the life of the host process; Explorer's surrogate is cheap to
/// keep and unloading COM servers early is a common source of crashes.
#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}

#[no_mangle]
pub extern "system" fn DllMain(module: HINSTANCE, reason: u32, _reserved: *mut c_void) -> BOOL {
    let attached = std::panic::catch_unwind(|| {
        if reason == DLL_PROCESS_ATTACH {
            let _ = MODULE.set(module.0 as usize);
        }
    });
    BOOL::from(attached.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{Read, Seek, SeekFrom, Write};
    use windows::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED};
    use windows::Win32::UI::Shell::Common::ITEMIDLIST;
    use windows::Win32::UI::Shell::{SHCreateShellItemArrayFromIDLists, SHParseDisplayName};
    use windows_core::PCWSTR;

    /// The submenu Explorer shows for `paths`, read through the same COM calls Explorer
    /// makes: visible entries by title, with "-" for a separator.
    fn menu(paths: &[PathBuf]) -> Vec<String> {
        unsafe {
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
            let pidls: Vec<*const ITEMIDLIST> = paths
                .iter()
                .map(|p| {
                    let wide = HSTRING::from(p.as_os_str());
                    let mut pidl = std::ptr::null_mut();
                    SHParseDisplayName(PCWSTR(wide.as_ptr()), None, &mut pidl, 0, None).unwrap();
                    pidl as *const ITEMIDLIST
                })
                .collect();
            let items: IShellItemArray = SHCreateShellItemArrayFromIDLists(&pidls).unwrap();
            let root: IExplorerCommand = Command { kind: Kind::Root }.into();
            assert_eq!(root.GetState(&items, false).unwrap(), ECS_ENABLED.0 as u32);
            let list = root.EnumSubCommands().unwrap();
            let mut out = Vec::new();
            loop {
                let mut one = [None];
                let mut got = 0;
                let _ = list.Next(&mut one, Some(&mut got));
                let Some(cmd) = one[0].take().filter(|_| got == 1) else {
                    break;
                };
                if cmd.GetState(&items, false).unwrap() == ECS_HIDDEN.0 as u32 {
                    continue;
                }
                if cmd.GetFlags().unwrap() == ECF_ISSEPARATOR.0 as u32 {
                    out.push("-".to_string());
                    continue;
                }
                let title = cmd.GetTitle(&items).unwrap();
                out.push(title.to_string().unwrap());
                CoTaskMemFree(Some(title.0 as *const c_void));
            }
            for p in pidls {
                CoTaskMemFree(Some(p as *const c_void));
            }
            out
        }
    }

    thread_local! {
        /// Files sniffed and bytes read on this thread, for the tests that pin the bounds.
        pub(super) static SNIFFS: Cell<u32> = const { Cell::new(0) };
        pub(super) static READ: Cell<u64> = const { Cell::new(0) };
    }

    /// Counts the bytes read through it into `READ`.
    pub(super) struct Counted<R>(pub R);

    impl<R: Read> Read for Counted<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.0.read(buf)?;
            READ.with(|r| r.set(r.get() + n as u64));
            Ok(n)
        }
    }

    impl<R: Seek> Seek for Counted<R> {
        fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
            self.0.seek(to)
        }
    }

    fn counts() -> (u32, u64) {
        (SNIFFS.get(), READ.get())
    }

    fn fixture(rel: &str) -> Vec<u8> {
        std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../r7z/tests/fixtures")
                .join(rel),
        )
        .unwrap()
    }

    fn scratch(test: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("r7z-shell-{test}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Writes `data` to `path`, then grows it with zeros (sparse on most volumes) to `len`
    /// bytes and puts `trailer` at the end.
    fn write_padded(path: &Path, data: &[u8], len: u64, trailer: &[u8]) {
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(data).unwrap();
        f.set_len(len - trailer.len() as u64).unwrap();
        f.seek(SeekFrom::End(0)).unwrap();
        f.write_all(trailer).unwrap();
    }

    const BOUND: u64 = r7z::format::PAYLOAD_HEAD + r7z::format::PAYLOAD_OVERLAY;

    /// The root and every entry ask about the same selection: one look at the file answers
    /// them all, in a bounded read, and asking again reads nothing.
    #[test]
    fn a_program_is_sniffed_once_per_selection_within_the_bound() {
        let dir = scratch("once");
        let exe = dir.join("big.exe");
        write_padded(&exe, &fixture("pe/resources.exe"), 4 << 20, b"");
        let adds = ["Add to \"big.7z\"", "Add to \"big.zip\"", "Add to archive…"];
        assert_eq!(menu(std::slice::from_ref(&exe)), adds);
        let (sniffs, read) = counts();
        assert_eq!(sniffs, 1, "files sniffed for one menu");
        assert!(
            read > 0 && read <= BOUND,
            "read {read} bytes, bound {BOUND}"
        );
        assert_eq!(menu(std::slice::from_ref(&exe)), adds);
        assert_eq!(
            counts(),
            (sniffs, read),
            "the second menu read the file again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A payload marker past the bound is not searched for, however large the overlay.
    #[test]
    fn the_overlay_is_searched_only_up_to_the_bound() {
        let dir = scratch("bound");
        let exe = dir.join("late.exe");
        write_padded(&exe, &fixture("pe/resources.exe"), 4 << 20, b"PK");
        assert!(!archives(std::slice::from_ref(&exe)));
        let (_, read) = counts();
        assert!(
            read > 0 && read <= BOUND,
            "read {read} bytes, bound {BOUND}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Installers and self-extractors keep their payload right after the stub, so a long
    /// file is still recognized from its first bytes.
    #[test]
    fn payloads_after_the_stub_are_seen_in_long_files() {
        let dir = scratch("payloads");
        let long = BOUND + (1 << 20);
        for (name, data, expect) in [
            ("sfx.exe", fixture("pe/sfx-zip.exe"), true),
            (
                "nsis.exe",
                fixture("nsis/nsis3-unicode-solid-lzma.bin"),
                true,
            ),
            ("plain.exe", fixture("pe/resources.exe"), false),
        ] {
            for len in [data.len() as u64, long] {
                let path = dir.join(format!("{len}-{name}"));
                write_padded(&path, &data, len, b"");
                assert_eq!(
                    archives(std::slice::from_ref(&path)),
                    expect,
                    "{name}, {len} bytes"
                );
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The answer is kept per selection and per file state: a file rewritten since is
    /// looked at again.
    #[test]
    fn a_changed_file_is_sniffed_again() {
        let dir = scratch("changed");
        let exe = dir.join("setup.exe");
        let one = std::slice::from_ref(&exe);
        std::fs::write(&exe, fixture("pe/resources.exe")).unwrap();
        assert!(!archives(one));
        assert!(!archives(one));
        let (sniffs, _) = counts();
        std::fs::write(&exe, fixture("pe/sfx-zip.exe")).unwrap();
        assert!(archives(one));
        assert_eq!(counts().0, sniffs + 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A panic in a method comes back to Explorer as a failed call, not an abort.
    #[test]
    fn a_panic_is_a_failed_call() {
        let r: windows_core::Result<u32> = guard(|| panic!("a bug in a menu method"));
        assert_eq!(r.unwrap_err().code(), E_UNEXPECTED);
        assert_eq!(guard_hr(|| panic!("a bug in an export")), E_UNEXPECTED);
    }

    #[test]
    fn labels_follow_the_windows_language() {
        let files = [PathBuf::from("Backup.zip")];
        assert_eq!(title(Kind::ExtractHere, &files, false), "Extract here");
        assert_eq!(title(Kind::ExtractHere, &files, true), "解压到此处");
        assert_eq!(title(Kind::Add, &files, true), "添加到压缩包…");
        assert_eq!(title(Kind::ExtractTo, &files, true), "解压到“Backup\\”");
        assert_eq!(title(Kind::Add7z, &files, true), "添加到“Backup.7z”");
    }

    #[test]
    fn only_simplified_chinese_windows_gets_chinese_labels() {
        for id in [0x0804, 0x1004, 0x0004, 0x7804] {
            assert!(chinese_language(id), "{id:#x}");
        }
        // English, Traditional Chinese, Japanese.
        for id in [0x0409, 0x0404, 0x0C04, 0x0411] {
            assert!(!chinese_language(id), "{id:#x}");
        }
    }

    #[test]
    fn submenu_fits_the_selection() {
        let dir = std::env::temp_dir().join(format!("r7z-shell-test-{}", std::process::id()));
        let photos = dir.join("Photos");
        std::fs::create_dir_all(&photos).unwrap();
        for f in ["Backup.zip", "Old.7z", "notes.txt"] {
            std::fs::write(dir.join(f), b"").unwrap();
        }
        let p = |n: &str| dir.join(n);

        assert_eq!(
            menu(&[p("Backup.zip")]),
            [
                "Open with r7z",
                "Extract here",
                "Extract to \"Backup\\\"",
                "Test archive",
                "Convert to .7z",
                "-",
                "Add to \"Backup.7z\"",
                "Add to \"Backup.zip\"",
                "Add to archive…",
            ]
        );
        // Already a .7z: nothing to convert to.
        assert!(!menu(&[p("Old.7z")]).contains(&"Convert to .7z".to_string()));
        assert_eq!(
            menu(std::slice::from_ref(&photos)),
            [
                "Open in r7z",
                "-",
                "Add to \"Photos.7z\"",
                "Add to \"Photos.zip\"",
                "Add to archive…",
            ]
        );
        assert_eq!(
            menu(&[p("notes.txt")]),
            [
                "Add to \"notes.7z\"",
                "Add to \"notes.zip\"",
                "Add to archive…",
            ]
        );
        // Several items: the archive is named after their folder.
        let folder = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(
            menu(&[p("notes.txt"), photos.clone()]),
            [
                format!("Add to \"{folder}.7z\""),
                format!("Add to \"{folder}.zip\""),
                "Add to archive…".to_string(),
            ]
        );
        assert_eq!(
            menu(&[p("Backup.zip"), p("Old.7z")]),
            [
                "Extract here".to_string(),
                "Extract to…".to_string(),
                "-".to_string(),
                format!("Add to \"{folder}.7z\""),
                format!("Add to \"{folder}.zip\""),
                "Add to archive…".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
