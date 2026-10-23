//! The r7z entry in the Windows 11 context menu. Explorer loads this DLL through the r7z
//! package (see `package/AppxManifest.xml`) and asks the command below for its title,
//! icon, state and sub-commands. Each sub-command starts `r7z-gui.exe`, which sits next to
//! this DLL, with the selected paths.
#![cfg(windows)]

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_FAIL, E_NOTIMPL, E_POINTER, HINSTANCE,
    HMODULE, S_FALSE, S_OK,
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
            let path = name.to_string().ok();
            CoTaskMemFree(Some(name.0 as *const c_void));
            path.map(PathBuf::from)
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
    by_name || (name.ends_with(".exe") && r7z::format::exe_has_payload(path))
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

impl Command {
    fn title(&self, paths: &[PathBuf]) -> String {
        match self.kind {
            Kind::Root => "r7z".into(),
            Kind::Open if paths.iter().all(|p| p.is_dir()) => "Open in r7z".into(),
            Kind::Open => "Open with r7z".into(),
            Kind::ExtractHere => "Extract here".into(),
            Kind::ExtractTo => match paths {
                [one] => format!(
                    "Extract to \"{}\\\"",
                    one.file_stem().unwrap_or_default().to_string_lossy()
                ),
                _ => "Extract to…".into(),
            },
            Kind::Test => "Test archive".into(),
            Kind::Convert => "Convert to .7z".into(),
            Kind::Separator => String::new(),
            Kind::Add7z => format!("Add to \"{}.7z\"", r7z::util::archive_base_name(paths)),
            Kind::AddZip => format!("Add to \"{}.zip\"", r7z::util::archive_base_name(paths)),
            Kind::Add => "Add to archive…".into(),
        }
    }

    fn visible(&self, paths: &[PathBuf]) -> bool {
        let archives = !paths.is_empty() && paths.iter().all(|p| is_archive(p));
        let one_archive = paths.len() == 1 && archives;
        let one_folder = paths.len() == 1 && paths[0].is_dir();
        match self.kind {
            Kind::Root | Kind::Add7z | Kind::AddZip | Kind::Add => !paths.is_empty(),
            Kind::Open => one_archive || one_folder,
            Kind::ExtractHere | Kind::ExtractTo => archives,
            Kind::Test => one_archive,
            Kind::Convert => one_archive && !is_7z(&paths[0]),
            // Splits the entries for what is selected from the ones that make an archive.
            Kind::Separator => archives || one_folder,
        }
    }
}

impl IExplorerCommand_Impl for Command_Impl {
    fn GetTitle(&self, items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        dup(&self.title(&selected(items)))
    }

    fn GetIcon(&self, _items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        let exe = gui_exe().ok_or_else(|| windows_core::Error::from(E_FAIL))?;
        dup(&format!("{},0", exe.display()))
    }

    fn GetToolTip(&self, _items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetCanonicalName(&self) -> windows_core::Result<GUID> {
        Err(E_NOTIMPL.into())
    }

    fn GetState(&self, items: Ref<IShellItemArray>, _slow: BOOL) -> windows_core::Result<u32> {
        let state = if self.visible(&selected(items)) {
            ECS_ENABLED
        } else {
            ECS_HIDDEN
        };
        Ok(state.0 as u32)
    }

    fn Invoke(
        &self,
        items: Ref<IShellItemArray>,
        _bind: Ref<IBindCtx>,
    ) -> windows_core::Result<()> {
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
    }

    fn GetFlags(&self) -> windows_core::Result<u32> {
        let flags = match self.kind {
            Kind::Root => ECF_HASSUBCOMMANDS,
            Kind::Separator => ECF_ISSEPARATOR,
            _ => ECF_DEFAULT,
        };
        Ok(flags.0 as u32)
    }

    fn EnumSubCommands(&self) -> windows_core::Result<IEnumExplorerCommand> {
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
    }
}

#[implement(IEnumExplorerCommand)]
struct SubCommands {
    items: Vec<IExplorerCommand>,
    pos: AtomicUsize,
}

impl IEnumExplorerCommand_Impl for SubCommands_Impl {
    fn Next(&self, count: u32, out: *mut Option<IExplorerCommand>, fetched: *mut u32) -> HRESULT {
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
    }

    fn Skip(&self, count: u32) -> windows_core::Result<()> {
        let at = self.pos.load(Ordering::Relaxed) + count as usize;
        self.pos.store(at.min(self.items.len()), Ordering::Relaxed);
        Ok(())
    }

    fn Reset(&self) -> windows_core::Result<()> {
        self.pos.store(0, Ordering::Relaxed);
        Ok(())
    }

    fn Clone(&self) -> windows_core::Result<IEnumExplorerCommand> {
        Ok(SubCommands {
            items: self.items.clone(),
            pos: AtomicUsize::new(self.pos.load(Ordering::Relaxed)),
        }
        .into())
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
    if clsid.is_null() || iid.is_null() || object.is_null() {
        return E_POINTER;
    }
    unsafe { object.write(std::ptr::null_mut()) };
    if unsafe { *clsid } != CLSID_R7Z_MENU {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    let factory: IClassFactory = Factory.into();
    unsafe { factory.query(iid, object) }
}

/// The DLL stays loaded for the life of the host process; Explorer's surrogate is cheap to
/// keep and unloading COM servers early is a common source of crashes.
#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}

#[no_mangle]
pub extern "system" fn DllMain(module: HINSTANCE, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        let _ = MODULE.set(module.0 as usize);
    }
    BOOL::from(true)
}

#[cfg(test)]
mod tests {
    use super::*;
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
