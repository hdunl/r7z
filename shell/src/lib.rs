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
    IShellItemArray, SHStrDupW, ECF_DEFAULT, ECF_HASSUBCOMMANDS, ECS_ENABLED, ECS_HIDDEN,
    SIGDN_FILESYSPATH,
};
use windows_core::{implement, Interface, Ref, BOOL, GUID, HRESULT, HSTRING, PWSTR};

/// Registered in the package manifest for the `r7z` verb.
const CLSID_R7Z_MENU: GUID = GUID::from_u128(0xf0cd81fa_1491_4776_a237_812d0f379e9d);

static MODULE: OnceLock<usize> = OnceLock::new();

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Root,
    Open,
    ExtractHere,
    ExtractTo,
    Add,
}

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
    r7z::format::FORMATS.iter().any(|f| {
        f.extensions
            .iter()
            .any(|e| name.ends_with(&format!(".{}", e.trim_start_matches('.').to_lowercase())))
    })
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
            Kind::Open => "Open with r7z".into(),
            Kind::ExtractHere => "Extract here".into(),
            Kind::ExtractTo => match paths {
                [one] => format!(
                    "Extract to \"{}\\\"",
                    one.file_stem().unwrap_or_default().to_string_lossy()
                ),
                _ => "Extract to…".into(),
            },
            Kind::Add => "Add to archive…".into(),
        }
    }

    fn visible(&self, paths: &[PathBuf]) -> bool {
        let archives = !paths.is_empty() && paths.iter().all(|p| is_archive(p));
        match self.kind {
            Kind::Root | Kind::Add => !paths.is_empty(),
            Kind::Open => paths.len() == 1 && archives,
            Kind::ExtractHere | Kind::ExtractTo => archives,
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
            Kind::Root => return Ok(()),
            Kind::Open => None,
            Kind::ExtractHere => Some("--extract-here"),
            Kind::ExtractTo => Some("--extract-to"),
            Kind::Add => Some("--add"),
        };
        let mut cmd = std::process::Command::new(exe);
        cmd.args(flag).args(&paths);
        cmd.spawn()
            .map(drop)
            .map_err(|_| windows_core::Error::from(E_FAIL))
    }

    fn GetFlags(&self) -> windows_core::Result<u32> {
        let flags = if self.kind == Kind::Root {
            ECF_HASSUBCOMMANDS
        } else {
            ECF_DEFAULT
        };
        Ok(flags.0 as u32)
    }

    fn EnumSubCommands(&self) -> windows_core::Result<IEnumExplorerCommand> {
        if self.kind != Kind::Root {
            return Err(E_NOTIMPL.into());
        }
        let kinds = [Kind::Open, Kind::ExtractHere, Kind::ExtractTo, Kind::Add];
        Ok(SubCommands {
            items: kinds
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
