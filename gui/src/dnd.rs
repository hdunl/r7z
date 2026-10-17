//! Handing files to other programs: OLE drag and drop and the clipboard, both as CF_HDROP
//! path lists, plus pasting files from the clipboard into a folder.
//!
//! A drag runs on its own thread so the window keeps drawing while files from an archive
//! are still being extracted to the temp folder. That thread shares the window's input
//! state (AttachThreadInput), which lets OLE take over the mouse capture the window holds
//! and see the button go up. When the button goes up before extraction has finished, the
//! drop waits for it (Esc gives up) and only then lets the target copy the files.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::thread::JoinHandle;

pub const COPY: u32 = 1;
pub const MOVE: u32 = 2;
pub const LINK: u32 = 4;

pub struct Drag {
    handle: Option<JoinHandle<u32>>,
}

impl Drag {
    pub fn finished(&self) -> bool {
        self.handle.as_ref().is_none_or(|h| h.is_finished())
    }

    /// The effect the target performed (`COPY`, `MOVE`, `LINK`), or 0 when nothing was dropped.
    pub fn join(&mut self) -> u32 {
        self.handle.take().and_then(|h| h.join().ok()).unwrap_or(0)
    }
}

pub struct DragRequest {
    pub paths: Vec<PathBuf>,
    /// The effects the target may perform.
    pub effects: u32,
    /// The effect Explorer should pick by default, or 0 for its usual choice. Scratch copies
    /// ask for a move so Explorer takes them out of the temp folder.
    pub preferred: u32,
    /// Set while the files are still being written: the drop waits for a message on it,
    /// and a closed channel cancels the drop.
    pub ready: Option<Receiver<()>>,
    /// Set when the drag ends without a drop.
    pub abort: Arc<AtomicBool>,
}

#[cfg(windows)]
pub fn start(req: DragRequest) -> Drag {
    // SAFETY: plain Win32 call.
    let ui_thread = unsafe { imp::GetCurrentThreadId() };
    let handle = std::thread::Builder::new()
        .name("drag".into())
        .spawn(move || imp::run_drag(ui_thread, req))
        .ok();
    Drag { handle }
}

#[cfg(not(windows))]
pub fn start(req: DragRequest) -> Drag {
    let abort = req.abort;
    abort.store(true, std::sync::atomic::Ordering::Relaxed);
    Drag { handle: None }
}

#[cfg(windows)]
pub use imp::{clipboard_files, clipboard_has_files, clipboard_sequence, paste, set_clipboard};

/// True on the frame Ctrl+V goes down. egui swallows the key when the clipboard holds no
/// text, which is exactly the case for copied files, so this reads the key state itself.
#[cfg(windows)]
pub fn paste_pressed(was_down: &mut bool) -> bool {
    const VK_SHIFT: i32 = 0x10;
    const VK_CONTROL: i32 = 0x11;
    const VK_MENU: i32 = 0x12;
    let down = |vk: i32| unsafe { imp::GetKeyState(vk) } < 0;
    let now = down(VK_CONTROL) && down(b'V' as i32) && !down(VK_SHIFT) && !down(VK_MENU);
    let pressed = now && !*was_down;
    *was_down = now;
    pressed
}

#[cfg(not(windows))]
pub fn paste_pressed(_was_down: &mut bool) -> bool {
    false
}
#[cfg(not(windows))]
pub fn set_clipboard(_hwnd: isize, _paths: &[PathBuf]) -> bool {
    false
}
#[cfg(not(windows))]
pub fn clipboard_files() -> Option<(Vec<PathBuf>, bool)> {
    None
}
#[cfg(not(windows))]
pub fn clipboard_has_files() -> bool {
    false
}
#[cfg(not(windows))]
pub fn clipboard_sequence() -> u32 {
    0
}
#[cfg(not(windows))]
pub fn paste(
    _hwnd: isize,
    _files: &[PathBuf],
    _dest: &std::path::Path,
    _cut: bool,
) -> Result<(), String> {
    Err("pasting files is only available on Windows".into())
}

#[cfg(windows)]
mod imp {
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::path::{Path, PathBuf};
    use std::ptr::null_mut;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc::{Receiver, RecvTimeoutError};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[repr(C)]
    #[derive(PartialEq, Eq)]
    struct Guid(u32, u16, u16, [u8; 8]);

    const IID_IUNKNOWN: Guid = Guid(0, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
    const IID_IDATAOBJECT: Guid = Guid(0x10E, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);
    const IID_IDROPSOURCE: Guid = Guid(0x121, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FormatEtc {
        cf: u16,
        ptd: *mut c_void,
        aspect: u32,
        index: i32,
        tymed: u32,
    }

    #[repr(C)]
    struct StgMedium {
        tymed: u32,
        data: *mut c_void,
        release: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Point {
        x: i32,
        y: i32,
    }

    /// SHFILEOPSTRUCTW; packed only on 32-bit Windows.
    #[cfg_attr(target_pointer_width = "32", repr(C, packed(1)))]
    #[cfg_attr(not(target_pointer_width = "32"), repr(C))]
    struct FileOp {
        hwnd: isize,
        func: u32,
        from: *const u16,
        to: *const u16,
        flags: u16,
        aborted: i32,
        mappings: *mut c_void,
        title: *const u16,
    }

    const S_OK: i32 = 0;
    const E_NOTIMPL: i32 = 0x8000_4001_u32 as i32;
    const E_NOINTERFACE: i32 = 0x8000_4002_u32 as i32;
    const E_POINTER: i32 = 0x8000_4003_u32 as i32;
    const E_OUTOFMEMORY: i32 = 0x8007_000E_u32 as i32;
    const E_INVALIDARG: i32 = 0x8007_0057_u32 as i32;
    const DV_E_FORMATETC: i32 = 0x8004_0064_u32 as i32;
    const OLE_E_ADVISENOTSUPPORTED: i32 = 0x8004_0003_u32 as i32;
    const DRAGDROP_S_DROP: i32 = 0x0004_0100;
    const DRAGDROP_S_CANCEL: i32 = 0x0004_0101;
    const DRAGDROP_S_USEDEFAULTCURSORS: i32 = 0x0004_0102;

    const CF_HDROP: u16 = 15;
    const TYMED_HGLOBAL: u32 = 1;
    const DVASPECT_CONTENT: u32 = 1;
    const DATADIR_GET: u32 = 1;
    const MK_LBUTTON: u32 = 1;
    const GHND: u32 = 0x42;
    const VK_ESCAPE: i32 = 0x1B;
    const GA_ROOT: u32 = 2;

    const FO_MOVE: u32 = 1;
    const FO_COPY: u32 = 2;
    const FOF_RENAMEONCOLLISION: u16 = 0x8;
    const FOF_ALLOWUNDO: u16 = 0x40;
    const FOF_NOCONFIRMMKDIR: u16 = 0x200;

    #[link(name = "ole32")]
    extern "system" {
        fn OleInitialize(reserved: *mut c_void) -> i32;
        fn OleUninitialize();
        fn DoDragDrop(data: *mut c_void, source: *mut c_void, ok: u32, effect: *mut u32) -> i32;
    }

    #[link(name = "shell32")]
    extern "system" {
        fn SHCreateStdEnumFmtEtc(n: u32, fmts: *const FormatEtc, out: *mut *mut c_void) -> i32;
        fn DragQueryFileW(drop: *mut c_void, i: u32, buf: *mut u16, len: u32) -> u32;
        fn SHFileOperationW(op: *mut FileOp) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GlobalAlloc(flags: u32, bytes: usize) -> *mut c_void;
        fn GlobalLock(h: *mut c_void) -> *mut c_void;
        fn GlobalUnlock(h: *mut c_void) -> i32;
        fn GlobalFree(h: *mut c_void) -> *mut c_void;
        pub fn GetCurrentThreadId() -> u32;
        fn GetCurrentProcessId() -> u32;
    }

    #[link(name = "user32")]
    extern "system" {
        fn AttachThreadInput(from: u32, to: u32, attach: i32) -> i32;
        fn GetAsyncKeyState(vk: i32) -> i16;
        pub fn GetKeyState(vk: i32) -> i16;
        fn GetCursorPos(p: *mut Point) -> i32;
        fn WindowFromPoint(p: Point) -> isize;
        fn GetAncestor(hwnd: isize, flags: u32) -> isize;
        fn GetWindowThreadProcessId(hwnd: isize, pid: *mut u32) -> u32;
        fn OpenClipboard(hwnd: isize) -> i32;
        fn CloseClipboard() -> i32;
        fn EmptyClipboard() -> i32;
        fn SetClipboardData(fmt: u32, h: *mut c_void) -> *mut c_void;
        fn GetClipboardData(fmt: u32) -> *mut c_void;
        fn IsClipboardFormatAvailable(fmt: u32) -> i32;
        fn RegisterClipboardFormatW(name: *const u16) -> u32;
        fn GetClipboardSequenceNumber() -> u32;
    }

    fn wide_list(paths: &[PathBuf]) -> Vec<u16> {
        let mut text = Vec::new();
        for p in paths {
            text.extend(p.as_os_str().encode_wide());
            text.push(0);
        }
        text.push(0);
        text
    }

    /// A movable global block holding a DROPFILES header and the paths, as CF_HDROP wants.
    fn hdrop(paths: &[PathBuf]) -> *mut c_void {
        let text = wide_list(paths);
        // DROPFILES: offset of the list, drop point (x, y), fNC, fWide.
        let head: [u32; 5] = [20, 0, 0, 0, 1];
        let bytes = 20 + text.len() * 2;
        // SAFETY: the block is allocated with room for the header and the list, locked
        // while it is filled and unlocked before it is handed out.
        unsafe {
            let h = GlobalAlloc(GHND, bytes);
            if h.is_null() {
                return h;
            }
            let p = GlobalLock(h).cast::<u8>();
            if p.is_null() {
                GlobalFree(h);
                return null_mut();
            }
            std::ptr::copy_nonoverlapping(head.as_ptr().cast::<u8>(), p, 20);
            std::ptr::copy_nonoverlapping(text.as_ptr().cast::<u8>(), p.add(20), text.len() * 2);
            GlobalUnlock(h);
            h
        }
    }

    fn hglobal_u32(v: u32) -> *mut c_void {
        // SAFETY: a 4-byte block, filled while locked.
        unsafe {
            let h = GlobalAlloc(GHND, 4);
            if h.is_null() {
                return h;
            }
            let p = GlobalLock(h).cast::<u32>();
            if p.is_null() {
                GlobalFree(h);
                return null_mut();
            }
            p.write_unaligned(v);
            GlobalUnlock(h);
            h
        }
    }

    fn preferred_effect_format() -> u32 {
        let name: Vec<u16> = "Preferred DropEffect\0".encode_utf16().collect();
        // SAFETY: NUL-terminated name.
        unsafe { RegisterClipboardFormatW(name.as_ptr()) }
    }

    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ------------------------------------------------------------------ IDataObject

    #[repr(C)]
    struct DataVtbl {
        query_interface:
            unsafe extern "system" fn(*mut DataObject, *const Guid, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut DataObject) -> u32,
        release: unsafe extern "system" fn(*mut DataObject) -> u32,
        get_data:
            unsafe extern "system" fn(*mut DataObject, *const FormatEtc, *mut StgMedium) -> i32,
        get_data_here:
            unsafe extern "system" fn(*mut DataObject, *const FormatEtc, *mut StgMedium) -> i32,
        query_get_data: unsafe extern "system" fn(*mut DataObject, *const FormatEtc) -> i32,
        get_canonical_format_etc:
            unsafe extern "system" fn(*mut DataObject, *const FormatEtc, *mut FormatEtc) -> i32,
        set_data: unsafe extern "system" fn(
            *mut DataObject,
            *const FormatEtc,
            *mut StgMedium,
            i32,
        ) -> i32,
        enum_format_etc: unsafe extern "system" fn(*mut DataObject, u32, *mut *mut c_void) -> i32,
        d_advise: unsafe extern "system" fn(
            *mut DataObject,
            *const FormatEtc,
            u32,
            *mut c_void,
            *mut u32,
        ) -> i32,
        d_unadvise: unsafe extern "system" fn(*mut DataObject, u32) -> i32,
        enum_d_advise: unsafe extern "system" fn(*mut DataObject, *mut *mut c_void) -> i32,
    }

    #[repr(C)]
    struct DataObject {
        vtbl: &'static DataVtbl,
        refs: AtomicU32,
        files: Arc<Mutex<Vec<PathBuf>>>,
        /// "Preferred DropEffect" value, offered only when not 0.
        preferred: u32,
        cf_preferred: u16,
    }

    static DATA_VTBL: DataVtbl = DataVtbl {
        query_interface: data_query_interface,
        add_ref: data_add_ref,
        release: data_release,
        get_data: data_get_data,
        get_data_here: data_get_data_here,
        query_get_data: data_query_get_data,
        get_canonical_format_etc: data_get_canonical,
        set_data: data_set_data,
        enum_format_etc: data_enum_format_etc,
        d_advise: data_d_advise,
        d_unadvise: data_d_unadvise,
        enum_d_advise: data_enum_d_advise,
    };

    fn hglobal_format(cf: u16) -> FormatEtc {
        FormatEtc {
            cf,
            ptd: null_mut(),
            aspect: DVASPECT_CONTENT,
            index: -1,
            tymed: TYMED_HGLOBAL,
        }
    }

    impl DataObject {
        fn offers(&self, f: &FormatEtc) -> bool {
            let known = f.cf == CF_HDROP || (self.preferred != 0 && f.cf == self.cf_preferred);
            known && f.tymed & TYMED_HGLOBAL != 0 && f.aspect == DVASPECT_CONTENT
        }
    }

    unsafe extern "system" fn data_query_interface(
        this: *mut DataObject,
        iid: *const Guid,
        out: *mut *mut c_void,
    ) -> i32 {
        if out.is_null() || iid.is_null() {
            return E_POINTER;
        }
        if *iid == IID_IUNKNOWN || *iid == IID_IDATAOBJECT {
            data_add_ref(this);
            *out = this.cast();
            S_OK
        } else {
            *out = null_mut();
            E_NOINTERFACE
        }
    }

    unsafe extern "system" fn data_add_ref(this: *mut DataObject) -> u32 {
        (*this).refs.fetch_add(1, Ordering::AcqRel) + 1
    }

    unsafe extern "system" fn data_release(this: *mut DataObject) -> u32 {
        let left = (*this).refs.fetch_sub(1, Ordering::AcqRel) - 1;
        if left == 0 {
            drop(Box::from_raw(this));
        }
        left
    }

    unsafe extern "system" fn data_get_data(
        this: *mut DataObject,
        fmt: *const FormatEtc,
        medium: *mut StgMedium,
    ) -> i32 {
        if fmt.is_null() || medium.is_null() {
            return E_INVALIDARG;
        }
        let me = &*this;
        if !me.offers(&*fmt) {
            return DV_E_FORMATETC;
        }
        let h = if (*fmt).cf == CF_HDROP {
            hdrop(&lock(&me.files))
        } else {
            hglobal_u32(me.preferred)
        };
        if h.is_null() {
            return E_OUTOFMEMORY;
        }
        *medium = StgMedium {
            tymed: TYMED_HGLOBAL,
            data: h,
            release: null_mut(),
        };
        S_OK
    }

    unsafe extern "system" fn data_get_data_here(
        _this: *mut DataObject,
        _fmt: *const FormatEtc,
        _medium: *mut StgMedium,
    ) -> i32 {
        E_NOTIMPL
    }

    unsafe extern "system" fn data_query_get_data(
        this: *mut DataObject,
        fmt: *const FormatEtc,
    ) -> i32 {
        if !fmt.is_null() && (*this).offers(&*fmt) {
            S_OK
        } else {
            DV_E_FORMATETC
        }
    }

    unsafe extern "system" fn data_get_canonical(
        _this: *mut DataObject,
        _fmt: *const FormatEtc,
        out: *mut FormatEtc,
    ) -> i32 {
        if !out.is_null() {
            (*out).ptd = null_mut();
        }
        E_NOTIMPL
    }

    unsafe extern "system" fn data_set_data(
        _this: *mut DataObject,
        _fmt: *const FormatEtc,
        _medium: *mut StgMedium,
        _release: i32,
    ) -> i32 {
        E_NOTIMPL
    }

    unsafe extern "system" fn data_enum_format_etc(
        this: *mut DataObject,
        direction: u32,
        out: *mut *mut c_void,
    ) -> i32 {
        if out.is_null() {
            return E_POINTER;
        }
        if direction != DATADIR_GET {
            *out = null_mut();
            return E_NOTIMPL;
        }
        let me = &*this;
        let formats = [hglobal_format(CF_HDROP), hglobal_format(me.cf_preferred)];
        let n = if me.preferred != 0 { 2 } else { 1 };
        SHCreateStdEnumFmtEtc(n, formats.as_ptr(), out)
    }

    unsafe extern "system" fn data_d_advise(
        _this: *mut DataObject,
        _fmt: *const FormatEtc,
        _flags: u32,
        _sink: *mut c_void,
        _conn: *mut u32,
    ) -> i32 {
        OLE_E_ADVISENOTSUPPORTED
    }

    unsafe extern "system" fn data_d_unadvise(_this: *mut DataObject, _conn: u32) -> i32 {
        OLE_E_ADVISENOTSUPPORTED
    }

    unsafe extern "system" fn data_enum_d_advise(
        _this: *mut DataObject,
        _out: *mut *mut c_void,
    ) -> i32 {
        OLE_E_ADVISENOTSUPPORTED
    }

    // ------------------------------------------------------------------ IDropSource

    #[repr(C)]
    struct SourceVtbl {
        query_interface:
            unsafe extern "system" fn(*mut DropSource, *const Guid, *mut *mut c_void) -> i32,
        add_ref: unsafe extern "system" fn(*mut DropSource) -> u32,
        release: unsafe extern "system" fn(*mut DropSource) -> u32,
        query_continue_drag: unsafe extern "system" fn(*mut DropSource, i32, u32) -> i32,
        give_feedback: unsafe extern "system" fn(*mut DropSource, u32) -> i32,
    }

    #[repr(C)]
    struct DropSource {
        vtbl: &'static SourceVtbl,
        refs: AtomicU32,
        files: Arc<Mutex<Vec<PathBuf>>>,
        ready: Mutex<Option<Receiver<()>>>,
    }

    static SOURCE_VTBL: SourceVtbl = SourceVtbl {
        query_interface: source_query_interface,
        add_ref: source_add_ref,
        release: source_release,
        query_continue_drag: source_query_continue_drag,
        give_feedback: source_give_feedback,
    };

    unsafe extern "system" fn source_query_interface(
        this: *mut DropSource,
        iid: *const Guid,
        out: *mut *mut c_void,
    ) -> i32 {
        if out.is_null() || iid.is_null() {
            return E_POINTER;
        }
        if *iid == IID_IUNKNOWN || *iid == IID_IDROPSOURCE {
            source_add_ref(this);
            *out = this.cast();
            S_OK
        } else {
            *out = null_mut();
            E_NOINTERFACE
        }
    }

    unsafe extern "system" fn source_add_ref(this: *mut DropSource) -> u32 {
        (*this).refs.fetch_add(1, Ordering::AcqRel) + 1
    }

    unsafe extern "system" fn source_release(this: *mut DropSource) -> u32 {
        let left = (*this).refs.fetch_sub(1, Ordering::AcqRel) - 1;
        if left == 0 {
            drop(Box::from_raw(this));
        }
        left
    }

    /// The pointer is over one of this process's windows. Dropping there would hand the
    /// files back to the app's own drop handler, so such drops are cancelled.
    fn over_own_window() -> bool {
        let mut pt = Point { x: 0, y: 0 };
        // SAFETY: plain Win32 queries with valid out pointers.
        unsafe {
            if GetCursorPos(&mut pt) == 0 {
                return false;
            }
            let hwnd = WindowFromPoint(pt);
            if hwnd == 0 {
                return false;
            }
            let root = GetAncestor(hwnd, GA_ROOT);
            let mut pid = 0u32;
            GetWindowThreadProcessId(if root != 0 { root } else { hwnd }, &mut pid);
            pid == GetCurrentProcessId()
        }
    }

    unsafe extern "system" fn source_query_continue_drag(
        this: *mut DropSource,
        escape: i32,
        keys: u32,
    ) -> i32 {
        if escape != 0 {
            return DRAGDROP_S_CANCEL;
        }
        if keys & MK_LBUTTON != 0 {
            return S_OK;
        }
        if over_own_window() {
            return DRAGDROP_S_CANCEL;
        }
        let ready = lock(&(*this).ready).take();
        if let Some(rx) = ready {
            loop {
                match rx.recv_timeout(Duration::from_millis(30)) {
                    Ok(()) => break,
                    Err(RecvTimeoutError::Timeout) => {
                        if GetAsyncKeyState(VK_ESCAPE) < 0 {
                            return DRAGDROP_S_CANCEL;
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => return DRAGDROP_S_CANCEL,
                }
            }
            let mut files = lock(&(*this).files);
            files.retain(|p| p.exists());
            if files.is_empty() {
                return DRAGDROP_S_CANCEL;
            }
        }
        DRAGDROP_S_DROP
    }

    unsafe extern "system" fn source_give_feedback(_this: *mut DropSource, _effect: u32) -> i32 {
        DRAGDROP_S_USEDEFAULTCURSORS
    }

    // ------------------------------------------------------------------ drag thread

    pub fn run_drag(ui_thread: u32, req: super::DragRequest) -> u32 {
        let super::DragRequest {
            paths,
            effects,
            preferred,
            ready,
            abort,
        } = req;
        let files = Arc::new(Mutex::new(paths));
        let data = Box::into_raw(Box::new(DataObject {
            vtbl: &DATA_VTBL,
            refs: AtomicU32::new(1),
            files: files.clone(),
            preferred,
            cf_preferred: preferred_effect_format() as u16,
        }));
        let source = Box::into_raw(Box::new(DropSource {
            vtbl: &SOURCE_VTBL,
            refs: AtomicU32::new(1),
            files,
            ready: Mutex::new(ready),
        }));
        let mut effect = 0u32;
        // SAFETY: OLE is initialized for this thread before the drag and released after it;
        // both objects start with one reference that is dropped here once DoDragDrop returns.
        let hr = unsafe {
            let me = GetCurrentThreadId();
            let ole = OleInitialize(null_mut()) >= 0;
            let attached = ole && AttachThreadInput(me, ui_thread, 1) != 0;
            let hr = if ole {
                DoDragDrop(data.cast(), source.cast(), effects, &mut effect)
            } else {
                DRAGDROP_S_CANCEL
            };
            if attached {
                AttachThreadInput(me, ui_thread, 0);
            }
            data_release(data);
            source_release(source);
            if ole {
                OleUninitialize();
            }
            hr
        };
        if hr == DRAGDROP_S_DROP {
            effect
        } else {
            abort.store(true, Ordering::Relaxed);
            0
        }
    }

    // ------------------------------------------------------------------ clipboard

    fn open_clipboard(hwnd: isize) -> bool {
        // Another program may hold the clipboard for a moment.
        for _ in 0..10 {
            // SAFETY: plain Win32 call.
            if unsafe { OpenClipboard(hwnd) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        false
    }

    /// Puts `paths` on the clipboard as files to copy, as Explorer's Copy does.
    pub fn set_clipboard(hwnd: isize, paths: &[PathBuf]) -> bool {
        if paths.is_empty() || !open_clipboard(hwnd) {
            return false;
        }
        // SAFETY: the clipboard is open; a block the clipboard did not take is freed.
        unsafe {
            EmptyClipboard();
            let h = hdrop(paths);
            let ok = !h.is_null() && !SetClipboardData(CF_HDROP as u32, h).is_null();
            if !ok && !h.is_null() {
                GlobalFree(h);
            }
            if ok {
                let e = hglobal_u32(super::COPY);
                if !e.is_null() && SetClipboardData(preferred_effect_format(), e).is_null() {
                    GlobalFree(e);
                }
            }
            CloseClipboard();
            ok
        }
    }

    pub fn clipboard_has_files() -> bool {
        // SAFETY: plain Win32 call.
        unsafe { IsClipboardFormatAvailable(CF_HDROP as u32) != 0 }
    }

    /// Changes whenever anything is put on the clipboard.
    pub fn clipboard_sequence() -> u32 {
        // SAFETY: plain Win32 call.
        unsafe { GetClipboardSequenceNumber() }
    }

    /// Files on the clipboard, and whether they were cut (to be moved) rather than copied.
    pub fn clipboard_files() -> Option<(Vec<PathBuf>, bool)> {
        if !clipboard_has_files() || !open_clipboard(0) {
            return None;
        }
        let mut out = Vec::new();
        let mut cut = false;
        // SAFETY: the clipboard is open, so its handles stay valid until CloseClipboard;
        // buffers are sized from DragQueryFileW's own length answer.
        unsafe {
            let h = GetClipboardData(CF_HDROP as u32);
            if !h.is_null() {
                let n = DragQueryFileW(h, u32::MAX, null_mut(), 0);
                for i in 0..n {
                    let len = DragQueryFileW(h, i, null_mut(), 0);
                    if len == 0 {
                        continue;
                    }
                    let mut buf = vec![0u16; len as usize + 1];
                    let got = DragQueryFileW(h, i, buf.as_mut_ptr(), len + 1);
                    buf.truncate(got as usize);
                    out.push(PathBuf::from(OsString::from_wide(&buf)));
                }
            }
            let e = GetClipboardData(preferred_effect_format());
            if !e.is_null() {
                let p = GlobalLock(e).cast::<u32>();
                if !p.is_null() {
                    let v = p.read_unaligned();
                    cut = v & super::MOVE != 0 && v & super::COPY == 0;
                    GlobalUnlock(e);
                }
            }
            CloseClipboard();
        }
        (!out.is_empty()).then_some((out, cut))
    }

    /// Copies (or moves, for cut files) `files` into `dest` with the shell's own file
    /// operation, so conflicts, progress and undo behave as in Explorer. Blocks until done.
    pub fn paste(hwnd: isize, files: &[PathBuf], dest: &Path, cut: bool) -> Result<(), String> {
        let same_folder = files.iter().all(|f| f.parent() == Some(dest));
        if cut && same_folder {
            return Ok(());
        }
        let from = wide_list(files);
        let to: Vec<u16> = dest.as_os_str().encode_wide().chain([0, 0]).collect();
        let mut flags = FOF_ALLOWUNDO | FOF_NOCONFIRMMKDIR;
        // Pasting a copy next to the original makes "name - Copy", as Explorer does.
        if same_folder {
            flags |= FOF_RENAMEONCOLLISION;
        }
        let mut op = FileOp {
            hwnd,
            func: if cut { FO_MOVE } else { FO_COPY },
            from: from.as_ptr(),
            to: to.as_ptr(),
            flags,
            aborted: 0,
            mappings: null_mut(),
            title: std::ptr::null(),
        };
        // SAFETY: both lists are double-NUL terminated and outlive the call; the shell wants
        // an apartment-threaded thread, which OleInitialize provides.
        let rc = unsafe {
            let ole = OleInitialize(null_mut()) >= 0;
            let rc = SHFileOperationW(&mut op);
            if ole {
                OleUninitialize();
            }
            rc
        };
        // 0x4C7 (ERROR_CANCELLED) and the aborted flag mean the user stopped it.
        if rc == 0 || rc == 0x4C7 || op.aborted != 0 {
            Ok(())
        } else {
            Err(format!("the files could not be pasted (error {rc:#x})"))
        }
    }
}
