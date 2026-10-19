//! Windows Projected File System (ProjFS) bindings, loaded at run time.
//!
//! ProjectedFSLib.dll only exists when the optional feature Client-ProjFS is enabled, so it
//! is opened with LoadLibrary on first use instead of being linked. Without it the app runs
//! normally and `api()` returns an error saying how to turn the feature on.
//!
//! Struct layouts follow projectedfslib.h (Windows SDK 10.0.17763).

#![allow(non_snake_case, clippy::upper_case_acronyms)]

use std::ffi::c_void;
use std::sync::OnceLock;

pub type HRESULT = i32;
pub type Context = *mut c_void;
pub type DirEntryBuffer = *mut c_void;

pub const S_OK: HRESULT = 0;
pub const E_FAIL: HRESULT = 0x8000_4005_u32 as i32;
pub const E_ACCESSDENIED: HRESULT = 0x8007_0005_u32 as i32;
pub const E_OUTOFMEMORY: HRESULT = 0x8007_000E_u32 as i32;

pub const fn from_win32(code: u32) -> HRESULT {
    if code == 0 {
        0
    } else {
        ((code & 0xFFFF) | 0x8007_0000) as i32
    }
}

pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_CRC: u32 = 23;
pub const ERROR_OPERATION_ABORTED: u32 = 995;

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct GUID {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl GUID {
    pub fn key(&self) -> u128 {
        let mut b = [0u8; 16];
        b[..4].copy_from_slice(&self.data1.to_le_bytes());
        b[4..6].copy_from_slice(&self.data2.to_le_bytes());
        b[6..8].copy_from_slice(&self.data3.to_le_bytes());
        b[8..].copy_from_slice(&self.data4);
        u128::from_le_bytes(b)
    }

    /// A fresh random GUID from the system.
    pub fn new() -> GUID {
        #[link(name = "ole32")]
        extern "system" {
            fn CoCreateGuid(g: *mut GUID) -> HRESULT;
        }
        let mut g = GUID::default();
        // SAFETY: `g` is a valid out pointer for the duration of the call.
        unsafe {
            CoCreateGuid(&mut g);
        }
        g
    }
}

pub const PLACEHOLDER_ID_LENGTH: usize = 128;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PlaceholderVersionInfo {
    pub ProviderID: [u8; PLACEHOLDER_ID_LENGTH],
    pub ContentID: [u8; PLACEHOLDER_ID_LENGTH],
}

impl Default for PlaceholderVersionInfo {
    fn default() -> Self {
        PlaceholderVersionInfo {
            ProviderID: [0; PLACEHOLDER_ID_LENGTH],
            ContentID: [0; PLACEHOLDER_ID_LENGTH],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FileBasicInfo {
    pub IsDirectory: u8,
    pub FileSize: i64,
    pub CreationTime: i64,
    pub LastAccessTime: i64,
    pub LastWriteTime: i64,
    pub ChangeTime: i64,
    pub FileAttributes: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SizeOffset {
    pub size: u32,
    pub offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PlaceholderInfo {
    pub FileBasicInfo: FileBasicInfo,
    pub EaInformation: SizeOffset,
    pub SecurityInformation: SizeOffset,
    pub StreamsInformation: SizeOffset,
    pub VersionInfo: PlaceholderVersionInfo,
    pub VariableData: [u8; 1],
}

#[repr(C)]
pub struct CallbackData {
    pub Size: u32,
    pub Flags: u32,
    pub NamespaceVirtualizationContext: Context,
    pub CommandId: i32,
    pub FileId: GUID,
    pub DataStreamId: GUID,
    pub FilePathName: *const u16,
    pub VersionInfo: *mut PlaceholderVersionInfo,
    pub TriggeringProcessId: u32,
    pub TriggeringProcessImageFileName: *const u16,
    pub InstanceContext: *mut c_void,
}

pub const CB_DATA_FLAG_ENUM_RESTART_SCAN: u32 = 0x1;
pub const CB_DATA_FLAG_ENUM_RETURN_SINGLE_ENTRY: u32 = 0x2;

pub type StartEnumCb = unsafe extern "system" fn(*const CallbackData, *const GUID) -> HRESULT;
pub type EndEnumCb = unsafe extern "system" fn(*const CallbackData, *const GUID) -> HRESULT;
pub type GetEnumCb = unsafe extern "system" fn(
    *const CallbackData,
    *const GUID,
    *const u16,
    DirEntryBuffer,
) -> HRESULT;
pub type PlaceholderCb = unsafe extern "system" fn(*const CallbackData) -> HRESULT;
pub type FileDataCb = unsafe extern "system" fn(*const CallbackData, u64, u32) -> HRESULT;
pub type QueryNameCb = unsafe extern "system" fn(*const CallbackData) -> HRESULT;
pub type NotificationCb =
    unsafe extern "system" fn(*const CallbackData, u8, u32, *const u16, *mut c_void) -> HRESULT;
pub type CancelCb = unsafe extern "system" fn(*const CallbackData);

#[repr(C)]
pub struct Callbacks {
    pub StartDirectoryEnumerationCallback: Option<StartEnumCb>,
    pub EndDirectoryEnumerationCallback: Option<EndEnumCb>,
    pub GetDirectoryEnumerationCallback: Option<GetEnumCb>,
    pub GetPlaceholderInfoCallback: Option<PlaceholderCb>,
    pub GetFileDataCallback: Option<FileDataCb>,
    pub QueryFileNameCallback: Option<QueryNameCb>,
    pub NotificationCallback: Option<NotificationCb>,
    pub CancelCommandCallback: Option<CancelCb>,
}

// PRJ_NOTIFY_TYPES / PRJ_NOTIFICATION values.
pub const NOTIFY_NEW_FILE_CREATED: u32 = 0x4;
pub const NOTIFY_FILE_OVERWRITTEN: u32 = 0x8;
pub const NOTIFY_PRE_DELETE: u32 = 0x10;
pub const NOTIFY_PRE_RENAME: u32 = 0x20;
pub const NOTIFY_PRE_SET_HARDLINK: u32 = 0x40;
pub const NOTIFY_FILE_PRE_CONVERT_TO_FULL: u32 = 0x1000;

#[repr(C)]
pub struct NotificationMapping {
    pub NotificationBitMask: u32,
    pub NotificationRoot: *const u16,
}

#[repr(C)]
pub struct StartOptions {
    pub Flags: u32,
    pub PoolThreadCount: u32,
    pub ConcurrentThreadCount: u32,
    pub NotificationMappings: *mut NotificationMapping,
    pub NotificationMappingsCount: u32,
}

#[repr(C)]
#[derive(Default)]
pub struct InstanceInfo {
    pub InstanceID: GUID,
    pub WriteAlignment: u32,
}

// PRJ_UPDATE_TYPES for PrjDeleteFile.
pub const UPDATE_ALLOW_DIRTY_METADATA: u32 = 0x1;
pub const UPDATE_ALLOW_DIRTY_DATA: u32 = 0x2;
pub const UPDATE_ALLOW_TOMBSTONE: u32 = 0x4;
pub const UPDATE_ALLOW_READ_ONLY: u32 = 0x20;

pub struct Api {
    pub mark_root: unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const PlaceholderVersionInfo,
        *const GUID,
    ) -> HRESULT,
    pub start: unsafe extern "system" fn(
        *const u16,
        *const Callbacks,
        *const c_void,
        *const StartOptions,
        *mut Context,
    ) -> HRESULT,
    pub stop: unsafe extern "system" fn(Context),
    pub instance_info: unsafe extern "system" fn(Context, *mut InstanceInfo) -> HRESULT,
    pub fill_dir_entry:
        unsafe extern "system" fn(*const u16, *const FileBasicInfo, DirEntryBuffer) -> HRESULT,
    pub write_placeholder:
        unsafe extern "system" fn(Context, *const u16, *const PlaceholderInfo, u32) -> HRESULT,
    pub alloc: unsafe extern "system" fn(Context, usize) -> *mut c_void,
    pub free: unsafe extern "system" fn(*mut c_void),
    pub write_data:
        unsafe extern "system" fn(Context, *const GUID, *const c_void, u64, u32) -> HRESULT,
    pub name_match: unsafe extern "system" fn(*const u16, *const u16) -> u8,
    pub name_compare: unsafe extern "system" fn(*const u16, *const u16) -> i32,
    pub delete_file: unsafe extern "system" fn(Context, *const u16, u32, *mut u32) -> HRESULT,
}

// SAFETY: the table only holds function pointers into a DLL that stays loaded.
unsafe impl Send for Api {}
unsafe impl Sync for Api {}

/// Why ProjFS can't be used here.
pub const NOT_ENABLED: &str = "ProjFS is not enabled";

/// The ProjFS functions, or an error when the feature is not installed.
pub fn api() -> Result<&'static Api, String> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(load).as_ref().map_err(Clone::clone)
}

fn load() -> Result<Api, String> {
    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    }
    const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;
    let name: Vec<u16> = "ProjectedFSLib.dll\0".encode_utf16().collect();
    // SAFETY: NUL-terminated name; the module is never freed, so the pointers stay valid.
    let module = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(NOT_ENABLED.into());
    }
    let sym = |n: &str| -> Result<*mut c_void, String> {
        let z = format!("{n}\0");
        // SAFETY: valid module handle and NUL-terminated ASCII name.
        let p = unsafe { GetProcAddress(module, z.as_ptr()) };
        if p.is_null() {
            Err(format!(
                "ProjectedFSLib.dll has no {n}; Windows 10 1809 or later is needed"
            ))
        } else {
            Ok(p)
        }
    };
    /// A symbol address as the function pointer type `F`.
    unsafe fn cast<F: Copy>(p: *mut c_void) -> F {
        debug_assert_eq!(std::mem::size_of::<F>(), std::mem::size_of::<*mut c_void>());
        std::mem::transmute_copy(&p)
    }
    // SAFETY: each symbol is cast to the signature declared in projectedfslib.h.
    unsafe {
        Ok(Api {
            mark_root: cast(sym("PrjMarkDirectoryAsPlaceholder")?),
            start: cast(sym("PrjStartVirtualizing")?),
            stop: cast(sym("PrjStopVirtualizing")?),
            instance_info: cast(sym("PrjGetVirtualizationInstanceInfo")?),
            fill_dir_entry: cast(sym("PrjFillDirEntryBuffer")?),
            write_placeholder: cast(sym("PrjWritePlaceholderInfo")?),
            alloc: cast(sym("PrjAllocateAlignedBuffer")?),
            free: cast(sym("PrjFreeAlignedBuffer")?),
            write_data: cast(sym("PrjWriteFileData")?),
            name_match: cast(sym("PrjFileNameMatch")?),
            name_compare: cast(sym("PrjFileNameCompare")?),
            delete_file: cast(sym("PrjDeleteFile")?),
        })
    }
}

/// Length of a NUL-terminated UTF-16 string.
///
/// # Safety
/// `p` must be null or point to a NUL-terminated string.
pub unsafe fn wcslen(p: *const u16) -> usize {
    if p.is_null() {
        return 0;
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    n
}

/// # Safety
/// As for `wcslen`.
pub unsafe fn wide_slice<'a>(p: *const u16) -> &'a [u16] {
    if p.is_null() {
        &[]
    } else {
        std::slice::from_raw_parts(p, wcslen(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    // Sizes and offsets of the x64 C structs.
    #[test]
    fn layouts_match_the_sdk_header() {
        assert_eq!(size_of::<FileBasicInfo>(), 56);
        assert_eq!(offset_of!(FileBasicInfo, FileSize), 8);
        assert_eq!(offset_of!(FileBasicInfo, FileAttributes), 48);
        assert_eq!(size_of::<PlaceholderInfo>(), 344);
        assert_eq!(offset_of!(PlaceholderInfo, VersionInfo), 80);
        assert_eq!(size_of::<CallbackData>(), 96);
        assert_eq!(offset_of!(CallbackData, CommandId), 16);
        assert_eq!(offset_of!(CallbackData, DataStreamId), 36);
        assert_eq!(offset_of!(CallbackData, FilePathName), 56);
        assert_eq!(offset_of!(CallbackData, InstanceContext), 88);
        assert_eq!(size_of::<Callbacks>(), 64);
        assert_eq!(size_of::<StartOptions>(), 32);
        assert_eq!(size_of::<InstanceInfo>(), 20);
        assert_eq!(size_of::<NotificationMapping>(), 16);
    }

    #[test]
    fn hresults() {
        assert_eq!(from_win32(122) as u32, 0x8007_007A);
        assert_eq!(from_win32(ERROR_FILE_NOT_FOUND) as u32, 0x8007_0002);
    }
}
