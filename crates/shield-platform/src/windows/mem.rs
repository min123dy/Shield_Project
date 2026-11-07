//! Memory locking (VirtualLock) and process hardening on Windows.
//! None of this stops a kernel-level, administrator or physical attacker, and it does not fully
//! stop a malicious program running as the same user.

use crate::{HardenItem, HardenReport};
use std::sync::Mutex;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};

pub fn lock(p: *const u8, l: usize) -> bool {
    unsafe { windows_sys::Win32::System::Memory::VirtualLock(p as *const core::ffi::c_void, l) != 0 }
}

pub fn unlock(p: *const u8, l: usize) {
    unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(p as *const core::ffi::c_void, l);
    }
}

static WS_LOCK: Mutex<()> = Mutex::new(());

/// Locks a large region (Argon2 work memory). The minimum working set must be at least as large
/// as the locked size, so it is raised for the duration and restored by `unlock_large`.
pub fn lock_large(p: *const u8, l: usize) -> bool {
    let _g = WS_LOCK.lock().unwrap_or_else(|x| x.into_inner());
    unsafe {
        SetProcessWorkingSetSize(GetCurrentProcess(), l + (64 << 20), l + (512 << 20));
    }
    lock(p, l)
}

pub fn unlock_large(p: *const u8, l: usize, was_locked: bool) {
    let _g = WS_LOCK.lock().unwrap_or_else(|x| x.into_inner());
    if was_locked {
        unlock(p, l);
    }
    unsafe {
        SetProcessWorkingSetSize(GetCurrentProcess(), 32 << 20, 512 << 20);
    }
}

/// Process DACL:
/// - SYSTEM and Administrators: full access.
/// - OWNER RIGHTS (OW): only SYNCHRONIZE | READ_CONTROL | PROCESS_QUERY_LIMITED_INFORMATION |
///   PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, so a same-user process can't read / write its
///   memory, inject a thread, duplicate its handles or rewrite this DACL. One holding debug
///   privilege, one started before this ran, or an elevated one, is NOT stopped.
/// - Ending it stays allowed (3.0.0 fix): without it a window that stopped responding could not
///   be ended from Task Manager / taskkill / Stop-Process without administrator rights. Those tools
///   ask for PROCESS_QUERY_INFORMATION together with PROCESS_TERMINATE. Ending a process only lets
///   the OS free its memory; querying gives process information, never memory contents.
const PROCESS_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x121401;;;OW)";

/// Call once at start-up, before any window or DLL-using code.
pub fn harden_process() -> HardenReport {
    use windows_sys::Win32::Foundation::BOOL;
    use windows_sys::Win32::Security::Authorization::{SetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION};
    use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
    use windows_sys::Win32::System::LibraryLoader::{SetDefaultDllDirectories, SetDllDirectoryW};
    use windows_sys::Win32::System::Threading::{ProcessImageLoadPolicy, SetProcessMitigationPolicy};
    let mut rep = HardenReport::default();
    unsafe {
        const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;
        let empty = [0u16; 1];
        let a = SetDllDirectoryW(empty.as_ptr()) != 0;
        rep.items.push((HardenItem::DllSearch, SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0 && a));
        let flags: u32 = 0b111; // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
        rep.items.push((HardenItem::ImageLoadPolicy, SetProcessMitigationPolicy(ProcessImageLoadPolicy, &flags as *const u32 as _, 4) != 0));
        SetErrorMode(0x8003); // no crash / critical error dialogs
        rep.items.push((HardenItem::NoCoreDumps, true));
        SetProcessWorkingSetSize(GetCurrentProcess(), 32 << 20, 512 << 20);
        let dacl_ok = super::fs::with_sd(PROCESS_SDDL, |sd| {
            let mut present: BOOL = 0;
            let mut defaulted: BOOL = 0;
            let mut dacl: *mut ACL = core::ptr::null_mut();
            GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) != 0
                && present != 0
                && SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, core::ptr::null_mut(), core::ptr::null_mut(), dacl, core::ptr::null()) == 0
        })
        .unwrap_or(false);
        rep.items.push((HardenItem::ProcessDacl, dacl_ok));
    }
    rep
}
