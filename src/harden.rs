//! Best-effort memory and process hardening. None of this stops a kernel-level, administrator or
//! physical attacker, and it does not fully stop a malicious program running as the same user.
//! It removes cheap paths (swap of secrets, crash dumps, DLL planting, some same-user tools).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

/// Set when any VirtualLock/mlock call failed (shown in the UI).
pub static LOCK_FAILED: AtomicBool = AtomicBool::new(false);
/// Set when the Argon2 work memory could not be locked (it may be paged out while hashing).
pub static KDF_LOCK_FAILED: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
fn raw_lock(p: *const u8, l: usize) -> bool {
    unsafe { windows_sys::Win32::System::Memory::VirtualLock(p as *const core::ffi::c_void, l) != 0 }
}
#[cfg(windows)]
fn raw_unlock(p: *const u8, l: usize) {
    unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(p as *const core::ffi::c_void, l);
    }
}
#[cfg(unix)]
fn raw_lock(p: *const u8, l: usize) -> bool {
    unsafe { libc::mlock(p as *const core::ffi::c_void, l) == 0 }
}
#[cfg(unix)]
fn raw_unlock(p: *const u8, l: usize) {
    unsafe {
        libc::munlock(p as *const core::ffi::c_void, l);
    }
}
#[cfg(not(any(windows, unix)))]
fn raw_lock(_: *const u8, _: usize) -> bool {
    false
}
#[cfg(not(any(windows, unix)))]
fn raw_unlock(_: *const u8, _: usize) {}

/// Locks a small secret buffer in RAM; failures are recorded and reported, never fatal.
pub fn lock_mem(p: *const u8, l: usize) -> bool {
    let ok = raw_lock(p, l);
    if !ok {
        LOCK_FAILED.store(true, Ordering::Relaxed);
    }
    ok
}
pub fn unlock_mem(p: *const u8, l: usize) {
    raw_unlock(p, l)
}

static WS_LOCK: Mutex<()> = Mutex::new(());

/// Locks a large region (Argon2 work memory). Windows needs a minimum working set at least as large
/// as the locked size, so it is raised for the duration and restored by `unlock_large`.
pub fn lock_large(p: *const u8, l: usize) -> bool {
    let _g = WS_LOCK.lock().unwrap_or_else(|x| x.into_inner());
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
        SetProcessWorkingSetSize(GetCurrentProcess(), l + (64 << 20), l + (512 << 20));
    }
    let ok = raw_lock(p, l);
    if !ok {
        KDF_LOCK_FAILED.store(true, Ordering::Relaxed);
    }
    ok
}
pub fn unlock_large(p: *const u8, l: usize, was_locked: bool) {
    let _g = WS_LOCK.lock().unwrap_or_else(|x| x.into_inner());
    if was_locked {
        raw_unlock(p, l);
    }
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
        SetProcessWorkingSetSize(GetCurrentProcess(), 32 << 20, 512 << 20);
    }
}

/// What `harden_process` managed to apply (shown on the information tab).
#[derive(Default, Clone)]
pub struct HardenReport {
    pub dacl: bool,
    pub dll_dirs: bool,
    pub image_policy: bool,
    pub no_crash_dialogs: bool,
}
pub static REPORT: Mutex<Option<HardenReport>> = Mutex::new(None);

/// Process DACL:
/// - SYSTEM and Administrators: full access.
/// - OWNER RIGHTS (OW): only SYNCHRONIZE | READ_CONTROL | PROCESS_QUERY_LIMITED_INFORMATION.
///   An OW ACE replaces the owner's implicit READ_CONTROL|WRITE_DAC, so a same-user process can not
///   simply rewrite this DACL. A same-user process holding debug privilege, or one that started
///   before this ran, or an elevated one, is NOT stopped.
#[cfg(windows)]
const PROCESS_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x121000;;;OW)\0";

/// Call once at startup, before any window or DLL-using code.
#[cfg(windows)]
pub fn harden_process() {
    use windows_sys::Win32::Foundation::{LocalFree, BOOL};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION};
    use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
    use windows_sys::Win32::System::LibraryLoader::{SetDefaultDllDirectories, SetDllDirectoryW};
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, ProcessImageLoadPolicy, SetProcessMitigationPolicy, SetProcessWorkingSetSize,
    };
    let mut rep = HardenReport::default();
    unsafe {
        // DLL search: System32 only for LoadLibrary without a full path; drop the current folder.
        const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x800;
        let empty = [0u16; 1];
        let a = SetDllDirectoryW(empty.as_ptr()) != 0;
        rep.dll_dirs = SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0 && a;
        // Image load policy: no DLLs from remote shares or low-integrity locations, prefer System32.
        let flags: u32 = 0b111; // NoRemoteImages | NoLowMandatoryLabelImages | PreferSystem32Images
        rep.image_policy =
            SetProcessMitigationPolicy(ProcessImageLoadPolicy, &flags as *const u32 as _, 4) != 0;
        // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
        SetErrorMode(0x8003);
        rep.no_crash_dialogs = true;
        SetProcessWorkingSetSize(GetCurrentProcess(), 32 << 20, 512 << 20);

        let sddl: Vec<u16> = PROCESS_SDDL.encode_utf16().collect();
        let mut sd: *mut core::ffi::c_void = core::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), 1, &mut sd, core::ptr::null_mut()) != 0 {
            let mut present: BOOL = 0;
            let mut defaulted: BOOL = 0;
            let mut dacl: *mut ACL = core::ptr::null_mut();
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) != 0 && present != 0 {
                rep.dacl = SetSecurityInfo(
                    GetCurrentProcess(),
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    dacl,
                    core::ptr::null(),
                ) == 0;
            }
            LocalFree(sd as _);
        }
    }
    *REPORT.lock().unwrap_or_else(|x| x.into_inner()) = Some(rep);
}

#[cfg(unix)]
pub fn harden_process() {
    unsafe {
        let r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &r);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
    *REPORT.lock().unwrap_or_else(|x| x.into_inner()) = Some(HardenReport { no_crash_dialogs: true, ..Default::default() });
}

#[cfg(not(any(windows, unix)))]
pub fn harden_process() {}

// ---------------------------------------------------------------- secret input buffer

pub const SECRET_CAP: usize = 256;

/// Fixed, heap-pinned, page-locked (best effort) password buffer. It never reallocates, so no
/// stale copies are left behind, and it is zeroized on clear/drop. Bytes are stored as typed
/// (UTF-8); `take` returns the NFC-normalized form used by every operation.
pub struct SecretBuf {
    buf: Box<[u8; SECRET_CAP]>,
    len: usize,
    /// Input was cut at SECRET_CAP bytes.
    pub overflow: bool,
    /// Text arrived through a paste (the clipboard may still hold it).
    pub pasted: bool,
}

impl Default for SecretBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBuf {
    pub fn new() -> Self {
        let buf = Box::new([0u8; SECRET_CAP]);
        lock_mem(buf.as_ptr(), SECRET_CAP);
        Self { buf, len: 0, overflow: false, pasted: false }
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
    pub fn char_count(&self) -> usize {
        self.as_str().chars().count()
    }
    pub fn push_str(&mut self, s: &str) {
        for ch in s.chars() {
            if ch.is_control() {
                continue;
            }
            let mut t = [0u8; 4];
            let b = ch.encode_utf8(&mut t).as_bytes();
            if self.len + b.len() > SECRET_CAP {
                self.overflow = true;
                t.zeroize();
                break;
            }
            self.buf[self.len..self.len + b.len()].copy_from_slice(b);
            self.len += b.len();
            t.zeroize();
        }
    }
    pub fn pop(&mut self) {
        if let Some(n) = self.as_str().chars().next_back().map(|c| c.len_utf8()) {
            let st = self.len - n;
            self.buf[st..self.len].zeroize();
            self.len = st;
            self.overflow = false;
        }
    }
    pub fn clear(&mut self) {
        (*self.buf).zeroize();
        self.len = 0;
        self.overflow = false;
        self.pasted = false;
    }
    /// NFC-normalized copy (zeroizing). Used for confirmation checks and by `take`.
    pub fn normalized(&self) -> Zeroizing<Vec<u8>> {
        crate::password::normalize(self.as_str())
    }
    /// Moves the secret out (NFC-normalized, zeroizing) and clears this buffer.
    pub fn take(&mut self) -> Zeroizing<Vec<u8>> {
        let v = self.normalized();
        self.clear();
        v
    }
    /// Constant-time comparison of the normalized forms.
    pub fn ct_eq(&self, o: &Self) -> bool {
        crate::password::ct_eq(&self.normalized(), &o.normalized())
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.clear();
        unlock_mem(self.buf.as_ptr(), SECRET_CAP);
    }
}
