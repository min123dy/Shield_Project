//! Best-effort memory hardening. None of this stops a kernel-level or physical attacker;
//! it removes the cheap paths (swap, crash dumps, same-user dump tools, long-lived copies).

use zeroize::{Zeroize, Zeroizing};

#[cfg(windows)]
pub fn lock_mem(p: *const u8, l: usize) -> bool {
    unsafe { windows_sys::Win32::System::Memory::VirtualLock(p as *const core::ffi::c_void, l) != 0 }
}
#[cfg(windows)]
pub fn unlock_mem(p: *const u8, l: usize) {
    unsafe {
        windows_sys::Win32::System::Memory::VirtualUnlock(p as *const core::ffi::c_void, l);
    }
}
#[cfg(unix)]
pub fn lock_mem(p: *const u8, l: usize) -> bool {
    unsafe { libc::mlock(p as *const core::ffi::c_void, l) == 0 }
}
#[cfg(unix)]
pub fn unlock_mem(p: *const u8, l: usize) {
    unsafe {
        libc::munlock(p as *const core::ffi::c_void, l);
    }
}
#[cfg(not(any(windows, unix)))]
pub fn lock_mem(_: *const u8, _: usize) -> bool {
    false
}
#[cfg(not(any(windows, unix)))]
pub fn unlock_mem(_: *const u8, _: usize) {}

/// Process DACL:
/// - SYSTEM and Administrators: full access.
/// - OWNER RIGHTS (OW): only SYNCHRONIZE | READ_CONTROL | PROCESS_QUERY_LIMITED_INFORMATION.
///   An OW ACE replaces the owner's implicit READ_CONTROL|WRITE_DAC, so a same-user process can no
///   longer rewrite this DACL to grant itself memory access, while Explorer can still query the
///   image path (needed for "Pin to taskbar" and taskbar grouping).
/// Nobody else (no non-elevated same-user tool) can read/write memory, inject threads or dump.
#[cfg(windows)]
const PROCESS_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x121000;;;OW)\0";

/// Call once at startup.
/// Windows: no crash-report dialogs/dumps, larger working set (so VirtualLock works), and the
/// restrictive process DACL above.
#[cfg(windows)]
pub fn harden_process() {
    use windows_sys::Win32::Foundation::{LocalFree, BOOL};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION};
    use windows_sys::Win32::System::Diagnostics::Debug::SetErrorMode;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, SetProcessWorkingSetSize};
    unsafe {
        // SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
        SetErrorMode(0x8003);
        SetProcessWorkingSetSize(GetCurrentProcess(), 32 << 20, 256 << 20);

        let sddl: Vec<u16> = PROCESS_SDDL.encode_utf16().collect();
        let mut sd: *mut core::ffi::c_void = core::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut sd,
            core::ptr::null_mut(),
        ) != 0
        {
            let mut present: BOOL = 0;
            let mut defaulted: BOOL = 0;
            let mut dacl: *mut ACL = core::ptr::null_mut();
            if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) != 0
                && present != 0
            {
                SetSecurityInfo(
                    GetCurrentProcess(),
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                    dacl,
                    core::ptr::null(),
                );
            }
            LocalFree(sd as _);
        }
    }
}

#[cfg(unix)]
pub fn harden_process() {
    unsafe {
        let r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &r);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
}

#[cfg(not(any(windows, unix)))]
pub fn harden_process() {}

// ---------------------------------------------------------------- secret input buffer

pub const SECRET_CAP: usize = 256;

/// Fixed, heap-pinned, page-locked (best effort) password buffer. It never reallocates, so no
/// stale copies are left behind, and it is zeroized on clear/drop.
pub struct SecretBuf {
    buf: Box<[u8; SECRET_CAP]>,
    len: usize,
}

impl SecretBuf {
    pub fn new() -> Self {
        let buf = Box::new([0u8; SECRET_CAP]);
        lock_mem(buf.as_ptr(), SECRET_CAP);
        Self { buf, len: 0 }
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn char_count(&self) -> usize {
        std::str::from_utf8(&self.buf[..self.len]).map(|s| s.chars().count()).unwrap_or(0)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    pub fn push_str(&mut self, s: &str) {
        for ch in s.chars() {
            if ch.is_control() {
                continue;
            }
            let mut t = [0u8; 4];
            let b = ch.encode_utf8(&mut t).as_bytes();
            if self.len + b.len() > SECRET_CAP {
                break;
            }
            self.buf[self.len..self.len + b.len()].copy_from_slice(b);
            self.len += b.len();
        }
    }
    pub fn pop(&mut self) {
        let last = std::str::from_utf8(&self.buf[..self.len])
            .ok()
            .and_then(|s| s.chars().next_back())
            .map(|c| c.len_utf8());
        if let Some(n) = last {
            let st = self.len - n;
            self.buf[st..self.len].zeroize();
            self.len = st;
        }
    }
    pub fn clear(&mut self) {
        (*self.buf).zeroize();
        self.len = 0;
    }
    /// Moves the secret out (zeroizing copy) and clears this buffer.
    pub fn take(&mut self) -> Zeroizing<Vec<u8>> {
        let v = Zeroizing::new(self.buf[..self.len].to_vec());
        self.clear();
        v
    }
    pub fn ct_eq(&self, o: &Self) -> bool {
        if self.len != o.len {
            return false;
        }
        let mut d = 0u8;
        for i in 0..self.len {
            d |= self.buf[i] ^ o.buf[i];
        }
        d == 0
    }
    /// Rough strength estimate in bits (charset size x length); only a hint for the UI.
    pub fn bits(&self) -> f64 {
        let s = std::str::from_utf8(&self.buf[..self.len]).unwrap_or("");
        let (mut lo, mut up, mut di, mut sy, mut ot) = (false, false, false, false, false);
        for c in s.chars() {
            if c.is_ascii_lowercase() {
                lo = true
            } else if c.is_ascii_uppercase() {
                up = true
            } else if c.is_ascii_digit() {
                di = true
            } else if c.is_ascii() {
                sy = true
            } else {
                ot = true
            }
        }
        let pool = lo as u32 * 26 + up as u32 * 26 + di as u32 * 10 + sy as u32 * 33 + ot as u32 * 2000;
        if pool == 0 {
            0.0
        } else {
            s.chars().count() as f64 * (pool as f64).log2()
        }
    }
}

impl Drop for SecretBuf {
    fn drop(&mut self) {
        self.clear();
        unlock_mem(self.buf.as_ptr(), SECRET_CAP);
    }
}
