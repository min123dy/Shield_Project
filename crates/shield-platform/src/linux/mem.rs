//! mlock and process hardening on Linux: no core dumps, not dumpable (which also blocks ptrace
//! attach and /proc/<pid>/mem access by other same-user processes that are not root).
//! Swap is not encrypted by this; an encrypted swap (or none) is recommended in the docs.

use crate::{HardenItem, HardenReport};

pub fn lock(p: *const u8, l: usize) -> bool {
    unsafe { libc::mlock(p as *const libc::c_void, l) == 0 }
}

pub fn unlock(p: *const u8, l: usize) {
    unsafe {
        libc::munlock(p as *const libc::c_void, l);
    }
}

/// Large regions usually exceed RLIMIT_MEMLOCK (often 8 MiB) for normal users: the failure is
/// reported in the UI, never fatal.
pub fn lock_large(p: *const u8, l: usize) -> bool {
    lock(p, l)
}

pub fn unlock_large(p: *const u8, l: usize, was_locked: bool) {
    if was_locked {
        unlock(p, l);
    }
}

pub fn harden_process() -> HardenReport {
    let mut rep = HardenReport::default();
    unsafe {
        let r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        rep.items.push((HardenItem::NoCoreDumps, libc::setrlimit(libc::RLIMIT_CORE, &r) == 0));
        rep.items.push((HardenItem::NotDumpable, libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0));
    }
    rep
}
