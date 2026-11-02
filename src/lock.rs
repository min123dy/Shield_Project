//! Cross-process locks (B-2 container lock, B-5 journal lock).
//!
//! Why `LockFileEx` on a separate lock file, and not on the container itself:
//! * the container is replaced by an atomic rename (`MoveFileExW`); a lock on the old file object
//!   would not cover the new one, and holding the container open would block that rename;
//! * an advisory lock on a small side file is released by the kernel when the handle is closed,
//!   which includes a crash or kill of the process (no stale lock to clean up by hand);
//! * a plain "lock file exists" scheme (create_new) leaves a stale file after a crash.
//!
//! The lock files live in `%LOCALAPPDATA%\Shield\locks\` and are named by the SHA3-256 of the
//! container's resolved, case-folded path, so no file name is written anywhere and two spellings of
//! one path share one lock. They are opened with share mode READ|WRITE and without DELETE, so a
//! lock file can't be removed while somebody holds it.

use crate::i18n::{coded, has_code};
use crate::progress::*;
use sha3::{Digest, Sha3_256};
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const C_BUSY: &str = "E_BUSY";

pub fn busy_msg() -> String {
    coded(C_BUSY, "err.busy")
}

pub fn is_busy(msg: &str) -> bool {
    has_code(msg, C_BUSY)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Readers (open, check, extract): many at once, never during a write.
    Shared,
    /// Writers (add, delete, password change, rekey): alone, held through the final rename.
    Exclusive,
}

/// A held lock; released when dropped (and by the OS if the process dies).
pub struct FileLock {
    f: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = unlock(&self.f);
    }
}

fn open_lock_file(p: &Path) -> io::Result<File> {
    if let Some(d) = p.parent() {
        fs::create_dir_all(d)?;
    }
    let mut o = OpenOptions::new();
    o.read(true).write(true).create(true).truncate(false);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.share_mode(0x1 | 0x2); // FILE_SHARE_READ | FILE_SHARE_WRITE, no DELETE
    }
    o.open(p)
}

#[cfg(windows)]
fn try_lock(f: &File, m: Mode) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::ERROR_LOCK_VIOLATION;
    use windows_sys::Win32::Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY};
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    let flags = LOCKFILE_FAIL_IMMEDIATELY | if m == Mode::Exclusive { LOCKFILE_EXCLUSIVE_LOCK } else { 0 };
    let ok = unsafe { LockFileEx(f.as_raw_handle() as _, flags, 0, 1, 0, &mut ov) };
    if ok != 0 {
        return Ok(true);
    }
    let x = io::Error::last_os_error();
    if x.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(x)
    }
}

#[cfg(windows)]
fn unlock(f: &File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::UnlockFileEx;
    use windows_sys::Win32::System::IO::OVERLAPPED;
    let mut ov: OVERLAPPED = unsafe { core::mem::zeroed() };
    if unsafe { UnlockFileEx(f.as_raw_handle() as _, 0, 1, 0, &mut ov) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn try_lock(f: &File, m: Mode) -> io::Result<bool> {
    use std::os::unix::io::AsRawFd;
    let op = libc::LOCK_NB | if m == Mode::Exclusive { libc::LOCK_EX } else { libc::LOCK_SH };
    if unsafe { libc::flock(f.as_raw_fd(), op) } == 0 {
        return Ok(true);
    }
    let x = io::Error::last_os_error();
    if x.kind() == io::ErrorKind::WouldBlock {
        Ok(false)
    } else {
        Err(x)
    }
}

#[cfg(unix)]
fn unlock(f: &File) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_UN) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(windows, unix)))]
fn try_lock(_f: &File, _m: Mode) -> io::Result<bool> {
    Ok(true)
}
#[cfg(not(any(windows, unix)))]
fn unlock(_f: &File) -> io::Result<()> {
    Ok(())
}

fn lock_dir() -> PathBuf {
    if cfg!(test) {
        return std::env::temp_dir().join("shield_test_locks");
    }
    crate::settings::data_dir().join("locks")
}

/// Lock file of a container: name = SHA3-256 of the resolved, case-folded path.
pub fn lock_path_for(container: &Path) -> PathBuf {
    let key = crate::sysinfo::path_key(&crate::sysinfo::resolve(container).unwrap_or_else(|| container.to_path_buf()));
    let d = Sha3_256::digest(key.as_bytes());
    let name: String = d.iter().take(16).map(|b| format!("{b:02x}")).collect();
    lock_dir().join(format!("{name}.lck"))
}

/// Takes `m` on `lock_file`, waiting up to `wait` (cancel aware). After that the caller gets the
/// "busy" error, which the UI shows with a retry button.
pub fn acquire(lock_file: &Path, m: Mode, wait: Duration) -> R<FileLock> {
    let f = open_lock_file(lock_file).map_err(|x| crate::i18n::tf("err.lock_open", &[&x]))?;
    let start = Instant::now();
    let mut announced = false;
    loop {
        match try_lock(&f, m) {
            Ok(true) => return Ok(FileLock { f }),
            Ok(false) => {}
            Err(x) => return Err(crate::i18n::tf("err.lock_open", &[&x])),
        }
        if start.elapsed() >= wait {
            return Err(busy_msg());
        }
        if !announced {
            announced = true;
            set_stage(ST_LOCK);
        }
        check_cancel()?;
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// How long an operation waits for another Shield task on the same container.
pub const WAIT: Duration = Duration::from_secs(3);

pub fn lock_container(container: &Path, m: Mode) -> R<FileLock> {
    acquire(&lock_path_for(container), m, WAIT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_lock() -> PathBuf {
        lock_dir().join(format!("t_{}.lck", crate::entropy::rand_hex().unwrap()))
    }

    #[test]
    fn exclusive_excludes_everything() {
        let p = tmp_lock();
        let a = acquire(&p, Mode::Exclusive, Duration::ZERO).unwrap();
        let e1 = acquire(&p, Mode::Exclusive, Duration::ZERO).err().unwrap();
        let e2 = acquire(&p, Mode::Shared, Duration::from_millis(150)).err().unwrap();
        assert!(is_busy(&e1) && is_busy(&e2), "{e1} / {e2}");
        drop(a);
        assert!(acquire(&p, Mode::Exclusive, Duration::ZERO).is_ok(), "released on drop");
    }

    #[test]
    fn shared_allows_readers_but_not_writers() {
        let p = tmp_lock();
        let r1 = acquire(&p, Mode::Shared, Duration::ZERO).unwrap();
        let r2 = acquire(&p, Mode::Shared, Duration::ZERO).unwrap();
        assert!(is_busy(&acquire(&p, Mode::Exclusive, Duration::ZERO).err().unwrap()));
        drop(r1);
        assert!(acquire(&p, Mode::Exclusive, Duration::ZERO).is_err(), "one reader is still there");
        drop(r2);
        assert!(acquire(&p, Mode::Exclusive, Duration::ZERO).is_ok());
    }

    #[test]
    fn lock_file_cannot_be_deleted_while_held() {
        let p = tmp_lock();
        let a = acquire(&p, Mode::Exclusive, Duration::ZERO).unwrap();
        if cfg!(windows) {
            assert!(fs::remove_file(&p).is_err());
        }
        drop(a);
    }

    #[test]
    fn same_container_two_spellings_one_lock() {
        let d = std::env::temp_dir();
        let a = lock_path_for(&d.join("Some.SHD"));
        let b = lock_path_for(&d.join("some.shd"));
        if cfg!(windows) {
            assert_eq!(a, b);
        }
        assert_ne!(a, lock_path_for(&d.join("other.shd")));
        assert!(!a.to_string_lossy().contains("Some"), "no container name in the lock path");
    }
}
