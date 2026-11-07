//! Cross-process locks (B-2 container lock, B-5 journal lock).
//!
//! Why `LockFileEx` on a separate lock file, and not on the container itself:
//! * the container is replaced by an atomic rename (`MoveFileExW`); a lock on the old file object
//!   would not cover the new one, and holding the container open would block that rename;
//! * an advisory lock on a small side file is released by the kernel when the handle is closed,
//!   which includes a crash or kill of the process (no stale lock to clean up by hand);
//! * a plain "lock file exists" scheme (create_new) leaves a stale file after a crash.
//!
//! The lock files live in `<config dir>/locks/` (`%LOCALAPPDATA%\Shield`, `~/.config/shield`) and
//! are named by the SHA3-256 of the container's resolved (on Windows case-folded) path, so no file
//! name is written anywhere and two spellings of one path share one lock. Windows opens them
//! without DELETE sharing (can't be removed while held); Linux uses flock on a 0600 file opened
//! with O_NOFOLLOW.

use crate::i18n::{coded, has_code};
use crate::progress::*;
use sha3::{Digest, Sha3_256};
use std::{
    fs::File,
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

fn try_lock(f: &File, m: Mode) -> io::Result<bool> {
    // std: LockFileEx on Windows, flock on Linux (released by the kernel when the handle closes)
    let r = match m {
        Mode::Exclusive => f.try_lock(),
        Mode::Shared => f.try_lock_shared(),
    };
    match r {
        Ok(()) => Ok(true),
        Err(std::fs::TryLockError::WouldBlock) => Ok(false),
        Err(std::fs::TryLockError::Error(x)) => Err(x),
    }
}

fn unlock(f: &File) -> io::Result<()> {
    f.unlock()
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
    let f = shield_platform::fs::open_lock_file(lock_file).map_err(|x| crate::i18n::tf("err.lock_open", &[&x]))?;
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
            assert!(std::fs::remove_file(&p).is_err());
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
