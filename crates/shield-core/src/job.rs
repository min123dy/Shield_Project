//! Background jobs shared by both windows. A panic or a vanished worker is always reported as a
//! failure (never as success); temporary data is cleaned by the Drop guards on the worker side.

use crate::progress::*;
use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::Ordering,
        mpsc::{channel, Receiver, TryRecvError},
    },
    time::Instant,
};

pub const C_PANIC: &str = "E_PANIC";
pub fn panic_msg() -> String {
    crate::i18n::coded(C_PANIC, "err.panic")
}

pub struct Job<T> {
    pub title: &'static str,
    pub stages: Vec<u8>,
    pub started: Instant,
    pub stage_t0: (u8, Instant),
    rx: Receiver<R<T>>,
}

impl<T: Send + 'static> Job<T> {
    pub fn spawn<F: FnOnce() -> R<T> + Send + 'static>(title: &'static str, stages: Vec<u8>, f: F) -> Job<T> {
        CANCEL.store(false, Ordering::Relaxed);
        set_stage(0);
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let r = catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(panic_msg()));
            set_stage(0);
            let _ = tx.send(r);
        });
        Job { title, stages, started: Instant::now(), stage_t0: (0, Instant::now()), rx }
    }

    /// Some(result) once the worker is done. A worker that disappeared counts as a failure.
    pub fn poll(&self) -> Option<R<T>> {
        match self.rx.try_recv() {
            Ok(r) => Some(r),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => Some(Err(panic_msg())),
        }
    }

    pub fn secs(&self) -> String {
        crate::i18n::tf("job.secs", &[&self.started.elapsed().as_secs()])
    }
}

/// Starts the other Shield window (same executable) with the given arguments.
pub fn launch(args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|x| x.to_string())?;
    std::process::Command::new(exe).args(args).spawn().map(|_| ()).map_err(|x| crate::i18n::tf("job.launch_failed", &[&x]))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn panics_become_failures() {
        let j: Job<String> = Job::spawn("t", vec![], || panic!("boom"));
        let r = loop {
            if let Some(r) = j.poll() {
                break r;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        };
        assert!(crate::i18n::has_code(&r.unwrap_err(), C_PANIC));
    }
}
