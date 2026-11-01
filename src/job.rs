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

pub const PANIC_MSG: &str = "내부 오류(패닉)로 작업을 중단했습니다. 원본은 지우지 않았고 임시 자료는 정리했습니다. 결과를 성공으로 보지 마세요.";

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
            let r = catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(PANIC_MSG.to_string()));
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
            Err(TryRecvError::Disconnected) => Some(Err(PANIC_MSG.to_string())),
        }
    }

    pub fn secs(&self) -> String {
        format!(" ({}초)", self.started.elapsed().as_secs())
    }
}

/// Starts the other Shield window (same executable) with the given arguments.
pub fn launch(args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|x| x.to_string())?;
    std::process::Command::new(exe).args(args).spawn().map(|_| ()).map_err(|x| format!("창을 열지 못했습니다: {x}"))
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
        assert_eq!(r.unwrap_err(), PANIC_MSG);
    }
}
