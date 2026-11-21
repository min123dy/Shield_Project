//! Cancelling a secure delete (3.1.0 final, docs/10 section 2-5). A test program of its own: the
//! cancel flag is global, so nothing else may run in this process meanwhile (one test function).
#![allow(clippy::disallowed_methods)] // reads the files this test made

use shield_core::progress::{CANCEL, PROG_DONE};
use shield_core::secure_delete::{confirm_with_token, execute, permit_with, scan_with, Guard, Outcome, WipePermit};
use shield_core::settings::Settings;
use shield_core::wipe::Passes;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("shield_wipe_cancel_{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn no_pw() -> WipePermit {
    permit_with(&Settings::default(), &Settings::default(), None).unwrap()
}

fn confirmed(items: &[PathBuf], passes: Passes) -> shield_core::secure_delete::ConfirmedWipePlan {
    let plan = scan_with(items, passes, &Guard::with(vec![], vec![], vec![])).unwrap();
    let token = plan.token();
    confirm_with_token(plan, &token, true).unwrap()
}

#[test]
fn cancel_stops_between_files_at_once_and_inside_a_file_after_the_pass() {
    let d = dir();
    // 1. cancelled before the first file: nothing is touched, every entry says so
    let (a, b) = (d.join("a.txt"), d.join("b.txt"));
    std::fs::write(&a, b"keep a").unwrap();
    std::fs::write(&b, b"keep b").unwrap();
    let c = confirmed(&[a.clone(), b.clone()], Passes::Three);
    CANCEL.store(true, Ordering::SeqCst);
    let rep = execute(c, no_pw());
    CANCEL.store(false, Ordering::SeqCst);
    assert!(rep.cancelled && !rep.all_ok(), "{rep:?}");
    assert_eq!(rep.results.len(), 2);
    assert!(rep.results.iter().all(|r| matches!(r.outcome, Outcome::Skipped(_))), "{rep:?}");
    assert_eq!(std::fs::read(&a).unwrap(), b"keep a");
    assert_eq!(std::fs::read(&b).unwrap(), b"keep b");

    // 2. cancelled while a big file is overwritten: the current pass ends, the file is reported
    //    as partly overwritten and not deleted; the next file is not touched
    let big = d.join("big.bin");
    let len: u64 = 96 << 20;
    {
        use std::io::Write;
        let mut f = std::fs::File::create(&big).unwrap();
        let chunk = vec![0x5Au8; 1 << 20];
        for _ in 0..(len >> 20) {
            f.write_all(&chunk).unwrap();
        }
        f.sync_all().unwrap();
    }
    let after = d.join("after.txt");
    std::fs::write(&after, b"keep after").unwrap();
    let c = confirmed(&[big.clone(), after.clone()], Passes::Seven);
    let watcher = std::thread::spawn(|| {
        let t0 = Instant::now();
        // as soon as the first megabytes of the first pass are written
        while PROG_DONE.load(Ordering::SeqCst) < (4 << 20) && t0.elapsed() < Duration::from_secs(60) {
            std::thread::sleep(Duration::from_millis(1));
        }
        CANCEL.store(true, Ordering::SeqCst);
    });
    let rep = execute(c, no_pw());
    watcher.join().unwrap();
    CANCEL.store(false, Ordering::SeqCst);
    assert!(rep.cancelled, "{rep:?}");
    let big_r = rep.results.iter().find(|r| r.path.file_name() == big.file_name()).unwrap();
    match &big_r.outcome {
        Outcome::Partial(m) => assert!(m.contains("of 7") || m.contains("7"), "says how many passes: {m}"),
        o => panic!("a file stopped inside its passes is reported as partly done, got {o:?}"),
    }
    assert!(big.exists(), "a partly overwritten file is not deleted");
    assert_eq!(std::fs::metadata(&big).unwrap().len(), len);
    let after_r = rep.results.iter().find(|r| r.path.file_name() == after.file_name()).unwrap();
    assert!(matches!(after_r.outcome, Outcome::Skipped(_)), "{after_r:?}");
    assert_eq!(std::fs::read(&after).unwrap(), b"keep after");
    let _ = std::fs::remove_dir_all(d);
}
