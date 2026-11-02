use super::*;

/// Runs `f` with a journal of its own (this thread only).
fn with_journal<T>(f: impl FnOnce(&Path) -> T) -> T {
    let d = std::env::temp_dir().join(format!("shield_jt_{}", rand_hex().unwrap()));
    fs::create_dir_all(&d).unwrap();
    let j = d.join("staging.lst");
    JOURNAL_OVERRIDE.with(|o| *o.borrow_mut() = Some(j.clone()));
    let r = f(&d);
    JOURNAL_OVERRIDE.with(|o| *o.borrow_mut() = None);
    let _ = fs::remove_dir_all(&d);
    r
}

fn stage_dir(parent: &Path) -> PathBuf {
    parent.join(format!(".shd_{}_x", rand_hex().unwrap()))
}

#[test]
fn names_are_strict() {
    assert!(is_stage_name(&format!(".shd_{}_x", "0".repeat(24))));
    for bad in [".shd__x", ".shd_ZZ_x", "shd_00_x", &format!(".shd_{}_x", "A".repeat(24)), &format!(".shd_{}_x/..", "0".repeat(24))] {
        assert!(!is_stage_name(bad), "{bad}");
    }
}

#[test]
fn round_trip_and_unique_temp_names() {
    with_journal(|d| {
        let a = stage_dir(d);
        let b = stage_dir(d);
        register_as(1, 2, &a).unwrap();
        register_as(3, 4, &b).unwrap();
        let v = read_list().unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!((v[0].pid, v[0].start, v[0].path()), (1, 2, a.clone()));
        unregister(&a).unwrap();
        assert_eq!(read_list().unwrap().len(), 1);
        let tmp_left = fs::read_dir(d).unwrap().flatten().any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert!(!tmp_left, "temp files are renamed into place");
    });
}

#[test]
fn dead_owner_and_reused_pid_are_leftovers() {
    with_journal(|d| {
        let dead = stage_dir(d);
        fs::create_dir(&dead).unwrap();
        register_as(u32::MAX - 7, 1, &dead).unwrap();
        // our own pid but a different start time = an earlier process that had the same pid
        let reused = stage_dir(d);
        fs::create_dir(&reused).unwrap();
        register_as(std::process::id(), 12345, &reused).unwrap();
        // ours, alive: never reported
        let live = stage_dir(d);
        fs::create_dir(&live).unwrap();
        let (pid, start) = me();
        register_as(pid, start, &live).unwrap();
        let l: Vec<PathBuf> = leftovers().unwrap().iter().map(Entry::path).collect();
        assert!(l.contains(&dead) && l.contains(&reused) && !l.contains(&live), "{l:?}");
        let (n, bad) = remove_leftovers(&leftovers().unwrap());
        assert_eq!((n, bad.len()), (2, 0), "{bad:?}");
        assert!(!dead.exists() && !reused.exists() && live.exists());
    });
}

#[test]
fn live_owner_entry_survives_before_its_folder_exists() {
    with_journal(|d| {
        let p = stage_dir(d);
        let (pid, start) = me();
        register_as(pid, start, &p).unwrap();
        leftovers().unwrap();
        assert_eq!(read_list().unwrap().len(), 1, "a registered-but-not-yet-created folder keeps its entry");
    });
}

#[test]
fn corrupt_journal_is_an_error_and_can_be_reset() {
    with_journal(|d| {
        fs::write(journal(), "garbage without tabs\n").unwrap();
        assert!(leftovers().is_err(), "a damaged journal is never read as 'nothing left'");
        assert!(Stage::create(d).is_err(), "nothing is extracted without a journal entry");
        let orphan = stage_dir(d);
        fs::create_dir(&orphan).unwrap();
        let found = reset_journal(Some(d)).unwrap();
        assert!(found.iter().any(|en| en.path() == orphan));
        assert!(journal().with_extension("lst.bad").exists());
        assert!(leftovers().unwrap().is_empty());
        assert_eq!(remove_leftovers(&found).0, 1);
        assert!(!orphan.exists());
    });
}

#[test]
fn unwritable_journal_stops_stage_creation() {
    with_journal(|d| {
        // a folder where the journal file should be: the atomic replace fails
        fs::create_dir_all(journal()).unwrap();
        let before = fs::read_dir(d).unwrap().count();
        assert!(Stage::create(d).is_err());
        let staged = fs::read_dir(d).unwrap().flatten().any(|e| is_stage_name(&e.file_name().to_string_lossy()));
        assert!(!staged, "the folder is not created when it could not be recorded");
        assert!(fs::read_dir(d).unwrap().count() <= before + 1);
    });
}

#[test]
fn failed_cleanup_keeps_the_entry() {
    with_journal(|d| {
        let st = Stage::create(d).unwrap();
        let f = st.path.join("plain.txt");
        fs::write(&f, b"secret").unwrap();
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let h = fs::OpenOptions::new().read(true).share_mode(1).open(&f).unwrap();
            let p = st.path.clone();
            assert!(st.finish().is_err());
            assert!(read_list().unwrap().iter().any(|en| en.path() == p), "entry stays after a failed removal");
            drop(h);
            assert_eq!(remove_leftovers(&[read_list().unwrap()[0].clone()]).0, 1);
        }
        #[cfg(not(windows))]
        st.finish().unwrap();
    });
}

#[test]
fn removal_refuses_links_and_foreign_names() {
    with_journal(|d| {
        let en = Entry { pid: 0, start: 0, parent: d.to_path_buf(), name: "not_ours".into() };
        fs::create_dir(en.path()).unwrap();
        assert!(removable(&en).is_err());
        let root = Entry { pid: 0, start: 0, parent: PathBuf::from(if cfg!(windows) { "C:\\" } else { "/" }), name: format!(".shd_{}_x", "0".repeat(24)) };
        assert!(removable(&root).is_err());
    });
}
