use super::*;
use crate::engine::{do_encrypt, tests_support::*};
use crate::i18n::has_code;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter};
use std::io::{Cursor, Read};

fn sample(dir: &Path) -> (PathBuf, Cred) {
    let src = dir.join("Docs");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), b"alpha").unwrap();
    fs::write(src.join("sub").join("b.txt"), vec![b'b'; 100_000]).unwrap();
    let c = cred("container password 1", 0);
    let dst = dir.join("Docs.shd");
    do_encrypt(&src, &dst, &c, &opts()).unwrap();
    (dst, c)
}

fn names(o: &Opened) -> Vec<String> {
    let mut v: Vec<String> = o.entries.iter().map(|x| x.name.to_string()).collect();
    v.sort();
    v
}

fn ao() -> AddOpts {
    AddOpts { overwrite: false, shred_src: false, passes: crate::wipe::Passes::Three, strength: Strength::Auto, keyfiles: vec![] }
}

#[test]
fn open_list_info_and_wrong_password() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let o = open(&p, c.duplicate()).unwrap();
    assert_eq!(names(&o), vec!["Docs", "Docs/a.txt", "Docs/sub", "Docs/sub/b.txt"]);
    assert_eq!(o.total, 100_005);
    assert_eq!(o.meta.file_count, 2);
    assert_eq!(o.file_len, fs::metadata(&p).unwrap().len());
    assert_eq!(o.body, BodyCheck::NotChecked);
    assert!(verify_body(&o, c.duplicate()).is_ok());
    assert!(has_code(&open(&p, cred("wrong password 1", 0)).err().unwrap(), C_OPEN_BAD));
    // a random file that is not a Shield container reads the same
    let junk = dir.join("junk.shd");
    fs::write(&junk, vec![7u8; 5000]).unwrap();
    assert_eq!(open(&junk, c.duplicate()).err().unwrap(), open_bad());
    // tampered body: open still works (headers only) but the full check fails
    let mut bytes = fs::read(&p).unwrap();
    let n = bytes.len();
    bytes[n - 20] ^= 1;
    let t = dir.join("tampered.shd");
    fs::write(&t, &bytes).unwrap();
    if let Ok(o2) = open(&t, c.duplicate()) {
        assert!(verify_body(&o2, c).is_err());
    }
    let _ = fs::remove_dir_all(dir);
}

/// A-4: an open container keeps no key. Every operation derives the key again from the
/// credentials it is given, so wrong or empty credentials fail even though the list is open.
#[test]
fn open_container_keeps_no_key() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c.duplicate()).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let all: HashSet<String> = ["Docs".to_string()].into();
    assert!(has_code(&verify_body(&o, cred("wrong password 1", 0)).unwrap_err(), C_OPEN_BAD));
    for bad in [cred("wrong password 1", 0), cred("", 0), cred("container password 1", 1)] {
        assert!(verify_body(&o, bad.duplicate()).is_err());
        assert!(extract_selected(&o, bad.duplicate(), &all, "", &out, DecOpts::default()).is_err());
        assert!(add_files(&mut o, bad.duplicate(), &[], "", &ao()).is_err());
        assert!(remove_entries(&mut o, bad, &all, Strength::Auto, crate::wipe::Passes::Three).is_err());
    }
    assert_eq!(fs::read_dir(&out).unwrap().count(), 0, "nothing extracted");
    // the type has no field that could hold a key, a password or a key file digest
    let Opened { path: _, stamp: _, meta: _, file_len: _, entries: _, total: _, body: _ } = &o;
    extract_selected(&o, c, &all, "", &out, DecOpts::default()).unwrap();
    assert!(out.join("Docs").join("a.txt").is_file());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn selective_extraction() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let o = open(&p, c.duplicate()).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let sel: HashSet<String> = ["Docs/sub".to_string()].into();
    extract_selected(&o, c.duplicate(), &sel, "Docs", &out, DecOpts::default()).unwrap();
    assert_eq!(fs::read(out.join("sub").join("b.txt")).unwrap().len(), 100_000);
    assert!(!out.join("a.txt").exists());
    let one: HashSet<String> = ["Docs/a.txt".to_string()].into();
    extract_selected(&o, c, &one, "", &out, DecOpts::default()).unwrap();
    assert_eq!(fs::read(out.join("Docs").join("a.txt")).unwrap(), b"alpha");
    let names: Vec<_> = fs::read_dir(&out).unwrap().flatten().map(|d| d.file_name()).collect();
    assert!(names.iter().all(|n| !n.to_string_lossy().starts_with(".shd_")), "no staging left");
    assert_eq!(selection_map("Docs/sub/b.txt", "Docs", &sel).as_deref(), Some("sub/b.txt"));
    assert_eq!(selection_map("Docs/a.txt", "Docs", &sel), None);
    let _ = fs::remove_dir_all(dir);
}

/// B-15: what an extraction already moved out is removed again when a later step fails.
#[test]
fn rollback_removes_moved_items() {
    let dir = tmpdir();
    let a = dir.join("a.txt");
    let b = dir.join("folder");
    fs::write(&a, b"moved").unwrap();
    fs::create_dir_all(b.join("x")).unwrap();
    fs::write(b.join("x").join("y.txt"), b"moved too").unwrap();
    let m = roll_back(&[a.clone(), b.clone()]);
    assert!(!a.exists() && !b.exists(), "{m}");
    assert_eq!(m, tf("cont.rolled_back", &[&2]));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn add_files_rebuilds_verifies_and_replaces() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let before = fs::read(&p).unwrap();
    let mut o = open(&p, c.duplicate()).unwrap();
    let extra = dir.join("new.txt");
    fs::write(&extra, b"added later").unwrap();
    add_files(&mut o, c.duplicate(), std::slice::from_ref(&extra), "Docs", &ao()).unwrap();
    assert!(names(&o).contains(&"Docs/new.txt".to_string()));
    assert_ne!(fs::read(&p).unwrap()[..64], before[..64], "new salts and slots after the rebuild");
    // reopen from disk with the password: old and new entries are all there
    let o2 = open(&p, c.duplicate()).unwrap();
    assert_eq!(names(&o2), vec!["Docs", "Docs/a.txt", "Docs/new.txt", "Docs/sub", "Docs/sub/b.txt"]);
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    dec(&p, &out, &c).unwrap();
    assert_eq!(fs::read(out.join("Docs").join("new.txt")).unwrap(), b"added later");
    assert_eq!(fs::read(out.join("Docs").join("sub").join("b.txt")).unwrap().len(), 100_000);
    // same name again: refused without overwrite, replaced with it
    let mut o3 = open(&p, c.duplicate()).unwrap();
    fs::write(&extra, b"second version").unwrap();
    assert!(add_files(&mut o3, c.duplicate(), std::slice::from_ref(&extra), "Docs", &ao()).is_err());
    let ow = AddOpts { overwrite: true, ..ao() };
    add_files(&mut o3, c.duplicate(), std::slice::from_ref(&extra), "Docs", &ow).unwrap();
    let o4 = open(&p, c).unwrap();
    assert_eq!(o4.entries.iter().filter(|x| x.name.as_str() == "Docs/new.txt").count(), 1);
    let left: Vec<String> = fs::read_dir(&dir).unwrap().flatten().map(|d| d.file_name().to_string_lossy().into_owned()).collect();
    assert!(left.iter().all(|n| !n.starts_with(".shd_")), "no temp files left: {left:?}");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn remove_entries_rebuilds_without_them() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c.duplicate()).unwrap();
    let sel: HashSet<String> = ["Docs/sub".to_string()].into();
    remove_entries(&mut o, c.duplicate(), &sel, Strength::Auto, crate::wipe::Passes::Three).unwrap();
    assert_eq!(names(&o), vec!["Docs", "Docs/a.txt"]);
    let o2 = open(&p, c.duplicate()).unwrap();
    assert_eq!((o2.meta.file_count, o2.total), (1, 5));
    assert!(remove_entries(&mut o, c, &HashSet::new(), Strength::Auto, crate::wipe::Passes::Three).is_err(), "nothing selected");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn add_refuses_when_container_changed_and_keeps_original() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c.duplicate()).unwrap();
    let before = fs::read(&p).unwrap();
    // touch the container after opening (same bytes, new modification time)
    let f = fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5)).unwrap();
    drop(f);
    let extra = dir.join("x.txt");
    fs::write(&extra, b"x").unwrap();
    let err = add_files(&mut o, c, &[extra], "", &ao()).unwrap_err();
    assert!(has_code(&err, C_CHANGED), "{err}");
    assert_eq!(fs::read(&p).unwrap(), before);
    let _ = fs::remove_dir_all(dir);
}

/// B-2: while another task writes the container, opening waits and then reports E_BUSY.
#[test]
fn open_reports_busy_during_a_write() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let held = crate::lock::lock_container(&p, Mode::Exclusive).unwrap();
    let err = open(&p, c.duplicate()).err().unwrap();
    assert!(crate::lock::is_busy(&err), "{err}");
    drop(held);
    let _shared = crate::lock::lock_container(&p, Mode::Shared).unwrap();
    assert!(open(&p, c).is_ok(), "readers share the lock");
    let _ = fs::remove_dir_all(dir);
}

fn evil_archive(name: &str) -> Vec<u8> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        z.push_archive_entry(ArchiveEntry::new_file(name), Some(&b"pwned"[..])).unwrap();
        z.finish().unwrap();
    }
    buf.into_inner()
}

#[test]
fn path_attacks_are_blocked() {
    for bad in ["../evil.txt", "a/../../evil", "C:/Windows/evil", "/abs", "NUL", "a/con.txt", "x:ads", "dir/trail. ", "a\\..\\evil", "sub\\x.txt"] {
        let mut c = Cursor::new(evil_archive(bad));
        let len = c.get_ref().len() as u64;
        assert!(archive::inspect(&mut c, len).is_err(), "{bad}");
        let dir = tmpdir();
        assert!(archive::extract(&mut c, &dir, 5, &|n| Some(n.to_string())).is_err(), "{bad}");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        let _ = fs::remove_dir_all(dir);
    }
    // case-only duplicates
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        z.push_archive_entry(ArchiveEntry::new_file("A.txt"), Some(&b"1"[..])).unwrap();
        z.push_archive_entry(ArchiveEntry::new_file("a.txt"), Some(&b"2"[..])).unwrap();
        z.finish().unwrap();
    }
    let len = buf.get_ref().len() as u64;
    assert!(archive::inspect(&mut buf, len).is_err());
    // link entries (reparse attribute)
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        let mut en = ArchiveEntry::new_file("link");
        en.has_windows_attributes = true;
        en.windows_attributes = 0x400;
        z.push_archive_entry(en, Some(&b"target"[..])).unwrap();
        z.finish().unwrap();
    }
    let len = buf.get_ref().len() as u64;
    assert!(archive::inspect(&mut buf, len).is_err());
}

/// 1.2 GiB of zeros compressed with Zstandard: the ratio limit rejects it before extraction.
#[test]
fn compression_bomb_ratio_is_rejected() {
    struct Zeros(u64);
    impl Read for Zeros {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let n = (b.len() as u64).min(self.0) as usize;
            b[..n].fill(0);
            self.0 -= n as u64;
            Ok(n)
        }
    }
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        z.set_content_methods(vec![sevenz_rust2::encoder_options::ZstandardOptions::from_level(1).into()]);
        z.push_archive_entry(ArchiveEntry::new_file("zeros.bin"), Some(Zeros(1_200 << 20))).unwrap();
        z.finish().unwrap();
    }
    let len = buf.get_ref().len() as u64;
    let err = archive::inspect(&mut buf, len).err().unwrap();
    assert_eq!(err, t("arc.bomb"));
}

#[test]
fn reads_same_as_bad_password_before_auth() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut bytes = fs::read(&p).unwrap();
    bytes[3] ^= 0xFF; // a slot byte: the real slot may be either one
    bytes[SLOT + 3] ^= 0xFF;
    fs::write(&p, &bytes).unwrap();
    let r = open(&p, c).err().unwrap();
    assert_eq!(r, open_bad());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn listing_is_written_back_after_writes() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let mut o = open(&p, c.duplicate()).unwrap();
    let extra = dir.join("z.txt");
    fs::write(&extra, b"zz").unwrap();
    add_files(&mut o, c.duplicate(), &[extra], "", &ao()).unwrap();
    assert_eq!(o.body, BodyCheck::Ok);
    assert_eq!(o.stamp, stamp(&p).unwrap());
    // the refreshed state is the one a later operation checks against
    assert!(verify_body(&o, c).is_ok());
    let _ = fs::remove_dir_all(dir);
}

// ---- 3.1.0 #4: direction-control characters in names ----

fn archive_of(names: &[&str]) -> Cursor<Vec<u8>> {
    let mut buf = Cursor::new(Vec::new());
    {
        let mut z = ArchiveWriter::new(&mut buf).unwrap();
        for n in names {
            if let Some(d) = n.strip_suffix('/') {
                z.push_archive_entry::<&[u8]>(ArchiveEntry::new_directory(d), None).unwrap();
            } else {
                z.push_archive_entry(ArchiveEntry::new_file(n), Some(&b"x"[..])).unwrap();
            }
        }
        z.finish().unwrap();
    }
    buf.set_position(0);
    buf
}

#[test]
fn spoof_characters_are_listed_but_replaced_on_extraction() {
    let names = [
        "d\u{202E}ir/",
        "d\u{202E}ir/invoice\u{202E}fdp.exe",
        "photo\u{2067}gpj.scr",
        "zwj\u{200D}emoji\u{200C}.txt", // ZWJ / ZWNJ are kept
        "plain.txt",
        "desktop.ini",
        "link.URL",
    ];
    let mut c = archive_of(&names);
    let len = c.get_ref().len() as u64;
    let l = archive::inspect(&mut c, len).unwrap(); // existing containers keep opening
    assert_eq!(l.entries.len(), names.len());
    let dir = tmpdir();
    let done = archive::extract(&mut c, &dir, 100, &|n| Some(n.to_string())).unwrap();
    assert_eq!(done, archive::Extracted { files: 6, renamed: 3, risky: 2 });
    assert!(dir.join("d_ir").join("invoice_fdp.exe").is_file());
    assert!(dir.join("photo_gpj.scr").is_file());
    assert!(dir.join("zwj\u{200D}emoji\u{200C}.txt").is_file());
    let all: Vec<String> = walk_names(&dir);
    assert!(all.iter().all(|n| !n.chars().any(archive::is_spoof_char)), "{all:?}");
    let notes = done.notes();
    assert!(notes.contains('3') && notes.contains('2'), "{notes}");
    let _ = fs::remove_dir_all(dir);
}

fn walk_names(d: &Path) -> Vec<String> {
    let mut v = vec![];
    for e in fs::read_dir(d).unwrap().flatten() {
        v.push(e.file_name().to_string_lossy().into_owned());
        if e.path().is_dir() {
            v.extend(walk_names(&e.path()));
        }
    }
    v
}

#[test]
fn names_that_collide_after_replacement_stop_the_extraction() {
    for pair in [["a\u{202E}b.txt", "a_b.txt"], ["a_b.txt", "a\u{202E}b.txt"], ["a\u{202E}b.txt", "A\u{202D}B.txt"]] {
        let mut c = archive_of(&pair);
        let dir = tmpdir();
        let err = archive::extract(&mut c, &dir, 100, &|n| Some(n.to_string())).unwrap_err();
        assert!(err.contains("<U+202"), "the message shows the hidden character: {err}");
        let _ = fs::remove_dir_all(dir);
    }
}

/// 3.1.0 final, review H: names that could be the same file or look the same are duplicates.
#[test]
fn duplicate_names_are_compared_conservatively() {
    use archive::dup_key as k;
    assert_eq!(k("Dir/A.TXT"), k("dir/a.txt"), "case");
    assert_eq!(k("caf\u{e9}.txt"), k("cafe\u{301}.txt"), "NFC / NFD (macOS)");
    assert_eq!(k("\u{FF21}.txt"), k("a.txt"), "full-width letter");
    assert_eq!(k("\u{FB01}le"), k("file"), "ligature");
    assert_eq!(k("a\u{200B}b"), k("ab"), "zero width space");
    assert_eq!(k("a\u{200D}b"), k("ab"), "ZWJ is ignored for comparison");
    assert_eq!(k("x\u{FE0F}"), k("x"), "variation selector");
    assert_ne!(k("a.txt"), k("b.txt"));
    assert_ne!(k("\u{d55c}"), k("\u{d55c}\u{ae00}"));
}

/// 3.1.0 final, review H: zstd frame headers are checked before any decoder sees them.
#[test]
fn zstd_windows_are_limited() {
    use archive::{zstd_frame_window as w, MAX_ZSTD_WINDOW};
    let magic = [0x28u8, 0xB5, 0x2F, 0xFD];
    let frame = |fhd: u8, rest: &[u8]| [&magic[..], &[fhd], rest].concat();
    // window descriptor: exponent 13 (8 MiB) and 17 (128 MiB)
    assert_eq!(w(&frame(0x00, &[13 << 3])).unwrap(), (8 << 20, 6));
    assert_eq!(w(&frame(0x00, &[17 << 3])).unwrap().0, 128 << 20);
    assert_eq!(w(&frame(0x00, &[(12 << 3) | 4])).unwrap().0, (4 << 20) + (4 << 20) / 8 * 4, "mantissa");
    // single segment: the content size is the buffer
    assert_eq!(w(&frame(0x20, &[200])).unwrap(), (200, 6));
    assert_eq!(w(&frame(0x60, &[0x00, 0x01])).unwrap().0, 256 + 256, "2-byte size has +256");
    assert_eq!(w(&frame(0xA0, &[0, 0, 0, 0x08])).unwrap().0, 128 << 20);
    assert_eq!(w(&frame(0x01, &[13 << 3, 7])).unwrap_err(), "arc.zstd_dict");
    assert_eq!(w(&frame(0x08, &[13 << 3])).unwrap_err(), "arc.zstd_frame", "reserved bit");
    assert_eq!(w(&[1, 2, 3, 4, 5, 6]).unwrap_err(), "arc.zstd_frame", "not zstd");
    assert_eq!(w(&frame(0x00, &[])).unwrap_err(), "arc.zstd_frame", "cut off");
    const { assert!(MAX_ZSTD_WINDOW >= 8 << 20, "everything Shield writes (level <= 19) fits") };
}

#[test]
fn spoof_set_and_display_escaping() {
    for c in ['\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', '\u{200E}', '\u{200F}', '\u{061C}', '\u{FEFF}'] {
        assert!(archive::is_spoof_char(c), "{:04X}", c as u32);
    }
    for c in ['\u{200C}', '\u{200D}', 'a', '한', '_', '\u{2065}', '\u{2029}', '\u{FE0F}', 'é'] {
        assert!(!archive::is_spoof_char(c), "{:04X}", c as u32);
    }
    // 3.1.0 final, review H: other format characters, private use, noncharacters
    for c in ['\u{00AD}', '\u{200B}', '\u{2060}', '\u{2062}', '\u{180E}', '\u{FFF9}', '\u{E0041}', '\u{E000}', '\u{F8FF}', '\u{F0000}', '\u{10FFFD}', '\u{FDD0}', '\u{FFFE}', '\u{1FFFF}'] {
        assert!(archive::is_spoof_char(c), "{:04X}", c as u32);
    }
    // a variation selector is fine after a visible character, spoofing on its own
    assert!(!archive::has_spoof("\u{2764}\u{FE0F}.txt"), "red heart emoji");
    assert!(archive::has_spoof("\u{FE0F}x.txt") && archive::has_spoof("a\u{FE0F}\u{FE0F}.txt") && archive::has_spoof("a \u{FE0F}b"));
    assert_eq!(archive::sanitize_component("\u{FE0F}a\u{200B}b"), "_a_b");
    assert_eq!(archive::display_name("pay\u{00AD}ment"), "pay<U+00AD>ment");
    assert_eq!(archive::display_name("a\u{202E}gpj.exe"), "a<U+202E>gpj.exe");
    assert_eq!(archive::display_name("\u{FEFF}x"), "<U+FEFF>x");
    assert!(matches!(archive::display_name("plain"), std::borrow::Cow::Borrowed(_)));
    assert_eq!(archive::sanitize_component("a\u{202E}b\u{2066}c"), "a_b_c");
    for (n, risky) in [("desktop.ini", true), ("Desktop.INI", true), ("x.url", true), ("a.library-ms", true), ("b.searchConnector-ms", true), ("c.scf", true), ("d.lnk", false), ("e.exe", false), ("desktop.ini.txt", false)] {
        assert_eq!(archive::is_risky_windows_name(n), risky, "{n}");
    }
}

#[test]
fn decrypted_single_file_name_is_cleaned_too() {
    let dir = tmpdir();
    let f = dir.join("report\u{202E}fdp.exe");
    fs::write(&f, b"content").unwrap();
    let c = cred("container password 1", 0);
    let shd = dir.join("r.shd");
    do_encrypt(&f, &shd, &c, &opts()).unwrap();
    fs::remove_file(&f).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let msg = crate::engine::do_decrypt(&shd, &out, &c, crate::engine::DecOpts::default()).unwrap();
    assert_eq!(fs::read(out.join("report_fdp.exe")).unwrap(), b"content", "{msg}");
    assert_eq!(fs::read_dir(&out).unwrap().count(), 1);
    assert!(msg.contains(&crate::i18n::tf("arc.spoof_renamed", &[&1])), "{msg}");
    // the manager still lists the stored (real) name, and extracting it by that name works
    let o = open(&shd, c.duplicate()).unwrap();
    assert_eq!(o.entries[0].name.as_str(), "report\u{202E}fdp.exe");
    let sel: std::collections::HashSet<String> = [o.entries[0].name.to_string()].into();
    let out2 = dir.join("out2");
    fs::create_dir_all(&out2).unwrap();
    extract_selected(&o, c, &sel, "", &out2, crate::engine::DecOpts::default()).unwrap();
    assert!(out2.join("report_fdp.exe").is_file());
    let _ = fs::remove_dir_all(dir);
}

// ---- 3.1.0 #14 ----

#[test]
fn only_regular_files_are_opened() {
    let dir = tmpdir();
    let (p, c) = sample(&dir);
    let renamed = dir.join("picture.png");
    fs::rename(&p, &renamed).unwrap();
    assert!(open(&renamed, c.duplicate()).is_ok(), "any name");
    let bad = |p: &Path| open(p, c.duplicate()).err().unwrap();
    assert_eq!(bad(&dir.join("Docs")), not_regular(), "folder");
    // a missing file says so (the system's "not found"), as in 3.0.0, not "not a regular file"
    let missing = bad(&dir.join("nope"));
    assert_ne!(missing, not_regular(), "missing");
    assert!(missing.contains("(os error 2)"), "missing: {missing}");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&renamed, dir.join("link.shd")).unwrap();
        assert_eq!(bad(&dir.join("link.shd")), not_regular(), "link");
        let fifo = dir.join("fifo.shd");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let t0 = std::time::Instant::now();
        assert_eq!(bad(&fifo), not_regular(), "FIFO");
        assert!(t0.elapsed() < std::time::Duration::from_secs(5), "opening a FIFO never blocks");
        assert_eq!(bad(Path::new("/dev/zero")), not_regular(), "device");
    }
    #[cfg(windows)]
    for dev in [r"\\.\PhysicalDrive0", r"\\?\GLOBALROOT\Device\Null", "NUL", "CON", r"C:\dir\COM1.shd", r"\\.\pipe\x"] {
        assert!(dev.starts_with(r"\\") || !dev.starts_with('\\'), "test data: {dev}");
        assert_eq!(bad(Path::new(dev)), not_regular(), "{dev}");
    }
    // a regular file that is no container: the usual "wrong password or not a container" answer
    let junk = dir.join("junk.bin");
    fs::write(&junk, vec![1u8; 4096]).unwrap();
    assert!(has_code(&bad(&junk), C_OPEN_BAD));
    let _ = fs::remove_dir_all(dir);
}
