use super::*;

fn cred(p: &str, pim: u32) -> Cred {
    Cred { pw: Zeroizing::new(p.as_bytes().to_vec()), kf: None, pim }
}

fn tmpdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shield_t_{}", rand_hex()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn no_shred() -> Opts {
    Opts { shred_src: false, force7: false, trim_after: false, wipe_free_after: false }
}

#[test]
fn roundtrip_wrongpw_and_password_change() {
    let dir = tmpdir();
    let dst = dir.join("a.shd");
    let data = vec![7u8; 150_000];
    let a = cred("correct horse battery", 0);
    encrypt_stream(&mut io::Cursor::new(data.clone()), data.len() as u64, &dst, &a, 1, "x.bin").unwrap();
    let mut out = Vec::new();
    let (m, _) = decrypt_stream(&dst, &a, &mut out).unwrap();
    assert_eq!(out, data);
    assert_eq!(m.name, "x.bin");
    assert!(decrypt_stream(&dst, &cred("wrong wrong wrong!", 0), &mut io::sink()).is_err());
    let b = cred("another long passphrase", 1);
    do_change_password(&dst, &a, &b).unwrap();
    assert!(decrypt_stream(&dst, &a, &mut io::sink()).is_err());
    let mut out2 = Vec::new();
    decrypt_stream(&dst, &b, &mut out2).unwrap();
    assert_eq!(out2, data);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn legacy_default_pim_still_opens() {
    let dir = tmpdir();
    let dst = dir.join("old.shd");
    let data = b"made by shield 1.0".to_vec();
    encrypt_stream(&mut io::Cursor::new(data.clone()), data.len() as u64, &dst, &cred("legacy password!", 0), 1, "o")
        .unwrap();
    let (_, pim) = decrypt_stream(&dst, &cred("legacy password!", DEFAULT_PIM), &mut io::sink()).unwrap();
    assert_eq!(pim, LEGACY_PIM);
    // a non-default PIM never falls back
    assert!(decrypt_stream(&dst, &cred("legacy password!", 5), &mut io::sink()).is_err());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn folder_and_file_roundtrip_with_name_collision() {
    let dir = tmpdir();
    let src = dir.join("Docs.v2");
    fs::create_dir_all(src.join("sub")).unwrap();
    fs::write(src.join("a.txt"), b"hello").unwrap();
    fs::write(src.join("sub").join("b.bin"), vec![3u8; 70_000]).unwrap();
    let c = cred("folder password 123", 0);
    let dst = dir.join("Docs.v2.shd");
    do_encrypt(&src, &dst, &c, &no_shred()).unwrap();

    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let m = do_decrypt(&dst, &out, &c).unwrap();
    assert!(m.contains("Docs.v2"), "{m}");
    assert_eq!(fs::read(out.join("Docs.v2").join("a.txt")).unwrap(), b"hello");
    assert_eq!(fs::read(out.join("Docs.v2").join("sub").join("b.bin")).unwrap().len(), 70_000);
    // second time: the name exists, so the folder gets an English suffix
    do_decrypt(&dst, &out, &c).unwrap();
    assert!(out.join("Docs.v2 (decrypted)").join("a.txt").is_file());

    let f = dir.join("note.txt");
    fs::write(&f, b"single file").unwrap();
    let fd = dir.join("note.txt.shd");
    do_encrypt(&f, &fd, &c, &no_shred()).unwrap();
    do_decrypt(&fd, &dir, &c).unwrap();
    assert_eq!(fs::read(dir.join("note (decrypted).txt")).unwrap(), b"single file");
    do_decrypt(&fd, &dir, &c).unwrap();
    assert!(dir.join("note (decrypted 2).txt").is_file());
    let _ = fs::remove_dir_all(dir);
}

/// Folder files written by Shield 1.0 (sevenz_rust::compress: empty root entry, names relative to
/// the folder itself) must still decrypt into a folder with the original name.
#[test]
fn legacy_folder_archive_decrypts() {
    let dir = tmpdir();
    let src = dir.join("Old");
    fs::create_dir_all(src.join("x")).unwrap();
    fs::write(src.join("x").join("a.txt"), b"a").unwrap();
    fs::write(src.join("b.txt"), b"b").unwrap();
    let mut arc = io::Cursor::new(Vec::new());
    sevenz_rust::compress(&src, &mut arc).unwrap();
    let data = arc.into_inner();
    let c = cred("legacy folder pass", 0);
    let dst = dir.join("Old.shd");
    encrypt_stream(&mut io::Cursor::new(data.clone()), data.len() as u64, &dst, &c, 3, "Old").unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    do_decrypt(&dst, &out, &cred("legacy folder pass", DEFAULT_PIM)).unwrap();
    assert_eq!(fs::read(out.join("Old").join("x").join("a.txt")).unwrap(), b"a");
    assert_eq!(fs::read(out.join("Old").join("b.txt")).unwrap(), b"b");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn encrypt_with_shred_removes_original() {
    let dir = tmpdir();
    let src = dir.join("secret.txt");
    fs::write(&src, vec![9u8; 10_000]).unwrap();
    let c = cred("shred test password", 0);
    let o = Opts { shred_src: true, force7: false, trim_after: false, wipe_free_after: false };
    do_encrypt(&src, &dir.join("secret.shd"), &c, &o).unwrap();
    assert!(!src.exists());
    do_decrypt(&dir.join("secret.shd"), &dir, &c).unwrap();
    assert_eq!(fs::read(&src).unwrap(), vec![9u8; 10_000]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn names_and_rules() {
    assert!(safe_name("a.txt").is_some());
    assert!(safe_name("..").is_none());
    assert!(safe_name("a/b").is_none());
    assert!(safe_name("NUL.txt").is_none());
    assert_eq!(min_password_len(DEFAULT_PIM, false), 12);
    assert_eq!(min_password_len(0, false), 20);
    assert_eq!(min_password_len(0, true), 0);
    let long = "가".repeat(200); // 600 bytes
    let m = meta_decode(&meta_encode(&Meta { len: 1, flags: 1, name: long })).unwrap();
    assert_eq!(m.name.chars().count(), 85);
}

/// cargo test --release -- --ignored --nocapture kdf_timing
#[test]
#[ignore]
fn kdf_timing() {
    let c = cred("timing", 0);
    for pim in [0, 6, DEFAULT_PIM] {
        let t = std::time::Instant::now();
        kek(&c, pim, &[0u8; SALT]).unwrap();
        println!("PIM {pim}: {:?}", t.elapsed());
    }
}
