use super::*;
use crate::crypto::{encrypt_stream, read_header, Cred};
use crate::password::normalize;
use std::io::Read;

pub fn cred(p: &str, pim: u32) -> Cred {
    Cred { pw: normalize(p), kf: None, pim }
}

pub fn tmpdir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("shield_t_{}", rand_hex().unwrap()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn opts() -> Opts {
    Opts {
        shred_src: false,
        force7: false,
        trim_after: false,
        wipe_free_after: false,
        strength: Strength::Auto,
        keyfiles: vec![],
    }
}

fn sha3(p: &Path) -> [u8; 64] {
    Sha3_512::digest(fs::read(p).unwrap()).into()
}

/// Names in `dir`, ignoring nothing: proves no plaintext or temp file was left behind.
fn listing(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir).unwrap().flatten().map(|d| d.file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

#[test]
fn file_folder_empty_and_hangul_roundtrip() {
    let dir = tmpdir();
    let src = dir.join("문서 폴더");
    fs::create_dir_all(src.join("하위").join("빈 폴더")).unwrap();
    fs::write(src.join("한글 이름.txt"), "안녕하세요".repeat(1000)).unwrap();
    fs::write(src.join("empty.bin"), b"").unwrap();
    let big: Vec<u8> = (0..300_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    fs::write(src.join("하위").join("big.bin"), &big).unwrap();
    let c = cred("folder password 123", 0);
    let dst = dir.join("문서 폴더.shd");
    let m = do_encrypt(&src, &dst, &c, &opts()).unwrap();
    assert!(m.contains("복원 검증 완료"), "{m}");

    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    do_decrypt(&dst, &out, &c).unwrap();
    let r = out.join("문서 폴더");
    assert_eq!(sha3(&r.join("한글 이름.txt")), sha3(&src.join("한글 이름.txt")));
    assert_eq!(sha3(&r.join("하위").join("big.bin")), sha3(&src.join("하위").join("big.bin")));
    assert_eq!(fs::read(r.join("empty.bin")).unwrap().len(), 0);
    assert!(r.join("하위").join("빈 폴더").is_dir());
    assert_eq!(listing(&out), vec!["문서 폴더".to_string()]);
    // second time: the name exists, so the folder gets a suffix
    do_decrypt(&dst, &out, &c).unwrap();
    assert!(out.join("문서 폴더 (decrypted)").join("한글 이름.txt").is_file());

    // single empty file
    let f = dir.join("빈.txt");
    fs::write(&f, b"").unwrap();
    let fd = dir.join("빈.txt.shd");
    do_encrypt(&f, &fd, &c, &opts()).unwrap();
    do_decrypt(&fd, &out, &c).unwrap();
    assert_eq!(fs::read(out.join("빈.txt")).unwrap().len(), 0);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn existing_output_is_never_overwritten() {
    let dir = tmpdir();
    let f = dir.join("a.txt");
    fs::write(&f, b"data").unwrap();
    let dst = dir.join("a.shd");
    fs::write(&dst, b"keep me").unwrap();
    assert!(do_encrypt(&f, &dst, &cred("some long password", 0), &opts()).is_err());
    assert_eq!(fs::read(&dst).unwrap(), b"keep me");
    assert!(do_encrypt(&dir, &dir.join("inside.shd"), &cred("some long password", 0), &opts()).is_err());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn wrong_credentials_give_one_error_and_no_plaintext() {
    let dir = tmpdir();
    let f = dir.join("s.txt");
    fs::write(&f, b"secret").unwrap();
    fs::write(dir.join("k.key"), b"key file content").unwrap();
    let mut c = cred("right password!!", 1);
    c.kf = Some(crate::keyfile::keyfile_material(&[dir.join("k.key")]).unwrap());
    let dst = dir.join("s.shd");
    let mut o = opts();
    o.keyfiles = vec![dir.join("k.key")];
    do_encrypt(&f, &dst, &c, &o).unwrap();
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    let wrong_pw = Cred { pw: normalize("wrong password!!"), kf: c.kf.clone(), pim: 1 };
    let wrong_pim = Cred { pw: normalize("right password!!"), kf: c.kf.clone(), pim: 2 };
    let no_kf = cred("right password!!", 1);
    for w in [wrong_pw, wrong_pim, no_kf] {
        assert_eq!(do_decrypt(&dst, &out, &w).unwrap_err(), BAD);
    }
    assert!(listing(&out).is_empty());
    assert!(crate::crypto::kdf_params(MAX_PIM + 1).is_err());
    let p = crate::crypto::kdf_params(0).unwrap();
    assert_eq!((p.m_cost(), p.p_cost(), p.t_cost()), (256 * 1024, 4, 3));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn keyfile_inside_target_is_blocked() {
    let dir = tmpdir();
    let src = dir.join("data");
    fs::create_dir_all(&src).unwrap();
    fs::write(src.join("k.key"), b"key inside the target").unwrap();
    let mut o = opts();
    o.keyfiles = vec![src.join("k.key")];
    let err = do_encrypt(&src, &dir.join("data.shd"), &cred("long enough password", 0), &o).unwrap_err();
    assert!(err.contains("키 파일"), "{err}");
    let _ = fs::remove_dir_all(dir);
}

fn make_file(dir: &Path, data: &[u8], c: &Cred) -> PathBuf {
    let p = dir.join(format!("{}.shd", rand_hex().unwrap()));
    let mut m = Meta::new("x.bin", FLAG_ARCHIVE);
    m.real_len = data.len() as u64;
    let mut out = fs::File::create(&p).unwrap();
    encrypt_stream(&mut io::Cursor::new(data.to_vec()), &mut out, c, &mut m).unwrap();
    p
}

fn body(p: &Path, c: &Cred) -> R<Vec<u8>> {
    let mut f = File::open(p).map_err(e)?;
    let h = read_header(&mut f, c)?;
    let mut out = Vec::new();
    stream_body(&mut f, &h, &mut out)?;
    Ok(out)
}

#[test]
fn tampering_truncation_extension_and_reordering_fail() {
    let dir = tmpdir();
    let c = cred("tamper test password", 0);
    let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
    let p = make_file(&dir, &data, &c);
    assert_eq!(body(&p, &c).unwrap(), data);
    let orig = fs::read(&p).unwrap();
    let n = orig.len();
    let hdr = HEADER;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("slot", { let mut v = orig.clone(); v[5] ^= 1; v[SLOT + 5] ^= 1; v }),
        ("prefix", { let mut v = orig.clone(); v[SLOTS + 1] ^= 1; v }),
        ("meta", { let mut v = orig.clone(); v[SLOTS + PREFIX + 10] ^= 1; v }),
        ("chunk", { let mut v = orig.clone(); v[hdr + 100] ^= 1; v }),
        ("last tag", { let mut v = orig.clone(); v[n - 1] ^= 1; v }),
        ("truncated", orig[..n - 1].to_vec()),
        ("truncated chunk", orig[..hdr + CHUNK + TAG].to_vec()),
        ("extended", [orig.clone(), vec![0u8; 1]].concat()),
        ("swapped chunks", {
            let mut v = orig.clone();
            let a = hdr..hdr + CHUNK + TAG;
            let b = hdr + CHUNK + TAG..hdr + 2 * (CHUNK + TAG);
            let (x, y) = (v[a.clone()].to_vec(), v[b.clone()].to_vec());
            v[a].copy_from_slice(&y);
            v[b].copy_from_slice(&x);
            v
        }),
    ];
    for (what, bytes) in cases {
        let q = dir.join(format!("{what}.shd"));
        fs::write(&q, &bytes).unwrap();
        assert!(body(&q, &c).is_err(), "{what} must fail");
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn unknown_version_is_reported_only_after_authentication() {
    let dir = tmpdir();
    let c = cred("version test password", 0);
    let p = dir.join("v3.shd");
    let mut m = Meta::new("x", FLAG_ARCHIVE);
    m.version = 3;
    m.real_len = 10;
    encrypt_stream(&mut io::Cursor::new(vec![1u8; 10]), &mut fs::File::create(&p).unwrap(), &c, &mut m).unwrap();
    assert_eq!(body(&p, &c).unwrap_err(), UNSUPPORTED);
    assert_eq!(body(&p, &cred("wrong", 0)).unwrap_err(), BAD);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn length_hiding_padding() {
    let dir = tmpdir();
    let c = cred("padding test password", 0);
    let data = vec![42u8; 1000];
    let a = make_file(&dir, &data, &c);
    let b = make_file(&dir, &data, &c);
    let (la, lb) = (fs::metadata(&a).unwrap().len(), fs::metadata(&b).unwrap().len());
    assert_ne!(la, lb, "same input, different ciphertext sizes (1/65537 false alarm chance)");
    for (p, l) in [(&a, la), (&b, lb)] {
        let min = expected_size(1000).unwrap();
        let max = expected_size(1000 + pad_max(1000)).unwrap();
        assert!(l >= min && l <= max);
        assert_eq!(body(p, &c).unwrap(), data);
    }
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn password_change_and_full_rekey() {
    let dir = tmpdir();
    let f = dir.join("doc.txt");
    fs::write(&f, b"rekey me").unwrap();
    let dst = dir.join("doc.shd");
    let a = cred("first password 123", 0);
    do_encrypt(&f, &dst, &a, &opts()).unwrap();
    let dek0 = read_header(&mut File::open(&dst).unwrap(), &a).unwrap().dek;

    let b = cred("second password 456", 1);
    do_change_password(&dst, &a, &b).unwrap();
    assert_eq!(read_header(&mut File::open(&dst).unwrap(), &a).err().unwrap(), BAD);
    let dek1 = read_header(&mut File::open(&dst).unwrap(), &b).unwrap().dek;
    assert_eq!(*dek0, *dek1, "password change keeps the DEK");

    let c3 = cred("third password 789", 0);
    do_full_rekey(&dst, &b, &c3).unwrap();
    assert_eq!(read_header(&mut File::open(&dst).unwrap(), &b).err().unwrap(), BAD);
    let dek2 = read_header(&mut File::open(&dst).unwrap(), &c3).unwrap().dek;
    assert_ne!(*dek1, *dek2, "full rekey makes a new DEK");
    let out = dir.join("out");
    fs::create_dir_all(&out).unwrap();
    do_decrypt(&dst, &out, &c3).unwrap();
    assert_eq!(fs::read(out.join("doc.txt")).unwrap(), b"rekey me");
    assert_eq!(listing(&dir), vec!["doc.shd", "doc.txt", "out"]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn nfc_password_opens_regardless_of_input_form() {
    use unicode_normalization::UnicodeNormalization;
    let dir = tmpdir();
    let composed = "비밀번호는한글로만듭니다";
    let decomposed: String = composed.nfd().collect();
    let p = make_file(&dir, b"hangul", &cred(composed, 0));
    assert_eq!(body(&p, &cred(&decomposed, 0)).unwrap(), b"hangul");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn encrypt_with_shred_removes_only_listed_files() {
    let dir = tmpdir();
    let src = dir.join("secret.txt");
    fs::write(&src, vec![9u8; 10_000]).unwrap();
    let c = cred("shred test password", 0);
    let mut o = opts();
    o.shred_src = true;
    let m = do_encrypt(&src, &dir.join("secret.shd"), &c, &o).unwrap();
    assert!(m.contains("파쇄"), "{m}");
    assert!(!src.exists());
    do_decrypt(&dir.join("secret.shd"), &dir, &c).unwrap();
    assert_eq!(fs::read(&src).unwrap(), vec![9u8; 10_000]);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn shred_protects_changed_new_and_hardlinked_files() {
    let dir = tmpdir();
    let src = dir.join("t");
    fs::create_dir_all(&src).unwrap();
    for n in ["a", "b", "c"] {
        fs::write(src.join(n), n.repeat(100)).unwrap();
    }
    let mut m = Manifest::default();
    Manifest::scan(&src, "", &mut m).unwrap();
    fs::write(src.join("b"), b"changed after the list was fixed").unwrap();
    fs::write(src.join("new"), b"not in the list").unwrap();
    fs::hard_link(src.join("c"), dir.join("c-link")).unwrap();
    let rep = shred_listed(&m, 1);
    assert_eq!(rep.shredded, 1, "{rep:?}");
    assert!(!src.join("a").exists());
    assert!(src.join("b").exists() && src.join("new").exists() && src.join("c").exists());
    assert_eq!(rep.changed.len(), 1);
    assert_eq!(rep.hardlinked.len(), 1);
    assert_eq!(rep.dirs_kept.len(), 1, "folder with unlisted items is kept");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn failed_restore_verification_deletes_result_and_keeps_original() {
    let dir = tmpdir();
    let f = dir.join("orig.txt");
    fs::write(&f, b"original").unwrap();
    let c = cred("verify test password", 0);
    let mut m = Manifest::default();
    Manifest::scan(&f, "", &mut m).unwrap();
    let mut st = SecTemp::create(&dir).unwrap();
    let plan = compress::plan(m.total, 1 << 30, 1, Strength::Auto);
    archive::pack(&mut st, &mut m, &plan).unwrap();
    let (h, part, _) = seal_archive(st, &dir, &c, Meta::new("orig.txt", FLAG_ARCHIVE)).unwrap();
    let (mut want, mut dirs) = (Digests::new(), BTreeSet::new());
    m.expected(&mut want, &mut dirs).unwrap();
    want.get_mut("orig.txt").unwrap().1[0] ^= 1; // pretend the restored data differs
    let part_path = part.path.clone();
    assert!(verify_container(&part.path, &h, &c, &want, &dirs, m.total).is_err());
    drop(part);
    assert!(!part_path.exists());
    assert_eq!(fs::read(&f).unwrap(), b"original");
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn fast_strength_records_zstd_in_meta() {
    let dir = tmpdir();
    let f = dir.join("z.txt");
    fs::write(&f, "zstd ".repeat(10_000)).unwrap();
    let c = cred("zstd test password", 0);
    let mut o = opts();
    o.strength = Strength::Fast;
    do_encrypt(&f, &dir.join("z.shd"), &c, &o).unwrap();
    let h = read_header(&mut File::open(dir.join("z.shd")).unwrap(), &c).unwrap();
    assert_eq!((h.meta.comp_method, h.meta.comp_level), (COMP_ZSTD, 3));
    assert_eq!((h.meta.file_count, h.meta.total_unpacked), (1, 50_000));
    let out = dir.join("o");
    fs::create_dir_all(&out).unwrap();
    do_decrypt(&dir.join("z.shd"), &out, &c).unwrap();
    assert_eq!(fs::read(out.join("z.txt")).unwrap(), "zstd ".repeat(10_000).as_bytes());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn leftover_staging_is_detected_after_a_crash() {
    let dir = tmpdir();
    let st = crate::staging::Stage::create(&dir).unwrap();
    let live = st.path.clone();
    assert!(!crate::staging::leftovers().contains(&live), "own active stage is not a leftover");
    // a stage written by a process that no longer exists (killed while extracting)
    let dead = dir.join(format!(".shd_{}_x", rand_hex().unwrap()));
    fs::create_dir(&dead).unwrap();
    fs::write(dead.join("plain.txt"), b"left behind").unwrap();
    crate::staging::register_as(u32::MAX - 7, &dead);
    assert!(crate::staging::leftovers().contains(&dead));
    let (ok, bad) = crate::staging::remove_leftovers(std::slice::from_ref(&dead));
    assert_eq!((ok, bad.len()), (1, 0));
    assert!(!dead.exists());
    assert!(!crate::staging::leftovers().contains(&dead));
    drop(st);
    assert!(!live.exists());
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn chunk_reader_random_access() {
    let dir = tmpdir();
    let c = cred("chunk reader password", 0);
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
    let p = make_file(&dir, &data, &c);
    let mut f = File::open(&p).unwrap();
    let h = read_header(&mut f, &c).unwrap();
    let mut cr = ChunkReader::new(f, &h);
    cr.seek(SeekFrom::Start(200_000)).unwrap();
    let mut b = vec![0u8; 1000];
    cr.read_exact(&mut b).unwrap();
    assert_eq!(b, data[200_000..201_000]);
    cr.seek(SeekFrom::Start(0)).unwrap();
    let mut all = Vec::new();
    cr.read_to_end(&mut all).unwrap();
    assert_eq!(all, data, "logical length is real_len (padding not exposed)");
    let _ = fs::remove_dir_all(dir);
}
