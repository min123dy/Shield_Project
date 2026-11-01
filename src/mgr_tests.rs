use super::*;

#[test]
fn closing_wipes_key_listing_and_secrets() {
    let dir = std::env::temp_dir().join(format!("shield_mg_{}", crate::entropy::rand_hex().unwrap()));
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src").join("x.txt"), b"x").unwrap();
    let c = Cred { pw: crate::password::normalize("manager test password"), kf: None, pim: 0 };
    let o = crate::engine::Opts {
        shred_src: false,
        force7: false,
        trim_after: false,
        wipe_free_after: false,
        strength: Strength::Auto,
        keyfiles: vec![],
    };
    let shd = dir.join("src.shd");
    crate::engine::do_encrypt(&dir.join("src"), &shd, &c, &o).unwrap();
    let mut app = MgrApp::new(Some(shd.clone()));
    assert_eq!(app.pending.as_deref(), Some(shd.as_path()));
    app.open = Some(container::open(&shd, c, vec![]).unwrap());
    app.rebuild_children();
    assert_eq!(app.children.len(), 1);
    app.enter("src");
    assert_eq!(app.children[0].name.as_str(), "x.txt");
    app.pw.push_str("typed");
    app.tab = MTab::Info;
    app.close_container(); // same path as the idle timeout
    assert!(app.open.is_none() && app.children.is_empty() && app.inner.is_empty() && app.pw.is_empty());
    assert_eq!(app.tab, MTab::Files);
    let _ = std::fs::remove_dir_all(dir);
}
