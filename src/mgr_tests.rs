use super::*;
use crate::engine::tests_support::{cred, opts, tmpdir};

fn app_with_container() -> (MgrApp, PathBuf, PathBuf) {
    let dir = tmpdir();
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src").join("x.txt"), b"x").unwrap();
    let shd = dir.join("src.shd");
    crate::engine::do_encrypt(&dir.join("src"), &shd, &cred("manager test password", 0), &opts()).unwrap();
    let app = MgrApp::new(Settings::default(), Some(shd.clone()));
    (app, shd, dir)
}

#[test]
fn closing_wipes_listing_and_secrets() {
    let (mut app, shd, dir) = app_with_container();
    assert_eq!(app.pending.as_deref(), Some(shd.as_path()));
    app.open = Some(container::open(&shd, cred("manager test password", 0)).unwrap());
    app.rebuild_children();
    assert_eq!(app.children.len(), 1);
    app.enter("src");
    assert_eq!(app.children[0].name.as_str(), "x.txt");
    app.pw.push_str("typed");
    app.op = Some(Op::Check);
    app.tab = MTab::Info;
    app.close_container(); // same path as the auto-lock
    assert!(app.open.is_none() && app.children.is_empty() && app.inner.is_empty() && app.pw.is_empty() && app.op.is_none());
    assert_eq!(app.tab, MTab::Files);
    let _ = std::fs::remove_dir_all(dir);
}

/// A-4: every operation asks for the credentials; nothing runs and nothing is reused without them.
#[test]
fn operations_wait_for_fresh_credentials() {
    let (mut app, shd, dir) = app_with_container();
    app.open = Some(container::open(&shd, cred("manager test password", 0)).unwrap());
    app.pw.push_str("left over from the open screen");
    app.request(Op::Check);
    assert_eq!(app.op, Some(Op::Check));
    assert!(app.pw.is_empty(), "a request starts with empty credential fields");
    app.run_op();
    assert!(app.job.is_none(), "no job without a password");
    assert_eq!(app.op, Some(Op::Check), "the request stays until cancelled");
    assert!(app.open.is_some(), "the listing is kept");
    // a request without an open container does nothing
    app.close_container();
    app.request(Op::Check);
    assert!(app.op.is_none());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn hidden_files_and_sorting_follow_settings() {
    let dir = tmpdir();
    std::fs::write(dir.join(".hidden"), b"h").unwrap();
    std::fs::write(dir.join("b.txt"), b"bb").unwrap();
    std::fs::write(dir.join("a.txt"), b"aaaa").unwrap();
    std::fs::create_dir(dir.join("zdir")).unwrap();
    let mut app = MgrApp::new(Settings::default(), Some(dir.clone()));
    let names = |a: &MgrApp| a.entries.iter().map(|e| e.name.clone()).collect::<Vec<_>>();
    assert_eq!(names(&app), vec!["zdir", "a.txt", "b.txt"], "folders first, hidden left out");
    app.sh.set.show_hidden = true;
    app.sh.set.sort = SortBy::Size;
    app.refresh();
    assert_eq!(names(&app), vec!["zdir", "a.txt", "b.txt", ".hidden"]);
    let _ = std::fs::remove_dir_all(dir);
}
