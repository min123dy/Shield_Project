//! File manager window (7-Zip style): browse folders, open .shd containers, list / extract / add /
//! remove. Encryption, decryption and key changes are done in the encryption window (enc_app.rs).
//!
//! A-4: an open container holds no key. Every operation on it (integrity check, extract, add,
//! remove) first asks for the password, PIM and key files again (`Op` + the credential dialog),
//! and the typed secret is consumed by that one operation.

use crate::archive::EntryInfo;
use crate::compress::Strength;
use crate::container::{self, AddOpts, BodyCheck, Opened};
use crate::crypto::Cred;
use crate::engine::DecOpts;
use crate::harden::SecretBuf;
use crate::i18n::{t, tf};
use crate::job::{launch, Job};
use crate::keyfile::keyfile_opt;
use crate::progress::*;
use crate::settings::{Settings, SortBy, StartFolder};
use crate::shell::Shell;
use crate::sysinfo::{home_dir, is_hidden, is_shd, roots};
use eframe::egui;
use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsStr,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MTab {
    Files,
    Info,
    Settings,
    Help,
}

pub struct Entry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<SystemTime>,
}

/// One row of the current folder inside an open container.
pub struct Child {
    pub name: Zeroizing<String>,
    pub full: Zeroizing<String>,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<SystemTime>,
}

/// Result of a container job: the container comes back (or is dropped on failure to open).
pub struct Out {
    pub opened: Option<Opened>,
    pub res: Result<String, String>,
}

/// An operation on the open container that waits for the credentials (A-4).
#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    Check,
    ExtractSelected { sel: HashSet<String>, base: String, dir: PathBuf },
    ExtractAll { dir: PathBuf },
    Add { paths: Vec<PathBuf>, overwrite: bool },
    Remove { sel: HashSet<String> },
}

/// A question shown before an operation (overwrite / shred originals / delete entries).
pub enum Confirm {
    Add { paths: Vec<PathBuf>, clash: Vec<String> },
    Remove { sel: HashSet<String> },
}

pub struct MgrApp {
    pub sh: Shell,
    pub tab: MTab,
    pub cwd: Option<PathBuf>, // None = drive list
    pub addr: String,
    pub entries: Vec<Entry>,
    pub filter: String,
    pub sel: HashSet<PathBuf>,
    // credentials (open and every later operation; consumed by each)
    pub pending: Option<PathBuf>,
    pub pw: SecretBuf,
    pub custom_pim: bool,
    pub pim: u32,
    pub keyfiles: Vec<PathBuf>,
    pub op: Option<Op>,
    // open container
    pub open: Option<Opened>,
    pub inner: String,
    pub children: Vec<Child>,
    pub csel: HashSet<String>,
    pub strength: Strength,
    pub shred_added: bool,
    pub confirm: Option<Confirm>,
    pub job: Option<Job<Out>>,
}

fn start_dir(s: StartFolder) -> Option<PathBuf> {
    match s {
        StartFolder::Drives => None,
        StartFolder::Home => home_dir(),
        StartFolder::Documents => home_dir().map(|h| h.join("Documents")).filter(|d| d.is_dir()).or_else(home_dir),
    }
}

impl MgrApp {
    pub fn new(set: Settings, start: Option<PathBuf>) -> Self {
        let mut a = MgrApp {
            tab: MTab::Files,
            cwd: start_dir(set.start_folder),
            addr: String::new(),
            entries: vec![],
            filter: String::new(),
            sel: HashSet::new(),
            pending: None,
            pw: SecretBuf::new(),
            custom_pim: false,
            pim: set.default_pim,
            keyfiles: vec![],
            op: None,
            open: None,
            inner: String::new(),
            children: vec![],
            csel: HashSet::new(),
            strength: set.strength,
            shred_added: false,
            confirm: None,
            job: None,
            sh: Shell::new(set),
        };
        if let Some(p) = start {
            if is_shd(&p) {
                a.cwd = p.parent().map(Path::to_path_buf).or(a.cwd);
                a.pending = Some(p);
            } else if p.is_dir() {
                a.cwd = Some(p);
            } else {
                a.cwd = p.parent().map(Path::to_path_buf).or(a.cwd);
                a.sel.insert(p);
            }
        }
        a.refresh();
        a
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    // -------------------------------------------------------------- browsing

    pub fn refresh(&mut self) {
        self.entries.clear();
        self.addr = self.cwd.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        match &self.cwd {
            Some(d) => {
                if let Ok(rd) = std::fs::read_dir(d) {
                    for en in rd.flatten() {
                        let name = en.file_name().to_string_lossy().into_owned();
                        if name.starts_with(".shd_") {
                            continue; // Shield scratch/staging names
                        }
                        let md = en.metadata().ok();
                        if !self.sh.set.show_hidden && is_hidden(&name, md.as_ref()) {
                            continue;
                        }
                        self.entries.push(Entry {
                            name,
                            path: en.path(),
                            is_dir: md.as_ref().is_some_and(|m| m.is_dir()),
                            size: md.as_ref().map(|m| m.len()).unwrap_or(0),
                            mtime: md.and_then(|m| m.modified().ok()),
                        });
                    }
                } else {
                    self.sh.msg(false, t("m.cant_read"));
                }
                self.sort();
            }
            None => {
                for r in roots() {
                    self.entries.push(Entry { name: r.display().to_string(), path: r, is_dir: true, size: 0, mtime: None });
                }
            }
        }
        self.sel.retain(|p| p.exists());
    }

    fn sort(&mut self) {
        let by = self.sh.set.sort;
        self.entries.sort_by(|a, b| {
            let k = match by {
                SortBy::Name => std::cmp::Ordering::Equal,
                SortBy::Size => b.size.cmp(&a.size),
                SortBy::Date => b.mtime.cmp(&a.mtime),
                SortBy::Kind => a.path.extension().cmp(&b.path.extension()),
            };
            b.is_dir.cmp(&a.is_dir).then(k).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
    }

    pub fn go(&mut self, p: Option<PathBuf>) {
        self.cwd = p;
        self.sel.clear();
        self.refresh();
    }

    pub fn up(&mut self) {
        let parent = self.cwd.as_deref().and_then(Path::parent).map(Path::to_path_buf);
        self.go(parent);
    }

    /// Double click / Enter on a browse row.
    pub fn activate(&mut self, p: PathBuf, is_dir: bool) {
        if is_dir {
            self.go(Some(p));
        } else if is_shd(&p) {
            self.pending = Some(p);
            self.tab = MTab::Files;
        } else {
            self.launch_enc("--encrypt", &p);
        }
    }

    pub fn launch_enc(&mut self, flag: &str, p: &Path) {
        if let Err(x) = launch(&[OsStr::new(flag), p.as_os_str()]) {
            self.sh.msg(false, x);
        }
    }

    pub fn launch_enc_window(&mut self) {
        if let Err(x) = launch(&[]) {
            self.sh.msg(false, x);
        }
    }

    // -------------------------------------------------------------- container

    /// Rebuilds the rows of the current folder inside the container (folders first).
    pub fn rebuild_children(&mut self) {
        self.children.clear();
        let Some(o) = &self.open else { return };
        let base = if self.inner.is_empty() { String::new() } else { format!("{}/", self.inner) };
        let mut dirs: BTreeMap<String, (u64, Option<SystemTime>)> = BTreeMap::new();
        let mut files: Vec<&EntryInfo> = vec![];
        for en in &o.entries {
            let Some(rest) = en.name.strip_prefix(base.as_str()) else { continue };
            if rest.is_empty() {
                continue;
            }
            match rest.split_once('/') {
                Some((first, _)) => {
                    let d = dirs.entry(first.to_string()).or_insert((0, None));
                    if !en.is_dir {
                        d.0 += en.size;
                    }
                }
                None if en.is_dir => dirs.entry(rest.to_string()).or_insert((0, None)).1 = en.mtime,
                None => files.push(en),
            }
        }
        for (name, (size, mtime)) in dirs {
            let full = format!("{base}{name}");
            self.children.push(Child { name: Zeroizing::new(name), full: Zeroizing::new(full), is_dir: true, size, mtime });
        }
        let mut fs: Vec<Child> = files
            .into_iter()
            .map(|en| Child { name: Zeroizing::new(en.name[base.len()..].to_string()), full: en.name.clone(), is_dir: false, size: en.size, mtime: en.mtime })
            .collect();
        fs.sort_by_key(|a| a.name.to_lowercase());
        self.children.extend(fs);
    }

    pub fn enter(&mut self, full: &str) {
        self.inner = full.to_string();
        self.csel.clear();
        self.rebuild_children();
    }

    pub fn inner_up(&mut self) {
        let up = self.inner.rsplit_once('/').map(|(a, _)| a.to_string()).unwrap_or_default();
        self.enter(&up);
    }

    pub fn clear_credentials(&mut self) {
        self.pw.clear();
        self.keyfiles.clear();
        self.custom_pim = false;
    }

    /// Wipes the listing and any typed secret (close button, lock, window close).
    pub fn close_container(&mut self) {
        self.open = None;
        self.children.clear();
        self.csel.clear();
        self.inner.clear();
        self.confirm = None;
        self.op = None;
        self.clear_credentials();
        if self.tab == MTab::Info {
            self.tab = MTab::Files;
        }
        crate::entropy::clear_pool();
    }

    fn spawn(&mut self, title: &'static str, stages: Vec<u8>, f: impl FnOnce() -> R<Out> + Send + 'static) {
        self.job = Some(Job::spawn(title, stages, f));
        self.sh.msg(true, "");
    }

    pub fn poll_job(&mut self) {
        let Some(job) = &self.job else { return };
        let Some(r) = job.poll() else { return };
        let secs = job.secs();
        self.job = None;
        match r {
            Ok(out) => {
                let fresh = self.open.is_none() && out.opened.is_some();
                self.open = out.opened;
                if fresh {
                    self.pending = None;
                    self.inner.clear();
                    self.tab = MTab::Files;
                }
                match out.res {
                    Ok(m) => self.sh.msg(true, m + &secs),
                    Err(m) => self.sh.msg(false, m),
                }
            }
            Err(m) => {
                self.open = None; // the worker panicked with the container: start over
                self.sh.msg(false, m);
            }
        }
        self.csel.clear();
        self.rebuild_children();
        if self.open.is_none() {
            self.inner.clear();
        }
        self.refresh();
    }

    /// Builds the credentials from the typed fields and clears them (one use only).
    fn take_cred(&mut self) -> R<(Zeroizing<Vec<u8>>, Vec<PathBuf>, u32)> {
        if self.pw.is_empty() && self.keyfiles.is_empty() {
            return Err(t("p.need_pw").into());
        }
        let pim = if self.custom_pim { self.pim } else { self.sh.set.default_pim }.min(crate::format::MAX_PIM);
        let kfs = std::mem::take(&mut self.keyfiles);
        let pw = self.pw.take();
        self.custom_pim = false;
        Ok((pw?, kfs, pim))
    }

    pub fn start_open(&mut self) {
        let Some(p) = self.pending.clone() else { return };
        let (pw, kfs, pim) = match self.take_cred() {
            Ok(c) => c,
            Err(x) => return self.sh.msg(false, x),
        };
        self.spawn(t("job.open"), vec![ST_OPEN], move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            Ok(match container::open(&p, c) {
                Ok(o) => {
                    let n = o.meta.file_count;
                    Out { opened: Some(o), res: Ok(tf("m.opened", &[&n])) }
                }
                Err(x) => Out { opened: None, res: Err(x) },
            })
        });
    }

    /// Asks for the credentials, then runs `op` (A-4).
    pub fn request(&mut self, op: Op) {
        if self.open.is_some() {
            self.clear_credentials();
            self.op = Some(op);
        }
    }

    /// Runs the operation that was waiting for the credentials.
    pub fn run_op(&mut self) {
        let Some(op) = self.op.take() else { return };
        let Some(mut o) = self.open.take() else { return };
        let (pw, kfs, pim) = match self.take_cred() {
            Ok(c) => c,
            Err(x) => {
                self.open = Some(o);
                self.op = Some(op);
                return self.sh.msg(false, x);
            }
        };
        let strict = self.sh.set.strict_motw;
        let (title, stages) = match &op {
            Op::Check => (t("job.check"), vec![ST_CHECK]),
            Op::ExtractSelected { .. } => (t("job.extract_sel"), vec![ST_EXTRACT]),
            Op::ExtractAll { .. } => (t("job.extract_all"), vec![ST_DECRYPT, ST_EXTRACT]),
            Op::Add { .. } => (t("job.add"), vec![ST_SCAN, ST_DECRYPT, ST_REBUILD, ST_ENCRYPT, ST_VERIFY, ST_REPLACE]),
            Op::Remove { .. } => (t("job.remove"), vec![ST_DECRYPT, ST_REBUILD, ST_ENCRYPT, ST_VERIFY, ST_REPLACE]),
        };
        let ao = AddOpts { overwrite: false, shred_src: self.shred_added, strength: self.strength, keyfiles: kfs.clone() };
        let prefix = self.inner.clone();
        self.shred_added = false;
        self.spawn(title, stages, move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            let res = match op {
                Op::Check => {
                    let r = container::verify_body(&o, c);
                    o.body = if r.is_ok() { BodyCheck::Ok } else { BodyCheck::Failed };
                    r
                }
                Op::ExtractSelected { sel, base, dir } => container::extract_selected(&o, c, &sel, &base, &dir, DecOpts { strict_motw: strict }),
                Op::ExtractAll { dir } => crate::engine::do_decrypt(&o.path, &dir, &c, DecOpts { strict_motw: strict }),
                Op::Add { paths, overwrite } => container::add_files(&mut o, c, &paths, &prefix, &AddOpts { overwrite, ..ao }),
                Op::Remove { sel } => container::remove_entries(&mut o, c, &sel, ao.strength),
            };
            Ok(Out { opened: Some(o), res })
        });
    }

    /// Asks before overwriting same-name entries or shredding the added originals.
    pub fn request_add(&mut self, paths: Vec<PathBuf>) {
        let Some(o) = &self.open else { return };
        if paths.is_empty() {
            return;
        }
        let clash = container::conflicts(o, &paths, &self.inner);
        if clash.is_empty() && !self.shred_added {
            self.request(Op::Add { paths, overwrite: false });
        } else {
            self.confirm = Some(Confirm::Add { paths, clash });
        }
    }

    pub fn request_remove(&mut self) {
        if self.csel.is_empty() {
            return self.sh.msg(false, t("m.pick_entries"));
        }
        let sel = self.csel.clone();
        if self.sh.set.confirm_delete {
            self.confirm = Some(Confirm::Remove { sel });
        } else {
            self.request(Op::Remove { sel });
        }
    }

    /// Dropped files, auto-lock and "don't close while working".
    pub fn housekeeping(&mut self, ctx: &egui::Context) {
        let has = !self.pw.is_empty() || self.open.is_some();
        let ev = self.sh.frame(ctx, has);
        if let Some(r) = ev.lock {
            if has && !self.busy() {
                self.close_container();
                self.sh.lock_message(r);
            }
        }
        if !ev.dropped.is_empty() && !self.busy() {
            if self.open.is_some() {
                self.request_add(ev.dropped);
            } else if let Some(p) = ev.dropped.into_iter().next() {
                if is_shd(&p) {
                    self.cwd = p.parent().map(Path::to_path_buf);
                    self.refresh();
                    self.pending = Some(p);
                } else if p.is_dir() {
                    self.go(Some(p));
                } else {
                    self.go(p.parent().map(Path::to_path_buf));
                    self.sel.insert(p);
                }
            }
        }
        if ev.close_requested {
            if self.busy() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.sh.msg(false, t("shell.busy_close"));
            } else {
                self.close_container();
            }
        }
        self.sh.clipboard_after_paste(&mut [&mut self.pw]);
        if self.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        self.poll_job();
    }
}

#[cfg(test)]
#[path = "mgr_tests.rs"]
mod tests;
