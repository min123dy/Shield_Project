//! File manager window (7-Zip style): browse folders, open .shd containers, list / extract / add.
//! Encryption, decryption and key changes are done in the encryption window (enc_app.rs), which
//! this window starts with the selected path.

use crate::archive::EntryInfo;
use crate::compress::Strength;
use crate::container::{self, AddOpts, BodyCheck, Opened};
use crate::crypto::Cred;
use crate::harden::SecretBuf;
use crate::job::{launch, Job};
use crate::keyfile::keyfile_opt;
use crate::progress::*;
use crate::sysinfo::{is_shd, roots};
use crate::{entropy, format::DEFAULT_PIM};
use eframe::egui;
use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsStr,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};
use zeroize::Zeroizing;

/// Typed secrets are wiped after this long without input.
pub const IDLE_SECRETS: Duration = Duration::from_secs(120);
/// An open container (key + listing) is closed after this long without input.
pub const IDLE_CONTAINER: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MTab {
    Files,
    Info,
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

/// Add request waiting for the user's confirmation (overwrite / shred originals).
pub struct PendingAdd {
    pub paths: Vec<PathBuf>,
    pub clash: Vec<String>,
}

pub struct MgrApp {
    pub tab: MTab,
    pub cwd: Option<PathBuf>, // None = drive list
    pub addr: String,
    pub entries: Vec<Entry>,
    pub filter: String,
    pub sel: HashSet<PathBuf>,
    // unlock
    pub pending: Option<PathBuf>,
    pub pw: SecretBuf,
    pub custom_pim: bool,
    pub pim: u32,
    pub keyfiles: Vec<PathBuf>,
    // open container
    pub open: Option<Opened>,
    pub inner: String,
    pub children: Vec<Child>,
    pub csel: HashSet<String>,
    pub strength: Strength,
    pub shred_added: bool,
    pub confirm: Option<PendingAdd>,
    // common
    pub status: String,
    pub ok: bool,
    pub job: Option<Job<Out>>,
    pub last_act: Instant,
    pub leftovers: Vec<PathBuf>,
}

fn home() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(PathBuf::from)
}

impl MgrApp {
    pub fn new(start: Option<PathBuf>) -> Self {
        let mut a = MgrApp {
            tab: MTab::Files,
            cwd: home(),
            addr: String::new(),
            entries: vec![],
            filter: String::new(),
            sel: HashSet::new(),
            pending: None,
            pw: SecretBuf::new(),
            custom_pim: false,
            pim: DEFAULT_PIM,
            keyfiles: vec![],
            open: None,
            inner: String::new(),
            children: vec![],
            csel: HashSet::new(),
            strength: Strength::Auto,
            shred_added: false,
            confirm: None,
            status: String::new(),
            ok: true,
            job: None,
            last_act: Instant::now(),
            leftovers: crate::staging::leftovers(),
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

    pub fn set(&mut self, ok: bool, m: impl Into<String>) {
        self.ok = ok;
        self.status = m.into();
    }

    pub fn apply_msg(&mut self, m: Option<(bool, String)>) {
        if let Some((ok, s)) = m {
            self.set(ok, s);
        }
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    pub fn pim_value(&self) -> u32 {
        if self.custom_pim { self.pim.min(crate::format::MAX_PIM) } else { DEFAULT_PIM }
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
                        self.entries.push(Entry {
                            name,
                            path: en.path(),
                            is_dir: md.as_ref().is_some_and(|m| m.is_dir()),
                            size: md.as_ref().map(|m| m.len()).unwrap_or(0),
                            mtime: md.and_then(|m| m.modified().ok()),
                        });
                    }
                } else {
                    self.set(false, "폴더를 읽을 수 없습니다 (권한 또는 경로 확인).");
                }
                self.entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
            }
            None => {
                for r in roots() {
                    self.entries.push(Entry { name: r.display().to_string(), path: r, is_dir: true, size: 0, mtime: None });
                }
            }
        }
        self.sel.retain(|p| p.exists());
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
            self.set(false, x);
        }
    }

    pub fn launch_enc_window(&mut self) {
        if let Err(x) = launch(&[]) {
            self.set(false, x);
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
                None if en.is_dir => {
                    dirs.entry(rest.to_string()).or_insert((0, None)).1 = en.mtime;
                }
                None => files.push(en),
            }
        }
        for (name, (size, mtime)) in dirs {
            let full = format!("{base}{name}");
            self.children.push(Child { name: Zeroizing::new(name), full: Zeroizing::new(full), is_dir: true, size, mtime });
        }
        let mut fs: Vec<Child> = files
            .into_iter()
            .map(|en| Child {
                name: Zeroizing::new(en.name[base.len()..].to_string()),
                full: en.name.clone(),
                is_dir: false,
                size: en.size,
                mtime: en.mtime,
            })
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

    /// Wipes the key and the listing (close button, idle timeout, window close).
    pub fn close_container(&mut self) {
        self.open = None;
        self.children.clear();
        self.csel.clear();
        self.inner.clear();
        self.confirm = None;
        self.pw.clear();
        if self.tab == MTab::Info {
            self.tab = MTab::Files;
        }
        entropy::clear_pool();
    }

    fn spawn(&mut self, title: &'static str, stages: Vec<u8>, f: impl FnOnce() -> R<Out> + Send + 'static) {
        self.job = Some(Job::spawn(title, stages, f));
        self.set(true, "");
    }

    fn poll_job(&mut self) {
        let Some(job) = &self.job else { return };
        let Some(r) = job.poll() else { return };
        let secs = job.secs();
        self.job = None;
        match r {
            Ok(out) => {
                let had = self.open.is_none() && out.opened.is_some();
                self.open = out.opened;
                if had {
                    self.pending = None;
                    self.inner.clear();
                    self.tab = MTab::Files;
                }
                match out.res {
                    Ok(m) => self.set(true, m + &secs),
                    Err(m) => self.set(false, m),
                }
            }
            Err(m) => {
                self.open = None; // the worker panicked with the container: start over
                self.set(false, m);
            }
        }
        self.csel.clear();
        self.rebuild_children();
        if self.open.is_none() {
            self.inner.clear();
        }
        self.refresh();
    }

    pub fn start_open(&mut self) {
        let Some(p) = self.pending.clone() else { return };
        if self.pw.is_empty() && self.keyfiles.is_empty() {
            self.set(false, "비밀번호 또는 키 파일을 입력하세요.");
            return;
        }
        let pw = self.pw.take();
        let kfs = self.keyfiles.clone();
        let pim = self.pim_value();
        self.spawn("열기", vec![ST_OPEN], move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            Ok(match container::open(&p, c, kfs) {
                Ok(o) => {
                    let n = o.hdr.meta.file_count;
                    Out { opened: Some(o), res: Ok(format!("열었습니다: 파일 {n}개 (본문 전체는 아직 미검사)")) }
                }
                Err(x) => Out { opened: None, res: Err(x) },
            })
        });
    }

    /// Runs `f` on the open container in a worker; the container comes back with the result.
    fn with_open(&mut self, title: &'static str, stages: Vec<u8>, f: impl FnOnce(&mut Opened) -> R<String> + Send + 'static) {
        let Some(mut o) = self.open.take() else { return };
        self.spawn(title, stages, move || {
            let res = f(&mut o);
            Ok(Out { opened: Some(o), res })
        });
    }

    pub fn start_check(&mut self) {
        self.with_open("본문 전체 검사", vec![ST_CHECK], |o| {
            let r = container::verify_body(o);
            o.body = if r.is_ok() { BodyCheck::Ok } else { BodyCheck::Failed };
            r
        });
    }

    pub fn start_extract_selected(&mut self) {
        if self.csel.is_empty() {
            self.set(false, "추출할 항목을 선택하세요.");
            return;
        }
        let Some(dir) = rfd::FileDialog::new().set_title("추출할 폴더").pick_folder() else { return };
        let (sel, base) = (self.csel.clone(), self.inner.clone());
        self.with_open("선택 항목 추출", vec![ST_EXTRACT], move |o| container::extract_selected(o, &sel, &base, &dir));
    }

    pub fn start_extract_all(&mut self) {
        let Some(dir) = rfd::FileDialog::new().set_title("전체를 풀 폴더").pick_folder() else { return };
        self.with_open("전체 추출", vec![ST_DECRYPT, ST_EXTRACT], move |o| {
            let c = o.cred.duplicate();
            crate::engine::do_decrypt(&o.path, &dir, &c)
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
            self.start_add(paths, false);
        } else {
            self.confirm = Some(PendingAdd { paths, clash });
        }
    }

    pub fn start_add(&mut self, paths: Vec<PathBuf>, overwrite: bool) {
        let ao = AddOpts { overwrite, shred_src: self.shred_added, strength: self.strength };
        let prefix = self.inner.clone();
        let mut stages = vec![ST_SCAN, ST_DECRYPT, ST_REBUILD, ST_ENCRYPT, ST_VERIFY, ST_REPLACE];
        if ao.shred_src {
            stages.push(ST_SHRED);
        }
        self.shred_added = false;
        self.with_open("파일 추가", stages, move |o| container::add_files(o, &paths, &prefix, &ao));
    }

    /// Mouse entropy, idle wipes, dropped files and "don't close while working".
    pub fn housekeeping(&mut self, ctx: &egui::Context) {
        let (active, close, dropped) = ctx.input(|i| {
            for ev in &i.events {
                if let egui::Event::PointerMoved(p) = ev {
                    entropy::mix_mouse(p.x, p.y, i.time);
                }
            }
            let d: Vec<PathBuf> = i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect();
            (!i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO, i.viewport().close_requested(), d)
        });
        if !dropped.is_empty() && !self.busy() {
            if self.open.is_some() {
                self.request_add(dropped);
            } else if let Some(p) = dropped.into_iter().next() {
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
        if active || self.busy() {
            self.last_act = Instant::now();
        } else {
            let idle = self.last_act.elapsed();
            if idle > IDLE_CONTAINER && self.open.is_some() {
                self.close_container();
                self.set(true, "5분 동안 조작이 없어 열린 컨테이너의 키와 목록을 지우고 닫았습니다.");
            } else if idle > IDLE_SECRETS && !self.pw.is_empty() {
                self.pw.clear();
                entropy::clear_pool();
                self.set(true, "2분 동안 입력이 없어 입력된 비밀번호를 지웠습니다.");
            }
        }
        if close {
            if self.busy() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.set(false, "작업 중에는 창을 닫을 수 없습니다. 먼저 [취소]를 누르세요.");
            } else {
                self.close_container();
            }
        }
        ctx.request_repaint_after(Duration::from_secs(5));
        self.poll_job();
    }
}

#[cfg(test)]
#[path = "mgr_tests.rs"]
mod tests;
