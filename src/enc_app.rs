//! Encryption window: state, input checks and job start/finish.
//! Tabs: 암호화 / 복호화 / 비밀번호·키 교체 / 디스크 정리 / 알고리즘·정보 / 사용법.
//! Browsing and opening containers live in the separate file manager window (mgr_app.rs).

use crate::compress::Strength;
use crate::crypto::Cred;
use crate::engine::*;
use crate::format::MAX_PIM;
use crate::harden::SecretBuf;
use crate::job::{launch, Job};
use crate::keyfile::{keyfile_opt, KF_DEFAULT_KIB};
use crate::progress::*;
use crate::sysinfo::is_shd;
use crate::{entropy, ui, wipe};
use eframe::egui;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const IDLE: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Encrypt,
    Decrypt,
    Rekey,
    Disk,
    Algo,
    Help,
}

pub struct EncApp {
    pub tab: Tab,
    pub selected: Option<PathBuf>,
    pub keyfiles: Vec<PathBuf>,
    pub pw: SecretBuf,
    pub pw2: SecretBuf,
    pub custom_pim: bool,
    pub pim: u32,
    pub kf_only_ack: bool,
    pub gen_kib: u32,
    pub choose_dest: bool,
    pub strength: Strength,
    pub shred_src: bool,
    pub shred_ack: bool,
    pub force7: bool,
    pub trim_after: bool,
    pub wipe_free_after: bool,
    pub full_rekey: bool,
    pub new_pw: SecretBuf,
    pub new_pw2: SecretBuf,
    pub new_custom_pim: bool,
    pub new_pim: u32,
    pub new_keyfiles: Vec<PathBuf>,
    pub new_kf_only_ack: bool,
    pub disk_drive: Option<PathBuf>,
    pub disk_trim_after_wipe: bool,
    pub status: String,
    pub ok: bool,
    pub job: Option<Job<String>>,
    pub last_act: Instant,
    pub leftovers: Vec<PathBuf>,
}

/// "name.shd" next to `src`, or "name (2).shd", ... when taken.
fn default_output(src: &Path) -> Option<PathBuf> {
    let dir = src.parent()?;
    let name = src.file_name()?.to_string_lossy().into_owned();
    (1..10_000u32)
        .map(|i| if i == 1 { dir.join(format!("{name}.shd")) } else { dir.join(format!("{name} ({i}).shd")) })
        .find(|p| std::fs::symlink_metadata(p).is_err())
}

fn pim_of(custom: bool, pim: u32) -> u32 {
    if custom { pim.min(MAX_PIM) } else { DEFAULT_PIM }
}

/// Shared checks for new credentials (encrypt and rekey).
#[allow(clippy::too_many_arguments)]
fn new_cred_problems(v: &mut Vec<String>, pw: &SecretBuf, pw2: &SecretBuf, pim: u32, custom: bool, kfs: &[PathBuf], kf_ack: bool, what: &str) {
    let min = min_password_len(pim, !kfs.is_empty());
    if pw.is_empty() && kfs.is_empty() {
        v.push(format!("{what}비밀번호 또는 키 파일이 필요합니다."));
    } else if pw.char_count() < min {
        v.push(if custom && pim < DEFAULT_PIM && kfs.is_empty() {
            format!("PIM이 권장값({DEFAULT_PIM})보다 낮아 {what}비밀번호는 {min}자 이상이어야 합니다 (현재 {}자).", pw.char_count())
        } else {
            format!("{what}비밀번호를 {min}자 이상 입력하세요 (현재 {}자). 키 파일을 함께 쓰면 제한이 없습니다.", pw.char_count())
        });
    }
    if !pw.ct_eq(pw2) {
        v.push(format!("{what}비밀번호 확인이 일치하지 않습니다."));
    }
    if pw.is_empty() && !kfs.is_empty() && !kf_ack {
        v.push("비밀번호 없이 키 파일만 쓰려면 아래 확인란을 체크하세요.".into());
    }
}

impl EncApp {
    pub fn new(start: Option<(Tab, PathBuf)>) -> Self {
        let mut a = EncApp {
            tab: Tab::Encrypt,
            selected: None,
            keyfiles: vec![],
            pw: SecretBuf::new(),
            pw2: SecretBuf::new(),
            custom_pim: false,
            pim: DEFAULT_PIM,
            kf_only_ack: false,
            gen_kib: KF_DEFAULT_KIB,
            choose_dest: false,
            strength: Strength::Auto,
            shred_src: false,
            shred_ack: false,
            force7: false,
            trim_after: true,
            wipe_free_after: false,
            full_rekey: false,
            new_pw: SecretBuf::new(),
            new_pw2: SecretBuf::new(),
            new_custom_pim: false,
            new_pim: DEFAULT_PIM,
            new_keyfiles: vec![],
            new_kf_only_ack: false,
            disk_drive: None,
            disk_trim_after_wipe: true,
            status: String::new(),
            ok: true,
            job: None,
            last_act: Instant::now(),
            leftovers: crate::staging::leftovers(),
        };
        if let Some((t, p)) = start {
            a.select(p);
            a.tab = t;
        }
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

    /// Selecting a .shd file switches to decryption, anything else to encryption.
    pub fn select(&mut self, p: PathBuf) {
        if matches!(self.tab, Tab::Encrypt | Tab::Decrypt | Tab::Algo | Tab::Help) {
            self.tab = if is_shd(&p) { Tab::Decrypt } else { Tab::Encrypt };
        }
        if self.tab == Tab::Disk {
            self.disk_drive = wipe::drive_letter(&p).map(|l| PathBuf::from(format!("{l}:\\")));
        }
        self.selected = Some(p);
    }

    pub fn open_manager(&mut self, p: Option<&Path>) {
        let r = match p {
            Some(p) if is_shd(p) => launch(&[OsStr::new("--open"), p.as_os_str()]),
            Some(p) => launch(&[OsStr::new("--manager"), p.as_os_str()]),
            None => launch(&[OsStr::new("--manager")]),
        };
        if let Err(x) = r {
            self.set(false, x);
        }
    }

    fn secrets_empty(&self) -> bool {
        self.pw.is_empty() && self.pw2.is_empty() && self.new_pw.is_empty() && self.new_pw2.is_empty()
    }

    fn clear_secrets(&mut self) {
        self.pw.clear();
        self.pw2.clear();
        self.new_pw.clear();
        self.new_pw2.clear();
    }

    fn spawn(&mut self, title: &'static str, stages: Vec<u8>, f: impl FnOnce() -> R<String> + Send + 'static) {
        self.job = Some(Job::spawn(title, stages, f));
        self.set(true, "");
    }

    fn poll_job(&mut self) {
        let Some(job) = &self.job else { return };
        let Some(r) = job.poll() else { return };
        let secs = job.secs();
        match r {
            Ok(m) => self.set(true, m + &secs),
            Err(m) => self.set(false, m),
        }
        self.job = None;
        self.selected = None;
        entropy::clear_pool();
    }

    // -------------------------------------------------------------- validation (shown live)

    pub fn encrypt_problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.selected.is_none() {
            v.push("암호화할 파일 또는 폴더를 선택하세요.".into());
        }
        let pim = pim_of(self.custom_pim, self.pim);
        new_cred_problems(&mut v, &self.pw, &self.pw2, pim, self.custom_pim, &self.keyfiles, self.kf_only_ack, "");
        if self.shred_src && !self.shred_ack {
            v.push("원본 파쇄를 쓰려면 '복구할 수 없음을 이해했습니다'를 체크하세요.".into());
        }
        v
    }

    pub fn decrypt_problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        match &self.selected {
            Some(p) if p.is_file() => {}
            _ => v.push(".shd 파일을 선택하세요.".into()),
        }
        if self.pw.is_empty() && self.keyfiles.is_empty() {
            v.push("비밀번호 또는 키 파일을 입력하세요.".into());
        }
        v
    }

    pub fn rekey_problems(&self) -> Vec<String> {
        let mut v = self.decrypt_problems();
        let pim = pim_of(self.new_custom_pim, self.new_pim);
        new_cred_problems(&mut v, &self.new_pw, &self.new_pw2, pim, self.new_custom_pim, &self.new_keyfiles, self.new_kf_only_ack, "새 ");
        v
    }

    // -------------------------------------------------------------- actions

    pub fn start_encrypt(&mut self) {
        if !self.encrypt_problems().is_empty() {
            return;
        }
        let Some(src) = self.selected.clone() else { return };
        let auto = default_output(&src);
        let dst = if self.choose_dest || auto.is_none() {
            let name = src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "drive".into());
            let mut d = rfd::FileDialog::new().set_title("암호화 파일 저장").set_file_name(format!("{name}.shd"));
            if let Some(p) = src.parent() {
                d = d.set_directory(p);
            }
            d.save_file()
        } else {
            auto
        };
        let Some(dst) = dst else { return };
        let pw = self.pw.take();
        self.pw2.clear();
        let kfs = self.keyfiles.clone();
        let pim = pim_of(self.custom_pim, self.pim);
        let opts = Opts {
            shred_src: self.shred_src,
            force7: self.force7,
            trim_after: self.trim_after,
            wipe_free_after: self.wipe_free_after,
            strength: self.strength,
            keyfiles: kfs.clone(),
        };
        let mut stages = vec![ST_SCAN, ST_COMPRESS, ST_ENCRYPT, ST_VERIFY];
        if opts.shred_src {
            stages.push(ST_SHRED);
            if opts.wipe_free_after {
                stages.push(ST_WIPE_FREE);
            }
            if opts.trim_after {
                stages.push(ST_TRIM);
            }
        }
        self.shred_src = false;
        self.shred_ack = false;
        self.kf_only_ack = false;
        self.spawn("암호화", stages, move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            do_encrypt(&src, &dst, &c, &opts)
        });
    }

    pub fn start_decrypt(&mut self) {
        if !self.decrypt_problems().is_empty() {
            return;
        }
        let Some(src) = self.selected.clone() else { return };
        let outdir = if self.choose_dest {
            rfd::FileDialog::new().set_title("복호화 결과를 저장할 폴더").pick_folder()
        } else {
            Some(parent_dir(&src))
        };
        let Some(outdir) = outdir else { return };
        let pw = self.pw.take();
        let kfs = self.keyfiles.clone();
        let pim = pim_of(self.custom_pim, self.pim);
        self.spawn("복호화", vec![ST_DECRYPT, ST_EXTRACT], move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            do_decrypt(&src, &outdir, &c)
        });
    }

    pub fn start_rekey(&mut self) {
        if !self.rekey_problems().is_empty() {
            return;
        }
        let Some(src) = self.selected.clone() else { return };
        let old_pw = self.pw.take();
        let new_pw = self.new_pw.take();
        self.new_pw2.clear();
        let (okf, nkf) = (self.keyfiles.clone(), self.new_keyfiles.clone());
        let (opim, npim) = (pim_of(self.custom_pim, self.pim), pim_of(self.new_custom_pim, self.new_pim));
        let full = self.full_rekey;
        self.new_kf_only_ack = false;
        let (title, stages) = if full {
            ("전체 키 교체", vec![ST_DECRYPT, ST_ENCRYPT, ST_VERIFY, ST_REPLACE])
        } else {
            ("비밀번호 변경", vec![ST_REWRAP])
        };
        self.spawn(title, stages, move || {
            crate::keyfile::check_overlap(&nkf, &[&src])?;
            let old = Cred { pw: old_pw, kf: keyfile_opt(&okf)?, pim: opim };
            let new = Cred { pw: new_pw, kf: keyfile_opt(&nkf)?, pim: npim };
            if full { do_full_rekey(&src, &old, &new) } else { do_change_password(&src, &old, &new) }
        });
    }

    pub fn start_trim(&mut self) {
        let Some(l) = self.disk_drive.as_deref().and_then(wipe::drive_letter) else {
            self.set(false, "TRIM할 드라이브를 선택하세요.");
            return;
        };
        self.spawn("TRIM", vec![ST_TRIM], move || {
            set_stage(ST_TRIM);
            wipe::trim_volume(l)
        });
    }

    pub fn start_wipe_free(&mut self) {
        let Some(d) = self.disk_drive.clone() else {
            self.set(false, "정리할 드라이브를 선택하세요.");
            return;
        };
        let trim = self.disk_trim_after_wipe;
        let mut stages = vec![ST_WIPE_FREE];
        if trim {
            stages.push(ST_TRIM);
        }
        self.spawn("여유 공간 덮어쓰기", stages, move || {
            set_stage(ST_WIPE_FREE);
            let mut m = wipe::wipe_free_space(&d)?;
            if let (true, Some(l)) = (trim, wipe::drive_letter(&d)) {
                set_stage(ST_TRIM);
                m += &match wipe::trim_volume(l) {
                    Ok(t) => format!(" · {t}"),
                    Err(x) => format!(" · {x}"),
                };
            }
            Ok(m)
        });
    }

    /// Mouse entropy, idle wipe of typed secrets, dropped files, "don't close while working".
    fn housekeeping(&mut self, ctx: &egui::Context) {
        let (active, close, dropped) = ctx.input(|i| {
            for ev in &i.events {
                if let egui::Event::PointerMoved(p) = ev {
                    entropy::mix_mouse(p.x, p.y, i.time);
                }
            }
            let d: Vec<PathBuf> = i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect();
            (!i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO, i.viewport().close_requested(), d)
        });
        if let Some(p) = dropped.into_iter().next() {
            if !self.busy() {
                self.select(p);
            }
        }
        if active {
            self.last_act = Instant::now();
        } else if self.last_act.elapsed() > IDLE && !self.secrets_empty() {
            self.clear_secrets();
            entropy::clear_pool();
            self.set(true, "2분 동안 입력이 없어 입력된 비밀번호를 지웠습니다.");
        }
        if close && self.busy() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.set(false, "작업 중에는 창을 닫을 수 없습니다. 먼저 [취소]를 누르세요.");
        }
        ctx.request_repaint_after(Duration::from_secs(5));
        self.poll_job();
    }
}

impl eframe::App for EncApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.housekeeping(ctx);
        if self.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("🛡 Shield").strong().size(18.0));
                ui.separator();
                ui.add_enabled_ui(!self.busy(), |ui| {
                    ui::tabs(
                        ui,
                        &mut self.tab,
                        &[
                            (Tab::Encrypt, "🔒 암호화"),
                            (Tab::Decrypt, "🔓 복호화"),
                            (Tab::Rekey, "🔑 비밀번호·키 교체"),
                            (Tab::Disk, "💽 디스크 정리"),
                            (Tab::Algo, "🧬 알고리즘·정보"),
                            (Tab::Help, "❓ 사용법"),
                        ],
                    );
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🗂 파일 관리자").on_hover_text("파일 탐색 · .shd 열기 창을 엽니다").clicked() {
                        self.open_manager(None);
                    }
                });
            });
            ui.add_space(2.0);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(4.0);
            if let Some(job) = &mut self.job {
                ui::progress_view(ui, job);
            } else {
                ui::status_line(ui, self.ok, &self.status, "파일·폴더를 이 창에 끌어다 놓아도 됩니다.");
            }
            ui.add_space(2.0);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            let m = ui::leftover_banner(ui, &mut self.leftovers);
            self.apply_msg(m);
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                ui.add_enabled_ui(!self.busy(), |ui| match self.tab {
                    Tab::Encrypt => self.view_encrypt(ui),
                    Tab::Decrypt => self.view_decrypt(ui),
                    Tab::Rekey => self.view_rekey(ui),
                    Tab::Disk => self.view_disk(ui),
                    Tab::Algo => crate::enc_views::view_algo(ui),
                    Tab::Help => ui::usage_view(ui, "❓ 사용법 (암호화 창)", crate::help::ENC_USAGE),
                });
            });
        });
    }
}
