//! Encryption window: state, input checks and dialogs (jobs: enc_jobs.rs).
//! Tabs: encrypt / decrypt / password and key change / disk cleanup / settings / algorithms / help.
//! Browsing and opening containers live in the separate file manager window (mgr_app.rs).

use crate::engine::*;
use crate::progress::R;
use crate::format::MAX_PIM;
use crate::harden::SecretBuf;
use crate::i18n::{has_code, t, tf};
use crate::job::{launch, Job};
use crate::settings::{Settings, StartScreen};
use crate::shell::Shell;
use crate::sysinfo::is_shd;
use crate::wipe::Passes;
use crate::{ui, Start};
use eframe::egui;
use std::{
    ffi::OsStr,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Encrypt,
    Decrypt,
    Rekey,
    Disk,
    Settings,
    Algo,
    Help,
}

/// Job that overwrites or deletes data and therefore shows the snapshot / storage warning first.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShredAction {
    Encrypt,
    Rekey,
}

/// A dialog waiting for the user (B-9 / B-10, 3.0 §2 / §5).
#[derive(Clone, PartialEq, Debug)]
pub enum Pending {
    WeakEncrypt(Vec<String>),
    WeakRekey(Vec<String>),
    Ads(String),
    /// Several items from Explorer: separately or bundled?
    Multi(usize),
    /// Before overwriting: what may survive (snapshots, flash storage), passes to use.
    Shred(ShredAction, Vec<String>),
}

pub struct EncApp {
    pub sh: Shell,
    pub tab: Tab,
    /// Items to encrypt (editable list).
    pub items: Vec<PathBuf>,
    /// Container for decryption / key change.
    pub selected: Option<PathBuf>,
    pub recent: Vec<PathBuf>,
    pub keyfiles: Vec<PathBuf>,
    pub pw: SecretBuf,
    pub pw2: SecretBuf,
    pub custom_pim: bool,
    pub pim: u32,
    pub kf_only_ack: bool,
    pub shred_ack: bool,
    /// Overwrite passes for shredding originals and the old data of a full rekey.
    pub passes: Passes,
    pub new_pw: SecretBuf,
    pub new_pw2: SecretBuf,
    pub new_custom_pim: bool,
    pub new_pim: u32,
    pub new_keyfiles: Vec<PathBuf>,
    pub new_kf_only_ack: bool,
    /// Any folder on the volume to TRIM / wipe.
    pub disk_drive: Option<PathBuf>,
    pub job: Option<Job<String>>,
    pub pending: Option<Pending>,
}

pub use crate::outname::{bundle_output, default_output};

pub const GATE_ENCRYPT: u8 = 1;
pub const GATE_DECRYPT: u8 = 2;
pub const GATE_REKEY: u8 = 3;

/// The one password check (`password::check_new`) for a new credential of this window.
pub fn new_cred_check(pw: &SecretBuf, pw2: &SecretBuf, pim: u32, kfs: &[PathBuf]) -> crate::password::Check {
    check_new_password(pw.as_str(), Some(pw.ct_eq(pw2)), pw.overflow, pim, !kfs.is_empty())
}

/// What blocks a new credential (encrypt and rekey). Weak but usable passwords are not here:
/// they are listed live under the field and confirmed in a dialog (`request_*`).
fn new_cred_problems(v: &mut Vec<String>, pw: &SecretBuf, pw2: &SecretBuf, pim: u32, kfs: &[PathBuf], kf_ack: bool, new: bool) {
    let k = |a: &'static str, b: &'static str| if new { b } else { a };
    for b in new_cred_check(pw, pw2, pim, kfs).blocks {
        // the window's own wording for "nothing given" mentions key files too
        v.push(if b == t("pw.b_empty") { t(k("p.need_cred", "p.need_new_cred")).into() } else { b });
    }
    if pw.is_empty() && !kfs.is_empty() && !kf_ack {
        v.push(t("p.kf_only_ack").into());
    }
}

impl EncApp {
    pub fn new(set: Settings, start: Start) -> Self {
        let tab = if set.start_screen == StartScreen::Decrypt { Tab::Decrypt } else { Tab::Encrypt };
        let mut a = EncApp {
            tab,
            items: vec![],
            selected: None,
            recent: vec![],
            keyfiles: vec![],
            pw: SecretBuf::new(),
            pw2: SecretBuf::new(),
            custom_pim: false,
            pim: set.default_pim,
            kf_only_ack: false,
            shred_ack: false,
            passes: crate::ui_prefs::passes_floor(set.ui.enc_passes, set.shred_passes),
            new_pw: SecretBuf::new(),
            new_pw2: SecretBuf::new(),
            new_custom_pim: false,
            new_pim: set.default_pim,
            new_keyfiles: vec![],
            new_kf_only_ack: false,
            disk_drive: None,
            job: None,
            pending: None,
            sh: Shell::new(set),
        };
        match start {
            Start::Encrypt(items) => {
                a.tab = Tab::Encrypt;
                for p in items {
                    a.select(p);
                }
                if a.items.len() > 1 {
                    a.pending = Some(Pending::Multi(a.items.len()));
                }
            }
            Start::Decrypt(p) => {
                a.tab = Tab::Decrypt;
                if let Some(p) = p {
                    a.select(p);
                }
            }
            Start::Settings => a.tab = Tab::Settings,
            _ => {}
        }
        a
    }

    pub fn pim_of(&self, custom: bool, pim: u32) -> u32 {
        if custom { pim.min(MAX_PIM) } else { self.sh.set.default_pim.min(MAX_PIM) }
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// A .shd file is the container to decrypt / rekey; anything else joins the items to encrypt.
    pub fn select(&mut self, p: PathBuf) {
        if self.tab == Tab::Disk {
            self.disk_drive = Some(p);
            return;
        }
        let shd = is_shd(&p) && p.is_file();
        if matches!(self.tab, Tab::Encrypt | Tab::Decrypt | Tab::Algo | Tab::Help | Tab::Settings) {
            self.tab = if shd { Tab::Decrypt } else { Tab::Encrypt };
        }
        if self.sh.set.recent_files && !self.recent.contains(&p) {
            self.recent.insert(0, p.clone());
            self.recent.truncate(8);
        }
        if shd && self.tab != Tab::Encrypt {
            self.selected = Some(p);
        } else if !self.items.contains(&p) {
            self.items.push(p);
        }
    }

    pub fn open_manager(&mut self, p: Option<&Path>) {
        let r = match p {
            Some(p) if is_shd(p) => launch(&[OsStr::new("--open"), p.as_os_str()]),
            Some(p) => launch(&[OsStr::new("--manager"), p.as_os_str()]),
            None => launch(&[OsStr::new("--manager")]),
        };
        if let Err(x) = r {
            self.sh.msg(false, x);
        }
    }

    pub fn has_secrets(&self) -> bool {
        !(self.pw.is_empty() && self.pw2.is_empty() && self.new_pw.is_empty() && self.new_pw2.is_empty())
    }

    pub fn clear_secrets(&mut self) {
        self.pw.clear();
        self.pw2.clear();
        self.new_pw.clear();
        self.new_pw2.clear();
        self.recent.clear();
        self.pending = None;
    }

    pub(crate) fn spawn(&mut self, title: &'static str, stages: Vec<u8>, f: impl FnOnce() -> R<String> + Send + 'static) {
        self.job = Some(Job::spawn(title, stages, f));
        self.sh.msg(true, "");
    }

    fn poll_job(&mut self) {
        let Some(job) = &self.job else { return };
        let Some(r) = job.poll() else { return };
        let secs = job.secs();
        self.job = None;
        crate::entropy::clear_pool();
        match r {
            Ok(m) => {
                self.sh.msg(true, m + &secs);
                self.selected = None;
                self.items.clear();
            }
            Err(m) if has_code(&m, C_ADS) => {
                // the password was used and wiped: the user enters it again after choosing (A-4)
                self.pending = Some(Pending::Ads(m.clone()));
                self.sh.msg(false, m);
            }
            Err(m) => self.sh.msg(false, m),
        }
    }

    // -------------------------------------------------------------- validation (shown live)

    pub fn encrypt_problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.items.is_empty() {
            v.push(t("p.pick_target").into());
        }
        if let Some(p) = self.items.iter().find(|p| std::fs::symlink_metadata(p).is_err()) {
            v.push(tf("multi.missing", &[&p.display()]));
        }
        let pim = self.pim_of(self.custom_pim, self.pim);
        new_cred_problems(&mut v, &self.pw, &self.pw2, pim, &self.keyfiles, self.kf_only_ack, false);
        if self.sh.set.shred_default && !self.shred_ack {
            v.push(t("p.shred_ack").into());
        }
        v
    }

    pub fn decrypt_problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        match &self.selected {
            Some(p) if p.is_file() => {}
            _ => v.push(t("p.pick_shd").into()),
        }
        if self.pw.overflow {
            v.push(tf("ui.pw_too_long", &[&crate::harden::SECRET_CAP]));
        }
        if self.pw.is_empty() && self.keyfiles.is_empty() {
            v.push(t("p.need_pw").into());
        }
        v
    }

    pub fn rekey_problems(&self) -> Vec<String> {
        let mut v = self.decrypt_problems();
        let pim = self.pim_of(self.new_custom_pim, self.new_pim);
        new_cred_problems(&mut v, &self.new_pw, &self.new_pw2, pim, &self.new_keyfiles, self.new_kf_only_ack, true);
        v
    }

    // -------------------------------------------------------------- confirmations

    /// B-10: a weak new password needs an explicit confirmation (Cancel is the default).
    pub fn request_encrypt(&mut self) {
        if !self.encrypt_problems().is_empty() {
            return;
        }
        let pim = self.pim_of(self.custom_pim, self.pim);
        let r = new_cred_check(&self.pw, &self.pw2, pim, &self.keyfiles).warnings;
        if r.is_empty() {
            self.confirm_shred(ShredAction::Encrypt);
        } else {
            self.pending = Some(Pending::WeakEncrypt(r));
        }
    }

    pub fn request_rekey(&mut self) {
        if !self.rekey_problems().is_empty() {
            return;
        }
        let pim = self.pim_of(self.new_custom_pim, self.new_pim);
        let r = new_cred_check(&self.new_pw, &self.new_pw2, pim, &self.new_keyfiles).warnings;
        if r.is_empty() {
            self.confirm_shred(ShredAction::Rekey);
        } else {
            self.pending = Some(Pending::WeakRekey(r));
        }
    }

    /// 3.0 §2: before anything is overwritten or deleted, say what may survive (snapshots / VSS,
    /// flash and copy-on-write storage). Jobs that overwrite nothing start right away.
    fn confirm_shred(&mut self, a: ShredAction) {
        let paths: Vec<&Path> = match a {
            ShredAction::Encrypt if self.sh.set.shred_default => self.items.iter().map(PathBuf::as_path).collect(),
            ShredAction::Rekey => self.selected.iter().map(PathBuf::as_path).collect(),
            ShredAction::Encrypt => return self.start_encrypt(),
        };
        let ex = crate::wipe::exposure(&paths);
        let mut lines = ex.snapshot_lines.clone();
        if ex.not_guaranteed {
            lines.push(t("dlg.shred_flash").into());
        }
        lines.push(t("dlg.shred_body").into());
        self.pending = Some(Pending::Shred(a, lines));
    }

    /// Starts a job after the "protections not in effect" question when needed (3.0.0 §4).
    pub fn gated(&mut self, job: u8) {
        if self.sh.gate(job) {
            self.run_gated(job);
        }
    }

    fn run_gated(&mut self, job: u8) {
        match job {
            GATE_ENCRYPT => self.request_encrypt(),
            GATE_DECRYPT => self.start_decrypt(),
            _ => self.request_rekey(),
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if let Some(job) = self.sh.gate_dialog(ctx) {
            self.run_gated(job);
        }
        let Some(p) = self.pending.clone() else { return };
        let r = match &p {
            Pending::WeakEncrypt(r) | Pending::WeakRekey(r) => ui::confirm_modal(ctx, "weak", t("dlg.weak_title"), r, t("dlg.weak_use")),
            Pending::Ads(m) => ui::confirm_modal(ctx, "ads", t("dlg.ads_title"), &[m.clone(), t("dlg.ads_body").into()], t("dlg.ads_include")),
            Pending::Multi(n) => ui::choice_modal(ctx, "multi", t("multi.title"), &[tf("multi.body", &[n])], t("multi.bundle"), t("multi.separate")),
            Pending::Shred(a, lines) => {
                let passes = *a == ShredAction::Encrypt || self.sh.set.ui.full_rekey;
                ui::shred_modal(ctx, t("dlg.shred_title"), lines, passes.then_some(&mut self.passes), t("dlg.shred_go"))
            }
        };
        let Some(yes) = r else { return };
        self.pending = None;
        match (p, yes) {
            (Pending::WeakEncrypt(_), true) => self.confirm_shred(ShredAction::Encrypt),
            (Pending::WeakRekey(_), true) => self.confirm_shred(ShredAction::Rekey),
            (Pending::Shred(ShredAction::Encrypt, _), true) => self.start_encrypt(),
            (Pending::Shred(ShredAction::Rekey, _), true) => self.start_rekey(),
            (Pending::Multi(_), b) => self.sh.set.ui.bundle = b,
            (Pending::Ads(_), true) => {
                self.sh.set.ui.include_streams = true;
                self.tab = Tab::Encrypt;
                self.sh.msg(true, t("dlg.ads_reenter"));
            }
            (Pending::Ads(_), false) => self.sh.msg(false, t("dlg.ads_aborted")),
            _ => self.sh.msg(true, t("dlg.cancelled")),
        }
    }
}

impl eframe::App for EncApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ui_frame(ctx);
    }
}

impl EncApp {
    /// One frame of the window (without eframe's `Frame`, so tests can run real frames).
    pub fn ui_frame(&mut self, ctx: &egui::Context) {
        let ev = self.sh.frame(ctx, self.has_secrets());
        if let Some(r) = ev.lock {
            if self.has_secrets() || self.pending.is_some() {
                self.clear_secrets();
                self.sh.lock_message(r);
            }
        }
        if ev.install && !self.busy() {
            self.clear_secrets();
            self.sh.install_update(ctx);
        }
        if !self.busy() {
            for p in ev.dropped {
                self.select(p);
            }
        }
        if ev.close_requested && self.busy() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.sh.msg(false, t("shell.busy_close"));
        }
        self.sh.clipboard_after_paste(ctx, &mut [&mut self.pw, &mut self.pw2, &mut self.new_pw, &mut self.new_pw2]);
        // remembered pass count (3.0.0 §3): only a choice the user made, never below the protected default
        let ui = &mut self.sh.set.ui;
        if self.passes != crate::ui_prefs::passes_floor(ui.enc_passes, self.sh.set.shred_passes) {
            ui.enc_passes = Some(self.passes);
        }
        self.poll_job();
        if self.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        crate::enc_views::frame(self, ctx);
        self.dialogs(ctx);
        crate::shell::end_frame(ctx);
    }
}
