//! Encryption window: state, input checks and job start/finish.
//! Tabs: encrypt / decrypt / password and key change / disk cleanup / settings / algorithms / help.
//! Browsing and opening containers live in the separate file manager window (mgr_app.rs).

use crate::compress::Strength;
use crate::crypto::Cred;
use crate::engine::*;
use crate::format::MAX_PIM;
use crate::harden::SecretBuf;
use crate::i18n::{has_code, t, tf};
use crate::job::{launch, Job};
use crate::keyfile::keyfile_opt;
use crate::progress::*;
use crate::settings::{Naming, Settings, StartScreen};
use crate::shell::Shell;
use crate::sysinfo::is_shd;
use crate::{ui, wipe};
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

/// A dialog waiting for the user (B-9 / B-10).
#[derive(Clone, PartialEq, Debug)]
pub enum Pending {
    WeakEncrypt(Vec<String>),
    WeakRekey(Vec<String>),
    Ads(String),
}

pub struct EncApp {
    pub sh: Shell,
    pub tab: Tab,
    pub selected: Option<PathBuf>,
    pub recent: Vec<PathBuf>,
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
    pub include_streams: bool,
    pub full_rekey: bool,
    pub new_pw: SecretBuf,
    pub new_pw2: SecretBuf,
    pub new_custom_pim: bool,
    pub new_pim: u32,
    pub new_keyfiles: Vec<PathBuf>,
    pub new_kf_only_ack: bool,
    pub disk_drive: Option<PathBuf>,
    pub disk_trim_after_wipe: bool,
    pub job: Option<Job<String>>,
    pub pending: Option<Pending>,
}

/// Output next to `src`: "name.ext.shd" or "name.shd" (Settings), "(2)", "(3)"... when taken.
pub fn default_output(src: &Path, naming: Naming) -> Option<PathBuf> {
    let dir = src.parent()?;
    let full = src.file_name()?.to_string_lossy().into_owned();
    let base = match (naming, src.is_dir()) {
        (Naming::Replace, false) => src.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or(full),
        _ => full,
    };
    (1..10_000u32)
        .map(|i| if i == 1 { dir.join(format!("{base}.shd")) } else { dir.join(format!("{base} ({i}).shd")) })
        .find(|p| std::fs::symlink_metadata(p).is_err())
}

/// Shared checks for new credentials (encrypt and rekey).
fn new_cred_problems(v: &mut Vec<String>, pw: &SecretBuf, pw2: &SecretBuf, pim: u32, kfs: &[PathBuf], kf_ack: bool, new: bool) {
    let min = min_password_len(pim, !kfs.is_empty());
    let k = |a: &'static str, b: &'static str| if new { b } else { a };
    if pw.overflow {
        v.push(tf("ui.pw_too_long", &[&crate::harden::SECRET_CAP]));
    }
    if pw.is_empty() && kfs.is_empty() {
        v.push(t(k("p.need_cred", "p.need_new_cred")).into());
    } else if pw.char_count() < min {
        v.push(if pim < DEFAULT_PIM && kfs.is_empty() {
            tf(k("p.min_len_pim", "p.new_min_len_pim"), &[&DEFAULT_PIM, &min, &pw.char_count()])
        } else {
            tf(k("p.min_len", "p.new_min_len"), &[&min, &pw.char_count()])
        });
    }
    if !pw.ct_eq(pw2) {
        v.push(t(k("p.confirm", "p.new_confirm")).into());
    }
    if pw.is_empty() && !kfs.is_empty() && !kf_ack {
        v.push(t("p.kf_only_ack").into());
    }
}

impl EncApp {
    pub fn new(set: Settings, start: Option<(Tab, PathBuf)>) -> Self {
        let tab = if set.start_screen == StartScreen::Decrypt { Tab::Decrypt } else { Tab::Encrypt };
        let mut a = EncApp {
            tab,
            selected: None,
            recent: vec![],
            keyfiles: vec![],
            pw: SecretBuf::new(),
            pw2: SecretBuf::new(),
            custom_pim: false,
            pim: set.default_pim,
            kf_only_ack: false,
            gen_kib: set.keyfile_kib,
            choose_dest: false,
            strength: set.strength,
            shred_src: set.shred_default,
            shred_ack: false,
            force7: false,
            trim_after: true,
            wipe_free_after: false,
            include_streams: false,
            full_rekey: false,
            new_pw: SecretBuf::new(),
            new_pw2: SecretBuf::new(),
            new_custom_pim: false,
            new_pim: set.default_pim,
            new_keyfiles: vec![],
            new_kf_only_ack: false,
            disk_drive: None,
            disk_trim_after_wipe: true,
            job: None,
            pending: None,
            sh: Shell::new(set),
        };
        if let Some((t, p)) = start {
            a.select(p);
            a.tab = t;
        }
        a
    }

    pub fn pim_of(&self, custom: bool, pim: u32) -> u32 {
        if custom { pim.min(MAX_PIM) } else { self.sh.set.default_pim.min(MAX_PIM) }
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Selecting a .shd file switches to decryption, anything else to encryption.
    pub fn select(&mut self, p: PathBuf) {
        if matches!(self.tab, Tab::Encrypt | Tab::Decrypt | Tab::Algo | Tab::Help | Tab::Settings) {
            self.tab = if is_shd(&p) { Tab::Decrypt } else { Tab::Encrypt };
        }
        if self.tab == Tab::Disk {
            self.disk_drive = wipe::drive_letter(&p).map(|l| PathBuf::from(format!("{l}:\\")));
        }
        if self.sh.set.recent_files && !self.recent.contains(&p) {
            self.recent.insert(0, p.clone());
            self.recent.truncate(8);
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

    fn spawn(&mut self, title: &'static str, stages: Vec<u8>, f: impl FnOnce() -> R<String> + Send + 'static) {
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
        if self.selected.is_none() {
            v.push(t("p.pick_target").into());
        }
        let pim = self.pim_of(self.custom_pim, self.pim);
        new_cred_problems(&mut v, &self.pw, &self.pw2, pim, &self.keyfiles, self.kf_only_ack, false);
        if self.shred_src && !self.shred_ack {
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

    // -------------------------------------------------------------- actions

    /// B-10: a weak new password needs an explicit confirmation (Cancel is the default).
    pub fn request_encrypt(&mut self) {
        if !self.encrypt_problems().is_empty() {
            return;
        }
        let r = crate::password::weak_reasons(self.pw.as_str(), !self.keyfiles.is_empty());
        if r.is_empty() {
            self.start_encrypt();
        } else {
            self.pending = Some(Pending::WeakEncrypt(r));
        }
    }

    pub fn request_rekey(&mut self) {
        if !self.rekey_problems().is_empty() {
            return;
        }
        let r = crate::password::weak_reasons(self.new_pw.as_str(), !self.new_keyfiles.is_empty());
        if r.is_empty() {
            self.start_rekey();
        } else {
            self.pending = Some(Pending::WeakRekey(r));
        }
    }

    pub fn start_encrypt(&mut self) {
        let Some(src) = self.selected.clone() else { return };
        let auto = default_output(&src, self.sh.set.naming);
        let dst = if self.choose_dest || auto.is_none() {
            let name = auto.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "drive.shd".into());
            let mut d = rfd::FileDialog::new().set_title(t("dlg.save_shd")).set_file_name(name);
            if let Some(p) = src.parent() {
                d = d.set_directory(p);
            }
            d.save_file()
        } else {
            auto
        };
        let Some(dst) = dst else { return };
        let pw = match self.pw.take() {
            Ok(p) => p,
            Err(x) => return self.sh.msg(false, x),
        };
        self.pw2.clear();
        let kfs = self.keyfiles.clone();
        let pim = self.pim_of(self.custom_pim, self.pim);
        let opts = Opts {
            shred_src: self.shred_src,
            force7: self.force7,
            trim_after: self.trim_after,
            wipe_free_after: self.wipe_free_after,
            strength: self.strength,
            keyfiles: kfs.clone(),
            streams: if self.include_streams { StreamPolicy::Include } else { StreamPolicy::Ask },
        };
        let mut stages = vec![ST_SCAN];
        if opts.shred_src {
            stages.push(ST_ADS);
        }
        stages.extend([ST_COMPRESS, ST_ENCRYPT, ST_VERIFY]);
        if opts.shred_src {
            stages.push(ST_SHRED);
            if opts.wipe_free_after {
                stages.push(ST_WIPE_FREE);
            }
            if opts.trim_after {
                stages.push(ST_TRIM);
            }
        }
        self.kf_only_ack = false;
        self.spawn(t("job.encrypt"), stages, move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            do_encrypt(&src, &dst, &c, &opts)
        });
    }

    pub fn start_decrypt(&mut self) {
        if !self.decrypt_problems().is_empty() {
            return;
        }
        let Some(src) = self.selected.clone() else { return };
        let outdir = if self.choose_dest { rfd::FileDialog::new().set_title(t("dlg.out_folder")).pick_folder() } else { Some(parent_dir(&src)) };
        let Some(outdir) = outdir else { return };
        let pw = match self.pw.take() {
            Ok(p) => p,
            Err(x) => return self.sh.msg(false, x),
        };
        let kfs = self.keyfiles.clone();
        let pim = self.pim_of(self.custom_pim, self.pim);
        let d = DecOpts { strict_motw: self.sh.set.strict_motw };
        self.spawn(t("job.decrypt"), vec![ST_DECRYPT, ST_EXTRACT], move || {
            let c = Cred { pw, kf: keyfile_opt(&kfs)?, pim };
            do_decrypt(&src, &outdir, &c, d)
        });
    }

    pub fn start_rekey(&mut self) {
        let Some(src) = self.selected.clone() else { return };
        let (old_pw, new_pw) = match (self.pw.take(), self.new_pw.take()) {
            (Ok(a), Ok(b)) => (a, b),
            (Err(x), _) | (_, Err(x)) => return self.sh.msg(false, x),
        };
        self.new_pw2.clear();
        let (okf, nkf) = (self.keyfiles.clone(), self.new_keyfiles.clone());
        let (opim, npim) = (self.pim_of(self.custom_pim, self.pim), self.pim_of(self.new_custom_pim, self.new_pim));
        let full = self.full_rekey;
        self.new_kf_only_ack = false;
        let (title, stages) = if full {
            (t("job.full_rekey"), vec![ST_DECRYPT, ST_ENCRYPT, ST_VERIFY, ST_REPLACE])
        } else {
            (t("job.change_pw"), vec![ST_REWRAP])
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
            return self.sh.msg(false, t("p.pick_drive"));
        };
        self.spawn("TRIM", vec![ST_TRIM], move || {
            set_stage(ST_TRIM);
            wipe::trim_volume(l)
        });
    }

    pub fn start_wipe_free(&mut self) {
        let Some(d) = self.disk_drive.clone() else {
            return self.sh.msg(false, t("p.pick_drive"));
        };
        let trim = self.disk_trim_after_wipe;
        let mut stages = vec![ST_WIPE_FREE];
        if trim {
            stages.push(ST_TRIM);
        }
        self.spawn(t("job.wipe_free"), stages, move || {
            set_stage(ST_WIPE_FREE);
            let mut m = wipe::wipe_free_space(&d)?;
            if let (true, Some(l)) = (trim, wipe::drive_letter(&d)) {
                set_stage(ST_TRIM);
                m += &format!(" \u{00B7} {}", wipe::trim_volume(l).unwrap_or_else(|x| x));
            }
            Ok(m)
        });
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let Some(p) = self.pending.clone() else { return };
        let r = match &p {
            Pending::WeakEncrypt(r) | Pending::WeakRekey(r) => ui::confirm_modal(ctx, "weak", t("dlg.weak_title"), r, t("dlg.weak_use")),
            Pending::Ads(m) => ui::confirm_modal(ctx, "ads", t("dlg.ads_title"), &[m.clone(), t("dlg.ads_body").into()], t("dlg.ads_include")),
        };
        let Some(yes) = r else { return };
        self.pending = None;
        match (p, yes) {
            (Pending::WeakEncrypt(_), true) => self.start_encrypt(),
            (Pending::WeakRekey(_), true) => self.start_rekey(),
            (Pending::Ads(_), true) => {
                self.include_streams = true;
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
        let ev = self.sh.frame(ctx, self.has_secrets());
        if let Some(r) = ev.lock {
            if self.has_secrets() || self.pending.is_some() {
                self.clear_secrets();
                self.sh.lock_message(r);
            }
        }
        if let Some(p) = ev.dropped.into_iter().next() {
            if !self.busy() {
                self.select(p);
            }
        }
        if ev.close_requested && self.busy() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.sh.msg(false, t("shell.busy_close"));
        }
        self.sh.clipboard_after_paste(&mut [&mut self.pw, &mut self.pw2, &mut self.new_pw, &mut self.new_pw2]);
        self.poll_job();
        if self.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        crate::enc_views::frame(self, ctx);
        self.dialogs(ctx);
    }
}
