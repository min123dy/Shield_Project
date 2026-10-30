#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod archive;
mod engine;
mod entropy;
mod harden;
mod help;
mod icon;
mod keyfile;
mod progress;
mod sectemp;
mod ui;
mod views;
mod wipe;

use eframe::egui;
use engine::*;
use harden::*;
use progress::*;
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::Ordering,
        mpsc::{channel, Receiver},
    },
    time::{Duration, Instant},
};

const IDLE: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Rekey,
    Disk,
    Help,
}

pub struct Entry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
}

pub struct Job {
    pub title: &'static str,
    pub stages: Vec<u8>,
    pub started: Instant,
    pub stage_t0: (u8, Instant),
    rx: Receiver<R<String>>,
}

pub struct App {
    pub mode: Mode,
    pub cwd: Option<PathBuf>, // None = drive list
    pub entries: Vec<Entry>,
    pub filter: String,
    pub selected: Option<PathBuf>,
    pub keyfiles: Vec<PathBuf>,
    pub pw: SecretBuf,
    pub pw2: SecretBuf,
    pub custom_pim: bool,
    pub pim: u32,
    pub choose_dest: bool,
    pub shred_src: bool,
    pub shred_ack: bool,
    pub force7: bool,
    pub trim_after: bool,
    pub wipe_free_after: bool,
    pub new_pw: SecretBuf,
    pub new_pw2: SecretBuf,
    pub new_custom_pim: bool,
    pub new_pim: u32,
    pub new_keyfiles: Vec<PathBuf>,
    pub disk_drive: Option<PathBuf>,
    pub disk_trim_after_wipe: bool,
    pub status: String,
    pub ok: bool,
    pub job: Option<Job>,
    pub last_act: Instant,
}

pub fn roots() -> Vec<PathBuf> {
    if cfg!(windows) {
        ('A'..='Z').map(|c| PathBuf::from(format!("{c}:\\"))).filter(|p| p.exists()).collect()
    } else {
        vec![PathBuf::from("/")]
    }
}

pub fn is_shd(p: &Path) -> bool {
    p.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("shd"))
}

/// "name.shd" next to `src`, or "name (2).shd", ... when taken.
fn default_output(src: &Path) -> Option<PathBuf> {
    let dir = src.parent()?;
    let name = src.file_name()?.to_string_lossy().into_owned();
    (1..10_000u32)
        .map(|i| if i == 1 { dir.join(format!("{name}.shd")) } else { dir.join(format!("{name} ({i}).shd")) })
        .find(|p| std::fs::symlink_metadata(p).is_err())
}

impl App {
    fn new() -> Self {
        let home = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(PathBuf::from);
        let mut a = App {
            mode: Mode::Encrypt,
            cwd: home,
            entries: vec![],
            filter: String::new(),
            selected: None,
            keyfiles: vec![],
            pw: SecretBuf::new(),
            pw2: SecretBuf::new(),
            custom_pim: false,
            pim: DEFAULT_PIM,
            choose_dest: false,
            shred_src: false,
            shred_ack: false,
            force7: false,
            trim_after: true,
            wipe_free_after: false,
            new_pw: SecretBuf::new(),
            new_pw2: SecretBuf::new(),
            new_custom_pim: false,
            new_pim: DEFAULT_PIM,
            new_keyfiles: vec![],
            disk_drive: None,
            disk_trim_after_wipe: true,
            status: String::new(),
            ok: true,
            job: None,
            last_act: Instant::now(),
        };
        // right-click launch: shield.exe --encrypt|--decrypt <path>
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.len() >= 2 && (args[0] == "--encrypt" || args[0] == "--decrypt") {
            let p = PathBuf::from(&args[1]);
            a.cwd = p.parent().map(Path::to_path_buf).or(a.cwd);
            a.select(p);
            a.mode = if args[0] == "--encrypt" { Mode::Encrypt } else { Mode::Decrypt };
        }
        a.refresh();
        a
    }

    pub fn set(&mut self, ok: bool, m: impl Into<String>) {
        self.ok = ok;
        self.status = m.into();
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    /// Selecting a .shd file switches to decryption, anything else to encryption.
    pub fn select(&mut self, p: PathBuf) {
        if matches!(self.mode, Mode::Encrypt | Mode::Decrypt | Mode::Help) {
            self.mode = if is_shd(&p) { Mode::Decrypt } else { Mode::Encrypt };
        }
        if self.mode == Mode::Disk {
            self.disk_drive = wipe::drive_letter(&p).map(|l| PathBuf::from(format!("{l}:\\")));
        }
        self.selected = Some(p);
    }

    pub fn pim_value(&self) -> u32 {
        if self.custom_pim { self.pim.min(MAX_PIM) } else { DEFAULT_PIM }
    }
    pub fn new_pim_value(&self) -> u32 {
        if self.new_custom_pim { self.new_pim.min(MAX_PIM) } else { DEFAULT_PIM }
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

    pub fn refresh(&mut self) {
        self.entries.clear();
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
                            is_dir: md.as_ref().map(|m| m.is_dir()).unwrap_or(false),
                            size: md.map(|m| m.len()).unwrap_or(0),
                        });
                    }
                }
                self.entries
                    .sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
            }
            None => {
                for r in roots() {
                    self.entries.push(Entry { name: r.to_string_lossy().into_owned(), is_dir: true, size: 0 });
                }
            }
        }
    }

    fn spawn<F: FnOnce() -> R<String> + Send + 'static>(&mut self, title: &'static str, stages: Vec<u8>, f: F) {
        CANCEL.store(false, Ordering::Relaxed);
        set_stage(0);
        let (tx, rx) = channel();
        self.job = Some(Job { title, stages, started: Instant::now(), stage_t0: (0, Instant::now()), rx });
        self.set(true, "");
        std::thread::spawn(move || {
            let r = f();
            set_stage(0);
            let _ = tx.send(r);
        });
    }

    /// Called every frame; finishes the job when the worker reports back.
    fn poll_job(&mut self) {
        let Some(job) = &self.job else { return };
        let Ok(r) = job.rx.try_recv() else { return };
        let took = job.started.elapsed();
        let secs = format!(" ({}초)", took.as_secs());
        match r {
            Ok(m) => self.set(true, m + &secs),
            Err(m) => self.set(false, m),
        }
        self.job = None;
        self.selected = None;
        self.refresh();
    }

    // -------------------------------------------------------------- validation (shown live in the UI)

    pub fn encrypt_problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        if self.selected.is_none() {
            v.push("암호화할 파일 또는 폴더를 선택하세요.".into());
        }
        let min = min_password_len(self.pim_value(), !self.keyfiles.is_empty());
        if self.pw.char_count() < min {
            v.push(if self.custom_pim && self.pim_value() < DEFAULT_PIM && self.keyfiles.is_empty() {
                format!("PIM이 권장값({DEFAULT_PIM})보다 낮아 비밀번호는 {min}자 이상이어야 합니다 (현재 {}자).", self.pw.char_count())
            } else {
                format!("비밀번호를 {min}자 이상 입력하세요 (현재 {}자). 키 파일을 쓰면 제한이 없습니다.", self.pw.char_count())
            });
        }
        if !self.pw.ct_eq(&self.pw2) {
            v.push("비밀번호 확인이 일치하지 않습니다.".into());
        }
        if self.shred_src && !self.shred_ack {
            v.push("원본 파쇄를 쓰려면 '복구할 수 없음을 이해했습니다'를 체크하세요.".into());
        }
        v
    }

    pub fn decrypt_problems(&self) -> Vec<String> {
        let mut v = Vec::new();
        match &self.selected {
            Some(p) if p.is_file() => {}
            _ => v.push("복호화할 .shd 파일을 선택하세요.".into()),
        }
        if self.pw.is_empty() && self.keyfiles.is_empty() {
            v.push("비밀번호 또는 키 파일을 입력하세요.".into());
        }
        v
    }

    pub fn rekey_problems(&self) -> Vec<String> {
        let mut v = self.decrypt_problems();
        let min = min_password_len(self.new_pim_value(), !self.new_keyfiles.is_empty());
        if self.new_pw.char_count() < min {
            v.push(format!("새 비밀번호를 {min}자 이상 입력하세요 (현재 {}자).", self.new_pw.char_count()));
        }
        if self.new_pw.is_empty() && self.new_keyfiles.is_empty() {
            v.push("새 비밀번호 또는 새 키 파일이 필요합니다.".into());
        }
        if !self.new_pw.ct_eq(&self.new_pw2) {
            v.push("새 비밀번호 확인이 일치하지 않습니다.".into());
        }
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
        let pim = self.pim_value();
        let opts = Opts {
            shred_src: self.shred_src,
            force7: self.force7,
            trim_after: self.trim_after,
            wipe_free_after: self.wipe_free_after,
        };
        let mut stages = vec![ST_COMPRESS, ST_ENCRYPT, ST_VERIFY];
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
        let outdir = match src.parent().filter(|_| !self.choose_dest) {
            Some(p) => Some(p.to_path_buf()),
            None => rfd::FileDialog::new().set_title("복호화 결과를 저장할 폴더").pick_folder(),
        };
        let Some(outdir) = outdir else { return };
        let pw = self.pw.take();
        self.pw2.clear();
        let kfs = self.keyfiles.clone();
        let pim = self.pim_value();
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
        self.pw2.clear();
        self.new_pw2.clear();
        let (okf, nkf) = (self.keyfiles.clone(), self.new_keyfiles.clone());
        let (opim, npim) = (self.pim_value(), self.new_pim_value());
        self.spawn("비밀번호 변경", vec![ST_REWRAP], move || {
            let old = Cred { pw: old_pw, kf: keyfile_opt(&okf)?, pim: opim };
            let new = Cred { pw: new_pw, kf: keyfile_opt(&nkf)?, pim: npim };
            do_change_password(&src, &old, &new)
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

    /// Mouse entropy, idle wipe of typed secrets, and "don't close while working".
    fn housekeeping(&mut self, ctx: &egui::Context) {
        let (active, close) = ctx.input(|i| {
            for ev in &i.events {
                if let egui::Event::PointerMoved(p) = ev {
                    entropy::mix_mouse(p.x, p.y, i.time);
                }
            }
            (!i.events.is_empty() || i.pointer.delta() != egui::Vec2::ZERO, i.viewport().close_requested())
        });
        if active {
            self.last_act = Instant::now();
        } else if self.last_act.elapsed() > IDLE && !self.secrets_empty() {
            self.clear_secrets();
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

fn load_korean_font(ctx: &egui::Context) {
    let cands = [
        "C:\\Windows\\Fonts\\malgun.ttf",
        "/System/Library/Fonts/AppleSDGothicNeo.ttc",
        "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ];
    for p in cands {
        if let Ok(b) = std::fs::read(p) {
            let mut f = egui::FontDefinitions::default();
            f.font_data.insert("kr".into(), egui::FontData::from_owned(b));
            for fam in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
                f.families.entry(fam).or_default().insert(0, "kr".into());
            }
            ctx.set_fonts(f);
            return;
        }
    }
}

fn main() {
    harden_process();
    let icon = egui::IconData { rgba: icon::shield_rgba(64), width: 64, height: 64 };
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Shield")
            .with_app_id("Shield")
            .with_icon(icon)
            .with_inner_size([1060.0, 720.0])
            .with_min_inner_size([820.0, 560.0]),
        ..Default::default()
    };
    let _ = eframe::run_native(
        "Shield",
        opts,
        Box::new(|cc| {
            load_korean_font(&cc.egui_ctx);
            ui::style(&cc.egui_ctx);
            Box::new(App::new())
        }),
    );
}
