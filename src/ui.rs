//! Window layout, shared widgets, explorer panel and the progress/status bar.

use crate::{entropy, progress::*, App, Job, Mode};
use eframe::egui::{self, vec2, Color32, RichText};
use std::{
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

pub const GREEN: Color32 = Color32::from_rgb(34, 139, 70);
pub const RED: Color32 = Color32::from_rgb(200, 50, 50);
pub const AMBER: Color32 = Color32::from_rgb(190, 120, 0);
pub const ACCENT: Color32 = Color32::from_rgb(38, 96, 196);
/// Light enough that the dark progress text stays readable on top of it.
const BAR: Color32 = Color32::from_rgb(140, 185, 245);

pub fn style(ctx: &egui::Context) {
    ctx.set_visuals(egui::Visuals::light());
    let mut s = (*ctx.style()).clone();
    s.spacing.item_spacing = vec2(8.0, 7.0);
    s.spacing.button_padding = vec2(10.0, 5.0);
    use egui::{FontFamily, FontId, TextStyle as T};
    s.text_styles = [
        (T::Heading, FontId::new(21.0, FontFamily::Proportional)),
        (T::Body, FontId::new(15.0, FontFamily::Proportional)),
        (T::Button, FontId::new(15.0, FontFamily::Proportional)),
        (T::Small, FontId::new(12.5, FontFamily::Proportional)),
        (T::Monospace, FontId::new(14.0, FontFamily::Monospace)),
    ]
    .into();
    ctx.set_style(s);
}

pub fn human(n: u64) -> String {
    let mut v = n as f64;
    for u in ["B", "KB", "MB", "GB", "TB"] {
        if v < 1024.0 {
            return format!("{v:.1} {u}");
        }
        v /= 1024.0;
    }
    format!("{v:.1} PB")
}

fn clock(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 { format!("{}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60) } else { format!("{}:{:02}", s / 60, s % 60) }
}

pub fn section(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::group(ui.style()).inner_margin(egui::Margin::same(12.0)).rounding(6.0).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(title).strong().size(16.0));
        ui.add_space(2.0);
        add(ui);
    });
    ui.add_space(6.0);
}

pub fn hint(ui: &mut egui::Ui, t: impl Into<String>) {
    ui.label(RichText::new(t.into()).small().weak());
}

/// Password field that never hands the secret to egui's TextEdit (which keeps undo copies and
/// re-allocates). Key events go straight into a fixed locked buffer; only dots are drawn.
pub fn secret_field(ui: &mut egui::Ui, id: &str, buf: &mut crate::harden::SecretBuf, placeholder: &str) {
    let size = vec2(ui.available_width().min(420.0), 30.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let eid = egui::Id::new(id);
    let resp = ui.interact(rect, eid, egui::Sense::click());
    ui.memory_mut(|m| m.interested_in_focus(eid)); // Tab moves between fields
    if resp.clicked() {
        ui.memory_mut(|m| m.request_focus(eid));
    }
    let focused = ui.memory(|m| m.has_focus(eid));
    if focused {
        ui.input(|i| {
            for ev in &i.events {
                match ev {
                    egui::Event::Text(t) | egui::Event::Paste(t) => buf.push_str(t),
                    egui::Event::Key { key: egui::Key::Backspace, pressed: true, .. } => buf.pop(),
                    _ => {}
                }
            }
        });
    }
    let v = ui.visuals();
    let col = if focused { ACCENT } else { v.widgets.inactive.bg_stroke.color };
    ui.painter().rect(rect, 4.0, v.extreme_bg_color, egui::Stroke::new(if focused { 2.0_f32 } else { 1.0_f32 }, col));
    let (text, color, font) = if buf.is_empty() && !focused {
        (placeholder.to_string(), v.weak_text_color(), egui::FontId::proportional(14.0))
    } else {
        let mut d = "●".repeat(buf.char_count().min(40));
        if focused {
            d.push('|');
        }
        (d, v.text_color(), egui::FontId::proportional(13.0))
    };
    ui.painter().text(rect.left_center() + vec2(8.0, 0.0), egui::Align2::LEFT_CENTER, text, font, color);
    resp.on_hover_text("클릭해서 입력 (Tab으로 다음 칸 이동)");
}

pub fn strength_bar(ui: &mut egui::Ui, b: &crate::harden::SecretBuf) {
    if b.is_empty() {
        return;
    }
    let bits = b.bits();
    let (t, c) = if bits < 45.0 {
        ("약함", RED)
    } else if bits < 65.0 {
        ("보통", AMBER)
    } else if bits < 90.0 {
        ("강함", GREEN)
    } else {
        ("매우 강함", GREEN)
    };
    let f = (bits / 110.0).clamp(0.05, 1.0) as f32;
    ui.horizontal(|ui| {
        ui.add(egui::ProgressBar::new(f).desired_width(160.0).desired_height(8.0).fill(c));
        ui.label(RichText::new(format!("강도: {t} · {}자", b.char_count())).color(c).small());
    });
}

pub fn match_label(ui: &mut egui::Ui, a: &crate::harden::SecretBuf, b: &crate::harden::SecretBuf) {
    if b.is_empty() {
        return;
    }
    if a.ct_eq(b) {
        ui.label(RichText::new("✔ 일치합니다").color(GREEN));
    } else {
        ui.label(RichText::new("✖ 일치하지 않습니다").color(RED));
    }
}

pub fn pim_picker(ui: &mut egui::Ui, custom: &mut bool, pim: &mut u32, decrypting: bool) {
    use crate::engine::{DEFAULT_PIM, MAX_PIM};
    ui.horizontal(|ui| {
        ui.label("PIM");
        ui.radio_value(custom, false, format!("권장 기본값 ({DEFAULT_PIM})"));
        ui.radio_value(custom, true, "직접 지정");
        if *custom {
            ui.add(egui::DragValue::new(pim).clamp_range(0..=MAX_PIM).speed(0.2));
        }
    });
    if decrypting {
        hint(ui, "암호화할 때 PIM을 바꾸지 않았다면 기본값 그대로 두세요. 1.0 버전 파일(PIM 0)도 자동으로 열립니다.");
    } else if *custom && *pim < DEFAULT_PIM {
        ui.label(RichText::new(format!("⚠ 기본값보다 약합니다. 키 파일 없이 쓰면 비밀번호 20자 이상이 필요합니다.")).small().color(AMBER));
    } else if *custom {
        hint(ui, "값이 클수록 추측 공격에 강하지만 열 때마다 오래 걸립니다. 이 숫자를 반드시 기록해 두세요.");
    }
}

pub fn entropy_meter(ui: &mut egui::Ui) {
    let bits = entropy::credited_bits();
    let target = entropy::TARGET_BITS;
    let f = (bits.min(target) as f32) / target as f32;
    let ready = bits >= target;
    ui.label(format!(
        "마우스 엔트로피 {} / {target} 비트{} · 샘플 {}",
        bits.min(target),
        if ready { " ✔ 충분함" } else { "" },
        entropy::SAMPLES.load(Ordering::Relaxed)
    ));
    ui.add(
        egui::ProgressBar::new(f)
            .desired_width(ui.available_width().min(420.0))
            .desired_height(10.0)
            .fill(if ready { GREEN } else { ACCENT }),
    );
    if !ready {
        hint(ui, "키 파일을 만들려면 이 창 위에서 마우스를 불규칙하게(원, 지그재그) 움직이세요. 일정한 직선 이동은 거의 계산되지 않습니다.");
    }
}

/// Key file list with add/remove (+ generate). Returns a status message to show, if any.
pub fn keyfile_list(ui: &mut egui::Ui, list: &mut Vec<PathBuf>, allow_generate: bool) -> Option<(bool, String)> {
    let mut msg = None;
    let mut rm: Option<usize> = None;
    if list.is_empty() {
        hint(ui, "키 파일 없음 (비밀번호만 사용)");
    }
    for (i, p) in list.iter().enumerate() {
        ui.horizontal(|ui| {
            if ui.small_button("✖").on_hover_text("목록에서 제거 (파일은 삭제되지 않음)").clicked() {
                rm = Some(i);
            }
            let n = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            ui.label(format!("🔑 {n}")).on_hover_text(p.display().to_string());
        });
    }
    if let Some(i) = rm {
        list.remove(i);
    }
    ui.horizontal(|ui| {
        if ui.button("➕ 키 파일 추가…").clicked() {
            if let Some(v) = rfd::FileDialog::new().set_title("키 파일 선택").pick_files() {
                for p in v {
                    if !list.contains(&p) {
                        list.push(p);
                    }
                }
            }
        }
        if allow_generate {
            let ready = entropy::entropy_ready();
            let b = ui.add_enabled(ready, egui::Button::new("✨ 새 키 파일 생성…"));
            let b = if ready { b } else { b.on_disabled_hover_text("아래 마우스 엔트로피가 다 모이면 활성화됩니다.") };
            if b.clicked() {
                if let Some(p) = rfd::FileDialog::new().set_title("키 파일 저장").set_file_name("my.key").save_file() {
                    msg = Some(match crate::engine::generate_keyfile(&p) {
                        Ok(()) => {
                            let m = format!("키 파일 생성됨: {} — 반드시 다른 곳에 백업하고 절대 수정하지 마세요.", p.display());
                            list.push(p);
                            (true, m)
                        }
                        Err(x) => (false, format!("키 파일 생성 실패: {x}")),
                    });
                }
            }
        }
    });
    if allow_generate {
        entropy_meter(ui);
    }
    if !list.is_empty() {
        hint(ui, "복호화할 때 이 키 파일들이 모두 필요합니다 (순서 무관).");
    }
    msg
}

/// Live list of what is still missing, then the primary button (enabled only when nothing is missing).
pub fn action_button(ui: &mut egui::Ui, problems: &[String], label: &str) -> bool {
    for p in problems {
        ui.label(RichText::new(format!("• {p}")).color(AMBER));
    }
    ui.add_space(4.0);
    let ok = problems.is_empty();
    let b = egui::Button::new(RichText::new(label).size(17.0).strong().color(Color32::WHITE))
        .fill(if ok { ACCENT } else { Color32::from_gray(170) })
        .min_size(vec2(240.0, 40.0))
        .rounding(6.0);
    ui.add_enabled(ok, b).clicked()
}

pub fn target_card(ui: &mut egui::Ui, sel: &Option<PathBuf>) {
    let Some(p) = sel else {
        ui.label(RichText::new("선택된 항목이 없습니다.").color(AMBER));
        hint(ui, "왼쪽 목록에서 클릭하거나, 파일/폴더를 이 창에 끌어다 놓으세요.");
        return;
    };
    let md = std::fs::metadata(p).ok();
    let is_dir = md.as_ref().is_some_and(|m| m.is_dir());
    let (icon, kind) = if is_dir {
        ("📁", "폴더".to_string())
    } else if crate::is_shd(p) {
        ("🔐", format!("Shield 암호화 파일 · {}", human(md.as_ref().map_or(0, |m| m.len()))))
    } else {
        ("📄", format!("파일 · {}", human(md.as_ref().map_or(0, |m| m.len()))))
    };
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string());
    ui.horizontal(|ui| {
        ui.label(RichText::new(icon).size(30.0));
        ui.vertical(|ui| {
            ui.label(RichText::new(name).strong().size(16.0));
            ui.label(RichText::new(kind).small());
            hint(ui, p.display().to_string());
        });
    });
}

fn stage_short(n: u8) -> &'static str {
    match n {
        ST_COMPRESS => "압축",
        ST_ENCRYPT => "암호화",
        ST_VERIFY => "검증",
        ST_DECRYPT => "복호화",
        ST_EXTRACT => "압축 해제",
        ST_SHRED => "원본 파쇄",
        ST_WIPE_FREE => "여유 공간 덮어쓰기",
        ST_REWRAP => "키 재봉인",
        ST_TRIM => "TRIM",
        _ => "",
    }
}

fn progress_view(ui: &mut egui::Ui, job: &mut Job) {
    let st = STAGE.load(Ordering::Relaxed);
    if job.stage_t0.0 != st {
        job.stage_t0 = (st, Instant::now());
    }
    let cur = job.stages.iter().position(|&s| s == st);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(job.title).strong());
        for (i, &s) in job.stages.iter().enumerate() {
            let t = format!("{} {}", i + 1, stage_short(s));
            let r = match cur {
                Some(c) if i < c => RichText::new(format!("✔ {t}")).color(GREEN),
                Some(c) if i == c => RichText::new(format!("▶ {t}")).color(ACCENT).strong(),
                _ => RichText::new(t).weak(),
            };
            ui.label(r);
            if i + 1 < job.stages.len() {
                ui.label(RichText::new("›").weak());
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.label(format!("경과 {}", clock(job.started.elapsed())));
        });
    });
    let (done, tot) = (PROG_DONE.load(Ordering::Relaxed), PROG_TOTAL.load(Ordering::Relaxed));
    let bar = if KDF_BUSY.load(Ordering::Relaxed) {
        egui::ProgressBar::new(0.0).animate(true).text("키 유도 중 (Argon2id) — PIM이 클수록 오래 걸립니다")
    } else if tot > 0 {
        let f = (done as f64 / tot as f64).min(1.0);
        let el = job.stage_t0.1.elapsed().as_secs_f64();
        let speed = if el > 0.5 { done as f64 / el } else { 0.0 };
        let mut t = format!("{:.0}% · {} / {}", f * 100.0, human(done), human(tot));
        if speed > 0.0 {
            t += &format!(" · {}/s", human(speed as u64));
            if f > 0.02 && f < 1.0 {
                t += &format!(" · 남은 시간 약 {}", clock(Duration::from_secs_f64((tot - done.min(tot)) as f64 / speed)));
            }
        }
        egui::ProgressBar::new(f as f32).text(t)
    } else {
        egui::ProgressBar::new(0.0).animate(true).text(format!("{} …", stage_label(st)))
    };
    ui.horizontal(|ui| {
        ui.add(bar.desired_width(ui.available_width() - 110.0).fill(BAR));
        let can = stage_cancellable(st) && !cancelled();
        let label = if cancelled() { "취소 중…" } else { "취소" };
        let b = ui.add_enabled(can, egui::Button::new(label).min_size(vec2(96.0, 26.0)));
        if b.on_disabled_hover_text("이 단계는 중간에 멈출 수 없습니다.").clicked() {
            CANCEL.store(true, Ordering::Relaxed);
        }
    });
    ui.label(RichText::new(stage_label(st)).small());
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        self.housekeeping(ctx);
        let busy = self.busy();
        let (dropped, hovering) = ctx.input(|i| {
            (i.raw.dropped_files.first().and_then(|f| f.path.clone()), !i.raw.hovered_files.is_empty())
        });
        if let (Some(p), false) = (dropped, busy) {
            self.cwd = p.parent().map(Path::to_path_buf);
            self.select(p);
            self.refresh();
        }

        egui::TopBottomPanel::top("tabs").show(ctx, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("🛡 Shield").size(20.0).strong().color(ACCENT));
                    ui.add_space(12.0);
                    for (m, t) in [
                        (Mode::Encrypt, "🔒 암호화"),
                        (Mode::Decrypt, "🔓 복호화"),
                        (Mode::Rekey, "🔑 비밀번호 변경"),
                        (Mode::Disk, "💽 디스크 정리"),
                        (Mode::Help, "❓ 사용법·주의사항"),
                    ] {
                        ui.selectable_value(&mut self.mode, m, RichText::new(t).size(16.0));
                    }
                });
            });
        });

        egui::TopBottomPanel::bottom("status").min_height(70.0).show(ctx, |ui| {
            ui.add_space(4.0);
            if let Some(job) = &mut self.job {
                progress_view(ui, job);
                ctx.request_repaint_after(Duration::from_millis(100));
            } else if !self.status.is_empty() {
                let (icon, c) = if self.ok { ("✔", GREEN) } else { ("✖", RED) };
                ui.label(RichText::new(format!("{icon} {}", self.status)).color(c));
            } else {
                hint(ui, "파일/폴더를 왼쪽에서 선택하거나 창에 끌어다 놓으세요. 처음이라면 '사용법·주의사항' 탭을 먼저 읽어 주세요.");
            }
            ui.add_space(4.0);
        });

        egui::SidePanel::left("explorer").default_width(320.0).min_width(240.0).show(ctx, |ui| {
            ui.add_enabled_ui(!busy, |ui| self.explorer(ui));
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_enabled_ui(!busy, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    ui.set_max_width(720.0);
                    match self.mode {
                        Mode::Encrypt => self.view_encrypt(ui),
                        Mode::Decrypt => self.view_decrypt(ui),
                        Mode::Rekey => self.view_rekey(ui),
                        Mode::Disk => self.view_disk(ui),
                        Mode::Help => crate::views::view_help(ui),
                    }
                });
            });
        });

        if hovering && !busy {
            let r = ctx.screen_rect();
            let p = ctx.layer_painter(egui::LayerId::new(egui::Order::Foreground, egui::Id::new("drop")));
            p.rect_filled(r, 0.0, Color32::from_black_alpha(140));
            p.text(r.center(), egui::Align2::CENTER_CENTER, "여기에 놓으면 선택됩니다", egui::FontId::proportional(28.0), Color32::WHITE);
        }
    }
}

impl App {
    fn explorer(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if ui.button("⬆ 상위").clicked() {
                self.cwd = self.cwd.as_ref().and_then(|d| d.parent().map(Path::to_path_buf));
                self.refresh();
            }
            if ui.button("🏠 홈").clicked() {
                self.cwd = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")).map(PathBuf::from);
                self.refresh();
            }
            if ui.button("💻 드라이브").clicked() {
                self.cwd = None;
                self.refresh();
            }
            if ui.button("🔄").on_hover_text("새로고침").clicked() {
                self.refresh();
            }
        });
        ui.horizontal(|ui| {
            if ui.button("📄 파일 열기…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.cwd = p.parent().map(Path::to_path_buf);
                    self.select(p);
                    self.refresh();
                }
            }
            if ui.button("📁 폴더 선택…").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    self.cwd = p.parent().map(Path::to_path_buf);
                    self.select(p);
                    self.refresh();
                }
            }
        });
        let here = self.cwd.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "내 PC (드라이브)".into());
        ui.label(RichText::new(here).small().strong());
        ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("🔍 이름으로 거르기").desired_width(f32::INFINITY));
        ui.separator();
        let mut nav: Option<PathBuf> = None;
        let mut pick: Option<PathBuf> = None;
        let flt = self.filter.to_lowercase();
        egui::ScrollArea::vertical().auto_shrink([false, false]).max_height(ui.available_height() - 24.0).show(ui, |ui| {
            ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
            for en in &self.entries {
                if !flt.is_empty() && !en.name.to_lowercase().contains(&flt) {
                    continue;
                }
                let full = match &self.cwd {
                    Some(d) => d.join(&en.name),
                    None => PathBuf::from(&en.name),
                };
                let text = if en.is_dir {
                    format!("📁 {}", en.name)
                } else if en.name.to_ascii_lowercase().ends_with(".shd") {
                    format!("🔐 {}   ·  {}", en.name, human(en.size))
                } else {
                    format!("📄 {}   ·  {}", en.name, human(en.size))
                };
                let sel = self.selected.as_ref() == Some(&full);
                let r = ui.add(egui::SelectableLabel::new(sel, text));
                if r.double_clicked() && en.is_dir {
                    nav = Some(full);
                } else if r.clicked() {
                    pick = Some(full);
                }
            }
            });
        });
        hint(ui, "클릭: 선택 · 더블클릭: 폴더 열기 · 끌어 놓기 가능");
        if let Some(p) = nav {
            self.cwd = Some(p);
            self.filter.clear();
            self.refresh();
        } else if let Some(p) = pick {
            self.select(p);
        }
    }
}
