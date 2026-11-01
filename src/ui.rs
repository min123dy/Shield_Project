//! Shared look, widgets and the progress/status bar used by both windows.

use crate::harden::SecretBuf;
use crate::job::Job;
use crate::{entropy, progress::*};
use eframe::egui::{self, vec2, Color32, RichText};
pub use crate::ui_fmt::{date, human};
use std::{
    path::PathBuf,
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

pub fn load_korean_font(ctx: &egui::Context) {
    let windir = {
        #[cfg(windows)]
        {
            crate::sysinfo::system_dir().parent().map(|p| p.join("Fonts").join("malgun.ttf"))
        }
        #[cfg(not(windows))]
        {
            None::<PathBuf>
        }
    };
    let cands: Vec<PathBuf> = windir
        .into_iter()
        .chain(
            [
                "/System/Library/Fonts/AppleSDGothicNeo.ttc",
                "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
                "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            ]
            .map(PathBuf::from),
        )
        .collect();
    for p in cands {
        if let Ok(b) = std::fs::read(&p) {
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

pub fn warn(ui: &mut egui::Ui, t: impl Into<String>) {
    ui.label(RichText::new(t.into()).small().color(AMBER));
}

/// Tab strip; returns true when the selection changed.
pub fn tabs<T: PartialEq + Copy>(ui: &mut egui::Ui, cur: &mut T, items: &[(T, &str)]) -> bool {
    let before = *cur;
    for (m, t) in items {
        ui.selectable_value(cur, *m, RichText::new(*t).size(16.0));
    }
    *cur != before
}

/// Password field that never hands the secret to egui's TextEdit (which keeps undo copies and
/// re-allocates). Key events go straight into a fixed locked buffer; only dots are drawn.
/// Limitation: egui still owns the event strings (Event::Text/Paste) and frees them without
/// zeroizing; that is documented, and the clipboard can be emptied after a paste.
pub fn secret_field(ui: &mut egui::Ui, id: &str, buf: &mut SecretBuf, placeholder: &str) {
    let size = vec2(ui.available_width().min(420.0), 30.0);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let eid = egui::Id::new(id);
    let resp = ui.interact(rect, eid, egui::Sense::click());
    ui.memory_mut(|m| m.interested_in_focus(eid));
    if resp.clicked() {
        ui.memory_mut(|m| m.request_focus(eid));
    }
    let focused = ui.memory(|m| m.has_focus(eid));
    if focused {
        ui.input(|i| {
            for ev in &i.events {
                match ev {
                    egui::Event::Text(t) => buf.push_str(t),
                    egui::Event::Paste(t) => {
                        buf.push_str(t);
                        buf.pasted = true;
                    }
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
    if buf.overflow {
        warn(ui, format!("⚠ 최대 {}바이트까지만 입력됩니다. 초과한 글자는 무시되었습니다.", crate::harden::SECRET_CAP));
    }
    if buf.pasted {
        ui.horizontal(|ui| {
            warn(ui, "⚠ 붙여넣은 비밀번호는 클립보드와 메모리에 남아 있을 수 있습니다.");
            if ui.small_button("클립보드 비우기").clicked() {
                let ok = crate::sysinfo::clear_clipboard();
                buf.pasted = !ok;
            }
        });
    }
}

/// Rough strength guess with the reasons it was lowered. Never claims more than an estimate.
pub fn strength_bar(ui: &mut egui::Ui, b: &SecretBuf) {
    if b.is_empty() {
        return;
    }
    let a = crate::password::assess(b.as_str());
    let c = match a.label {
        "약함" => RED,
        "보통" => AMBER,
        _ => GREEN,
    };
    let f = (a.bits / 110.0).clamp(0.05, 1.0) as f32;
    ui.horizontal(|ui| {
        ui.add(egui::ProgressBar::new(f).desired_width(160.0).desired_height(8.0).fill(c));
        ui.label(RichText::new(format!("강도(대략적 추정): {} · {}자", a.label, b.char_count())).color(c).small());
    });
    for w in a.warnings {
        warn(ui, format!("• {w}"));
    }
}

pub fn match_label(ui: &mut egui::Ui, a: &SecretBuf, b: &SecretBuf) {
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
    use crate::format::{DEFAULT_PIM, MAX_PIM};
    ui.horizontal(|ui| {
        ui.label("PIM");
        ui.radio_value(custom, false, format!("권장 기본값 ({DEFAULT_PIM})"));
        ui.radio_value(custom, true, "직접 지정");
        if *custom {
            ui.add(egui::DragValue::new(pim).clamp_range(0..=MAX_PIM).speed(0.2));
        }
    });
    if decrypting {
        hint(ui, "암호화할 때 PIM을 바꾸지 않았다면 기본값 그대로 두세요. PIM은 파일에 저장되지 않습니다.");
    } else if *custom && *pim < DEFAULT_PIM {
        warn(ui, "⚠ 기본값보다 약합니다. 키 파일 없이 쓰면 비밀번호 20자 이상이 필요합니다.");
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
        "마우스로 추가 무작위성 수집: {} / {target}{} · 샘플 {}",
        bits.min(target),
        if ready { " ✔ 수집 완료" } else { "" },
        entropy::SAMPLES.load(Ordering::Relaxed)
    ));
    ui.add(egui::ProgressBar::new(f).desired_width(ui.available_width().min(420.0)).desired_height(10.0).fill(if ready { GREEN } else { ACCENT }));
    hint(ui, "보조 수단입니다. 키 파일의 강도는 운영체제 난수가 보장하며, '수집 완료'는 암호학적 보증이 아닙니다.");
    if !ready {
        hint(ui, "이 창 위에서 마우스를 불규칙하게(원, 지그재그) 움직이세요. 일정한 직선 이동은 거의 계산되지 않습니다.");
    }
}

/// Key file list with add/remove (+ generate with an adjustable size). Returns a status message.
pub fn keyfile_list(ui: &mut egui::Ui, list: &mut Vec<PathBuf>, gen_kib: Option<&mut u32>) -> Option<(bool, String)> {
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
    let generate = gen_kib.is_some();
    ui.horizontal_wrapped(|ui| {
        if ui.button("➕ 키 파일 추가…").clicked() {
            if let Some(v) = rfd::FileDialog::new().set_title("키 파일 선택").pick_files() {
                for p in v {
                    if !list.contains(&p) {
                        list.push(p);
                    }
                }
            }
        }
        if let Some(kib) = gen_kib {
            ui.label("새 키 파일 크기");
            ui.add(egui::DragValue::new(kib).clamp_range(1..=crate::keyfile::KF_MAX_KIB).suffix(" KiB").speed(1.0));
            let ready = entropy::entropy_ready();
            let b = ui.add_enabled(ready, egui::Button::new("✨ 새 키 파일 생성…"));
            let b = if ready { b } else { b.on_disabled_hover_text("아래 무작위성 수집이 끝나면 활성화됩니다.") };
            if b.clicked() {
                if let Some(p) = rfd::FileDialog::new().set_title("키 파일 저장").set_file_name("my.key").save_file() {
                    msg = Some(match crate::keyfile::generate_keyfile(&p, *kib) {
                        Ok(()) => {
                            let m = format!("키 파일 생성됨 ({} KiB, 사용자 전용 권한): {} — 반드시 다른 곳에 백업하고 절대 수정하지 마세요.", kib, p.display());
                            list.push(p);
                            (true, m)
                        }
                        Err(x) => (false, format!("키 파일 생성 실패: {x}")),
                    });
                }
            }
        }
    });
    if generate {
        hint(ui, "생성 크기: 1~1024 KiB (기본 1 KiB). 크기를 늘려도 실효 강도의 상한은 해시 길이(512비트)입니다.");
        entropy_meter(ui);
    }
    if !list.is_empty() {
        hint(ui, "복호화할 때 이 키 파일들이 모두 필요합니다 (순서 무관). 암호화 대상 안에 있는 키 파일은 쓸 수 없습니다.");
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

/// Memory-protection warnings (shown when a lock failed).
pub fn memory_warnings(ui: &mut egui::Ui) {
    if crate::harden::LOCK_FAILED.load(Ordering::Relaxed) {
        warn(ui, "⚠ 일부 비밀 값의 메모리 잠금(VirtualLock)에 실패했습니다. 비밀번호가 페이지 파일로 옮겨질 수 있습니다.");
    }
    if crate::harden::KDF_LOCK_FAILED.load(Ordering::Relaxed) {
        warn(ui, "⚠ Argon2 작업 메모리(256 MiB)를 잠그지 못했습니다. 키 유도 중 일부가 페이지 파일로 옮겨질 수 있습니다.");
    }
}

pub fn progress_view<T>(ui: &mut egui::Ui, job: &mut Job<T>) {
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
        egui::ProgressBar::new(0.0).animate(true).text("키 유도 중 (Argon2id 256 MiB) — PIM이 클수록 오래 걸립니다")
    } else if tot > 0 {
        let f = (done as f64 / tot as f64).min(1.0);
        let el = job.stage_t0.1.elapsed().as_secs_f64();
        let speed = if el > 0.5 { done as f64 / el } else { 0.0 };
        let mut t = format!("{:.0}% · {} / {}", f * 100.0, human(done.min(tot)), human(tot));
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

/// Bottom status line (job progress, last result or a hint).
pub fn status_line(ui: &mut egui::Ui, ok: bool, status: &str, idle_hint: &str) {
    if !status.is_empty() {
        let (icon, c) = if ok { ("✔", GREEN) } else { ("✖", RED) };
        ui.label(RichText::new(format!("{icon} {status}")).color(c));
    } else {
        hint(ui, idle_hint);
    }
}

pub const ROW_H: f32 = 24.0;

/// One table row painted manually (full-row selection like a file manager). `cols` are
/// (text, width); the first column takes the remaining width. Returns the row response.
pub fn table_row(ui: &mut egui::Ui, selected: bool, cols: &[(&str, f32)], header: bool) -> egui::Response {
    let w = ui.available_width();
    let (rect, resp) = ui.allocate_exact_size(vec2(w, ROW_H), egui::Sense::click());
    let v = ui.visuals();
    let bg = if header {
        Some(v.faint_bg_color)
    } else if selected {
        Some(Color32::from_rgb(204, 224, 255))
    } else if resp.hovered() {
        Some(Color32::from_rgb(235, 242, 255))
    } else {
        None
    };
    if let Some(c) = bg {
        ui.painter().rect_filled(rect, 2.0, c);
    }
    let fixed: f32 = cols.iter().skip(1).map(|c| c.1).sum();
    let mut x = rect.left() + 6.0;
    let font = egui::FontId::proportional(if header { 13.5 } else { 14.0 });
    let color = if header { v.strong_text_color() } else { v.text_color() };
    for (i, (t, cw)) in cols.iter().enumerate() {
        let width = if i == 0 { (w - fixed - 12.0).max(80.0) } else { *cw };
        let cell = egui::Rect::from_min_size(egui::pos2(x, rect.top()), vec2(width - 8.0, ROW_H));
        let right = i > 0 && !header && t.chars().next().is_some_and(|c| c.is_ascii_digit());
        let (pos, align) = if right { (cell.right_center(), egui::Align2::RIGHT_CENTER) } else { (cell.left_center(), egui::Align2::LEFT_CENTER) };
        ui.painter().with_clip_rect(cell).text(pos, align, *t, font.clone(), color);
        x += width;
    }
    resp
}

/// Renders a usage text (사용법 tab).
pub fn usage_view(ui: &mut egui::Ui, title: &str, sections: crate::help::Sections) {
    ui.heading(title);
    ui.add_space(4.0);
    for (t, lines) in sections {
        section(ui, t, |ui| {
            for l in *lines {
                ui.label(*l);
            }
        });
    }
}

/// Startup notice about plaintext staging folders left by a killed run. Returns a status message.
pub fn leftover_banner(ui: &mut egui::Ui, left: &mut Vec<PathBuf>) -> Option<(bool, String)> {
    if left.is_empty() {
        return None;
    }
    let mut out = None;
    egui::Frame::none().fill(Color32::from_rgb(255, 240, 210)).inner_margin(8.0).rounding(4.0).show(ui, |ui| {
        ui.label(RichText::new(format!("⚠ 이전 실행이 비정상 종료되어 평문 임시 폴더 {}개가 남아 있습니다.", left.len())).color(AMBER).strong());
        for p in left.iter().take(5) {
            ui.label(RichText::new(p.display().to_string()).small());
        }
        ui.horizontal(|ui| {
            if ui.button("지금 덮어쓰고 삭제").clicked() {
                let (n, bad) = crate::staging::remove_leftovers(left);
                out = Some(if bad.is_empty() {
                    (true, format!("남은 임시 폴더 {n}개를 정리했습니다."))
                } else {
                    (false, format!("{n}개 정리, 실패: {}", bad.join(" / ")))
                });
                *left = crate::staging::leftovers();
            }
            if ui.button("나중에").clicked() {
                left.clear();
            }
        });
    });
    out
}
