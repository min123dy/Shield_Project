//! Screens of the file manager window: browse table, unlock panel, container table, info tab and
//! the add-confirmation dialog.

use crate::compress::Strength;
use crate::container::BodyCheck;
use crate::format::{self, comp_name};
use crate::mgr_app::{MTab, MgrApp};
use crate::sysinfo::is_shd;
use crate::ui::*;
use eframe::egui::{self, RichText};
use std::path::PathBuf;
use std::time::Duration;

const W_SIZE: f32 = 110.0;
const W_DATE: f32 = 150.0;
const W_KIND: f32 = 90.0;

enum Act {
    Select(usize, bool),
    Activate(usize),
}

impl MgrApp {
    pub fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("🗂 Shield 파일 관리자").strong().size(18.0));
            ui.separator();
            let items: &[(MTab, &str)] = if self.open.is_some() {
                &[(MTab::Files, "📄 파일"), (MTab::Info, "ℹ 정보"), (MTab::Help, "❓ 사용법")]
            } else {
                &[(MTab::Files, "🗂 탐색"), (MTab::Help, "❓ 사용법")]
            };
            tabs(ui, &mut self.tab, items);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("🔒 암호화 창").on_hover_text("암호화·복호화·비밀번호 교체 창을 엽니다").clicked() {
                    self.launch_enc_window();
                }
            });
        });
        if self.tab != MTab::Files {
            return;
        }
        ui.horizontal(|ui| {
            if let Some(o) = &self.open {
                let name = o.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                if ui.button("🔒 닫기").on_hover_text("키와 목록을 메모리에서 지우고 닫습니다").clicked() {
                    self.close_container();
                    return;
                }
                if ui.add_enabled(!self.inner.is_empty(), egui::Button::new("⬆ 위로")).clicked() {
                    self.inner_up();
                }
                let loc = if self.inner.is_empty() { format!("🔐 {name}") } else { format!("🔐 {name} › {}", self.inner.replace('/', " › ")) };
                ui.label(RichText::new(loc).strong());
                return;
            }
            if ui.add_enabled(self.cwd.is_some(), egui::Button::new("⬆ 위로")).clicked() {
                self.up();
            }
            if ui.button("💽 드라이브").clicked() {
                self.go(None);
            }
            if ui.button("🔄").on_hover_text("새로 고침").clicked() {
                self.refresh();
            }
            let r = ui.add(egui::TextEdit::singleline(&mut self.addr).desired_width(ui.available_width() - 190.0).hint_text("경로 입력 후 Enter"));
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                let p = PathBuf::from(self.addr.trim());
                if p.is_dir() {
                    self.go(Some(p));
                } else if is_shd(&p) {
                    self.go(p.parent().map(|x| x.to_path_buf()));
                    self.pending = Some(p);
                } else {
                    self.set(false, "폴더 또는 .shd 파일 경로가 아닙니다.");
                }
            }
            ui.add(egui::TextEdit::singleline(&mut self.filter).desired_width(170.0).hint_text("🔍 이름 필터"));
        });
    }

    pub fn view_browse(&mut self, ui: &mut egui::Ui) {
        let one = (self.sel.len() == 1).then(|| self.sel.iter().next().cloned()).flatten();
        let shd = one.clone().filter(|p| is_shd(p));
        ui.horizontal(|ui| {
            if ui.button("🔒 암호화…").on_hover_text("선택한 파일·폴더로 암호화 창을 엽니다").clicked() {
                match &one {
                    Some(p) => self.launch_enc("--encrypt", &p.clone()),
                    None if self.sel.is_empty() => self.set(false, "암호화할 파일 또는 폴더를 하나 선택하세요."),
                    None => self.set(false, "암호화는 한 번에 한 항목씩 합니다. 여러 개를 묶으려면 한 폴더에 넣으세요."),
                }
            }
            if ui.add_enabled(shd.is_some(), egui::Button::new("🔐 열기")).clicked() {
                self.pending = shd.clone();
            }
            if ui.add_enabled(shd.is_some(), egui::Button::new("🔓 복호화…")).on_hover_text("암호화 창의 복호화 탭으로 엽니다").clicked() {
                if let Some(p) = &shd {
                    self.launch_enc("--decrypt", &p.clone());
                }
            }
            let n = self.sel.len();
            if n > 0 {
                let size: u64 = self.entries.iter().filter(|e| self.sel.contains(&e.path) && !e.is_dir).map(|e| e.size).sum();
                hint(ui, format!("선택 {n}개 · 파일 {}", human(size)));
            }
        });
        ui.add_space(2.0);
        table_row(ui, false, &[("이름", 0.0), ("크기", W_SIZE), ("수정한 날짜", W_DATE), ("종류", W_KIND)], true);
        let f = self.filter.to_lowercase();
        let rows: Vec<usize> = (0..self.entries.len()).filter(|&i| f.is_empty() || self.entries[i].name.to_lowercase().contains(&f)).collect();
        let mut act = None;
        let ctrl = ui.input(|i| i.modifiers.command);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, ROW_H, rows.len(), |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for &i in &rows[range] {
                let e = &self.entries[i];
                let icon = if e.is_dir { "📁" } else if is_shd(&e.path) { "🔐" } else { "📄" };
                let kind = if self.cwd.is_none() { "드라이브" } else if e.is_dir { "폴더" } else if is_shd(&e.path) { "Shield" } else { "파일" };
                let size = if e.is_dir { String::new() } else { human(e.size) };
                let name = format!("{icon} {}", e.name);
                let dt = if e.mtime.is_some() { date(e.mtime) } else { String::new() };
                let r = table_row(ui, self.sel.contains(&e.path), &[(&name, 0.0), (&size, W_SIZE), (&dt, W_DATE), (kind, W_KIND)], false);
                if r.double_clicked() {
                    act = Some(Act::Activate(i));
                } else if r.clicked() {
                    act = Some(Act::Select(i, ctrl));
                }
            }
        });
        match act {
            Some(Act::Activate(i)) => {
                let (p, d) = (self.entries[i].path.clone(), self.entries[i].is_dir);
                self.activate(p, d);
            }
            Some(Act::Select(i, add)) => {
                let p = self.entries[i].path.clone();
                if !add {
                    self.sel.clear();
                    self.sel.insert(p);
                } else if !self.sel.remove(&p) {
                    self.sel.insert(p);
                }
            }
            None => {}
        }
    }

    pub fn view_unlock(&mut self, ui: &mut egui::Ui) {
        let Some(p) = self.pending.clone() else { return };
        ui.heading("🔐 .shd 컨테이너 열기");
        hint(ui, "키 슬롯·메타데이터와 7z 목록만 인증·복호화합니다. 평문 파일은 만들지 않습니다.");
        ui.add_space(6.0);
        section(ui, "① 컨테이너", |ui| {
            ui.label(RichText::new(p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()).strong().size(16.0));
            let size = std::fs::metadata(&p).map(|m| human(m.len())).unwrap_or_else(|_| "찾을 수 없음".into());
            hint(ui, format!("{} · {}", size, p.display()));
        });
        section(ui, "② 비밀번호 / PIM", |ui| {
            secret_field(ui, "mpw", &mut self.pw, "비밀번호");
            pim_picker(ui, &mut self.custom_pim, &mut self.pim, true);
        });
        let mut msg = None;
        section(ui, "③ 키 파일 (사용했다면 모두)", |ui| msg = keyfile_list(ui, &mut self.keyfiles, None));
        self.apply_msg(msg);
        memory_warnings(ui);
        let mut problems = vec![];
        if self.pw.is_empty() && self.keyfiles.is_empty() {
            problems.push("비밀번호 또는 키 파일을 입력하세요.".to_string());
        }
        let enter = problems.is_empty() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        ui.horizontal(|ui| {
            if action_button(ui, &problems, "🔓 열기") || enter {
                self.start_open();
            }
            if ui.button("← 목록으로").clicked() {
                self.pending = None;
                self.pw.clear();
            }
        });
        hint(ui, "비밀번호·PIM·키 파일이 틀렸을 때와 Shield 2 파일이 아닐 때는 같은 메시지가 나옵니다.");
    }

    pub fn view_container(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            if ui.add_enabled(!self.csel.is_empty(), egui::Button::new("📤 선택 항목 추출…")).clicked() {
                self.start_extract_selected();
            }
            if ui.button("📦 전체 추출…").on_hover_text("본문 전체를 인증한 뒤 모두 풉니다").clicked() {
                self.start_extract_all();
            }
            ui.separator();
            if ui.button("➕ 파일 추가…").clicked() {
                if let Some(v) = rfd::FileDialog::new().set_title("추가할 파일").pick_files() {
                    self.request_add(v);
                }
            }
            if ui.button("➕ 폴더 추가…").clicked() {
                if let Some(d) = rfd::FileDialog::new().set_title("추가할 폴더").pick_folder() {
                    self.request_add(vec![d]);
                }
            }
            ui.separator();
            if ui.button("🛡 본문 전체 검사").on_hover_text("모든 청크의 인증 태그를 확인합니다 (큰 파일은 오래 걸림, 취소 가능)").clicked() {
                self.start_check();
            }
        });
        ui.horizontal(|ui| {
            ui.label("추가 시 압축");
            egui::ComboBox::from_id_source("mstrength").selected_text(self.strength.label()).show_ui(ui, |ui| {
                for s in Strength::ALL {
                    ui.selectable_value(&mut self.strength, s, s.label());
                }
            });
            ui.checkbox(&mut self.shred_added, "추가·검증 후 추가한 원본 파쇄");
            let n = self.csel.len();
            if n > 0 {
                let size: u64 = self.children.iter().filter(|c| self.csel.contains(c.full.as_str())).map(|c| c.size).sum();
                hint(ui, format!("선택 {n}개 · {}", human(size)));
            }
        });
        ui.add_space(2.0);
        table_row(ui, false, &[("이름", 0.0), ("크기", W_SIZE), ("수정한 날짜", W_DATE)], true);
        let mut act = None;
        let ctrl = ui.input(|i| i.modifiers.command);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show_rows(ui, ROW_H, self.children.len(), |ui, range| {
            ui.spacing_mut().item_spacing.y = 0.0;
            for i in range {
                let c = &self.children[i];
                let name = format!("{} {}", if c.is_dir { "📁" } else { "📄" }, c.name.as_str());
                let size = human(c.size);
                let dt = if c.mtime.is_some() { date(c.mtime) } else { String::new() };
                let r = table_row(ui, self.csel.contains(c.full.as_str()), &[(&name, 0.0), (&size, W_SIZE), (&dt, W_DATE)], false);
                if r.double_clicked() && c.is_dir {
                    act = Some(Act::Activate(i));
                } else if r.clicked() {
                    act = Some(Act::Select(i, ctrl));
                }
            }
        });
        if self.children.is_empty() {
            hint(ui, "빈 폴더입니다.");
        }
        match act {
            Some(Act::Activate(i)) => {
                let f = self.children[i].full.to_string();
                self.enter(&f);
            }
            Some(Act::Select(i, add)) => {
                let f = self.children[i].full.to_string();
                if !add {
                    self.csel.clear();
                    self.csel.insert(f);
                } else if !self.csel.remove(&f) {
                    self.csel.insert(f);
                }
            }
            None => {}
        }
    }

    pub fn view_info(&mut self, ui: &mut egui::Ui) {
        let Some(o) = &self.open else { return };
        let m = &o.hdr.meta;
        let comp = match m.comp_method {
            format::COMP_LZMA2 => format!("LZMA2 · 레벨 {} · 사전 {}", m.comp_level, human(m.comp_dict as u64)),
            format::COMP_ZSTD => format!("Zstandard · 레벨 {}", m.comp_level),
            x => comp_name(x).to_string(),
        };
        let stored = if m.flags & format::FLAG_SOME_STORED != 0 { " (일부 무압축 저장)" } else { "" };
        let created = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(m.created));
        let rows: Vec<(&str, String)> = vec![
            ("형식 버전", format!("Shield v{}", m.version)),
            ("원래 이름", m.name.clone()),
            ("만든 날짜", date(created)),
            ("데이터 암호화", "XChaCha20-Poly1305".into()),
            ("키 유도", format!("Argon2id · 메모리 {} · 병렬도 {} · 반복 {} (3 + PIM {})", human(m.kdf_mem_kib as u64 * 1024), m.kdf_lanes, 3 + o.cred.pim, o.cred.pim)),
            ("해시", "SHA3-512".into()),
            ("압축", format!("{comp}{stored}")),
            ("암호문 크기", format!("{} ({} 바이트)", human(o.hdr.file_len), o.hdr.file_len)),
            ("실제 크기 (7z)", human(m.real_len)),
            ("패딩 크기", human(o.padding())),
            ("청크", format!("{}개 × {}", o.chunk_count(), human(m.chunk as u64))),
            ("파일 / 폴더 수", format!("{} / {}", m.file_count, m.dir_count)),
            ("총 해제 크기", human(m.total_unpacked)),
        ];
        ui.heading("ℹ 컨테이너 정보");
        ui.add_space(4.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            section(ui, "구성", |ui| {
                egui::Grid::new("info").num_columns(2).striped(true).spacing([16.0, 6.0]).show(ui, |ui| {
                    for (k, v) in &rows {
                        ui.label(RichText::new(*k).strong());
                        ui.label(v);
                        ui.end_row();
                    }
                });
            });
            let body = o.body;
            section(ui, "검사 상태", |ui| {
                for t in ["키 슬롯 인증 (헤더)", "메타데이터 인증", "7z 헤더 구조·경로·크기 제한 검사"] {
                    ui.label(RichText::new(format!("✔ {t}")).color(GREEN));
                }
                match body {
                    BodyCheck::NotChecked => ui.label(RichText::new("… 본문 전체 인증: 미검사").color(AMBER)),
                    BodyCheck::Ok => ui.label(RichText::new("✔ 본문 전체 인증: 통과").color(GREEN)),
                    BodyCheck::Failed => ui.label(RichText::new("✖ 본문 전체 인증: 실패 (손상 또는 변조)").color(RED)),
                };
                hint(ui, "추출할 때는 읽는 청크마다 인증하므로 미검사 상태에서도 변조된 데이터는 풀리지 않습니다.");
            });
        });
        if ui.button("🛡 본문 전체 검사").clicked() {
            self.start_check();
        }
    }

    pub fn confirm_window(&mut self, ctx: &egui::Context) {
        let Some(pa) = &self.confirm else { return };
        let (clash, shred) = (pa.clash.clone(), self.shred_added);
        let mut decision = None;
        egui::Window::new("확인").collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
            if !clash.is_empty() {
                ui.label(RichText::new("같은 이름의 항목이 컨테이너에 이미 있습니다:").strong());
                for c in clash.iter().take(10) {
                    ui.label(format!("• {c}"));
                }
                if clash.len() > 10 {
                    hint(ui, format!("외 {}개", clash.len() - 10));
                }
                ui.label("덮어쓰면 기존 항목(폴더라면 그 안의 모든 항목)이 새 것으로 바뀝니다.");
            }
            if shred {
                ui.label(RichText::new("추가·검증이 끝나면 추가한 원본 파일을 7회 덮어쓴 뒤 삭제합니다. 되돌릴 수 없습니다.").color(RED));
            }
            ui.horizontal(|ui| {
                let label = if clash.is_empty() { "추가" } else { "덮어쓰고 추가" };
                if ui.button(label).clicked() {
                    decision = Some(true);
                }
                if ui.button("취소").clicked() {
                    decision = Some(false);
                }
            });
        });
        match decision {
            Some(true) => {
                if let Some(pa) = self.confirm.take() {
                    let ow = !pa.clash.is_empty();
                    self.start_add(pa.paths, ow);
                }
            }
            Some(false) => self.confirm = None,
            None => {}
        }
    }
}

impl eframe::App for MgrApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.housekeeping(ctx);
        if self.busy() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        egui::TopBottomPanel::top("bar").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.add_enabled_ui(!self.busy(), |ui| self.top_bar(ui));
            ui.add_space(2.0);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.add_space(4.0);
            if let Some(job) = &mut self.job {
                crate::ui::progress_view(ui, job);
            } else {
                let hint = if self.open.is_some() { "파일·폴더를 끌어다 놓으면 지금 보고 있는 폴더에 추가합니다." } else { ".shd 파일을 두 번 클릭하거나 끌어다 놓으면 엽니다." };
                crate::ui::status_line(ui, self.ok, &self.status, hint);
            }
            ui.add_space(2.0);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            let m = crate::ui::leftover_banner(ui, &mut self.leftovers);
            self.apply_msg(m);
            ui.add_enabled_ui(!self.busy(), |ui| match self.tab {
                MTab::Help => {
                    egui::ScrollArea::vertical().show(ui, |ui| crate::ui::usage_view(ui, "❓ 사용법 (파일 관리자)", crate::help::MGR_USAGE));
                }
                MTab::Info if self.open.is_some() => self.view_info(ui),
                _ if self.open.is_some() => self.view_container(ui),
                _ if self.pending.is_some() => self.view_unlock(ui),
                _ => self.view_browse(ui),
            });
        });
        self.confirm_window(ctx);
    }
}
