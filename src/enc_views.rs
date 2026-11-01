//! Screens of the encryption window. Each screen is laid out as numbered steps, lists what is still
//! missing, and only enables its main button when the input is complete.

use crate::compress::Strength;
use crate::enc_app::EncApp;
use crate::sysinfo::{self, is_shd, roots};
use crate::ui::*;
use crate::{help, wipe};
use eframe::egui::{self, RichText};
use std::path::PathBuf;

#[derive(PartialEq)]
enum Pick {
    Any,
    Shd,
}

/// Selected target with its size and pick buttons. Returns a newly picked path.
fn target_card(ui: &mut egui::Ui, sel: &Option<PathBuf>, pick: Pick) -> Option<PathBuf> {
    match sel {
        Some(p) => {
            let md = std::fs::metadata(p).ok();
            let kind = match &md {
                Some(m) if m.is_dir() => "📁 폴더".to_string(),
                Some(m) => format!("📄 파일 · {}", human(m.len())),
                None => "⚠ 찾을 수 없음".to_string(),
            };
            let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| p.display().to_string());
            ui.label(RichText::new(name).strong().size(16.0));
            hint(ui, format!("{kind} · {}", p.display()));
        }
        None => hint(ui, "아직 선택하지 않았습니다. 아래 버튼을 누르거나 창에 끌어다 놓으세요."),
    }
    let mut out = None;
    ui.horizontal(|ui| {
        if pick == Pick::Any {
            if ui.button("📄 파일 선택…").clicked() {
                out = rfd::FileDialog::new().set_title("암호화할 파일").pick_file();
            }
            if ui.button("📁 폴더 선택…").clicked() {
                out = rfd::FileDialog::new().set_title("암호화할 폴더").pick_folder();
            }
        } else if ui.button("🔐 .shd 파일 선택…").clicked() {
            out = rfd::FileDialog::new().set_title(".shd 파일").add_filter("Shield", &["shd"]).pick_file();
        }
    });
    out
}

fn kf_only_check(ui: &mut egui::Ui, ack: &mut bool) {
    ui.checkbox(ack, RichText::new("비밀번호 없이 키 파일만 사용합니다 (키 파일을 가진 사람은 누구나 열 수 있음)").color(AMBER));
    hint(ui, "권장: 비밀번호와 키 파일을 함께 쓰세요.");
}

impl EncApp {
    fn pick(&mut self, p: Option<PathBuf>) {
        if let Some(p) = p {
            self.select(p);
        }
    }

    pub fn view_encrypt(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔒 파일·폴더 암호화");
        hint(ui, "선택한 항목을 7z로 압축한 뒤 XChaCha20-Poly1305로 암호화해 하나의 .shd 파일로 만듭니다. 원본은 그대로 남습니다(파쇄 선택 시 제외).");
        ui.add_space(6.0);
        let mut picked = None;
        section(ui, "① 대상", |ui| picked = target_card(ui, &self.selected, Pick::Any));
        self.pick(picked);
        section(ui, "② 비밀번호", |ui| {
            secret_field(ui, "pw", &mut self.pw, "비밀번호 (12자 이상 권장: 여러 단어 조합)");
            strength_bar(ui, &self.pw);
            secret_field(ui, "pw2", &mut self.pw2, "비밀번호 다시 입력");
            match_label(ui, &self.pw, &self.pw2);
            pim_picker(ui, &mut self.custom_pim, &mut self.pim, false);
        });
        let mut msg = None;
        section(ui, "③ 키 파일 (선택)", |ui| {
            msg = keyfile_list(ui, &mut self.keyfiles, Some(&mut self.gen_kib));
            if self.pw.is_empty() && !self.keyfiles.is_empty() {
                kf_only_check(ui, &mut self.kf_only_ack);
            }
        });
        self.apply_msg(msg);
        section(ui, "④ 압축", |ui| {
            egui::ComboBox::from_id_source("strength").selected_text(self.strength.label()).show_ui(ui, |ui| {
                for s in Strength::ALL {
                    ui.selectable_value(&mut self.strength, s, s.label());
                }
            });
            hint(ui, match self.strength {
                Strength::Auto => "대상 크기·가용 메모리·CPU 수를 보고 LZMA2 레벨과 사전 크기를 고릅니다. 메모리가 부족하면 Zstandard를 씁니다.",
                Strength::Fast => "Zstandard 레벨 3: 가장 빠르고 압축률은 낮습니다.",
                Strength::Balanced => "LZMA2 중간 레벨: 속도와 압축률의 균형.",
                Strength::Max => "LZMA2 최고 레벨: 가장 작지만 느리고 메모리를 많이 씁니다(사전 최대 64 MiB).",
            });
            hint(ui, "jpg·mp4·zip 같은 이미 압축된 파일은 자동으로 무압축 저장해 시간을 아낍니다.");
        });
        section(ui, "⑤ 옵션", |ui| {
            ui.checkbox(&mut self.choose_dest, "저장 위치 직접 선택");
            hint(ui, "끄면 원본 옆에 '이름.shd'로 저장합니다 (같은 이름이 있으면 번호를 붙임).");
            ui.checkbox(&mut self.shred_src, "암호화·복원 검증이 끝나면 원본 파쇄 (영구 삭제)");
            if self.shred_src {
                ui.indent("shred", |ui| {
                    ui.checkbox(&mut self.shred_ack, RichText::new("원본이 영구 삭제되어 복구할 수 없음을 이해했습니다").color(RED));
                    ui.checkbox(&mut self.force7, "SSD여도 7회 덮어쓰기 (기본: HDD 7회 / SSD 1회)");
                    ui.checkbox(&mut self.trim_after, "파쇄 후 TRIM 실행 (SSD 권장 · 관리자 확인 창이 뜰 수 있음)");
                    ui.checkbox(&mut self.wipe_free_after, "파쇄 후 드라이브 여유 공간 덮어쓰기 (선택 · 매우 오래 걸림)");
                    hint(ui, "목록을 확정한 시점의 파일만, 바뀌지 않았을 때만 파쇄합니다. 하드 링크·링크·새로 생긴 파일은 건드리지 않습니다.");
                    warn(ui, "SSD·스냅샷·클라우드 동기화 폴더에서는 물리적 삭제를 보장할 수 없습니다.");
                });
            }
        });
        memory_warnings(ui);
        let problems = self.encrypt_problems();
        if action_button(ui, &problems, "🔒 암호화 시작") {
            self.start_encrypt();
        }
    }

    pub fn view_decrypt(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔓 복호화");
        hint(ui, ".shd 파일 전체를 인증한 뒤 원래 파일·폴더로 되돌립니다. 같은 이름이 있으면 덮어쓰지 않고 '(decrypted)'를 붙입니다.");
        ui.add_space(6.0);
        let mut picked = None;
        section(ui, "① 암호화 파일 (.shd)", |ui| {
            picked = target_card(ui, &self.selected, Pick::Shd);
            if let Some(p) = self.selected.clone().filter(|p| is_shd(p)) {
                if ui.button("🗂 파일 관리자에서 내용 보기 / 일부만 추출").clicked() {
                    self.open_manager(Some(&p));
                }
            }
        });
        self.pick(picked);
        section(ui, "② 암호화할 때 쓴 비밀번호", |ui| {
            secret_field(ui, "pw", &mut self.pw, "비밀번호");
            pim_picker(ui, &mut self.custom_pim, &mut self.pim, true);
        });
        let mut msg = None;
        section(ui, "③ 키 파일 (사용했다면 모두)", |ui| msg = keyfile_list(ui, &mut self.keyfiles, None));
        self.apply_msg(msg);
        section(ui, "④ 저장 위치", |ui| {
            ui.checkbox(&mut self.choose_dest, "저장 폴더 직접 선택");
            hint(ui, "끄면 .shd 파일과 같은 폴더에 풉니다.");
        });
        memory_warnings(ui);
        let problems = self.decrypt_problems();
        if action_button(ui, &problems, "🔓 복호화 시작") {
            self.start_decrypt();
        }
    }

    pub fn view_rekey(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔑 비밀번호·키 교체");
        hint(ui, "작업 전에 .shd 파일을 백업해 두기를 권장합니다.");
        ui.add_space(6.0);
        let mut picked = None;
        section(ui, "① 대상 .shd 파일", |ui| picked = target_card(ui, &self.selected, Pick::Shd));
        self.pick(picked);
        let mut msg = None;
        section(ui, "② 현재 비밀번호 / PIM / 키 파일", |ui| {
            secret_field(ui, "pw", &mut self.pw, "현재 비밀번호");
            pim_picker(ui, &mut self.custom_pim, &mut self.pim, true);
            ui.label("현재 키 파일");
            msg = keyfile_list(ui, &mut self.keyfiles, None);
        });
        self.apply_msg(msg);
        section(ui, "③ 방식", |ui| {
            ui.radio_value(&mut self.full_rekey, false, "비밀번호만 변경 (빠름)");
            hint(ui, "파일 키(DEK)를 새 자격 증명으로 다시 감싸고 이전 키 슬롯을 7회 덮어씁니다. 본문은 그대로입니다.");
            ui.radio_value(&mut self.full_rekey, true, "전체 키 교체 (새 DEK로 전체 재암호화)");
            hint(ui, "새 DEK·솔트·nonce·패딩으로 전체를 다시 암호화하고 검증한 뒤 원자적으로 교체합니다. 파일 크기만큼 시간과 여유 공간이 필요합니다. DEK 유출이 의심될 때 쓰세요.");
            warn(ui, "⚠ 어느 방식이든 이전에 만든 백업본·클라우드 버전 기록·섀도 복사본은 이전 비밀번호로 계속 열립니다.");
        });
        let mut msg = None;
        section(ui, "④ 새 비밀번호 / PIM / 키 파일", |ui| {
            secret_field(ui, "npw", &mut self.new_pw, "새 비밀번호");
            strength_bar(ui, &self.new_pw);
            secret_field(ui, "npw2", &mut self.new_pw2, "새 비밀번호 다시 입력");
            match_label(ui, &self.new_pw, &self.new_pw2);
            pim_picker(ui, &mut self.new_custom_pim, &mut self.new_pim, false);
            ui.label("새 키 파일");
            msg = keyfile_list(ui, &mut self.new_keyfiles, Some(&mut self.gen_kib));
            if self.new_pw.is_empty() && !self.new_keyfiles.is_empty() {
                kf_only_check(ui, &mut self.new_kf_only_ack);
            }
        });
        self.apply_msg(msg);
        memory_warnings(ui);
        let problems = self.rekey_problems();
        let label = if self.full_rekey { "🔑 전체 키 교체" } else { "🔑 비밀번호 변경" };
        if action_button(ui, &problems, label) {
            self.start_rekey();
        }
    }

    pub fn view_disk(&mut self, ui: &mut egui::Ui) {
        ui.heading("💽 디스크 정리");
        hint(ui, "삭제한 파일의 흔적을 줄이는 기능입니다. 보통은 TRIM만으로 충분하며, 여유 공간 덮어쓰기는 선택 사항입니다.");
        ui.add_space(6.0);
        if self.disk_drive.is_none() {
            self.disk_drive = self.selected.as_deref().and_then(wipe::drive_letter).map(|l| format!("{l}:\\").into());
        }
        section(ui, "① 드라이브", |ui| {
            let cur = self.disk_drive.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "선택하세요".into());
            egui::ComboBox::from_id_source("drive").selected_text(cur).show_ui(ui, |ui| {
                for r in roots() {
                    let t = r.display().to_string();
                    ui.selectable_value(&mut self.disk_drive, Some(r), t);
                }
            });
        });
        section(ui, "② TRIM만 실행 (권장 · 빠름)", |ui| {
            hint(ui, "SSD에 '이미 삭제된 블록'을 알려 컨트롤러가 실제로 지우도록 합니다. 보통 수 초~수 분이면 끝납니다.");
            hint(ui, "관리자 권한이 필요해 Windows 확인 창(UAC)이 뜰 수 있습니다. HDD에서는 지원되지 않습니다.");
            if ui.add_enabled(self.disk_drive.is_some(), egui::Button::new("⚡ TRIM 실행")).clicked() {
                self.start_trim();
            }
        });
        section(ui, "③ 여유 공간 덮어쓰기 (선택)", |ui| {
            hint(ui, "드라이브의 빈 공간 전체를 3회(00 → FF → 난수) 덮어씁니다. 수십 분~수 시간이 걸리고 SSD 쓰기 수명을 소모합니다. 취소 가능.");
            ui.checkbox(&mut self.disk_trim_after_wipe, "끝난 뒤 TRIM도 실행");
            if ui.add_enabled(self.disk_drive.is_some(), egui::Button::new("🧽 여유 공간 덮어쓰기 시작")).clicked() {
                self.start_wipe_free();
            }
        });
        if let Some(d) = &self.disk_drive {
            if wipe::drive_letter(d).is_none() {
                ui.label(RichText::new("이 드라이브는 문자를 확인할 수 없습니다.").color(AMBER));
            }
        }
    }
}

fn yes_no(ui: &mut egui::Ui, ok: bool, what: &str) {
    let (icon, c) = if ok { ("✔", GREEN) } else { ("✖", AMBER) };
    ui.label(RichText::new(format!("{icon} {what}")).color(c));
}

/// "알고리즘·정보" tab: what Shield uses, and what this process actually managed to apply.
pub fn view_algo(ui: &mut egui::Ui) {
    use std::sync::atomic::Ordering;
    ui.heading("🧬 사용 알고리즘 · 정보");
    hint(ui, format!("Shield {} · 형식 버전 {}", env!("CARGO_PKG_VERSION"), crate::format::FORMAT_VERSION));
    ui.add_space(4.0);
    section(ui, "암호 구성", |ui| {
        egui::Grid::new("algo").num_columns(2).striped(true).spacing([16.0, 6.0]).show(ui, |ui| {
            for (k, v) in help::ALGO_ROWS {
                ui.label(RichText::new(*k).strong());
                ui.add(egui::Label::new(*v).wrap(true));
                ui.end_row();
            }
        });
    });
    section(ui, "PIM과 Argon2id 반복 횟수", |ui| {
        let d = crate::format::DEFAULT_PIM;
        ui.label(format!("반복 횟수 = 3 + PIM · 기본 PIM {d} → 반복 {} · 최대 PIM {} → 반복 {}", 3 + d, crate::format::MAX_PIM, 3 + crate::format::MAX_PIM));
        hint(ui, "PIM이 1 늘 때마다 키 유도 시간이 대략 한 단계(256 MiB 1회 통과)만큼 늘어납니다. PIM은 파일에 저장되지 않으니 기억해야 합니다.");
    });
    section(ui, "이 PC에서 적용된 보호", |ui| {
        let rep = crate::harden::REPORT.lock().map(|r| r.clone()).unwrap_or_default().unwrap_or_default();
        yes_no(ui, rep.dacl, "프로세스 접근 제한(DACL) — 같은 사용자 프로세스의 메모리 읽기·조작을 어렵게 함");
        yes_no(ui, rep.dll_dirs, "DLL 검색 경로 제한 (SetDefaultDllDirectories: System32만)");
        yes_no(ui, rep.image_policy, "원격·낮은 무결성 이미지 로드 차단 정책");
        yes_no(ui, rep.no_crash_dialogs, "오류 대화상자·크래시 덤프 억제");
        yes_no(ui, !crate::harden::LOCK_FAILED.load(Ordering::Relaxed), "비밀번호 입력 버퍼 메모리 잠금 (VirtualLock)");
        yes_no(ui, !crate::harden::KDF_LOCK_FAILED.load(Ordering::Relaxed), "Argon2 작업 메모리 잠금 (사용한 적 있을 때만 의미 있음)");
        hint(ui, format!(
            "CPU {}개 · 사용 가능한 메모리 {} · Argon2id는 작업마다 256 MiB를 씁니다.",
            sysinfo::cores(),
            human(sysinfo::avail_mem())
        ));
    });
    section(ui, "한계 (꼭 읽어 주세요)", |ui| {
        for n in help::ALGO_NOTES {
            ui.label(*n);
        }
    });
}
