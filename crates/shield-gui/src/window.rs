//! Window geometry for both windows on both systems (3.0.0 §2): one set of constants, the
//! remembered position and its checks.
//!
//! * Size: `DEFAULT_SIZE` / `MIN_SIZE` / `RESIZABLE` in logical points, the same on Windows and
//!   Linux (no per-OS values). Logical points times the display scale give pixels; Linux used to
//!   get a guessed scale on X11, see `shield_platform::display` (fixed before the window exists).
//! * Position: saved in physical pixels when it changes (not while minimized), restored at the
//!   next start after `ui_prefs::restore_position` checked it against the connected monitors,
//!   and corrected on the first frames if the window landed elsewhere (mixed-scale monitors).
//!   Wayland can't do this: the option is shown as switched off with the reason (§4).

use crate::settings::{EnvKey, Settings};
use crate::ui_prefs::{restore_position, RectPx, WinPos};
use eframe::egui;

/// Default inner size in logical points (2.1.0 value, both systems).
pub const DEFAULT_SIZE: [f32; 2] = [1040.0, 700.0];
/// Smallest inner size in logical points (both systems).
pub const MIN_SIZE: [f32; 2] = [800.0, 560.0];
pub const RESIZABLE: bool = true;
/// Title bar height in logical points used for the "can still be dragged" check.
const TITLE_H: f32 = 32.0;

/// What `display::prepare_scale` changed at start-up (shown on the information tab).
pub static SCALE_NOTE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WinKind {
    Encrypt,
    Manager,
}

fn saved(set: &Settings, k: WinKind) -> Option<WinPos> {
    match k {
        WinKind::Encrypt => set.ui.win_enc,
        WinKind::Manager => set.ui.win_mgr,
    }
}

fn saved_mut(set: &mut Settings, k: WinKind) -> &mut Option<WinPos> {
    match k {
        WinKind::Encrypt => &mut set.ui.win_enc,
        WinKind::Manager => &mut set.ui.win_mgr,
    }
}

fn rects(m: &[shield_platform::Monitor]) -> Vec<RectPx> {
    m.iter().map(|m| RectPx { x: m.x, y: m.y, w: m.w, h: m.h }).collect()
}

/// Physical outer size of a default window on a monitor with this scale (frame included roughly).
fn size_px(scale: f32) -> (i32, i32) {
    ((DEFAULT_SIZE[0] * scale) as i32 + 16, ((DEFAULT_SIZE[1] + TITLE_H) * scale) as i32 + 8)
}

/// Where the window should open (physical pixels), or None for the default (centred).
pub fn target_position(set: &Settings, k: WinKind, monitors: Option<&[shield_platform::Monitor]>) -> Option<WinPos> {
    if !set.ui.remember_window_pos {
        return None;
    }
    let m = monitors?;
    let p = saved(set, k)?;
    // the scale of the monitor it was on (the primary one when it's gone)
    let on = m.iter().find(|m| p.x >= m.x && p.x < m.x + m.w && p.y >= m.y && p.y < m.y + m.h).or_else(|| m.iter().find(|m| m.primary)).or(m.first())?;
    let (w, h) = size_px(on.scale);
    restore_position(Some(p), w, h, (TITLE_H * on.scale) as i32, &rects(m))
}

/// The window's builder: same size rules everywhere; a checked remembered position (converted to
/// the points egui expects: egui multiplies by the primary monitor's scale at creation).
pub fn viewport(title: &str, icon: egui::IconData, target: Option<WinPos>, monitors: Option<&[shield_platform::Monitor]>) -> egui::ViewportBuilder {
    let mut b = egui::ViewportBuilder::default()
        .with_title(title)
        .with_app_id("shield")
        .with_icon(icon)
        .with_inner_size(DEFAULT_SIZE)
        .with_min_inner_size(MIN_SIZE)
        .with_resizable(RESIZABLE)
        .with_drag_and_drop(true);
    if let Some(p) = target {
        let primary = monitors.and_then(|m| m.iter().find(|m| m.primary).or(m.first()).map(|m| m.scale)).unwrap_or(1.0).max(0.1);
        b = b.with_position([p.x as f32 / primary, p.y as f32 / primary]);
    }
    b
}

/// Follows the window: saves its position (debounced by the shell's save), corrects a restored
/// position that landed elsewhere, and switches the option off where positions can't be read.
pub struct Tracker {
    pub kind: WinKind,
    /// Position the window should be at (from the start-up check), until it was confirmed.
    target: Option<WinPos>,
    frames: u32,
    /// Whether the window system reports and accepts positions: the platform's answer (X11 yes,
    /// Wayland or no display no). Tests pin it so they mean the same on every machine.
    supported: fn() -> Result<(), &'static str>,
}

impl Tracker {
    pub fn new(kind: WinKind, target: Option<WinPos>) -> Self {
        Tracker { kind, target, frames: 0, supported: shield_platform::display::position_supported }
    }

    /// Replaces the platform check (tests: a headless Linux build has no display, a desktop one may
    /// run Wayland or X11; the answer must not depend on where the tests run).
    #[cfg(test)]
    pub(crate) fn with_support(mut self, f: fn() -> Result<(), &'static str>) -> Self {
        self.supported = f;
        self
    }

    /// Call every frame. `set` is the live settings (the shell saves changes).
    pub fn frame(&mut self, ctx: &egui::Context, set: &mut Settings) {
        self.frames = self.frames.saturating_add(1);
        if set.off_reason(EnvKey::RememberWindowPos).is_some() || !set.ui.remember_window_pos {
            return;
        }
        if let Err(why) = (self.supported)() {
            set.suppress(EnvKey::RememberWindowPos, crate::i18n::tf("win.pos_unsupported", &[&why]));
            return;
        }
        // read before `ctx.input`: that closure holds egui's context lock, and calling any `ctx`
        // method inside it (zoom_factor locks again) blocks the UI thread forever - the 3.0.0 bug
        // where the window never appeared (see frame_tests.rs)
        let zoom = ctx.zoom_factor();
        let (rect, minimized, native) = ctx.input(|i| {
            let vp = i.viewport();
            (vp.outer_rect, vp.minimized.unwrap_or(false), vp.native_pixels_per_point.unwrap_or(1.0))
        });
        let ppp = native * zoom;
        let Some(rect) = rect else {
            // the window system gives no position (a few frames are allowed for the first report)
            if self.frames > 10 {
                set.suppress(EnvKey::RememberWindowPos, crate::i18n::tf("win.pos_unsupported", &[&"no position"]));
            }
            return;
        };
        if minimized {
            return; // never save the parking position of a minimized window (-32000 on Windows)
        }
        let now = WinPos { x: (rect.min.x * ppp).round() as i32, y: (rect.min.y * ppp).round() as i32 };
        if let Some(t) = self.target {
            // landed elsewhere (monitors with different scales): move it once more
            if ((now.x - t.x).abs() > 2 || (now.y - t.y).abs() > 2) && self.frames <= 3 {
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(t.x as f32 / ppp, t.y as f32 / ppp)));
                return;
            }
            self.target = None;
        }
        if now.sane() && saved(set, self.kind) != Some(now) {
            *saved_mut(set, self.kind) = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shield_platform::Monitor;

    #[test]
    fn one_size_for_every_system() {
        // the only place sizes are defined; lib.rs uses `viewport` for both windows
        assert_eq!(DEFAULT_SIZE, [1040.0, 700.0]);
        assert_eq!(MIN_SIZE, [800.0, 560.0]);
        let icon = egui::IconData { rgba: vec![0; 4], width: 1, height: 1 };
        let b = viewport("t", icon, None, None);
        assert_eq!(b.inner_size, Some(egui::vec2(DEFAULT_SIZE[0], DEFAULT_SIZE[1])));
        assert_eq!(b.min_inner_size, Some(egui::vec2(MIN_SIZE[0], MIN_SIZE[1])));
        assert_eq!(b.resizable, Some(RESIZABLE));
        assert_eq!(b.position, None, "no remembered position: centred");
        let src = |f: &str| std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join(f)).unwrap();
        for f in ["lib.rs", "enc_app.rs", "mgr_app.rs", "shell.rs", "theme.rs"] {
            let s = src(f);
            assert!(!s.contains("with_inner_size(") && !s.contains("with_min_inner_size("), "{f} must use window::viewport");
            assert!(!s.contains("cfg(target_os"), "{f}: no per-OS window code");
        }
    }

    #[test]
    fn remembered_position_is_checked_before_use() {
        let mon = [Monitor { x: 0, y: 0, w: 1920, h: 1040, scale: 1.0, primary: true }];
        let mut s = Settings::default();
        s.ui.win_enc = Some(WinPos { x: 200, y: 100 });
        assert_eq!(target_position(&s, WinKind::Encrypt, Some(&mon)), Some(WinPos { x: 200, y: 100 }));
        assert_eq!(target_position(&s, WinKind::Manager, Some(&mon)), None, "per window");
        assert_eq!(target_position(&s, WinKind::Encrypt, None), None, "monitors unknown (Wayland)");
        s.ui.win_enc = Some(WinPos { x: 5000, y: 100 });
        assert_eq!(target_position(&s, WinKind::Encrypt, Some(&mon)), None, "monitor unplugged");
        s.ui.win_enc = Some(WinPos { x: 200, y: 100 });
        s.ui.remember_window_pos = false;
        assert_eq!(target_position(&s, WinKind::Encrypt, Some(&mon)), None, "option off");
        // 150 % monitor: the egui position is divided by the primary scale
        let hi = [Monitor { x: 0, y: 0, w: 2880, h: 1560, scale: 1.5, primary: true }];
        s.ui.remember_window_pos = true;
        let t = target_position(&s, WinKind::Encrypt, Some(&hi));
        let icon = egui::IconData { rgba: vec![0; 4], width: 1, height: 1 };
        let b = viewport("t", icon, t, Some(&hi));
        assert_eq!(b.position, Some(egui::pos2(200.0 / 1.5, 100.0 / 1.5)));
    }
}
