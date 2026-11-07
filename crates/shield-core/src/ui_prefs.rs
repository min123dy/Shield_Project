//! Remembered UI state (3.0.0 §2-B, §3): one struct for every window and tab, saved in the
//! settings file (same atomic write, owner-only permissions, schema version, merge-on-save and
//! MAC rules as every other setting; see `settings.rs`).
//!
//! Never stored here: passwords, key files or their paths, the files or containers that were
//! picked, PIM values and the per-task acknowledgements ("I understand the originals are deleted",
//! "key files only"): those must be given again for every task. "Shred the added originals" in
//! the file manager is not remembered either: it is reset after every add on purpose.
//!
//! Options that already have a default in Settings (compression strength, shred originals, key
//! file size, hidden files, sort order) are not duplicated: the tab edits that setting directly,
//! so there is one value. The overwrite pass count is security-relevant (its default is a
//! protected setting): a remembered choice is only used when it is not lower than that default.

use crate::wipe::Passes;

/// Outer top-left corner of a window in physical pixels (virtual desktop coordinates).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct WinPos {
    pub x: i32,
    pub y: i32,
}

/// Windows parks minimized windows at (-32000, -32000); anything this far out is never a real
/// position and is neither saved nor restored.
pub const COORD_LIMIT: i32 = 30_000;

impl WinPos {
    pub fn sane(self) -> bool {
        self.x.abs() < COORD_LIMIT && self.y.abs() < COORD_LIMIT
    }
    pub fn code(self) -> String {
        format!("{},{}", self.x, self.y)
    }
    pub fn parse(s: &str) -> Option<WinPos> {
        let (a, b) = s.split_once(',')?;
        let p = WinPos { x: a.trim().parse().ok()?, y: b.trim().parse().ok()? };
        p.sane().then_some(p)
    }
}

/// A rectangle in physical pixels (a monitor's work area, a window).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RectPx {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl RectPx {
    fn right(&self) -> i64 {
        self.x as i64 + self.w as i64
    }
    fn bottom(&self) -> i64 {
        self.y as i64 + self.h as i64
    }
    fn overlap(&self, o: &RectPx) -> i64 {
        let w = (self.right().min(o.right()) - (self.x.max(o.x) as i64)).max(0);
        let h = (self.bottom().min(o.bottom()) - (self.y.max(o.y) as i64)).max(0);
        w * h
    }
}

/// Where to open a window that was last at `saved` (outer size `w` x `h`, title bar `title_h`
/// pixels high), given the work areas of the connected monitors. None = use the default position
/// (centre of the primary monitor):
/// * nothing remembered, an impossible value, or no monitor known;
/// * the title bar would not be on any monitor (monitor unplugged, resolution or scale changed).
///
/// Otherwise the window is moved, if needed, fully into the work area of the monitor that holds
/// most of its title bar, so the title bar is always visible and the window can be dragged.
pub fn restore_position(saved: Option<WinPos>, w: i32, h: i32, title_h: i32, monitors: &[RectPx]) -> Option<WinPos> {
    let p = saved.filter(|p| p.sane())?;
    let (w, h, title_h) = (w.max(1), h.max(1), title_h.clamp(1, h.max(1)));
    let title = RectPx { x: p.x, y: p.y, w, h: title_h };
    // at least a grabbable piece of the title bar: 48 x (title height / 2) pixels
    let need = 48.min(w as i64) * (title_h as i64 / 2).max(1);
    let m = monitors.iter().filter(|m| m.w > 0 && m.h > 0).max_by_key(|m| m.overlap(&title)).filter(|m| m.overlap(&title) >= need)?;
    let clamp = |v: i32, lo: i32, len: i32, size: i32| if size >= len { lo } else { v.clamp(lo, lo + len - size) };
    Some(WinPos { x: clamp(p.x, m.x, m.w, w), y: clamp(p.y, m.y, m.h, h) })
}

#[derive(Clone, Debug, PartialEq)]
pub struct UiPrefs {
    /// Open each window where it was closed (Settings > General). Off: always centred.
    pub remember_window_pos: bool,
    pub win_enc: Option<WinPos>,
    pub win_mgr: Option<WinPos>,
    // encryption window
    pub choose_dest: bool,
    pub bundle: bool,
    pub wipe_free_after: bool,
    pub include_streams: bool,
    pub full_rekey: bool,
    pub enc_passes: Option<Passes>,
    pub disk_trim_after_wipe: bool,
    // file manager
    pub mgr_passes: Option<Passes>,
}

impl Default for UiPrefs {
    fn default() -> Self {
        UiPrefs {
            remember_window_pos: true,
            win_enc: None,
            win_mgr: None,
            choose_dest: false,
            bundle: false,
            wipe_free_after: false,
            include_streams: false,
            full_rekey: false,
            enc_passes: None,
            disk_trim_after_wipe: true,
            mgr_passes: None,
        }
    }
}

/// A remembered pass count, never below the protected default (3.0.0 §3: lowering the overwrite
/// count is a security setting and follows the settings password rules).
pub fn passes_floor(remembered: Option<Passes>, protected_default: Passes) -> Passes {
    match remembered {
        Some(p) if p.count() >= protected_default.count() => p,
        _ => protected_default,
    }
}

impl UiPrefs {
    /// `(key, value)` rows in the settings file. Every key starts with `ui_`.
    pub fn rows(&self) -> Vec<(&'static str, String)> {
        let b = |v: bool| if v { "true".to_string() } else { "false".to_string() };
        let q = |s: String| format!("\"{s}\"");
        let pos = |p: Option<WinPos>| q(p.map(WinPos::code).unwrap_or_default());
        let passes = |p: Option<Passes>| p.map(|p| p.count().to_string()).unwrap_or_else(|| "0".into());
        vec![
            ("ui_remember_window_pos", b(self.remember_window_pos)),
            ("ui_win_enc", pos(self.win_enc)),
            ("ui_win_mgr", pos(self.win_mgr)),
            ("ui_choose_dest", b(self.choose_dest)),
            ("ui_bundle", b(self.bundle)),
            ("ui_wipe_free_after", b(self.wipe_free_after)),
            ("ui_include_streams", b(self.include_streams)),
            ("ui_full_rekey", b(self.full_rekey)),
            ("ui_enc_passes", passes(self.enc_passes)),
            ("ui_disk_trim_after_wipe", b(self.disk_trim_after_wipe)),
            ("ui_mgr_passes", passes(self.mgr_passes)),
        ]
    }

    /// One `ui_*` line. Returns false for an unknown key or a value that is not valid (the value
    /// then keeps its default and the caller reports the damage).
    pub fn parse_line(&mut self, k: &str, v: &str) -> bool {
        let sv = v.strip_prefix('"').and_then(|x| x.strip_suffix('"'));
        let bv = match v {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
        let set_b = |dst: &mut bool| bv.map(|b| *dst = b).is_some();
        let set_pos = |dst: &mut Option<WinPos>| match sv {
            Some("") => {
                *dst = None;
                true
            }
            Some(s) => WinPos::parse(s).map(|p| *dst = Some(p)).is_some(),
            None => false,
        };
        let set_passes = |dst: &mut Option<Passes>| match v.parse::<u64>() {
            Ok(0) => {
                *dst = None;
                true
            }
            Ok(n) => Passes::from_count(n).map(|p| *dst = Some(p)).is_some(),
            Err(_) => false,
        };
        match k {
            "ui_remember_window_pos" => set_b(&mut self.remember_window_pos),
            "ui_win_enc" => set_pos(&mut self.win_enc),
            "ui_win_mgr" => set_pos(&mut self.win_mgr),
            "ui_choose_dest" => set_b(&mut self.choose_dest),
            "ui_bundle" => set_b(&mut self.bundle),
            "ui_wipe_free_after" => set_b(&mut self.wipe_free_after),
            "ui_include_streams" => set_b(&mut self.include_streams),
            "ui_full_rekey" => set_b(&mut self.full_rekey),
            "ui_enc_passes" => set_passes(&mut self.enc_passes),
            "ui_disk_trim_after_wipe" => set_b(&mut self.disk_trim_after_wipe),
            "ui_mgr_passes" => set_passes(&mut self.mgr_passes),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MON: RectPx = RectPx { x: 0, y: 0, w: 1920, h: 1040 };
    const RIGHT: RectPx = RectPx { x: 1920, y: -200, w: 2560, h: 1400 };

    #[test]
    fn normal_position_comes_back() {
        let p = WinPos { x: 300, y: 120 };
        assert_eq!(restore_position(Some(p), 1040, 700, 31, &[MON]), Some(p));
        // second monitor, negative y (left of / above the primary one)
        let p = WinPos { x: 2500, y: -150 };
        assert_eq!(restore_position(Some(p), 1040, 700, 31, &[MON, RIGHT]), Some(p));
    }

    #[test]
    fn off_screen_positions_are_corrected_or_dropped() {
        // monitor unplugged: nothing of the window is visible -> default position
        assert_eq!(restore_position(Some(WinPos { x: 2500, y: 100 }), 1040, 700, 31, &[MON]), None);
        // mostly off the right edge, title bar still partly visible -> moved inside
        assert_eq!(restore_position(Some(WinPos { x: 1800, y: 100 }), 1040, 700, 31, &[MON]), Some(WinPos { x: 880, y: 100 }));
        // title bar above the top edge (the window could not be dragged) -> None, not visible
        assert_eq!(restore_position(Some(WinPos { x: 100, y: -500 }), 1040, 700, 31, &[MON]), None);
        // bottom part off screen -> moved up so it fits
        assert_eq!(restore_position(Some(WinPos { x: 100, y: 900 }), 1040, 700, 31, &[MON]), Some(WinPos { x: 100, y: 340 }));
        // window larger than the monitor -> top-left of the work area
        assert_eq!(restore_position(Some(WinPos { x: 10, y: 10 }), 3000, 2000, 31, &[MON]), Some(WinPos { x: 0, y: 0 }));
        // no monitor known (e.g. Wayland) -> default
        assert_eq!(restore_position(Some(WinPos { x: 10, y: 10 }), 1040, 700, 31, &[]), None);
    }

    #[test]
    fn minimized_coordinates_are_never_used() {
        assert!(!WinPos { x: -32000, y: -32000 }.sane());
        assert_eq!(WinPos::parse("-32000,-32000"), None);
        assert_eq!(restore_position(Some(WinPos { x: -32000, y: -32000 }), 1040, 700, 31, &[MON]), None);
        assert_eq!(WinPos::parse(" 12 , -40 "), Some(WinPos { x: 12, y: -40 }));
        assert_eq!(WinPos::parse("12"), None);
        assert_eq!(WinPos::parse("a,b"), None);
    }

    #[test]
    fn rows_round_trip_and_bad_values_are_reported() {
        let mut p = UiPrefs { win_enc: Some(WinPos { x: -5, y: 7 }), choose_dest: true, enc_passes: Some(Passes::Three), disk_trim_after_wipe: false, ..Default::default() };
        p.remember_window_pos = false;
        let mut q = UiPrefs::default();
        for (k, v) in p.rows() {
            assert!(q.parse_line(k, &v), "{k} = {v}");
        }
        assert_eq!(p, q);
        assert!(!q.parse_line("ui_choose_dest", "maybe"));
        assert!(!q.parse_line("ui_win_enc", "\"-32000,-32000\""));
        assert!(!q.parse_line("ui_enc_passes", "5"));
        assert!(!q.parse_line("ui_unknown", "true"));
        assert_eq!(p, q, "bad values change nothing");
    }

    #[test]
    fn remembered_passes_never_go_below_the_protected_default() {
        assert_eq!(passes_floor(Some(Passes::Three), Passes::Seven), Passes::Seven);
        assert_eq!(passes_floor(Some(Passes::Seven), Passes::Three), Passes::Seven);
        assert_eq!(passes_floor(Some(Passes::Three), Passes::Three), Passes::Three);
        assert_eq!(passes_floor(None, Passes::Three), Passes::Three);
    }
}
