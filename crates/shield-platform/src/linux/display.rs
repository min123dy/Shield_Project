//! Display facts for window placement and the display scale (3.0.0 §2).
//!
//! Why the Linux window used to be bigger than the Windows one: the window size is given in
//! logical points (the same 1040 x 700 on both systems) and multiplied by the display scale.
//! Windows uses the scale the user chose. On X11 winit takes `Xft.dpi` when the desktop sets it,
//! but without it winit *guesses* the scale from the monitor's physical size in millimetres
//! (e.g. a 14" 1920 x 1080 panel gives 1.67). Everything was then drawn 67 % larger, and the
//! window manager cut the oversized window down to the screen, so the content no longer fitted.
//! `prepare_scale` makes X11 follow the configured scale like Windows does (Xft.dpi, else
//! GDK_SCALE x GDK_DPI_SCALE, else 1); it never guesses from the monitor size. An invalid
//! `WINIT_X11_SCALE_FACTOR` (which makes winit panic) is removed.
//!
//! Wayland: the compositor chooses the scale (configured by the user, used as is), and a client
//! can neither read nor set its window's position, so remembering the position is unavailable.
//! The monitor list and Xft.dpi need the `display` feature (X11 client, GUI builds only).

use crate::Monitor;

fn env(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.is_empty())
}

/// A Wayland session: winit connects to Wayland when WAYLAND_DISPLAY is set.
pub fn is_wayland() -> bool {
    env("WAYLAND_DISPLAY").is_some()
}

/// Remembering the window position needs X11 (Wayland clients can't position windows).
pub fn position_supported() -> Result<(), &'static str> {
    if is_wayland() {
        Err("Wayland")
    } else if env("DISPLAY").is_none() {
        Err("no display")
    } else {
        Ok(())
    }
}

#[cfg(feature = "display")]
fn connect() -> Option<(x11rb::rust_connection::RustConnection, usize)> {
    x11rb::connect(None).ok()
}

/// `Xft.dpi` from the X resource database (the same lookup winit does).
#[cfg(feature = "display")]
fn xft_dpi() -> Option<f64> {
    let (conn, _) = connect()?;
    let db = x11rb::resource_manager::new_from_default(&conn).ok()?;
    db.get_string("Xft.dpi", "")?.trim().parse::<f64>().ok()
}

#[cfg(not(feature = "display"))]
fn xft_dpi() -> Option<f64> {
    None
}

/// Sets up `WINIT_X11_SCALE_FACTOR` before the window exists (see the module docs). Must run
/// before any other thread starts. Returns what was done (for the information tab), if anything.
pub fn prepare_scale() -> Option<String> {
    if is_wayland() || env("DISPLAY").is_none() {
        return None;
    }
    let cur = env("WINIT_X11_SCALE_FACTOR");
    let xft = if cur.is_none() || !crate::x11_scale_valid(cur.as_deref().unwrap_or("")) { xft_dpi() } else { None };
    let want = crate::x11_scale_choice(cur.as_deref(), xft, env("GDK_SCALE").as_deref(), env("GDK_DPI_SCALE").as_deref());
    if want == cur {
        return None;
    }
    // edition 2021: set_var is safe; it runs before eframe, the entropy thread and any other thread
    match &want {
        Some(v) => std::env::set_var("WINIT_X11_SCALE_FACTOR", v),
        None => std::env::remove_var("WINIT_X11_SCALE_FACTOR"),
    }
    Some(format!("WINIT_X11_SCALE_FACTOR={}", want.unwrap_or_default()))
}

/// The scale X11 windows use now (after `prepare_scale`).
#[cfg(feature = "display")]
fn x11_scale() -> f32 {
    match env("WINIT_X11_SCALE_FACTOR").and_then(|v| v.parse::<f32>().ok()) {
        Some(s) if s.is_finite() && s > 0.0 => s,
        _ => xft_dpi().map(|d| (d / 96.0) as f32).filter(|s| s.is_finite() && *s > 0.0).unwrap_or(1.0),
    }
}

/// Monitors (RandR 1.5) in physical pixels. None on Wayland or without the X11 client.
#[cfg(feature = "display")]
pub fn monitors() -> Option<Vec<Monitor>> {
    use x11rb::connection::Connection as _;
    use x11rb::protocol::randr::ConnectionExt as _;
    position_supported().ok()?;
    let (conn, screen) = connect()?;
    let root = conn.setup().roots.get(screen)?.root;
    let r = conn.randr_get_monitors(root, true).ok()?.reply().ok()?;
    let scale = x11_scale();
    let v: Vec<Monitor> = r
        .monitors
        .iter()
        .map(|m| Monitor { x: m.x as i32, y: m.y as i32, w: m.width as i32, h: m.height as i32, scale, primary: m.primary })
        .filter(|m| m.w > 0 && m.h > 0)
        .collect();
    (!v.is_empty()).then_some(v)
}

#[cfg(not(feature = "display"))]
pub fn monitors() -> Option<Vec<Monitor>> {
    None
}
