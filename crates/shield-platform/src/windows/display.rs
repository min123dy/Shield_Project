//! Display facts for window placement (3.0.0 §2): the monitors' work areas and scale. Windows
//! always reports window positions, so remembering the window position is always available.

use crate::Monitor;
use windows_sys::Win32::Foundation::{BOOL, LPARAM, RECT};
use windows_sys::Win32::Graphics::Gdi::{EnumDisplayMonitors, GetMonitorInfoW, HDC, HMONITOR, MONITORINFO};
use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, MDT_EFFECTIVE_DPI};
use windows_sys::Win32::UI::WindowsAndMessaging::MONITORINFOF_PRIMARY;

/// Per-monitor DPI awareness (the same mode winit sets when its event loop starts; setting it
/// first makes the monitor list below use real pixels instead of 96-dpi virtualised ones). A
/// second call (by winit) fails harmlessly. The display scale is the one chosen in Windows.
pub fn prepare_scale() -> Option<String> {
    unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
    None
}

/// Window positions can always be read and set.
pub fn position_supported() -> Result<(), &'static str> {
    Ok(())
}

unsafe extern "system" fn add(h: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> BOOL {
    // SAFETY: `data` is the `&mut Vec<Monitor>` passed to EnumDisplayMonitors below, alive for the call
    let v = unsafe { &mut *(data as *mut Vec<Monitor>) };
    let mut mi: MONITORINFO = unsafe { std::mem::zeroed() };
    mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
    if unsafe { GetMonitorInfoW(h, &mut mi) } != 0 {
        let (mut dx, mut dy) = (96u32, 96u32);
        let scale = if unsafe { GetDpiForMonitor(h, MDT_EFFECTIVE_DPI, &mut dx, &mut dy) } == 0 { dx as f32 / 96.0 } else { 1.0 };
        let r = mi.rcWork;
        v.push(Monitor { x: r.left, y: r.top, w: r.right - r.left, h: r.bottom - r.top, scale, primary: mi.dwFlags & MONITORINFOF_PRIMARY != 0 });
    }
    1
}

/// Work areas (without the taskbar) of the connected monitors, in physical pixels.
pub fn monitors() -> Option<Vec<Monitor>> {
    let mut v: Vec<Monitor> = Vec::new();
    unsafe { EnumDisplayMonitors(0, std::ptr::null(), Some(add), &mut v as *mut Vec<Monitor> as LPARAM) };
    (!v.is_empty()).then_some(v)
}
