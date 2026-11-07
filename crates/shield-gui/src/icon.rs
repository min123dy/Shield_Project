//! Procedurally drawn application icon (shield with a keyhole).
//! Shared by build.rs (embedded .ico resource for the exe / taskbar / installer) and the window icon,
//! so the project does not need a binary icon file.

/// Straight (non-premultiplied) RGBA pixels, row-major, top row first.
pub fn shield_rgba(size: u32) -> Vec<u8> {
    const SS: u32 = 4; // supersampling per axis
    let n = size as f32;
    let mut out = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let (mut a, mut r, mut g, mut b) = (0.0f32, 0.0f32, 0.0f32, 0.0f32);
            for sy in 0..SS {
                for sx in 0..SS {
                    let u = (x as f32 + (sx as f32 + 0.5) / SS as f32) / n;
                    let v = (y as f32 + (sy as f32 + 0.5) / SS as f32) / n;
                    if let Some(c) = sample(u, v) {
                        a += 1.0;
                        r += c[0];
                        g += c[1];
                        b += c[2];
                    }
                }
            }
            if a > 0.0 {
                let i = ((y * size + x) * 4) as usize;
                out[i] = (r / a) as u8;
                out[i + 1] = (g / a) as u8;
                out[i + 2] = (b / a) as u8;
                out[i + 3] = (a / (SS * SS) as f32 * 255.0) as u8;
            }
        }
    }
    out
}

/// Half width of the shield at height v (0 = top, 1 = bottom), None outside.
fn half_width(v: f32) -> Option<f32> {
    const TOP: f32 = 0.08;
    const BEND: f32 = 0.52;
    const TIP: f32 = 0.94;
    const W: f32 = 0.38;
    if !(TOP..=TIP).contains(&v) {
        return None;
    }
    if v <= BEND {
        return Some(W);
    }
    let t = (v - BEND) / (TIP - BEND);
    Some(W * (1.0 - t * t).sqrt() * (1.0 - 0.35 * t))
}

fn inside(u: f32, v: f32, inset: f32) -> bool {
    let dx = (u - 0.5).abs();
    match half_width(v) {
        Some(w) => {
            // top edge dips slightly toward the middle
            let top = 0.13 + inset - 0.05 * (dx / 0.38).powi(2);
            dx <= w - inset && v >= top && half_width(v + inset).is_some()
        }
        None => false,
    }
}

fn keyhole(u: f32, v: f32) -> bool {
    let (cx, cy, r) = (0.5, 0.42, 0.095);
    let d2 = (u - cx).powi(2) + (v - cy).powi(2);
    if d2 <= r * r {
        return true;
    }
    if (0.44..=0.70).contains(&v) {
        let t = (v - 0.44) / 0.26;
        return (u - cx).abs() <= 0.045 + 0.04 * t;
    }
    false
}

fn sample(u: f32, v: f32) -> Option<[f32; 3]> {
    if !inside(u, v, 0.0) {
        return None;
    }
    if !inside(u, v, 0.045) {
        return Some([214.0, 226.0, 245.0]); // rim
    }
    if keyhole(u, v) {
        return Some([250.0, 250.0, 252.0]);
    }
    // vertical gradient, slightly lighter on the left half
    let t = v.clamp(0.0, 1.0);
    let lift = if u < 0.5 { 14.0 } else { 0.0 };
    Some([30.0 + 10.0 * (1.0 - t) + lift, 82.0 + 40.0 * (1.0 - t) + lift, 170.0 + 50.0 * (1.0 - t) + lift])
}

/// Multi-size .ico (32-bit BMP entries) for the Windows resource compiler.
#[allow(dead_code)]
pub fn ico_bytes(sizes: &[u32]) -> Vec<u8> {
    let mut images: Vec<Vec<u8>> = Vec::new();
    for &s in sizes {
        let rgba = shield_rgba(s);
        let mask_row = (s.div_ceil(32) * 4) as usize;
        let mut img = Vec::new();
        img.extend_from_slice(&40u32.to_le_bytes());
        img.extend_from_slice(&(s as i32).to_le_bytes());
        img.extend_from_slice(&((s * 2) as i32).to_le_bytes()); // XOR + AND mask
        img.extend_from_slice(&1u16.to_le_bytes());
        img.extend_from_slice(&32u16.to_le_bytes());
        img.extend_from_slice(&[0u8; 24]); // BI_RGB, sizes, resolution, palette
        for y in (0..s).rev() {
            for x in 0..s {
                let i = ((y * s + x) * 4) as usize;
                img.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
            }
        }
        img.extend(std::iter::repeat_n(0u8, mask_row * s as usize));
        images.push(img);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (&s, img) in sizes.iter().zip(&images) {
        let b = if s >= 256 { 0 } else { s as u8 };
        out.extend_from_slice(&[b, b, 0, 0]);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&(img.len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += img.len() as u32;
    }
    for img in images {
        out.extend_from_slice(&img);
    }
    out
}
