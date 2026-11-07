//! Build helper (not shipped): writes the application icon as PNG files for the Linux packages.
//!   cargo run -p shield-gui --example export_icon -- <dir>
//! creates <dir>/<n>x<n>/apps/shield.png for the hicolor theme. The PNG uses stored (uncompressed)
//! deflate blocks, so no image crate is needed.

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend((data.len() as u32).to_be_bytes());
    let mut c = kind.to_vec();
    c.extend_from_slice(data);
    out.extend_from_slice(&c);
    out.extend(crc32(&c).to_be_bytes());
}

fn png(size: u32) -> Vec<u8> {
    let rgba = shield_gui::icon::shield_rgba(size);
    let mut raw = Vec::with_capacity(rgba.len() + size as usize);
    for row in rgba.chunks(size as usize * 4) {
        raw.push(0); // filter: none
        raw.extend_from_slice(row);
    }
    // zlib stream with stored blocks
    let mut z = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = raw.chunks(65_535).collect();
    for (i, b) in blocks.iter().enumerate() {
        z.push(u8::from(i + 1 == blocks.len()));
        z.extend((b.len() as u16).to_le_bytes());
        z.extend((!(b.len() as u16)).to_le_bytes());
        z.extend_from_slice(b);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for &x in &raw {
        a = (a + x as u32) % 65_521;
        b = (b + a) % 65_521;
    }
    z.extend(((b << 16) | a).to_be_bytes());
    let mut out = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = size.to_be_bytes().to_vec();
    ihdr.extend(size.to_be_bytes());
    ihdr.extend([8, 6, 0, 0, 0]); // 8-bit RGBA
    chunk(&mut out, b"IHDR", &ihdr);
    chunk(&mut out, b"IDAT", &z);
    chunk(&mut out, b"IEND", &[]);
    out
}

fn main() {
    let dir = std::path::PathBuf::from(std::env::args().nth(1).expect("usage: export_icon <dir>"));
    for s in [16u32, 32, 48, 64, 128, 256] {
        let d = dir.join(format!("{s}x{s}")).join("apps");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("shield.png"), png(s)).unwrap();
    }
}
