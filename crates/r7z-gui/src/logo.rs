// The r7z mark: a graphite tile with an orange zipper. Free of crate dependencies so
// `build.rs` can include this file to render the executable's icon.

/// Signed distance from (x, y) to a rounded rectangle; negative inside.
fn rounded_rect_sd(x: f32, y: f32, x0: f32, y0: f32, x1: f32, y1: f32, rad: f32) -> f32 {
    let cx = (x0 + x1) / 2.0;
    let cy = (y0 + y1) / 2.0;
    let hx = (x1 - x0) / 2.0 - rad;
    let hy = (y1 - y0) / 2.0 - rad;
    let dx = (x - cx).abs() - hx;
    let dy = (y - cy).abs() - hy;
    let ox = dx.max(0.0);
    let oy = dy.max(0.0);
    (ox * ox + oy * oy).sqrt() + dx.max(dy).min(0.0) - rad
}

/// Zipper teeth and pull tab as rectangles in unit coordinates (x0, y0, x1, y1).
pub fn mark_shapes() -> Vec<[f32; 4]> {
    let mut v = Vec::new();
    for k in 0..5 {
        let y = 0.2 + k as f32 * 0.105;
        if k % 2 == 0 {
            v.push([0.36, y, 0.52, y + 0.07]);
        } else {
            v.push([0.48, y, 0.64, y + 0.07]);
        }
    }
    v.push([0.39, 0.74, 0.61, 0.84]);
    v
}

pub const TILE: [u8; 3] = [0x1B, 0x1C, 0x21];
pub const ACCENT: [u8; 3] = [0xFF, 0x6B, 0x2C];

/// RGBA pixels of the mark, `size` x `size`.
pub fn logo_rgba(size: u32) -> Vec<u8> {
    let s = size as f32;
    let shapes = mark_shapes();
    let mut px = vec![0u8; (size * size * 4) as usize];
    for yi in 0..size {
        for xi in 0..size {
            let (x, y) = (xi as f32 + 0.5, yi as f32 + 0.5);
            let tile = (0.5 - rounded_rect_sd(x, y, 0.0, 0.0, s, s, s * 0.23)).clamp(0.0, 1.0);
            let mut mark: f32 = 0.0;
            for r in &shapes {
                let d = rounded_rect_sd(x, y, r[0] * s, r[1] * s, r[2] * s, r[3] * s, s * 0.018);
                mark = mark.max((0.5 - d).clamp(0.0, 1.0));
            }
            let i = ((yi * size + xi) * 4) as usize;
            for c in 0..3 {
                px[i + c] = (TILE[c] as f32 * (1.0 - mark) + ACCENT[c] as f32 * mark) as u8;
            }
            px[i + 3] = (tile * 255.0) as u8;
        }
    }
    px
}
