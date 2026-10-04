// SPDX-License-Identifier: GPL-2.0
//! NCC-based frame matcher for the SIL6250 64×80 sensor.

use crate::engine::IMG_SIZE;

pub const PM_W: usize = 64;
pub const PM_H: usize = 80;
pub const PM_N: usize = PM_W * PM_H; // 5120

/// Destriped, locally-normalized frame ready for matching.
pub struct Frame {
    pub px: [f32; PM_N],
}

impl Frame {
    /// Destripe and locally normalize a raw 8-bit frame.
    pub fn from_raw(raw: &[u8; IMG_SIZE]) -> Self {
        let mut tmp = [0f32; PM_N];
        let mut ds = [0f32; PM_N];

        // Per-column mean subtraction (removes vertical-coherent fixed-pattern noise).
        for x in 0..PM_W {
            let sum: f64 = (0..PM_H).map(|y| raw[y * PM_W + x] as f64).sum();
            let cmean = (sum / PM_H as f64) as f32;
            for y in 0..PM_H {
                tmp[y * PM_W + x] = raw[y * PM_W + x] as f32 - cmean;
            }
        }

        // Per-row mean subtraction.
        for y in 0..PM_H {
            let sum: f64 = (0..PM_W).map(|x| tmp[y * PM_W + x] as f64).sum();
            let rmean = (sum / PM_W as f64) as f32;
            for x in 0..PM_W {
                ds[y * PM_W + x] = tmp[y * PM_W + x] - rmean;
            }
        }

        let mut px = [0f32; PM_N];
        local_normalize(&ds, &mut px);
        Frame { px }
    }
}

// ---- local contrast normalization (sigma=6 bandpass) -----------------------

const LN_R: usize = 6;

fn box_blur(inp: &[f32; PM_N], out: &mut [f32; PM_N], r: usize) {
    let inv = 1.0f32 / (2 * r + 1) as f32;
    let mut tmp = [0f32; PM_N];

    // Along y (axis 0).
    for x in 0..PM_W {
        for y in 0..PM_H {
            let mut s = 0.0f64;
            let k_start = if y >= r { 0 } else { r - y };
            let k_end = if y + r < PM_H { 2 * r } else { PM_H - 1 + r - y };
            for k in k_start..=k_end {
                let yy = y + k - r;
                s += inp[yy * PM_W + x] as f64;
            }
            tmp[y * PM_W + x] = (s * inv as f64) as f32;
        }
    }

    // Along x (axis 1).
    for y in 0..PM_H {
        for x in 0..PM_W {
            let mut s = 0.0f64;
            let k_start = if x >= r { 0 } else { r - x };
            let k_end = if x + r < PM_W { 2 * r } else { PM_W - 1 + r - x };
            for k in k_start..=k_end {
                let xx = x + k - r;
                s += tmp[y * PM_W + xx] as f64;
            }
            out[y * PM_W + x] = (s * inv as f64) as f32;
        }
    }
}

fn local_normalize(inp: &[f32; PM_N], out: &mut [f32; PM_N]) {
    let mut mean = [0f32; PM_N];
    let mut cen = [0f32; PM_N];
    let mut sq = [0f32; PM_N];
    let mut var = [0f32; PM_N];

    box_blur(inp, &mut mean, LN_R);
    for i in 0..PM_N {
        cen[i] = inp[i] - mean[i];
        sq[i] = cen[i] * cen[i];
    }
    box_blur(&sq, &mut var, LN_R);
    for i in 0..PM_N {
        let sd = if var[i] > 1e-6 { var[i].sqrt() } else { 1e-3 };
        out[i] = cen[i] / sd;
    }
}

// ---- NCC matching ----------------------------------------------------------

fn ncc_at_shift(probe: &Frame, reference: &Frame, dx: i32, dy: i32, min_overlap: i32) -> f32 {
    let x0 = if dx < 0 { (-dx) as usize } else { 0 };
    let x1 = if dx > 0 { PM_W - dx as usize } else { PM_W };
    let y0 = if dy < 0 { (-dy) as usize } else { 0 };
    let y1 = if dy > 0 { PM_H - dy as usize } else { PM_H };

    if x1 <= x0 || y1 <= y0 {
        return -1.0;
    }
    let count = ((x1 - x0) * (y1 - y0)) as i32;
    if count < min_overlap {
        return -1.0;
    }

    let mut sa = 0.0f64;
    let mut sb = 0.0f64;
    for y in y0..y1 {
        for x in x0..x1 {
            sa += probe.px[y * PM_W + x] as f64;
            sb += reference.px[((y as i32 + dy) as usize) * PM_W
                + (x as i32 + dx) as usize] as f64;
        }
    }
    let ma = sa / count as f64;
    let mb = sb / count as f64;

    let mut num = 0.0f64;
    let mut da = 0.0f64;
    let mut db = 0.0f64;
    for y in y0..y1 {
        for x in x0..x1 {
            let a = probe.px[y * PM_W + x] as f64 - ma;
            let b = reference.px[((y as i32 + dy) as usize) * PM_W
                + (x as i32 + dx) as usize] as f64
                - mb;
            num += a * b;
            da += a * a;
            db += b * b;
        }
    }
    let denom = (da * db).sqrt();
    if denom < 1e-9 { 0.0 } else { (num / denom) as f32 }
}

/// Best-shift NCC of `probe` against `reference`.
///
/// Searches integer shifts in `[-max_dx, max_dx] × [-max_dy, max_dy]`.
/// Overlaps smaller than `min_overlap` pixels are skipped.
pub fn best_shift_ncc(
    probe: &Frame,
    reference: &Frame,
    max_dx: i32,
    max_dy: i32,
    min_overlap: i32,
    best_dx: Option<&mut i32>,
    best_dy: Option<&mut i32>,
) -> f32 {
    if max_dx < 0 || max_dy < 0 {
        return -1.0;
    }
    let max_dx = max_dx.min(PM_W as i32 - 1);
    let max_dy = max_dy.min(PM_H as i32 - 1);
    let mut best = -1.0f32;
    let mut bdx = 0i32;
    let mut bdy = 0i32;

    for dy in -max_dy..=max_dy {
        for dx in -max_dx..=max_dx {
            let s = ncc_at_shift(probe, reference, dx, dy, min_overlap);
            if s > best {
                best = s;
                bdx = dx;
                bdy = dy;
            }
        }
    }
    if let Some(p) = best_dx {
        *p = bdx;
    }
    if let Some(p) = best_dy {
        *p = bdy;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extreme_shift_bounds_do_not_panic() {
        let frame = Frame { px: [0.0; PM_N] };

        assert_eq!(
            best_shift_ncc(&frame, &frame, i32::MAX, i32::MAX, PM_N as i32 + 1, None, None),
            -1.0
        );
        assert_eq!(best_shift_ncc(&frame, &frame, -1, 1, 1, None, None), -1.0);
        assert_eq!(best_shift_ncc(&frame, &frame, i32::MIN, 1, 1, None, None), -1.0);
    }
}
