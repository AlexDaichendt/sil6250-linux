// SPDX-License-Identifier: GPL-2.0
//! SIFT-based keypoint descriptor matcher for the SIL6250 64×80 sensor.
//!
//! Algorithm:
//!   1. Multi-scale Harris keypoint detection + NMS, top-200 by response.
//!   2. Per-keypoint dominant orientation (36-bin gradient histogram).
//!   3. SIFT-128 descriptor (4×4 spatial × 8 orientation, trilinear,
//!      unit-norm + 0.2-clamp + renorm).
//!   4. Nearest-neighbour + Lowe ratio test → tentative correspondences.
//!   5. Pairwise geometric consistency clique → inlier count (the score).
//!
//! Accept fingerprint match when `ps_verify` returns ≥ 5 inliers.

use std::f32::consts::PI;

use crate::matcher::{Frame, PM_H, PM_N, PM_W};

pub const MAX_KPTS: usize = 200;
pub const DESC_DIM: usize = 128;

#[derive(Clone, Copy)]
pub struct Keypoint {
    pub x: f32,
    pub y: f32,
    pub scale: f32,
    pub ori: f32,
    pub resp: f32,
    pub desc: [f32; DESC_DIM],
}

pub struct Features {
    pub kp: Vec<Keypoint>,
}

impl Features {
    fn new() -> Self {
        Features { kp: Vec::new() }
    }

    /// Serialize features to a compact binary representation.
    ///
    /// Format:
    ///   - magic: b"SILF" (4 bytes)
    ///   - version: 1 (1 byte)
    ///   - reserved: 3 zero bytes
    ///   - keypoint count as u32 LE (4 bytes)
    ///   - keypoint data: x, y, scale, ori, resp (5 x f32 LE) + desc (128 x f32 LE)
    pub fn serialize(&self) -> Vec<u8> {
        const KP_BYTES: usize = 5 * 4 + DESC_DIM * 4;
        let mut out = Vec::with_capacity(12 + self.kp.len() * KP_BYTES);
        out.extend_from_slice(b"SILF");
        out.push(1u8); // version
        out.extend_from_slice(&[0u8; 3]);
        out.extend_from_slice(&(self.kp.len() as u32).to_le_bytes());
        for kp in &self.kp {
            out.extend_from_slice(&kp.x.to_le_bytes());
            out.extend_from_slice(&kp.y.to_le_bytes());
            out.extend_from_slice(&kp.scale.to_le_bytes());
            out.extend_from_slice(&kp.ori.to_le_bytes());
            out.extend_from_slice(&kp.resp.to_le_bytes());
            for &d in &kp.desc {
                out.extend_from_slice(&d.to_le_bytes());
            }
        }
        out
    }

    /// Deserialize features from `bytes`. Returns `None` if the data is malformed
    /// or the format version is unsupported.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        const KP_BYTES: usize = 5 * 4 + DESC_DIM * 4;
        if bytes.len() < 12 {
            return None;
        }
        if &bytes[0..4] != b"SILF" {
            return None;
        }
        if bytes[4] != 1 {
            return None;
        }
        let n = u32::from_le_bytes(bytes[8..12].try_into().ok()?) as usize;
        if n > MAX_KPTS {
            return None;
        }
        if bytes.len() != 12 + n * KP_BYTES {
            return None;
        }

        let mut kp = Vec::with_capacity(n);
        let mut off = 12;
        for _ in 0..n {
            let x = f32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
            off += 4;
            let y = f32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
            off += 4;
            let scale = f32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
            off += 4;
            let ori = f32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
            off += 4;
            let resp = f32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
            off += 4;
            let mut desc = [0.0f32; DESC_DIM];
            for i in 0..DESC_DIM {
                desc[i] = f32::from_le_bytes(bytes[off..off + 4].try_into().ok()?);
                off += 4;
            }
            if !x.is_finite()
                || !y.is_finite()
                || !scale.is_finite()
                || !ori.is_finite()
                || !resp.is_finite()
                || !(0.0..PM_W as f32).contains(&x)
                || !(0.0..PM_H as f32).contains(&y)
                || scale <= 0.0
                || !(-std::f32::consts::TAU..=std::f32::consts::TAU).contains(&ori)
                || desc.iter().any(|v| !v.is_finite())
            {
                return None;
            }
            let ori = ori.rem_euclid(std::f32::consts::TAU);
            kp.push(Keypoint {
                x,
                y,
                scale,
                ori,
                resp,
                desc,
            });
        }
        Some(Features { kp })
    }
}

#[cfg(test)]
mod serialization_tests {
    use super::*;

    #[test]
    fn rejects_non_finite_feature_values() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SILF");
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&f32::NAN.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        bytes.extend_from_slice(&0.0f32.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; DESC_DIM * 4]);
        assert!(Features::deserialize(&bytes).is_none());
    }

    #[test]
    fn rejects_extreme_finite_orientation() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"SILF");
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        bytes.extend_from_slice(&1e30f32.to_le_bytes());
        bytes.extend_from_slice(&1.0f32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; DESC_DIM * 4]);
        assert!(Features::deserialize(&bytes).is_none());
    }

    #[test]
    fn wraps_extreme_finite_angles_without_looping() {
        let wrapped = ang_wrap(1e30);
        assert!((-PI..=PI).contains(&wrapped));
    }
}

// ---- Gaussian blur (zero-clamped border) -----------------------------------

fn gaussian_blur(inp: &[f32; PM_N], out: &mut [f32; PM_N], sigma: f32) {
    let r = (3.0f32 * sigma + 0.5) as usize;
    let r = r.max(1).min(31);
    let klen = 2 * r + 1;
    let mut k = [0f32; 64];
    let mut ksum = 0.0f32;
    for i in 0..klen {
        let x = (i as f32 - r as f32) / sigma;
        k[i] = (-0.5 * x * x).exp();
        ksum += k[i];
    }
    for i in 0..klen {
        k[i] /= ksum;
    }

    let mut tmp = [0f32; PM_N];
    // Horizontal pass.
    for y in 0..PM_H {
        for x in 0..PM_W {
            let mut s = 0.0f32;
            for i in 0..klen {
                let xi = (x as i32 + i as i32 - r as i32).clamp(0, PM_W as i32 - 1) as usize;
                s += k[i] * inp[y * PM_W + xi];
            }
            tmp[y * PM_W + x] = s;
        }
    }
    // Vertical pass.
    for y in 0..PM_H {
        for x in 0..PM_W {
            let mut s = 0.0f32;
            for i in 0..klen {
                let yi = (y as i32 + i as i32 - r as i32).clamp(0, PM_H as i32 - 1) as usize;
                s += k[i] * tmp[yi * PM_W + x];
            }
            out[y * PM_W + x] = s;
        }
    }
}

// ---- Gradient (central difference) -----------------------------------------

fn gradients(img: &[f32; PM_N], gx: &mut [f32; PM_N], gy: &mut [f32; PM_N]) {
    for y in 0..PM_H {
        for x in 0..PM_W {
            let xl = if x > 0 { x - 1 } else { x };
            let xr = if x < PM_W - 1 { x + 1 } else { x };
            let yu = if y > 0 { y - 1 } else { y };
            let yd = if y < PM_H - 1 { y + 1 } else { y };
            gx[y * PM_W + x] = 0.5 * (img[y * PM_W + xr] - img[y * PM_W + xl]);
            gy[y * PM_W + x] = 0.5 * (img[yd * PM_W + x] - img[yu * PM_W + x]);
        }
    }
}

// ---- Harris keypoint detection ---------------------------------------------

const HARRIS_K: f32 = 0.04;
const NMS_RADIUS: i32 = 1;
const EDGE: usize = 3;
const RESP_FRAC: f32 = 0.0006;

#[derive(Clone, Copy)]
struct Candidate {
    x: f32,
    y: f32,
    scale: f32,
    resp: f32,
}

fn detect_scale(
    img: &[f32; PM_N],
    sigma: f32,
    cand: &mut Vec<Candidate>,
    cap: usize,
) {
    let mut sm = [0f32; PM_N];
    let mut gx = [0f32; PM_N];
    let mut gy = [0f32; PM_N];
    let mut a = [0f32; PM_N];
    let mut b = [0f32; PM_N];
    let mut c = [0f32; PM_N];
    let mut resp = [0f32; PM_N];

    gaussian_blur(img, &mut sm, sigma);
    gradients(&sm, &mut gx, &mut gy);

    for i in 0..PM_N {
        a[i] = gx[i] * gx[i];
        b[i] = gx[i] * gy[i];
        c[i] = gy[i] * gy[i];
    }

    let mut ta = [0f32; PM_N];
    let mut tb = [0f32; PM_N];
    let mut tc = [0f32; PM_N];
    gaussian_blur(&a, &mut ta, 1.5 * sigma);
    gaussian_blur(&b, &mut tb, 1.5 * sigma);
    gaussian_blur(&c, &mut tc, 1.5 * sigma);

    let mut maxr = 0.0f32;
    for i in 0..PM_N {
        let det = ta[i] * tc[i] - tb[i] * tb[i];
        let tr = ta[i] + tc[i];
        resp[i] = det - HARRIS_K * tr * tr;
        if resp[i] > maxr {
            maxr = resp[i];
        }
    }
    if maxr <= 0.0 {
        return;
    }
    let thresh = RESP_FRAC * maxr;

    for y in EDGE..PM_H - EDGE {
        'next_x: for x in EDGE..PM_W - EDGE {
            let r = resp[y * PM_W + x];
            if r < thresh {
                continue;
            }
            // 3×3 non-maximum suppression.
            for dy in -1i32..=1 {
                for dx in -1i32..=1 {
                    if dx == 0 && dy == 0 {
                        continue;
                    }
                    if resp[((y as i32 + dy) as usize) * PM_W + (x as i32 + dx) as usize] > r {
                        continue 'next_x;
                    }
                }
            }
            if cand.len() < cap {
                cand.push(Candidate { x: x as f32, y: y as f32, scale: sigma, resp: r });
            }
        }
    }
}

fn spatial_nms(cand: &mut [Candidate], out: &mut [Candidate]) -> usize {
    // Sort descending by response.
    cand.sort_unstable_by(|a, b| b.resp.partial_cmp(&a.resp).unwrap_or(std::cmp::Ordering::Equal));
    let mut kept = 0usize;
    'next: for i in 0..cand.len() {
        if kept >= out.len() {
            break;
        }
        let ci = cand[i];
        for j in 0..kept {
            let dx = ci.x - out[j].x;
            let dy = ci.y - out[j].y;
            if dx * dx + dy * dy < (NMS_RADIUS * NMS_RADIUS) as f32 {
                continue 'next;
            }
        }
        out[kept] = ci;
        kept += 1;
    }
    kept
}

// ---- Dominant orientation --------------------------------------------------

const ORI_BINS: usize = 36;

fn dominant_orientation(gx: &[f32; PM_N], gy: &[f32; PM_N], cx: f32, cy: f32, scale: f32) -> f32 {
    let mut hist = [0f32; ORI_BINS];
    let radius = (4.0 * scale + 0.5) as i32;
    let sig = 1.5 * scale;
    let expden = 2.0 * sig * sig;
    let xi = (cx + 0.5) as i32;
    let yi = (cy + 0.5) as i32;

    for dy in -radius..=radius {
        for dx in -radius..=radius {
            let x = xi + dx;
            let y = yi + dy;
            if x < 0 || x >= PM_W as i32 || y < 0 || y >= PM_H as i32 {
                continue;
            }
            let idx = y as usize * PM_W + x as usize;
            let gxv = gx[idx];
            let gyv = gy[idx];
            let mag = (gxv * gxv + gyv * gyv).sqrt();
            let w = (-(dx * dx + dy * dy) as f32 / expden).exp();
            let mut ang = gyv.atan2(gxv);
            if ang < 0.0 {
                ang += 2.0 * PI;
            }
            let bin = ((ang / (2.0 * PI) * ORI_BINS as f32) as usize).min(ORI_BINS - 1);
            hist[bin] += w * mag;
        }
    }

    // Smooth once (circular 3-tap).
    let mut sm = [0f32; ORI_BINS];
    for i in 0..ORI_BINS {
        let l = (i + ORI_BINS - 1) % ORI_BINS;
        let r = (i + 1) % ORI_BINS;
        sm[i] = 0.25 * hist[l] + 0.5 * hist[i] + 0.25 * hist[r];
    }

    let peak = sm
        .iter()
        .enumerate()
        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, _)| i)
        .unwrap_or(0);

    let l = (peak + ORI_BINS - 1) % ORI_BINS;
    let r = (peak + 1) % ORI_BINS;
    let denom = sm[l] - 2.0 * sm[peak] + sm[r];
    let off = if denom != 0.0 { 0.5 * (sm[l] - sm[r]) / denom } else { 0.0 };
    (peak as f32 + off) / ORI_BINS as f32 * 2.0 * PI
}

// ---- SIFT-128 descriptor ---------------------------------------------------

const PS_D: usize = 4; // spatial cells per axis
const PS_OBINS: usize = 8;
const PS_MAGFAC: f32 = 3.0;

fn compute_descriptor(gx: &[f32; PM_N], gy: &[f32; PM_N], kp: &mut Keypoint) {
    let mut hist = [[[0f32; PS_OBINS]; PS_D]; PS_D];

    let cell = PS_MAGFAC * kp.scale;
    let ct = kp.ori.cos();
    let st = kp.ori.sin();
    let radius = (cell * (PS_D as f32 + 1.0) * 0.5 * std::f32::consts::SQRT_2 + 0.5) as i32;
    let xi = (kp.x + 0.5) as i32;
    let yi = (kp.y + 0.5) as i32;
    let expden = 2.0 * (0.5 * PS_D as f32).powi(2);

    for dy in -radius..=radius {
        for dx in -radius..=radius {
            let x = xi + dx;
            let y = yi + dy;
            if x < 0 || x >= PM_W as i32 || y < 0 || y >= PM_H as i32 {
                continue;
            }
            let idx = y as usize * PM_W + x as usize;
            let rx = (ct * dx as f32 + st * dy as f32) / cell;
            let ry = (-st * dx as f32 + ct * dy as f32) / cell;
            let cbx = rx + PS_D as f32 * 0.5 - 0.5;
            let cby = ry + PS_D as f32 * 0.5 - 0.5;
            if cbx <= -1.0 || cbx >= PS_D as f32 || cby <= -1.0 || cby >= PS_D as f32 {
                continue;
            }

            let gxv = gx[idx];
            let gyv = gy[idx];
            let mag = (gxv * gxv + gyv * gyv).sqrt();
            let w = (-(rx * rx + ry * ry) / expden).exp();
            let mut ang = gyv.atan2(gxv) - kp.ori;
            while ang < 0.0 {
                ang += 2.0 * PI;
            }
            while ang >= 2.0 * PI {
                ang -= 2.0 * PI;
            }
            let obin = ang / (2.0 * PI) * PS_OBINS as f32;
            let wmag = w * mag;

            let x0 = cbx.floor() as i32;
            let y0 = cby.floor() as i32;
            let o0 = obin.floor() as i32;
            let fx = cbx - x0 as f32;
            let fy = cby - y0 as f32;
            let fo = obin - o0 as f32;

            for iy in 0..=1i32 {
                let yy = y0 + iy;
                if yy < 0 || yy >= PS_D as i32 {
                    continue;
                }
                let wy = if iy == 1 { fy } else { 1.0 - fy };
                for ix in 0..=1i32 {
                    let xx = x0 + ix;
                    if xx < 0 || xx >= PS_D as i32 {
                        continue;
                    }
                    let wx = if ix == 1 { fx } else { 1.0 - fx };
                    for io in 0..=1i32 {
                        let oo = ((o0 + io).rem_euclid(PS_OBINS as i32)) as usize;
                        let wo = if io == 1 { fo } else { 1.0 - fo };
                        hist[yy as usize][xx as usize][oo] += wmag * wy * wx * wo;
                    }
                }
            }
        }
    }

    // Flatten.
    let mut idx = 0;
    for iy in 0..PS_D {
        for ix in 0..PS_D {
            for io in 0..PS_OBINS {
                kp.desc[idx] = hist[iy][ix][io];
                idx += 1;
            }
        }
    }

    // SIFT normalization: unit-norm → clamp 0.2 → renorm.
    let norm = kp.desc.iter().map(|&v| v * v).sum::<f32>().sqrt().max(1e-9);
    for v in &mut kp.desc {
        *v = (*v / norm).min(0.2);
    }
    let norm2 = kp.desc.iter().map(|&v| v * v).sum::<f32>().sqrt().max(1e-9);
    for v in &mut kp.desc {
        *v /= norm2;
    }
}

// ---- Capture quality -------------------------------------------------------

const Q_BS: usize = 8;
const Q_ENERGY: f32 = 6.0;

/// Orientation-tensor coherence quality score in [0, 1].
///
/// High when the frame carries clear ridge flow; low for weak/dry presses.
/// Reject frames below ~0.52 and request a re-scan.
pub fn quality(f: &Frame) -> f32 {
    let nbx = PM_W / Q_BS;
    let nby = PM_H / Q_BS;
    let mut covered = 0usize;
    let mut cohsum = 0.0f64;

    for by in 0..nby {
        for bx in 0..nbx {
            let mut gxx = 0.0f64;
            let mut gyy = 0.0f64;
            let mut gxy = 0.0f64;
            let mut energy = 0.0f64;

            for yy in 1..Q_BS - 1 {
                for xx in 1..Q_BS - 1 {
                    let x = bx * Q_BS + xx;
                    let y = by * Q_BS + yy;
                    let gx = (f.px[y * PM_W + x + 1] - f.px[y * PM_W + x - 1]) as f64;
                    let gy = (f.px[(y + 1) * PM_W + x] - f.px[(y - 1) * PM_W + x]) as f64;
                    gxx += gx * gx;
                    gyy += gy * gy;
                    gxy += gx * gy;
                    energy += gx * gx + gy * gy;
                }
            }
            let tr = gxx + gyy;
            if energy <= Q_ENERGY as f64 || tr <= 1e-6 {
                continue;
            }
            let coher = ((gxx - gyy).powi(2) + 4.0 * gxy * gxy).sqrt() / tr;
            covered += 1;
            cohsum += coher;
        }
    }
    if covered == 0 { 0.0 } else { (cohsum / covered as f64) as f32 }
}

// ---- Feature extraction ----------------------------------------------------

/// Extract keypoints and SIFT-128 descriptors from a destriped frame.
pub fn extract(f: &Frame) -> Features {
    const CAND_CAP: usize = MAX_KPTS * 8;
    let mut cand = Vec::with_capacity(CAND_CAP);
    for sigma in [1.2f32, 1.6, 2.2, 3.0] {
        detect_scale(&f.px, sigma, &mut cand, CAND_CAP);
    }

    let mut kept = [Candidate { x: 0.0, y: 0.0, scale: 0.0, resp: 0.0 }; MAX_KPTS];
    let nk = spatial_nms(&mut cand, &mut kept);

    let mut sm = [0f32; PM_N];
    let mut gx = [0f32; PM_N];
    let mut gy = [0f32; PM_N];
    gaussian_blur(&f.px, &mut sm, 1.0);
    gradients(&sm, &mut gx, &mut gy);

    let mut out = Features::new();
    for i in 0..nk {
        let mut kp = Keypoint {
            x: kept[i].x,
            y: kept[i].y,
            scale: kept[i].scale,
            resp: kept[i].resp,
            ori: 0.0,
            desc: [0.0; DESC_DIM],
        };
        kp.ori = dominant_orientation(&gx, &gy, kp.x, kp.y, kp.scale);
        compute_descriptor(&gx, &gy, &mut kp);
        out.kp.push(kp);
    }
    out
}

// ---- Matching --------------------------------------------------------------

const PS_RATIO: f32 = 0.92;
const PS_DIST_TOL_A: f32 = 0.15;
const PS_DIST_TOL_B: f32 = 2.5;
const PS_ORI_TOL: f32 = 0.45;
const PS_MIN_SEP: f32 = 3.0;

fn desc_dist2(a: &[f32; DESC_DIM], b: &[f32; DESC_DIM]) -> f32 {
    a.iter().zip(b.iter()).map(|(&ai, &bi)| (ai - bi) * (ai - bi)).sum()
}

fn ang_wrap(a: f32) -> f32 {
    (a + PI).rem_euclid(std::f32::consts::TAU) - PI
}

#[derive(Clone, Copy)]
struct Corr {
    px: f32,
    py: f32,
    rx: f32,
    ry: f32,
    dori: f32,
}

/// Geometric inlier count of `probe` vs `reference`.
pub fn match_features(probe: &Features, reference: &Features) -> i32 {
    if probe.kp.is_empty() || reference.kp.is_empty() {
        return 0;
    }
    let pn = probe.kp.len();
    let rn = reference.kp.len();

    // Mutual nearest-neighbour cross-check indices for reference keypoints.
    let mut ref_nn = vec![0usize; rn];
    for j in 0..rn {
        let mut best = f32::MAX;
        let mut bi = 0usize;
        for i in 0..pn {
            let d = desc_dist2(&probe.kp[i].desc, &reference.kp[j].desc);
            if d < best {
                best = d;
                bi = i;
            }
        }
        ref_nn[j] = bi;
    }

    // Lowe ratio + mutual cross-check → tentative correspondences.
    let mut corr: Vec<Corr> = Vec::new();
    for i in 0..pn {
        let mut best = f32::MAX;
        let mut second = f32::MAX;
        let mut bj = 0usize;
        for j in 0..rn {
            let d = desc_dist2(&probe.kp[i].desc, &reference.kp[j].desc);
            if d < best {
                second = best;
                best = d;
                bj = j;
            } else if d < second {
                second = d;
            }
        }
        if ref_nn[bj] != i {
            continue;
        }
        if best < PS_RATIO * PS_RATIO * second {
            corr.push(Corr {
                px: probe.kp[i].x,
                py: probe.kp[i].y,
                rx: reference.kp[bj].x,
                ry: reference.kp[bj].y,
                dori: reference.kp[bj].ori - probe.kp[i].ori,
            });
        }
    }
    let m = corr.len();
    if m == 0 {
        return 0;
    }

    // Pairwise compatibility: distance preservation + consistent rotation.
    let mut comp = vec![vec![false; m]; m];
    let mut deg = vec![0i32; m];
    for i in 0..m {
        for j in i + 1..m {
            let pdx = corr[i].px - corr[j].px;
            let pdy = corr[i].py - corr[j].py;
            let rdx = corr[i].rx - corr[j].rx;
            let rdy = corr[i].ry - corr[j].ry;
            let dp = (pdx * pdx + pdy * pdy).sqrt();
            let dr = (rdx * rdx + rdy * rdy).sqrt();
            if dp >= PS_MIN_SEP && dr >= PS_MIN_SEP {
                let tol = PS_DIST_TOL_A * dp.max(dr) + PS_DIST_TOL_B;
                if (dp - dr).abs() <= tol
                    && ang_wrap(corr[i].dori - corr[j].dori).abs() <= PS_ORI_TOL
                {
                    comp[i][j] = true;
                    comp[j][i] = true;
                    deg[i] += 1;
                    deg[j] += 1;
                }
            }
        }
    }

    // Greedy max-clique from each seed node.
    let mut clique: Vec<usize> = Vec::with_capacity(m);
    let mut best_inliers = 0i32;
    for s in 0..m {
        if deg[s] + 1 <= best_inliers {
            continue;
        }
        clique.clear();
        clique.push(s);
        for _pass in 0..2 {
            for k in 0..m {
                if k == s {
                    continue;
                }
                let fits = clique.iter().all(|&t| comp[k][t]);
                if fits && !clique.contains(&k) {
                    clique.push(k);
                }
            }
        }
        if clique.len() as i32 > best_inliers {
            best_inliers = clique.len() as i32;
        }
    }
    best_inliers
}

/// Gallery verify: max inlier count of `probe` over all reference feature sets.
pub fn verify(probe: &Features, gallery: &[Features]) -> i32 {
    gallery.iter().map(|g| match_features(probe, g)).max().unwrap_or(0)
}
