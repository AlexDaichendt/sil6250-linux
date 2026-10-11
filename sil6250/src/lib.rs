// SPDX-License-Identifier: GPL-2.0
//! Driver library for the Silead SIL6250 fingerprint sensor.

pub mod engine;
pub mod matcher;
pub mod proto;
pub mod psk;
pub mod sift;
pub mod transport;

pub use engine::{Engine, IMG_H, IMG_SIZE, IMG_W};
pub use matcher::Frame;
pub use sift::Features;

// Methods added here to avoid a circular dependency between matcher and sift.

impl matcher::Frame {
    /// Orientation-tensor coherence quality in [0, 1]. Reject frames below ~0.52.
    pub fn quality(&self) -> f32 {
        sift::quality(self)
    }

    /// Best-shift NCC of `self` against `reference` over `±max_shift` pixels.
    pub fn ncc_vs(&self, reference: &Self, max_shift: i32, min_overlap: i32) -> f32 {
        matcher::best_shift_ncc(self, reference, max_shift, max_shift, min_overlap, None, None)
    }
}

impl sift::Features {
    /// Extract SIFT keypoints and descriptors from a destriped frame.
    pub fn extract(frame: &matcher::Frame) -> Self {
        sift::extract(frame)
    }

    /// Max geometric inlier count of `self` against all entries in `gallery`.
    pub fn verify_against(&self, gallery: &[Self]) -> i32 {
        sift::verify(self, gallery)
    }
}
