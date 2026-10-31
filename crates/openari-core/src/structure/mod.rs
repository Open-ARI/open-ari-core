// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! Bounded structural listings of JPEG, TIFF/DNG, and ISOBMFF/HEIC containers.
//!
//! These walkers follow the public container specifications (ITU-T T.81,
//! TIFF 6.0, ISO/IEC 14496-12). They report where every segment, IFD entry,
//! or box sits, with lengths and SHA-256 digests, so that unknown payloads can
//! be located and compared across files.
//!
//! A structural listing is not ARI detection, format validation, or evidence
//! of authenticity. The walkers never decode pixels and never follow offsets
//! outside the input.

mod isobmff;
mod jpeg;
mod tiff;

pub use isobmff::{IsobmffBox, IsobmffItem, IsobmffStructure};
pub use jpeg::{JpegSegment, JpegStructure, JpegTrailer};
pub use tiff::{TiffEntry, TiffIfd, TiffStructure};

use crate::{DEFAULT_MAX_INPUT_BYTES, Error};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Version of the structure report format. Independent of the verification report.
pub const STRUCTURE_SCHEMA_VERSION: u32 = 1;

/// Fixed statement included in every report.
pub const STRUCTURE_NOTICE: &str =
    "Structural listing only. Not Apple Reference Image detection or verification.";

/// Bounds applied to attacker-controlled structure.
#[derive(Clone, Copy, Debug)]
pub struct StructureLimits {
    pub max_input_bytes: usize,
    pub max_jpeg_segments: usize,
    pub max_tiff_ifds: usize,
    pub max_tiff_entries: usize,
    pub max_tiff_depth: usize,
    pub max_boxes: usize,
    pub max_box_depth: usize,
    pub max_items: usize,
    pub max_findings: usize,
}

impl Default for StructureLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_jpeg_segments: 4096,
            max_tiff_ifds: 256,
            max_tiff_entries: 65_536,
            max_tiff_depth: 8,
            max_boxes: 4096,
            max_box_depth: 16,
            max_items: 4096,
            max_findings: 256,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Container {
    Jpeg,
    Tiff,
    Isobmff,
    Unknown,
}

/// A structural problem or limit encountered while walking the input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Finding {
    pub code: &'static str,
    pub offset: Option<usize>,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StructureReport {
    pub schema_version: u32,
    pub notice: &'static str,
    pub input_bytes: usize,
    pub sha256: String,
    pub container: Container,
    pub jpeg: Option<JpegStructure>,
    pub tiff: Option<TiffStructure>,
    pub isobmff: Option<IsobmffStructure>,
    pub findings: Vec<Finding>,
    pub findings_truncated: bool,
}

/// Collects findings up to a limit.
pub(crate) struct Findings {
    items: Vec<Finding>,
    limit: usize,
    truncated: bool,
}

impl Findings {
    fn new(limit: usize) -> Self {
        Self {
            items: Vec::new(),
            limit,
            truncated: false,
        }
    }

    pub(crate) fn push(&mut self, code: &'static str, offset: Option<usize>, detail: String) {
        if self.items.len() < self.limit {
            self.items.push(Finding {
                code,
                offset,
                detail,
            });
        } else {
            self.truncated = true;
        }
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// Printable ASCII rendering of a four-character code or short identifier.
pub(crate) fn printable(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect()
}

fn classify(input: &[u8]) -> Container {
    if input.starts_with(&[0xff, 0xd8]) {
        Container::Jpeg
    } else if input.starts_with(b"II\x2a\x00")
        || input.starts_with(b"MM\x00\x2a")
        || input.starts_with(b"II\x2b\x00")
        || input.starts_with(b"MM\x00\x2b")
    {
        Container::Tiff
    } else if input.len() >= 8 && &input[4..8] == b"ftyp" {
        Container::Isobmff
    } else {
        Container::Unknown
    }
}

/// Produces a bounded structural listing of `input`.
pub fn describe(input: &[u8], limits: &StructureLimits) -> Result<StructureReport, Error> {
    if input.len() > limits.max_input_bytes {
        return Err(Error::InputTooLarge {
            limit: limits.max_input_bytes,
            actual: input.len(),
        });
    }
    let mut findings = Findings::new(limits.max_findings);
    let container = classify(input);
    let (mut jpeg, mut tiff, mut isobmff) = (None, None, None);
    match container {
        Container::Jpeg => jpeg = Some(jpeg::walk(input, limits, &mut findings)),
        Container::Tiff => tiff = Some(tiff::walk(input, limits, &mut findings)),
        Container::Isobmff => isobmff = Some(isobmff::walk(input, limits, &mut findings)),
        Container::Unknown => findings.push(
            "unrecognized_container",
            None,
            "input does not start with a JPEG, TIFF, or ISOBMFF signature".into(),
        ),
    }
    Ok(StructureReport {
        schema_version: STRUCTURE_SCHEMA_VERSION,
        notice: STRUCTURE_NOTICE,
        input_bytes: input.len(),
        sha256: sha256_hex(input),
        container,
        jpeg,
        tiff,
        isobmff,
        findings: findings.items,
        findings_truncated: findings.truncated,
    })
}

#[cfg(test)]
mod tests;
