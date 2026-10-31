// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! ISO base media file format box walker (ISO/IEC 14496-12), as used by HEIF/HEIC.

use super::{Findings, StructureLimits, printable, sha256_hex};
use serde::Serialize;

const MAX_NAME_BYTES: usize = 256;

/// Boxes whose payload is a sequence of child boxes.
const CONTAINERS: &[&[u8; 4]] = &[
    b"moov", b"trak", b"mdia", b"minf", b"stbl", b"dinf", b"edts", b"udta", b"iprp", b"ipco",
    b"grpl", b"mvex", b"moof", b"traf", b"meco",
];
/// Full boxes (4-byte version and flags) whose remaining payload is child boxes.
const FULL_CONTAINERS: &[&[u8; 4]] = &[b"meta"];

#[derive(Clone, Debug, Serialize)]
pub struct IsobmffBox {
    pub offset: usize,
    pub depth: usize,
    pub box_type: String,
    /// Extended type for `uuid` boxes, as 32 hex digits.
    pub user_type: Option<String>,
    pub size: u64,
    pub header_length: usize,
    pub payload_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct IsobmffItem {
    pub item_id: u32,
    pub item_type: String,
    pub name: String,
    pub content_type: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct IsobmffStructure {
    pub major_brand: Option<String>,
    pub minor_version: Option<u32>,
    pub compatible_brands: Vec<String>,
    pub boxes: Vec<IsobmffBox>,
    pub boxes_truncated: bool,
    /// Entries of `iinf` item information boxes. Item locations (`iloc`) are
    /// not resolved.
    pub items: Vec<IsobmffItem>,
}

fn be_u16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn be_u64(b: &[u8], at: usize) -> Option<u64> {
    let s = b.get(at..at.checked_add(8)?)?;
    let mut a = [0; 8];
    a.copy_from_slice(s);
    Some(u64::from_be_bytes(a))
}

fn c_string(b: &[u8], at: usize) -> (String, usize) {
    let rest = b.get(at..).unwrap_or(&[]);
    let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
    (
        printable(&rest[..end.min(MAX_NAME_BYTES)]),
        (end + 1).min(rest.len()),
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct Walker<'a, 'f> {
    input: &'a [u8],
    limits: &'a StructureLimits,
    findings: &'f mut Findings,
    out: IsobmffStructure,
}

impl Walker<'_, '_> {
    fn walk_range(&mut self, start: usize, end: usize, depth: usize) {
        let mut pos = start;
        while pos < end {
            if self.out.boxes.len() >= self.limits.max_boxes {
                self.out.boxes_truncated = true;
                self.findings.push(
                    "box_limit",
                    Some(pos),
                    format!("stopped after {} boxes", self.limits.max_boxes),
                );
                return;
            }
            let (Some(size32), Some(kind)) =
                (be_u32(self.input, pos), self.input.get(pos + 4..pos + 8))
            else {
                self.findings.push(
                    "truncated",
                    Some(pos),
                    "input ends inside a box header".into(),
                );
                return;
            };
            let mut header = 8;
            let size = match size32 {
                0 => (end - pos) as u64,
                1 => {
                    let Some(large) = be_u64(self.input, pos + 8) else {
                        self.findings.push(
                            "truncated",
                            Some(pos),
                            "input ends inside a 64-bit box size".into(),
                        );
                        return;
                    };
                    header = 16;
                    large
                }
                n => u64::from(n),
            };
            let mut user_type = None;
            if kind == b"uuid" {
                let Some(ext) = self.input.get(pos + header..pos + header + 16) else {
                    self.findings.push(
                        "truncated",
                        Some(pos),
                        "input ends inside a uuid box type".into(),
                    );
                    return;
                };
                user_type = Some(hex(ext));
                header += 16;
            }
            let box_end = usize::try_from(size).ok().and_then(|s| pos.checked_add(s));
            let Some(box_end) = box_end.filter(|&e| e <= end && size >= header as u64) else {
                self.findings.push(
                    "invalid_box_size",
                    Some(pos),
                    format!(
                        "box '{}' declares {size} bytes, outside its parent",
                        printable(kind)
                    ),
                );
                return;
            };
            let kind: [u8; 4] = [kind[0], kind[1], kind[2], kind[3]];
            let payload_start = pos + header;
            self.out.boxes.push(IsobmffBox {
                offset: pos,
                depth,
                box_type: printable(&kind),
                user_type,
                size,
                header_length: header,
                payload_sha256: sha256_hex(&self.input[payload_start..box_end]),
            });
            if depth == 0 && &kind == b"ftyp" {
                self.read_ftyp(payload_start, box_end);
            }
            let child_start = if CONTAINERS.contains(&&kind) {
                Some(payload_start)
            } else if FULL_CONTAINERS.contains(&&kind) {
                Some(payload_start + 4)
            } else {
                None
            };
            if let Some(child_start) = child_start {
                if depth + 1 > self.limits.max_box_depth {
                    self.findings.push(
                        "depth_limit",
                        Some(pos),
                        "box nesting limit reached".into(),
                    );
                } else if child_start <= box_end {
                    self.walk_range(child_start, box_end, depth + 1);
                }
            }
            if &kind == b"iinf" {
                self.read_iinf(payload_start, box_end);
            }
            pos = box_end;
        }
    }

    fn read_ftyp(&mut self, start: usize, end: usize) {
        let body = &self.input[start..end];
        if body.len() < 8 {
            self.findings.push(
                "truncated",
                Some(start),
                "ftyp is shorter than 8 bytes".into(),
            );
            return;
        }
        self.out.major_brand = Some(printable(&body[..4]));
        self.out.minor_version = be_u32(body, 4);
        self.out.compatible_brands = body[8..].chunks_exact(4).map(printable).collect();
    }

    fn read_iinf(&mut self, start: usize, end: usize) {
        let body = &self.input[start..end];
        let Some(&version) = body.first() else {
            return;
        };
        let (count, mut pos) = if version == 0 {
            (be_u16(body, 4).map(u32::from), 6)
        } else {
            (be_u32(body, 4), 8)
        };
        let Some(count) = count else {
            self.findings.push(
                "truncated",
                Some(start),
                "iinf entry count is missing".into(),
            );
            return;
        };
        for _ in 0..count {
            if self.out.items.len() >= self.limits.max_items {
                self.findings.push(
                    "item_limit",
                    Some(start + pos),
                    "item list truncated".into(),
                );
                return;
            }
            let (Some(size), Some(kind)) = (be_u32(body, pos), body.get(pos + 4..pos + 8)) else {
                self.findings.push(
                    "truncated",
                    Some(start + pos),
                    "iinf ends inside an entry".into(),
                );
                return;
            };
            let size = size as usize;
            let Some(entry_end) = pos
                .checked_add(size)
                .filter(|&e| e <= body.len() && size >= 12)
            else {
                self.findings.push(
                    "invalid_box_size",
                    Some(start + pos),
                    "infe size is invalid".into(),
                );
                return;
            };
            if kind == b"infe" {
                self.read_infe(&body[pos + 8..entry_end], start + pos);
            }
            pos = entry_end;
        }
    }

    fn read_infe(&mut self, body: &[u8], offset: usize) {
        let version = body[0];
        if version < 2 {
            self.findings.push(
                "unsupported_infe",
                Some(offset),
                format!("infe version {version} not decoded"),
            );
            return;
        }
        let (item_id, mut pos) = if version == 2 {
            (be_u16(body, 4).map(u32::from), 6)
        } else {
            (be_u32(body, 4), 8)
        };
        pos += 2; // item_protection_index
        let (Some(item_id), Some(item_type)) = (item_id, body.get(pos..pos + 4)) else {
            self.findings
                .push("truncated", Some(offset), "infe is truncated".into());
            return;
        };
        pos += 4;
        let (name, used) = c_string(body, pos);
        pos += used;
        let content_type = (item_type == b"mime").then(|| c_string(body, pos).0);
        self.out.items.push(IsobmffItem {
            item_id,
            item_type: printable(item_type),
            name,
            content_type,
        });
    }
}

pub(crate) fn walk(
    input: &[u8],
    limits: &StructureLimits,
    findings: &mut Findings,
) -> IsobmffStructure {
    let mut walker = Walker {
        input,
        limits,
        findings,
        out: IsobmffStructure {
            major_brand: None,
            minor_version: None,
            compatible_brands: Vec::new(),
            boxes: Vec::new(),
            boxes_truncated: false,
            items: Vec::new(),
        },
    };
    walker.walk_range(0, input.len(), 0);
    walker.out
}
