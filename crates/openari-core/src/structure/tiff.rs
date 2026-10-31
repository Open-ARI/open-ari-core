// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! TIFF image file directory walker (TIFF 6.0 section 2), as used by DNG.

use super::{Findings, StructureLimits, printable, sha256_hex};
use serde::Serialize;
use std::collections::HashSet;

const MAX_PREVIEW_CHARS: usize = 64;
const MAX_PREVIEW_VALUES: u32 = 8;

#[derive(Clone, Debug, Serialize)]
pub struct TiffEntry {
    pub tag: u16,
    pub name: Option<&'static str>,
    pub field_type: u16,
    pub count: u32,
    /// Bytes occupied by the value, when the field type is known.
    pub value_length: Option<usize>,
    /// Offset of an out-of-line value. `None` when the value fits in the entry.
    pub value_offset: Option<usize>,
    pub value_sha256: Option<String>,
    /// Short rendering of ASCII values or small integer arrays.
    pub value_preview: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TiffIfd {
    /// Path such as `IFD0`, `IFD0/SubIFD[1]`, or `IFD0/Exif`.
    pub path: String,
    pub offset: usize,
    pub entry_count: u16,
    pub entries: Vec<TiffEntry>,
    pub next_ifd_offset: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TiffStructure {
    pub byte_order: &'static str,
    pub big_tiff: bool,
    pub first_ifd_offset: Option<usize>,
    /// Value of the DNGVersion tag (50706) in IFD0, if present. Presence of
    /// the tag does not establish that the file is a valid DNG.
    pub dng_version_tag: Option<String>,
    pub ifds: Vec<TiffIfd>,
    pub ifds_truncated: bool,
}

fn tag_name(tag: u16) -> Option<&'static str> {
    Some(match tag {
        254 => "NewSubfileType",
        256 => "ImageWidth",
        257 => "ImageLength",
        258 => "BitsPerSample",
        259 => "Compression",
        262 => "PhotometricInterpretation",
        271 => "Make",
        272 => "Model",
        273 => "StripOffsets",
        274 => "Orientation",
        277 => "SamplesPerPixel",
        278 => "RowsPerStrip",
        279 => "StripByteCounts",
        305 => "Software",
        306 => "DateTime",
        322 => "TileWidth",
        323 => "TileLength",
        324 => "TileOffsets",
        325 => "TileByteCounts",
        330 => "SubIFDs",
        513 => "JPEGInterchangeFormat",
        514 => "JPEGInterchangeFormatLength",
        700 => "XMP",
        33421 => "CFARepeatPatternDim",
        33422 => "CFAPattern",
        33432 => "Copyright",
        34665 => "ExifIFD",
        34853 => "GPSIFD",
        37500 => "MakerNote",
        40965 => "InteroperabilityIFD",
        50706 => "DNGVersion",
        50707 => "DNGBackwardVersion",
        50708 => "UniqueCameraModel",
        50709 => "LocalizedCameraModel",
        50740 => "DNGPrivateData",
        50741 => "MakerNoteSafety",
        50781 => "RawDataUniqueID",
        50827 => "OriginalRawFileName",
        50828 => "OriginalRawFileData",
        50829 => "ActiveArea",
        51041 => "NoiseProfile",
        51125 => "DefaultUserCrop",
        52525 => "ProfileGainTableMap",
        52529 => "SemanticName",
        _ => return None,
    })
}

fn type_size(field_type: u16) -> Option<usize> {
    Some(match field_type {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 | 13 => 4,
        5 | 10 | 12 => 8,
        _ => return None,
    })
}

#[derive(Clone, Copy)]
struct Reader<'a> {
    input: &'a [u8],
    little: bool,
}

impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let b = self.input.get(at..at.checked_add(2)?)?;
        Some(if self.little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let b = self.input.get(at..at.checked_add(4)?)?;
        let a = [b[0], b[1], b[2], b[3]];
        Some(if self.little {
            u32::from_le_bytes(a)
        } else {
            u32::from_be_bytes(a)
        })
    }
}

fn preview(reader: Reader<'_>, field_type: u16, count: u32, value: &[u8]) -> Option<String> {
    match field_type {
        2 => {
            let end = value.iter().position(|&b| b == 0).unwrap_or(value.len());
            let text = &value[..end.min(MAX_PREVIEW_CHARS)];
            Some(printable(text))
        }
        1 | 7 if count <= MAX_PREVIEW_VALUES => Some(
            value
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        3 | 4 | 13 if count <= MAX_PREVIEW_VALUES => {
            let size = type_size(field_type)?;
            let local = Reader {
                input: value,
                little: reader.little,
            };
            let values: Option<Vec<String>> = (0..count as usize)
                .map(|i| {
                    if size == 2 {
                        local.u16(i * 2).map(|v| v.to_string())
                    } else {
                        local.u32(i * 4).map(|v| v.to_string())
                    }
                })
                .collect();
            values.map(|v| v.join(" "))
        }
        _ => None,
    }
}

struct Walker<'a, 'f> {
    reader: Reader<'a>,
    limits: &'a StructureLimits,
    findings: &'f mut Findings,
    visited: HashSet<usize>,
    out: TiffStructure,
    total_entries: usize,
}

impl Walker<'_, '_> {
    fn ifd_offsets(&self, entry: &TiffEntry, inline_at: usize) -> Vec<usize> {
        let base = entry.value_offset.unwrap_or(inline_at);
        (0..entry.count as usize)
            .filter_map(|i| self.reader.u32(base.checked_add(i.checked_mul(4)?)?))
            .map(|v| v as usize)
            .collect()
    }

    fn walk_chain(&mut self, mut offset: usize, path: &str, depth: usize, follow_next: bool) {
        let mut index = 0;
        loop {
            let label = if follow_next {
                format!("{path}{index}")
            } else {
                path.to_string()
            };
            let Some(next) = self.walk_ifd(offset, &label, depth) else {
                return;
            };
            if !follow_next || next == 0 {
                return;
            }
            offset = next;
            index += 1;
        }
    }

    /// Walks one IFD and its children. Returns the next IFD offset.
    fn walk_ifd(&mut self, offset: usize, path: &str, depth: usize) -> Option<usize> {
        if depth > self.limits.max_tiff_depth {
            self.findings.push(
                "depth_limit",
                Some(offset),
                format!("{path} exceeds nesting limit"),
            );
            return None;
        }
        if self.out.ifds.len() >= self.limits.max_tiff_ifds {
            self.out.ifds_truncated = true;
            self.findings
                .push("ifd_limit", Some(offset), format!("stopped before {path}"));
            return None;
        }
        if !self.visited.insert(offset) {
            self.findings
                .push("ifd_loop", Some(offset), format!("{path} revisits an IFD"));
            return None;
        }
        let Some(entry_count) = self.reader.u16(offset) else {
            self.findings.push(
                "out_of_bounds",
                Some(offset),
                format!("{path} offset is outside the input"),
            );
            return None;
        };
        let mut ifd = TiffIfd {
            path: path.to_string(),
            offset,
            entry_count,
            entries: Vec::new(),
            next_ifd_offset: None,
        };
        let mut children = Vec::new();
        for i in 0..usize::from(entry_count) {
            if self.total_entries >= self.limits.max_tiff_entries {
                self.findings.push(
                    "entry_limit",
                    Some(offset),
                    format!("stopped inside {path}"),
                );
                break;
            }
            let at = offset + 2 + i * 12;
            let (Some(tag), Some(field_type), Some(count), Some(raw)) = (
                self.reader.u16(at),
                self.reader.u16(at + 2),
                self.reader.u32(at + 4),
                self.reader.u32(at + 8),
            ) else {
                self.findings.push(
                    "truncated",
                    Some(at),
                    format!("{path} entry {i} is truncated"),
                );
                break;
            };
            self.total_entries += 1;
            let value_length = type_size(field_type).and_then(|s| s.checked_mul(count as usize));
            let mut entry = TiffEntry {
                tag,
                name: tag_name(tag),
                field_type,
                count,
                value_length,
                value_offset: None,
                value_sha256: None,
                value_preview: None,
            };
            match value_length {
                None => self.findings.push(
                    "unknown_field_type",
                    Some(at),
                    format!("{path} tag {tag} has field type {field_type}"),
                ),
                Some(len) => {
                    let start = if len <= 4 { at + 8 } else { raw as usize };
                    if len > 4 {
                        entry.value_offset = Some(start);
                    }
                    match start.checked_add(len).and_then(|end| self.reader.input.get(start..end)) {
                        Some(value) => {
                            entry.value_sha256 = Some(sha256_hex(value));
                            entry.value_preview = preview(self.reader, field_type, count, value);
                        }
                        None => self.findings.push(
                            "out_of_bounds",
                            Some(at),
                            format!("{path} tag {tag} value at {start} with {len} bytes is outside the input"),
                        ),
                    }
                }
            }
            if path == "IFD0" && tag == 50706 {
                self.out.dng_version_tag = entry.value_preview.clone();
            }
            let child = match tag {
                330 => Some("SubIFD"),
                34665 => Some("Exif"),
                34853 => Some("GPS"),
                40965 => Some("Interop"),
                _ => None,
            };
            if let Some(kind) = child
                && matches!(field_type, 4 | 13)
            {
                for (n, child_offset) in self.ifd_offsets(&entry, at + 8).into_iter().enumerate() {
                    let child_path = if tag == 330 {
                        format!("{path}/{kind}[{n}]")
                    } else {
                        format!("{path}/{kind}")
                    };
                    children.push((child_offset, child_path));
                }
            }
            ifd.entries.push(entry);
        }
        let next_at = offset + 2 + usize::from(entry_count) * 12;
        let next = self.reader.u32(next_at).map(|v| v as usize);
        if next.is_none() {
            self.findings.push(
                "truncated",
                Some(next_at),
                format!("{path} next-IFD offset is missing"),
            );
        }
        ifd.next_ifd_offset = next.filter(|&n| n != 0);
        self.out.ifds.push(ifd);
        for (child_offset, child_path) in children {
            self.walk_chain(child_offset, &child_path, depth + 1, false);
        }
        next
    }
}

pub(crate) fn walk(
    input: &[u8],
    limits: &StructureLimits,
    findings: &mut Findings,
) -> TiffStructure {
    let little = input.starts_with(b"II");
    let reader = Reader { input, little };
    let mut out = TiffStructure {
        byte_order: if little { "little" } else { "big" },
        big_tiff: reader.u16(2) == Some(0x2b),
        first_ifd_offset: None,
        dng_version_tag: None,
        ifds: Vec::new(),
        ifds_truncated: false,
    };
    if out.big_tiff {
        findings.push(
            "big_tiff_unsupported",
            Some(0),
            "BigTIFF directories are not walked".into(),
        );
        return out;
    }
    let Some(first) = reader.u32(4) else {
        findings.push(
            "truncated",
            Some(4),
            "header ends before the first IFD offset".into(),
        );
        return out;
    };
    out.first_ifd_offset = Some(first as usize);
    let mut walker = Walker {
        reader,
        limits,
        findings,
        visited: HashSet::new(),
        out,
        total_entries: 0,
    };
    walker.walk_chain(first as usize, "IFD", 0, true);
    walker.out
}
