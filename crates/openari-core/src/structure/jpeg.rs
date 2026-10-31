// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! JPEG marker segment walker (ITU-T T.81 Annex B).

use super::{Findings, StructureLimits, printable, sha256_hex};
use serde::Serialize;

const MAX_IDENTIFIER_BYTES: usize = 32;

#[derive(Clone, Debug, Serialize)]
pub struct JpegSegment {
    /// Offset of the 0xFF that starts the marker.
    pub offset: usize,
    pub marker: u8,
    pub name: String,
    /// Total bytes including the marker, length field, and payload.
    pub length: usize,
    pub payload_offset: usize,
    pub payload_length: usize,
    /// For APPn segments, the leading NUL-terminated identifier (for example "Exif").
    pub identifier: Option<String>,
    pub payload_sha256: String,
    /// For SOS, the entropy-coded bytes that follow the header, up to the next marker.
    pub scan_data_length: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
pub struct JpegTrailer {
    pub offset: usize,
    pub length: usize,
    pub sha256: String,
    /// The trailer begins with SOI, as secondary images described by MPF do.
    pub starts_with_soi: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct JpegStructure {
    pub segments: Vec<JpegSegment>,
    pub segments_truncated: bool,
    pub eoi_offset: Option<usize>,
    pub trailer: Option<JpegTrailer>,
}

fn marker_name(marker: u8) -> String {
    match marker {
        0xd8 => "SOI".into(),
        0xd9 => "EOI".into(),
        0xda => "SOS".into(),
        0xdb => "DQT".into(),
        0xc4 => "DHT".into(),
        0xdd => "DRI".into(),
        0xfe => "COM".into(),
        0xcc => "DAC".into(),
        0xc0..=0xcf => format!("SOF{}", marker - 0xc0),
        0xd0..=0xd7 => format!("RST{}", marker - 0xd0),
        0xe0..=0xef => format!("APP{}", marker - 0xe0),
        0xf0..=0xfd => format!("JPG{}", marker - 0xf0),
        0x01 => "TEM".into(),
        _ => format!("0x{marker:02X}"),
    }
}

fn standalone(marker: u8) -> bool {
    matches!(marker, 0x01 | 0xd0..=0xd9)
}

fn identifier(payload: &[u8]) -> Option<String> {
    let window = &payload[..payload.len().min(MAX_IDENTIFIER_BYTES)];
    let end = window.iter().position(|&b| b == 0)?;
    if end == 0 {
        return None;
    }
    Some(printable(&window[..end]))
}

/// Length of entropy-coded data starting at `start`: bytes up to the next
/// marker other than a stuffed 0xFF00 or an RSTn.
fn scan_length(input: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < input.len() {
        if input[i] == 0xff && i + 1 < input.len() {
            let next = input[i + 1];
            if next == 0x00 || (0xd0..=0xd7).contains(&next) {
                i += 2;
                continue;
            }
            if next == 0xff {
                i += 1;
                continue;
            }
            return i - start;
        }
        i += 1;
    }
    input.len() - start
}

pub(crate) fn walk(
    input: &[u8],
    limits: &StructureLimits,
    findings: &mut Findings,
) -> JpegStructure {
    let mut out = JpegStructure {
        segments: Vec::new(),
        segments_truncated: false,
        eoi_offset: None,
        trailer: None,
    };
    let mut pos = 0;
    let mut sos_seen = false;
    while pos < input.len() {
        if out.segments.len() >= limits.max_jpeg_segments {
            out.segments_truncated = true;
            findings.push(
                "segment_limit",
                Some(pos),
                format!("stopped after {} segments", limits.max_jpeg_segments),
            );
            return out;
        }
        if input[pos] != 0xff {
            findings.push(
                "expected_marker",
                Some(pos),
                format!("found 0x{:02X} where a marker was expected", input[pos]),
            );
            return out;
        }
        let start = pos;
        // Fill bytes: any number of 0xFF may precede a marker.
        while pos < input.len() && input[pos] == 0xff {
            pos += 1;
        }
        let Some(&marker) = input.get(pos) else {
            findings.push(
                "truncated",
                Some(start),
                "input ends inside a marker".into(),
            );
            return out;
        };
        pos += 1;
        if marker == 0x00 {
            findings.push(
                "invalid_marker",
                Some(start),
                "0xFF00 outside entropy-coded data".into(),
            );
            return out;
        }
        if standalone(marker) {
            out.segments.push(JpegSegment {
                offset: start,
                marker,
                name: marker_name(marker),
                length: pos - start,
                payload_offset: pos,
                payload_length: 0,
                identifier: None,
                payload_sha256: sha256_hex(&[]),
                scan_data_length: None,
            });
            if marker == 0xd8 && start != 0 {
                findings.push(
                    "unexpected_soi",
                    Some(start),
                    "SOI after start of stream".into(),
                );
            }
            if marker == 0xd9 {
                out.eoi_offset = Some(start);
                if pos < input.len() {
                    let rest = &input[pos..];
                    out.trailer = Some(JpegTrailer {
                        offset: pos,
                        length: rest.len(),
                        sha256: sha256_hex(rest),
                        starts_with_soi: rest.starts_with(&[0xff, 0xd8]),
                    });
                    findings.push(
                        "trailing_data",
                        Some(pos),
                        format!("{} bytes follow EOI", rest.len()),
                    );
                }
                return out;
            }
            if (0xd0..=0xd7).contains(&marker) {
                // A restart marker between scans; continue with any scan data.
                let data = scan_length(input, pos);
                pos += data;
            }
            continue;
        }
        let Some(len_bytes) = input.get(pos..pos + 2) else {
            findings.push(
                "truncated",
                Some(start),
                "input ends inside a segment length".into(),
            );
            return out;
        };
        let declared = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
        if declared < 2 {
            findings.push(
                "invalid_length",
                Some(start),
                format!("segment length field {declared} is below 2"),
            );
            return out;
        }
        let payload_offset = pos + 2;
        let end = pos + declared;
        if end > input.len() {
            findings.push(
                "truncated",
                Some(start),
                format!(
                    "{} declares {declared} bytes but only {} remain",
                    marker_name(marker),
                    input.len() - pos
                ),
            );
            return out;
        }
        let payload = &input[payload_offset..end];
        let is_app = (0xe0..=0xef).contains(&marker);
        let mut segment = JpegSegment {
            offset: start,
            marker,
            name: marker_name(marker),
            length: end - start,
            payload_offset,
            payload_length: payload.len(),
            identifier: if is_app { identifier(payload) } else { None },
            payload_sha256: sha256_hex(payload),
            scan_data_length: None,
        };
        pos = end;
        if marker == 0xda {
            sos_seen = true;
            let data = scan_length(input, pos);
            segment.scan_data_length = Some(data);
            pos += data;
        }
        out.segments.push(segment);
    }
    findings.push(
        "missing_eoi",
        Some(input.len()),
        if sos_seen {
            "input ends without EOI".into()
        } else {
            "input ends without a scan or EOI".into()
        },
    );
    out
}
