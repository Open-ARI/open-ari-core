// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
use super::*;

fn segment(marker: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0xff, marker];
    out.extend_from_slice(&u16::try_from(payload.len() + 2).unwrap().to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn sample_jpeg() -> Vec<u8> {
    let mut jpeg = vec![0xff, 0xd8];
    jpeg.extend(segment(0xe1, b"Exif\0\0II*\0"));
    jpeg.extend(segment(0xeb, b"JP\0\x01payload"));
    jpeg.extend(segment(0xdb, &[0; 65]));
    jpeg.extend(segment(0xda, &[1, 1, 0, 0, 63, 0]));
    // Entropy data with a stuffed 0xFF00 and a restart marker.
    jpeg.extend([0x12, 0xff, 0x00, 0x34, 0xff, 0xd0, 0x56]);
    jpeg.extend([0xff, 0xd9]);
    jpeg.extend([0xff, 0xd8, 0xff, 0xd9]);
    jpeg
}

#[test]
fn jpeg_segments_are_listed_with_offsets() {
    let input = sample_jpeg();
    let report = describe(&input, &StructureLimits::default()).unwrap();
    assert_eq!(report.container, Container::Jpeg);
    let jpeg = report.jpeg.unwrap();
    let names: Vec<_> = jpeg.segments.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["SOI", "APP1", "APP11", "DQT", "SOS", "EOI"]);
    assert_eq!(jpeg.segments[1].identifier.as_deref(), Some("Exif"));
    assert_eq!(jpeg.segments[2].identifier.as_deref(), Some("JP"));
    assert_eq!(jpeg.segments[1].offset, 2);
    assert_eq!(jpeg.segments[4].scan_data_length, Some(7));
    let trailer = jpeg.trailer.unwrap();
    assert!(trailer.starts_with_soi);
    assert_eq!(trailer.length, 4);
    assert_eq!(report.findings[0].code, "trailing_data");
    assert_eq!(report.sha256.len(), 64);
}

#[test]
fn jpeg_truncation_is_reported() {
    let input = sample_jpeg();
    for length in 0..input.len() {
        let report = describe(&input[..length], &StructureLimits::default()).unwrap();
        if let Some(jpeg) = report.jpeg {
            for s in &jpeg.segments {
                assert!(s.offset + s.length <= length);
            }
            if jpeg.eoi_offset.is_none() {
                assert!(!report.findings.is_empty());
            }
        }
    }
    let mut bad = vec![0xff, 0xd8];
    bad.extend([0xff, 0xe1, 0x00, 0x01]);
    let report = describe(&bad, &StructureLimits::default()).unwrap();
    assert_eq!(report.findings[0].code, "invalid_length");
}

#[test]
fn jpeg_segment_limit_applies() {
    let mut input = vec![0xff, 0xd8];
    for _ in 0..10 {
        input.extend(segment(0xfe, b"c"));
    }
    let limits = StructureLimits {
        max_jpeg_segments: 4,
        ..StructureLimits::default()
    };
    let jpeg = describe(&input, &limits).unwrap().jpeg.unwrap();
    assert_eq!(jpeg.segments.len(), 4);
    assert!(jpeg.segments_truncated);
}

fn entry(tag: u16, field_type: u16, count: u32, value: u32) -> Vec<u8> {
    let mut e = tag.to_le_bytes().to_vec();
    e.extend(field_type.to_le_bytes());
    e.extend(count.to_le_bytes());
    e.extend(value.to_le_bytes());
    e
}

/// Little-endian TIFF: IFD0 at 8 with Make (out of line), DNGVersion and a
/// SubIFD pointer; the SubIFD's next pointer loops back to IFD0.
fn sample_tiff() -> Vec<u8> {
    let mut t = b"II\x2a\x00".to_vec();
    t.extend(8u32.to_le_bytes());
    // IFD0: 3 entries at offset 8, ends at 8 + 2 + 36 + 4 = 50.
    t.extend(3u16.to_le_bytes());
    t.extend(entry(271, 2, 6, 50));
    t.extend(entry(50706, 1, 4, u32::from_le_bytes([1, 7, 0, 0])));
    t.extend(entry(330, 4, 1, 56));
    t.extend(0u32.to_le_bytes());
    t.extend(b"Apple\0");
    // SubIFD at 56 with one entry, next pointer 8 (a loop).
    t.extend(1u16.to_le_bytes());
    t.extend(entry(256, 3, 1, 4032));
    t.extend(8u32.to_le_bytes());
    t
}

#[test]
fn tiff_ifds_and_subifds_are_walked() {
    let input = sample_tiff();
    let report = describe(&input, &StructureLimits::default()).unwrap();
    let tiff = report.tiff.unwrap();
    assert_eq!(tiff.byte_order, "little");
    assert_eq!(tiff.dng_version_tag.as_deref(), Some("1 7 0 0"));
    let paths: Vec<_> = tiff.ifds.iter().map(|i| i.path.as_str()).collect();
    assert_eq!(paths, ["IFD0", "IFD0/SubIFD[0]"]);
    let make = &tiff.ifds[0].entries[0];
    assert_eq!(make.name, Some("Make"));
    assert_eq!(make.value_offset, Some(50));
    assert_eq!(make.value_preview.as_deref(), Some("Apple"));
    assert_eq!(
        tiff.ifds[1].entries[0].value_preview.as_deref(),
        Some("4032")
    );
    // SubIFD is walked without following its next pointer, so no loop is reported here.
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn tiff_loops_and_bad_offsets_are_reported() {
    let mut input = sample_tiff();
    // Point IFD0's next-IFD field at IFD0 itself.
    input[46..50].copy_from_slice(&8u32.to_le_bytes());
    let report = describe(&input, &StructureLimits::default()).unwrap();
    assert!(report.findings.iter().any(|f| f.code == "ifd_loop"));

    let mut input = sample_tiff();
    input[10 + 8..10 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
    let report = describe(&input, &StructureLimits::default()).unwrap();
    assert!(report.findings.iter().any(|f| f.code == "out_of_bounds"));

    for length in 0..input.len() {
        describe(&input[..length], &StructureLimits::default()).unwrap();
    }
}

fn bmff(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(payload.len() + 8)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(payload);
    out
}

fn sample_heif() -> Vec<u8> {
    let mut ftyp = b"heic".to_vec();
    ftyp.extend(0u32.to_be_bytes());
    ftyp.extend(b"mif1heic");
    let mut infe = vec![2, 0, 0, 0];
    infe.extend(1u16.to_be_bytes());
    infe.extend(0u16.to_be_bytes());
    infe.extend(b"hvc1");
    infe.extend(b"Image\0");
    let mut infe_mime = vec![2, 0, 0, 0];
    infe_mime.extend(2u16.to_be_bytes());
    infe_mime.extend(0u16.to_be_bytes());
    infe_mime.extend(b"mime");
    infe_mime.extend(b"\0application/rdf+xml\0");
    let mut iinf = vec![0, 0, 0, 0];
    iinf.extend(2u16.to_be_bytes());
    iinf.extend(bmff(b"infe", &infe));
    iinf.extend(bmff(b"infe", &infe_mime));
    let mut meta = vec![0, 0, 0, 0];
    meta.extend(bmff(b"hdlr", &[0; 24]));
    meta.extend(bmff(b"iinf", &iinf));
    meta.extend(bmff(b"iprp", &bmff(b"ipco", &bmff(b"ispe", &[0; 12]))));
    let mut file = bmff(b"ftyp", &ftyp);
    file.extend(bmff(b"meta", &meta));
    file.extend(bmff(b"mdat", b"pixels"));
    file
}

#[test]
fn isobmff_boxes_and_items_are_listed() {
    let input = sample_heif();
    let report = describe(&input, &StructureLimits::default()).unwrap();
    assert_eq!(report.container, Container::Isobmff);
    let heif = report.isobmff.unwrap();
    assert_eq!(heif.major_brand.as_deref(), Some("heic"));
    assert_eq!(heif.compatible_brands, ["mif1", "heic"]);
    let boxes: Vec<_> = heif
        .boxes
        .iter()
        .map(|b| (b.depth, b.box_type.as_str()))
        .collect();
    assert_eq!(
        boxes,
        [
            (0, "ftyp"),
            (0, "meta"),
            (1, "hdlr"),
            (1, "iinf"),
            (1, "iprp"),
            (2, "ipco"),
            (3, "ispe"),
            (0, "mdat")
        ]
    );
    assert_eq!(heif.items.len(), 2);
    assert_eq!(heif.items[0].item_type, "hvc1");
    assert_eq!(heif.items[0].name, "Image");
    assert_eq!(
        heif.items[1].content_type.as_deref(),
        Some("application/rdf+xml")
    );
    assert!(report.findings.is_empty(), "{:?}", report.findings);
}

#[test]
fn isobmff_bad_sizes_and_truncation_are_reported() {
    let mut input = sample_heif();
    input[0..4].copy_from_slice(&u32::MAX.to_be_bytes());
    let report = describe(&input, &StructureLimits::default()).unwrap();
    assert_eq!(report.findings[0].code, "invalid_box_size");
    let input = sample_heif();
    for length in 8..input.len() {
        describe(&input[..length], &StructureLimits::default()).unwrap();
    }
}

#[test]
fn unknown_and_oversized_inputs() {
    let report = describe(b"plain text", &StructureLimits::default()).unwrap();
    assert_eq!(report.container, Container::Unknown);
    assert_eq!(report.findings[0].code, "unrecognized_container");
    let limits = StructureLimits {
        max_input_bytes: 2,
        ..StructureLimits::default()
    };
    assert!(describe(b"abc", &limits).is_err());
}
