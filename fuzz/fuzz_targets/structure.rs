// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
#![no_main]
use libfuzzer_sys::fuzz_target;
use openari_core::structure::{StructureLimits, describe};
fuzz_target!(|data: &[u8]| {
    let limits = StructureLimits {
        max_input_bytes: 1024 * 1024,
        ..StructureLimits::default()
    };
    if let Ok(report) = describe(data, &limits) {
        assert!(report.findings.len() <= limits.max_findings);
        if let Some(jpeg) = &report.jpeg {
            assert!(jpeg.segments.len() <= limits.max_jpeg_segments);
            for s in &jpeg.segments {
                assert!(s.offset + s.length <= data.len());
            }
        }
        if let Some(tiff) = &report.tiff {
            assert!(tiff.ifds.len() <= limits.max_tiff_ifds);
        }
        if let Some(bmff) = &report.isobmff {
            assert!(bmff.boxes.len() <= limits.max_boxes);
            assert!(bmff.boxes.iter().all(|b| b.depth <= limits.max_box_depth));
        }
    }
});
