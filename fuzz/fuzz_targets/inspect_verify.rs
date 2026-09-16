// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
#![no_main]
use libfuzzer_sys::fuzz_target;
use openari_core::{Decision, Verifier};
fuzz_target!(|data: &[u8]| {
    let verifier = Verifier::new(1024 * 1024);
    if let Ok(report) = verifier.verify(data) {
        assert_eq!(report.decision, Decision::Indeterminate);
        assert!(report.inspection.ari_version.is_none());
    }
});
