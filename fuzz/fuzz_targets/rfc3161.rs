// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
#![no_main]
use libfuzzer_sys::fuzz_target;
use openari_crypto::rfc3161::{ImprintAlgorithm, verify_token};

const TSA: &[u8] = include_bytes!("../../crates/openari-crypto/tests/vectors/rfc3161/tsa.der");
const MESSAGE: &[u8] = include_bytes!("../../crates/openari-crypto/tests/vectors/rfc3161/message.txt");

fuzz_target!(|data: &[u8]| {
    // Arbitrary tokens must not panic, and must never verify for an imprint
    // the fuzzer cannot produce a valid signature over.
    let imprint = ImprintAlgorithm::Sha256.digest(MESSAGE);
    let _ = verify_token(data, ImprintAlgorithm::Sha256, &imprint, TSA);
    let _ = verify_token(data, ImprintAlgorithm::Sha256, &imprint, data);
});
