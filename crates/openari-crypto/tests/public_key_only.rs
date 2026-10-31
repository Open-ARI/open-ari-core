// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! Guards the scope of the RUSTSEC-2023-0071 exception in .cargo/audit.toml:
//! library code must not use RSA private-key operations.

#[test]
fn library_code_uses_only_public_keys() {
    let source = include_str!("../src/lib.rs");
    for forbidden in [
        "RsaPrivateKey",
        "DecodeRsaPrivateKey",
        "sign_with_rng",
        "decrypt",
    ] {
        assert!(
            !source.contains(forbidden),
            "src/lib.rs mentions {forbidden}; review .cargo/audit.toml before adding private-key use"
        );
    }
}
