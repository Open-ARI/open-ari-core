// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
use std::process::Command;

#[test]
fn verification_does_not_exit_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_arictl"))
        .args(["verify", concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["decision"], "indeterminate");
    assert_eq!(report["schema_version"], 1);
}

#[test]
fn capabilities_do_not_advertise_apple_support() {
    let output = Command::new(env!("CARGO_BIN_EXE_arictl"))
        .arg("capabilities")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["cryptographic_verification"], false);
    assert_eq!(report["supported_ari_versions"], serde_json::json!([]));
}
