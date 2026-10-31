// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
use std::process::Command;

#[test]
fn verification_does_not_exit_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_openari"))
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
    let output = Command::new(env!("CARGO_BIN_EXE_openari"))
        .arg("capabilities")
        .output()
        .unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["cryptographic_verification"], false);
    assert_eq!(report["supported_ari_versions"], serde_json::json!([]));
}

#[test]
fn structure_lists_without_claiming_ari() {
    let dir = std::env::temp_dir().join(format!("openari-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("tiny.jpg");
    std::fs::write(
        &path,
        [0xff, 0xd8, 0xff, 0xfe, 0x00, 0x03, b'x', 0xff, 0xd9],
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_openari"))
        .args(["structure", path.to_str().unwrap()])
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["container"], "jpeg");
    assert_eq!(report["jpeg"]["segments"][1]["name"], "COM");
    assert!(
        report["notice"]
            .as_str()
            .unwrap()
            .contains("Not Apple Reference Image")
    );
}
