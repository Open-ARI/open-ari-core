// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! OpenARI's initial inspection and verification contract.
//!
//! No Apple ARI format revision is supported yet. Container hints are not
//! structural validation, DNG identification, or evidence of authenticity.
#![forbid(unsafe_code)]

use serde::Serialize;
use std::fmt;

pub const REPORT_SCHEMA_VERSION: u32 = 1;
pub const DEFAULT_MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub const POLICY_ID: &str = "openari.pre-spec/1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContainerHint {
    Jpeg,
    Tiff,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Decision {
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CheckStatus {
    NotChecked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Reason {
    SpecificationPending,
    UnrecognizedContainer,
}

/// OpenARI does not assign version numbers on Apple's behalf.
/// A future detector will preserve the actual, documented on-wire identifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AriVersion {
    pub identifier: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Inspection {
    pub schema_version: u32,
    pub input_bytes: usize,
    pub container_hint: ContainerHint,
    pub ari_version: Option<AriVersion>,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub engine_version: &'static str,
    pub policy_id: &'static str,
    pub inspection: Inspection,
    pub decision: Decision,
    pub reason: Reason,
    pub structure: CheckStatus,
    pub image_integrity: CheckStatus,
    pub signature: CheckStatus,
    pub trust: CheckStatus,
    pub revocation: CheckStatus,
    pub capture_interval: Option<CaptureInterval>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CaptureInterval {
    pub lower_unix_seconds: i64,
    pub upper_unix_seconds: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Capabilities {
    pub schema_version: u32,
    pub engine_version: &'static str,
    pub supported_ari_versions: Vec<AriVersion>,
    pub cryptographic_verification: bool,
    pub network_access: bool,
    pub accelerators: Vec<&'static str>,
}

pub fn capabilities() -> Capabilities {
    Capabilities {
        schema_version: REPORT_SCHEMA_VERSION,
        engine_version: env!("CARGO_PKG_VERSION"),
        supported_ari_versions: Vec::new(),
        cryptographic_verification: false,
        network_access: false,
        accelerators: Vec::new(),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InputTooLarge { limit: usize, actual: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { limit, actual } => {
                write!(f, "input has {actual} bytes; limit is {limit}")
            }
        }
    }
}
impl std::error::Error for Error {}

/// Immutable, reusable verifier. No I/O, clock reads, or mutable global state.
#[derive(Clone, Debug)]
pub struct Verifier {
    max_input_bytes: usize,
}

impl Default for Verifier {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_INPUT_BYTES)
    }
}

impl Verifier {
    pub const fn new(max_input_bytes: usize) -> Self {
        Self { max_input_bytes }
    }

    pub fn inspect(&self, input: &[u8]) -> Result<Inspection, Error> {
        if input.len() > self.max_input_bytes {
            return Err(Error::InputTooLarge {
                limit: self.max_input_bytes,
                actual: input.len(),
            });
        }
        let container_hint = if input.starts_with(&[0xff, 0xd8, 0xff]) {
            ContainerHint::Jpeg
        } else if input.starts_with(b"II\x2a\x00")
            || input.starts_with(b"MM\x00\x2a")
            || input.starts_with(b"II\x2b\x00")
            || input.starts_with(b"MM\x00\x2b")
        {
            ContainerHint::Tiff
        } else {
            ContainerHint::Unknown
        };
        Ok(Inspection {
            schema_version: REPORT_SCHEMA_VERSION,
            input_bytes: input.len(),
            container_hint,
            ari_version: None,
        })
    }

    /// `Ok(report)` means evaluation completed, never that the image is trusted.
    /// This pre-spec implementation can only return an indeterminate decision.
    pub fn verify(&self, input: &[u8]) -> Result<VerificationReport, Error> {
        let inspection = self.inspect(input)?;
        let reason = if inspection.container_hint == ContainerHint::Unknown {
            Reason::UnrecognizedContainer
        } else {
            Reason::SpecificationPending
        };
        Ok(VerificationReport {
            schema_version: REPORT_SCHEMA_VERSION,
            engine_version: env!("CARGO_PKG_VERSION"),
            policy_id: POLICY_ID,
            inspection,
            decision: Decision::Indeterminate,
            reason,
            structure: CheckStatus::NotChecked,
            image_integrity: CheckStatus::NotChecked,
            signature: CheckStatus::NotChecked,
            trust: CheckStatus::NotChecked,
            revocation: CheckStatus::NotChecked,
            capture_interval: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_and_truncated_inputs_never_authenticate() {
        let verifier = Verifier::default();
        for seed in [
            b"\xff\xd8\xffpayload".as_slice(),
            b"II\x2a\x00payload",
            b"MM\x00\x2bpayload",
            b"ordinary upload",
        ] {
            for length in 0..=seed.len() {
                let report = verifier.verify(&seed[..length]).unwrap();
                assert_eq!(report.decision, Decision::Indeterminate);
                assert_eq!(report.signature, CheckStatus::NotChecked);
                assert!(report.inspection.ari_version.is_none());
            }
        }
        assert!(capabilities().supported_ari_versions.is_empty());
    }

    #[test]
    fn limits_apply_before_detection() {
        let verifier = Verifier::new(3);
        assert!(verifier.inspect(b"abc").is_ok());
        assert_eq!(
            verifier.verify(b"abcd").unwrap_err(),
            Error::InputTooLarge {
                limit: 3,
                actual: 4
            }
        );
    }

    #[test]
    fn tiff_is_not_claimed_to_be_dng() {
        let report = Verifier::default().inspect(b"II\x2a\x00").unwrap();
        assert_eq!(report.container_hint, ContainerHint::Tiff);
        assert!(report.ari_version.is_none());
    }
}
