// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! Offline verification of RFC 3161 timestamp tokens signed with ECDSA P-256.
//!
//! Apple documents RFC 3161 tokens signed with ECDSA P-256 over SHA-256 for the
//! capture-time bounds of a reference image. Apple has not published its
//! timestamp authority certificates or where tokens sit in its files, so this
//! module is a standards building block, not Apple support.
//!
//! [`verify_token`] checks a token against a certificate the caller supplies.
//! It does not build or validate a certificate path, check revocation, or
//! decide whether the certificate is trusted. Those are policy decisions for
//! the caller. It does check that the certificate is a time-stamping
//! certificate, that it identifies the signer, that it was valid at the
//! token's generation time, and every signature and digest binding listed in
//! RFC 3161 section 2.4.2, RFC 5652 section 5.4, and RFC 5816.

use cms::{
    cert::IssuerAndSerialNumber,
    content_info::{CmsVersion, ContentInfo},
    signed_data::{SignedData, SignerIdentifier},
};
use der::{
    Decode, Encode, Sequence, Tagged,
    asn1::{ObjectIdentifier, OctetString},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use x509_cert::{
    Certificate,
    ext::pkix::{ExtendedKeyUsage, SubjectKeyIdentifier},
    spki::AlgorithmIdentifierOwned,
};
use x509_tsp::TstInfo;

/// Tokens larger than this are rejected before parsing.
pub const MAX_TOKEN_BYTES: usize = 64 * 1024;
/// Certificates larger than this are rejected before parsing.
pub const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;

const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CT_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_CERTIFICATE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const ID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");
const ID_CE_EXT_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");
const ID_CE_SUBJECT_KEY_IDENTIFIER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.14");

/// Hash algorithm of the message imprint inside the token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ImprintAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl ImprintAlgorithm {
    fn oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => ID_SHA256,
            Self::Sha384 => ID_SHA384,
            Self::Sha512 => ID_SHA512,
        }
    }

    /// Hashes `data` with this algorithm, for building an expected imprint.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha384 => Sha384::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Fields of a token whose signature, digests, and imprint all verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedTimestamp {
    /// `genTime`, in whole seconds since the Unix epoch. Fractions are dropped.
    pub gen_time_unix_seconds: u64,
    /// TSA policy OID in dotted form.
    pub policy: String,
    /// Big-endian serial number bytes as encoded.
    pub serial_number: Vec<u8>,
    pub imprint_algorithm: ImprintAlgorithm,
    pub imprint: Vec<u8>,
    pub nonce: Option<Vec<u8>>,
    /// Accuracy as (seconds, milliseconds, microseconds), when present.
    pub accuracy: Option<(Option<u64>, Option<i16>, Option<i16>)>,
}

/// Reasons a token was not accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TimestampError {
    TokenTooLarge(usize),
    CertificateTooLarge(usize),
    Encoding,
    NotSignedData,
    NotTstInfo,
    MissingContent,
    UnsupportedTstInfoVersion,
    StructureVersion,
    SignerCount(usize),
    UnsupportedDigestAlgorithm,
    UnsupportedSignatureAlgorithm,
    MissingSignedAttributes,
    ContentTypeAttribute,
    MessageDigestAttribute,
    MessageDigestMismatch,
    SigningCertificateAttribute,
    SigningCertificateMismatch,
    CertificateEncoding,
    NotTimestampingCertificate,
    UnsupportedPublicKey,
    SignerMismatch,
    CertificateNotValidAtGenTime,
    SignatureInvalid,
    ImprintAlgorithmMismatch,
    ImprintMismatch,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TokenTooLarge(n) => {
                return write!(f, "token has {n} bytes; limit is {MAX_TOKEN_BYTES}");
            }
            Self::CertificateTooLarge(n) => {
                return write!(
                    f,
                    "certificate has {n} bytes; limit is {MAX_CERTIFICATE_BYTES}"
                );
            }
            Self::Encoding => "token is not valid DER",
            Self::NotSignedData => "token is not CMS SignedData",
            Self::NotTstInfo => "encapsulated content is not TSTInfo",
            Self::MissingContent => "encapsulated TSTInfo is absent",
            Self::UnsupportedTstInfoVersion => "TSTInfo version is not 1",
            Self::StructureVersion => {
                "SignedData or SignerInfo version is not the value RFC 5652 requires"
            }
            Self::SignerCount(_) => "token must have exactly one signer",
            Self::UnsupportedDigestAlgorithm => "signer digest algorithm is not SHA-256",
            Self::UnsupportedSignatureAlgorithm => "signature algorithm is not ecdsa-with-SHA256",
            Self::MissingSignedAttributes => "signed attributes are absent",
            Self::ContentTypeAttribute => "content-type attribute is missing, repeated, or wrong",
            Self::MessageDigestAttribute => "message-digest attribute is missing or repeated",
            Self::MessageDigestMismatch => "message digest does not match TSTInfo",
            Self::SigningCertificateAttribute => {
                "SigningCertificateV2 attribute is missing, repeated, or unsupported"
            }
            Self::SigningCertificateMismatch => {
                "SigningCertificateV2 does not identify the supplied certificate"
            }
            Self::CertificateEncoding => "certificate is not valid DER",
            Self::NotTimestampingCertificate => {
                "certificate lacks a critical id-kp-timeStamping extended key usage"
            }
            Self::UnsupportedPublicKey => "certificate key is not an ECDSA P-256 key",
            Self::SignerMismatch => "signer identifier does not match the certificate",
            Self::CertificateNotValidAtGenTime => "certificate was not valid at genTime",
            Self::SignatureInvalid => "signature over signed attributes is invalid",
            Self::ImprintAlgorithmMismatch => "message imprint uses a different hash algorithm",
            Self::ImprintMismatch => "message imprint does not match the expected digest",
        };
        f.write_str(text)
    }
}

impl std::error::Error for TimestampError {}

/// ESSCertIDv2 (RFC 5035). `hashAlgorithm` defaults to SHA-256 when absent.
#[derive(Clone, Debug, Sequence)]
struct EssCertIdV2 {
    #[asn1(optional = "true")]
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    #[asn1(optional = "true")]
    issuer_serial: Option<der::Any>,
}

/// SigningCertificateV2 (RFC 5035).
#[derive(Clone, Debug, Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
    #[asn1(optional = "true")]
    policies: Option<der::Any>,
}

/// SHA-256 with absent or NULL parameters, as RFC 5754 allows.
fn is_sha256(alg: &AlgorithmIdentifierOwned) -> bool {
    alg.oid == ID_SHA256
        && alg
            .parameters
            .as_ref()
            .is_none_or(|p| p.tag() == der::Tag::Null && p.value().is_empty())
}

fn extension(cert: &Certificate, oid: ObjectIdentifier) -> Option<&x509_cert::ext::Extension> {
    cert.tbs_certificate
        .extensions
        .as_ref()?
        .iter()
        .find(|e| e.extn_id == oid)
}

/// Verifies `token` (a DER TimeStampToken) for `expected_imprint` hashed with
/// `algorithm`, using the DER `tsa_certificate` supplied by the caller.
pub fn verify_token(
    token: &[u8],
    algorithm: ImprintAlgorithm,
    expected_imprint: &[u8],
    tsa_certificate: &[u8],
) -> Result<VerifiedTimestamp, TimestampError> {
    use TimestampError as E;
    if token.len() > MAX_TOKEN_BYTES {
        return Err(E::TokenTooLarge(token.len()));
    }
    if tsa_certificate.len() > MAX_CERTIFICATE_BYTES {
        return Err(E::CertificateTooLarge(tsa_certificate.len()));
    }

    let content_info = ContentInfo::from_der(token).map_err(|_| E::Encoding)?;
    if content_info.content_type != ID_SIGNED_DATA {
        return Err(E::NotSignedData);
    }
    let signed_data: SignedData = content_info.content.decode_as().map_err(|_| E::Encoding)?;
    // RFC 5652 section 5.1: version 3 because eContentType is not id-data.
    if signed_data.version != CmsVersion::V3 {
        return Err(E::StructureVersion);
    }
    let digest_algorithms = signed_data.digest_algorithms.as_slice();
    if digest_algorithms.is_empty() || !digest_algorithms.iter().all(is_sha256) {
        return Err(E::UnsupportedDigestAlgorithm);
    }
    if signed_data.encap_content_info.econtent_type != ID_CT_TST_INFO {
        return Err(E::NotTstInfo);
    }
    let econtent = signed_data
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(E::MissingContent)?;
    let tst_der = econtent
        .decode_as::<OctetString>()
        .map_err(|_| E::Encoding)?;
    let tst_der = tst_der.as_bytes();
    let tst = TstInfo::from_der(tst_der).map_err(|_| E::Encoding)?;
    if tst.version != x509_tsp::TspVersion::V1 {
        return Err(E::UnsupportedTstInfoVersion);
    }

    let signers = signed_data.signer_infos.0.as_slice();
    if signers.len() != 1 {
        return Err(E::SignerCount(signers.len()));
    }
    let signer = &signers[0];
    let expected_version = match signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(_) => CmsVersion::V1,
        SignerIdentifier::SubjectKeyIdentifier(_) => CmsVersion::V3,
    };
    if signer.version != expected_version {
        return Err(E::StructureVersion);
    }
    if !is_sha256(&signer.digest_alg) {
        return Err(E::UnsupportedDigestAlgorithm);
    }
    // RFC 5758 section 3.2: ecdsa-with-SHA256 has absent parameters.
    if signer.signature_algorithm.oid != ECDSA_WITH_SHA256
        || signer.signature_algorithm.parameters.is_some()
    {
        return Err(E::UnsupportedSignatureAlgorithm);
    }
    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or(E::MissingSignedAttributes)?;

    let single = |oid: ObjectIdentifier, error: TimestampError| {
        let mut found = attrs.iter().filter(|a| a.oid == oid);
        match (found.next(), found.next()) {
            (Some(attr), None) if attr.values.len() == 1 => Ok(attr.values.get(0).ok_or(error)?),
            _ => Err(error),
        }
    };
    let content_type = single(ID_CONTENT_TYPE, E::ContentTypeAttribute)?
        .decode_as::<ObjectIdentifier>()
        .map_err(|_| E::ContentTypeAttribute)?;
    if content_type != ID_CT_TST_INFO {
        return Err(E::ContentTypeAttribute);
    }
    let digest = single(ID_MESSAGE_DIGEST, E::MessageDigestAttribute)?
        .decode_as::<OctetString>()
        .map_err(|_| E::MessageDigestAttribute)?;
    if digest.as_bytes() != Sha256::digest(tst_der).as_slice() {
        return Err(E::MessageDigestMismatch);
    }
    if attrs.iter().any(|a| a.oid == ID_SIGNING_CERTIFICATE) {
        // RFC 5816 permits the SHA-1 based attribute; it is not supported here.
        return Err(E::SigningCertificateAttribute);
    }
    let signing_cert = single(ID_SIGNING_CERTIFICATE_V2, E::SigningCertificateAttribute)?
        .decode_as::<SigningCertificateV2>()
        .map_err(|_| E::SigningCertificateAttribute)?;
    let first = signing_cert
        .certs
        .first()
        .ok_or(E::SigningCertificateAttribute)?;
    if first
        .hash_algorithm
        .as_ref()
        .is_some_and(|alg| alg.oid != ID_SHA256)
    {
        return Err(E::SigningCertificateAttribute);
    }
    if first.cert_hash.as_bytes() != Sha256::digest(tsa_certificate).as_slice() {
        return Err(E::SigningCertificateMismatch);
    }

    let cert = Certificate::from_der(tsa_certificate).map_err(|_| E::CertificateEncoding)?;
    let eku = extension(&cert, ID_CE_EXT_KEY_USAGE).ok_or(E::NotTimestampingCertificate)?;
    let usages = ExtendedKeyUsage::from_der(eku.extn_value.as_bytes())
        .map_err(|_| E::NotTimestampingCertificate)?;
    if !eku.critical || usages.0.as_slice() != [ID_KP_TIME_STAMPING] {
        return Err(E::NotTimestampingCertificate);
    }
    let matches_signer = match &signer.sid {
        SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer,
            serial_number,
        }) => {
            *issuer == cert.tbs_certificate.issuer
                && *serial_number == cert.tbs_certificate.serial_number
        }
        SignerIdentifier::SubjectKeyIdentifier(ski) => {
            extension(&cert, ID_CE_SUBJECT_KEY_IDENTIFIER)
                .and_then(|e| SubjectKeyIdentifier::from_der(e.extn_value.as_bytes()).ok())
                .is_some_and(|own| own == *ski)
        }
    };
    if !matches_signer {
        return Err(E::SignerMismatch);
    }

    let gen_time = tst.gen_time.to_unix_duration();
    let validity = &cert.tbs_certificate.validity;
    if gen_time < validity.not_before.to_unix_duration()
        || gen_time > validity.not_after.to_unix_duration()
    {
        return Err(E::CertificateNotValidAtGenTime);
    }

    let spki = &cert.tbs_certificate.subject_public_key_info;
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    if spki.algorithm.oid != ID_EC_PUBLIC_KEY || curve != Some(SECP256R1) {
        return Err(E::UnsupportedPublicKey);
    }
    let key = VerifyingKey::from_sec1_bytes(spki.subject_public_key.raw_bytes())
        .map_err(|_| E::UnsupportedPublicKey)?;
    let signature =
        Signature::from_der(signer.signature.as_bytes()).map_err(|_| E::SignatureInvalid)?;
    let signed = attrs.to_der().map_err(|_| E::Encoding)?;
    key.verify(&signed, &signature)
        .map_err(|_| E::SignatureInvalid)?;

    if tst.message_imprint.hash_algorithm.oid != algorithm.oid() {
        return Err(E::ImprintAlgorithmMismatch);
    }
    if tst.message_imprint.hashed_message.as_bytes() != expected_imprint {
        return Err(E::ImprintMismatch);
    }

    Ok(VerifiedTimestamp {
        gen_time_unix_seconds: gen_time.as_secs(),
        policy: tst.policy.to_string(),
        serial_number: tst.serial_number.as_bytes().to_vec(),
        imprint_algorithm: algorithm,
        imprint: expected_imprint.to_vec(),
        nonce: tst.nonce.map(|n| n.as_bytes().to_vec()),
        accuracy: tst.accuracy.map(|a| (a.seconds, a.millis, a.micros)),
    })
}
