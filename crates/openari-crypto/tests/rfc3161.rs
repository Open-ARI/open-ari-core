// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! RFC 3161 checks against synthetic tokens produced by `openssl ts`.
//! Expected values come from `openssl ts -reply -token_in -text`, and both
//! tokens pass `openssl ts -verify`. See tests/vectors/rfc3161/README.md.

use openari_crypto::rfc3161::{
    ImprintAlgorithm, MAX_TOKEN_BYTES, TimestampError, VerifiedTimestamp, verify_token,
};

const TOKEN: &[u8] = include_bytes!("vectors/rfc3161/token.der");
const TOKEN_NO_CERT: &[u8] = include_bytes!("vectors/rfc3161/token-nocert.der");
const TSA: &[u8] = include_bytes!("vectors/rfc3161/tsa.der");
const OTHER_TSA: &[u8] = include_bytes!("vectors/rfc3161/other.der");
const CA: &[u8] = include_bytes!("vectors/rfc3161/ca.der");
const MESSAGE: &[u8] = include_bytes!("vectors/rfc3161/message.txt");

fn imprint() -> Vec<u8> {
    ImprintAlgorithm::Sha256.digest(MESSAGE)
}

#[test]
fn openssl_tokens_verify_with_expected_fields() {
    let verified = verify_token(TOKEN, ImprintAlgorithm::Sha256, &imprint(), TSA).unwrap();
    assert_eq!(
        verified,
        VerifiedTimestamp {
            gen_time_unix_seconds: 1_793_462_265,
            policy: "1.3.6.1.4.1.99999.1".into(),
            serial_number: vec![0x02],
            imprint_algorithm: ImprintAlgorithm::Sha256,
            imprint: imprint(),
            nonce: Some(vec![0x5a, 0xe0, 0xe7, 0xa6, 0x1b, 0xfc, 0x21, 0x32]),
            accuracy: Some((Some(1), None, None)),
        }
    );
    let no_cert = verify_token(TOKEN_NO_CERT, ImprintAlgorithm::Sha256, &imprint(), TSA).unwrap();
    assert_eq!(no_cert.gen_time_unix_seconds, 1_793_462_266);
    assert_eq!(no_cert.serial_number, [0x03]);
    assert_eq!(no_cert.nonce, None);
}

#[test]
fn wrong_imprint_or_certificate_is_rejected() {
    let mut other = imprint();
    other[0] ^= 1;
    assert_eq!(
        verify_token(TOKEN, ImprintAlgorithm::Sha256, &other, TSA).unwrap_err(),
        TimestampError::ImprintMismatch
    );
    assert_eq!(
        verify_token(TOKEN, ImprintAlgorithm::Sha512, &imprint(), TSA).unwrap_err(),
        TimestampError::ImprintAlgorithmMismatch
    );
    for cert in [OTHER_TSA, CA] {
        assert_eq!(
            verify_token(TOKEN, ImprintAlgorithm::Sha256, &imprint(), cert).unwrap_err(),
            TimestampError::SigningCertificateMismatch
        );
    }
    assert_eq!(
        verify_token(TOKEN, ImprintAlgorithm::Sha256, &imprint(), b"not a cert").unwrap_err(),
        TimestampError::SigningCertificateMismatch
    );
}

#[test]
fn altered_tokens_are_rejected() {
    // Change one byte of the message imprint inside TSTInfo: the signed
    // message-digest attribute no longer matches.
    let digest = imprint();
    let at = TOKEN
        .windows(digest.len())
        .position(|w| w == digest.as_slice())
        .unwrap();
    let mut token = TOKEN.to_vec();
    token[at] ^= 1;
    assert_eq!(
        verify_token(&token, ImprintAlgorithm::Sha256, &digest, TSA).unwrap_err(),
        TimestampError::MessageDigestMismatch
    );

    // Change the last byte, inside the ECDSA signature.
    let mut token = TOKEN.to_vec();
    *token.last_mut().unwrap() ^= 1;
    assert_eq!(
        verify_token(&token, ImprintAlgorithm::Sha256, &digest, TSA).unwrap_err(),
        TimestampError::SignatureInvalid
    );

    for length in 0..TOKEN.len() {
        assert!(verify_token(&TOKEN[..length], ImprintAlgorithm::Sha256, &digest, TSA).is_err());
    }
    let oversized = vec![0; MAX_TOKEN_BYTES + 1];
    assert_eq!(
        verify_token(&oversized, ImprintAlgorithm::Sha256, &digest, TSA).unwrap_err(),
        TimestampError::TokenTooLarge(MAX_TOKEN_BYTES + 1)
    );
}

/// Byte range of the token's embedded `certificates` field, from
/// `openssl asn1parse`: the [0] element at offset 164 with a 4-byte header
/// and 432 bytes of content. It is unsigned and not used for verification,
/// because the caller supplies the certificate.
const EMBEDDED_CERTIFICATES: std::ops::Range<usize> = 164..600;

#[test]
fn every_signed_or_structural_byte_change_is_rejected() {
    let digest = imprint();
    assert_eq!(&TOKEN[164..168], &[0xa0, 0x82, 0x01, 0xb0]);
    for index in 0..TOKEN.len() {
        let mut token = TOKEN.to_vec();
        token[index] ^= 0x01;
        if verify_token(&token, ImprintAlgorithm::Sha256, &digest, TSA).is_ok() {
            assert!(
                EMBEDDED_CERTIFICATES.contains(&index),
                "changing byte {index} was not detected"
            );
        }
    }
}
