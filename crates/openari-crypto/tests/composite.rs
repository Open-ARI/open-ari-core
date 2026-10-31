// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! Checks against the draft-ietf-lamps-pq-composite-sigs-13 test vector.

use openari_crypto::{
    Error,
    mldsa87_rsa3072_pss_sha512::{
        LABEL, MLDSA_PUBLIC_KEY_BYTES, MLDSA_SIGNATURE_BYTES, SIGNATURE_BYTES, VerifyingKey,
        message_representative, prehash,
    },
};
use rand_core::OsRng;
use rsa::{
    Pss, RsaPrivateKey, RsaPublicKey,
    pkcs1::{DecodeRsaPrivateKey, EncodeRsaPublicKey},
};
use sha2::{Digest, Sha256};

struct Vector {
    message: Vec<u8>,
    public_key: Vec<u8>,
    signature: Vec<u8>,
    secret_key: Vec<u8>,
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn vector() -> Vector {
    let json: serde_json::Value = serde_json::from_str(include_str!(
        "vectors/draft13-mldsa87-rsa3072-pss-sha512.json"
    ))
    .unwrap();
    assert_eq!(json["tag"], "draft-ietf-lamps-pq-composite-sigs-13");
    assert_eq!(json["tcId"], "id-MLDSA87-RSA3072-PSS-SHA512");
    assert_eq!(json["ctx"], "");
    let field = |name: &str| hex(json[name].as_str().unwrap());
    Vector {
        message: field("m"),
        public_key: field("pk"),
        signature: field("s"),
        secret_key: field("sk"),
    }
}

#[test]
fn ietf_vector_verifies() {
    let v = vector();
    assert_eq!(v.message, b"The quick brown fox jumps over the lazy dog.");
    assert_eq!(v.signature.len(), SIGNATURE_BYTES);
    assert_eq!(SIGNATURE_BYTES, 5011);
    let key = VerifyingKey::from_bytes(&v.public_key).unwrap();
    key.verify(&v.message, b"", &v.signature).unwrap();
    key.verify_prehash(&prehash(&v.message), b"", &v.signature)
        .unwrap();
}

#[test]
fn altered_inputs_are_rejected() {
    let v = vector();
    let key = VerifyingKey::from_bytes(&v.public_key).unwrap();

    let mut message = v.message.clone();
    message[0] ^= 1;
    assert!(key.verify(&message, b"", &v.signature).is_err());
    assert!(key.verify(&v.message, b"ctx", &v.signature).is_err());

    for index in [0, 1000, MLDSA_SIGNATURE_BYTES - 1] {
        let mut signature = v.signature.clone();
        signature[index] ^= 0x80;
        let error = key.verify(&v.message, b"", &signature).unwrap_err();
        assert!(matches!(
            error,
            Error::MlDsaSignatureInvalid | Error::MlDsaSignatureEncoding
        ));
    }
    for index in [MLDSA_SIGNATURE_BYTES, SIGNATURE_BYTES - 1] {
        let mut signature = v.signature.clone();
        signature[index] ^= 0x01;
        assert_eq!(
            key.verify(&v.message, b"", &signature).unwrap_err(),
            Error::RsaSignatureInvalid
        );
    }

    assert_eq!(
        key.verify(&v.message, b"", &v.signature[..SIGNATURE_BYTES - 1])
            .unwrap_err(),
        Error::SignatureLength(SIGNATURE_BYTES - 1)
    );
    let mut longer = v.signature.clone();
    longer.push(0);
    assert_eq!(
        key.verify(&v.message, b"", &longer).unwrap_err(),
        Error::SignatureLength(SIGNATURE_BYTES + 1)
    );
    assert_eq!(
        key.verify(&v.message, &[0; 256], &v.signature).unwrap_err(),
        Error::ContextTooLong(256)
    );
}

#[test]
fn malformed_public_keys_are_rejected() {
    let v = vector();
    assert!(matches!(
        VerifyingKey::from_bytes(&v.public_key[..MLDSA_PUBLIC_KEY_BYTES]),
        Err(Error::PublicKeyLength(_))
    ));
    let mut bad_der = v.public_key.clone();
    bad_der[MLDSA_PUBLIC_KEY_BYTES] ^= 0xff;
    assert_eq!(
        VerifyingKey::from_bytes(&bad_der).unwrap_err(),
        Error::RsaPublicKeyEncoding
    );

    let small = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let mut wrong_size = v.public_key[..MLDSA_PUBLIC_KEY_BYTES].to_vec();
    wrong_size.extend_from_slice(
        RsaPublicKey::from(&small)
            .to_pkcs1_der()
            .unwrap()
            .as_bytes(),
    );
    assert_eq!(
        VerifyingKey::from_bytes(&wrong_size).unwrap_err(),
        Error::RsaModulusBits(2048)
    );
}

/// Signs with the IETF test key to cover a non-empty context, which the
/// published vector does not.
#[test]
fn round_trip_with_context() {
    let v = vector();
    let seed = ml_dsa::Seed::try_from(&v.secret_key[..32]).unwrap();
    let mldsa = ml_dsa::SigningKey::<ml_dsa::MlDsa87>::from_seed(&seed);
    let rsa = RsaPrivateKey::from_pkcs1_der(&v.secret_key[32..]).unwrap();
    let key = VerifyingKey::from_bytes(&v.public_key).unwrap();

    let context = b"openari-test-context";
    let representative = message_representative(&prehash(&v.message), context).unwrap();
    let mut signature = mldsa
        .expanded_key()
        .sign_deterministic(&representative, LABEL)
        .unwrap()
        .encode()
        .to_vec();
    signature.extend(
        rsa.sign_with_rng(
            &mut OsRng,
            Pss::new_with_salt::<Sha256>(32),
            &Sha256::digest(&representative),
        )
        .unwrap(),
    );

    key.verify(&v.message, context, &signature).unwrap();
    assert!(key.verify(&v.message, b"", &signature).is_err());

    let mut wrong_salt = signature[..MLDSA_SIGNATURE_BYTES].to_vec();
    wrong_salt.extend(
        rsa.sign_with_rng(
            &mut OsRng,
            Pss::new_with_salt::<Sha256>(20),
            &Sha256::digest(&representative),
        )
        .unwrap(),
    );
    assert_eq!(
        key.verify(&v.message, context, &wrong_salt).unwrap_err(),
        Error::RsaSignatureInvalid
    );
}
