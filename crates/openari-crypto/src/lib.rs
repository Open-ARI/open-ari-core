// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ncdents, LLC.
//! Signature verification building blocks for OpenARI.
//!
//! This crate implements the composite signature algorithm
//! `id-MLDSA87-RSA3072-PSS-SHA512` exactly as written in
//! `draft-ietf-lamps-pq-composite-sigs-13`. It is checked against the IETF
//! test vector published with that draft revision.
//!
//! This is **not** an Apple Reference Image profile. Apple has named the
//! scheme "MLDSA87-RSA-3072-PSS-SHA512", and Apple's Private Cloud Compute
//! source release of 2026-10-23 lists the signing algorithm
//! `MLDSA87_RSA3072_PSS_SHA512_DR13`. OpenARI reads "DR13" as draft revision
//! 13, but Apple has not documented that. The message bytes Apple signs, the
//! application context, trust anchors, and revocation are all unknown, so
//! `openari-core` does not call this crate and never reports an image as
//! verified.
//!
//! Only public-key operations are performed. No secret material is handled
//! outside tests.
#![forbid(unsafe_code)]

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87};
use rsa::{BigUint, Pss, RsaPublicKey, pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256, Sha512};
use std::fmt;

/// Specification revision this implementation follows.
pub const SPECIFICATION: &str = "draft-ietf-lamps-pq-composite-sigs-13";

/// Fixed prefix from the draft section "Prefix, Label and CTX":
/// ASCII "CompositeAlgorithmSignatures2025".
pub const PREFIX: &[u8; 32] = b"CompositeAlgorithmSignatures2025";

/// Composite ML-DSA-87 with RSA-3072 RSASSA-PSS and a SHA-512 pre-hash.
pub mod mldsa87_rsa3072_pss_sha512 {
    use super::*;

    /// Object identifier assigned in draft revision 13.
    pub const OID: &str = "1.3.6.1.5.5.7.6.52";
    /// Signature label. Also passed as the ML-DSA context string.
    pub const LABEL: &[u8] = b"COMPSIG-MLDSA87-RSA3072-PSS-SHA512";
    /// ML-DSA-87 public key length in bytes (FIPS 204).
    pub const MLDSA_PUBLIC_KEY_BYTES: usize = 2592;
    /// ML-DSA-87 signature length in bytes (FIPS 204).
    pub const MLDSA_SIGNATURE_BYTES: usize = 4627;
    /// RSA-3072 signature length in bytes.
    pub const RSA_SIGNATURE_BYTES: usize = 384;
    /// Composite signature length: ML-DSA-87 signature followed by the RSA signature.
    pub const SIGNATURE_BYTES: usize = MLDSA_SIGNATURE_BYTES + RSA_SIGNATURE_BYTES;
    /// SHA-512 pre-hash length.
    pub const PREHASH_BYTES: usize = 64;
    /// RSA modulus size required by this algorithm.
    pub const RSA_MODULUS_BITS: usize = 3072;
    /// RSASSA-PSS salt length for the 3072-bit parameter set (SHA-256 digest length).
    pub const RSA_PSS_SALT_BYTES: usize = 32;
    /// Upper bound on the DER RSAPublicKey component. A 3072-bit key with
    /// exponent 65537 encodes to 398 bytes; anything far larger is rejected
    /// before parsing.
    pub const MAX_RSA_PUBLIC_KEY_DER_BYTES: usize = 1024;
    /// Maximum application context length.
    pub const MAX_CONTEXT_BYTES: usize = 255;

    /// Returns the SHA-512 pre-hash `PH(M)` of a message.
    pub fn prehash(message: &[u8]) -> [u8; PREHASH_BYTES] {
        Sha512::digest(message).into()
    }

    /// Builds `M' = Prefix || Label || len(ctx) || ctx || PH(M)`.
    pub fn message_representative(
        prehash: &[u8; PREHASH_BYTES],
        context: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let context_len =
            u8::try_from(context.len()).map_err(|_| Error::ContextTooLong(context.len()))?;
        let mut representative =
            Vec::with_capacity(PREFIX.len() + LABEL.len() + 1 + context.len() + PREHASH_BYTES);
        representative.extend_from_slice(PREFIX);
        representative.extend_from_slice(LABEL);
        representative.push(context_len);
        representative.extend_from_slice(context);
        representative.extend_from_slice(prehash);
        Ok(representative)
    }

    /// A deserialized composite public key.
    #[derive(Clone)]
    pub struct VerifyingKey {
        mldsa: ml_dsa::VerifyingKey<MlDsa87>,
        rsa: RsaPublicKey,
    }

    impl fmt::Debug for VerifyingKey {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("VerifyingKey")
                .field("algorithm", &OID)
                .field("rsa_modulus_bits", &self.rsa.n().bits())
                .finish_non_exhaustive()
        }
    }

    impl VerifyingKey {
        /// Deserializes `mldsaPK || tradPK`, where `tradPK` is a DER
        /// RSAPublicKey (RFC 8017). Rejects any modulus other than 3072 bits
        /// and any exponent other than 65537, which the draft permits.
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
            if bytes.len() <= MLDSA_PUBLIC_KEY_BYTES
                || bytes.len() > MLDSA_PUBLIC_KEY_BYTES + MAX_RSA_PUBLIC_KEY_DER_BYTES
            {
                return Err(Error::PublicKeyLength(bytes.len()));
            }
            let (mldsa_bytes, rsa_der) = bytes.split_at(MLDSA_PUBLIC_KEY_BYTES);
            let encoded = EncodedVerifyingKey::<MlDsa87>::try_from(mldsa_bytes)
                .map_err(|_| Error::PublicKeyLength(bytes.len()))?;
            let mldsa = ml_dsa::VerifyingKey::<MlDsa87>::decode(&encoded);
            let rsa =
                RsaPublicKey::from_pkcs1_der(rsa_der).map_err(|_| Error::RsaPublicKeyEncoding)?;
            let bits = rsa.n().bits();
            if bits != RSA_MODULUS_BITS {
                return Err(Error::RsaModulusBits(bits));
            }
            if *rsa.e() != BigUint::from(65_537u32) {
                return Err(Error::RsaExponent);
            }
            Ok(Self { mldsa, rsa })
        }

        /// Verifies `signature` over `message` with application context `context`.
        ///
        /// `Ok(())` means both component signatures verified. Any error means
        /// the signature is invalid or could not be evaluated.
        pub fn verify(
            &self,
            message: &[u8],
            context: &[u8],
            signature: &[u8],
        ) -> Result<(), Error> {
            self.verify_prehash(&prehash(message), context, signature)
        }

        /// Verifies a signature given an externally computed SHA-512 pre-hash,
        /// as described in the draft section "External Pre-hashing".
        pub fn verify_prehash(
            &self,
            prehash: &[u8; PREHASH_BYTES],
            context: &[u8],
            signature: &[u8],
        ) -> Result<(), Error> {
            let representative = message_representative(prehash, context)?;
            if signature.len() != SIGNATURE_BYTES {
                return Err(Error::SignatureLength(signature.len()));
            }
            let (mldsa_bytes, rsa_signature) = signature.split_at(MLDSA_SIGNATURE_BYTES);
            let encoded = EncodedSignature::<MlDsa87>::try_from(mldsa_bytes)
                .map_err(|_| Error::SignatureLength(signature.len()))?;
            let mldsa_signature = ml_dsa::Signature::<MlDsa87>::decode(&encoded)
                .ok_or(Error::MlDsaSignatureEncoding)?;
            if !self
                .mldsa
                .verify_with_context(&representative, LABEL, &mldsa_signature)
            {
                return Err(Error::MlDsaSignatureInvalid);
            }
            let digest = Sha256::digest(&representative);
            self.rsa
                .verify(
                    Pss::new_with_salt::<Sha256>(RSA_PSS_SALT_BYTES),
                    &digest,
                    rsa_signature,
                )
                .map_err(|_| Error::RsaSignatureInvalid)
        }
    }
}

/// Reasons a composite signature was not accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    ContextTooLong(usize),
    PublicKeyLength(usize),
    RsaPublicKeyEncoding,
    RsaModulusBits(usize),
    RsaExponent,
    SignatureLength(usize),
    MlDsaSignatureEncoding,
    MlDsaSignatureInvalid,
    RsaSignatureInvalid,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContextTooLong(len) => write!(f, "context has {len} bytes; limit is 255"),
            Self::PublicKeyLength(len) => {
                write!(f, "composite public key has invalid length {len}")
            }
            Self::RsaPublicKeyEncoding => {
                f.write_str("RSA public key is not valid DER RSAPublicKey")
            }
            Self::RsaModulusBits(bits) => write!(f, "RSA modulus has {bits} bits; 3072 required"),
            Self::RsaExponent => f.write_str("RSA public exponent is not 65537"),
            Self::SignatureLength(len) => {
                write!(f, "composite signature has {len} bytes; 5011 required")
            }
            Self::MlDsaSignatureEncoding => f.write_str("ML-DSA-87 signature encoding is invalid"),
            Self::MlDsaSignatureInvalid => f.write_str("ML-DSA-87 component signature is invalid"),
            Self::RsaSignatureInvalid => f.write_str("RSA-PSS component signature is invalid"),
        }
    }
}

impl std::error::Error for Error {}
