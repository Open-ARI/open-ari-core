# Changelog

## Unreleased

- Add `openari structure` and `openari_core::structure`: bounded listings of JPEG
  segments, TIFF/DNG directories, and ISOBMFF/HEIC boxes and items, with a
  separate report schema (`schemas/structure-report-v1.json`) and fuzz target.
- Add `openari-crypto` with composite ML-DSA-87 + RSA-3072-PSS-SHA512 verification
  per draft-ietf-lamps-pq-composite-sigs-13, tested against the IETF vector.
  It is not connected to `verify`.
- Add `openari_crypto::rfc3161`: offline verification of RFC 3161 timestamp
  tokens signed with ECDSA P-256 against a caller-supplied certificate, with
  OpenSSL-generated fixtures and a fuzz target.
- Record Apple's published Reference Image design and the PCC signing-service
  identifier in the format evidence register. No Apple revision is supported.
- Add the dependency review and a scoped RUSTSEC-2023-0071 exception.
- Update serde_json to 1.0.154.

- Name the CLI executable `openari` and its Rust package `openari-cli`.
- Name the native library target `openari_ffi` to avoid Windows debug-symbol collisions.

- Add the Rust workspace, bounded container hints, JSON reports, and CLI.
- Add an experimental versioned C interface and C consumer test.
- Document format research, compatibility, security, upload integration, and performance plans.
- No Apple ARI revision is supported; verification remains indeterminate.
