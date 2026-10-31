# Dependencies

Status: reviewed 2026-10-31. Lockfiles pin exact versions. Re-review on every
major or minor upgrade of a cryptographic dependency.

## Direct dependencies

| Crate | Used by | Purpose | License |
| --- | --- | --- | --- |
| `serde`, `serde_json` | core, CLI, FFI | Report serialization | MIT OR Apache-2.0 |
| `clap` | CLI | Argument parsing | MIT OR Apache-2.0 |
| `sha2` 0.10 | core, crypto | SHA-256 digests in structure reports; SHA-256 and SHA-512 in composite verification | MIT OR Apache-2.0 |
| `ml-dsa` 0.1.1 | crypto | ML-DSA-87 verification (FIPS 204) | Apache-2.0 OR MIT |
| `rsa` 0.9.10 | crypto | RSASSA-PSS verification (RFC 8017) | MIT OR Apache-2.0 |

All are RustCrypto or widely used Rust ecosystem crates. Transitive
dependencies are under MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, Unicode-3.0,
or Unlicense terms, each offered alone or as an option. Generate a full
inventory before distributing binaries; see THIRD_PARTY_NOTICES.txt.

`openari-core` does not depend on `openari-crypto`. Applications that only need
inspection or structure listings do not build the signature libraries.

## Cryptographic dependency review

**ml-dsa 0.1.1.** Pure Rust, `forbid(unsafe_code)` upstream. Provides FIPS 204
verification with an explicit context string, which composite ML-DSA requires.
No independent audit is known. Correctness for this project rests on the IETF
draft-13 test vector and negative tests in `crates/openari-crypto/tests`.

**rsa 0.9.10.** Latest stable release. Affected by RUSTSEC-2023-0071 (Marvin
timing side channel), which concerns private-key operations. OpenARI performs
only public-key PSS verification, so the advisory does not apply to library
code. `.cargo/audit.toml` records a scoped exception, and the test
`tests/public_key_only.rs` fails if library code adds private-key use. The
0.10 release candidates were not chosen: the advisory lists them as affected
too, and a release candidate adds API churn without a security benefit here.

**Alternatives considered.** `aws-lc-rs` offers RSA and ML-DSA backed by
AWS-LC, but requires a C and CMake toolchain on every CI platform and exposes
ML-DSA through an unstable API. OpenSSL 3.5 adds ML-DSA but would add a system
library dependency and complicate Windows builds. Either can be evaluated
later as an alternative provider. The architecture requires identical
decisions from every approved provider.

## Advisory policy

CI runs `cargo audit --deny warnings` on every pull request and weekly. An
exception needs an entry in `.cargo/audit.toml` with the reason, the code it
is limited to, a review date, and a test or check that keeps it limited.
