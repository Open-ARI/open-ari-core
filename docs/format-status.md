# Format status

Last reviewed: 2026-09-16. Supported Apple ARI revisions: **none**.

The [Apple announcement](https://security.apple.com/blog/apple-reference-image)
describes secure DNG negatives, developed JPEGs, capture-time bounds, composite
MLDSA87-RSA-3072-PSS-SHA512 signatures, and photo revocation. It does not establish
the binary interoperability contract required by this implementation.

The local scaffold recognizes only container prefixes. A TIFF prefix does not
identify a DNG, and a JPEG prefix does not establish a structurally valid JPEG.

## Evidence register

| Requirement | Evidence needed before implementation | Status |
| --- | --- | --- |
| Version detection | Authoritative version field, encoding, and ambiguity rules | Unresolved |
| JPEG signature extraction | Markers, chunking, duplicate rules, byte ranges | Unresolved |
| Composite verification | Encoding, OIDs, context/domain separation, hashing, RSA-PSS parameters | Scheme named; profile unresolved |
| Trust | Authoritative keys/roots, usages, constraints, rotation, expiry rules | Unresolved |
| Capture bounds | Public representation and binding to the signed image | Unresolved |
| Revocation | Distribution, authentication, freshness, rollback, GUID derivation | Mechanism described; interoperability unresolved |
| DNG inspection | Tags, offsets, signature encodings, metadata coverage | Unresolved |
| Conformance | Redistributable positive files and independent expected results | Unavailable locally |

Each future finding must include a source URL or sample hash, retrieval date,
revision, provenance, and confidence: documented, observed, or unresolved.
Observed encodings do not become normative merely because one sample uses them.
Store no invented Apple version number or guessed OID as a supported profile.

## Compatibility matrix

| Apple format | Detect | Inspect payload | Verify | Trust/revocation |
| --- | --- | --- | --- | --- |
| Unknown revision | No ARI detector yet | No | No | No |
| Future documented revision | Planned | Planned | Planned | Pending authoritative inputs |

Add actual revision identifiers only after their meaning is confirmed. Every
entry must name fixtures, supported algorithms, and remaining limitations.

OpenARI will verify evidence made available by Apple's system. It will not
recreate Apple's capture hardware, private signing service, or PCC confidence
assessment. A future application receipt is an OpenARI verification receipt,
not a new Apple attestation.
