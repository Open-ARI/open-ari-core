# Format status

Last reviewed: 2026-10-31. Supported Apple ARI revisions: **none**.

Apple has published a design description, user documentation, and a viewing
API. It has not published a file format specification, public keys or
certificates, revocation list format, or test images. Those are the inputs a
verifier needs, so `openari verify` still returns `indeterminate`.

Confidence labels: **documented** means stated by Apple. **Observed** means
seen in Apple-published code or a third-party sample, not stated as a format
rule. **Unresolved** means no usable evidence yet. Observed encodings do not
become normative because one source uses them.

## Sources reviewed

| Source | Date | Retrieved | What it establishes |
| --- | --- | --- | --- |
| [Apple Security Research: Apple Reference Image](https://security.apple.com/blog/apple-reference-image/) | 2026-09-15 | 2026-10-31 | Capture, development, signing, time, and revocation design (documented) |
| [Apple Support 128064](https://support.apple.com/en-us/128064) | 2026-09-17 | 2026-10-31 | Storage sizes, sharing and transfer behavior, network needs (documented) |
| [iPhone User Guide: view reference images](https://support.apple.com/guide/iphone/view-reference-images-iphwvm89mgxhnqr/ios) | 2026 | 2026-10-31 | Deferred development when offline, transfer settings (documented) |
| [Apple Newsroom: iPhone 18 Pro](https://www.apple.com/newsroom/2026/09/apple-debuts-iphone-18-pro-and-iphone-18-pro-max/) | 2026-09-09 | 2026-10-31 | Third-party APIs are for viewing (documented) |
| [PhotoKit `PHReferenceImageInfo`](https://developer.apple.com/documentation/photos/phreferenceimageinfo) | 2026 | 2026-10-31 | Detection API accepts HEIC, JPEG, or DNG files (documented) |
| [apple/security-pcc](https://github.com/apple/security-pcc), release "Private Cloud Compute 2026-10-23" | 2026-10-23 | 2026-10-31 | Signing-service algorithm identifier and API shape (observed) |
| [draft-ietf-lamps-pq-composite-sigs-13](https://github.com/lamps-wg/draft-composite-sigs/tree/draft-ietf-lamps-pq-composite-sigs-13) | 2025-10-21 | 2026-10-31 | Composite ML-DSA construction, sizes, OIDs, test vectors |

Secondary sources are listed under [Unconfirmed claims](#unconfirmed-claims).
The apple/security-pcc material is under a restrictive Apple license. OpenARI
records facts about it and does not copy or redistribute its code.

## What Apple documents

**Capture (secure digital negative).**

- Each image sensor generates an ECDSA P-256 key pair at manufacture. A
  factory certificate authority certifies the public key and records it in
  the device hardware manifest. The Secure Enclave has a separate key certified
  by Apple's Basic Attestation Authority (BAA) under another CA. A third CA
  signs the device manifest that binds the sensor key and Secure Enclave key.
- In Reference mode the sensor accepts one input from the OS: a SHA-256 digest
  of the latest timestamp token, the device manifest, and the secure boot
  manifest. The sensor embeds it "at a fixed location in the captured frame's
  metadata" and signs it with the pixels.
- The Secure Enclave signs a commitment to the sensor signature together with
  OS-derived metadata (digital zoom, exposure, lens parameters).
- The negative is stored in DNG format, linked to the conventional photo. It
  contains the pixels, both signatures, the timestamps, the metadata, the device
  manifest, and the secure boot manifest. It can be shared undeveloped.

**Capture time.**

- Lower bound: an RFC 3161 timestamp token from Apple's timestamp service,
  signed with ECDSA P-256 over SHA-256, delivered with the APNs heartbeat
  (about every 15 minutes on average). The device keeps the latest one.
- Upper bound: a second RFC 3161 token over a SHA-256 commitment to the Secure
  Enclave signature, requested after capture. If the device is offline, a
  background process inserts it later.
- During development, if the lower bound fails verification PCC substitutes
  2026-03-31. If the upper bound is missing or invalid PCC substitutes the
  development time. A verifier must therefore report whether each bound is a
  verified token or a substitute.

**Development and the reference image.**

- Development requires a network connection and runs in Private Cloud Compute.
  PCC verifies the sensor, Secure Enclave, and manifest chains and checks that
  the sensor and Secure Enclave belong to one device.
- PCC computes a confidence score with a model whose weights are not published,
  develops the image, compresses it as JPEG, and hashes the JPEG. That hash is
  the value signed and "supplies the bits used for the photo GUID".
- A companion service records the GUID, hash, score, and sensor ID and checks
  sensor revocation. Apple's signing service then signs the commitment with
  the composite MLDSA87-RSA-3072-PSS-SHA512 scheme. The signature is embedded
  in the JPEG.
- The developed negative moves to Recently Deleted and is purged after 30 days
  unless recovered.

**Verification on Apple devices.** When displayed, the client verifies the
final signature on the JPEG and checks that its photo GUID is not on the
current revocation list. Apple devices fetch revocation lists on a regular
cadence and check locally.

**Distribution.** Users choose whether to include the reference image when
sharing. "Transfer Reference Image" includes the data when copying to a Mac or
PC. Viewing requires iOS 27, iPadOS 27, or macOS 27. Approximate sizes:
undeveloped data 8 to 10 MB (12 or 24 MP) or 35 to 40 MB (48 MP); developed
data about 3 MB or 7 to 8 MB. An undeveloped negative may include the device
serial number and the full frame regardless of zoom.

**Platform API.** `PHReferenceImageInfo(fileURL:)` accepts a HEIC, JPEG, or DNG
file, and `imageContainsReferenceImageData` reports whether Reference Image data
is present. `photosReferenceImageViewer` presents Apple's viewer. Its completion
returns `Result<PHAsset, Error>` and exposes no verification outcome.

## Evidence register

| Requirement | Evidence | Status |
| --- | --- | --- |
| Version detection | None published | Unresolved |
| Container placement | Signature embedded in the JPEG; HEIC, JPEG, and DNG files can carry the data; segment or box names unknown | Partly documented |
| Signed bytes | Apple hashes the compressed JPEG, then embeds the signature. The exclusion rule for the signature bytes, the hash function, and any context string are unknown | Unresolved |
| Composite verification | Scheme named by Apple. PCC source lists `MLDSA87_RSA3072_PSS_SHA512_DR13` and signs a pre-computed digest | Profile observed: draft-13 implemented in `openari-crypto`; Apple binding unresolved |
| Signature size | 5011 bytes reported by a third-party teardown, equal to the draft-13 size (4627 + 384) | Observed (secondary) |
| Trust | CA roles documented. Signing-service responses carry a leaf-first DER chain. No certificates published | Unresolved |
| Capture bounds | RFC 3161, ECDSA P-256, SHA-256; substitution rules documented. Encoding inside the reference image unknown | Mechanism documented; encoding unresolved |
| Revocation | Per photo and per sensor; GUID derived from the JPEG hash; on-device lists. List format, authentication, freshness, and GUID derivation unpublished | Mechanism documented; interoperability unresolved |
| DNG negative | Contents documented; tags and encodings unknown | Partly documented |
| Conformance | No redistributable positive files | Unavailable |

Each future finding must include a source URL or sample hash, retrieval date,
revision, provenance, and confidence. Store no invented Apple version number,
segment name, or OID as a supported profile.

## Implications for an offline verifier

- **Revocation could be checked offline.** The GUID is derived from the image
  hash, so a verifier can compute it locally. Offline revocation still needs an
  authenticated, published list, which does not exist.
- **The negative uses standard primitives.** ECDSA P-256 and RFC 3161 tokens are
  public standards, but verifying them needs Apple's CA certificates and the DNG
  layout, neither of which is published.
- **Apple's privacy design limits what a verifier should expose.** A developed
  reference image carries Apple's signature, not a device credential. An
  undeveloped negative carries device-unique certificates, so two negatives can
  be linked to one device without Apple's help.

## Unconfirmed claims

| Claim | Source | Status |
| --- | --- | --- |
| Apple plans to publish documentation "next year" (written in 2026) so Windows, Android, and browsers can verify reference images | [c2paviewer.com](https://c2paviewer.com/articles/apple-reference-image-vs-c2pa) | No Apple source found. The newsroom release mentions only viewing APIs |
| Apple intends to support verification outside its ecosystem | [Tech Policy Press](https://www.techpolicy.press/will-apples-reference-image-feature-help-defend-against-ai-manipulation/), author briefed by Apple | Stated intention, no detail |
| A reference JPEG holds a 5,011-byte signature and an Apple certificate chain; some apps strip it | [Medium teardown](https://medium.com/macoclock/i-took-apples-new-unfakeable-photo-apart-in-terminal-a-deep-dive-into-apple-reference-image-e8af2210423e) | Article not reviewed in full |

No public parser, verifier, or sample corpus was found on GitHub as of
2026-10-31. ExifTool 13.60 (2026-10-28) does not decode Reference Image data.

## Compatibility matrix

| Apple format | Detect | Inspect payload | Verify | Trust/revocation |
| --- | --- | --- | --- | --- |
| Unknown revision | No ARI detector yet | Structure listing only | No | No |
| Future documented revision | Planned | Planned | Planned | Pending authoritative inputs |

`openari structure` lists JPEG segments, TIFF/DNG directories, and ISOBMFF/HEIC
boxes with offsets and digests. It does not identify which of them hold ARI data.
`openari-crypto` verifies draft-13 composite signatures against IETF test
vectors, and verifies RFC 3161 timestamp tokens signed with ECDSA P-256 against
a caller-supplied certificate. None of these is connected to `verify`.

Add actual revision identifiers only after their meaning is confirmed. Every
entry must name fixtures, supported algorithms, and remaining limitations.

OpenARI will verify evidence made available by Apple's system. It will not
recreate Apple's capture hardware, private signing service, or PCC confidence
assessment. A future application receipt is an OpenARI verification receipt,
not a new Apple attestation.
