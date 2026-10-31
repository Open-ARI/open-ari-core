# Roadmap

This is an implementation plan, not a claim of available verification support.
Milestones depend on evidence and review rather than launch dates.

| Milestone | Work | Exit criteria |
| --- | --- | --- |
| M0: foundation | Workspace, CLI/C ABI prototype, policies, website, CI, sponsor links | Tests pass; every verification stays indeterminate; no invented Apple profile |
| M1: format evidence | Acquire specs and permitted samples; record encodings, trust, time, revocation | Evidence register resolved for one complete public JPEG profile; independent expected results |
| M2: bounded inspection | JPEG extraction, DNG inspection where documented, profile detection, forensic output | Exact ranges and limits tested; fuzz corpus covers ambiguity, offsets and truncation |
| M3: offline verification | Approved composite crypto, trust policy, snapshot inputs, report context | Positive/negative conformance; unknown versions and downgrade cases fail closed; security review |
| M4: SDK and upload integration | Stable C ABI, Python/Go first, .NET/Java next, framework examples | Packaged native artifacts pass installed-package tests; consistent outcomes across bindings |
| M5: trust operations and performance | Authenticated updater, freshness/rollback, caches, CPU dispatch, benchmarks | Offline/stale/update-failure tests; backend parity; published reproducible performance results |
| M6: production release | Independent audit, release attestations, SBOMs, docs and support policy | Audit findings resolved or clearly scoped; release gates pass on advertised platforms |
| M7: optional receipts/services | Local sidecar and operator-signed verification receipts | Separate protocol review, privacy model, key lifecycle, replay/expiry semantics |

## Progress as of 2026-10-31

| Milestone | State |
| --- | --- |
| M0 | Complete |
| M1 | In progress. Apple's design is documented; the format, keys, and revocation list are not. See [format status](format-status.md) |
| M2 | Started. `openari structure` lists JPEG, TIFF/DNG, and ISOBMFF/HEIC structure with fuzzing. No ARI detection |
| M3 | Started. `openari-crypto` implements composite ML-DSA-87 + RSA-3072-PSS (draft-13) against IETF vectors. Not connected to verification |

## Work available while specifications are pending

- Refine the threat model, input budgets, report schema, and version negotiation.
- Extend the structure walkers (for example HEIF item locations) against their
  public specifications without labeling generic parsing as ARI support.
- Verify RFC 3161 timestamp tokens offline with explicitly supplied
  certificates. Apple documents RFC 3161 with ECDSA P-256 for capture bounds.
- Build fixture tooling, native packaging, and upload examples.
- Add a macOS 27 helper that records `PHReferenceImageInfo` results for
  fixture manifests as an independent presence oracle, not a validity oracle.
- Evaluate alternative crypto providers against the same test vectors; reserve
  ARI compatibility claims for confirmed Apple profiles.
- Define benchmark workloads and test the ABI from real language runtimes.

## Repository plan

Keep engine, CLI, binding prototypes, small fixtures, and design documents in
`open-ari-core`. Keep public docs in `website` and shared community policies in
`.github`. Split SDK repos when independent releases or maintainers need them.
Move a large corpus to `test-vectors` with immutable releases and checksums;
consumers need not use Git submodules. Preserve fixture provenance and licenses.

[OpenARI Capture](https://github.com/open-ari/open-ari-capture) is a separate
research track for independent camera signing, a Pi prototype, and manufacturer
integration. Its [milestones](https://github.com/open-ari/open-ari-capture/milestones)
do not change Apple ARI support or the release gates above. Capture profiles,
trust roots, and evidence claims remain distinct from Apple attestations and
operator verification receipts.

## Decisions still needed

Authoritative Apple profile access, positive fixture rights, public trust and
revocation distribution, supported platform minima, cryptographic provider,
production size/time budgets, maintenance window, and independent audit scope.
Record these in reviewed design changes before enabling a supported profile.
