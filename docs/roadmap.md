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

## Work available while specifications are pending

- Refine the threat model, input budgets, report schema, and version negotiation.
- Build bounded container parsers against their actual specifications without
  labeling generic JPEG/TIFF parsing as ARI support.
- Build fixture tooling, parser fuzzing, native packaging, and upload examples.
- Evaluate crypto candidates against standard test vectors; reserve ARI
  compatibility claims for confirmed Apple profiles.
- Define benchmark workloads and test the ABI from real language runtimes.

## Repository plan

Keep engine, CLI, binding prototypes, small fixtures, and design documents in
`open-ari-core`. Keep public docs in `website` and shared community policies in
`.github`. Split SDK repos when independent releases or maintainers need them.
Move a large corpus to `test-vectors` with immutable releases and checksums;
consumers need not use Git submodules. Preserve fixture provenance and licenses.

## Decisions still needed

Authoritative Apple profile access, positive fixture rights, public trust and
revocation distribution, supported platform minima, cryptographic provider,
production size/time budgets, maintenance window, and independent audit scope.
Record these in reviewed design changes before enabling a supported profile.
