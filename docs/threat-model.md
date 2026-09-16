# Security model

Status: initial design and review checklist. No external audit has occurred.

## Assets and boundaries

Protect verification decisions, parser availability, upload privacy, trust
updates, receipt signing keys if introduced, and release integrity. Image bytes,
file names, metadata, certificates, and remote update responses are untrusted.
The native caller must satisfy the C memory contract. Rust cannot validate an
arbitrary pointer supplied by a hostile or buggy in-process caller.

## Required controls

| Threat | Control and required evidence |
| --- | --- |
| Offset overflow, cycles, aliasing, truncation | Checked arithmetic; visited IFD offsets; depth, count, byte and work budgets; fuzzing |
| Allocation/CPU exhaustion | Independent input/metadata/certificate limits; deadline and cancellation checks; bounded queues |
| Signature wrapping or ambiguous containers | Exact signed-byte profile; duplicate/conflicting segment rejection; cross-parser fixtures |
| Algorithm downgrade/version confusion | Exact dispatch; full composite verification; no fallback to weaker profiles |
| Untrusted signer/root | Explicit profile trust anchors and full validation policy |
| Stale or rolled-back revocation | Authenticated snapshots, freshness and generation checks; fail closed |
| TOCTOU and cache poisoning | Immutable inputs; digest-bound reports; context-complete cache keys |
| SSRF or privacy leaks | No implicit I/O; allowlisted updater endpoints; no per-image lookup without reviewed need |
| Unsafe acceleration | Reviewed providers, differential testing, portable fallback, no weakened checks |
| FFI misuse/panics | Small audited unsafe layer, explicit ownership, C smoke tests, unwind containment |
| Compromised build/dependency | Locked dependencies, SHA-pinned Actions, limited permissions, advisory checks and provenance |

`Result` is not a proof that a parser cannot panic. Panics, hangs, excessive
allocations, and inconsistent decisions are all fuzz findings. Unwind containment
does not catch process aborts, memory faults, or OOM. Upload services needing a
hard availability boundary should use resource-limited worker processes.

No image decoding is needed unless the confirmed verification profile requires
it. If decoding becomes necessary, isolate it and apply pixel/decompression
limits. Uploaded authentic images can still be malicious to downstream software.

## Review and release gates

Require focused review for parser, signed-range, trust, crypto, unsafe, and
release changes. Before claiming verification support, complete differential
conformance tests, sustained fuzzing, dependency review, and independent security
review. Publish audit scope and outstanding findings without implying broader
coverage. Keep test roots unreachable from production trust configuration.

PR workflows receive no release credentials and never execute untrusted fork
code under `pull_request_target`. Publishing uses a protected environment,
reviewed tags, short-lived credentials, and artifact provenance. Protected
branches and required CI checks reduce accidental bypass; they do not replace
review. See SECURITY.md for private vulnerability reporting.
