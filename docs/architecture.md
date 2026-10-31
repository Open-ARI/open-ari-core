# Architecture

Status: accepted direction. The pre-spec scaffold, structure walkers, and a
composite signature primitive exist today.

## Boundaries

`openari-core` owns bounded parsing, format dispatch, signed-byte selection,
cryptographic orchestration, and policy evaluation. It has no implicit network
access, system clock reads, global mutable trust store, or image upload behavior.
`openari-crypto` holds reviewed signature primitives. `openari-core` does not
depend on it yet, so no signature result can reach a verification report.
`openari-cli` builds the `openari` executable and owns file access and presentation.
`openari-ffi` owns unsafe C interop.
Bindings call the same core rather than reimplementing verification rules.

Independent camera signing and capture-evidence verification are planned in
[open-ari-capture](https://github.com/open-ari/open-ari-capture). Its camera adapters,
signing backends, and private/manufacturer trust roots stay outside this Apple ARI
engine. Future integration may use optional commands in the existing openari CLI;
no capture API or command is implemented here. Never fall back from failed Apple
verification to acceptance under an independent capture profile.

```mermaid
flowchart LR
  Upload[Bounded immutable upload] --> Detect[Container and ARI revision detection]
  Detect --> Profile[Exact version profile]
  Profile --> Evidence[Parsed evidence and signed byte ranges]
  Evidence --> Crypto[Approved crypto provider]
  Crypto --> Policy[Policy evaluation]
  Snapshot[Trust and revocation snapshot] --> Policy
  Context[Evaluation time and limits] --> Policy
  Policy --> Report[Versioned report]
  Report --> Adapter[Rust / C / CLI / language SDK]
```

## Planned modules

| Module | Responsibility |
| --- | --- |
| `structure` (exists) | Bounded JPEG, TIFF/DNG, and ISOBMFF/HEIC listings; offsets refer to the original input |
| `format` | Exact profile registry; unsupported versions remain unsupported |
| `evidence` | Owned or borrowed immutable evidence with explicit provenance |
| `openari-crypto` (exists) | Approved algorithm suites and interchangeable tested implementations |
| `trust` | Explicit anchors and constraints; no reliance on the OS web PKI |
| `policy` | Full decision from evidence, snapshots, limits, and supplied time |
| `inspect` | Forensic data marked untrusted until separately verified |

Start these as modules. Split crates when dependency isolation or consumers
justify it. Do not create unused traits for unspecified Apple data structures.

## Data and ownership

Inspection and verification operate on the same immutable bytes. Keep raw
signed ranges without decode/re-encode transformations. Stream hashing where
the confirmed profile permits it. Bound metadata independently of total file
size. Seekable inputs need stable snapshots; concurrent file changes must not
mix evidence from different objects. Do not trust an extension or MIME header.

The future verifier context owns immutable policy and trust snapshots and is
reused across requests. Network refresh atomically replaces snapshots outside
the verification path. Each request retains the snapshot it started with.

## Dependencies

Dependencies cover CLI parsing, report serialization, SHA-2, ML-DSA, and
RSA-PSS verification. [Dependencies](dependencies.md) records licenses, audit
status, and advisory exceptions. ASN.1, certificate path validation, and RFC
3161 parsing are not selected yet. Parsing a certificate or checking its
signature is not full path validation.

No dynamic loading of arbitrary crypto plugins. Providers are reviewed build
choices, identified in capabilities and reports. Core policy must produce the
same decision with every approved provider.
