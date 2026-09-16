# Fixtures

The initial corpus contains hex-encoded synthetic prefixes, not photographs or
valid image files. It tests the scaffold's refusal to claim verification.
No genuine Apple ARI positive fixtures are available locally.

`schema.json` defines the manifest format. `manifest.json` pins each input by
SHA-256 and records expected results. The Python check verifies corpus integrity
and runs every case through the CLI. It is not a general JSON Schema validator.

Future cases need independently established per-stage outcomes, real format IDs,
evaluation time, trust/revocation snapshots, provenance, redistribution rights,
and corpus revision. Null context here means no such checks are implemented.
Never mix synthetic test roots with production anchors. Large licensed corpora
can move to immutable corpus releases without requiring Git submodules.
