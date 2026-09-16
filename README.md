# OpenARI

<p><a href="https://openari.org"><img src="assets/openari-logo.png" alt="OpenARI mosaic logo" width="192" height="192"></a></p>

Independent open-source tools for Apple Reference Image.

OpenARI is building a shared verification engine for applications that accept
image uploads, forensic tools, and language libraries. This repository contains
the Rust core, the `openari` CLI, and an experimental C interface.

**Development status:** no Apple ARI format revision is supported yet. The code
recognizes preliminary JPEG/TIFF container hints and emits structured reports.
It does not parse ARI payloads, verify signatures, establish trust, or check
revocation. `openari verify` always reports `indeterminate` and exits with code 3.
Do not use this scaffold to accept images as authenticated.

This project is not affiliated with or endorsed by Apple. See [TRADEMARKS.md](TRADEMARKS.md).

## Try the scaffold

Requires the Rust toolchain in `rust-toolchain.toml`.

```sh
cargo run -p openari-cli -- capabilities
cargo run -p openari-cli -- inspect photo.jpg
cargo run -p openari-cli -- verify photo.jpg
cargo test --workspace --locked
```

Input is limited to 64 MiB by default. The CLI accepts regular files and outputs
JSON. Inspection success means a report was produced, not that a valid image or
an ARI signature was found. No file contents are uploaded anywhere.

## Documentation

| Guide | Contents |
| --- | --- |
| [Roadmap](docs/roadmap.md) | Milestones, dependencies, and acceptance criteria |
| [Format status](docs/format-status.md) | Published facts, missing details, and supported revisions |
| [Architecture](docs/architecture.md) | Core, providers, bindings, and evidence flow |
| [Versioning](docs/versioning.md) | Apple revisions, ABI, schemas, policy, and compatibility |
| [Verification policy](docs/verification-policy.md) | Decisions, trust, time, revocation, and attestation |
| [Security model](docs/threat-model.md) | Threats, limits, and review requirements |
| [Upload integration](docs/upload-integration.md) | Admission control and application examples |
| [Performance](docs/performance.md) | Benchmarks, CPU acceleration, and batch processing |
| [Releases](docs/releases.md) | Artifact plans and release gates |
| [Bindings](bindings/README.md) | C ABI and language packaging plans |

## Contributing and security

Use Apache-2.0 licensing, SPDX source headers, and DCO-signed commits. Start with
[CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately using
[SECURITY.md](SECURITY.md). Repository CI checks the scaffold; it is not evidence
that Apple verification has been implemented or audited.

## Support development

[Sponsor Shaun Murphy](https://github.com/sponsors/shoon) to support OpenARI and
the other open-source projects he maintains.

## License

[Apache License 2.0](LICENSE). Copyright 2026 ncdents, LLC.
