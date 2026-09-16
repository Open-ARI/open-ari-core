# Releases and supply chain

Status: development scaffold. No public package or release has been published.

Use `dist` 0.33.0 for CLI release planning. Keep FFI packaging separate: a static
musl CLI is not the correct shared library for a glibc Python process. Planned
CLI targets are Linux x86_64/ARM64 musl, macOS x86_64/ARM64, and Windows x86_64.
Additional Windows ARM64 support requires its own installed-artifact checks.

The active `release.yml` workflow only runs `dist plan`, with read-only repository
permissions and a pinned download checksum. The generated publishing workflow
is retained as `docs/release-template.yml` for review, not execution. Its known
`steps.cargo-cyclonedx.output` typo is corrected to `outputs`. The dist
`allow-dirty = ["ci"]` exception preserves this deliberate separation. Before
enabling publishing, implement the gates below, review the template's installer
downloads and permissions, and remove or revise that exception. Running dist
initialization again must not silently enable publishing.

Start with archives and checksums. Enable Homebrew publication once a supported
release exists and a tap is configured. Scoop and APT/RPM need separate package
automation and, for repositories, signing and hosting. No installer should claim
production verification support for a scaffold release.

## Release gates

- Test the exact release commit and lockfile across advertised targets.
- Validate native dependencies and minimum OS/libc versions on clean systems.
- Generate dependency/license inventory and SBOMs for shipped artifacts.
- Produce GitHub provenance attestations and publish checksum verification steps.
- Check advisory scans and review parser/crypto changes and required conformance.
- Record format, policy, schema, ABI, and provider compatibility in release notes.
- Use reviewed release tags and a protected publishing environment. No tag or
  package is published automatically during bootstrap.

Draft release automation must not become the only test path. Run format, lint,
unit/integration tests, C ABI smoke tests, and workflow linting on pull requests.
Schedule fuzzing and advisory checks independently so new findings are detected
without source changes. A dependency inventory is not an audit.

The website is built from its lockfile. Its Pages deployment is manually
dispatchable; domain configuration and DNS must be verified separately. Never
publish a claims page implying Apple verification works before M3 and M6 gates.
