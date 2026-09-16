# Integrating image uploads

Status: implementation plan. Current builds cannot approve ARI uploads.

## Intended integration

Create a verifier once with explicit limits, policy, and immutable trust data.
Pass immutable bounded bytes and evaluate the report. The future convenience
method should accept only a complete verified decision under the requested policy.
The current `Verifier::verify` returns an indeterminate report for every input.

```rust
use openari_core::Verifier;
let verifier = Verifier::default();
let report = verifier.verify(b"uploaded image bytes")?;
// This scaffold cannot authenticate uploads. Do not interpret Ok as trusted.
# Ok::<(), openari_core::Error>(())
```

## Request flow

1. Enforce authentication, request size, time, rate, and concurrency limits at
   the server before buffering. Do not trust Content-Length, MIME, or extension.
2. Store bounded immutable bytes in memory or a private temporary file. Reject
   symlinks and avoid reopening attacker-controlled paths. Apply a cleanup policy.
3. Verify in a bounded worker queue. Provide cancellation and per-job budgets.
   Use process isolation when hard deadlines or memory caps are required.
4. Bind the report to the stored object digest, and accept only the explicitly
   permitted decision. Choose reject or quarantine for indeterminate results.
5. Keep malware/content scanning and safe image decoding as separate checks.
6. Store minimal report context with the object. Re-evaluate revocation before
   later security-sensitive use; an upload-time result is not permanent trust.

If a signed reference is embedded beside an edited preview, label and display
them separately. Do not transfer a reference verdict to a generated thumbnail
or re-encoded derivative. Document how your application binds displayed pixels
to the authenticated object.

## SDK and service options

Rust uses the core directly. Python, Go, .NET, and Java will share a tested native
engine and report schema. Provide framework examples after the ABI stabilizes:
ASGI, Go net/http, ASP.NET Core, and Java upload handlers. Each example must
exercise oversize, truncated, unsupported, revoked, timeout, and cancellation cases.

A local sidecar is a planned alternative for applications that cannot load
native code. Default to a Unix socket/named pipe or loopback with authenticated
access, bounded requests, and no public listening interface. A hosted upload
service is not part of the initial scope. No SDK sends photographs to OpenARI.
