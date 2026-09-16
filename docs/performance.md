# Performance and acceleration

Status: design. No cryptographic benchmark or accelerator is implemented yet.

Optimize verified end-to-end behavior using representative files. Do not publish
latency claims from the current prefix detector as ARI verification benchmarks.

## Measurement plan

Measure parse, hash, each composite-signature component, trust evaluation,
revocation lookup, serialization, and FFI overhead separately. Track warm/cold
p50, p95, p99 latency, throughput, peak RSS, allocations, startup time, and
cancellation latency. Record hardware, OS, compiler, provider, power settings,
file sizes, corpus revision, and validation policy with every result.

Include small and large JPEGs, metadata-heavy files, malformed worst cases,
concurrent uploads, and valid/invalid signatures. Separate cached and uncached
work. Set service budgets after establishing a real baseline, then make
regressions reviewable with noise-aware thresholds.

## Optimization order

1. Avoid decoding/re-encoding pixels and unnecessary copies. Stream hashes over
   the correct signed ranges when the profile allows it.
2. Reuse immutable parsed trust material and bounded revocation indexes. Share
   verifier contexts across workers without mutable global state.
3. Use reviewed crypto implementations with runtime CPU feature detection:
   SHA extensions, ARM crypto instructions, and suitable SIMD implementations.
   Portable baseline builds remain usable on older CPUs; do not distribute
   artifacts compiled with `target-cpu=native`.
4. Bound task parallelism and batch independent images. Avoid oversubscribing
   threads inside crypto providers and the application's own worker pool.
5. Evaluate GPU/Metal/CUDA or other offload only if representative batch results
   justify transfer, startup, deployment, and attack-surface costs. Do not assume
   an accelerator supports the required ML-DSA or composite verification profile.

Every optimized provider must pass identical conformance, malformed-input,
cross-version, and differential tests against a portable implementation. An
unavailable accelerator falls back to the same approved algorithm and policy,
never a reduced signature check. Expose backend identity and let operators
disable a backend after a security finding. Do not silently offload image data
to a remote service. HSM/TPM support, if needed for future receipt signing, is
separate from image verification acceleration.
