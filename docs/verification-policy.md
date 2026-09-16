# Verification policy

Status: design. The current policy always returns `indeterminate`.

## Decision contract

The intended report distinguishes verified, rejected, and indeterminate.
Only a complete, supported evaluation under an identified policy can produce
verified. `Result::Ok`, an FFI success code, or valid JSON only means evaluation
or serialization completed. A signature check alone is insufficient.

Record independent outcomes for structure, signed-image integrity, composite
signature, trust, capture-time evidence, and revocation. Attach stable reason
codes; human-readable text is not an API. Unsupported algorithms and missing
authoritative evidence remain indeterminate. Malformed supported evidence,
signature mismatch, and authenticated revocation reject under the future policy.

Do not infer that absent ARI evidence means an image is fake. Do not infer a
scene's truth, the photographer's identity, or an edited preview's authenticity
from a verified reference image. Bind results to the exact reference bytes.

## Required report context

When implemented, include input digest and size, authenticated byte ranges,
actual Apple profile, engine/build and crypto provider identity, policy ID,
trust and revocation snapshot hashes/generations, supplied evaluation time,
capture interval with evidence provenance, freshness deadlines, and per-check
outcomes. Do not log raw pixels, device identifiers, or sensitive metadata.
Unavailable context is explicitly absent, never represented by invented values.

## Trust and time

Allow only profile-approved trust anchors, algorithms, key usages, constraints,
and certificate paths. An attacker-supplied certificate is evidence, not an
anchor. No network retrieval from untrusted certificate URLs or image metadata.
Define signing-time versus evaluation-time rules from the authoritative profile.
Certificate expiry must not be confused with an image or timestamp expiring.

Revocation snapshots require authenticated source, bounded parsing, generation
and freshness checks, atomic updates, and rollback protection where the format
allows it. Missing or stale revocation evidence cannot become 'not revoked'.
Offline policy reports exactly which snapshot was evaluated and its age.
Use a supplied trusted clock; detect unreasonable clock rollback in the updater.

## Attestation and receipts

Apple capture attestation, verification of Apple evidence, and an OpenARI service
receipt are three separate claims. OpenARI cannot issue Apple capture attestations.
A future optional receipt signs the input digest, policy, complete evidence
context, decision, and validity interval with the operator's identity. Define
canonical serialization, replay semantics, audience binding where needed,
key rotation, revocation, and independent receipt verification before shipping.

Do not create a new centralized trust dependency for local verification. A
receipt must not remain valid indefinitely after its underlying evidence grows
stale. Cached decisions require the full input/profile/policy/trust/revocation/
provider context and expire no later than the relevant evidence deadline.
