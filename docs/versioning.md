# Versioning and compatibility

Apple format revisions and OpenARI releases are independent. The name `v1`
must always identify its namespace. OpenARI does not yet know whether Apple
will use integers, OIDs, another discriminator, or several version fields.

| Namespace | Current value | Change rule |
| --- | --- | --- |
| OpenARI packages | `0.1.0-dev.0` | SemVer; document breaking pre-1.0 changes |
| Apple ARI format | Unknown; none supported | Preserve actual on-wire identifier |
| C ABI | Experimental 1 | Breaking layout/ownership changes require new symbols or ABI major |
| Report schema | 1 | Breaking changes increment schema version |
| Policy | `openari.pre-spec/1` | Immutable ID; changed trust meaning requires new policy ID |
| Trust/revocation bundle | Not implemented | Content identity plus authenticated generation/freshness |
| Fixture manifest | 1 | Independently versioned schema and immutable corpus revision |
| Receipt format | Not implemented | Separate schema and signing identity from Apple evidence |

## Dispatch rules

1. Bound container parsing before reading the format discriminator.
2. Select the exact registered profile for the documented discriminator.
3. Enforce that profile's required fields, algorithms, canonical encodings,
   duplicate handling, and critical extensions.
4. Unknown major versions, ambiguous discriminators, and unknown critical
   fields produce an explicit unsupported or rejected result as appropriate.
5. Never retry another profile because signature verification failed.

Profiles for confirmed Apple v1 and v2 can coexist. A future version will not
replace an older implementation in place. A profile can be recognized but
disabled by policy after a security finding. Compatibility is never permission
to accept a retired algorithm. If Apple's version field is unsigned, the full
profile must still cryptographically bind the intended interpretation.

## Consumer behavior

Consumers must reject unsupported report-schema majors and treat unknown enum
values as unsupported, never as verified. Additive fields are allowed within a
schema version only when existing interpretation remains safe. Required new
security evidence must not be hidden behind an optional field old clients ignore.

SDKs expose engine version, ABI version, schema support, supported Apple profiles,
and enabled providers. They check ABI compatibility before processing uploads.
No library fetches a newer native binary at runtime. Wrapper releases name the
tested native engine and corpus revision; patch updates do not silently change
policy IDs. Stable report consumers should not depend on the forensic AST.

## Compatibility tests and maintenance

Test each profile against its own positive/negative corpus and cross-profile
confusion cases. Retain old vectors when adding a new profile. Test new SDKs
against their advertised minimum native ABI and new engines against supported
report consumers. Publish a support matrix and migration notes with releases.

Until 1.0, security fixes target main and the latest release. Before 1.0, choose
and publish a maintenance window. Do not promise indefinite support for unsafe
profiles or dependencies. Re-evaluation under new trust data creates a new
report; it does not rewrite historical evidence.
