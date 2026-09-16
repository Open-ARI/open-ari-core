# Contributing to OpenARI

Thanks for your interest in contributing! This project is licensed under the
**Apache License 2.0**, and all contributions are accepted under that license.

## Developer Certificate of Origin (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. It is a lightweight way for you to certify that you wrote, or
otherwise have the right to submit, the code you are contributing.

Add a `Signed-off-by` line to your commits by committing with `-s`:

```bash
git commit -s -m "your message"
```

which appends:

```
Signed-off-by: Your Name <your.email@example.com>
```

<details>
<summary>Developer Certificate of Origin 1.1 (full text)</summary>

```
By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I have the right
    to submit it under the open source license indicated in the file; or
(b) The contribution is based upon previous work that, to the best of my
    knowledge, is covered under an appropriate open source license and I have
    the right under that license to submit that work with modifications,
    whether created in whole or in part by me, under the same open source
    license (unless I am permitted to submit under a different license), as
    indicated in the file; or
(c) The contribution was provided directly to me by some other person who
    certified (a), (b) or (c) and I have not modified it.
(d) I understand and agree that this project and the contribution are public and
    that a record of the contribution (including all personal information I
    submit with it, including my sign-off) is maintained indefinitely and may be
    redistributed consistent with this project or the open source license(s)
    involved.
```
</details>

## Changes and review

Use focused branches and pull requests. Describe what changes, why it matters,
and how it was checked. Source files use SPDX-License-Identifier: Apache-2.0
and Copyright 2026 ncdents, LLC. headers, with contributor notices where applicable.
Keep all cryptographic policy in open-ari-core; SDKs must not implement competing
trust decisions. Identify documented facts, observations, and proposals separately.

For core changes run cargo fmt --all --check, cargo clippy --workspace
--all-targets --locked -- -D warnings, and cargo test --workspace --locked.
For website changes run npm ci and npm run docs:build. Follow each repository's CI.
Do not add a dependency without a concrete need, license review, and security review.

Use plain language. Avoid em dashes, inflated claims, and generated marketing copy.
Do not add icons or images until the project owner requests them.
Read SECURITY.md before reporting a vulnerability.
