# Contributing to srx

Open an issue to discuss changes or usage problems at https://github.com/ryro-hq/srx/issues.
Report security vulnerabilities privately using [SECURITY.md](SECURITY.md).

Use the toolchain in `rust-toolchain.toml`. Start with `cargo xtask check`.
The [testing guide](docs/testing.md) explains portable and VM checks. Checks do not
rewrite maintained sources or locks; `cargo xtask fmt` formats sources explicitly.

Use Conventional Commits with a lowercase scope, for example
`fix(config): retain YAML comments` or `feat(catalog)!: require exact versions`.
Explain breaking changes and their migration in the PR. Add tests for behavior
and security boundaries; avoid tests that merely repeat the implementation.

Every author must certify their own contribution under the
[Developer Certificate of Origin](https://developercertificate.org/).
Use `git commit --signoff` only when you can make that certification yourself.
Never add another person's signoff. The CNCF DCO2 App supplies the required `DCO`
check; maintainers cannot waive it. Automation must use its own configured App
identity and signoff, and must not impersonate a maintainer.

PRs integrate through the required merge queue using rebase and linear history,
with conversations resolved and all `verify` and `DCO` checks passing. The target
queue allows one PR, requires ALLGREEN, waits up to 360 minutes, and has no bypass.
[Security evidence](docs/security/controls.md) records rollout status. There is
currently one write maintainer, so independent human approval is a documented gap;
zero required approvals is temporary and is not a claim of independent review.

Source, license and checksum changes require explicit lock updates. Preserve old
source pins and released identities. Do not commit executables, generated archives,
credentials, local configuration or caches. Distributed package licenses are
reviewed separately from Rust maintenance dependencies.
