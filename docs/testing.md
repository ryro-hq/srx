# Testing srx

Use the toolchain pinned in `rust-toolchain.toml`. A fresh checkout starts with
`cargo xtask check`: Rust/srx formatting and locked compilation. It does not edit
sources or locks and needs neither root privileges nor a VM. `cargo xtask fmt`
formats maintained sources explicitly.

`cargo xtask test --suite portable` covers the language, CLI, diagnostics, public
bindings, profiles, usability, formatter, LSP and harness contract. Native engine
tests use `cargo test --locked -p syrox-engine --lib`; local IPC/namespace tests need
an environment that permits their kernel operations. Restricted sandboxes cannot
substitute for the native VM lane. The compiler and typed YAML/TOML regression
suites cover invalid syntax/types, defaults, external keys, partial patches,
immutable documents, comments and authenticated text assets.

Prepare the VM using the existing explicit `cargo test -p syrox --test vm --
--prepare ...` arguments from the CI workflow and VM harness help. Then use
`cargo xtask test --suite native` or `--suite acceptance`. These use the pinned
Linux kernel, explicit userspace image/runtime/firmware hashes and authenticated
CLI/worker candidates. KVM is required; do not treat unavailable KVM as a passing run.
CI runs native and minimum-environment suites for relevant changes and weekly.

Only explicitly whitelisted prose changes skip VM builds. Unknown paths, code,
std, contracts, dependencies, lock files and workflows run the full lane. Daily
Cargo audits run independently. The required `verify` aggregate waits for dependency,
workflow, portable and VM checks, including merge groups.
The old `success` context is transitional until GitHub required rules use `verify`.

Use `cargo xtask security audit`, `cargo xtask security exceptions`, and
`cargo xtask security workflows` for dependency, expiry and workflow policy checks.
The workflow linter requires authenticated actionlint and ShellCheck on PATH.
Security failures and analysis failures block integration. Fuzz campaigns complement
regressions and do not establish that an input parser is free of vulnerabilities.
