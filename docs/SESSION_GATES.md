# Session gates through Cargo

Session preparation and execution use the Rust VM harness. It captures the core
sources and lock, prepares release CLI/worker, selected libtest binaries and C payloads
in a pinned container before starting the guest, and invokes each gate by its
exact registered name. Preparation inherits host CPU, memory and swap resources;
its effective limits, CPU usage and peak memory are recorded. The default
`cargo test` run requires one microVM with one CPU/512 MiB; the eight default
scenarios share it and run sequentially. VM startup requires 1536 MiB available,
including 1 GiB of host reserve, accounting for cgroup ancestors. Missing
KVM/configuration or a failing scenario fails the run.

The `microvm` job in [CI](../.github/workflows/ci.yml) runs the default gates on
Linux x86_64. It checks KVM and Docker access, builds the guest from pinned base
images, prepares the 0.7.3 runtime and Landlock firmware, and records the final
image and firmware hashes. Preparation uses the host evidence owner's UID/GID;
the guest continues to use its fixed test user. Missing prerequisites fail the
job. Reports, logs, candidate hashes and gate archives are uploaded even when a
gate fails; a successful image build is not passing gate evidence.

```sh
cargo test --locked -p syrox --test vm host_managed_shell -- --nocapture
cargo test --locked -p syrox --test vm host_managed_foreground -- --nocapture
cargo test --locked -p syrox --test vm managed_path_root -- --nocapture
cargo test --locked -p syrox --test vm root_exit_between_protocol_pause -- --nocapture
cargo test --locked -p syrox --test vm shell_restart -- --nocapture
cargo test --locked -p syrox --test vm -- --list
```

The [registry](../crates/syrox/tests/vm_support/gates.json) records prerequisites
and separates executable gates, internal subprocess fixtures, benchmarks,
network and external-artifact proofs. A missing name, fixture or capability,
zero executed tests, timeout or changed candidate bytes fails the run.

Reports, candidate hashes, test output, journal and per-gate filesystem archives
remain in `target/test-evidence/<run-id>`. Cancellation destroys the VM and
preserves available evidence. The common Rust supervisor stops subprocess groups
before reaping their leaders, including after normal exit.

The standard workspace run requires the microVM. A native-only diagnostic subset uses an explicit override:

```sh
cargo test --workspace --locked --no-default-features
cargo test --locked -p syrox --test vm_harness --no-default-features
```

The old candidate preparer has been removed. Registration does not approve a
gate: foreground, terminal races and the remaining VM gates retain the observed
status documented in [PLANO.md](PLANO.md#devx-nativa-com-cargo-test).

Editor checks with explicit checkouts use the Rust example:

```sh
cargo run --locked -p syrox --example check_editors -- \
  --binary /absolute/candidate/srx \
  --vscode /absolute/syrox-vscode \
  --neovim /absolute/syrox.nvim \
  --opencode /absolute/syrox-opencode
```

`--hosts` also executes VS Code Extension Host, OpenCode packaging and OpenCode
host tests; those hosts must be available. Without it, the report marks them
pending. Candidate copies are bounded, pinned and never overwrite evidence.
Local commands use the candidate CLI and core std, with isolated editor state.
