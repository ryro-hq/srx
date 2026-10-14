<p align="center">
  <img src="assets/syrox.png" width="180" alt="Syrox mascot: a penguin in a package box" />
</p>

<h1 align="center">Syrox</h1>

<p align="center">
  <strong>A typed package manager for Linux.</strong><br />
  Check → lock → plan → build → run.
</p>

<p align="center">
  <a href="https://github.com/ryro-hq/syrox/actions/workflows/ci.yml"><img src="https://github.com/ryro-hq/syrox/actions/workflows/ci.yml/badge.svg?branch=main" alt="Syrox CI on main" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0 license" /></a>
  <img src="https://img.shields.io/badge/status-experimental-orange.svg" alt="Experimental" />
</p>

Syrox is an experimental package manager and package language written in Rust. It checks typed package declarations, locks their inputs, and produces an inspectable plan before downloads or builds. An authenticated standard library is bundled with the CLI. Projects can also import locally locked modules and compose package catalogs from lazy recipe factories.

The language server lives in the same `srx` binary; editor clients are maintained separately for [Neovim](https://github.com/ryro-hq/syrox.nvim), [VS Code](https://github.com/ryro-hq/syrox-vscode), and [OpenCode V2](https://github.com/ryro-hq/syrox-opencode).

> Syrox currently targets Linux. APIs, language syntax, and persisted formats may change before a stable release.

## Build

The workspace pins Rust in `rust-toolchain.toml`. Build both the CLI and worker:

```sh
git clone https://github.com/ryro-hq/syrox.git
cd syrox
cargo build --release --locked -p syrox --bins
export PATH="$PWD/target/release:$PATH"
srx --help
```

The Linux release workflow also checks a static `srx` and worker. Building from source does not require a checkout of the separate package catalog.

## Check a project

Every project starts with `main.srx`. For a small package graph, create `demo/main.srx`:

```srx
outputs {
    support: std::Package = std::Package {
        id = "support";
        dependencies = [];
    };

    demo: std::Package = std::Package {
        id = "demo";
        dependencies = [std::Dependency { package = "support"; }];
    };
}
```

Then run:

```sh
srx project check demo
srx project lock demo
srx project plan demo
```

`check` validates the project, `lock` writes `demo/Syrox.lock`, and `plan` verifies the lock and prints the package graph without downloading or building. This example defines packages and their dependency only: a build needs an explicit source and build recipe. Use `srx project --help` and `srx build --help` for the available operations.

## Editor support

Start the shared language server with `srx lsp` over stdio. An editor client starts it for you; put `srx` on the editor host's `PATH` or configure the client with its absolute path. The server provides diagnostics, completion, navigation, document symbols, semantic tokens, inlay hints, and versioned quick fixes. It can analyze unsaved buffers and the standard-library sources when authoring `std/`.

| Client | Setup |
| --- | --- |
| [syrox.nvim](https://github.com/ryro-hq/syrox.nvim) | Neovim 0.11+ plugin using `srx lsp`. |
| [syrox-vscode](https://github.com/ryro-hq/syrox-vscode) | VS Code extension; set `syrox.serverPath` if `srx` is not on the extension host's `PATH`. |
| [syrox-opencode](https://github.com/ryro-hq/syrox-opencode) | OpenCode V2 plugin with semantic tools; set `SYROX_LSP_BIN` for a custom binary. |

The clients have independent repositories and CI. Each tests against a pinned Syrox server revision; the language semantics and LSP implementation live here.

## Workspace and development

- [`crates/syrox-lang`](crates/syrox-lang) — parser, resolver, type and ownership checker, evaluator, and recoverable editor analysis.
- [`crates/syrox-engine`](crates/syrox-engine) — project loading, locks, planning, acquisition, builds, store, runtime, and editor snapshots.
- [`crates/syrox`](crates/syrox) — the `srx` CLI, `syrox-worker`, and stdio language server.
- [`std/`](std) — bundled Syrox standard-library sources.

Before sending a change, run:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The [CI workflow](.github/workflows/ci.yml) also checks dependencies, macOS portability stubs, and the static Linux binaries. Native build and runtime integration tests require an appropriately configured Linux host.

## Merge workflow

Open a focused pull request from a topic branch. Changes enter `main` through
GitHub's merge queue, which tests one pull request at a time with the current
`main` and squash-merges it as one commit. Review approval is optional for
solo development; all review conversations must be resolved.

The required GitHub Actions check, `success`, covers every mandatory CI job.
Failed, cancelled, or skipped dependencies fail the gate. CI runs on pull
requests and `merge_group` candidates, and the queue waits up to 180 minutes
for required checks. A failed or timed-out entry must be fixed and queued again.

CodeQL keeps its default Rust and GitHub Actions configuration. Code scanning
merge protection checks the pull request and blocks new high or critical
security alerts and error-level findings. That rule does not evaluate merge
groups; the queue requires the complete CI gate on its candidate.

After reviewing the change and its checks, request integration with:

```sh
gh pr merge <number> --auto
```

GitHub waits for the pull request requirements, then adds it to the queue.
Topic branches are deleted after merging. Direct pushes, force pushes, deletion
of `main`, and merge commits are blocked; use the queue for integration.

## License

Syrox is licensed under the [Apache License 2.0](LICENSE).
