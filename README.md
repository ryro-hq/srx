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

Describe packages and environments in `.srx`. Syrox checks your declarations,
locks their inputs, and gives you an inspectable plan before downloading sources
or building.

- Compose packages with typed recipes, modules, and explicit dependencies.
- Declare `Shell` and `Os` environments alongside their services and configuration.
- Lock local projects and pinned GitHub inputs.
- Get diagnostics, completion, navigation, and formatting in your editor.

Syrox is experimental and currently targets Linux.

## The language

Use packages from [syrox-pkgs](https://github.com/ryro-hq/syrox-pkgs) in your own
environment. With the catalog checked out beside your project, save this as
`main.srx`:

```srx
inputs { pkgs = "path:../syrox-pkgs"; }

use std::{Shell, select_command};

outputs {
    dev: Shell = Shell {
        pkgs = [select_command(pkgs::hello, "out", "hello")];
        services = [];
    };
}
```

This selects GNU Hello and its declared runtime dependencies. The catalog owns
the recipe; your project chooses the packages and commands it exposes.

Check and lock the catalog, then inspect your project:

```sh
srx project lock ../syrox-pkgs
srx project check .
srx project lock .
srx project plan .
```

On a configured Linux build host, build and run the selected command:

```sh
srx shell .#dev --command hello --non-interactive \
    --config build.toml --store ./store -- --greeting 'Hello from Syrox!'
```

`build.toml` supplies the host toolchain and source permissions described in
the [catalog's setup](https://github.com/ryro-hq/syrox-pkgs#build-and-select-a-command).

## Versioned services

The selected package determines the configuration contract before acquisition:

```srx
inputs { pkgs = "path:../syrox-pkgs"; }

services.nginx = {
    enable = true;
    package = pkgs.nginx { version = "1.30.5"; };
    settings = { listen = 8080; proxyPass = "http://127.0.0.1:3000"; };
};
```

This declares an `os` output. Use `pkgs.forSystem("linux-x86_64-musl").nginx`
for musl; GNU and musl selections can share a project. Exact literal versions
and string constants are supported. Unknown versions, variants and fields fail
before acquisition. `extraConfig` is checked by the selected nginx with `nginx -t`
in an isolated runtime before a generation is frozen. `let/in`, contextual
attribute sets, booleans and triple-quoted multiline strings are pure.

`srx catalog check`, `lock`, `matrix`, `updates`, `add`, `qualify` and
`release-manifest` maintain the pinned TOML inventory using native commands.
Qualification builds and runs each required combination and verifies offline
bundle import; a missing or failed combination prevents a release manifest.

## Get started

The repository pins its Rust toolchain. Build the CLI and worker:

```sh
git clone https://github.com/ryro-hq/syrox.git
cd syrox
rustup target add x86_64-unknown-linux-musl
# Linux build host: install musl-gcc, pkg-config and native link tools first.
export RUSTFLAGS="-C target-feature=+crt-static" LZMA_API_STATIC=1
export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
cargo build --release --locked -p syrox --bin syrox-worker --target x86_64-unknown-linux-musl
SYROX_EMBED_WORKER="$PWD/target/x86_64-unknown-linux-musl/release/syrox-worker" \
  cargo build --release --locked -p syrox --bin srx --target x86_64-unknown-linux-musl
export PATH="$PWD/target/x86_64-unknown-linux-musl/release:$PATH"
```

The language server ships with `srx`.

Licensed under [Apache-2.0](LICENSE).
