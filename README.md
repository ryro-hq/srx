<p align="center">
  <img src="assets/syrox.png" width="180" alt="Syrox mascot: a penguin in a package box" />
</p>

<h1 align="center">Syrox</h1>

<p align="center">
  <strong>A typed package manager for Linux.</strong><br />
  Check → lock → plan → build → run.
</p>

<p align="center">
  <a href="https://github.com/ryro-hq/srx/actions/workflows/ci.yml"><img src="https://github.com/ryro-hq/srx/actions/workflows/ci.yml/badge.svg?branch=main" alt="Syrox CI on main" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="Apache-2.0 license" /></a>
  <img src="https://img.shields.io/badge/status-experimental-orange.svg" alt="Experimental" />
</p>

Describe packages and environments in `.srx`. Syrox checks your declarations,
locks their inputs, and gives you an inspectable plan before downloading sources
or building.

- Compose packages with typed recipes, modules, and explicit dependencies.
- Declare `Shell` and `Services` environments alongside their services and configuration.
- Lock local projects and pinned GitHub inputs.
- Get diagnostics, completion, navigation, and formatting in your editor.

**Syrox** is the public product name. The CLI is `srx`, and it includes the
`srx lsp` language server for `.srx` files. The core repository is
[`ryro-hq/srx`](https://github.com/ryro-hq/srx); the separate package catalog is
[`ryro-hq/srx-pkgs`](https://github.com/ryro-hq/srx-pkgs). The Cargo package
`syrox`, worker binary `syrox-worker`, and lockfile `Syrox.lock` keep their names.
[ryro-bot](https://github.com/ryro-hq/ryro-bot) is separate GitHub automation,
not part of the Syrox runtime.

Syrox is experimental, currently targets Linux, and is licensed under
[Apache-2.0](LICENSE).

## Get started

### Build the CLI

Use x86-64 Linux with Git, [rustup](https://rustup.rs/), HTTPS access to GitHub,
Rust distribution servers and crates.io, and native build tools. On Ubuntu
24.04, for example, install these system packages before building:

```sh
sudo apt-get update
sudo apt-get install build-essential ca-certificates git liblzma-dev musl-tools pkg-config
```

With `rustup` on `PATH`, run the following from a workspace directory where
`srx`, `srx-pkgs`, and `hello-demo` do not yet exist. The repository's
`rust-toolchain.toml` pins Rust. Build the static worker before embedding it in
the CLI:

```sh
git clone https://github.com/ryro-hq/srx.git
cd srx
rustup toolchain install --no-update
rustup target add x86_64-unknown-linux-musl
export RUSTFLAGS="-C target-feature=+crt-static" LZMA_API_STATIC=1
export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
cargo build --release --locked -p syrox --bin syrox-worker --target x86_64-unknown-linux-musl
SYROX_EMBED_WORKER="$PWD/target/x86_64-unknown-linux-musl/release/syrox-worker" \
  cargo build --release --locked -p syrox --bin srx --target x86_64-unknown-linux-musl
export PATH="$PWD/target/x86_64-unknown-linux-musl/release:$PATH"
srx --version
```

### Check, lock, and plan a project

From `srx`, return to the workspace directory. Clone the catalog and create the
demo as its sibling, so `path:../srx-pkgs` resolves from the demo:

```sh
cd ..
git clone https://github.com/ryro-hq/srx-pkgs.git
mkdir hello-demo
cd hello-demo
cat > main.srx <<'SRX'
inputs { pkgs = "path:../srx-pkgs"; }

let packages = pkgs.forPlatform { system = "linux-x86_64"; libc = "musl"; };

outputs {
    dev: Shell = Shell {
        pkgs = [select_command(package_recipe(packages.hello {
            version = "2.12.1";
        }), "out", "hello")];
        services = [];
    };
}
SRX
```

Lock the local catalog with the CLI you just built. This can update
`../srx-pkgs/Syrox.lock` in your clone because the catalog's committed lock
tracks the core revision pinned in its `.syrox-core` file.

```sh
srx project lock ../srx-pkgs
srx project check .
srx project lock .
srx project plan . --output dev
```

The plan lists GNU Hello 2.12.1 for `linux-x86_64-musl` and the `hello` command
exposed by the `dev` Shell. These commands do not download package sources,
build Hello, or initialize a Store.

### Build and run Hello (optional)

Run as an unprivileged user on a compatible Linux build host with a running
systemd user manager, Bubblewrap with user and cgroup namespaces, and a kernel
and `setpriv` that support Landlock's `ioctl-dev` right. The host toolchain must
provide `/usr/bin/musl-gcc` and Make, and the source host must be reachable over
HTTPS. See [catalog qualification](https://github.com/ryro-hq/srx-pkgs#qualification-and-publication)
for the tested environments; the CLI build prerequisites alone are not enough.

On such a host, create `build.toml` in `hello-demo` to authorize the host
toolchain and the exact source URL listed in the plan:

```sh
cat > build.toml <<'TOML'
[build]
host-toolchain = "/usr"

[network]
allow-https = ["https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz"]
TOML
srx shell .#dev --command hello --non-interactive \
    --config ./build.toml --store ./store -- --greeting 'Hello from Syrox!'
```

The command prints `Hello from Syrox!`.

## Editor integrations

Install the Linux `srx` binary in the environment where your editor runs, or
configure the integration with its absolute path. The integrations use
`srx lsp`; their documentation covers setup and version requirements:

- [Neovim (`ryro-hq/srx.nvim`)](https://github.com/ryro-hq/srx.nvim)
- [VS Code (`ryro-hq/srx-vscode`)](https://github.com/ryro-hq/srx-vscode)
- [OpenCode (`ryro-hq/srx-opencode`)](https://github.com/ryro-hq/srx-opencode)

## Linux system management

`srx system inspect --builder-directory /existing/scratch --json` also reports
filesystem capacity and observed project quotas without creating the directory
or changing quotas; see [system builders](docs/system-builders.md).

`srx system inspect --json` reports read-only kernel, disk identity, partition,
storage topology and mount-namespace observations. It needs no project, Store or
external utilities. Full-system builds and provisioning are still being
implemented in the [Linux system roadmap](docs/design/linux-system-management.md).

`srx system plan ./project#host --json` compares a locked `System` or
`HostConfiguration` with read-only Linux observations, including selected sysctls
and a System storage binding attempt. [System declarations](docs/system-declarations.md)
explain unresolved checks and the separate authority needed to apply changes.

The image libraries compose authenticated initramfs, dm-verity trees, GPT RAW and qcow2
streams in the chunked Store; see [system images](docs/system-images.md) for their
contracts and verified limits. Bootable system images remain under implementation.

## The language

See the [language reference](docs/language.md) for checked, executable examples
of bindings, record calls, platform conditions and shared recipes.

## Typed configuration

`std::yaml` and `std::toml` expose `encode`, `decode<T>`, `document<T>`,
`value`, `patch` and `render`. Text uses the existing `std::ConfigText` type.
Struct fields can declare an external key without changing their `.srx` name:

```srx
value NodeName(str);
value NodeIp(str);
struct HostConfig { name: NodeName; ip: NodeIp; }
struct K3sConfig {
    #[key("node-name")] nodeName: NodeName;
    #[key("node-ip")] nodeIp: NodeIp;
}
fn configuration() -> std::ConfigText {
    let host = std::toml::decode<HostConfig>(std::files::read_text("assets/host.toml"));
    let original = std::yaml::document<K3sConfig>(std::files::read_text("assets/k3s.yaml"));
    let updated = std::yaml::patch(original, { nodeName = host.name; nodeIp = host.ip; });
    std::yaml::render(updated)
}
```

`decode` rejects unknown keys and applies declared defaults. `document` validates
known fields while retaining other content. `patch` accepts a partial record;
omitted fields keep their values, including existing values that differ from a
default. Documents are immutable, and rendering an untouched document returns
its original bytes. Scalar edits preserve adjacent comments through `yaml-edit`
and `toml_edit`. File writes remain explicit engine operations.

Records, nominal strings and integers, booleans, lists, ordered maps and options
are supported. `None` fields are omitted when encoding; TOML cannot represent
`None` as a list element. Functions, recipes, resources and opaque data types
are rejected, including inside empty lists or absent options. YAML tags and
aliases, floats and TOML datetimes have no typed representation; unknown fields
containing them can remain in a document.

`read_text` reads UTF-8 bytes retained during project authentication, from that
caller's `assets/` inventory. It never opens arbitrary paths during evaluation.
Assets and the new standard modules enter `Syrox.lock`; refresh locks explicitly
after changing them. Evaluation and loading budgets apply to parsing and conversion.

## Versioned services

The selected package determines the configuration contract before acquisition:

```srx
inputs { pkgs = "path:../srx-pkgs"; }

let packages = pkgs.forPlatform { system = "linux-x86_64"; };

services.nginx = {
    enable = true;
    package = packages.nginx { version = "1.30.6"; };
    settings = { listen = 8080; proxyPass = "http://127.0.0.1:3000"; };
};
```

This declares an `os` output of type `Services`. Omitted `libc` selects GNU; add `libc = "musl";`
to select musl. The set exposes normalized `platform.system`/`platform.libc` and
`buildPlatform` (Linux x86_64 GNU). Package calls inherit the set's platform;
contradictory overrides fail before acquisition. Direct package calls default to
Linux x86_64 GNU. Versions are explicit; use `forPlatform` to select musl.

Root public names of the authenticated standard library are available directly;
`std::Recipe` and other qualified names remain valid. Local declarations and
explicit imports take precedence. Module `let` bindings are private by default,
exported with `pub let`, immutable, reusable and shared during evaluation.
Global initializers cannot consume affine resources. Effects hidden behind
invoked callbacks are traced by the checker with call-path diagnostics; the
evaluator retains the same safeguard.
Forward references are allowed and cycles are diagnosed. Known `if`/`match`
conditions in module initializers and configurations check the selected branch.
Names and syntax are resolved in every branch. Exact versions remain required.

A public binding containing a `RecipeRef<Recipe>` is also a CLI export. Select
the package once, then export its recipe:

```srx
pub let hello = package_recipe(packages.hello { version = "2.12.1"; });
```

```sh
srx project lock .
srx info .#hello
srx build .#hello --dry-run
```

For offline builders, [import an explicitly selected source file](docs/source-import.md)
against its locked SHA-256 and size with `srx project import-source`.

Public aliases share the same lazy recipe instance. Private bindings stay private;
inspection and dry runs do not acquire sources or initialize a Store.

`linux-aarch64` is representable for conditions, with `gnu` or `musl`; this
catalog has no ARM64 implementations. `linux` and `linux-arm` require an explicit
architecture. Persisted package identities keep full target tags.
`extraConfig` is checked by the selected nginx with `nginx -t` in an isolated
runtime before a generation is frozen.

Configure the service installation once, then operate it by profile:

```sh
srx project lock .
srx services init .#os --name web --user --config ./build.toml
srx services apply --profile web
srx services status --profile web
srx services logs nginx --profile web --follow
srx services stop --profile web
```

See [installation profiles](docs/os-profiles.md) for ownership, rollback,
recovery and Linux requirements, and [artifact selection](docs/artifacts.md)
for automatic consumption of explicitly authorized local bundles.

Existing projects and scripts must follow the
[Services migration](docs/migrations/services.md) to replace `Os` and `srx os`
and explicitly refresh standard-library locks.

Package modules use ordinary `if`, `==`/`!=`, literal `match` and static traits.
`package_traits::Package` associates an implementation with `Settings`,
recipe and rendering operations; `ServicePackage` adds service integration.
Selectors such as `fn nginx(const selection: Selection) -> _` specialize their
result from known arguments. An unsupported static case fails at the call;
ordinary functions require compatible branches and exhaustive matches.

`srx catalog check`, `generate`, `lock`, `matrix`, `updates`, `add`, `qualify` and
`release-manifest` maintain the pinned TOML inventory using native commands.
Qualification builds and runs each required combination and verifies offline
bundle import; a missing or failed combination prevents a release manifest.

## Contributing

Run `cargo xtask check` from the core checkout, `cargo xtask fmt` to format
explicitly, and `cargo xtask test --suite portable` for local tests. See
[testing](docs/testing.md), [contributing](CONTRIBUTING.md) and
[security](SECURITY.md).
