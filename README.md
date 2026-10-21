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
  <a href="https://scorecard.dev/viewer/?uri=github.com/ryro-hq/srx"><img src="https://api.scorecard.dev/projects/github.com/ryro-hq/srx/badge" alt="OpenSSF Scorecard" /></a>
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

## Get started

The repository pins its Rust toolchain. Build the CLI and worker:

```sh
git clone https://github.com/ryro-hq/srx.git
cd srx
rustup target add x86_64-unknown-linux-musl
# Linux build host: install musl-gcc, pkg-config and native link tools first.
export CC_x86_64_unknown_linux_musl=musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
RUSTFLAGS="-C target-feature=+crt-static" LZMA_API_STATIC=1 \
  cargo build --release --locked -p syrox --bin syrox-worker --target x86_64-unknown-linux-musl
RUSTFLAGS="-C target-feature=+crt-static" LZMA_API_STATIC=1 \
  SYROX_EMBED_WORKER="$PWD/target/x86_64-unknown-linux-musl/release/syrox-worker" \
  cargo build --release --locked -p syrox --bin srx --target x86_64-unknown-linux-musl
export PATH="$PWD/target/x86_64-unknown-linux-musl/release:$PATH"
```

The language server ships with `srx`.

## The language

See the [language reference](docs/language.md) for checked, executable examples
of bindings, record calls, platform conditions and shared recipes.

Use packages from [srx-pkgs](https://github.com/ryro-hq/srx-pkgs) in your own
environment. In a separate workspace, check out the catalog beside a new project:

```sh
git clone https://github.com/ryro-hq/srx-pkgs.git
mkdir my-environment
cd my-environment
```

Save this as `main.srx`:

```srx
inputs { pkgs = "path:../srx-pkgs"; }

let packages = pkgs.forPlatform { system = "linux-x86_64"; };

outputs {
    dev: Shell = Shell {
        pkgs = [select_command(package_recipe(packages.hello {
            version = "2.12.1";
        }), "out", "hello")];
        services = [];
    };
}
```

This selects GNU Hello and its declared runtime dependencies. The catalog owns
the recipe; your project chooses the packages and commands it exposes.

Check and lock the catalog, then inspect your project:

```sh
srx project lock ../srx-pkgs
srx project check .
srx project lock .
srx project plan .
```

Save this as `build.toml` for the Hello example:

```toml
[build]
host-toolchain = "/usr"

[network]
allow-https = [
  "https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz",
  "https://ftp.gnu.org/gnu/glibc/glibc-2.44.tar.xz",
]
```

Building requires the declared host tools, including a compiler, make, Python,
gawk, bison and patch for GNU glibc. `srx host inspect` reports native kernel
capabilities. See [testing](docs/testing.md) for the qualified Linux environments.

On a configured Linux build host, build and run the selected command:

```sh
srx shell .#dev --command hello --non-interactive \
    --config build.toml --store ./store -- --greeting 'Hello from Syrox!'
```

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

This declares an `os` output. Omitted `libc` selects GNU; add `libc = "musl";`
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
srx os init .#os --name web --user --config ./build.toml
srx os apply --profile web
srx os status --profile web
srx os logs nginx --profile web --follow
srx os stop --profile web
```

See [installation profiles](docs/os-profiles.md) for ownership, rollback,
recovery and Linux requirements, and [artifact selection](docs/artifacts.md)
for automatic consumption of explicitly authorized local bundles.

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


## Develop

Use the pinned toolchain and start with the native maintenance entry point:

```sh
cargo xtask check
cargo xtask fmt
cargo xtask test --suite portable
```

`check` validates sources and locked compilation; `fmt` rewrites formatting
explicitly. See [testing](docs/testing.md), [contributing](CONTRIBUTING.md),
[security](SECURITY.md) and [rollout evidence](docs/security/rollout.md).
The [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/ryro-hq/srx)
links the badge to the published repository checks.

| Path | Responsibility |
| --- | --- |
| `crates/syrox/` | CLI, worker and native VM harness |
| `crates/syrox-engine/` | Authentication, evaluation, acquisition, builds and runtime |
| `crates/syrox-lang/` | Parser, type checker, formatter and language server |
| `std/` | Authenticated standard library and configuration APIs |
| `tools/xtask/` | Rust maintenance, policy and release commands |
| `docs/` | Language, testing, runtime and security contracts |

Package recipes and qualification belong to
[srx-pkgs](https://github.com/ryro-hq/srx-pkgs). Runtime ryro-bot is a separate
project.

Licensed under [Apache-2.0](LICENSE).
