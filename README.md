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

Syrox is an experimental package manager and package language written in Rust. It checks typed package declarations, locks their inputs, and produces an inspectable plan before package-source downloads or builds. An authenticated standard library is bundled with the CLI. Projects can import locally locked projects or pinned GitHub snapshots and compose package catalogs from lazy recipe factories.

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

## Rust tests with a microVM

The default `cargo test` run includes the required microVM suite. Microsandbox
is a `[dev-dependencies]` dependency and is absent from normal product builds.
Local Cargo defaults use one build job and one test thread, without debug
information or incremental compilation in dev/test profiles. Missing KVM,
configuration or capabilities fail the required VM target.

```sh
cargo test --workspace --locked
cargo test --test vm -- --list
cargo test --test vm
cargo test --test vm -- --suite full
cargo test --test vm -- \
  runtime::tests::host_runtime_cancellation_settles_before_releasing_retention --exact
```

The default VM suite runs eight product journeys: authenticated managed build,
CLI build paths, declared dynamic loader/library, runtime cancellation and
settlement, persistent and isolated Shell state, bounded Os restart with revoked
payload refusal, interactive resize/exit/restore, and Ctrl+C/restore. Other
registered local gates remain available by filter or `--suite full`. Pidfs is
qualified once per VM. Two Unix socket/descriptor proofs run natively. Internal
subprocess fixtures are auxiliary coverage; their empty returns are never
independent behavioral evidence. Benchmarks, live network, external artifacts
and extensive harness verification remain separate.

The required harness uses Microsandbox `=0.7.3` with **one CPU and 512 MiB**, for
both initial and maximum resources. It saves and checks the effective SDK
configuration. A shared lock serializes preparation and VMs. Before VM startup,
admission requires 1536 MiB available (512 MiB VM plus 1 GiB host reserve).
Remaining memory in every visible cgroup v2 ancestor can lower availability;
insufficient resources fail before startup. VM limits never increase automatically.

Release CLI/worker, the runner, C payloads and only selected libtest targets are built
**before VM startup** in an immutable Docker image with pinned Rust 1.98.1.
Preparation inherits host CPU, memory and swap availability without imposing a
compiler resource ceiling or admission margin. Effective container limits,
CPU usage and peak memory are recorded. Product candidates use the release profile; libtest
fixtures use the test profile without debug/incremental builds. Sources,
binary hashes and independent copies retain the layout needed by fixtures.
The guest's `/work` uses a 128 MiB native tmpfs, executes one gate at a time and
archives and removes each workspace before starting the next. The basic route
does not qualify Rust, Node or Neovim inside the VM. Editor tools remain part of
the explicit ecosystem route.

Initial setup requires Linux x86_64, KVM, Docker, an image with systemd >=254,
a non-root `syrox` user with UID/GID 1000, the C tools and namespace/cgroup
capabilities. [guest recipe](tests/vm/guest.Containerfile) builds the guest from pinned
Debian and Rust images. Export it with `docker save`. Supply the Docker image ID
or digest separately when the SDK's imported OCI digest differs:

```sh
cargo test --test vm -- --prepare --install-runtime
cargo test --test vm -- --prepare \
  --image-archive /absolute/guest.tar \
  --preparation-image sha256:IMMUTABLE_DOCKER_IMAGE_ID
```

Preparation records runtime, firmware and image hashes in `target/vm-config.json`
and refuses to overwrite an existing configuration. `SYROX_VM_CONFIG` selects
another configuration. The official SDK firmware lacks the required Landlock
support; use `--prepare --build-firmware` or an explicitly pinned qualified
firmware. The [firmware recipe](tests/vm/firmware.Containerfile) builds that
kernel from the pinned SDK revision; preparation records its provenance.

Evidence under `target/test-evidence/<run-id>` includes source manifests,
selected gates, effective container/VM limits, release hashes, logs, journals,
workspace archives and cleanup results. Preparation records cgroup CPU and
aggregate memory peak. Commands record wall time, CPU and per-process maximum
RSS through `wait4`. Guest samples report CLI, worker and payload separately
by executable and PID/starttime; short-lived processes can be missed, so these
samples do not prove an exact aggregate product peak. A successful gate registry
or compilation alone never qualifies the minimum product environment.

Compilation caches share a pinned environment/lock key. Result identities also
include sources, selection and execution policy. Byte-identical successive
captures preserve Cargo freshness; changes and reversions after failed attempts
force invalidation. Independent copies retain executed evidence. Cache quota is
32 GiB. `Ctrl-C` preserves evidence and tears
down the preparation container or VM. `SYROX_VM_EVIDENCE` selects a fresh report
directory; `SYROX_VM_CANCEL_FILE` selects a cancellation marker.
`SYROX_VM_FAULT` exercises `test_failure`, `timeout`, `missing_fixture` or
`candidate_mutation`. Extensive fault/cancellation verification runs explicitly:

```sh
cargo run --example verify_vm_harness
```

The product targets one core/2 GiB. `Standard` builds retain a 768 MiB envelope;
`Large` uses 1 GiB, 100% CPU, 512 MiB scratch and 128 MiB output tmpfs. Inventory
uses one worker. Live producers share a per-user admission lease across Stores,
and unsettled attempts block a new producer in their Store. Consumers of the
same action share the producer and can cancel independently. Versioned execution
profiles change cache identities without changing `.srx`, CLI APIs or record
framing. Exceeding an envelope fails with diagnostics and settlement/cleanup.
The required default run passed with **one CPU/512 MiB**: all eight microVM
scenarios and 1686 native test entries (including auxiliary fixtures), with
zero failures and 59 classified ignored tests. The effective SDK configuration
confirmed the initial and maximum limits, and VM destruction was confirmed.
Clippy and the harness regressions passed alongside the required suite.

Cold preparation took 768 s outside the VM at one CPU/2 GiB, including release
product builds and test-profile fixtures/SDK. This compilation budget is separate
from the 512 MiB guest. Other full-suite scenarios, editor hosts and broader
product workloads retain their separate qualification requirements. Source and
binary hashes and exact results remain in the run's evidence directory.

`cargo test --features ecosystem-tests --test ecosystem` adds catalogue/editor
checks with `SYROX_ECOSYSTEM_CONFIG` (default `target/ecosystem-config.json`),
containing absolute paths and full revisions for `syrox`, `syrox-pkgs`,
`syrox-vscode`, `syrox-opencode`, and `syrox.nvim`. These integrations and real
editor hosts, seed, Hello/glibc, recovery, logout and boot retain separate
requirements. CI uses the following required matrix. Its separation of style,
platform builds and qualified-kernel jobs follows the
[Rust libc workflow](https://github.com/rust-lang/libc/blob/main/.github/workflows/ci.yaml).

| Job | Matrix | Checks |
| --- | --- | --- |
| Quality | Pinned Rust 1.98.1 | Format, structure, private rustdoc, doctests, dependency policy |
| Clippy | All features; no default features | All workspace targets, warnings as errors |
| Portable tests | Linux x86_64 host | Language, CLI, formatter, LSP and harness regressions without VM features |
| Static build | GNU; musl | Worker before embedded CLI, static ELF, installed worker/CLI, source manifest |
| Kernel suite | GNU, Linux 6.12.109, 1 CPU / 2 GiB | Complete nonignored workspace libtests, classified ignored inventory, kernel qualification |
| Acceptance | GNU; musl, Linux 6.12.109, 1 CPU / 512 MiB | Eight product journeys, resource limits, byte identity and cleanup |
| Success | Every required job | Reject any failed, cancelled or skipped dependency |

The Ubuntu host can restrict unprivileged namespaces, so the complete engine
suite runs inside the qualified kernel. The native profile uses 512 MiB of
workspace tmpfs; the acceptance profile keeps 128 MiB. Both compile libtests
before boot. To run the complete kernel suite locally, prepare a separate
configuration with `--profile native`, select it with `SYROX_VM_CONFIG`, then
run `cargo test --locked -p syrox --test vm -- --suite native`.

Build jobs publish CLI/worker pairs with exact source and binary hashes. Kernel
jobs import those pairs through `--candidate-bundle /absolute/directory` and
refuse a different source inventory, toolchain, target or executable hash. They
compile only the required GNU libtests and C fixtures. Firmware and the guest
image are built once, cached with pinned inputs and checked before each row.
A second kernel belongs in this matrix only after the same capability probes
and journeys qualify it. Weekly and manual runs repeat the required matrix.

Every kernel row checks KVM and Docker and preserves reports, logs and journals
even after failure. Preparation uses the host evidence owner's UID/GID while the
guest keeps its fixed test user. Missing prerequisites fail the job.

## Check a project

Every project starts with `main.srx`. For a small recipe, create `demo/main.srx`:

```srx
mod recipes::demo {
    pub fn recipe() -> std::Recipe {
        std::Recipe {
            package = std::Package {
                id = "demo";
                dependencies = [];
            };
        }
    }
}
pub publish(recipes, recipe): std::Recipe;
```

Then run:

```sh
srx project check demo
srx project lock demo
srx project plan demo
```

`check` validates the project, `lock` writes `demo/Syrox.lock`, and `plan` verifies the lock and prints the package graph without downloading or building. Publication exposes the lazy reference `project::demo`; it does not create a deployment output. Only `Os` and `Shell` are deployment outputs.

This example declares package metadata only. Once the recipe declares a source and build program, select it explicitly with `srx build demo#demo`. Once it declares a command, select both the recipe and command with `srx run demo#demo --command NAME`. There is no implicit default build or command. Use `srx project --help`, `srx build --help` and `srx run --help` for the available operations.

Every `std::Build` also requires an explicit `profile`:
`std::BuildProfile::HostBootstrap` for the existing host toolchain backend, or
`std::BuildProfile::Managed` for declared inputs. The profile is authenticated in
the build program and result identity. Managed rejects host paths, including
those embedded in arguments, environment and generated text. Its executor uses the
explicit Managed configuration below. Missing configuration or an invalid worker
is refused before Store initialization. It never falls back to HostBootstrap. After updating existing
recipes, regenerate project locks against the updated standard library.

Managed operational configuration is explicit in `syrox/config.toml`. Parsing
this section does not start a manager. The build route validates the selected
worker and realizes declared inputs before admitting a shared producer. Replace the
example paths and digest with your selected candidate's values:

```toml
[build.managed]
worker = "/opt/syrox/syrox-worker"
worker-sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
scope = "user"
user-bus = "/run/user/1000/bus"
socket-parent = "/run/user/1000/syrox-build"
```

All fields shown are required for user scope. For `scope = "system"`, omit
`user-bus`; selecting this scope does not elevate credentials. Worker and socket
paths must be absolute, and the worker digest must be lowercase SHA-256. The
executor validates the static worker image and the existing private socket
parent (owned mode `0700`) before use. There is no implicit worker lookup, bus
selection or fallback to the host toolchain. `[build] host-toolchain = "/usr"`
remains a separate HostBootstrap policy.

Inspect local Linux capabilities and one explicitly selected manager:

```sh
srx host inspect --systemd-user-bus /run/user/1000/bus
srx host inspect --systemd-system
```

The manager check has a five-second budget and reports access to its API and
observed identity. It does not start or stop units. Execution permissions,
FDSTORE, journald, logout and boot still require their operation-specific gates.
Successful inspection can report unavailable capabilities; its exit status alone
does not certify manager access.
Without either manager flag, inspection does not contact systemd. Cgroup mutation
remains separately opt-in with `--probe-cgroup`.

The engine's explicit `prepare_managed_build` API validates a locked selection
against source and retained inputs already in the Store, pins their descriptors,
and stages the authenticated program and worker. The returned
`PreparedManagedBuild` can revalidate that preparation; it neither authorizes a
payload nor executes a build. Dropping it leaves the unlaunched operation for
explicit Store recovery. The service preparation API records a local `Awaiting`
attempt. Journal v4 durably records `StartAuthorized` before dispatching Start;
only then may worker inspection and a verified manager observation bind it.
Authorization is single-use and does not itself authorize the build payload.
Preparation holds exclusive local ownership until its service description is
returned. An error in that interval closes only the attempt created by that call:
before admission it cleans the stage; after admission it records `LocalAborted`
and terminal evidence for recovery. Recovery can finish interrupted local cleanup
under exclusive ownership. A preexisting attempt never receives that token's
cleanup authority. Uncertain Start requests and older records remain retained
for reconciliation.
Observation checks the static worker image, credentials, cgroup and loaded service
properties. `inspect_managed_build_worker` can reopen and revalidate the recorded
staging snapshot with pinned descriptors. This inspection does not retain input
views or authorize mounts. `retain_for_handoff` separately combines source and
input interests; its independent process descriptor survives the coordinator.
`ManagedBuildHandshake` owns a private listener and authenticates a zero-descriptor
Hello against fresh manager observations before recording Bound. It borrows the
prepared inputs for the connection lifetime. Resource transfer derives the
descriptors from that preparation, authenticates each batch and validates the
received files and input views against pinned bytes. The sender keeps retention
after transmission; receipt does not authorize mounts or execution. The service
description does not start a unit. The worker can publish its retention descriptor
and wait for a notification barrier. The coordinator independently observes the
exact FD store name, inode, mode and flags through `DumpFileDescriptorStore`,
requiring systemd 254 or newer for this build capability. This observation cannot
prove an open file description's flock, so both endpoints keep local retention.
The coordinator acknowledges that first observation before the worker publishes
a second descriptor for namespace PID 1. Admission requires unique pidfs identities
and namespace ioctls available in Linux 6.12; anonymous-inode pidfds are refused.
The namespace must be the observed worker's child, with matching credentials and
cgroup membership and the expected namespace relationships. After observing both
FD store entries, the journal records `NamespacePrepared`; this is not COMMIT.
The dedicated worker's unsafe namespace preparation API establishes readonly
inputs and private writable work/output mounts, then parks namespace PID 1 without
executing a payload. Its handle settles PID 1 before releasing those resources.
The dedicated `__managed-build` dispatcher verifies its own pinned executable,
receives resources and publishes retention, the parked namespace and separate
artifact/log capture channels. A canonical COMMIT requires durable authorization;
the worker durably consumes it before releasing the local gate. Namespace PID 1
starts the separate Managed IR worker, which validates its private environment and
installs Landlock and seccomp before processing commands. READY follows exec
confirmation. The coordinator acknowledges the exit report only after namespace
exit and EOF on both bounded capture channels. That acknowledgement does not prove
manager settlement or authorize a receipt. Cancellation, revocation, EOF and
unexpected messages abort the worker. The explicit `ManagedBuildExecution` API
now starts the unit, conducts the handshake and drains output before waiting for
readiness. Publication requires both processes exited, a pinned cgroup observed
empty or removed, an empty FD store and an inactive successful unit with no job.
The normal build route now connects this executor to shared producer admission:
staging uses the producer's single operation, cancellation follows the remaining
consumer interests, and publication checks that original interest directly.
Verified built and imported results retain their object closures without holding
the global Store barrier during another build. Real systemd execution and recovery
of uncertain attempts before binding remain pending.


A recipe can instead declare `imported = std::Option::Some(std::ImportedResult {
root = "seed"; manifest = "<sha256>"; entries = [std::ImportedOutput {
output = "out"; key = "compiler"; }]; });`. It cannot also declare acquisition,
build or build inputs. The manifest must already be admitted under that Store
root; the selected entry must retain its declared output name. Imported outputs
work in package selections, commands and build inputs without fabricating a build
receipt or requiring the producer's source/toolchain. All sibling artifacts remain
part of the verified closure. The root is operational; origin and manifest pin
participate in the consumer Action identity. This does not provide a compiler seed
or prove real Managed execution.

## GitHub project inputs

An input can name a public GitHub project containing `main.srx` and a current
`Syrox.lock`:

```srx
inputs { pkgs = "github:owner/repository"; }
```

Use `github:owner/repository/ref` for a branch, tag or commit; omitting the ref
selects `HEAD`. The remote project's Lock must match the bundled standard library.

```sh
srx project lock demo          # Resolve direct refs and pin commit + snapshot SHA-256
srx project lock --check demo  # Verify from the local cache, offline
srx project lock --fetch demo  # Acquire missing pinned snapshots, preserving the Lock
srx project plan demo          # Use the pinned project graph, offline
```

Only explicit lock operations acquire project inputs. Transitive projects keep
their own pins. Snapshots are retained in `demo/.syrox/github`; the HTTPS transport
and bounded archive reader are built in. The native resolver follows supported NSS
ordering and fallback rules, with hosts/DNS and local `systemd-resolved` support.
See the [transport contract](crates/syrox-engine/src/acquire/https/mod.rs) and
[DNS resolver](crates/syrox-engine/src/acquire/https/dns/mod.rs) for their limits.
Completion and navigation use cached sources;
remote definitions open as read-only virtual documents and reload when the Lock
changes.

## Pinned offline runtime bundles

`srx bundle export` packages an existing verified application and its explicitly
selected output/path and loader/libraries. `--entry` is required; library selections
use `ROOT@RECEIPT@OUTPUT`. It prints a manifest digest; obtain that pin through
a trusted channel before importing the file on another machine:

```sh
srx bundle import --store ./receiver --root hello --file hello.bundle --manifest-sha256 "$MANIFEST_SHA256"
srx bundle inspect --store ./receiver --root hello --manifest-sha256 "$MANIFEST_SHA256"
srx bundle run --store ./receiver --root hello --manifest-sha256 "$MANIFEST_SHA256" -- --version
```

The CLI requires a regular bundle file within the 1 GiB transport limit and
checks the opened file before creating the receiving Store. Import validates
the complete manifest, artifacts and ELF closure before retaining
the result. The receiving Store needs no recipe, source archive, compiler inventory
or build receipt. `srx bundle export --help` describes selection of existing build
roots. A manifest can also retain data outputs and name multiple commands through
the engine API. This is explicit local pin authorization, not signed cache discovery
or automatic trust updates. Running uses the existing Linux namespace launcher;
End-to-end Shell/systemd validation remains pending. Synthetic transfer tests pass; real
Hello/glibc execution across Stores requires the opt-in host gate.

## Editor support

Use `srx fmt path/to/file.srx` to print formatted source, or `srx fmt -`
to read it from stdin. `srx fmt --check path/to/file.srx` returns failure
when formatting differs and emits no source text. These commands leave files
unchanged, preserve comment and string bytes, and reject incomplete syntax.
Formatting does not load a project, resolve imports, or evaluate recipes.

Start the shared language server with `srx lsp` over stdio. An editor client starts it for you; put `srx` on the editor host's `PATH` or configure the client with its absolute path. The server provides diagnostics, completion, navigation, document symbols, semantic tokens, inlay hints, formatting, and versioned quick fixes. It can analyze unsaved buffers and the standard-library sources when authoring `std/`. Formatting uses the current open buffer; incomplete sources receive no edits, stale responses are discarded, and virtual dependency sources remain read-only.

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

Engine consumers inspect a pure `Plan` and keep a `PreparedPlan` for realization.
Typed output selections can be realized, retained under generation roots and
reopened with `RetainedOutput`; `RetainedRuntime` reopens verified application
closures for the native runtime launcher. See the
[retained output contract](crates/syrox-engine/src/result/materialize/retention.rs)
and [Os generation flow](crates/syrox-engine/src/deployment/os/mod.rs).

`srx shell PROJECT#OUTPUT --command NAME --non-interactive -- ARGS` runs one
exposed command from a locked `Shell` plan. Service commands can bind arguments
and environment variables to declared configuration files, mounted read-only
in that service's private namespace. To supervise declared service processes,
select the user manager explicitly:

```sh
srx shell PROJECT#OUTPUT --command NAME --non-interactive \
  --session-state /absolute/private-state \
  --systemd-user-bus /run/user/1000/bus -- ARGS
```

Use your user manager's actual bus path. The state directory must already exist,
belong to your non-root user and have mode 0700. The CLI checks this profile before
realizing packages. The session retains configuration on uncertain shutdown and
uses a pinned worker candidate. Without these options, service processes are
rejected. Interactive terminals, complete recovery and persistent `Os` deployment
remain under development. Real systemd, namespace and abrupt-termination gates
require a compatible Linux host and remain unverified in the restricted sandbox.

Managed Shell services can declare logical secret names with
`secrets = ["token"];` and use `std::CommandArgument::SecretFile("token")` in a
service command. Authorize each source separately in your operational
`syrox/config.toml`; for a service named `api`:

```toml
[shell.secrets.api]
token = "/absolute/private-secrets/api-token"
```

The source must be an owned regular file with mode `0400` or `0600`, without
links, outside the mounted working directory. Unrequested grants are not read.
Each session takes a sealed snapshot and exposes it only to that service at
`/syrox/secrets/api/token`, as a read-only, non-executable file. Changing the
source affects a new session; it does not rotate a running session's snapshot.
Plans and manifests contain logical names, never source paths or secret bytes.
Secret declarations are refused for direct Shell and `Os`. This path is under
validation; the real namespace/manager consumption gate remains pending.

The CLI also accepts `--interactive` instead of `--non-interactive`, with both
managed-session options above. It requires stdin and stdout on the same
foreground terminal and checks them before package realization or session start.
It runs the explicitly selected command; it does not select a host shell or
compose a shared command PATH. `PreparedShellTerminal` and
`ManagedShell::run_prepared_terminal` coordinate relay, resize, monitor custody
and restoration through namespace settlement. This path is under validation;
local adapter tests do not prove the full systemd/namespace session, job control
or recovery after abrupt termination. The lower-level
`ManagedShell::run_command_with_terminal` still accepts a caller-owned PTY slave
whose relay and external terminal restoration belong to the caller.

`srx session list --session-state /absolute/private-state --json` reads existing
journal evidence without creating state or contacting systemd. To revoke new
starts and stop recorded matching invocations, use:

```sh
srx session recover SESSION_ID --session-state /absolute/private-state \
  --systemd-user-bus /run/user/1000/bus --store /absolute/store
```

Recovery authenticates existing retention records against the explicit Store;
it never creates a missing Store or hold. A service's interest can be retired
only after kernel observations prove every recorded launcher and namespace exited,
the recorded manager is reconciled, and the journal confirms the complete history.
Missing handoffs and uncertain retirements remain pending. Configuration and the
journal are preserved; reconciliation of the session owner and foreground commands
still requires additional evidence, so recovery returns code 2 while that work is
pending, even if the manager confirmed a Stop job.
Absent or replaced units never authorize a blind stop or deletion.
Session records bind recovery to the boot that created them. Recovery refuses
records from another boot and obsolete record formats before contacting the
manager, preserving their evidence without automatic migration or cleanup.
Managed working-directory mounts exclude nested mounts and reject `/sys` and
cgroup filesystems; these restrictions alone are not proof of complete confinement.

Prepared `Os` generations can be retained and reopened independently of their
source project. Use an existing owned mode-0700 installation directory and an
explicit Store:

```sh
srx os prepare ./project#system --installation /absolute/installation --store /absolute/store
srx os list --installation /absolute/installation --json
srx os status --installation /absolute/installation --json
srx os inspect PIN --installation /absolute/installation --store /absolute/store --json
srx os diff PREVIOUS_PIN CANDIDATE_PIN --installation /absolute/installation --store /absolute/store
```

Preparation pins the installed worker, persists the manifest and output roots,
and publishes a private configuration tree and executable worker snapshot within
the candidate. Partial publication preserves evidence for reconciliation; the
`prepared` journal phase describes retained candidate bytes, not active services.
`inspect` revalidates those retained bytes; `list` reports journal evidence only.
`status` reads the activation journal without opening a Store or contacting a
manager. It reports the desired generation, active operation, recorded binding
authorizations and pending effects. Its JSON identifies `observation: "journal"`;
these records do not establish current service health or repair publication
durability. Reading pending effects succeeds with exit status 0 and does not
retry them. Configuration contents, arguments and environment values are omitted.
Apply a retained candidate with an explicit manager, persistent unit directory,
working directory and execution credentials:

```sh
srx os apply CANDIDATE_PIN --initial \
  --installation /absolute/installation --store /absolute/store \
  --units /absolute/unit-directory --cwd /absolute/work \
  --systemd-user-bus /run/user/1000/bus --uid 1000 --gid 1000 --json
```

For an update, replace `--initial` with `--expected PREVIOUS_PIN`; the comparison
prevents an implicit overwrite of the selected generation. Choose exactly one
manager: `--systemd-user-bus PATH` or `--systemd-system`. System scope does not
elevate credentials or change ownership; the initial profile requires the current
UID/GID. The unit directory must satisfy the engine's ownership and manager-path
checks. No project or replacement worker is loaded during apply.

The report distinguishes started, stopped, unchanged and pending resources.
Exit status 2 with `needs_reconciliation: true` preserves evidence of an
incomplete operation; it does not authorize replay or cleanup. Start observation
is not an application-health check. Startup and stop timeouts default to 30 and
5 seconds (`--start-timeout-seconds`, `--stop-timeout-seconds`), within a shared
300-second operation deadline. Rollback and complete boot recovery remain under
development.

Reconcile one recorded operation using its explicit identifier and the same
execution context:

```sh
srx os recover OPERATION --installation /absolute/installation --store /absolute/store \
  --units /absolute/unit-directory --cwd /absolute/work \
  --systemd-user-bus /run/user/1000/bus --uid 1000 --gid 1000 --json
```

Pending effects include their `stage` and, when available, the original failure
under `error`. Text output carries the same details. Recovery with unresolved
effects continues to return exit status 2 and retains its evidence.

Ordinary recovery reads the candidate from that operation's journal record. It checks
current evidence and synchronizes confirmed ownership records; it does not send
Start, Stop or Reload requests or republish units or bindings. Effects are
reported as `observed`, `not_applied`, `boot_fenced` or `pending`. A local publication can be
`not_applied` only after durable verification of the exact previous owned state
or absence. This terminal state permits a later explicit apply; it does not
authorize a start, replay the effect or release retention. Insufficient or
conflicting evidence remains pending.
An inactive unit alone cannot settle Stop: its accepted job must also be absent
from the same manager. A Stop without a recorded job stays pending. Exit status is 0 when the selected
effects are reconciled, 2 when reconciliation remains pending, and 1 when a
precondition fails. The same explicit manager, credentials, timeout options and
300-second overall deadline apply. This is not complete boot recovery or an
application-health check.

An Os `ServiceProcess` can explicitly request restart after failure:

```syrox
std::ServiceProcess {
    id = "server";
    command = "serve";
    restart = std::ProcessRestart::OnFailure(std::RestartLimits {
        delay_seconds = 2;
        window_seconds = 30;
        burst = 4;
    });
}
```

The default is `Never`. An enabled policy requires all three limits: delay
1–300 seconds, window 1–3600 seconds and burst 1–100, with window at least delay.
The burst counts starts within the manager window, including the initial start;
it is not a lifetime retry budget. The policy is pinned with the generation and
shown in its diff. Shell currently rejects enabled restart before effects.
Each invocation reopens the retained generation and validates current launch
authority. The manager receives a launcher exit envelope: 0 for payload success,
1 for payload failure and 78 only for a definitive launch denial. The original
payload code or signal is logged separately; payload status 78 is still a failure,
not an authorization denial. Restart behavior, FD-store handoff across attempts
and concurrent GC require the real manager gate, which remains pending.

The opt-in restart gate uses a static build of `tests/fixtures/session-payload.c`
and an explicitly pinned worker. Set `SYROX_RESTART_WORKER` and
`SYROX_RESTART_PAYLOAD` to their absolute paths, with matching `_SHA256`
variables. Also set `SYROX_RESTART_PARENT` to an owned mode-0700 evidence
directory, `SYROX_RESTART_UNITS` to the user manager's unit directory, and
`SYROX_SYSTEMD_USER_BUS` to its socket. Run on a suitable Linux/systemd test host:

```sh
cargo test --offline --locked -p syrox-engine --lib \
  execution::launcher::os::tests::restart::automatic_restart_reopens_pins_limits_attempts_and_refuses_revoked_payload \
  -- --ignored --exact --nocapture
```

It checks two distinct invocations, per-attempt FD-store retention, the start
limit, and definitive denial after revocation. Numbered payload witnesses only
prove execution; cleanup separately requires kernel exit observations for every
recorded launcher and namespace. The gate retains its installation, unit files,
and evidence for inspection. Compiling this gate does not prove it passed.

The internal Shell restart gates exercise the admission group before restart is
enabled in the public Shell configuration. They require a worker built from the
current sources, using the service-v2 protocol, and the same static payload
fixture. Set `SYROX_OWNER_WORKER` and `SYROX_SESSION_PAYLOAD` to absolute paths,
their respective `_SHA256` variables to the authenticated digests, and
`SYROX_SYSTEMD_USER_BUS` to the authorized user manager socket:

```sh
cargo test --offline --locked -p syrox-engine --lib \
  execution::launcher::service_coordinator::tests::restart:: -- --ignored --nocapture
```

These gates check distinct admissions, the start limit, retention between
invocations, and durable Closing during the restart interval. Both passed on an
x86_64 Linux host with kernel 7.2.9 and user systemd 262 against an identified
CLI/worker/payload/libtest tuple. Logs confirm one executed passing test per gate,
including object/view collection after settlement. This is a controlled C payload
proof; public Shell restart, foreground/PTY, crash recovery, logout and boot
remain separate work. Other hosts and the minimum supported baseline require
their own executions.

After a Linux reboot, add `--new-boot` to the explicit recovery command. The
engine verifies a different boot in the same scope, revokes authorizations from
previous boots, and records unresolved remote effects as `boot_fenced`, retaining
accepted job identities. Local publications still need filesystem reconciliation.
This does not report successful jobs or permit cleanup.

For a manager change within the same boot, `--manager-changed` explicitly revokes
prior launch authority and reconciles the historical resources. It may submit an
authenticated Stop after recording a durable, single-use intent; an uncertain
Stop is never replayed. This option cannot be combined with `--new-boot` and is
not accepted by apply or rollback. A completed manager fence is reported as
`manager_fenced`, separately from successful completion of an earlier effect.
Namespace exit, cgroup and descriptor-store evidence, current jobs and manager
identity are checked independently. Retained generations remain available while
evidence is incomplete. This path is still under development: recovery after
cgroup removal or interruption is not yet a validated end-to-end capability.

New-boot recovery accepts the selected operation or the exact last abandonment when
selection is empty. A premature apply/rollback refuses unfenced prior boots before
replacing that selection. A later explicit apply checks that each prior unit is
absent or inactive with no current job; active units and jobs remain pending. It
publishes a new binding and starts a new invocation without stopping or adopting
the old invocation. No automatic boot/login activation is installed by this flow.

Restore an explicitly chosen retained generation with the same manager and path
options as `os apply`:

```sh
srx os rollback OLD_PIN --expected CURRENT_PIN --installation /absolute/installation \
  --store /absolute/store --units /absolute/unit-directory --cwd /absolute/work \
  --systemd-user-bus /run/user/1000/bus --uid 1000 --gid 1000 --json
```

Rollback records its intent in the journal and `os status` reports
`active_kind: "rollback"`. It reconciles each resource through the same ownership
and stop/start checks as apply; uncertain effects remain pending. It preserves
external data and retained generations and does not reverse data migrations or
infer a previously healthy generation. The target must differ from `--expected`;
`--initial` is not accepted.

To withdraw a desired selection after every recorded effect has been reconciled:

```sh
srx os abandon OPERATION --installation /absolute/installation --json
```

Abandonment clears `desired` and `active_operation` and records the abandoned
operation in `os status`. It preserves existing authorizations, services, files
and retention; it does not roll back or stop a generation. Unresolved effects
prevent abandonment. Only the last abandonment can be repeated, before a new
selection. This command needs neither a Store nor a manager connection. A later
explicit apply uses `--initial` for the now-empty desired selection and still
accounts for existing bindings.

Rust formatting follows [`rustfmt.toml`](rustfmt.toml): calls, method chains,
collections and struct fields expand earlier into separate lines, and short
conditional branches stay in blocks. `cargo fmt --all` applies this layout
using the pinned stable toolchain; editor integrations using rustfmt read the
same workspace configuration.

Before sending a change, run:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

The [CI workflow](.github/workflows/ci.yml) also checks dependencies and the static Linux binaries. Native build and runtime integration tests require an appropriately configured Linux host.

## Reading the code

Start at the root of the crate you intend to change, then follow its topic links:

- [`syrox-lang`](crates/syrox-lang/src/lib.rs): sources and resolution, checking and evaluation, editor snapshots and formatting.
- [`syrox-engine`](crates/syrox-engine/src/lib.rs): projects and builds, output retention and execution, Shell sessions and Os generations, cancellation and recovery.
- [`srx`](crates/syrox/src/main.rs): command dispatch and LSP integration. The [worker entry](crates/syrox/src/worker.rs) explains its separate identity, modes and admission.

From there, follow the operation to the contracts that need explanation: what a
handle keeps alive, when a result may be published, or what recovery must verify.
Internal docs describe decisions, data passed between stages and resource
lifetimes. A clearly named file with an obvious implementation can omit an
introduction.

Write documentation in plain English with short paragraphs. Introduce the flow,
then explain the decision that a signature alone does not reveal. Use an example
when it shows a meaningful use; getters and small helpers need no filler.
Keep safety comments beside the calls whose requirements they explain.

The topic guide follows [Tokio's crate tour](https://docs.rs/tokio/latest/tokio/).
The explanations for contributors follow the
[rust-analyzer architecture guide](https://rust-analyzer.github.io/book/contributing/architecture.html),
which connects code structure to the decisions behind it. The
[checker](tools/check_structure.rs) checks crate entries and module layout without
requiring a header in every file. Follow the linked source contracts when
changing ownership, publication or recovery behavior.

To check the reading guide and its links, generate private-item documentation and
run the examples and layout regressions:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --locked --all-features --no-deps --document-private-items
RUSTDOCFLAGS="-D warnings" cargo test --workspace --locked --all-features --doc
cargo fmt --all -- --check
rustfmt --edition 2024 --check tools/check_structure.rs
rustc --edition 2024 -D warnings --test tools/check_structure.rs -o /tmp/syrox-check-structure-tests
/tmp/syrox-check-structure-tests
rustc --edition 2024 -D warnings tools/check_structure.rs -o /tmp/syrox-check-structure
/tmp/syrox-check-structure
```

## License

Syrox is licensed under the [Apache License 2.0](LICENSE).

Editor checks with explicit candidates and checkouts use Rust:

```sh
cargo run --locked -p syrox --example check_editors -- \
  --binary /absolute/candidate/srx \
  --vscode /absolute/syrox-vscode \
  --neovim /absolute/syrox.nvim \
  --opencode /absolute/syrox-opencode
```

Add `--hosts` to run the installed editor hosts and OpenCode packaging. Logs,
candidate hashes and results remain under `target/test-evidence/editors-*`.
The default VM gates also run directly with `cargo test --locked -p syrox --test vm`.


## Rust source consolidation (2026-10-13)

Production modules with children use directories; leaf modules use `.rs` files.
Small unit suites stay with their owner, while eight larger suites live in domain
`tests` directories. The 90 inventoried leaves and the additional test-only
`checker/bodies/effects` leaf were consolidated without changing logical test
names or visibility. Equivalent projections and policies share their existing
owners. The consolidation originally added `Purpose` and `Why` headers to
all files. The later documentation pass replaced that rule with crate introductions
and explanations at the contracts that need them; [the checker](tools/check_structure.rs)
now checks entry docs and module layout.

| Crate | Rust files before → after | Production syntax tokens before → after |
| --- | ---: | ---: |
| `syrox-lang` | 75 → 66 | 136,760 → 136,557 |
| `syrox-engine` | 437 → 357 | 569,608 → 568,421 |
| `syrox` | 93 → 91 | 47,143 → 46,940 |
| Total | **605 → 514** | **753,511 → 751,918** |

The comparison uses the saved dirty checkout and excludes comments,
documentation and test-only syntax. The exact inventory retains all previous
test names: 1,677 native entries passed, 54 external/conditional entries remain
ignored, and 22 subprocess fixtures are proved through their parents. Seventeen
fixtures now reject missing context instead of reporting passes without assertions.
Formatting, structure checks, strict Clippy with all targets/features and without
default features, static ELF/install verification, 53 catalogue tests and the
three editor protocol checks passed.

**Mandatory workspace acceptance passed after the separate closing fix.**
Joining service admission could cancel a D-Bus query and leave its connection
unusable. Cleanup now reconnects after admission stops and checks the original
manager identity before issuing a new Stop or observing settlement. Mutations
are never replayed, and process exit and retention proofs remain required.

`cargo test --workspace --locked` passed 1,679 native entries and all eight gates
in the 1-CPU/512-MiB VM, including Ctrl+C status 130 and terminal restoration.
Two additional real service shutdown/retention gates passed. Every VM, runtime
home and preparation container was cleaned up; compilation inherited host
resources without imposed CPU or memory quotas. The corrected static candidate,
installation, catalogue and editor protocol checks passed. The
`target/test-evidence/shell-close-reconnect-20261013/summary.json` holds the final
acceptance, hashes and source comparisons. Earlier failed attempts remain in
`target/test-evidence/fragmentation-20261012/` as historical evidence.


## Composable operations and Rust API migration

Build realization receives `RealizeOptions { configuration, worker, offline }`.
`realize_build` and `realize_builds` replace the corresponding
`*_with_cancellation` functions; `realize_output` receives the same options.
Cancellation and progress remain request arguments. The internal realization
owner opens its Store after backend preflight and lends that Store to dependencies.
HostBootstrap and Managed preserve their own cache, acquisition, preparation and
execution order, with granular retention across dependency execution.

`RuntimeClosure::application()` returns `&RuntimeFile<MaterializedArtifact>`;
`loader()` returns `Option<&RuntimeFile<MaterializedArtifact>>`. Select the path
through `.path` and the retained view through `.output`. Separate application/loader
path getters were removed. Runtime verification composes output identity,
application, interpreter, provider and ELF dependency checks; the resulting
closure owns all output handles through settlement.

Semantic analysis composes effective source preparation, resolution, checking
and publication. Immutable documents own parsing caches; one accumulator preserves
phase precedence under the diagnostic cap. LSP workers own `Unloaded`, `Ready`
and `Failed` states and process load, overlay synchronization, analysis and publication.
The experimental body installation harness, its rebase and exclusive test hooks
were removed. Production `BodyEffects`, observational replay, body partition
parity and retention/budget tests remain. The workspace permits `too_many_lines`
for cohesive operations whose resources share a lifecycle; other lints remain strict.

Verification evidence for this batch remains in
`target/test-evidence/composable-20261013/`.

The completed batch passed the full workspace and all eight mandatory VM gates,
plus both service closure gates, on 1 CPU / 512 MiB with confirmed cleanup.
The exact native inventory records 1,673 passing tests, 22 auxiliary fixtures
proved by their parent tests and 54 classified ignored tests. Format, structure,
both strict Clippy configurations, static release/installation and the Rust
catalogue consumer passed. `summary.json` records the candidate pins and results.
