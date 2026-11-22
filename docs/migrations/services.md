# Migrating Os declarations and commands to Services

The service manager now uses `Services` in `.srx` and `srx services` on the CLI.
`Os`, `std::Os`, `std::deployment::Os` and the `srx os` command are removed.
This change makes room for the separate full-system and host-configuration
contracts in the [Linux system architecture](../design/linux-system-management.md).
`System` and `HostConfiguration` now have separate authenticated std types and
pure project plans. Building/installing a complete system and adopting/applying
host resources remain under implementation.

## Project declarations

Replace the type and constructor, including imports and function signatures:

```srx
outputs {
    os: Services = Services {
        pkgs = [];
        services = [];
    };
}
```

The qualified names are `std::Services` and `std::deployment::Services`. Keep
the output name (`os` above) so existing profile selectors continue to work.
The `services.NAME = { ... };` shorthand still produces the output named `os`,
now with type `Services`. Its settings and package integration are unchanged.
Package and module identifiers that happen to contain `os` do not need renaming.

Update any local dependency that exposes the old contract, including a catalog
checkout, before checking the consumer. With the new executable, check and lock
changed dependency projects first, then the root project:

```sh
srx project check .
srx project lock .
srx project lock --check .
srx project plan . --output os
```

The bundled standard library has a new identity. Its pin must be updated with
the explicit `project lock` command, even for projects that only use `Shell`.
Profile apply's automatic root-file refresh rejects an old standard-library pin
and leaves the lock untouched. Locking does not build packages or apply services.

## Commands and existing installations

Replace the command prefix in scripts and interactive use:

| Former command | Current command |
|---|---|
| `srx os init .#os --name web --user` | `srx services init .#os --name web --user` |
| `srx os prepare .#os …` | `srx services prepare .#os …` |
| `srx os apply --profile web` | `srx services apply --profile web` |
| `srx os status --profile web` | `srx services status --profile web` |
| `srx os logs nginx --profile web` | `srx services logs nginx --profile web` |
| `srx os stop --profile web` | `srx services stop --profile web` |
| `srx os rollback PIN --profile web` | `srx services rollback PIN --profile web` |
| `srx os recover --profile web` | `srx services recover --profile web` |

The same prefix change applies to `list`, `inspect`, `diff` and `abandon`.
There is no compatibility alias for the former command.

Existing version-1 profiles keep their schema and paths:

- `$XDG_CONFIG_HOME/syrox/os/NAME.json` (default `~/.config/syrox/os/NAME.json`).
- `$XDG_STATE_HOME/syrox/os/NAME/` (default `~/.local/state/syrox/os/NAME/`).

Use the existing profile directly; do not rerun `init` or move its state.
Installation identities, ownership, retained generations, journals and launcher
protocols keep their existing formats. Recorded status and list do not need a
migrated project or a refreshed lock. Recovery continues to use the explicit
manager and identity checks described in [installation profiles](../services-profiles.md).

Previously published artifacts keep their content identities. New builds remain
subject to the current authenticated inputs and produce their corresponding
identities; this migration does not rewrite old artifacts or journals.

## Engine callers and authority

Rust callers must replace `PlanConsumerKind::Os` with
`PlanConsumerKind::Services`. The engine module is now `deployment::services` and its handles use the
`Services` prefix (`ServicesProfile`, `ServicesApplyRequest`, ...). Their
persistence and execution protocols have not been renamed: `syrox-os-*` format
tags and the `__os-service` worker mode stay byte-identical so existing
installations and units keep working.

Services still require the existing matching non-root execution identity.
Systemd system scope continues to require its existing delegated authority.
This migration adds no authority to manage disks, boot entries, kernel settings
or full-system generations.

## Separate System builder configuration

An optional `[build.system]` section now selects explicit worker/manager/helper
endpoints and all eight `[build.system.maximum]` ceilings. Existing configurations
remain valid. Ordinary managed builds continue reading only `[build.managed]`;
System policy never expands their limits or supplies an implicit host toolchain.
See [the builder policy contract](../system-builders.md#select-a-local-system-builder-policy).

`srx system plan .#system --builder-config /absolute/builder.toml` admits the
locked request against that local policy, without starting a build or contacting
the configured endpoints. Only this optional report uses version 2 and its own
observation hash domain; default reports retain version 1. It establishes no
helper authority or runtime enforcement. System output framing is likewise
separately versioned; existing action/receipt and legacy worker formats are not
reinterpreted, and System result admission still cannot create a local receipt.

Rust engine callers can now prepare System components with
`build::system::prepare_system_build_inputs`. Its distinct `SystemBuildAction`
format and System policy are required; do not pass it to legacy Managed action
parsers or execution APIs. System preparation can consume authenticated v3 inputs
and use its admitted source/duration limits without changing ordinary Managed
admission. See [component preparation](../system-builders.md#prepare-a-system-component-and-its-action)
for the exact scope and custody contract. The System service-limit adapter
maps that action to finite manager properties; it does not enable a System CLI
executor, privileged scratch or installation.

`BuildError` has a new `Budget(BudgetError)` variant for resource-specific
admission/capacity failures. Rust consumers with exhaustive matches must handle
it. Existing persisted formats and project locks do not change for these Rust
APIs; project/standard-library changes still require explicit lock updates.

The separate `SystemBuildInputs::prepare_scratch` API can now request private
scratch from the root-authenticated helper endpoint captured during preparation.
It borrows input custody and returns a grant with explicit release semantics;
dropping it preserves uncertainty for helper recovery. Merely preparing inputs
or applying service resource properties still does not allocate scratch. See
[the scratch binding contract](../system-builders.md#bind-a-prepared-component-to-private-helper-scratch).

Chunked inputs now have a separate descriptor export/reader API, exposed for
prepared System inputs through `chunked_input_descriptors`. Receivers need the
exact selected manifest pin, independent byte/FD limits and trusted retention
handoff. The existing chunked manifest v1 bytes, ordinary action/resources and
bundle identities remain unchanged; no automatic cache/lock migration occurs.

`SystemBuildInputResources` now groups legacy/chunked inputs under one aggregate
descriptor budget and a separate locked retention description. Its canonical
`syrox-system-input-resources-v1` record requires an independently authenticated
digest, action and reserve; receivers must not trust the offer's own claims.
`SystemBuildInputTransfer` adds a distinct one-shot, kernel-credential-checked
seqpacket exchange with its own ready/manifest/batch/accepted v1 domains. These
APIs do not enter the ordinary worker protocol or grant execution authority.
See [the complete input contract](../system-builders.md#complete-input-resources-and-receiver-retention).
No standard-library, project-lock, artifact or existing receipt format changes
are introduced by this Rust/transport increment.

The Rust-only `workspace` API adds deterministic, separately bounded scratch and
output ext4 roles derived from an admitted System budget. Its layout has a new
`syrox-system-workspace-layout-v1` identity domain; existing action bytes and
single-scratch helper requests retain their meanings. Callers must authenticate
both root roles and observations and manage partial mount/ownership failures.
This does not enable a System CLI executor or migrate existing journals, project
locks, ordinary worker protocols or artifact identities. See
[the workspace contract](../system-builders.md#separate-scratch-and-output-filesystems).

The helper now has distinct version-1 workspace prepare/release/inspect/recover
operations and a two-image authorization/recovery domain. Update Rust callers
matching the shared `helper_protocol::Request` enum exhaustively. Legacy scratch
requests and records keep their formats and resource allowlist. Workspace journals
use explicit role metadata and their own image/tool names; an older helper may
refuse a state directory containing them. Keep the selected helper and retained
evidence together rather than downgrading or deleting journals to bypass that
refusal. No automatic journal, lock, artifact or receipt reidentification occurs.
`SystemBuildInputs::prepare_workspace` is an explicit new effect; ordinary input
preparation and existing single-scratch calls keep their behavior. See
[the two-volume helper contract](../system-helper.md#two-volume-workspace-protocol).

`srx system recover` now requires exactly one of `--scratch-operation ID` or
`--workspace-operation ID`, plus the explicit helper socket. Existing scratch
invocations and plan-hash domains retain their meanings. Workspace selection
uses the new two-image inspection/reconciliation operations; there is no
automatic kind detection or fallback. Invalid or conflicting selectors and
noncanonical IDs/hashes fail during argument parsing before helper contact.

System source archives now have a separate `SystemArchiveLimits` and explicit
inspection/extraction entry points. Ordinary `ArchiveLimits` validation and build
interpreters keep their existing limits; passing copied System limits to the
legacy entry still fails when they exceed that contract. Prepared System inputs
can inspect their authenticated source under the action budget without starting
an attempt. `Raw` is not implicitly decompressed. No source object, artifact,
action bytes, project lock or ordinary receipt is reidentified by these Rust APIs.
