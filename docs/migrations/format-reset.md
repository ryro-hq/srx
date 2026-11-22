# Pre-release format reset

Before its first release, srx reset every format it writes, hashes or compares.
Format tags lost their version suffixes, a few formats were renamed or split,
tagged records lost their duplicate JSON `version` fields and the build program
magic restarted at `SRXBUILD\x01`. The [format registry](../formats.md) lists the
current tags and the versioning policy that applies from now on.

This is a deliberate, one-time break. Nothing written by a pre-release srx is
read by this srx, and no migration rewrites old data. This page is for anyone
who ran pre-release builds.

## What changes for existing data

Every hash domain and identity tag changed, so every content identity derived
from them changed too: build actions and receipts, results, bundles, system
images, generation pins, catalog artifact recipes and lock digests. Data from a
pre-release srx is therefore refused where srx opens it, with an error that
names the earlier format, instead of failing later with a digest mismatch.

| Data | Refused with | Recreate it by |
| --- | --- | --- |
| `Syrox.lock` with a `syrox-lock-vN` header, or the old unversioned layout without `edges` | `lock written by an earlier srx format; run srx project lock to regenerate it` | `srx project lock` in each project, dependencies before their consumers |
| `Syrox.graph.lock` sidecar | `Syrox.graph.lock was written by an earlier srx format; run srx project lock to remove it` | `srx project lock`, which deletes it |
| Store without `.syrox-store/format` (or with another marker) | `the Store was written by an earlier pre-release srx format; remove the Store directory so srx can recreate it` | removing the Store directory (the configured `store`, or `--store`); srx creates a fresh one on the next build |
| Services installation whose identity file is not `syrox-services-installation` | `Services installation was written by an earlier pre-release srx format; remove the installation directory and run srx services init again` | see [Services installations](#services-installations) |

Results, runtime and system bundles, build receipts and journals live in the
Store or the installation and go away with them. Bundles exported by a
pre-release srx cannot be imported; rebuild and export them again. Recorded
Shell sessions from pre-release builds cannot be inspected or recovered; settle
them with the srx that created them before upgrading.

## Services installations

Units rendered by a pre-release srx are named `syrox-os-<installation>-<hash>.service`
and start the worker with the removed `__os-service` mode, so they cannot run
under this srx. Before upgrading, stop them with the old srx:

```console
srx services stop --profile web
```

If the old srx is gone, stop and disable those units with `systemctl` (add
`--user` for user scope), then delete them and the `.syrox-os-<installation>`
ownership directory from the unit directory and reload the manager.

Then remove the installation directory (by default
`~/.local/state/syrox/os/NAME/installation`) and the profile
(`~/.config/syrox/os/NAME.json`), because a profile is bound to the generated
installation identity and `init` never overwrites it. Recreate both and apply
again:

```console
srx services init .#os --name web --user --config ./build.toml
srx services apply --profile web
```

New units are named `syrox-services-<installation>-<hash>.service`, their
ownership directory is `.syrox-services-<installation>`, and they start the
worker with `__services-worker`.

## Catalog releases

Catalog releases published with a pre-release srx do not work with this srx.
Their locks use the old layout, and their artifact recipe and build action
identities were derived from the old tags. Pin a catalog release published
with this srx, then run `srx project lock`.

## Tag mapping

| Before | After |
| --- | --- |
| `syrox-lock-v4` | `syrox-lock` (single layout; `syrox-lock-v3`, `syrox-lock-v2` and the unversioned layout without `edges` are refused) |
| `syrox-graph-lock-v2` | removed; `Syrox.graph.lock` is refused and `srx project lock` deletes it |
| `syrox-std` | unchanged |
| `syrox-input` | unchanged |
| `syrox-project` | unchanged |
| `syrox-artifact-recipe-v1` | `syrox-artifact-recipe` |
| `syrox-root` | unchanged |
| `syrox-chunked-artifact-v1` | `syrox-chunked-artifact` |
| `syrox-interest-v1` | `syrox-interest` |
| `syrox-durable-interest-v1` | `syrox-durable-interest` |
| `syrox-durable-store-anchor-v1` | `syrox-durable-store-anchor` |
| `syrox-result-v3` | `syrox-system-result` (system results); `syrox-result-v2` became `syrox-package-result` |
| `syrox-artifact` | unchanged |
| `syrox-system-worker-outputs-v1` | `syrox-system-worker-outputs` |
| `syrox-system-output-budget-v1` | `syrox-system-output-budget` |
| `syrox-runtime-bundle-v1` | `syrox-runtime-bundle` |
| `syrox-system-bundle-v2` | `syrox-system-bundle` |
| `syrox-system-image-v1` | `syrox-system-image` |
| `syrox-initramfs-v1` | `syrox-initramfs` |
| `syrox-raw-image-v1` | `syrox-raw-image` |
| `syrox-qcow2-image-v1` | `syrox-qcow2-image` |
| `syrox-verity-image-v1` | `syrox-verity-image` |
| `SRXBUILD` | `SRXBUILD` + version byte `0x01` (was `0x02`) |
| `syrox-host-program-x86_64-v3` | `syrox-host-program-x86_64` |
| `syrox-managed-program-x86_64-v2` | `syrox-managed-program-x86_64` |
| `syrox-build-action-v5` | `syrox-build-action` |
| `syrox-build-result-v4` | `syrox-build-result` |
| `syrox-build-index` | unchanged |
| `syrox-build-closing` | unchanged |
| `syrox-build-attempt-v1` | `syrox-build-attempt` |
| `syrox-build-authorized` | unchanged |
| `syrox-build-revoked` | unchanged |
| `syrox-build-cleaned` | unchanged |
| `syrox-build-outcome` | unchanged |
| `syrox-build-cgroup` | unchanged |
| `syrox-build-operation` | unchanged |
| `syrox-build-origin` | unchanged |
| `syrox-host-toolchain` | unchanged |
| `syrox-output-group` | unchanged |
| `syrox-managed-build-hello-v1` | `syrox-managed-build-hello` |
| `syrox-managed-build-resources-v1` | `syrox-managed-build-resources` |
| `syrox-managed-build-resource-batch-v1` | `syrox-managed-build-resource-batch` |
| `syrox-managed-build-namespace-processed-v2` | `syrox-managed-build-namespace-processed` |
| `syrox-managed-build-commit-v1` | `syrox-managed-build-commit` |
| `syrox-managed-build-exit-v1` | `syrox-managed-build-exit` |
| `syrox-managed-build-exit-observed-v1` | `syrox-managed-build-exit-observed` |
| `syrox-managed-build-retention-processed-v1` | `syrox-managed-build-retention-processed` |
| `syrox-managed-build-retention-observed-v1` | `syrox-managed-build-retention-observed` |
| `syrox-system-managed-x86_64-v1` | `syrox-system-managed-x86_64` |
| `syrox-system-build-action-v1` | `syrox-system-build-action` |
| `syrox-system-build-payload-v1` | `syrox-system-build-payload` |
| `syrox-system-input-resources-v1` | `syrox-system-input-resources` |
| `syrox-system-input-ready-v1` | `syrox-system-input-ready` |
| `syrox-system-input-manifest-v1` | `syrox-system-input-manifest` |
| `syrox-system-input-batch-v1` | `syrox-system-input-batch` |
| `syrox-system-input-accepted-v1` | `syrox-system-input-accepted` |
| `syrox-generation-v2` | `syrox-generation` |
| `syrox-shell-session-v2` | `syrox-shell-session` |
| `syrox-shell-command-index-v1` | `syrox-shell-command-index` |
| `syrox-shell-operation-v2` | `syrox-shell-operation` |
| `syrox-os-installation-v1` | `syrox-services-installation` |
| `syrox-os-candidate-v1` | `syrox-services-candidate` |
| `syrox-generation-root-v1` | `syrox-generation-root` |
| `syrox-os-activation-v1` | `syrox-services-activation` |
| `syrox-os-launch-v3` | `syrox-services-launch` |
| `syrox-os-scope-v1` | `syrox-services-scope` |
| `syrox-os-reload-target-v1` | `syrox-services-reload-target` |
| `syrox-unit-ownership-v1` | `syrox-unit-ownership` |
| `syrox-os-unit-v1` | `syrox-services-unit` |
| `syrox-systemd-v1` | `syrox-systemd` |
| `syrox-systemd-manager-v1` | `syrox-systemd-manager` |
| `syrox-observed-build-unit-v1` | `syrox-observed-build-unit` |
| `syrox-observed-shell-service-v1` | `syrox-observed-shell-service` |
| `syrox-loaded-os-unit-v1` | `syrox-loaded-services-unit` |
| `syrox-command-execution` | unchanged |
| `syrox-command-root-arguments-v1` | `syrox-command-root-arguments` |
| `syrox-shell-command-request-v1` | `syrox-shell-command-request` |
| `syrox-command-guardian-v2` | `syrox-command-guardian` |
| `syrox-command-monitor` | unchanged |
| `syrox-command-monitor-ack-v1` | `syrox-command-monitor-ack` |
| `syrox-session-state-v2` | `syrox-session-state` |
| `syrox-service-role-v1` | `syrox-service-role` |
| `syrox-service-body-v1` | `syrox-service-body` |
| `syrox-service-offer-v1` | `syrox-service-offer` |
| `syrox-service-chunk-v1` | `syrox-service-chunk` |
| `syrox-service-resources-v1` | `syrox-service-resources` |
| `syrox-owner-v1` | `syrox-owner` |
| `syrox-service-v2` | `syrox-service` |
| `syrox-terminal-attributes-v1` | `syrox-terminal-attributes` |
| `syrox-system-tree-v1` | `syrox-system-tree` |
| `syrox-system-inventory-v1` | `syrox-system-inventory` |
| `syrox-filesystem-observation-v1` | `syrox-filesystem-observation` |
| `syrox-builder-limits-v1` | `syrox-builder-limits` |
| `syrox-system-workspace-layout-v1` | `syrox-system-workspace-layout` |
| `syrox-private-scratch-activation-v1` | `syrox-private-scratch-activation` |
| `syrox-private-scratch-authorization-v1` | `syrox-private-scratch-authorization` |
| `syrox-private-scratch-journal-v1` | `syrox-private-scratch-journal` |
| `syrox-private-scratch-recovery-plan-v1` | `syrox-private-scratch-recovery-plan` |
| `syrox-private-workspace-authorization-v1` | `syrox-private-workspace-authorization` |
| `syrox-private-workspace-recovery-plan-v1` | `syrox-private-workspace-recovery-plan` |
| `syrox-release-v1` | `syrox-release` |
| (new) | `syrox-store`, the Store format marker |

Other renames: the plan protocol `program-v2` is now `program`, rendered Services
units and their ownership directory use `syrox-services-` instead of
`syrox-os-`, and the worker mode `__os-service` is now `__services-worker`.
