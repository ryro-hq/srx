# SRX: building Linux systems, kernel, boot and storage

**Status:** architecture document and implementation roadmap. Apart from the
increments recorded below, the proposed contracts, types and commands await
implementation.
**Study reference date:** October 21, 2026.
**Repository:** `syrox`; executable: `srx`.

**First increment implemented:** the public `Os` type was renamed to
`Services`, planning uses `PlanConsumerKind::Services` and the services
commands use `srx services`. Profiles, journals and persisted protocols keep
their formats and identities. The [migration](../migrations/services.md)
describes how to update projects and locks. The remaining stages are still
proposals; references below to the current `Os` describe the baseline of the
study, prior to the migration.

**Artifact foundations implemented:** the
[`store::chunked`](../../crates/syrox-engine/src/store/chunked.rs) module
admits and reopens streams in 4 MiB chunks with a v1 manifest, an identity of
the complete content and bounded in-memory verification. Handles and roots
retain the complete set of objects using the current retention, recovery and
GC contracts. The
[format contract](../artifacts.md#large-streams-in-the-engine-store) describes
limits and guarantees. Explicit admission of system outputs uses budgets and
v3 results with v2 bundles and streaming materialization. Integration of
workers, receipts, the execution profile and the CLI is still pending; the
ordinary limits remain.

The interfaces include streaming writes with verified finalization and a
reader with seek and a single-chunk cache. Initramfs generation already uses
direct writes to the Store; indexes of large outputs will be able to use the
reader without loading the whole artifact into memory.

Preparation of managed sources now keeps an authenticated descriptor and
granular retention, revalidates identity/metadata and copies by streaming with
a hash, a limit and EOF before the atomic publication. Worker inspection also
verifies the source without collecting its entire content. A hundred tests of
the managed flow passed, in addition to a real build with binutils already
produced from sources and execution of the new result. The ordinary envelopes,
formats and limits remain preserved; the complete system profile is still
pending.

**Inventory implemented:** `srx system inspect [--json]` observes the kernel,
firmware, presence of the KVM device, block devices, identities, geometry,
partitions, holders/slaves and mounts of the current namespace. The
[`syrox-system`](../../crates/syrox-system/src/lib.rs) library can be shared
with the helper without depending on the language or the builder. Inspection
does not open block devices, does not run utilities and does not create
configuration or a Store.

**Loop primitives verified in a VM:** the library configures only private
regular images with revalidated identity and size, fixed geometry and
AUTOCLEAR. A Rust executable passed on a pinned Fedora CoreOS, booted by
QEMU/OVMF from disk with TCG: bounded writes, metadata changes, deferred
release and a new attempt after shutdown were observed. There was no network,
physical disk or change to the host boot. The [environment and evidence](../test-tools.md#disposable-loop-device-guest)
are recorded. The detached ext4 mount primitive also passed in the VM:
storage and inode limits, release deferred by a descriptor of the root and a
final e2fsck verification were observed. Integration of the unprivileged worker
and enforcement of the remaining budget dimensions are still pending. The state
does not confuse ENXIO during rundown with completed removal.

**Isolated tool execution verified:** static, authenticated mke2fs/e2fsck ran
in private namespaces, from sealed memfds, with a read-only root, zeroed
capabilities and a syscall filter. A probe verified inherited descriptors,
paths, limits and refusals of operations; the ext4 checks before/after,
exhaustion and release passed in the VM. The
[qualification record](../test-tools.md#isolated-ext4-tools) distinguishes the
earlier attempts and the observed scope. The separate
[`syrox-system-helper`](../system-helper.md) executable already implements
administrator policy, peer authentication and a private scratch lifecycle with
a journal. Its integration with a UID/GID 1000 client passed in the VM: handoff
and writes without root, verified release, effect-free refusal of invalid
requests, preservation on replay and blocking of a new format after an
uncertain disconnect. Recovery after reset, worker integration and provisioning
are still pending. The helper protocol now offers explicit inspection and
reconciliation of the scratch within the same boot, bound to the hash of the
evidence. It preserves the image, blocks a still-live session, a tool without a
result or an active loop, and distinguishes reconciliation from verified
health. Eight local tests and 19 VM scenarios passed, including an altered
journal, reconciliation with a preserved image and a descriptor retained by the
client. This does not yet constitute evidence of recovery after reset.

Receiving/attaching the scratch is also implemented in the library. A
UID/GID 1000 process moved the mount through descriptors into its private
namespace, dropped its capabilities and wrote to the ext4; the helper verified
the release and the filesystem at the end. The repetition using
`ReceivedScratch` passed the 20 VM scenarios, with binaries and hashes separate
from the earlier probes. Binding to the build worker and enforcement of the
complete budget are still missing.

The pure generator of helper activation by systemd was also implemented. A new
VM passed the 24 scenarios, including a seqpacket socket on fd 3, a non-root
client, real cgroup limit values, refusal of access to the VM's virtual disk
and refusal of writes outside the authorized state. The test used units
installed only in the guest. These limits belong to the helper; the profile and
configuration of the System builder still need to be connected.

The typed helper client and `srx system recover` also passed in a new VM, with
29 scenarios. The coordinator authenticates the root peer and the sealed
receipts, keeps control outside the worker namespace and transfers only the
scratch root. The CLI inspects an explicit operation without effects and
reconciles only the authorized hash; an incorrect hash was refused and the
image bytes were preserved. This recovery covers private scratch within the
same boot. Build worker integration, recovery after reset and recovery of
complete generations are still pending.

**Filesystem and quota observation implemented:** the shared library queries
capacity, inodes, inherited project, accounting, enforcement and limits by
descriptor. The fixed `FS_IOC_GETFSUUID` query adds the external UUID as a
supplementary observation, without changing the existing fingerprint or
checking ownership. `srx system inspect --builder-directory PATH [--json]`
exposes these observations without creating directories or changing quotas.
Missing support or privilege is explicit. The
[builder contract](../system-builders.md) separates this evidence from the
preparation and execution that are still pending.

**Shared primitives and offline import implemented:** the engine reuses the
descriptor library for restricted paths, locks and FD transport and for sealed
credential snapshots, preserving the existing protocol, 64 KiB limit and
identity checks.
`srx project import-source` admits an explicitly selected file against the
source's SHA and limit in the authenticated project, without changing the URL
or the lock. The [import contract](../source-import.md) describes validation
and retention. The catalog received an experimental static e2fsprogs recipe
with an explicit host seed. A native build by SRX, creation/verification of a
regular 64 MiB ext4 image in the sandbox and execution of the three tools by
the runtime were carried out. The result retains the source, the seed
inventory, the action, the artifact and the receipt. The tools were also run in
the qualification of the mounted ext4 primitive in a VM. This does not qualify
an own toolchain, a system executor or provisioning; those integrations are
still pending.

**Budget and storage contracts implemented:** the same library validates
resource requests against explicit administrator limits and capacity
observations, and plans GPT/ESP, RAID1/10, LUKS2, LVM, filesystem and mount
graphs. The graph resolves disks by WWID/serial and rejects ambiguous targets,
observed use, cycles, overlap, incompatible compositions and overcommit. The
`srx system plan PROJECT#OUTPUT` CLI connects the authenticated declarations to
the inventory, compares the requested sysctls and attempts to resolve the
disks. It distinguishes an unresolved binding, destructive provisioning, a
generation reboot and a parameter restore not yet verified. The report
identifies the current namespaces and keeps `can_apply: false`; its hash
records evidence without authorizing writes. The new system execution profile
and the privileged application still need to be implemented. These contracts
and observations do not constitute qualification of the storage stacks.

**Composition and initramfs implemented in the library:** trees with explicit
producers, ownership, permissions and links are validated and versioned. The
`newc` writer verifies files by streaming; the engine consumes authenticated
outputs, admits the archive in chunks and retains the tree, provenance and
sources. The [images contract](../system-images.md) records limits and checks.
There is not yet an own kernel/PID 1, a UKI or a qualified system boot.

**dm-verity tree implemented in the library:** the Rust writer emits format 1
with SHA-256, 4 KiB blocks, an explicit salt and levels in root order. The
engine generates levels by streaming into the Store and retains data, tree and
parameters. A comparison with a pinned `veritysetup` verified bytes and root
for seven sizes, including level transitions and the single-block case with no
tree. This evidence covers the format in userspace; kernel activation, UKI
signing and boot are still pending. The
[images contract](../system-images.md#dm-verity-hash-devices) defines limits and
retention.

**System declarations implemented:** the std offers `System` and
`HostConfiguration`, projected separately from the services consumers. The
planner validates references to outputs, budgets, A/B/ESP roles, storage
structure, identity, exposures, services/health and kernel/host selections.
The [declarations contract](../system-declarations.md) describes usage and the
checks still pending, including upstream Kconfig and privileged application.
The typed projections preserve Kconfig options, identity/users, credential
references, boot, health and persistent data compatibility for the later
builders and executors.

**binutils bootstrap exercised:** the catalog builds the 2.47 tools for
`x86_64-srx-linux-gnu` from the authenticated upstream source, with an explicit
host seed. Nine executables passed static ELF inspection. A second managed
build consumed that output, assembled/linked/ran a pinned assembly source with
`toolchain none` and produced a bundle run offline. The receipts retain the
dependency on the original seed; an own compiler, sysroot and Rust chain still
need to be built and qualified.

**make bootstrap exercised:** GNU make 4.4.1 was built with an explicit seed
and an unchanged Standard budget. A managed consumer used make and binutils
produced from sources to generate assembly, link and run the result, with
`toolchain none`; its bundle also passed in the offline runtime. The historical
make signature reports `EXPKEYSIG`, with its cryptographic validity recorded:
the time-based admission policy remains an open qualification item and this
recipe is outside the publication matrix. The catalog records identities,
limits and this restriction in the development evidence.

**RAW/GPT writer implemented in the library:** validated layouts receive
partition images with explicit SHA and size and generate a protective MBR,
primary/secondary GPT, payloads and deterministic padding by streaming. The
engine publishes chunks and the manifest only after verifying the inputs and
retains the union of the objects. A pinned `sfdisk` recognized regular images
with 512/4096-byte sectors and the secondary copy after corruption of the
primary. This evidence establishes GPT interoperability in userspace; it does
not yet represent a rootfs, ESP or bootable disk. The
[images contract](../system-images.md#gpt-raw-disk-images) records the limits
and the remaining work.

**qcow2 conversion implemented in the library:** a Rust writer generates a
self-contained qcow2 v3, by streaming, with 64 KiB clusters and 16-bit
refcounts. The engine consumes `BuiltRaw`, retains its provenance and the
transitive partitions, and publishes the conversion only after verifying length
and SHA. A signed `qemu-img` fixture was prepared in the workspace, without
installing packages on the host. The tests verify refcounts and compare the
conversion back to RAW; the fixture still depends on host libraries and does
not qualify the boot environment.
The [contract](../system-images.md#standalone-qcow2) and the
[test inputs](../test-tools.md) record these distinctions.

**System component preparation implemented:** the engine verifies the
component's membership in the authenticated System closure, its recipe,
source, worker and inputs, including v3 results. The new v1 action records the
budget, policy, source limit and its own protocols; it does not enter the
ordinary v5 parser. Granular retention allows GC and preserves inputs whose
roots were removed. The limits adapter derives finite systemd properties from
the action's budget and allows observing the complete unit contract. The
[builder contract](../system-builders.md#prepare-a-system-component-and-its-action)
separates this preparation from execution, scratch, settlement and system
receipts, which still need to be integrated. The explicit scratch request was
also bound to the action and to input retention: control stays in the
coordinator, only the root can be duplicated and release requires independent
checks by the helper. This binding passed in the disposable VM `v10`, with 33
scenarios, writes through a descriptor, GC keeping the source and release with
verified filesystem and loop.
This does not yet start a worker nor qualify the complete executor.
The limits of ordinary builds remain.

**Large inputs through descriptors implemented:** System preparation exports
the manifest and deduplicated CAS chunks under an explicit FD limit. The new
reader verifies roles, metadata, chunk hashes and the complete logical hash,
offers seek with a single 4 MiB cache and does not use Store paths. A real
stream of 1 GiB + 17 bytes passed with four descriptors; the v3 input case also
passed after its root was removed by GC. The authenticated transport, receiver
retention and resource package of the new worker still need to be connected.
This does not change the manifest format nor make the ordinary worker accept v3
inputs.

**Complete input handoff implemented:** preparation counts the FDs of all
inputs and the executor's reserve before creating additional retention. The
versioned package includes views, ordinary/chunked artifacts and an independent
retention description. The receiver verifies hash/metadata, references and
content, acquires the interest lock and preserves custody after the sender
exits and the roots are removed by GC. The separate seqpacket transport
validates kernel credentials, nonce, hashes, offsets and batches before
confirming receipt. A cross-process test passed with 33 mixed inputs and 84
descriptors, keeping the data after GC in the parent. Binding to the
executable/manager identity, FDSTORE, a writable workspace, gate, settlement
and receipts are still missing for a complete System executor.

**Separate work and output volumes implemented:** the layout derives two ext4
filesystems from the same admitted budget and splits the global inode ceiling
in proportion to the bytes. The output can be larger than the scratch without
forging a new admission. The primitives verify distinct identities, descriptor
roles, geometry, ownership and targets before attaching the mounts. On
November 2, 2026, the QEMU/OVMF VM passed the 33 earlier cases and ten new
ones: 64 MiB scratch, 128 MiB output, 1,008 effective inodes within the 1,024
ceiling, separate exhaustion, a UID/GID 1000 worker without capabilities after
attachment and independent release of the loops, followed by two ext4 checks.
The `tests/fixtures/system-build/system-workspace-vm.json` fixture records pins
and evidence. This first qualification used the earlier single-scratch protocol
for the helper tests and exercised the volume pair directly through the
primitives. Filesystem capacity limits allocated space; logical lengths of
sparse files require separate limits and result validation.

**Component workspace and two-volume helper implemented:** separate
preparation, release, inspection and recovery operations now keep both images
in a single journal. The root policy admits the same request independently of
the coordinator's policy. Release requires teardown of both loops and two final
checks; reconciliation within the same boot preserves the images and does not
assert filesystem health. `SystemBuildInputs::prepare_workspace` keeps custody
of the inputs during the grant and revalidates both roles before exporting
FDs. The VM `v14` passed 59 distinct cases, including real preparation of a
declared component, write/fsync on both volumes, GC, input revalidation and
release without creating a build or receipt. It also verified budget refusal,
an incorrect hash, disconnect and a retained descriptor blocking recovery. The
two earlier non-qualifying runs remain recorded separately.
`tests/fixtures/system-build/system-workspace-rpc-vm.json` contains pins, scope
and evidence. Still missing are the gate and custody in the manager/FDSTORE,
recipe execution, complete enforcement and System receipts.

**Workspace recovery through the CLI implemented:** `srx system recover`
requires exactly one selector, `--scratch-operation` or
`--workspace-operation`, plus the explicit socket. The VM `v15` passed the 59
earlier cases and five new CLI ones: abandonment, inspection, incorrect hash,
authorized reconciliation and terminal state. The hashes of both images were
preserved; recovery did not assert filesystem health. The
`tests/fixtures/system-build/system-workspace-cli-vm.json` fixture records the
64 cases, the binaries and the normal shutdown. There is no fallback between
operation kinds, automatic reboot, recovery of generations or recipe execution
in this flow.

**Extraction of large System sources implemented:** a separate envelope
derives expansion, individual file and entry limits from the geometry/inodes of
the admitted scratch; compressed transport keeps the 1 GiB blob ceiling. The
reader uses its own offsets and detects length changes. Inspection and
extraction share the safe parser; the limits and subsets of the ordinary
profiles remain. Inspection of the prepared inputs verifies the pin
before/after and neither creates a build nor calls the helper. 28 tests passed,
in addition to the subprocess with 1 GiB + 17 bytes under a 256 MiB address
limit; 65,537 entries also passed on the System path and were refused by the
ordinary limit. The native evidence is in
`tests/fixtures/system-build/native-system-source-archive.json`. This path
still needs to be selected at the entry point and in the authorized namespace
of the System worker; the run does not execute a recipe nor qualify the
complete profile.

## 1. Goal

Expand SRX to serve two uses:

1. Build a complete Linux system from sources and generate bootable images.
2. Manage selected resources of existing Linux installations.

The user should be able to declare kernel, parameters, modules, boot, storage
and services in `.srx`, check the types, inspect a plan and authorize its
application.

The goal includes making the consequences of changes visible. The plan needs to
distinguish a reversible configuration change, a change that requires a reboot
and an operation that destroys data.

The first complete delivery will be qualified in disposable VMs. Support for
real hardware will come after that qualification.

## 2. Settled decisions

| Area | Decision |
|---|---|
| System construction | Distributed components built by SRX from sources |
| Bootstrap | Own managed toolchain before building the base |
| Full-system update | Immutable generations |
| First environment | Disposable VM |
| Initial architecture | Linux x86_64 |
| Firmware and boot | UEFI and systemd-boot |
| Initial profile | Console, network and SSH |
| Initial security | Secure Boot and LUKS2 |
| Initial filesystem | ext4 |
| Volume management | LVM |
| Initial RAID | RAID1 and RAID10 |
| Adoption of existing installations | Arch, Debian and Ubuntu |
| API compatibility | Breaking changes allowed, with documented migration |
| TPM2 and desktop | Later stages |

These decisions define a minimal functional Linux. Expansion to desktop, other
architectures and other storage stacks will be built on this base.

## 3. Current project status

SRX already provides important parts of the foundation:

- Typed language, modules and declarative configuration.
- Authentication of projects, assets and the standard library.
- Locks and source acquisition with explicit identity.
- Recipes, dependencies and build execution.
- Store with content verification, retention and recovery.
- Planning prior to effects.
- Execution of applications with their dependencies.
- Preparation and application of services generations.
- systemd integration and observation of Linux capabilities.
- Journal and recovery of interrupted operations.

The current `Os` contains packages and services. It operates on an existing
Linux and does not represent a complete installation with kernel, boot and
disks. The current contracts are described in
[installation profiles](../services-profiles.md) and
[artifact selection](../artifacts.md).

The current profiles also require a non-root execution identity. This
restriction must keep protecting the services and builds flow. The new system
authority will be a separate capability.

There are concrete limitations for building larger systems:

| Current limit | Value |
|---|---:|
| Compressed source in the Large profile | 32 MiB |
| Raw source in the Large profile | 128 MiB |
| Individual output | 128 MiB |
| Aggregate result | 512 MiB |
| Individual blob in the Store | 1 GiB |
| Maximum build duration | 30 minutes |
| Large profile scratch | Approximately 1 GiB in tmpfs |

These limits were checked in
[`build`](../../crates/syrox-engine/src/build/mod.rs),
[`BuildProgram`](../../crates/syrox-engine/src/build/program.rs),
[`artifact`](../../crates/syrox-engine/src/result/artifact.rs),
[`result`](../../crates/syrox-engine/src/result/mod.rs) and
[`store`](../../crates/syrox-engine/src/store/mod.rs). The profiles' identity
restriction is in
[`deployment::services::profile`](../../crates/syrox-engine/src/deployment/services/profile.rs).

Kernel, compilers and images exceed some of these limits. The implementation
needs to evolve the artifact and resource model before adding their recipes.

## 4. Separation of the public concepts

The API should distinguish three operations of different nature.

### `Services`

Represents the current role of `Os`: packages and services managed on top of an
existing system.

User profiles remain without authority to modify boot, partitions or global
settings.

### `System`

Represents a complete system:

- Platform.
- Kernel and modules.
- Userspace.
- Identity and users.
- System configuration.
- Boot.
- Storage.
- Services.
- Health and update policy.

A `System` needs to provide enough information to build a bootable generation.

### `HostConfiguration`

Represents resources that SRX will be able to manage on an existing
distribution.

The configuration explicitly selects which resources belong to SRX. This allows
adopting sysctls, mounts, services or a kernel without taking ownership of the
whole installation.

The three concepts will share domain types, but will have their own validations
and operations.

## 5. Responsibilities across core, std and catalog

### Core

The core should implement:

- Planning and validation of operations.
- Inspection of capabilities and devices.
- Verification and transfer of artifacts.
- Execution authority.
- Journal, recovery and retention.
- Application of privileged operations.
- Observation of boot and health.
- Contracts consumed by the backends.

### Standard library

The std should offer the types and constructors used in `.srx`, including:

- `Services`.
- `System`.
- `HostConfiguration`.
- Kernel and kernel configuration.
- Boot.
- Storage graph.
- Filesystems and mounts.
- Credential references.
- Health and persistence policy.

Evaluating these values will remain an operation without effects on the
machine.

### Catalog

The catalog should contain the recipes and contracts of the components:

- Compilers and tools.
- Linux and headers.
- libc and libraries.
- systemd, udev and boot components.
- Shell and utilities.
- Networking and OpenSSH.
- Partitioning, filesystem, encryption, LVM and RAID tools.

Versions, sources, patches, licenses and qualified combinations will continue
to belong to the catalog.

Core operations must not contain branches by package name to execute these
recipes.

## 6. Bootstrap and building from sources

Building the entire base requires an explicit bootstrap chain.

The first compiler and its tools will be authenticated inputs. From them, SRX
will build its managed toolchain, which will be used to produce the distributed
components.

The flow will be:

1. Admit the tool seed and record its identity.
2. Build the compilers, binutils, sysroot and required tools.
3. Validate the managed toolchain.
4. Build the userspace and the kernel with that toolchain.
5. Verify that the build does not depend on undeclared environment tools.
6. Produce the system artifacts and their provenance.

The toolchain should declare the C/C++ compiler, linker, assembler, headers,
libraries and auxiliary tools. The support needed to build SRX itself should
also enter this chain.

The managed build must not silently fall back to the host's `/usr/bin`, headers
or libraries.

Images of existing distributions may be used as adoption fixtures. They will be
identified, pinned and recorded as test environments.

Upstream dependencies implemented in Python or shell will be packaged normally.
The project's own maintenance and orchestration will remain in Rust.

## 7. Large artifacts and build resources

Introduce a new artifact version to represent larger outputs without requiring
giant blobs or loading whole images into memory.

The format will use:

- 4 MiB chunks.
- Content hashes.
- Versioned manifests.
- Streaming transfer and verification.
- Transitive references for retention and GC.
- Publication only after complete verification.

GC should understand the relationship between manifests, chunks, installed
generations and pending operations.

Create a system build profile with an explicit budget for:

- Memory.
- CPU.
- Processes and descriptors.
- Disk scratch.
- Number of files.
- Output.
- Duration.

The builder administrator will define the admitted limits. An incompatible
budget should fail before the build starts.

The existing profiles will keep their limits. The change must not make the
execution of ordinary recipes unbounded.

## 8. Kernel configuration

Configuring the kernel involves four layers.

| Layer | Examples | When |
|---|---|---|
| Kconfig | Drivers, filesystems, security, namespace features | Compilation |
| Command line | Console, root, boot parameters | Boot |
| Modules | Inclusion, loading and parameters | Initramfs or runtime |
| Runtime parameters | sysctl and supported device settings | Running system |

These layers should appear separately in the API and in the plan.

### Kconfig

Generate contracts per version and architecture, offering:

- Symbol autocompletion.
- Boolean, tristate, integer, hexadecimal and string types.
- Diagnostics for unknown names.
- Reference to the originating field in the `.srx`.
- Identity of the effective configuration.

Dependency resolution will use upstream Kconfig. After it, compare the final
configuration with the requested values and diagnose options that could not be
satisfied. Reference:
[Kconfig documentation](https://docs.kernel.org/kbuild/kconfig.html).

### Kernel identity

The identity should bind source, patches, configuration, architecture,
toolchain, kernel, modules and headers.

Modules from incompatible configurations must not be mixed. The release used at
runtime should distinguish the kernels produced by SRX.

The reference versions recorded in the study are Linux LTS `6.18.57` and
systemd `262.1`. They are roadmap candidates, without automatic admission to
the catalog: their admission requires verified sources and explicit locks.
References:
[Linux](https://www.kernel.org/) and
[systemd](https://github.com/systemd/systemd/releases/tag/v262.1).

### Runtime parameters

Each setting should declare how it is applied and verified.

Changes that do not allow reliable restoration will be classified in the plan.
Settings that depend on a reboot will not be treated as instantaneous changes.

Boot parameters derived from storage will be generated from the validated
graph, avoiding contradictions between the declared root and the command line.

## 9. Userspace and system tree

The initial base should provide:

- systemd as PID 1.
- udev.
- Shell and essential utilities.
- Networking for the VM.
- OpenSSH.
- SRX and its system components.
- Tools required for storage.
- Essential boot and diagnostic services.

The image composition should record:

- Paths.
- Entry type.
- Ownership.
- Permissions.
- Links.
- Origin of each file.
- Content and identity of the components.

Package prefixes under `/syrox/store/` will be preserved. The exposures in
`/usr`, `/etc` and other directories will be declared and verified.

Collisions between components should be diagnosed before the image is
generated. The composition must not incorporate host files through implicit
discovery.

The image should work without the build directory, the original checkout or
external caches.

## 10. Images and boot

Produce the artifacts required for:

- Rootfs.
- Initramfs.
- UKI.
- RAW image.
- qcow2 image.
- UEFI installation and rescue ISO.

Use signed UKIs to bundle kernel, initramfs, parameters and boot metadata. The
immutable root will be verified by dm-verity, with its hash bound to the
authorized generation. References:
[UKI](https://www.freedesktop.org/software/systemd/man/latest/ukify.html) and
[dm-verity](https://docs.kernel.org/admin-guide/device-mapper/verity.html).

The deterministic parts will have reproducibility verification. Machine
identity, entropy and cryptographic material will be produced per
installation.

LUKS volumes of different installations will not share keys generated by the
image. Installation images will carry the artifacts and tools to provision the
instance.

## 11. Immutable generations and boot confirmation

The complete system will use an A/B root.

An update should:

1. Verify the new artifacts.
2. Prepare the inactive slot.
3. Verify its content.
4. Publish the corresponding kernel and boot entry.
5. Record the generation as a candidate.
6. Schedule a boot attempt.
7. Confirm the generation only after observing its health.

Confirmation should take into account the kernel, root, persistent volumes and
essential services.

The previous healthy generation will remain available during the attempt. The
bootloader will use attempt counting and fallback. Reference:
[Automatic Boot Assessment](https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/).

A hang may require a watchdog or a new reset for another attempt to occur. The
tests and reports should identify the mechanism used.

The state should distinguish a built, prepared, selected, booted and confirmed
generation.

## 12. Persistent data and rollback

Kernel, userspace and system configuration belong to the generation.
Persistent data has a separate lifecycle.

This includes:

- Application data.
- Home directories.
- Credentials.
- Installation identity.
- Journal.
- State required for recovery.

Rollback will select a previous system generation and its configuration.

Data migrations should declare compatibility with the generations involved. An
incompatible update will require an explicit strategy; selecting a previous
root will not be presented as restoring the data.

Retention should protect the running generation, the pending candidate and the
healthy generation required for fallback.

## 13. Storage model

Represent storage as a resource graph.

The first implementation should cover:

```text
Disk
  └─ GPT partition
       ├─ ESP
       └─ Data
            └─ Optional RAID
                 └─ Optional LUKS2
                      └─ Optional LVM
                           └─ Filesystem ext4
                                └─ Mount
```

The graph should also represent the multiple members of RAID compositions; the
tree above shows the layer order of a single stack.

The validator should detect cycles, invalid references, overlap, insufficient
capacity and unsupported compositions.

The declaration will select disks by identity and observed properties. Names
such as `/dev/sda` may appear in diagnostics, but will not be the sole
authority for performing a write.

Resolution should require an unambiguous target and revalidate identity,
geometry and metadata before changes.

### Partitioning and filesystems

Manage GPT, ESP and ext4 with authenticated upstream tools.

`systemd-repart` may be used where its semantics fit the operation. It adds and
grows partitions, but does not offer shrinking, moving or removal as general
reconciliation. Reference:
[repart documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html).

### LUKS2

Manage creation, opening, referencing and verification of LUKS2 volumes.

Credentials will be resolved through private channels. The plan should show
references and effects without revealing passwords or keys.

Recovery should remain available when the usual unlocking fails. TPM2 will be a
later expansion. Reference:
[LUKS2 credentials](https://www.freedesktop.org/software/systemd/man/latest/systemd-cryptenroll.html).

### LVM

The first implementation will use traditional volumes with verified identity
and capacity.

Removing a declaration will not automatically erase a volume.

### RAID

Qualify:

- RAID1 with two drives.
- RAID10 with four drives.

Verify assembly, member loss, rebuild and return to a healthy state. The ESPs
will remain independent, with consistent boot content.

Storage redundancy and generation recovery will be verified as distinct
properties.

## 14. Privileged authority

Add a small privileged helper in Rust.

The compiler, evaluator and builder will remain outside this process. The
helper will receive structured operations and references to already prepared
artifacts.

It should:

- Validate the plan and the requester's authority.
- Reopen and verify the real resources.
- Restrict operations to the authorized scope.
- Run admitted tools and operations.
- Record intent and result.
- Verify the observed state.
- Preserve uncertain operations for recovery.

The helper will not accept arbitrary shell supplied by the project.

Privileged services will be explicit resources of the authorized system, with
their executables and configuration bound to the plan.

Shared Linux primitives should live in a library that allows the helper to
operate without loading the language and the build components.

## 15. Destructive operations and recovery

Provisioning will be an explicit operation.

Its plan should show:

- Selected devices.
- Observed identities.
- Previous layout.
- Intended layout.
- Data that will be overwritten.
- Required credentials.
- Preconditions.
- Irreversible steps.
- Recovery procedure.

Authorization will be bound to the hash of that plan.

Changes to devices, metadata or relevant state will invalidate the plan.
Operations incompatible with disks in use should be rejected.

The journal should allow observing what happened after interruptions. Recovery
must not automatically repeat a format to resolve doubt about the previous
result.

When the evidence is insufficient, the operation will remain uncertain and
will require explicit reconciliation.

## 16. Adoption of Arch, Debian and Ubuntu

Adoption will manage selected resources, preserving the distribution's root and
package management.

The flow will be:

1. Inspect the installation.
2. Discover capabilities.
3. Identify existing resources and conflicts.
4. Select what will be under SRX management.
5. Record ownership.
6. Produce the plan.
7. Apply and verify the authorized effects.

The first resources will be runtime kernel settings, modules, mounts, services
and managed kernels.

New kernels will use modules and UKIs in their own locations, with a test UEFI
entry and preservation of the previous boot. Persistent selection will depend
on confirmation of a healthy boot.

Converting an adopted installation into a complete SRX system will be a
separate migration and provisioning operation.

Each distribution should be qualified on pinned fixtures and with its
capabilities observed.

## 17. Proposed CLI

The interfaces below are proposed for implementation; their presence in this
table does not indicate availability in the current executable.

| Operation | Interface |
|---|---|
| Check declarations | `srx project check` |
| Update pins explicitly | `srx project lock` |
| Inspect a machine or image | `srx system inspect` |
| Compare configuration and observed state | `srx system plan` |
| Build images | `srx system build` |
| Register resources of an existing installation | `srx system adopt` |
| Create storage and install | `srx system provision` |
| Apply configuration or prepare a generation | `srx system apply` |
| Query status | `srx system status` |
| Select a previous generation | `srx system rollback` |
| Reconcile an interrupted operation | `srx system recover` |
| Manage the current set of services | `srx services …` |

Building an image will not authorize its installation. Planning will not apply
changes. Preparing a generation will not imply an automatic reboot.

## 18. Breaking changes and migration

The expansion will allow reorganizing the API, while keeping a verifiable
migration.

Main changes:

- Rename the current `Os` to `Services`.
- Migrate services commands to `srx services`.
- Introduce `System` and `HostConfiguration`.
- Version the affected manifests, build protocols, artifacts and profiles.
- Evolve the toolchain contracts.
- Update std, catalog, examples, diagnostics and autocompletion.
- Update locks explicitly.

Old profiles will have a documented migration path. The conversion will
preserve installation identity and history, without introducing privileged
authority.

Published artifacts will not be silently reidentified. Build changes will
produce new identities, keeping the earlier evidence available.

## 19. Testing strategy

The current microVM will continue covering the existing engine contracts.

Qualification of the complete system will add QEMU and OVMF, booting through
the firmware and the disk. Boot tests will not use `-kernel`, since it bypasses
part of the chain that needs to be verified.

### Language and planning tests

- Imported types and fields.
- Kconfig autocompletion.
- Unknown symbols and incompatible values.
- Invalid storage graphs.
- File collisions.
- Ownership and permissions.
- Effect-free planning.

### Artifacts and builders

- Streaming and limits.
- Missing or corrupted chunks.
- Cancellation.
- Retention and GC.
- Recovery.
- Building without environment dependencies.
- Verification of the deterministic parts.

### Boot and generations

- First boot.
- A→B update.
- Confirmation.
- Faulty candidate.
- Return to the previous generation.
- Tampered or untrusted UKI.
- Modified root.
- Interruptions during publication and selection.

### Storage

- Single disk.
- LUKS2 with LVM.
- RAID1 with LUKS2 and LVM.
- RAID10 with LUKS2 and LVM.
- Incorrect credential.
- Device identity change.
- Member loss and rebuild.
- Preservation of unauthorized data.
- Interruptions in destructive steps.

### Adoption

Run the relevant scenarios on Arch, Debian and Ubuntu, verifying the previous
boot, unmanaged resources, conflicting settings and kernel rollback.

Missing KVM or another required capability will be recorded as an impediment to
that qualification.

## 20. Implementation stages

| Stage | Verifiable result |
|---|---|
| 1. Foundations | Large artifacts, budgets, manifests, shared primitives and read-only inventory |
| 2. Bootstrap | Managed toolchain built and validated |
| 3. Own base | Userspace and kernel produced by the recipes |
| 4. Experimental boot | Rootfs, initramfs and UKI booting in QEMU/OVMF |
| 5. Provisioning | Helper, journal and storage stacks working on virtual disks |
| 6. Generations | Update, confirmation, fallback, rollback and retention proven |
| 7. Adoption | Arch, Debian and Ubuntu qualified |
| 8. Publication | Verifiable images, sources, licenses, SBOM, vulnerabilities and attestations |

Each stage will have its own PRs and criteria. A first experimental boot will
be evidence of progress, without anticipating the qualification of the
following stages.

The complete goal remains open. The current status is:

| Stage | Current evidence | Remaining required work |
|---|---|---|
| Foundations | Services migration; chunked Store; system v3 results and v2 bundles; producer of large outputs from directories and own worker/coordinator transfer protocol verified with two processes; admission of the eight budgets through local configuration and the CLI plan; inventory and comparison of sysctls/disk binding through the CLI; budget/graph validators; System and HostConfiguration in the std and planning | System profile with enforcement and integration of the protocol into the executor; catalog receipts/authorizations; integration of the plans with application and system builds |
| Bootstrap | Current managed toolchain available for ordinary recipes | Authenticated seed and qualified complete chain of compilers, sysroot and Rust |
| Own base | No qualified own userspace/kernel | Recipes and builds of all minimal components |
| Experimental boot | Composition, initramfs, dm-verity, GPT RAW and qcow2 by streaming into the Store; no bootable own system | System/CLI pipeline, rootfs, functional initramfs, signed UKI, ISO and boot through OVMF/disk |
| Provisioning | Layout validation; private scratch helper and same-boot journal/recovery verified in a VM | Privileged provisioning operations; stack tools, credentials and destructive tests on virtual disks |
| Generations | Current services generations preserved | A/B root, health, confirmation, fallback, rollback and retention of complete systems |
| Adoption | Read-only inventory and comparison of declared sysctls through the plan CLI | Ownership, application/restore contracts, modules, mounts, services and Arch, Debian and Ubuntu fixtures |
| Publication | Existing CAS identities preserved | Qualified images, sources/licenses/SBOM, signatures, vulnerabilities and attestations |

The observed environment still has no `/dev/kvm` and no QEMU on `PATH`.
Reading sysfs/proc and the validation fixtures do not replace qualification
through firmware, disk and boot. The stages that do not depend on these
capabilities remain authorized.

## 21. Publication and maintenance

The images should include evidence of:

- Review of the core and catalog.
- Sources, patches and configurations.
- Toolchain and seed.
- Dependencies and licenses.
- SBOM.
- Vulnerability scanning.
- Tests and environments.
- Checksums.
- Provenance.
- Signature verification.

The current policies of explicit locks, artifact identity and qualified
publication will be extended to the system components.

Changes to the kernel, configuration, toolchain, storage or boot will produce
new identities and will require the corresponding qualification.

## 22. Limits of the first cycle

The first cycle covers x86_64, UEFI, systemd, console, network, SSH, immutable
generations, Secure Boot, ext4, LUKS2, LVM, RAID1 and RAID10.

Left for later expansions:

- Graphical desktop and GPU/audio integration.
- ARM64 and other architectures.
- Legacy BIOS.
- TPM2.
- Btrfs and ZFS.
- RAID0, RAID5 and RAID6.
- Shrinking and moving volumes.
- Machine firmware updates.
- Automatic migration of a distribution's root.
- Physical hardware qualification.

The local environment observed on October 21, 2026 has no `/dev/kvm`. The
implementation will need a builder and test environment with adequate resources
before claiming qualification of the complete system.
