# Private scratch helper

`syrox-system-helper` is a separate Rust executable in `syrox-system`. It links
neither the language nor the engine/builder. Its initial operation allocates a
NEW private regular scratch image, formats/checks it with administrator-pinned
static tools, configures a loop device, creates a detached ext4 mount and offers
only its directory descriptor to an authorized client. This is development
infrastructure for a future System worker. It does not provision physical disks,
apply HostConfiguration, change boot or implement a complete System executor.

Local tests cover peer/type authentication, sealed messages, unknown fields,
protected paths, journal interruption and replay refusal. A separate disposable
guest qualification passed with an actual UID/GID 1000 client and root helper:
allocation, descriptor handoff, client write, release and final check; wrong peer,
unknown field and excessive budget before effects; preserved-image replay and
refusal to reformat after disconnect. [Exact evidence](test-tools.md#private-scratch-helper-guest)
includes a second run with evidence-hash reconciliation, stale-plan refusal,
retained-descriptor blocking and a new allocation after reconciliation. It does
not qualify persistent crash recovery or a complete build executor.

## Two-volume workspace protocol

The helper also implements separate `prepare_workspace`, `release_workspace`,
`inspect_workspace` and `recover_workspace` version-1 operations. They do not
reinterpret single-scratch requests. A prepare request carries the exact budget,
operation ID and caller layout digest. The helper independently admits that
budget against its root-owned policy and derives both geometries before journal
creation or allocation. Unsupported geometry and excessive budgets fail before
those effects. It preallocates two NEW private images, formats/checks each,
creates distinct detached mounts, assigns the authorized non-root identity and
offers a sealed receipt followed by scratch and output root descriptions in
that order.

The caller's layout digest binds its independently admitted builder policy.
Root policy may have different maxima: it still independently bounds the same
request. The receipt's observation echoes the caller binding while
`helper_layout_sha256` records the root-admitted layout. Echoing the caller's
digest grants no authority to exceed root policy or select image paths. Both
geometries derive from the same requested bytes/files. The root authorization
hash uses a distinct `syrox-private-workspace-authorization` domain and binds
the complete request, root layout, policy, peer and state filesystem identity.
The client validates the exact requested budget/layout, role identities and
actual filesystem ceilings before accepting either role.

One journal and one control lease cover both images. Records retain version 1,
with explicit scratch/output roles on allocation and loop events. The image and
tool directory allowlist expands only for an original `prepare_workspace`
authorization; legacy journals keep their existing allowlist. A release must
match the operation ID and authorization. The helper waits for both loops to
finish teardown and checks both filesystems before recording a two-image
terminal receipt. Images and evidence remain retained. Loss of the connection,
partial allocation/format/mount/ownership changes or lost replies are uncertain;
the helper never repeats formatting to repair them.

Workspace recovery has its own plan-hash domain,
`syrox-private-workspace-recovery-plan`, and explicit inspection/reconciliation
operations. It verifies both allocation identities and requested lengths, the
original policy and same-boot/PID-namespace session identity, recorded tool exits
and independent loop teardown. Missing evidence or a live retained mount blocks
reconciliation. An exact reviewed hash is checked again before appending only a
journal record. Images remain retained and filesystem health remains unverified.
The old scratch inspection refuses workspace journals. CLI callers select
`--workspace-operation` explicitly; `--scratch-operation` retains its single-image
meaning. Rust clients use `HelperClient::inspect_workspace` and
`recover_workspace` explicitly.

`WorkspaceGrant` exposes the authenticated observation and splits into two
root files plus a `WorkspaceLease`. Keep control in the coordinator's original
identity namespace. All transferred descriptions, open files and worker
namespaces must end before release. Drop closes control and preserves
uncertainty; neither client nor helper reconnects or retries the operation.
The engine's `SystemBuildInputs::prepare_workspace` additionally borrows the
prepared component's source/input custody, rechecks it and supplied capacity
before contact, and revalidates both roots before exporting copies. This still
starts no worker and creates no build attempt, execution gate or receipt.

The disposable `v14` QEMU/OVMF guest passed 59 distinct cases, including all
43 previous helper/primitive cases and 16 workspace protocol/component cases.
The real non-root engine test locked its declaration, prepared the component,
wrote/fsynced both roots, ran Store GC while retaining inputs/workspace,
revalidated its inputs and explicitly released the pair. Independent root and
caller policy maxima were used. Wrong budgets, stale hashes and retained-root
recovery blocking were exercised; reconciling preserved both image hashes.
[Exact inputs, failed attempts and qualification scope](test-tools.md#two-volume-helper-and-prepared-component)
are recorded separately. This does not qualify complete recipe execution or
cross-reset recovery.

To inspect a retained two-volume operation:

```sh
srx --std none system recover \
  --workspace-operation 0123456789abcdef0123456789abcdef \
  --helper-socket /run/syrox-system-helper.sock --json
```

After reviewing the returned plan, repeat with its exact `--apply-plan SHA256`.
Select exactly one operation kind. Omitting the target kind, selecting both,
or supplying a noncanonical ID/hash fails during argument parsing before helper
contact. Workspace selection never falls back to single-scratch recovery.

## Activation and administrator policy

The executable requires real and effective UID zero and accepts only
`--policy ABSOLUTE_PATH`. It takes an already connected Unix SOCK_SEQPACKET
description on fd 3. It performs no elevation, socket discovery or listener
installation. A root launcher must select the connection and policy explicitly.
Existing non-root Services/build identities acquire no authority by installing
this binary.

The bounded JSON policy has version 1, `client_uid`, `client_gid`, `maximum`
(`BuildBudget`), `maximum_operations` (1..64), `state_directory`, `formatter`
and `checker`. Each tool declares an absolute `path`, lowercase SHA-256 and
exact `size_bytes`. Every object rejects unknown fields. Tool sources must pass
the [sealed static executable contract](system-builders.md#shared-descriptor-primitives).
No tool/argument/path choice comes from the client.

The policy, sources and ancestors must be protected by root ownership, with
no symlink traversal or group/other write access. Root-owned sticky temporary
ancestors are admitted; the selected state directory itself must already exist
with root ownership and mode 0700. The helper never creates or adopts that
administrator namespace implicitly. It takes an exclusive nonblocking directory
lock for the session and checks available bytes/inodes before allocation.

The helper observes SO_PEERCRED and requires an exact configured UID/GID and
positive PID on a connected Unix seqpacket. Receipt of an fd authenticates
neither its owner nor its contents by itself. Requests use the existing fixed
single-fd frame, containing a mode-0400, read-only, unlinked, content/length-sealed
tmpfs inode owned by that observed peer. JSON is at most 64 KiB and read with
pread independently of the sender's shared seek offset. Replies are similarly
sealed and root-owned; the receiver must validate expected UID zero separately.

### Administrator socket activation

The shared `helper_activation::HelperActivation` renderer produces
`syrox-system-helper.socket` and `syrox-system-helper@.service` from explicit
administrator selections. Rendering inspects and creates no file. It is not an
installation command and does not grant the caller root authority. The installer
must independently verify the executable pin/ownership, protected policy and
existing private state, then install the reviewed system units. The declared
`state_directory` must match the policy's selected state.

`ListenSequentialPacket` with `Accept=yes` supplies one accepted connection on
fd 3 per root service instance. The socket inode remains root-owned, mode 0660,
with an explicitly selected group. Socket access does not replace the helper's
exact peer checks. Socket paths are canonical literal Unix pathnames, at most
107 bytes; abstract/network addresses and specifier expansion are rejected.
Command words are quoted separately, percent specifiers are escaped and
`ExecStart=:` disables environment substitution. No project supplies a command.

Every rendering requires finite memory/CPU/task/descriptor/runtime limits and
1..64 concurrent connections. These constrain privileged helper overhead;
they do not enforce a future build worker's budget. The unit never restarts a
failed operation. It uses private mount/network namespaces, a read-only system
with an explicit writable state path, protected kernel/control-group interfaces,
bounded capabilities and device access for loop devices plus standard pseudo
devices. The administrator must load/observe loop support before activation;
the units do not silently load modules. State is not created automatically.

Two local tests cover pure rendering, literal command paths, path/line injection,
invalid addresses and non-finite envelopes. Real systemd activation passed in
the fixed disposable guest, including loaded cgroup/descriptor limits, denied
device/write operations and root/client scratch handoff through the shared
namespace API. [Exact evidence](test-tools.md#systemd-socket-activation)
separates helper overhead from build-worker enforcement. These units have not
been installed on the development host; an installation command remains pending.

## Unprivileged coordinator client

`helper_client::HelperClient` connects only to an explicitly selected protected
root-owned mode-0660 Unix seqpacket socket. It checks ancestors, the socket inode
before/after connection, kernel root peer credentials and root-owned sealed
replies. Requests use the shared strict version-1 protocol and sealed snapshots;
there is no shell or client-selected privileged command. Every exchange checks
cancellation and an explicit deadline.

Control remains in the non-root coordinator's full UID/GID identity namespace.
The client pins that namespace and rejects later exchanges from another one.
Only the received scratch root goes to the isolated worker; a worker's mapped
UID zero must never be interpreted as the privileged helper's identity.
`prepare` checks the returned budget, authorization and actual ext4 geometry
using `ReceivedScratch`. `ScratchGrant::into_parts` separates the root descriptor
from the coordinator's `ScratchLease`. The coordinator explicitly releases the
lease only after the worker namespace and every copied root/file descriptor have
ended. It verifies the helper's final receipt. Dropping a lease only disconnects;
it never invents successful release or automatically retries/reconciles an
uncertain operation. Managed System-worker integration remains pending.

## Single-scratch allocation per session

A single-scratch allocation starts with `prepare_scratch`, `version: 1`, a 32-digit lowercase
hex `id` and an explicit budget. Every resource is admitted against the root
policy. The resulting capability currently enforces scratch allocation/inodes;
it does not execute a build or enforce its CPU/memory/process/output budget.
Tool preparation uses the separate fixed [tool limits](system-builders.md#fixed-scratch-tool-runner).
An administrator launcher still needs its own service resource envelope.

The helper creates `op-ID` exactly once. Existing operation/image names are
refused. A request cannot supply a backing path, block device, mount target,
shell, arbitrary argv or ioctl. An authorization SHA-256 binds the policy bytes,
peer UID/GID, typed request and state filesystem identity. It authorizes this
delegated NEW private allocation; it is not an authorization for host storage
provisioning or a reusable full-system plan.

Intent/result records are new mode-0600 JSON files, fsynced with their parent.
Allocation intent precedes preallocation; image identity is recorded afterward.
Tool pins/intents/results and bounded output digests are recorded. Loop selection,
configuration, mounting and ownership assignment each have prior intent.
The helper does not mix a lost process result with proof that an effect did
not occur. Tool subprocesses request termination if the helper dies.

The `offered` record carries the operation authorization and observed filesystem
capacity. The helper sends that sealed record, then the mount-root fd. The root
is assigned to the configured client UID/GID with mode 0700. No image or loop
description is transferred. The client must close all copied mount/file
descriptors before sending `release_scratch` with the same version/id/authorization.

The helper drops its mount, journals release intent, requests loop release and
closes its descriptions. ENXIO is not treated as completed teardown. Independent
sysfs evidence must show no backing file and zero capacity; a final forced
read-only filesystem check must succeed before `released` is recorded/replied.

## Uncertain operations and retention

Failures after admission retain the image, intent, outputs and an uncertain
record where writable state permits. There is no automatic reformat, deletion,
repair or blind detach. Client disconnect or a retained mount descriptor can
leave uncertainty. A subsequent session refuses new allocations while an
unreconciled operation remains. A partial terminal JSON record is not completion.
Failure to deliver a reply after observed release is recorded separately.

Released and reconciled images/journals are also retained and count toward the administrator's
operation ceiling; filesystem capacity must cover scratch/output plus a 64 MiB
margin. Automated GC is pending. Manual removal is not a documented recovery procedure. Other
privileged loop managers must be excluded from the helper's owned bindings;
these primitives do not establish exclusive control of all host devices.

## Explicit scratch reconciliation

Two additional first-message operations use the same peer/policy/sealed-message
checks and exclusive state lock. Neither snapshots or executes tools:

- `inspect_scratch` with `version: 1` and `id` returns a sealed document containing
  `plan` and `plan_sha256`. Inspection writes no journal record or image.
- `recover_scratch` adds that exact `plan_sha256`. The helper observes the state
  again under the lock, compares the hash and revalidates immediately before
  appending a new fsynced `reconciled` record.

The version-1 plan binds policy bytes, operation/state directory identities,
the names and exact bytes of consecutive journal records, image identity and
size, boot/PID-namespace identity, the original helper PID/start time and the
recorded loop's current sysfs state. Unknown, excessive, partial or nonconsecutive
records are rejected. Existing version-1 records are preserved; new allocations
add runtime evidence inside `authorized.details.runtime`. Old journals lacking
that evidence require a later recovery mechanism and cannot be reconciled by
this operation. Released legacy journals remain readable without it.

Reconciliation requires that the original helper session has ended in the same
boot and PID namespace, exactly one allocation identity matches the retained
root-owned private image and all tool intents have recorded exits. A missing
tool result remains uncertain even if the original helper has exited. If loop
configuration was attempted, partition scanning must still be disabled and
independent sysfs evidence must show no backing file and zero capacity. A client
retaining a mount/file descriptor prevents that proof. Missing kernel evidence
does not establish completion. A blocked plan cannot authorize reconciliation.

The only effect is recording that this retained allocation is quiescent. No
format, repair, image deletion, detach, mount or filesystem health check occurs.
The reply explicitly says `image_retained: true` and
`filesystem_health_verified: false`; `reconciled` is distinct from a successful
`released` final check. A new operation may then use a different id, subject to
retention/capacity limits; the old id remains protected by exclusive creation.
A changed journal, policy, image identity or loop observation invalidates the
plan. Cross-reset reconciliation and inspection of historical records without
runtime evidence remain pending.

The public CLI exposes this narrow scratch operation with both target arguments
required. Without `--apply-plan`, it only prints the authenticated inspection:

```sh
srx system recover --scratch-operation 0123456789abcdef0123456789abcdef \
  --helper-socket /run/syrox-system-helper.sock --json
```

Review the complete returned plan before supplying its `plan_sha256` in a second
invocation with `--apply-plan SHA256`. The helper reobserves the evidence and
rejects a blocked or changed plan. The CLI neither selects a default helper nor
loads a project, configuration or Store. Identifiers and hashes require canonical
lowercase hexadecimal values; exchanges have a 30-second deadline and respond to
cancellation. This command reconciles retained builder scratch only; generation
recovery and host storage provisioning require their own implementations.

The [guest qualification](test-tools.md) uses only disposable VM files and
prebuilt signed fixture inputs. Persistent recovery across guest reset, helper
interruption at each effect, full builder cgroup enforcement and the System
worker/receipt integration remain separate qualification work. The typed client
and real CLI passed a fresh 29-case disposable-VM run, including authenticated
namespace handoff/release, disconnect, effect-free inspection/wrong-hash refusal
and exact-hash reconciliation with unchanged image bytes. Its
[separate evidence](test-tools.md#typed-helper-client-and-real-recovery-cli)
retains the earlier manual protocol probes and their identities.
