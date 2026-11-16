# System builder budgets and filesystem observations

System build execution remains under implementation. The existing Standard and
Large recipe profiles retain their resource envelopes and tmpfs scratch. The
contracts below provide admission, read-only observations and narrow privileged
scratch primitives; they do not enable a new execution profile or grant
authority over a directory or filesystem.

## Explicit admission

`syrox_system::budget::BuildBudget` requires positive limits for memory, CPU,
processes, descriptors, scratch bytes, file/inode count, output bytes and duration.
`BuilderLimits` represents separately selected administrator ceilings. Its
`admit` method checks every requested dimension and returns an `AdmittedBudget`
with the policy fingerprint. Deserialization of a request produces no admission
token. `check_capacity` separately checks observed available resources and the
combined scratch/output requirement for shared storage. Executors must still
establish current capacity and enforce every admitted resource.

## Select a local System builder policy

The user configuration accepts a separate `[build.system]` section. It does not
select `[build.managed]`, authorize HostBootstrap, or expand any ordinary recipe
limit. Worker/scope/endpoint paths and all eight maximum dimensions are explicit:

```toml
[store]
path = "/srv/srx/store"

[build.system]
worker = "/srv/srx/workers/system-worker"
worker-sha256 = "<exact lowercase SHA-256>"
scope = "user"
user-bus = "/run/user/1000/bus"
socket-parent = "/run/user/1000/srx-builds"
helper-socket = "/run/syrox/system-helper.sock"

[build.system.maximum]
memory-bytes = 8589934592
cpu-percent = 400
processes = 1024
descriptors = 8192
scratch-bytes = 68719476736
files = 1000000
output-bytes = 17179869184
duration-seconds = 14400
```

Replace the worker hash with the explicitly selected executable's complete pin.
Parsing checks finite positive integer limits, their integer widths, unknown
fields, scope-specific bus selection and canonical paths. It opens none of the
worker, bus, socket parent, helper or Store paths. No endpoints, ceilings or host
toolchain are inferred from a recipe or an ordinary managed configuration.

```sh
srx system plan .#system --builder-config /absolute/builder.toml --json
```

This optional flag reads only the explicit user configuration, admits the locked
System declaration's requested budget, and reports the local maximum, exact
request, policy fingerprint and operational selections. Any exceeded dimension
fails before Linux observation, recipe source acquisition or Store/helper activity.
`HostConfiguration` rejects the flag before reading the file; it has no complete
System build budget. Without the flag, planning reads no builder configuration
and preserves the existing version-1 observation report/domain. A report with
builder admission uses version 2 and `srx-system-observation-plan-v2\n` before
the same canonical JSON hash.

The result is policy admission only. Worker image, systemd manager, helper
authority, capacity and runtime enforcement remain explicitly unverified;
`can_apply` remains false. The root helper independently checks its own policy
and authenticated caller. Rendering/accepting these operational settings does
not enable a System executor, install units or permit writes, reboot or recovery.

## Prepare a System component and its action

`build::system::prepare_system_build_inputs` authenticates a component against a
selected, locked `PlanSystem` and the explicit local System policy. The component
must belong to the kernel, userspace, layout or service package closure, including
service-local packages and transitive recipe inputs/dependencies. Another package
in the same project does not acquire this execution context automatically.

Preparation verifies the exact declared Managed program, source directory,
ordinary timeout metadata and selected inputs, plus the configured complete worker
pin and static x86_64 ELF format. This checks the image format, not implementation
of the System worker protocol. HostBootstrap and ambient host tools are refused.
The effective duration is the admitted System duration, recorded separately from
the recipe's ordinary timeout. The source limit is the minimum of its declared
maximum, the current 1-GiB Store blob limit and the admitted scratch allocation.
Sources remain streamed and pinned; ordinary Standard/Large source limits remain
unchanged. Missing or collected source objects report `BuildError::MissingSource`.

Selected v2 and chunked v3 inputs are opened through their authenticated result
contracts and materialized with their own limits. The ordinary managed opener
still refuses v3 inputs. Source and input closure/view interests are granular:
GC can run, and retiring an input's durable root does not invalidate a held
preparation. Dropping the preparation releases its custody. Revalidation checks
the held source, worker and every input view before duplicating the readonly
source descriptor. Preparation creates no operation, scratch, process or receipt.

`SystemBuildAction` has its own canonical encoding: the prefix
`syrox-system-build-action-v1\n` followed by compact struct-ordered JSON. Its
`syrox-system-managed-x86_64-v1` profile binds the source and effective source
limit, worker, directory, ordered input identities/origins, exact hexadecimal
`SRXBUILD\x02` program, all eight budget values, administrator-policy fingerprint,
`syrox-system-worker-outputs-v1` output protocol and `subreaper-echild` settlement
contract. An independently admitted budget is required to parse it. Unknown or
duplicate fields, alternate encodings, altered policy/budget and trailing bytes
are refused. The independent 701-byte test vector has SHA-256
`43904a35825c0461f17d81a6977e396881ffa11959b2d0258d7315ced63e6cb2`.
It is a metadata fixture, not an executable-worker qualification.

Legacy v5 action parsing refuses this new format. Existing Managed actions,
receipts, source caps and journals are not reinterpreted. A parsed System action
does not establish Plan membership, authenticate a peer or authorize execution.

`SystemBuildInputs::chunked_input_descriptors` exports one already-authorized v3
input through the [chunked descriptor contract](artifacts.md#large-streams-in-the-engine-store).
It preflights its deduplicated role count and an explicit remaining slot ceiling
within the action's descriptor budget, revalidates custody and opens the exact
selected manifest with that input's own authenticated artifact limits. A receiver
can index/read the package frame without a Store path. Legacy inputs and invalid
indices are refused by this v3-specific method. Aggregate accounting across
all inputs/control roles, authenticated transport, receiver retention and the
new System worker resource packet still need to be connected; this does not
make legacy Managed resource packets accept v3 inputs.

## Complete input resources and receiver retention

`SystemBuildInputs::prepare_input_resources(reserved_descriptors, cancellation)`
now prepares every selected input in one `SystemBuildInputResources`. It first
counts the exact aggregate roles, including duplicate selections, and rejects
`roles + reserved_descriptors > action.budget.descriptors`. The reserve must be
at least 32 and must also include all non-input worker roles selected by the
caller. This check precedes opening roles or creating another Store interest.

Each input contributes its readonly materialized directory followed by either
one legacy artifact descriptor or a chunked manifest and its sorted unique chunk
descriptors. The last role is an independent process-retention description for
the source, full input closures and materialized views. Sender interests are
combined only within the same Store; no global maintenance barrier survives the
operation. No build attempt, scratch or receipt is created by this API.

The new canonical record is `syrox-system-input-resources-v1\n` followed by
struct-ordered JSON fields `version`, `action`, `reserved`, `slots`, `inputs`,
`retention`, `retention_device`, `retention_inode`. Each input records `storage`,
`artifact_slots`, `maximum_bytes`, `maximum_files`. The record is bounded at
32 KiB. Artifact identities/order come from the independently selected System
action. Blob roles keep legacy limits; chunked roles use the producer's
authenticated v3 limits, bounded by the current format caps. This descriptor
record is specific to one handoff/interest inode; it does not replace the action
or change artifact identities. The independent 281-byte metadata fixture has
SHA-256 `e2c3488f82e03dd9fd6c8c8253ec566dc6202bb9e38b4d0b65e511282062a132`.

`expected_descriptor_count` authenticates a record against an independently
known digest, action and reserve before a transport collects FD batches.
`from_received` checks those same values, exact counts and roles, then acquires
a shared lock on the exact readonly retention device/inode. A byte-identical
replacement file is refused. It verifies the canonical interest hash and coverage
of source, selected origins/actions/receipts, artifacts/chunks and views, plus
the full artifact frames and directory contents. Positional reads ignore shared
seek offsets. The System directory verifier selects that producer's entry cap;
the ordinary verifier keeps its 65,536-entry limit.

The receiver's locked OFD keeps custody after sender/preparation destruction and
original-root retirement. A separately transferred retention descriptor can
continue protecting it after the receiver object ends. These are content and
retention checks, not proof of an executable's identity, manager admission,
FDSTORE acceptance, namespace lifetime, a journal transition or execution gate.

Directly supplied owned descriptors are normalized one at a time to CLOEXEC,
including the retention role, so a later exec cannot inherit them accidentally.
The aggregate exporter brackets its capture with whole-preparation validation;
each chunked capture reopens/verifies only that artifact instead of rescanning
all other selected inputs for every input. Existing standalone export validation
remains unchanged.

## One-shot input transfer

`SystemBuildInputTransfer` consumes one connected local Unix seqpacket for one
transfer. The caller selects a fresh nonzero 32-byte nonce and independent kernel-peer
PID/UID/GID; both sides require matching non-root execution credentials. The
existing packet channel verifies `SCM_CREDENTIALS` on every message and closes
descriptors from malformed/truncated ancillary data. It checks the expected
message PID, including when the socketpair was created before a child exec.
No ordinary worker packet size, ancillary limit or protocol is expanded.

The receiver starts with `syrox-system-input-ready-v1\n`, then the nonce,
action SHA-256, expected resource-record SHA-256 (32 bytes each), and reserved
descriptor count as u32 little-endian. SHA-256 of that complete message binds
the remaining phases. The sender checks this exact message before transferring:

- `syrox-system-input-manifest-v1\n`: binding SHA-256, total metadata bytes and
  contiguous offset (u32 little-endian), followed by up to 1,024 metadata bytes.
  Every fragment has the exact expected length; the total is bounded at 32 KiB.
- `syrox-system-input-batch-v1\n`: binding SHA-256, total descriptors, contiguous
  offset and batch count (u32 little-endian), plus exactly that many FDs, at most
  64 per packet. The entire record passes admission before any FD batch is read.
- `syrox-system-input-accepted-v1\n`: binding SHA-256, total descriptors and zero
  offset, with no FDs, sent only after receiver validation and retention locking.

Cancellation/deadlines bound packet waits; validation observes cancellation and
the deadline is rechecked before acknowledgement. Blocking filesystem calls
still need their surrounding execution/transport supervision. Wrong peer,
nonce, binding, offset, length, role count, digest or budget fails without an
acceptance. There is no retry/replay on the consumed channel. An acknowledgement
establishes input validation/retention at that time; executable/manager binding,
FDSTORE, private writable workspace, gate, process settlement and System receipt
publication still need to be integrated into the complete executor.

## System action limits for transient services

`SystemBuildAction::service_limits` derives a separate manager-resource adapter.
`SystemBuildServiceLimits::apply` checks every available capacity dimension before
changing any service field, then selects the action's memory, task, CPU,
descriptor and duration limits. The individual-file limit is the larger of the
scratch/output allocations: an intermediate file may exceed the final-output
budget. The existing systemd mapper sets soft and hard limits together and
disables swap and core dumps. Infinity sentinels are refused. No Standard/Large
envelope or ordinary timeout supplies a fallback.

Application changes only resource properties. Executable, arguments, credentials,
profile, environment, dependencies and restart policy remain explicit caller
selections. `verify_service` refuses changed resource properties before manager
access. `observe_unit` independently reads the complete transient-unit contract
twice under a stable manager/live invocation and one deadline; its historical
observation binds the System action, manager, contract and status. It grants no
worker, gate, retention or settlement authority. Executable-image authentication
and kernel cgroup readback remain separate checks.

This adapter does not start units or enforce aggregate disk/output/inode usage.
Connecting private disk scratch, worker resources, all runtime dimensions,
settlement and System receipts is still required for a working System executor.

The [native service-limit probe](test-tools.md#system-component-preparation-and-action-identity)
verified this adapter against an actual non-root transient unit, manager
properties, child rlimits and kernel cgroup files. It then explicitly stopped
the unit. This is readback evidence for that subset; the probe runs a diagnostic
harness and does not execute the action's recipe or qualify resource exhaustion.

## Inspect and extract larger System sources

On x86_64, `acquire::archive::SystemArchiveLimits` is a separate checked envelope
derived from a genuine admitted System budget and an explicit compressed-source
limit. Both workspace geometries must pass pure validation. Compressed transport
retains the Store blob ceiling (1 GiB); expanded bytes and individual file lengths
use the scratch image ceiling. Tar entries use the scratch inode share, capped
at 1,000,000. XZ dictionary memory is bounded by both 128 MiB and the requested
memory budget. This bounds decoding; it does not enforce total worker memory.

`inspect_system_archive` and `extract_system_archive` consume a readonly regular
source descriptor. Positioned reads cover its initially admitted transport extent
independently of shared cursor changes and reject length changes, including at
EOF. Inspection and extraction use the same parser. The extractor writes beneath
a separately pinned directory, refuses existing-file overwrite and symlink
parents, and can leave partial new files on failure. It publishes no artifact and
does not retry or clean up uncertain work. The caller authenticates the complete
source pin and owns destination/namespace authority; the limits token supplies
neither. Sources retain the existing ASCII/255-byte path and 64-component depth
contract. System gzip and XZ accept bounded contained direct aliases and existing
supported GNU metadata; hardlinks, alias chains, escapes and special files remain
unsupported. Ordinary gzip/XZ constructors and validation keep their old caps
and accepted subsets.

`SystemBuildAction::source_archive_limits` binds the declared format, compressed
source limit and action budget. `SystemBuildInputs::inspect_source_archive`
brackets inspection with complete held-source/input revalidation and creates no
attempt, workspace or helper contact. `Raw` has no implicit tar interpretation.
The ordinary build interpreter still uses its existing extraction entry point;
the complete System worker must explicitly select the new path inside its
authorized scratch namespace and execution lifecycle.

The native qualification inspected/extracted 1 GiB + 17 bytes in a child with a
256 MiB address-space limit, admitted 65,537 metadata entries while the legacy
large path refused them, and passed the parser's legacy regressions. This is not
a full worker/cgroup or helper-filesystem qualification.
[Exact native evidence](test-tools.md#system-source-archives) records the 28
top-level cases and explicit child check.

## Bind a prepared component to private helper scratch

`SystemBuildInputs::prepare_scratch` is a separate, explicit effect. It checks
cancellation/deadline, canonical operation ID, current supplied capacity and
held source/input custody before contacting the helper endpoint snapshotted
during preparation. It sends the exact action budget; the helper authenticates
the non-root caller and independently applies its root-owned policy. This does
not create a build attempt, launch a worker or select installation storage.

`SystemBuildScratch` borrows the prepared inputs and owns the root-authenticated
grant/control lease. `root_descriptor` revalidates inputs, readonly ext4 root,
ownership and geometry before duplicating only the root directory. Control
stays in the coordinator's original identity namespace. The worker must still
authenticate its action/handoff, attach in its own private namespace and close
all root/file copies before release. The typed grant exposes no control socket.

Explicit `release` closes the coordinator root and asks the helper to check loop
teardown and filesystem health. Rejected or lost replies stay uncertain, without
retry or reconciliation. Drop only closes descriptors; it sends no RELEASE and
does not repeat formatting. The helper retains its private image/journal for
explicit recovery. Filesystem capacity/inodes are properties of this scratch
grant; enforcing the combined worker scratch/output/file budget and publishing
settled System receipts remain separate work.

## Bind a prepared component to a two-volume workspace

`SystemBuildInputs::prepare_workspace` is an explicit x86_64 engine effect using
the new two-volume helper client. It first validates cancellation/deadline and
operation ID, derives the layout from the prepared action's admitted budget,
checks supplied current builder capacity, and revalidates the source/input
custody before contacting the helper endpoint captured during preparation.
The root helper independently admits the request and observes available state
storage before allocating both images. Its policy maxima may differ from the
coordinator's maxima; neither replaces the other's admission.

The returned `SystemBuildWorkspace` borrows the prepared inputs for its lifetime
and retains both roots plus the coordinator-only control lease. It exposes the
action digest, exact layout and authenticated observation. Exporting ordered
root copies revalidates held inputs, both filesystem identities/capacities and
the layout's binding to that action. Receivers still require an authenticated
action/worker handoff and their own dedicated namespace lifecycle. Input-resource
FD budgets must reserve all these non-input descriptions and validation copies.

Explicit release closes the coordinator's two roots before asking the helper to
observe both loop teardowns and run both final checks. Call only after ending all
workers/namespaces and closing every transferred root or open file. Drop and
failed requests preserve uncertainty without replay or automatic reconciliation.
This allocates private build storage; it starts no worker, installs no system,
and supplies no execution-gate, FDSTORE, all-budget enforcement or build receipt.
The existing single-scratch API remains separately available.

The actual component/workspace/GC/release path passed as UID/GID 1000 in the
guarded `v14` QEMU/OVMF guest. The test runs no recipe and creates no local
attempt/receipt. [The 59-case evidence](test-tools.md#two-volume-helper-and-prepared-component)
also records helper denials, disconnect and retained-root recovery behavior.

## Observe an existing builder directory

```sh
srx system inspect --builder-directory /existing/scratch --json
```

The command opens the existing directory read-only, refusing a final symlink,
regular file or missing path. It does not create the directory, read a project,
load user configuration, initialize a Store, open block devices, run utilities,
change quotas or mount anything. Text output reports the same observations.

JSON retains the ordinary kernel `inventory` and its `digest`. The additional
`builder_filesystem` has its own `path`, `digest` and `observation`. Its SHA-256
uses the domain `syrox-filesystem-observation-v1\n` followed by compact serialized
observation bytes. It binds the exact reported identity, capacity, usage and
quota availability. These values can change immediately after inspection; the
digest provides neither exclusive use nor a persistent execution authorization.

The shared `filesystem::observe(&File)` API accepts an already open directory,
so a future helper can use the same observations without the language or builder.
It reports device/inode identity, filesystem type, total/available bytes and
inodes. Fixed `FS_IOC_FSGETXATTR`, `quotactl_fd(Q_XGETQSTATV)` and
`quotactl_fd(Q_GETQUOTA, PRJQUOTA)` queries observe the directory's project,
inheritance, accounting/enforcement state and hard limits/usage. Zero hard limits
are explicitly unlimited (`null`), not zero capacity. Incomplete or overflowing
quota data is rejected. The kernel distinguishes quota accounting and limit
enforcement; the observer reports both rather than treating accounting as proof
of enforcement. See the [Linux quota implementation](https://github.com/torvalds/linux/blob/master/fs/quota/quota.c)
and [quotactl interface](https://man7.org/linux/man-pages/man2/quotactl.2.html).

Unavailable operations, inactive quotas and insufficient privileges remain
explicit `unavailable` observations with their error/reason. A successful capacity
query does not imply quota support. Project quota limits may require privileged
observation; this command performs no privilege escalation or fallback to a
claim that limits are enforced. Query structures and requests have fixed Linux
UAPI layouts; no arbitrary ioctl or quota command is accepted from a project.

## Shared descriptor primitives

`syrox-system::descriptor` now owns the engine's path-only handles, read-only
descriptor checks, file locks, constrained `openat2` reads and single-descriptor
Unix seqpacket transport. The engine delegates these operations to the shared
library; its existing wire marker and peer authorization checks are preserved.
Malformed or truncated ancillary messages close all installed descriptors.
`SO_PEERCRED` observations report kernel credentials without granting authority.
There is no weaker path-resolution fallback when kernel constraints are absent.

The shared `descriptor::sealed` module also owns bounded anonymous credential
snapshots. Engine services/runtime now delegate to it: source selection and
revalidation stay with the existing callers, mode 0400 and the 64 KiB ceiling
remain, and the result is a read-only, close-on-exec memfd with content/length
seals. Checks run between short I/O operations and interrupted retries. Content
seals do not freeze inode ownership or mode; receivers still validate both.

`descriptor::pinned_tool::PinnedTool` snapshots a separately authorized tool
into an executable memfd, using streaming SHA-256 and exact size/EOF checks.
It accepts only static ELF64 little-endian x86_64 ET_EXEC executables, without
PT_INTERP, PT_DYNAMIC, writable executable segments or an executable stack.
Static PIE is outside this narrow contract. The result is read-only, mode 0555
and sealed against content, length and executable-mode changes. Explicit
MFD_EXEC/F_SEAL_EXEC support is required; there is no mutable-file fallback.
The source path and seek position are not execution authority. Receivers still
revalidate ownership, mode and seals. The helper must select the tool pin,
operation, arguments and isolation independently.

A future helper can reuse these primitives without loading the evaluator or
builder. This extraction does not implement helper authentication or system execution.

## Managed source staging

Managed input preparation keeps an already verified read-only CAS descriptor and
granular source retention. It rehashes source bytes with a 64-KiB buffer and pins
device/inode, length, links, ownership, mode and modification/change timestamps.
The descriptor uses positioned reads, so shared seek changes do not select a
different source range. Holding it does not retain the global Store GC barrier;
the existing object interest protects the source namespace independently.

Standalone staging checks the source metadata before creating an operation.
Staging then revalidates metadata, copies into its own atomic temporary file,
checks the original byte limit, complete SHA-256, exact size, EOF and metadata
again, and publishes `source` without replacing an existing name. Only the
complete verified copy receives mode 0400 and a file sync. The existing temporary
prefix, operation journal and recovery rules remain in use; neither cancellation
nor a failed/uncertain publication authorizes payload execution. Source changes
invalidate the preparation, and a repeated staging attempt preserves the existing
source file. No source-sized buffer remains in coordinator preparation or worker
inspection; the latter verifies the source digest without collecting its bytes.

The managed tests passed 100 cases with three environment-dependent cases still
ignored. The sandbox run's seven Unix-transport EPERM failures were rerun outside
that sandbox as the ordinary non-root user and passed. Coverage includes source
change before operation creation, change during copying, short/interrupted reads,
sink cancellation, shared seek, duplicate-name refusal, readonly publication,
granular retention/concurrent GC and the existing handoff/namespace protocols.
This checks preparation and protocol contracts; a complete System executor is
still pending. Common source limits, profile envelopes, wire records and action
identities keep their existing formats and budgets.

A new native Managed/Standard build also passed through the streamed coordinator
using the existing pinned static worker protocol. It assembled/linked a 445-byte
project source with the previously source-built binutils 2.47 output as its only
declared input, recorded `toolchain none`, copied the exact source into its output
and ran the resulting static executable. A separate runtime invocation exited
zero and printed `SRX managed source streaming`. The
[recorded inputs and result](../tests/fixtures/system-build/native-source-streaming.json)
bind the new action/artifact/receipt and distinguish this native regression from
a full-system or own-toolchain qualification. The tools retain their explicit
host-bootstrap seed provenance; no System budget or large-source profile is
claimed by this small build.

## System output production

The System output producer and its separate worker framing are now available
as [budgeted artifact APIs](artifacts.md#producing-system-output-frames).
They accept actual settled output trees without a whole-file buffer and check
aggregate bytes/inodes across a transfer. This completes that encoding/transfer
boundary, while selection of a System execution profile, disk scratch in the
managed namespace, all runtime resource enforcement and build receipts remain
under implementation. No common recipe envelope is expanded by these APIs.
The [native two-process probe](test-tools.md#system-output-producer-and-worker-framing)
passed a file larger than 1 GiB through a pipe with 256 MiB per-process address
space and 64-descriptor limits, independently checking its package pin and
round-tripping the v3 result through a system bundle. It does not execute a
System recipe or grant build receipt/installation authority.

## Loop primitives for private scratch images

On x86_64, `loop_device` implements a narrow descriptor-based loop interface.
The caller supplies root-owned loop-control/block descriptions and its own
new root-owned, mode-0600, singly linked regular image. A selected loop number
is advisory; only atomic `LOOP_CONFIGURE` can bind an available device. The
backing length must exactly match a positive supported 4 KiB multiple. Requests
fix offset zero, size limit, 4 KiB sectors and AUTOCLEAR. Legacy multi-ioctl setup,
arbitrary ioctl commands, physical backing devices and partition scans are not
supported. A bounded fixed sysfs read requires `max_part=0` before effects;
other values can force scans despite an omitted PARTSCAN request.

After configuration the primitive rechecks backing device/inode, root ownership,
mode/link count/length, actual loop number, flags, encryption fields and block
geometry. A failed attempt remains `Attempted`; repeating it is refused. Release
requires a verified binding and a fresh identity check; once requested it cannot
be blindly repeated. The caller must journal intent before either operation.
Kernel credentials and file properties alone do not establish helper ownership
of a resource or exclude another privileged device manager.

`GET_STATUS64` returning ENXIO also covers rundown, so `NotReportedBound` is
deliberately not a completed-teardown result. Other openers can defer release.
Closing descriptions and independently verifying final teardown remain the
helper's responsibility. Drop issues no detach ioctl. These details follow the
[Linux loop UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/loop.h)
and [driver lifecycle](https://github.com/torvalds/linux/blob/master/drivers/block/loop.c).

Local tests check UAPI layouts, exact initialized requests, changed bindings and
refusal of non-device descriptors without configuring devices. The
`scratch_loop_probe` example is a separate destructive qualification executable
restricted to a marked disposable QEMU guest. It journals its own test intent
and retains evidence on failure. It is not the helper or a system build.
Root/helper policy, interrupted-operation reconciliation and complete resource
enforcement are still required.

The probe passed in a fixed disposable Fedora CoreOS guest booted through
QEMU/OVMF using TCG, without host block devices, network or host shares. It
verified bounded writes, changed image metadata, deferred release and a separate
second attempt after teardown. [Fixture and evidence](test-tools.md#disposable-loop-device-guest)
record exact inputs and observed scope.

## Detached ext4 scratch primitive

On x86_64, `scratch::DetachedScratch` mounts a verified private scratch loop
using fsopen/fsconfig/fsmount, with CREATE_EXCL and nodev/nosuid attributes.
It exposes a directory descriptor without attaching the mount to the caller's
namespace. There is no legacy/global-mount fallback. The admitted backing
length, observed filesystem identity, 4 KiB geometry, writable attributes,
capacity and total inodes are checked before returning the handle. Assigning
ownership is an explicit effect; the caller must journal it and handle partial
failure. Duplicate root descriptors can retain the mount after the Rust owner
is dropped, so teardown requires independent observation.

The ext4 probe passed in the fixed disposable guest with source-built, pinned
mke2fs/e2fsck snapshots. It exhausted 512 total inodes and a 64 MiB backing
image, observed ENOSPC, verified deferred release while a root descriptor was
held and passed a final read-only forced filesystem check after teardown.
[Exact artifacts and scope](test-tools.md#disposable-ext4-scratch-guest) are
recorded separately. The writer ran as root inside the guest; this does not
qualify an unprivileged worker or helper isolation. This geometry bounds
allocated storage and inode count, not sparse-file logical lengths. Worker
file/output limits remain necessary.

## Separate scratch and output filesystems

On x86_64, `workspace::WorkspaceLayout::from_budget` derives two private ext4
geometries from one genuine `AdmittedBudget`, without opening resources. Scratch
uses `scratch_bytes`; output uses `output_bytes`, including when output is larger
than the administrator's scratch ceiling. It never constructs a child admission
that relabels output bytes as scratch. Each image must independently satisfy the
existing 64 MiB..128 GiB, 4 KiB-aligned geometry contract. Unsupported sizes or
inode shares fail before effects.

The global inode budget is divided in proportion to the byte ceilings: scratch
receives `floor(files * scratch_bytes / (scratch_bytes + output_bytes))`; output
receives the remainder. The multiplication uses u128. Each share then rounds
down to ext4's existing group/table granularity. The sum of observed filesystem
inodes must remain within the original budget; reserved filesystem inodes also
consume those ceilings. This does not give each filesystem the entire file budget.

The layout identity hashes `syrox-system-workspace-layout-v1\n`, the 32-byte
administrator-policy fingerprint, then twelve u64 little-endian values: the
eight requested budget dimensions in their existing order, scratch image bytes,
scratch effective inodes, output image bytes and output effective inodes. The
independent 161-byte unit fixture pins its SHA-256. `SystemBuildAction::workspace_layout`
exposes this same pure derivation; it allocates nothing and starts no worker.

`DetachedWorkspace` verifies exact image sizes and distinct backing-file and
loop identities before mounting either role. It creates two detached mounts
with the existing exclusive, writable nodev/nosuid ext4 contract. Ownership of
both roots is an explicit, non-atomic operation requiring a non-root builder.
The caller must journal intent and preserve partial failures. Observation binds
the layout digest, each root's device/inode and filesystem byte/inode capacity.

`ReceivedWorkspace` requires independently authenticated observations and ordered
root descriptors. It checks both roles against their exact identities, capacities,
ownership and mount flags; geometry alone does not authenticate role order.
Its unsafe `attach` operation validates both distinct, empty, owned targets before
the first move. The caller must be a dedicated single-threaded non-root worker
in private user/mount namespaces preserving its numeric identity. Any failure
requires discarding that entire namespace. The attached pair supports explicit
revalidation. Dropping Rust handles proves neither namespace termination nor loop
teardown; release requires observing both bindings independently.

These primitives remain separate from the helper's version-1 single-scratch
protocol. The [two-volume helper operation](system-helper.md#two-volume-workspace-protocol)
adds journaled allocation and recovery; authenticated worker handoff, executor
lifecycle and complete resource enforcement remain required. Filesystem limits
bound allocated space; sparse logical sizes still need file-size limits and
aggregate result admission. Ordinary build profiles and their limits are unchanged.

The guarded disposable VM qualification passed with 64 MiB scratch, 128 MiB
output and a global 1,024-inode budget (336 scratch + 672 output = 1,008 effective
inodes). A UID/GID-1000 child attached both roots in private namespaces, dropped
capabilities and exhausted each volume's bytes and inodes independently. Both
filesystems passed the pinned checker after independent loop teardown. The
33 existing helper cases and ten new cases passed together.
[Exact fixture and limits](test-tools.md#separate-workspace-volumes) record the
scope; this is primitive qualification, not the complete System executor.

## Required execution integration

### Fixed scratch tool runner

`ext4_tool` implements fixed Format/Check operations on a separately authorized,
root-owned regular image. The caller supplies the administrator-selected
`PinnedTool`, a private 0700 operation directory and prior journal intent.
There is no arbitrary argv, shell command, project path or privilege escalation.
Geometry is restricted to 64 MiB..128 GiB in 4 KiB blocks; inode requests round
down to group/table granularity. Re-observing the formatted filesystem remains
mandatory. The current empty tool configuration does not establish a journal or
filesystem feature policy.

Each attempt creates `tool-root` once. Its child unshares mount, network, IPC and
UTS namespaces, makes mount propagation private, and creates a bounded tmpfs
root. The root exposes only the image, empty configuration and a validated
`/dev/null` character device (1:3). A verified sealed
memfd is invoked directly through execveat and closes during exec; no executable
path or writable copy is provided. The root and image are noexec/nodev/nosuid;
the null-device leaf is a separate nosuid/noexec bind permitting only that device.
Check uses a read-only image bind. The directory and image are reopened without
symlinks and checked against pinned inode identity in the new mount namespace
before mounting: inherited descriptions retain their former namespace. The
child changes both root and working directory and marks all
non-stdio descriptions close-on-exec. It clears supplementary groups and all
capabilities, locks root privilege recovery out and sets no_new_privs before
installing a fixed x86_64 syscall allowlist. Fork, clone, sockets, peer signals,
ptrace, mounts, credentials, quotas and unknown syscalls are denied. This combines
confinement mechanisms: [chroot alone is insufficient](https://man7.org/linux/man-pages/man2/chroot.2.html),
[securebits constrain root capability recovery](https://man7.org/linux/man-pages/man7/capabilities.7.html),
and [seccomp checks architecture and syscall arguments](https://man7.org/linux/man-pages/man2/seccomp.2.html).

Fixed tool ceilings are 256 MiB address space, 8 MiB stack, 60 CPU seconds,
64 descriptors, RLIMIT_CORE=0 and file size at most the original image length.
The parent bounds captured stdout/stderr to 256 KiB together, checks cancellation
and a 120-second deadline between nonblocking reads, and kills/reaps its child
on error. Blocking kernel calls and spawn setup are not preempted by the polling
deadline. There is no isolation fallback or automatic image deletion/reformat.
Nonzero tool status is preserved as an observed result for reconciliation.

Unit tests cover geometry, allowlist branch targets and 64-bit argument halves,
bounded output, cancellation/timeout child reaping and refusal before effects.
An unprivileged subprocess also installs the actual filter and verifies a
denied, effect-free signal-zero query. Setup records its last stage for failure
diagnosis; that diagnostic is not a recovery journal or a completed-operation
record. The caller must still journal intent independently.
The ignored `filter_permits_pinned_static_rust_startup` oracle additionally
requires an explicit static qualification executable and SHA-256. It installs
the filter before exec, so Rust runtime initialization is covered as well as
filter installation. `poll`/`ppoll` are allowed for standard descriptor checks;
the policy still denies process creation and peer signalling.
Actual isolated Format/Check execution and the adversarial qualification payload
passed in the fixed disposable guest. The payload checked the exposed tree,
absence of inherited non-stdio FDs, read-only mounts, exact resource limits,
zero capabilities after exec and rejected signal-zero/clone3/setuid/namespace
requests. Both forced read-only filesystem checks, byte/inode exhaustion and
final teardown passed. [Artifacts and limitations](test-tools.md#isolated-ext4-tools)
remain separate from helper authentication, interrupted-operation recovery and
complete build-budget enforcement.

### System worker and helper

The initial [`syrox-system-helper`](system-helper.md) executable implements
administrator-selected activation, sealed request transport and a journaled
private scratch lifecycle. Its privileged client/server qualification passed
with a real UID/GID 1000 client in the fixed disposable guest. This does not enable a System build profile or authorize host
provisioning through ordinary services/builds.

The helper also implements explicit scratch inspection/reconciliation bound to
an evidence hash in the same boot/PID namespace. Reconciliation only appends a
retained/quiescent journal record; missing tool exits, a live original session
or an active loop block it. [The protocol and limits](system-helper.md#explicit-scratch-reconciliation)
distinguish that operation from verified filesystem health and reset recovery.

The production `helper_client` holds authenticated control in the non-root
coordinator's original identity namespace. It separates the admitted root fd
from the explicit release lease and verifies offered geometry and final receipts.
Only the root fd is transferred into a worker namespace. Connection loss never
causes an automatic release, reformat or reconciliation. The
[`srx system recover` interface](system-helper.md#explicit-scratch-reconciliation)
allows inspection and explicit hash-authorized scratch reconciliation without
loading a project or Store. This is separate from System-worker execution.

`scratch::ReceivedScratch` now validates a helper-authorized ext4 root against
the non-root worker identity, actual root inode, nodev/nosuid writable flags and
the admitted byte/inode ceilings. Its unsafe `attach` operation requires a
dedicated worker with private user/mount namespaces and a fresh empty private
target opened in that namespace. It moves the mount by source/target descriptors
with `MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH`; it never uses the
received root's readlink as a discoverable path or falls back to a global mount.
It checks cancellation before effects and revalidates geometry afterward. A
failure may follow attachment, so the worker must discard the namespace. Drop
closes descriptors only; the helper must still prove teardown. This does not
authenticate a producer: the sealed root-helper receipt and peer are checked
before constructing the handle. Native negative tests, a direct syscall
prototype and a second disposable-VM run using this shared API passed. The latter
verified descriptor-only source/target attachment, non-root writes with cleared
capabilities and the helper's final independent teardown/filesystem check.

`srx system inspect --builder-directory PATH` also reports `external_uuid`
separately from the existing capacity/quota observation and its fingerprint.
This fixed `FS_IOC_GETFSUUID` read uses the already opened directory, accepts
1..16 external UUID bytes and preserves unsupported-kernel/filesystem errors.
JSON carries the exact bytes; text prints lower-case hexadecimal bytes without
applying filesystem-specific display byte order. It performs no block-device
discovery or filesystem change. This supplementary observation does not change
existing fingerprint bytes or prove unique ownership: cloned filesystems may
share a UUID. Cross-boot recovery must bind this and its other evidence in a
separately versioned plan before it can use that identity.

A system executor still needs administrator-owned builder configuration,
integration of the verified scratch allocation/attachment lifecycle and its
journal/recovery with worker execution, plus complete build CPU/memory/process/
descriptor/duration enforcement. The helper's separate systemd activation units
were qualified in a disposable VM with observed kernel overhead limits and
device/write refusal. Those limits do not implement the worker envelope. Its
worker and receipt protocols must consume large
sources, chunked inputs and streamed outputs under the admitted limits. The
[system result/bundle APIs](artifacts.md#budgeted-system-outputs-and-bundles)
currently handle authenticated consumption streams independently of that executor.

Filesystem quota enforcement must be qualified with disposable virtual ext4/XFS
filesystems: accounting without enforcement, byte/inode exhaustion, project
inheritance, identity changes and concurrent/recovery behavior. Current tests
exercise read-only live queries and bounded metadata decoding; they do not
establish that privileged quota installation or a system build has run.
