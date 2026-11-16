# System and host declarations

The authenticated standard library now exposes `System` and `HostConfiguration`
alongside `Services` and `Shell`. System domain types live in `std::system`.
These are pure declarations: checking and planning do not read credentials,
start builds, adopt resources, write sysctls, open disks or change boot entries.

`System` requires platform, kernel, explicit userspace output references,
identity/users, directory/file/link exposures, boot, storage, services, health
and build budget. The initial platform is Linux x86_64 with UEFI, systemd-boot,
signed UKIs, dm-verity and A/B roots. Kernel image/configuration sources select
files from declared recipe outputs; modules and headers also select outputs.
Runtime sysctls, module parameters, boot arguments and compile-time Kconfig
requests have distinct fields.

`HostConfiguration` selects resources on an existing installation. Its sysctls,
modules, mounts and optional kernel default empty; `services` is explicit. For
example:

```srx
outputs {
    host: HostConfiguration = HostConfiguration {
        sysctls = [std::system::SysctlSetting {
                name = "vm.swappiness";
                value = "10";
            }];
        services = Services {
            pkgs = [];
            services = [];
        };
    };
}
```

Check, explicitly refresh the std pin, then inspect the selected declaration:

```sh
srx project check examples/host-configuration
srx project lock examples/host-configuration
srx project plan examples/host-configuration --output host
srx system plan ./examples/host-configuration#host --json
```

## Compare with current Linux observations

`srx system plan PROJECT#OUTPUT [--json]` requires an explicit locked `System`
or `HostConfiguration` output. It rejects Services/Shell, catalog shorthand,
missing selectors and stale locks. It does not refresh pins, acquire source or
artifacts, open a Store, contact the helper or apply changes. Normal project
authentication still applies to project inputs.

For a `System`, optional `--builder-config /absolute/builder.toml` additionally
admits the requested budget against an explicit local `[build.system.maximum]`
policy. It does not open the configured worker/Store/endpoints or infer a policy
from ordinary managed builds. Over-budget requests fail before machine
observation. Reports with this flag use version 2 and bind that policy/request;
default reports retain version 1. Runtime capacity, enforcement and helper
authority remain unverified. See the [builder contract](system-builders.md#select-a-local-system-builder-policy).

The command combines the complete canonical declaration with the read-only Linux
inventory and requested sysctl values. The target is explicitly
`current_process_namespaces`: entering another namespace changes the observed
view; these are not necessarily the host's initial namespaces.
The command pins user, mount, network, IPC, UTS, PID and cgroup namespaces,
records their device/inode identities and revalidates them before reporting.
Sysctls from an optional host kernel are included separately from boot/Kconfig
requests. Each value is `equal`, `different` or `unavailable`; unavailable includes the actual
error where present. A comparison proves neither resource ownership nor reliable
restoration. Parameter-specific application/verification contracts remain pending.

The shared `syrox_system::sysctl::observe` opens only a selected dotted name
under `/proc/sys` using constrained descriptor resolution and verifies procfs.
Names contain 2 or more bounded ASCII components separated by dots; slash syntax
and discovery are outside this initial contract. Accepted raw responses are at
most 4 KiB, including any final LF, with one extra byte read to detect overflow.
Values require UTF-8 without NUL and check cancellation between short reads.
Only one trailing LF is removed: tabs, spaces and numeric spelling remain exact,
since equivalence depends on the parameter. No utility or write is involved.
The upstream [sysctl documentation](https://docs.kernel.org/admin-guide/sysctl/index.html)
describes these runtime interfaces separately from compilation and boot options.

For `System`, the command also attempts the storage graph's existing identity,
capacity and observed-use binding against that inventory. It reports either
`bound_to_inventory` with complete bindings or `unresolved` with the reason.
Serial observation handles both the disk's `serial` attribute (including
virtio-blk) and `device/serial`. Both present values must agree; conflicts are
rejected, and the selected serial is read again before the device observation
completes. Existing device-level observations keep their encoding; disks whose
serial was previously unavailable can now have a different inventory fingerprint.
This improves evidence without rewriting an artifact identity or granting device
authority. The upstream [virtio-blk driver](https://raw.githubusercontent.com/torvalds/linux/v6.18/drivers/block/virtio_blk.c)
exposes its read-only serial attribute on the disk.
Provisioning is explicitly classified as destructive. Even a binding has
`metadata_verified: false` and `exclusive_use_verified: false`; it is insufficient
for disk writes. The kernel section compares release text and records the need
to boot a changed generation without claiming artifact/module compatibility or
an observed boot selection. Modules, mount identities, service authority, adoption,
builder admission and other pending checks remain explicit.

JSON wraps `plan` and `observation_sha256`. The hash covers the UTF-8 domain
`srx-system-observation-plan-v1\n` and compact JSON of the complete plan, with
object keys in lexical order. The report separately pins declaration text and
inventory bytes. Observations can change immediately and are not an atomic
snapshot. `can_apply` and `ownership_established` remain false. Successful exit
means the requested observation completed; an unresolved binding or unavailable
parameter is visible in the report. The hash is evidence, not authorization for
`system apply`, provisioning or the separate scratch recovery protocol.

Local CLI tests exercise equal/different/missing live sysctls, complete System
projection with a missing disk, boot requirements, consumer separation, stale
locks and rejection of effect-bearing flags. They verify unchanged project/lock
bytes, unchanged kernel values and absence of Store/configuration creation.
The actual CLI also passed the [32-case disposable-VM run](test-tools.md#read-only-system-plans-and-virtio-disk-identity),
including successful serial/capacity binding and read-only target refusal. The
earlier unsuccessful virtio binding attempt is preserved separately there.

The planner resolves nested typed recipe/output references and validates required
fields, positive resource budgets, storage graph structure, separate ext4 A/B
roots and FAT32 ESP roles. It checks identity/mode/path syntax, destination
collisions, declared directory parents, service declarations and health service
references. Kernel boot arguments cannot override storage-derived root, LUKS,
LVM, RAID or verity parameters. Module aliases differing only in `-`/`_` cannot
duplicate a selection; the same normalization applies to module parameter names.
Host mounts require the UUID shape of the selected filesystem. Persistent mounts
cannot cover generation binaries, configuration, boot or Store paths, including
their descendants. Credentials are bounded names, never filesystem key paths.

Storage nodes use `StorageNode { id = ...; device = StorageResource::...; }`.
The `device` field carries the typed resource variant. Graph validation needs no
machine. Binding still requires inventory and separately verifies selected disk
identities, capacity and observed use; a successful project plan proves none of
those observations. `srx system inspect` supplies a read-only local inventory.

Engine plans expose `systems()` and `host_configurations()` separately from
`consumers()`. Their embedded service descriptions do not turn the enclosing
output into a Services profile. Existing service preparation cannot select these
roots or acquire privileged authority through them. The complete checked value,
including Kconfig requests, identity, exposure, persistence, boot and health
fields, remains in the canonical plan roots. The typed `PlanSystem` projection
also retains identity/users, public authorized keys, private credential lookup
names, signing/boot attempts, essential-service/network health and persistent
volume compatibility selections. `PlanKernel::kconfig` preserves all five value
kinds, including signed integers, requested hex spelling and tristates.
`PlanSystem::layout` carries typed directory, exposure and link records with
their complete ownership and permissions. The plan summary exposes requested
kernel options, boot, health and persistence without resolving credentials.
Planning and final tree composition use the same path/link
validator, including containment and cycle checks before component builds.

Rust callers constructing these projection structs must supply the new fields;
`PlanKernelOption`, `PlanKconfigValue`, `PlanKernelTristate`, `PlanSystemIdentity`,
`PlanSystemUser`, `PlanSystemBoot`, `PlanSystemHealth`, `PlanPersistentVolume` and
`PlanDataCompatibility` are exported through `syrox_engine::plan`. The `.srx`
contracts and persisted service formats are unchanged by this projection update.

Current Kconfig validation covers request shape and duplicate symbols. Per-version
symbol contracts, generated completion and upstream dependency resolution remain
pending. Likewise, a declared release and selected outputs do not yet establish
kernel/module/header compatibility. Those checks must occur before a system
generation can be built or installed.

Budgets in project plans are requests, not administrator admission or enforced
execution profiles. Project host plans are ownership selections, not adoption
records. The separate `system plan` observations above add a sysctl comparison
and storage binding attempt, while the other runtime checks remain pending.
No `system apply`, boot installation, host adoption or full-system
qualification is implied. Implementation continues under the
[system roadmap](design/linux-system-management.md).

Adding the bundled `std/system.srx` changes the std snapshot identity. Refresh
each affected project's lock explicitly, including dependency/catalog projects
before their consumers. Existing persisted service profiles and journals retain
their current formats; published artifacts are not silently reidentified.
