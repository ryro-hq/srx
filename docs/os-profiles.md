# Installation profiles

Configure a named installation once, then select it with `--profile`:

```sh
srx project lock .
srx os init .#os --name web --user --config ./build.toml
srx os apply --profile web
srx os status --profile web
srx os logs nginx --profile web --follow
srx os stop --profile web
```

`init` writes configuration and initializes installation metadata. It does not
build packages, create a Store, publish units, or start services. Its JSON report
explicitly says `applied: false` and `manager_verified: false`. User scope is the
default. System scope requires `--system --units PATH` and the existing delegated
non-root execution identity; changing credentials with sudo is unsupported.

Profiles are schema-versioned JSON files at
`$XDG_CONFIG_HOME/syrox/os/NAME.json` (default `~/.config/syrox/os/NAME.json`). The
file must be owned mode 0600 and its containing directory owned mode 0700.
Existing profiles are never overwritten by `init`. Symlink traversal, unknown
fields, credential changes and overlapping installation/Store/units/work paths
are rejected. Existing unit directories may be mode 0755.

Installation and work directories default to
`$XDG_STATE_HOME/syrox/os/NAME/{installation,work}` (default
`~/.local/state/syrox/os/NAME/`). The Store comes from the normal user
configuration. Units default to `$XDG_CONFIG_HOME/systemd/user`. `init` accepts
`--installation`, `--cwd`, `--store`, `--units`, `--config` and
`--systemd-user-bus` overrides. Paths are recorded as absolute paths. Apply checks
the chosen manager's actual `UnitPath` before package realization and again
before unit publication. A temporary XDG configuration directory is not
automatically added to an already running manager's search path.

Every profile is bound to the installation's generated identity. Moving aside
the installation and creating a new installation at the same path does not
retarget the profile. Apply compares both the previously selected generation and
operation under the installation execution lock. A concurrent selection causes
an error, preserving retained candidates and evidence.

After editing `main.srx`, ordinary profile apply refreshes only that root file's
lock entry. Existing dependency, asset and standard-library pins must still
match. It executes the same checked snapshot used to update the lock.
`--locked` disables this refresh; `--offline` prevents acquisition while realizing
packages. Updating dependencies remains an explicit `srx project lock .` action.

Additional operations:

```sh
srx os status --profile web --recorded --json
srx os list --profile web --json
srx os rollback RETAINED_PIN --profile web
srx os recover --profile web
srx os recover OPERATION --profile web --new-boot
srx os recover OPERATION --profile web --manager-changed
```

Default status combines journal evidence with bounded live unit observations and
returns a nonzero exit code on unavailable or mismatched observations. It does
not assert application readiness or an atomic system-wide snapshot. `--recorded`
reads journal evidence without connecting to the manager. Existing commands with
explicit installation, Store, credentials and manager flags remain available.

Stop selects a retained empty generation through the normal coordinator. It
revokes recorded start authority and stops only the recorded invocation. It does
not evaluate project source, discard retained generations or delete service
data. Pending effects require recovery before another apply, rollback or stop.
Stopping one service independently is not part of this interface.

Logs require the optional host program `journalctl`. Arguments are passed
directly, without a shell, and constrain unit, UID, boot and recorded invocation
for application and manager records. `--follow` follows those recorded
invocations; rerun it after a new apply to follow new invocations. Cancelling the
reader does not stop the service. Journal permissions remain enforced by the
host.


## Linux requirements and qualification

Readiness depends on the requested operation:

| Operation | Requirements |
| --- | --- |
| Check, format, plan, recorded status | No manager or build toolchain |
| Import a local verified runtime bundle | Compatible target, verified runtime closure, writable Store |
| Run a selected command | Compatible kernel/architecture and retained runtime closure |
| Apply services | Selected systemd manager, required D-Bus interfaces, real unit search directory and execution authority |
| Build from source | The selected profile's compiler/tools, source permissions and isolation capabilities |

Build settings belong in the configuration supplied to `init --config`.
For local verified bundles, choose an [artifact policy](artifacts.md); importing
runtime outputs does not require a host compiler.

Service supervision uses the engine's versioned host interface contract.
Systemd 250 is the upstream supervision baseline and 254 the managed baseline;
actual required D-Bus signatures/properties determine compatibility, allowing
compatible backports. Source-build isolation additionally checks Landlock ABI 6,
namespaces, cgroups and the required descriptor/process APIs. `srx host inspect`
reports capabilities; it does not certify every later operation.

The catalog's Debian and Ubuntu 24.04 qualification VMs use an authenticated
Linux 6.12.109 kernel and explicitly provisioned tooling. They are not evidence
that every stock distribution kernel is sufficient. Existing GNU/musl bundles
and evidence remain bound to their exact release snapshot. ARM64 packages and
non-systemd service managers are not qualified. A user profile does not enable
linger, boot startup or login persistence implicitly.
