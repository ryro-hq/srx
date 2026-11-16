# Native image references and disposable VM fixtures

These are explicit test inputs for format interoperability. They are not SRX
system components, package release qualifications or proof of a complete VM boot.
The ordinary unit tests do not silently discover these tools through PATH.

## System component preparation and action identity

On 2026-10-23, `cargo test --locked -p syrox-engine --lib build::system::`
passed 15 cases before the manager-limit adapter was added. They cover strict
versioned/canonical action parsing, an independently assembled 701-byte identity,
all eight budget dimensions and policy binding, locked System closure membership,
service-local/transitive inputs, source mutation/cancellation, and refusal before
operation creation. An actual source of 17 MiB + 19 bytes exceeded the common
Standard cap while ordinary admission continued refusing it. A real v3 input was
materialized, bound into the action and retained after its original root was
retired by GC. Source collection after preparation custody ended was also checked.
The worker ELF in these unit cases is a format fixture, not an implemented worker.

The ordinary managed suite also passed 100 cases (three environment-dependent
cases ignored), run as the non-root user outside the Unix-transport-restricted
sandbox. Logs are `.syrox/work-logs/system-action-tests-v8.log` and
`.syrox/work-logs/system-action-managed-tests-unsandboxed.log`. Workspace
all-target/all-feature Clippy with warnings denied passed in
`.syrox/work-logs/system-action-clippy-v4.log`. These are preparation and
compatibility checks, not a full System recipe or runtime qualification.

The action/manager-limit suite then passed 19 cases. The additional cases cover
capacity denial before service mutation, preservation of operational selections,
scratch/output individual-file ceilings, infinity refusal and changed manager
limits. The native `system_service_limits` example passed with its final frozen
binary as a non-root user: complete manager-contract observation and independent
child/kernel readbacks agreed on 128 MiB memory, swap disabled, CPU 125%, 16 tasks,
64 soft/hard descriptors, a 16-MiB soft/hard file-size limit and core dumps disabled.
The manager also reported the requested 30-second runtime ceiling. Start/stop
jobs were observed Done and the unit had no live process after explicit stop.

The [native service-limit fixture](../tests/fixtures/system-build/native-system-service-limits.json)
records action, binary, harness, adapter and evidence pins. The frozen executable
is `.syrox/qualified-workers/system-service-limits-2026-10-23-v1`, SHA-256
`71069ea6a2bc3719afa9711f7e8d63fb46cb7f71dcd16fcf97254cc6a43da37f`.
It uses the development host loader/libraries. The metadata-only Directory
program was not executed; the actual child was the diagnostic harness. The
capacity values were explicit diagnostic selections. Runtime expiration,
resource exhaustion, disk/inode enforcement, worker authentication and a full
System recipe remain unqualified by this probe. Its initial sandbox socket
refusal and a passing pre-lint-change run are preserved separately from the
final frozen run in `.syrox/work-logs/system-service-limits-native-v3.log`.

The scratch-binding suite subsequently passed 21 local cases, with its one
disposable-VM case ignored locally. Capacity, identifier, cancellation and
deadline refusals, plus changed-source refusal, precede helper contact. The
log is `.syrox/work-logs/system-scratch-tests-v3.log`. The VM test uses the real
engine preparation/Store and private helper; its static ELF fixture is only
an image-format input and is never executed as a System worker.

## Complete System input resources and cross-process transfer

On 2 November 2026, the System suite passed 34 top-level cases (two helper entries
ignored by the parent run), plus its explicitly spawned child entry. Nine new
resource cases cover aggregate FD admission before interest creation, mixed
legacy/v3 descriptors, independent positional reads, receiver retention after
sender/preparation destruction and root retirement/GC, separately transferred
retention, wrong metadata/roles, byte-identical interest-file replacement,
incomplete retention coverage, blob/view corruption and cancellation. A view
with 16,385 files passed its v3 limits while ordinary managed preparation still
refused it. An independently assembled 281-byte metadata fixture has SHA-256
`e2c3488f82e03dd9fd6c8c8253ec566dc6202bb9e38b4d0b65e511282062a132`;
strict-version, unknown/duplicate-field and noncanonical-record cases passed.
Directly received descriptors with their CLOEXEC flags cleared were normalized
and verified to close on exec. Aggregate capture also avoids repeatedly verifying
every unrelated input for each selected input.

Four new transfer cases cover kernel PID/nonce mismatch, malformed metadata and
batch offsets, cancellation/deadline/idle channels and an actual process exec.
The parent prepared 33 imported inputs (17 chunked v3, 16 blob v2), transferred
84 descriptors through Unix seqpacket in multiple metadata fragments and FD
batches, and observed acceptance only after receiver validation. Every packet
was checked against its actual `SCM_CREDENTIALS`. The child closed unrelated
inherited descriptors on exec, so inherited Store leases could not mask a broken
retention handoff. After the parent dropped its preparation/resources and retired
all 33 roots through GC, the child revalidated/read its last input, exited zero
and a final GC collected the source. The child action was
`bc52ebb83e091839f6d5d1ab45e3bd6c9bb617ddf096875951e15a0d078f1f3a`.

The [native input-transfer evidence](../tests/fixtures/system-build/native-system-input-transfer.json)
pins the 89,401,192-byte test executable frozen at
`.syrox/qualified-workers/system-input-transfer-tests-2026-11-02-v2`, SHA-256
`39ad3226a846bc3874b0a27ccbf69fca3c73e962c0c80aef824d372c0b96784b`,
partial source snapshots and the successful log
`.syrox/work-logs/system-input-transfer-tests-unsandboxed-v1.log`. The executable
uses the development host Rust toolchain, loader and libraries. The initial
sandbox run's four socketpair EPERM failures remain in
`.syrox/work-logs/system-input-transfer-tests-v1.log`; rerunning as the same
non-root user outside that restriction passed. The earlier 33-case qualification
and intermediate run are preserved separately from the final binary/source
snapshot, which includes CLOEXEC normalization and aggregate scan optimization.

The ordinary managed-resource suite passed all ten cases, including its fixed
envelope, exact roles, interest coverage, GC and wide views. Materialization
passed all eleven cases. Workspace Clippy with all targets/features and with no
default features, warnings-denied rustdoc, formatting and structural checks also
passed. This increment qualifies input content/retention and the message protocol
in these native cases. It executes no System recipe and qualifies no executable/
manager binding, FDSTORE/gate/namespace lifecycle, full runtime budget, build
receipt, privileged operation, own kernel/boot, provisioning or host adoption.

## Chunked input descriptors

The separate chunked-input descriptor suite passed all 30 Store chunked cases
after adding six handoff/reader tests. A real sparse stream of 1 GiB + 17 bytes
used 257 logical chunks but only four descriptors (manifest plus first/zero/last
unique chunks). The receiver verified its whole content pin, sought across chunk
boundaries and read both markers with a one-chunk cache. Other cases checked
independent seek offsets, explicit FD/byte ceilings, wrong count/order/pin,
writable-role refusal, a correctly hashed manifest carrying a false whole-content
claim, mutation, cancellation, empty streams and custody through GC. Cached reads
also refuse roles unlinked after sender custody ends. The final log is
`.syrox/work-logs/system-chunked-descriptors-tests-v4.log`; the preceding v3 GC
failure is retained separately and prompted that cached-read custody check.

The prepared System v3-input case also passed with descriptor export, original
root retirement/GC, receiver verification and package indexing/readback without
a Store pathname. Its final targeted log is
`.syrox/work-logs/system-input-descriptors-integration-final.log`. These tests
clone actual readonly descriptors; they do not qualify a new authenticated
worker socket protocol or complete receiver-retention/gate/namespace lifecycle.

## System output producer and worker framing

On 2026-10-23, `cargo test --locked -p syrox-engine --lib result::` passed all
58 cases. The producer exercised an actual sparse regular file of 1 GiB + 17
bytes, with first/last markers, streamed into chunks. An independent whole-frame
hash matched; the v3 result was admitted, exported through a deduplicated v2
system bundle, imported into a second Store and checked. Root retirement and
GC then reclaimed the original result. Another case encoded 16,385 files while
the legacy encoder continued refusing that count.

The separate worker transfer passed multiple actual output trees across chunk
boundaries, v3 result admission/materialization, short/interrupted reads/writes,
every budget dimension/policy binding, selection mismatch, aggregate alias and
inode limits, cancellation, corruption, truncation and trailing-byte refusal.
The fixed 303-byte v1 packet fixture has SHA-256
`9985771dade5fd6896d66114cc2ee169f0ab44da1b8ac5faec5197d2341040b2`;
its budget binding is
`ba4541f59af8088a4b8efa9fdbfbfc9d8db13607120f23d4ea77476347612013`.
These pins were independently assembled from the documented framing and are
asserted in the test. The successful native log is
`.syrox/work-logs/system-worker-output-result-tests-v2.log`.

This qualifies the output encoding, transfer and consumption APIs using
caller-created regular files. It executes no System recipe and establishes no
runtime enforcement, worker authentication, build receipt, own toolchain, kernel
or boot qualification. No privileged device or mount operation is involved.

The `system_output_transport` Rust example then passed an actual two-process
transfer of a 1 GiB + 17-byte file through an anonymous pipe. Coordinator and
worker both set and read back soft/hard `RLIMIT_AS=256 MiB` and `RLIMIT_NOFILE=64`.
Observed VmHWM was 8,996 kB and 4,588 kB respectively. The complete independent
package hash matched, 257 chunks shared five result references, and a
8,414,048-byte bundle imported into a second Store. The run exited zero in
17,549 ms. Its source, frozen binary, generated payload and evidence pins are
recorded in [the native fixture](../tests/fixtures/system-build/native-system-output-transport.json).
The harness uses a 120-second deadline for nonblocking pipe reads and settles
its child on failure. It creates only a new explicit directory, preserving the
inputs, Stores, bundle and logs for review. This address-space limit verifies
bounded transfer in this case; it does not qualify cgroups or all eight runtime
budget dimensions. The binary uses the development host Rust toolchain and is
not a distributed System component or an own-bootstrap result.

## Explicit local builder admission

On 2026-10-23 the configuration suite passed 14 cases, including complete System
policy parsing without path effects, every required dimension/type/width,
unknown-field refusal, canonical endpoints, eight independent over-budget
denials and separation from ordinary managed/HostBootstrap settings. The real
CLI suites passed 14 general cases, one source-diagnostic matrix and 12 system
cases. New cases admit a locked System's budget with explicit `--builder-config`,
verify the version-2 observation digest, deny each exceeded dimension and reject
the flag on HostConfiguration before opening its supplied policy path.

The admitted fixture deliberately uses absent worker/bus/socket-parent/Store
paths and an unsuitable regular file at the helper endpoint. Admission succeeds
without opening/connecting to them, keeps their verification flags false, and
preserves project, lock, policy and endpoint bytes. Default reports retain
version 1. This checks policy selection/admission rather than resource
enforcement or execution. Logs are
`.syrox/work-logs/system-builder-policy-config-tests-final.log` and
`.syrox/work-logs/system-builder-policy-cli-regressions.log`.

## qcow2 reference

On 2026-10-22 the following signed Arch packages were downloaded into
`.syrox/test-tools/qemu/` without installing packages or changing `/usr`:

| Package | Archive SHA-256 |
|---|---|
| [qemu-img-11.1.2-1-x86_64](https://archive.archlinux.org/packages/q/qemu-img/qemu-img-11.1.2-1-x86_64.pkg.tar.zst) | `666dfe6cda552f09091c1cc03fd1143293bd25f47eee4745053efa170fc32e5c` |
| [libaio-0.3.113-5-x86_64](https://archive.archlinux.org/packages/l/libaio/libaio-0.3.113-5-x86_64.pkg.tar.zst) | `e746fdedefa9987ad06e918af78976917aba780be8ac51d22dcb9ded324a84ab` |

Detached `.sig` files were verified with the existing host Arch public keyring,
converted from armor to a local binary keyring. Both verifications reported
`GOODSIG` / `VALIDSIG` for signing subkey
`62CC73F884E52957B2FDD8839B7A287D9A2EC608`, primary
`991F6E3F0765CF6295888586139B09DA5BF0D338` (David Runge).
The converted keyring's SHA-256 was
`f7af717a90821803e5c366032f3135c236c4100962716b3c1ed352f8b9330f51`.
Signature hashes were `9cfafa1c7accca43871cf633a277dce3a243a48c2579d32a136229e146cfa571`
and `a54945f3bf1d4d6b9012a9182a72349a3fc0e21ae3c8a2dd564c7f391d9b2cf2`,
respectively. This records the local trust input, not an automatic trust policy
for future archive keys or package versions.

Only the selected `usr/bin/qemu-img` and libaio runtime files were extracted into
the private fixture tree. Executable SHA-256:
`3a57bce6765bfb73a75591dba2ac40d985cccde97d371e95537ecbf16d949d30`.
The libaio regular file SHA-256 was
`15cfed3ce7e472de5b87849812d4fc91271a81a0bc64c99e0971d02b11343685`.
The tool reported QEMU 11.1.2. Its other libraries/loader come from the native
host: this fixture is **not a hermetic VM test environment**. Full qualification
must separately fix the complete tool/firmware/VM environment.

Select the exact executable with `SRX_QEMU_IMG` and its pin with
`SRX_QEMU_IMG_SHA256` when running the ignored
`qemu_checks_refcounts_and_decodes_byte_identical_raw_content` test in
`syrox-system`. The local fixture also requires `LD_LIBRARY_PATH` pointing to
its `root/usr/lib` for libaio. Set `TMPDIR` to an existing private disk directory
with sufficient room for both encoded and decoded regular images. The test
creates no device mapping, mounts nothing and never repairs an image.

The oracle runs `qemu-img check`, JSON info and conversion to RAW, checks exact
decoded size/SHA-256, and rehashes the original qcow2. Cases include partial/full
clusters, the first L2 boundary and the transition to a second refcount block.
These are data-format tests; they do not run a guest or establish boot health.

## GPT and dm-verity references

The GPT test selects `SRX_SFDISK` / `SRX_SFDISK_SHA256`. The observed native
tool was util-linux 2.42.4, executable SHA-256
`858bc262400218707b901bd8ee4e018ee0eede4019f753a544d340d819b898eb`.
It reads disposable regular images with 512/4096-byte sectors, including a
deliberately corrupted primary header, and the test checks that it makes no repair.

The dm-verity test selects `SRX_VERITYSETUP` / `SRX_VERITYSETUP_SHA256`.
The observed native tool was veritysetup 2.8.8, executable SHA-256
`fbc00120a61154391afdcddb90ab23b00401fc3f63ab8ad59cbf57fba62b7e32`.
It compares root hashes and complete hash devices, verifies data, and refuses
modified data/hash images in userspace. It creates no kernel dm-verity mapping.
Both native reference executables also use host runtime libraries.

Local verification logs live under `.syrox/work-logs/`. Ignored fixture/log files
are local evidence locations, not published artifact endpoints.

## Disposable loop-device guest

The [fixture inputs](../tests/fixtures/system-vm/inputs.json) pin QEMU 11.1.2,
OVMF 202608, supporting Arch archives, signing fingerprints and Fedora CoreOS
44.20260928.3.1. All selected package signatures reported GOODSIG/VALIDSIG
against the same local Arch keyring described above. The Fedora image signature
reported GOODSIG/VALIDSIG for Fedora 44 primary
`36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`, using the official
[`fedora.gpg`](https://fedoraproject.org/fedora.gpg) input. The compressed and
uncompressed hashes matched the pinned
[stable stream metadata](https://builds.coreos.fedoraproject.org/streams/stable.json).
Supporting runtime files were extracted into the private fixture tree, without
installing packages; QEMU still uses the native host loader and some libraries.
This is a recorded test environment, not a hermetic redistributable toolchain.

Build the Rust qualification executable and emit the offline Ignition fixture:

```sh
RUSTFLAGS='-C target-feature=+crt-static' cargo build --locked \
  -p syrox-system --example scratch_loop_probe --target x86_64-unknown-linux-gnu
cargo run --locked -p syrox-system --example loop_fixture -- \
  target/x86_64-unknown-linux-gnu/debug/examples/scratch_loop_probe > probe.ign
```

The generator embeds a gzip/base64 probe with an uncompressed SHA-512 pin,
a marker under `/etc` and a systemd unit. It follows the
[Ignition 3.5 file contract](https://coreos.github.io/ignition/configuration-v3_5/).
The unit loads loop with `max_part=0`, executes the test and requests poweroff.
It disables automatic OS updates in the fixture. No network fetch or host share
is needed in the guest.

The observed invocation used `q35,accel=tcg`, CPU `max`, two CPUs, 2,048 MiB,
`-nodefaults -display none -vga none -serial stdio -monitor none -nic none`,
read-only OVMF CODE, a fresh copy of the pinned VARS template, a snapshot of the
fixed qcow2 attached through virtio-blk, and
`-fw_cfg name=opt/com.coreos/config,file=probe.ign`. A 600-second outer timeout
bounded QEMU. TMPDIR pointed to the private workspace disk directory, so temporary
overlays did not consume host RAM-backed `/tmp`. The original guest image was
not selected writable. No host block device was passed and `-kernel` was absent.

On 2026-10-22 the guest booted from OVMF/disk, ran Linux
`7.2.7-200.fc44.x86_64` and systemd `259.9-1.fc44`, and the probe exited zero.
It checked a new private regular 64 MiB image, exact loop geometry, first/last
block writes, refusal beyond capacity, changed mode/link-count/length detection,
repeated-attempt refusal, deferred release with a second opener, final sysfs
teardown evidence and a separately journaled second configuration/release.
All ten steps and `SRX_LOOP_PROBE_OK` appeared on the serial console, followed
by guest poweroff; QEMU exited zero. This proves those loop operations on this
fixture. It does not qualify ext4 mounts/inode limits, helper authorization,
system builds, Secure Boot or a source-built SRX operating system.

```text
probe sha256     9474762246dae7992ea0172920693f44a3c00ebb8c1341288f08696c5bdeecc5
ignition sha256  2bb8ed68ad1b2a254e4b88e0f1ac3d02c3e02726a092a43c5d968fe5ef52ba50
serial sha256    d5091fd6b4240c65afb3e932fa6aeec510f6953492169bf5845151301d179846
```

The probe is retained locally as
`.syrox/qualified-workers/scratch-loop-probe-2026-10-22`; the successful fixture
and log are `.syrox/test-tools/qemu/loop-probe-v2.ign` and
`.syrox/work-logs/loop-probe-vm-v2.log`. An earlier configuration attempted a
marker under read-only `/run` and failed during Ignition; its distinct initial
fixture/log are preserved, and that run did not reach the probe. The generator
now uses `/etc` and compresses its embedded executable to reduce fw_cfg transfer.

## Disposable ext4 scratch guest

On 2026-10-22 the extended probe passed on the same pinned QEMU/OVMF/Fedora
inputs with one CPU, 2,048 MiB and a 900-second outer timeout. It booted through
firmware and disk without `-kernel`, network, host shares or host block devices.
The generator accepted the probe followed by the source-built mke2fs and e2fsck
executables. Their source, seed inventory, build artifact and receipt are recorded
in the catalog's `docs/evidence/e2fsprogs-1.47.4-host-bootstrap-2026-10-21.md`.
The probe verified exact tool sizes/SHA-256 and executed sealed static snapshots.

```text
mke2fs sha256    59935ec5c57f7f3b2e5ef1119d7480275264a9f5adecb862b7bd2ae813fd83ec
e2fsck sha256    da1f6de6ac3a2efd7fc6d2581199ce7109a22dee7843ce923e4111a92666a95a
probe sha256     fff72f41b36ec08272f85fa36453c8b210e4afc2d19c5143297fa757864d5b2e
ignition sha256  145637e24a690de12abbb2a063afb67c8ff3a52b7a07436e7cb4d418ca9a8ed4
serial sha256    7429747519b9aa435c661d313c2adaeb84ed7581e1cbeec6a427165dee9d94fb
```

The retained executable is
`.syrox/qualified-workers/scratch-ext4-probe-2026-10-22`; the successful fixture
and log are `.syrox/test-tools/qemu/ext4-probe.ign` and
`.syrox/work-logs/ext4-probe-vm-v2.log`. All twenty journal steps,
`SRX_EXT4_PROBE_OK` and `SRX_LOOP_PROBE_OK` appeared, followed by guest poweroff
and QEMU exit zero. A preceding run (`ext4-probe-vm.log`) terminated with status
143 before the probe; the signal's origin was not established and that run is
not qualification evidence.

The ext4 test created and checked its own regular 64 MiB image, refused a
smaller admitted backing budget, mounted it through the detached mount API and
verified 512 total inodes. Creating empty files reached ENOSPC after 501 files;
reserved inodes, directories and lost+found consume the remainder. After removing
those files, writes reached ENOSPC after 66,060,288 bytes while the backing length
remained 67,108,864 bytes. Holding a duplicate mount-root descriptor deferred
loop release and preserved readable data; closing it allowed final teardown.
A forced read-only e2fsck then passed.

The writer and tool runner in this qualification example run as root inside the
guest. Assigning the mount root to UID/GID 1000 does not qualify an unprivileged
worker. This proves the tested allocated-storage/inode limits and lifecycle,
not sparse-file logical limits, helper authentication, isolated tool execution,
all build budgets, a journaled filesystem feature policy or a source-built OS.

The same frozen probe also passed using a second read-only virtio disk containing
only that executable and the two pinned tools. This replaces the large embedded
fw_cfg payload with a 1,117-byte Ignition configuration. The mount uses the
explicit guest SELinux context `system_u:object_r:bin_t:s0`; SELinux remains
enabled. An initial disk fixture mounted successfully but did not run the probe;
its log is preserved and is not a passing result. Adding the context and the
service journal to the serial diagnostics produced the successful repeat.

```text
payload sha256   a02d23129fd6a2ee2f076d92e4729fde2c88f0920206760208dfd59089153b53
ignition sha256  38c277e003fe9245aa1adf345f5370595eee004f62764c2aff6914f9db8b912b
serial sha256    5298b05de64d3badb804612efecb76622439910383323d09994db453444d6a05
```

Local paths are `.syrox/test-tools/qemu/probe-tools-20261022-v1.ext4`,
`ext4-probe-disk-v2.ign` in that directory and
`.syrox/work-logs/ext4-probe-vm-disk-v2.log`. Generate the small configuration
with `loop_fixture --disk`. Attach the payload with
`-drive if=none,id=tools,format=raw,readonly=on,file=PAYLOAD` and
`-device virtio-blk-pci,drive=tools,serial=srx-probe-tools`, using the preceding
firmware/disk boot flags and a fresh VARS copy. Both success markers, all twenty
steps, guest poweroff and QEMU exit zero were observed. Payload and base-image
hashes were unchanged. This is a test transport optimization, not an SRX system
image or a new qualification scope.

The guest's private intent/output files live in the disposable snapshot overlay.
The retained serial logs record the observed steps; those guest files are not
published or persisted for recovery after QEMU removes its temporary overlay.
Interrupted-operation recovery requires separate persistent-state fixtures.

## Isolated ext4 tools

The `loop_fixture --disk-isolated` configuration selects the probe's fixed
`--ext4-isolated` mode. On 2026-10-22 this passed with the same pinned firmware,
guest and native QEMU environment, one CPU, 2,048 MiB and a 900-second outer
timeout. The second read-only disk additionally contained a pinned static Rust
qualification payload. Source-built mke2fs/e2fsck pins remain those above.

```text
probe sha256      81f4923e5eea5e88654152abdedc0a7e8a97e490c85db5f919bab996942a65ba
assertions sha256 96be4e23b124e22112e0cbc963368ded50130419aaa174f5e3c0c55b7ca3bfba
payload sha256    59f2b51836abe0c4dac9d4db2a5894a9fa8a1037d5aca0b019e68d26494922ba
ignition sha256   625bd5c4008eb7ff763c927e8a164b8312e7af40f87ea02764e361b89371ef6e
serial sha256     7ae1a5f93beac148177becf97f39bc8d8facb33ca357a7b6db9172a9b49194d3
```

Local evidence is `.syrox/work-logs/ext4-isolated-vm-v5.log`,
`.syrox/test-tools/qemu/ext4-isolated-v1.ign` and
`.syrox/test-tools/qemu/probe-tools-isolated-20261022-v5.ext4`. The probe and
assertion executables are retained in `.syrox/qualified-workers/` as
`scratch-ext4-isolated-probe-2026-10-22-v5` and
`ext4-tool-isolation-checks-2026-10-22-v4`. Both tools execute inside private
namespaces through sealed memfds, with a read-only root exposing only the image,
empty configuration and a validated null-device leaf. The qualification payload
checked 4,093 possible non-stdio descriptor numbers, visible paths, refused
writes, exact rlimits, zero capabilities after exec and EPERM for harmless
clone3/signal-zero/setuid/unshare/peer-prlimit attempts.

All twenty loop/ext4 steps, `SRX_EXT4_TOOL_ISOLATION_PROBE_OK`,
`SRX_EXT4_ISOLATED_TOOLS_OK`, `SRX_EXT4_PROBE_OK` and `SRX_LOOP_PROBE_OK`
appeared. Format, pre-mount e2fsck and post-teardown e2fsck exited zero; QEMU
powered off and exited zero. The inode/byte results matched the preceding
501-file / 66,060,288-byte observations. The payload hash was unchanged.

Earlier attempts are preserved distinctly. The first returned EINVAL during
setup; stage diagnostics in the second identified mounting through a directory
description retained from the old mount namespace. Reopening with identity
checks in the new namespace and executing the anonymous tool by descriptor
resolved it. A third attempt formatted successfully but the Rust assertion
payload failed during startup; allowing poll/ppoll for Rust's standard-descriptor
checks resolved it, also verified by a separate pinned unprivileged exec oracle.
The fourth completed the full probe but e2fsck reported a missing /dev/null;
the fifth supplied only the validated character device and removed that error.

mke2fs still reports that host mount-table files are absent. None are fabricated
inside the private root. The caller must establish exclusive ownership of a
NEW image and final loop teardown independently; that warning is not evidence
that an arbitrary existing filesystem is safe to format. The empty configuration
also does not qualify a journal/feature policy. This case establishes the tested
tool containment and scratch primitives, not helper authorization, persistent
journal recovery, all build budgets or a source-built SRX operating system.

## Private scratch helper guest

On 2026-10-22 `helper_probe` passed using the same pinned QEMU/OVMF/FCOS inputs,
one CPU, 2,048 MiB, TCG and a 900-second outer timeout. The offline configuration
was generated with `loop_fixture --disk-helper`. The read-only payload contained
only the probe, helper and the two source-built e2fsprogs tools. The root probe
verified the helper/tool pins, copied them to its own root-owned namespace,
wrote private administrator policies and launched separate root helper sessions.
The unprivileged clients created their sockets after dropping supplementary
groups and switching to UID/GID 1000; socket-pair credentials created as root
were not substituted for that authentication test.

```text
helper sha256    faa8e8fe5bfbe3433e39114d862c71f041c59b75bccfdf8635b3bdf8cc832038
probe sha256     15210c17c9765bfb2e419966f52b49a6d424da2e91959f2b0a3b34b654c4b545
payload sha256   e023fee83ddc58989e74c1372ba70bf17de2c7fd07bf5db6ece37ea9a16ba42a
ignition sha256  249cdc2f829ee3ff5e24ea1a2acdcc15be6d018fbd1cb816bde50291e6978b01
serial sha256    51265e451b33c60e6293fa38d726c56b0772682eebd9ee0fd0f789287d59d6a5
```

Artifacts are retained locally as
`.syrox/qualified-workers/syrox-system-helper-2026-10-22-v1`,
`.syrox/qualified-workers/helper-probe-2026-10-22-v1`,
`.syrox/test-tools/qemu/helper-tools-20261022-v1.ext4`,
`.syrox/test-tools/qemu/helper-probe-v1.ign` and
`.syrox/work-logs/helper-probe-vm-v1.log`.

Seven cases completed: authorized allocation, replay, wrong peer UID, unknown
field, excessive budget, disconnect and a subsequent different request after
that disconnect. The positive client received root-owned sealed replies and
only the filesystem directory fd, wrote/read/fsynced its own file as UID 1000,
closed its descriptions and received the verified release record. Root-only
policy files were inaccessible to the client. The helper formatted/checked the
new 64 MiB image, mounted it, assigned ownership and observed final loop teardown
before its last filesystem check.

Wrong-peer/unknown-field/over-budget cases left their state directories empty.
Reusing a completed id preserved the exact image SHA-256. Disconnect left an
uncertain operation; a new helper process refused another id, retained the image
unchanged and did not create another operation. The fixture independently waited
for teardown before comparing the disconnected image. `SRX_HELPER_CLIENT_OK`,
all seven `SRX_HELPER_CASE_OK` markers, preserved-image/no-effect markers and
`SRX_HELPER_PROBE_OK` appeared before guest poweroff and QEMU exit zero. Payload
and base-image hashes remained unchanged.

This verifies the initial delegated private-scratch operation and fail-closed
replay behavior in that environment. The guest journal still lives in a temporary
snapshot. Power-loss/reset recovery, interruption at each privileged effect,
descriptor retention after a helper crash, deployment/activation units, automated
GC, all System worker limits and host storage provisioning remain
separate work. No physical disk or host boot configuration was used.

### Same-boot helper reconciliation and retained descriptors

A second qualification on 2026-10-22 passed all **19 cases** in one fresh guest
with the same pinned firmware, base disk, TCG/one CPU/2 GiB and no network or
host shares. The exact files below supersede neither the original binary nor
its recorded identity; the older seven-case result remains separate evidence.

```text
helper sha256    cbad2c343cf836adb950423dc933ad798ae32283ca2d93992ee19568312df56f
probe sha256     780ff713fc265eb3604be0af92a4d220843c1e8a36e328e57cfabd4c44d471bf
payload sha256   ce6f789dcd7dfe7aee43b3f4b29f66bb6840e27898e3642644593ce18106fa8f
Ignition sha256  249cdc2f829ee3ff5e24ea1a2acdcc15be6d018fbd1cb816bde50291e6978b01
serial sha256    902ee73cbf303677fd2ba69d1f30672f7ca47be7c8547e4aab4a7af5669561c4
```

Retained local inputs/output are
`.syrox/qualified-workers/syrox-system-helper-2026-10-22-v2` (3,630,408 bytes),
`.syrox/qualified-workers/helper-probe-2026-10-22-v2`,
`.syrox/test-tools/qemu/helper-tools-20261022-v2.ext4`,
`.syrox/test-tools/qemu/helper-probe-v2.ign` and
`.syrox/work-logs/helper-probe-vm-v2.log`. The helper is a static GNU executable;
the tools keep their source-build pins from the previous run.

The original seven cases passed again. The additional cases inspected the
disconnected operation without adding a journal entry, refused a wrong hash,
refused the previously observed hash after the root fixture appended additional
durable evidence, refreshed the plan and reconciled successfully. Reconciliation
and replay refusal preserved the complete backing image SHA-256. A different id
then completed allocation, unprivileged write and verified release, while the
old image remained unchanged.

In a separate allocation the unprivileged client shut down its sending socket
while retaining the actual mount-root fd. The original helper exited unsuccessfully
and was reaped. Inspection from another helper reported an active loop and a
blocked plan; authorization with that blocked hash was refused. After the
fixture signaled the client, it read its existing file through the retained fd,
closed it and exited. Independent sysfs teardown was observed before a fresh
plan and successful reconciliation. Replies distinguished `reconciled` from
`released` and explicitly reported unverified filesystem health.

All 19 `SRX_HELPER_CASE_OK` markers, `SRX_HELPER_RECOVERY_RETAINED_IMAGE`,
`SRX_HELPER_CLIENT_RETAINED_DESCRIPTOR_OK`,
`SRX_HELPER_RETAINED_DESCRIPTOR_RECOVERY_OK` and `SRX_HELPER_PROBE_OK` preceded
poweroff; QEMU exited zero. The read-only payload and base-image hashes were
rechecked unchanged. Eight native helper tests cover additional live-session,
unrecorded-tool-exit, identity-change, partial-record and boot/namespace refusal
cases. This run did not kill the helper during a privileged effect or reset
the guest. Journals still reside in the disposable snapshot, so persistent
power-loss recovery, cross-boot reconciliation and every System worker budget
remain unqualified.

### Non-root namespace attachment

A third fresh guest run on 2026-10-22 passed the previous 19 cases and a
20th namespace-attachment case, using the same helper v2 and source-built tools.
The static client probe v3 directly called the mount syscall for this feasibility
check; the shared `ReceivedScratch` API was added afterward and requires its
own integration qualification.

```text
helper sha256    cbad2c343cf836adb950423dc933ad798ae32283ca2d93992ee19568312df56f
probe sha256     1534044d038429078af81cedbb5f983ffe8cb59aa7994e3aa6ff1be93b099b0a
payload sha256   a32014372b27c68f123ab51882672f02ff2b85e3b25151c1ed06230d52742151
Ignition sha256  249cdc2f829ee3ff5e24ea1a2acdcc15be6d018fbd1cb816bde50291e6978b01
serial sha256    f0e92099ebd3e23a5c1dc3a7ef932aeb6364d0d73ee32516f0f7bf36fcd2294e
```

The corresponding local names are `helper-probe-2026-10-22-v3`,
`helper-tools-20261022-v3.ext4`, `helper-probe-v3.ign` and
`helper-probe-vm-v3.log`, under the same directories as the previous run. QEMU
exited zero after the markers `SRX_HELPER_SCRATCH_NAMESPACE_OK`,
`SRX_HELPER_CASE_OK namespace`, `SRX_HELPER_PROBE_OK` and guest poweroff. The
read-only payload hash was rechecked unchanged.

The authorized UID/GID 1000 client transferred only the actual mount-root fd
to a separate executable. That executable mapped the same numeric non-root
identity in a new user namespace, created mount/network/IPC/UTS namespaces,
made mount propagation private and moved the anonymous mount directly to its
new local target. It checked root identity, ext4 and nodev/nosuid writable flags,
cleared effective/permitted/inheritable capabilities, set no-new-privileges and
wrote/fsynced a file. The original client read the file after the namespace child
exited, then released its grant. The helper's independent teardown and final
filesystem check passed. No namespace PID 1, build process, cgroup enforcement,
large source transfer or worker receipt was exercised.

The prototype deliberately avoids resolving the received fd's readlink as a
new mount source. Its semantics were reviewed against upstream Linux
[`do_move_mount`](https://github.com/torvalds/linux/blob/v6.18/fs/namespace.c)
and the local UAPI's empty-path flags; qualification applies to the fixed guest
kernel, rather than establishing behavior for every supported kernel version.

The fourth fresh guest run replaced that direct syscall with the production
`scratch::ReceivedScratch`/`AttachedScratch` API. All 20 cases passed again,
including the independent identity/flag/write checks, client release, final
e2fsck, guest poweroff and QEMU exit zero. Both source and target used empty-path
directory descriptor resolution (`0x44`); the target was opened after creation
of the private namespaces. This verifies the shared primitive in that guest;
the managed build worker has not yet been connected to it.

```text
helper sha256    cbad2c343cf836adb950423dc933ad798ae32283ca2d93992ee19568312df56f
probe sha256     22515377f9bbb8fc725281b4a0693ff3d2caacad26edcc36a5477c698a011184
payload sha256   bce2699ddb348afed5f51e559cb1d2047db0d39b38f53d64c6df6c9aecef7d0b
Ignition sha256  249cdc2f829ee3ff5e24ea1a2acdcc15be6d018fbd1cb816bde50291e6978b01
serial sha256    43fd2949bc1ac12a89a05d57076a990abace00c7c93ff887a68903ad2f7c5352
```

The corresponding retained names end in `v4` under the same local directories.
The read-only payload was rehashed unchanged. Helper v2 and the source-built
mke2fs/e2fsck retain their previous pins; adding the shared receiver changes
neither those frozen inputs nor the earlier qualification evidence.

### Systemd socket activation

A fifth fresh guest run on 2026-10-22 passed **24 cases**, adding actual systemd
activation to the previous 20. It used the production `helper_activation`
renderer to create runtime system units only inside the marked disposable VM.
The root fixture selected protected policy/state paths and root-owned executable
copies, explicitly labeled the executables `system_u:object_r:bin_t:s0` for that
guest, installed the units in `/run/systemd/system` and used the pinned FCOS
systemctl. No development-host unit was installed or started.

```text
helper sha256    cbad2c343cf836adb950423dc933ad798ae32283ca2d93992ee19568312df56f
probe sha256     705f8b8a6b22543cb2c990e9e092859250f141541b7104095ea5977795be55d2
payload sha256   7a1918fce3a81c69f6f991468c67644bfc210e1f072cff0c1485ccf76894c5ec
Ignition sha256  c2e88a85b684f03802a6f7015e2a454200d0a881533f925c84ecb215a0f1db55
serial sha256    17741d5b8286c173cdf4c56b966c4c7e6e15fa176a3e15337b3f06bc34d5349b
```

Local inputs/output use the corresponding `v5` names under the same directories
as the previous cases; helper v2 and both e2fsprogs tools keep their pins. The
Ignition generator adds collection of the accepted helper instances' journal
before powering off. QEMU/OVMF, the base OS image, one TCG CPU, 2 GiB, read-only
tools payload and absence of networking/host shares are otherwise unchanged.

The UID/GID 1000 client connected to the root-owned mode-0660 socket. Systemd
spawned the root handler and supplied the accepted seqpacket on fd 3. While the
client held the offered grant, the fixture compared loaded service settings
with `memory.max=536870912`, `pids.max=8`, one-CPU `cpu.max` and both descriptor
rlimits at 128. It also observed no-new-privileges, private networking,
`ProtectSystem=strict` and the closed device policy. A test-only ExecStartPre
oracle, compiled into the pinned fixture binary, ran under those same service
restrictions and verified EPERM opening the VM's `/dev/vda` and EROFS creating
its new marker in `/etc`. Neither operation writes a host disk.

The client then attached scratch using `ReceivedScratch` in its private
namespaces, wrote with cleared capabilities and obtained the helper's final
checked release. Replaying that id and exceeding the root budget preserved the
exact image SHA-256. Reconfiguring the fixture's own units to a policy for a
different UID refused the peer and left that state directory empty. The
`SRX_HELPER_ACTIVATION_KERNEL_LIMITS_OK`, four device/write-denial markers,
all 24 case markers, `SRX_HELPER_ACTIVATION_PROBE_OK` and `SRX_HELPER_PROBE_OK`
preceded poweroff and QEMU exit zero. Payload and base-disk hashes were rechecked.

This qualifies activation and the helper overhead envelope in that environment,
not resource-exhaustion behavior or the future build-worker budget. Persistent
reset recovery, an installation command, managed System-worker integration and
hardware/host provision remain unqualified. The fixture uses the activated
root connection for scratch only; it adds no project-controlled privileged
command. Activation/device semantics follow upstream
[systemd.socket](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html)
and [systemd.resource-control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).

### Typed helper client and real recovery CLI

A fresh `v6` disposable guest passed 29 distinct cases on 22 October 2026.
It repeats the previous 24, now using the production `helper_client` for the
activated namespace/write/release case, and adds a typed-client disconnect and
four real `srx system recover` invocations. This uses the same frozen helper v2
and e2fsprogs tools; their protocol remains compatible with the shared strict
request enum. Existing qualified binaries and their evidence were preserved.

```text
helper sha256    cbad2c343cf836adb950423dc933ad798ae32283ca2d93992ee19568312df56f
CLI sha256       0181371c237851eed1855b744131320b1201b785fb023aefcc459ba2f41fdc57
probe sha256     cd3e19cac14851d2e4cddff5116bbf41b56a6c98366a3602523d181278a6c76a
payload sha256   fc3f1232b6401405825471eff32915080c3c1393f0c76344b1af11ec89a226bc
Ignition sha256  c2e88a85b684f03802a6f7015e2a454200d0a881533f925c84ecb215a0f1db55
serial sha256    673d9eb0cf2af4587c95259eea3c499cd81a6ae38480754e8f4a688932d8be69
```

The frozen CLI is `.syrox/qualified-workers/srx-system-recover-2026-10-22-v1`
(70,727,504 bytes); probe is `helper-probe-2026-10-22-v6` in that directory.
Both were built with the development host toolchain and
`RUSTFLAGS='-C target-feature=+crt-static'` for `x86_64-unknown-linux-gnu`.
The first CLI link failed because host static liblzma was absent; the successful
build explicitly used `LZMA_API_STATIC=1`, compiling the dependency's vendored
source. ELF inspection found no interpreter or needed shared libraries in the
resulting static PIE. This is a pinned test executable, not a source-bootstrap
toolchain or qualified distributed release.

The new read-only tools image `helper-tools-20261022-v6.ext4` is 128 MiB to carry
that CLI. It was created only at a new fixture path and checked with the pinned
source-built tools. Ignition and fresh OVMF variables use the `helper-probe-v6`
names. QEMU/OVMF, the signed base OS, 2 GiB, one TCG CPU, no network or host
shares, and firmware/disk boot remain the same. The serial log is
`.syrox/work-logs/helper-probe-vm-v6.log`.

The typed coordinator authenticated the root socket and sealed replies, checked
the received filesystem and kept control outside the worker user namespace.
Only the root fd entered the isolated worker; capability-free write and the
helper's final release check passed. A second grant wrote/fsynced data and then
disconnected without release. The fixture independently waited for the helper
process to end, checked the state lock and loop teardown, and observed the
uncertain record before executing the CLI as UID/GID 1000.

Read-only CLI inspection returned a reconcilable plan with retained image and
unverified health. Applying an incorrect hash failed without adding records or
changing the full image digest. Applying the inspected hash added exactly one
reconciled record, retained the image byte-for-byte and did not claim filesystem
health. A final inspection reported the terminal operation as blocked, with no
further effects. All 29 unique case markers, the typed release marker, kernel
limit checks, nine activation denial markers, both final probe markers and
normal poweroff preceded QEMU exit zero. Base OS and payload digests were
rechecked unchanged. Journal output repeats some markers; repeated lines do not
count as additional cases.

This qualifies the typed scratch client and narrow recovery CLI in the same
guest boot. Reset recovery, complete System-worker execution/resource budgets,
system generation recovery, host adoption and provisioning remain pending.

### Separate workspace volumes

On 2 November 2026, disposable guest `v11` passed 43 distinct cases: all 33
previous helper cases and ten new dual-volume workspace cases. The new driver
used the shared `DetachedWorkspace`, `ReceivedWorkspace` and `AttachedWorkspace`
primitives with two newly formatted private regular images. It rejected both
the same loop and different loops backed by the same image before mounting.

The admitted budget requested 64 MiB scratch, 128 MiB output and 1,024 total
inodes. Deterministic formatting yielded 336 and 672 total inodes respectively
(1,008 together). A dedicated UID/GID-1000 executable rejected swapped root
roles, incorrect authenticated identities and duplicate attachment targets. It
attached both roots in its own user/mount/network/IPC/UTS namespaces, cleared
capabilities, exhausted allocated bytes and inodes in each filesystem, and
confirmed output remained writable after scratch inode exhaustion. It also
demonstrated that a sparse file can exceed the output filesystem's logical byte
length: filesystem capacity alone does not enforce logical output admission.

After the child exited, retaining only a scratch root prevented its final loop
teardown while output completed independently. Dropping that root allowed scratch
teardown. Both images then passed the pinned read-only forced e2fsck. Three final
markers and normal guest poweroff preceded QEMU exit zero. Repeated journal lines
were deduplicated when counting cases. Base, readonly payload and the all-zero
4-GiB plan disk hashes were checked unchanged.

```text
probe sha256    107472aa762bde02f28cee9e7950374064dd7db4127619738490891184f4febb
payload sha256  0e07cf69903d93b30e95f60bd2ecd172c3a1963263ae1a2f29f91f6db280e1d6
Ignition sha256 d87a83f0dcd0d2730d8c79a24c340c637db0e8f10485adb7657aeb7c5a48cea3
serial sha256   356bc652e18a51d5bda9c151193297712b38dfc61ed3133c656193dd56f832f5
```

Probe is `.syrox/qualified-workers/helper-probe-2026-11-02-v11` (3,696,152
bytes), built with development rustc 1.98.1 and the explicit static GNU target;
ELF inspection found no interpreter or needed shared libraries. Source snapshot
is `.syrox/qualified-workers/workspace-sources-2026-11-02-v11`. Payload is
`helper-tools-20261102-v11.ext4`; fresh config/variables/data use the `v11`
suffix under `.syrox/test-tools/qemu/`. Serial evidence is
`.syrox/work-logs/helper-probe-vm-v11.log`; the committed record is
[`system-workspace-vm.json`](../tests/fixtures/system-build/system-workspace-vm.json).
The production helper v2, CLI v3, source-built ext4 tools and engine scratch test
v2 retain their previously qualified pins. QEMU/OVMF used firmware/disk boot,
TCG, one CPU, 2 GiB, disposable OS/data snapshots, no direct `-kernel` boot,
networking, shares or host block devices. KVM remains unavailable.

This qualifies the two-volume primitives. It does not qualify a production
two-volume helper protocol, journal/recovery, full System executor, all runtime
budgets, source bootstrap, provisioning or an SRX-built bootable system.

### Two-volume helper and prepared component

On 2 November 2026, disposable `v14` passed 59 distinct cases: all 43 previous
helper/workspace primitive cases and 16 new production workspace
protocol/component cases. The new helper independently admitted the exact
request under its root-owned maxima, with caller maxima selected separately.
Normal release required both loops gone and both final checks. A second grant
with a distinct operation ID verified reuse of a state containing released
workspace journals. Excessive budgets failed before any operation directory.

The actual engine test ran as UID/GID 1000, explicitly locked its System
declaration and prepared its action/source custody. It requested the two-image
grant using `SystemBuildInputs::prepare_workspace`, exported both ordered roots,
wrote/read/fsynced a proof in each, ran Store GC, revalidated its inputs, read
the output proof again, closed external root copies and released the workspace.
It received a two-image terminal receipt and observed no local build attempt.
Its static ELF parser fixture is never executed as a worker. This qualifies
the prepared-component workspace API, not recipe execution or full budgets.

Disconnect retained both images and left uncertainty. Legacy scratch inspection
refused that workspace journal. Workspace inspection produced a reviewable plan;
an incorrect hash was refused, and the original hash then reconciled exactly
the retained attempt. Both full image digests remained unchanged. A separate
client retained only a scratch root after disconnect: inspection was blocked
and recovery refused. After closing it, a fresh inspection/reconciliation
succeeded. Terminal inspections reported blocked without replaying formatting.

```text
helper sha256  4d7def7357daf815339742f78deeb205ce1009a253e3cb026c08aec8815e7eb1
engine sha256  a78e7f4bd7cd7fdea825a19b9892ebce1a5b4e1e46da0deb72cb4589faa4c341
probe sha256   6ab525868dc0aa2823b781eac4829df02badc9f49810db686254df87118cb558
payload sha256 ec84c82ff0094fe7982e424782c4bc61c56c3b20166ea82a9ed1c35cb0c660f5
serial sha256  2a0d63f36a5956e71f350a30e7ab5740fd85e84a0d1384741eedbff4aa2621c7
component      7952d80f4f239a54e23f4a797eefa2457a190f46adc27856bd0baddafd9bfcaf
```

Frozen executables are `.syrox/qualified-workers/syrox-system-helper-2026-11-02-v3`
(4,047,776 bytes), `system-workspace-tests-2026-11-02-v3` (91,050,536 bytes) and
`helper-probe-2026-11-02-v14` (3,937,256 bytes). They use development rustc 1.98.1,
the explicit static GNU target, and vendored liblzma for engine tests. ELF
inspection found no interpreter or needed shared libraries. The partial source
snapshot is `workspace-rpc-sources-2026-11-02-v14` in the same directory. This is
development qualification, not an authenticated managed-bootstrap attestation.

Payload is `helper-tools-20261102-v14.ext4` (384 MiB); fresh config/variables/data
use the `v14` suffix under `.syrox/test-tools/qemu/`. The serial log is
`.syrox/work-logs/helper-probe-vm-v14.log`; the committed machine-readable record
is [`system-workspace-rpc-vm.json`](../tests/fixtures/system-build/system-workspace-rpc-vm.json).
QEMU/OVMF used two TCG CPUs, 2 GiB, firmware/disk boot, disposable OS/data
snapshots, no `-kernel`, network, shares or host block devices. Five required
final markers, including the engine integration marker, and normal poweroff
preceded QEMU exit zero. Case counting deduplicated journal repetitions. Base,
readonly payload and the all-zero 4-GiB plan disk hashes remained unchanged.
The ext4 tools and frozen CLI v3 retained their prior pins.

Attempts `v12` and `v13` are recorded separately as unqualified. `v12` encountered
guest device-discovery timeouts before the SRX service ran and was interrupted
(session exit 130). `v13` repeated the previous 43 cases, then its test-only
workspace socket under root-owned mode-0711 `/var/tmp/srx-helper-probe` denied
the production client's parent-directory read before connection. It powered off
normally, but the missing workspace/final markers prevented qualification.
`v14` moved endpoints to protected mode-0660 sockets with client group 1000 under
root-owned `/run`; production trust checks were unchanged. KVM, full System
execution, manager/FDSTORE gates, System receipts, provisioning, source bootstrap,
own bootable images and distribution adoption remain outside this evidence.

### Workspace recovery through the real CLI

The `v15` disposable guest repeated all 59 preceding cases and passed five new
CLI cases (64 distinct cases total). As UID/GID 1000, the real CLI selected
`--workspace-operation`, inspected an abandoned pair, refused an incorrect hash,
reconciled the exact reviewed plan and then reported the terminal operation as
blocked. Both full image hashes remained unchanged. The rejected request wrote
no journal entry: the originally inspected hash remained valid for the following
successful reconciliation. Filesystem health remained explicitly unverified.
Legacy `--scratch-operation` CLI cases and the prepared-component/GC test also
passed. Five final markers and normal guest poweroff preceded QEMU exit zero.

```text
CLI sha256     011543d12c43d65b5a6af61ca3d0b655cc90f0b42560f7b0045d87375524ca88
probe sha256   6b65c6ef0bc9321015ffd09aca2a4043996818926128fa09115a2e6a099c0523
payload sha256 cc728f3febbf6fed263365ea342063b9d352d8d2b57e723501f375a1c4e367fc
serial sha256  987dbcea4d39148ad7fb938484dd91dab8eccfbc92f0c3a68baada5c869548e0
```

CLI is `.syrox/qualified-workers/srx-system-workspace-recover-2026-11-02-v4`
(71,154,064 bytes), built with development rustc 1.98.1, the explicit static GNU
target and vendored liblzma. Probe is `helper-probe-2026-11-02-v15` (3,947,208
bytes). Payload is `helper-tools-20261102-v15.ext4`; fresh config/variables/data
use `v15` under `.syrox/test-tools/qemu/`. Serial evidence is
`.syrox/work-logs/helper-probe-vm-v15.log`; the committed record is
[`system-workspace-cli-vm.json`](../tests/fixtures/system-build/system-workspace-cli-vm.json).
The helper v3 and engine test v3 retain their `v14` pins. Base, readonly payload
and the all-zero 4-GiB plan disk were verified unchanged. QEMU/OVMF used two TCG
CPUs, 2 GiB, firmware/disk boot and disposable snapshots without `-kernel`,
network, shares or host block devices. This qualifies workspace recovery CLI,
not generation recovery, recipe execution, provisioning or own-system boot.

### System source archives

On 2 November 2026, the frozen native engine test executable passed 26 archive
cases (including legacy parser/extraction regressions), two prepared-source
inspection cases, and the explicit child entry used by the large-source test.
One private child entry remains ignored in the parent by default. The child
inspected and extracted a synthetic gzip tar containing a regular file of
1,073,741,841 bytes under `RLIMIT_AS=268435456`, verified the output length and
its final 17 bytes, and exited zero. No entire expanded file/image is held in
userspace memory. This limits address space, not filesystem page cache or a full
worker cgroup. The destination is a fresh native temporary directory; no helper,
namespace, declared recipe or System executor runs in this qualification.

A separate metadata case accepted 65,537 entries under System admission and
refused the same archive under legacy large limits. Both gzip and XZ paths
exercised supported direct aliases, entry/byte limits, readonly sources,
cancellation, existing-file collision and preserved outside symlink targets.
Hardlinks and escape aliases stayed refused. A descriptor initially at EOF was
read from offset zero without moving its shared cursor; later transport growth
was refused even at EOF. Actual prepared component inspection explicitly locked
its declaration, verified the source/action budget and refused a modified source
without creating a build attempt or contacting the helper.

Frozen executable is
`.syrox/qualified-workers/system-source-archive-tests-2026-11-02-v1`
(90,050,888 bytes), SHA-256
`bebaeaeb2186a0aa545489e5c8b91074cf8aed117572cf02545c86aee24d4dce`.
It uses development rustc 1.98.1 and the host's dynamic loader/libraries, not the
managed bootstrap. The partial source snapshot is
`system-source-archive-sources-2026-11-02-v1` in that directory. Evidence log
`.syrox/work-logs/native-system-source-archive-v1.log` has SHA-256
`ffe64c8abe42a9dd94bffa54f73ab3b502b9a6d543ccc777e3834bf5bbbac160`.
The committed scope/limits record is
[`native-system-source-archive.json`](../tests/fixtures/system-build/native-system-source-archive.json).
All-feature and no-default-feature workspace Clippy plus rustdoc passed with
warnings denied. System worker integration, all runtime budgets, receipts,
own bootstrap, kernel/userspace builds and system boot remain pending.

### Prepared System component and private scratch

On 23 October 2026, the `v10` disposable guest passed 33 distinct cases. It
repeated the 32 previous helper/recovery/read-only-plan cases and ran the actual
engine's ignored System-scratch integration test as UID/GID 1000. The test
explicitly locked its declaration, prepared the component/action with real
source custody, requested the exact admitted budget through the production
helper client, wrote/read/fsynced a proof through the received root descriptor,
ran Store GC while retaining the source, closed the root and explicitly released
the grant. The root driver observed the released journal, retained image, no
uncertain record and loop teardown. No local build attempt/receipt was created.

```text
engine tests sha256 e06da68940ea4146810ec09108e371d4af92d0e399c0742fa9783a99fe34322f
probe sha256        ab9fe03588fb66b0a38202c89746a68a831bf8ce31d32fa14dda6bd8fbb6b72f
payload sha256      f2b4e1d072310ecf2e530c8cf76940de9fc9be3967256eff116b340e3bffb9fa
Ignition sha256     c13d91f482185ffd71b6c50180c44c89bca7b884552d5ce27105f7ec6d8bd056
serial sha256       a389be6e767e6e3b591b687b689239351d56d77efef96cb9c0a60bbabaa91bc9
component action    e81ec8e2da0f996f25a006025ddd307b438a7af933debe40ec0c474b6c66fb93
```

The engine test executable is frozen at
`.syrox/qualified-workers/system-scratch-tests-2026-10-23-v2` (90,010,704 bytes).
It was built with the development host toolchain, explicit static GNU target and
vendored-liblzma settings. ELF inspection found no interpreter or needed shared
libraries. The driver is `helper-probe-2026-10-23-v10`; payload is the new
384-MiB `helper-tools-20261023-v10.ext4`. Config/variables/data use the `v10`
suffix under `.syrox/test-tools/qemu/`; serial log is
`.syrox/work-logs/helper-probe-vm-v10.log`. Existing helper v2, source-built ext4
tools and frozen CLI v3 pins remain. The base OS and readonly payload hashes
were checked unchanged; the new 4-GiB all-zero virtual data disk also remained
unchanged. QEMU/OVMF boot used one TCG CPU, 2 GiB, a firmware/disk chain and
disposable snapshots, with no `-kernel`, networking, shares or host block device.
All final markers and normal poweroff preceded QEMU exit zero.

The preceding `v9` attempt is recorded separately as unqualified. Its non-root
test tried to read the root-owned mode-0600 VM marker and failed before component
preparation/helper contact. The corrected test checks its root-owned metadata;
the root driver still verifies the marker's content and QEMU identity. Its mode
was preserved. The successful engine case uses a static ELF format fixture that
is never run as a worker. This qualifies prepared-component scratch binding and
custody, not System recipe execution, all runtime budget dimensions, build
receipts, reset recovery, own kernel/boot, provisioning or adoption.

### Read-only system plans and virtio disk identity

The `v8` disposable guest passed 32 distinct cases on 22 October 2026. It repeats
the previous 29 with a new pinned CLI and adds actual HostConfiguration sysctl
comparison, a successful System disk binding and refusal of a read-only disk.
No system was built or provisioned by these declaration/observation tests.

```text
helper sha256    cbad2c343cf836adb950423dc933ad798ae32283ca2d93992ee19568312df56f
CLI sha256       219e77561642ae44a309e429cecd26f7c72c198bc65155e7dc147e72f2b05154
probe sha256     646d61045399b3f5f36880dcb426f1b582c8f41f4e9ed943fb390988619d81b9
payload sha256   9eeeda2a440cd67c99152336e82c5a3d130658ce54ee17513b7ab7a3a5b808a6
data sha256      8479e43911dc45e89f934fe48d01297e16f51d17aa561d4d1c216b1ae0fcddca
Ignition sha256  c2e88a85b684f03802a6f7015e2a454200d0a881533f925c84ecb215a0f1db55
serial sha256    a6bab5d5ea29639814757988d09fcff2a18fcab1de585df26c1c9f62e930c6c2
```

The frozen CLI is `.syrox/qualified-workers/srx-system-plan-2026-10-22-v3`
(70,997,080 bytes), with the same explicit static GNU/vendored-liblzma fixture
build settings as the prior CLI. ELF inspection again found no interpreter or
needed shared libraries. Probe is `helper-probe-2026-10-22-v8` in that directory.
Payload/config/variables use `helper-tools-20261022-v8.ext4`, `helper-probe-v8.ign`
and `helper-probe-v8-vars.fd` under `.syrox/test-tools/qemu/`; the serial log is
`.syrox/work-logs/helper-probe-vm-v8.log`. Helper v2 and e2fsprogs pins remain.

QEMU additionally received the NEW private sparse regular image
`helper-plan-data-v8.raw`, 4 GiB, mode 0600, all zero bytes, through a disposable
snapshot and virtio serial `srx-plan-disk`. The tools disk remained read-only
with serial `srx-probe-tools`. QEMU/OVMF, signed base OS, firmware/disk boot, one
TCG CPU, 2 GiB and absence of networking/host shares/host block devices are
unchanged. The fixture does not format or mount the new data disk.

The real CLI ran as UID/GID 1000 with no supplementary groups. Fixture setup
created its own project and explicitly locked each changed declaration. Planning
then preserved exact source/lock bytes and left only those two project files.
The HostConfiguration report compared a real sysctl and recorded seven pinned
namespace identities. The System report resolved exactly the selected virtual
disk by serial and 4-GiB capacity, returning seven validated storage nodes with
unverified metadata/exclusive use. Selecting the read-only tools disk instead
returned an unresolved binding with the read-only reason. Both reports retained
`can_apply: false`, the destructive provisioning classification and separate
generation boot requirements. The kernel parameter's bytes were unchanged.

All 32 unique case markers, `SRX_HELPER_PLAN_CLI_READ_ONLY_OK`, the prior typed
client/activation/recovery markers and final `SRX_HELPER_PROBE_OK` preceded normal
poweroff and QEMU exit zero. Payload, data backing file and base OS digests were
rechecked unchanged. Snapshots protect those backing inputs; their unchanged
hashes alone are not proof about writes inside a guest overlay. This evidence
qualifies the read-only observation path, not provisioning or data migration.

An earlier `v7` attempt is explicitly unqualified. Its previous 29 helper cases
and HostConfiguration comparison passed, but the expected writable disk binding
was unresolved, causing probe exit 101. The shutdown unit still powered off and
QEMU exited zero; QEMU exit alone is therefore insufficient evidence of success.
That probe omitted the binding reason from the assertion. Inspection identified
that the reader checked `device/serial` only; the upstream virtio-blk driver
exposes `serial` on the disk. The reader now handles both, refuses conflicting
values and revalidates serial before reporting. Twelve local inventory tests and
the fresh `v8` successful binding passed. Future failed assertions include the
complete storage diagnostic.

The failed attempt retains separate CLI/probe/payload pins:

```text
v7 CLI sha256      fa45ccef9d22e7f60555a285fd96df9a3648fa645ee3030a3dbf180e27682c91
v7 probe sha256    c54465337b4691ab4fc66e0aaa254edc9793bfc0964320451f14784063b2515d
v7 payload sha256  575a6098613aa71488524d8ead5696a074aca31b4849eeffdbe489c2066b97d1
v7 serial sha256   42cf8dafb7722c06f5ff55e7f6c6c879ade3e6e2d34a47b1875b8b4a2bf76ab5
```

Its `v7` inputs/log were preserved and recorded in `unqualified_attempts`, never
added to `qualified_cases`. This does not establish adoption ownership, parameter
restoration, a complete application plan or support for physical hardware.

### Native managed-source streaming regression

On 22 October 2026 the streamed source preparation path passed 100 managed tests
(three environment-dependent cases ignored) and a new actual Managed/Standard
build followed by execution. The [evidence record](../tests/fixtures/system-build/native-source-streaming.json)
contains the exact pins, source size/limit, old worker compatibility, binutils
provenance and new action/artifact/receipt. This is a native regression, separate
from the disposable-VM cases and complete-system qualification.

The coordinator `.syrox/qualified-workers/srx-managed-source-streaming-2026-10-22-v1`
was built with the development host toolchain (SHA-256
`e25f9a6e0b3a22ebe2e722896293ae59baa1f2618cedad729edc378a06a99ce3`,
69,642,192 bytes). It uses the host's dynamic loader. Its existing sibling host
worker and the explicitly configured static Managed worker retain their earlier
pins. The new private project `../.syrox-source-streaming-probe-v1` is a sibling
of the catalog, using the supported single-parent `path:../syrox-pkgs` locator;
no loader traversal rule was relaxed. It was checked and explicitly locked.

The build used `.syrox/managed-bootstrap.toml`, the existing absolute bootstrap
Store and `--offline`, with the pinned binutils output as its sole build input.
The 445-byte Raw source has a 4096-byte declared ceiling; multi-chunk/short-read
and cancellation behavior is covered separately by the native tests. The recipe
invoked the declared static assembler/linker, ran the result inside its build
namespace and copied source bytes into the output. The new action is
`dc84238853ea4a6ef3543c61abcbe78e9d9bb3e65300192cc9b1ecfc7369c26b`, artifact
`1697958c7ecf2c17c17d80623f66e42cd2ba5ed1da9c63eb51cd72ba5f4587eb`, receipt
`28b648b05e209ee11ea306563a1372652bf3c1ff777bd21ceed08f5ca5aa842c`.
It contains two files and records `toolchain none` for this consumer.

The materialized executable has SHA-256
`933681a28b5e1617aa7166c9a5ffa12edeadf417b0ae3639338866377aa3b4e3`;
ELF inspection found no interpreter/dynamic section, writable executable load
segment or executable stack. The copied source retained its original SHA-256.
A separate offline runtime invocation exited zero and printed the expected
one-line marker. Logs are `.syrox/work-logs/source-streaming-probe-build.log`
and `source-streaming-probe-runtime.log`.

The managed tests initially encountered seven Unix socket EPERM failures in the
sandbox; rerunning that exact suite outside it as the ordinary non-root user
passed. Actual build/runtime also ran without root using the user manager and
Linux namespaces outside that restriction. No physical disk, boot, system unit
or host sysctl was modified. This preserves existing common profile limits;
System-worker budgets, source-bootstrap toolchain and full-system execution
remain pending.
