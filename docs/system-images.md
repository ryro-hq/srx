# System tree, initramfs and verity construction

The shared [`syrox-system::image`](../crates/syrox-system/src/image/mod.rs)
library composes explicit component manifests and writes deterministic,
uncompressed Linux initramfs archives. The
[`engine image builder`](../crates/syrox-engine/src/image.rs) connects that
writer to authenticated package outputs and the chunked Store. These are library
operations. `System` and `HostConfiguration` declarations have pure project
plans; connecting those declarations to this image writer, the system build CLI
and bootable images remain work in the
[system roadmap](design/linux-system-management.md).

## Composition

Each input component is identified by its authenticated artifact SHA-256. Its
entries declare absolute destination paths, numeric ownership and permissions.
Regular files also identify their component-relative source, content SHA-256 and
length. Links carry their target text and ownership; directories are explicit,
including empty directories and `/`.

Composition checks producer identities, canonical paths, parent directories,
ownership, permissions, file counts and output byte budgets. Equal directories
can merge only when their complete metadata agrees. Every file and link has one
producer; equal contents do not silently resolve a collision. A directory cannot
be replaced with a link or file while it has descendants.

Link checking follows declared prefixes before processing `..`, bounds expansion
and link hops, and rejects escape, cycles and traversal through a declared file.
Dangling or runtime-provided targets may remain: their existence is never inferred
from the host filesystem. Image extraction must separately use a confined writer;
the validated link text is not permission to follow links on the host.

Trees retain each entry's origins in deterministic order. Their canonical format
is ASCII `syrox-system-tree` plus LF followed by compact UTF-8 JSON, with no
trailing LF. Field order is `entries`, `content_bytes`; entries are
ordered by path and origin sets are ordered. SHA-256 of these exact bytes is the
tree identity. Administrator policy ceilings do not affect that identity. Parsing
reconstructs and revalidates the composition and requires byte-for-byte canonical
encoding. It does not expose unchecked tree deserialization.

The format bounds components and input entry declarations to one million, paths
to 4096 bytes and encoded metadata to 64 MiB. Shared directories still consume
declaration and metadata work. The admitted file budget counts unique entries;
regular payload sizes consume the composition's output budget.

## Initramfs writer

`SystemTree::write_initramfs` emits the upstream
[`newc` wire format](https://docs.kernel.org/driver-api/early-userspace/buffer-format.html).
It preserves numeric owners, permissions, links and empty directories. Entry
order and inode numbers are deterministic, timestamps and device numbers are
zero, and the archive ends with a trailer and zero padding to 512 bytes. A real
top-level entry named `TRAILER!!!` is escaped as `./TRAILER!!!` so it cannot end
the archive prematurely. Special device nodes and hard links are not supported.

Preflight rejects oversized names, payloads above the format's per-file
4,294,967,295-byte cap and budgets that cannot fit the complete archive before
opening files or writing output. The archive budget includes headers, names,
links and padding. Each regular source is streamed in requests of at most 64 KiB
and checked for its complete SHA-256, exact size and EOF. Successful output
returns the archive's size and SHA-256 and the tree identity.

A destination may contain a prefix after cancellation, corruption or I/O failure.
Callers must stage it and publish only after success. Cooperative cancellation
does not interrupt a blocked reader or writer; those implementations must bound
their I/O. The writer never invokes a utility, opens a device or installs files.

## Engine and Store

`image::build_initramfs` accepts live `MaterializedArtifact` handles, a validated
tree and an admitted budget. All tree
origins must be selected artifacts from the same Store. Package sources are read
from verified CAS inodes with the existing bounded artifact index. The builder
does not consume the physical materialized view, search the host or execute
component contents. Current package input artifact limits still apply.

The archive streams directly into bounded chunked staging, without a complete
temporary image file or rereading an image from disk. Complete chunks can enter
CAS during writing; the chunk manifest is published only after all source hashes
and the complete archive hash pass. A failed image leaves no new image or chunk
manifest, and unretained partial chunks remain collectible by GC. The tree and
image provenance manifest are admitted after successful writing.
The provenance records archive format, length and content/container pins, tree
pins, and each component's action, output and built/imported origin. Imported
outputs retain their imported manifest identity; no local build receipt is
invented. Metadata is bounded to 64 MiB per manifest.

`BuiltInitramfs` retains the complete image and source closures. Its
`publish_root` publishes their union under the existing immutable root protocol,
including the chunks, chunk manifest, tree, image manifest and each component's
retained references. The union must fit the Store's 65,536-reference root limit.
The archive handle's own `publish_root` retains only the chunked archive; use the
image handle when retaining provenance. Root publication is separate from image
construction and grants no installation authority.

This path has tests for corruption, source selection, cancellation, reproducible
encoding, limits, metadata and GC retention. A generated archive was also read
with GNU cpio and bsdtar. That establishes archive interoperability only. No
kernel, init program, UKI, firmware boot or operating-system qualification is
implied. Executor enforcement of complete system build budgets, large package
worker/receipt integration, rootfs/disk writers and boot remain pending.

System consumption results can now provide chunked package components through
the same `MaterializedArtifact` interface. The image builder opens their verified
logical stream and retains the embedded result/chunk closure. This removes the
legacy blob cap from this consumption path; system workers, source budgets and
receipts remain pending as described in [artifacts](artifacts.md#budgeted-system-outputs-and-bundles).

## dm-verity hash devices

[`syrox-system::verity`](../crates/syrox-system/src/verity.rs) implements
[dm-verity format 1](https://docs.kernel.org/admin-guide/device-mapper/verity.html)
with SHA-256, 4096-byte data/hash blocks, an explicit 32-byte salt, no superblock
and hash offset zero. It hashes salt before each block, zero-fills unused digest
slots and serializes levels from the root toward the data. One data block has
only a root digest and an empty hash device. Data must be nonempty and exactly
block aligned; there is no silent truncation or padding of data.

`Geometry` computes level sizes with checked arithmetic. `write_level` streams
one level using two 4 KiB buffers and verifies the input's declared length,
ordinary SHA-256 and EOF before success. It can leave a partial output after an
error; callers must stage publication. The writer performs no host lookup or
privileged operation. The parameter semantics and root-first layout follow the
[kernel format contract](https://docs.kernel.org/admin-guide/device-mapper/verity.html#on-disk-format).

`image::build_verity` consumes a `RetainedChunkedArtifact` from the same Store
and an admitted budget. Each intermediate level is staged in authenticated CAS
chunks. It then streams those levels in reverse order to form the final hash
device. It never holds the complete data or hash device in memory, invokes a
host utility, creates a local image file or activates device-mapper.

Preflight requires the combined data/hash length within output bytes, the sum of
intermediate logical level lengths within scratch bytes, at least 32 MiB for CAS
transport/metadata, and a conservative union within the 65,536-reference root
limit. CAS framing/metadata retains its existing Store bounds. Cancellation and
elapsed duration are checked between bounded I/O calls. These library checks
do not establish a process resource envelope; the system executor must still
enforce memory, CPU, process and descriptor limits and bound blocked kernel I/O.

The parameter manifest is `syrox-verity-image` plus LF, compact JSON and a
final LF. Field order is `algorithm`, `data_block_bytes`,
`hash_block_bytes`, `hash_start_block`, `superblock`,
`data_manifest_sha256`, `data_sha256`, `data_bytes`,
`hash_manifest_sha256`, `hash_sha256`, `hash_bytes`, `root_hash`, `salt`.
The version is 1; the algorithm is `sha256`; both block sizes are 4096;
`hash_start_block` is 0 and `superblock` is false. All pins, the root hash and
salt are lowercase 64-digit hexadecimal strings. Salt and data determine the
bytes and identities; administrator ceilings are not part of those identities.

`BuiltVerity::publish_root` retains the parameter manifest and both complete
chunked streams. Intermediate level objects become collectible after their
handles are dropped. The caller must independently retain the original image's
tree, receipts and producer provenance as part of its generation; this operation
does not invent that evidence from a raw input stream. A root hash is useful for
boot only after it is bound to a trusted, authorized generation.

Tests compare the full hash device and root with an explicitly pinned upstream
`veritysetup` binary across 1, 2, 127, 128, 129, 16,384 and 16,385 data blocks.
The reference performs userspace verification on disposable regular images;
it creates no kernel mapping. A fixed two-level upstream vector also runs in
ordinary unit tests. This establishes format interoperability, not in-kernel
enforcement, ext4 rootfs composition, a signed UKI or verified firmware boot.

## GPT RAW disk images

[`syrox-system::disk`](../crates/syrox-system/src/disk/mod.rs) writes complete
RAW disks according to [UEFI GPT 1.0](https://uefi.org/specs/UEFI/2.10/05_GUID_Partition_Table_Format.html).
The disk uses explicit 512- or 4096-byte logical sectors, a protective MBR,
128 entries of 128 bytes, primary/backup headers and tables with CRC32, explicit
disk/partition GUIDs and zero-filled gaps and partition tails. GUID request
bytes use canonical UUID order; the writer emits GPT's mixed-endian fields.
Names contain at most 35 UTF-16 code units plus an explicit terminator; reserved
attribute bits remain zero. Identity generation belongs to the caller and must
distinguish installations and copies as required by the UEFI specification.

`DiskSpec::validate` rejects unsupported sector sizes, incomplete sectors,
insufficient metadata space, missing/duplicate/zero identities, invalid entry
numbers/names/attributes, misalignment, overlap, overflow and oversized payloads.
It creates a private `DiskLayout`, with entry numbers independent of physical
ordering. There is no unchecked layout deserialization.

`DiskLayout::write_raw` resolves partition streams by entry number and checks
each exact payload size, full SHA-256 and EOF. It preflights complete output
bytes, logical source/output file count and a 128 KiB writer memory minimum.
It checks cancellation/deadline between I/O calls and streams in requests no
larger than 64 KiB, without seeking, discovering host files or invoking tools.
Transports must bound blocked I/O. Errors may leave a prefix; callers must stage
publication. These library limits do not establish a process resource envelope.

`image::build_raw` binds each partition to a `RetainedChunkedArtifact` from the
same Store. Missing, repeated, foreign or inconsistent bindings fail before
staging. It requires at least 32 MiB for bounded CAS transport/metadata and a
conservative complete root-reference bound. The disk streams directly into
chunked staging. Only complete successful construction produces its chunk
manifest and `syrox-raw-image` provenance manifest.

The provenance format is the domain plus LF, compact JSON and a final LF. Field
order is `format`, `specification`, `image_sha256`,
`image_manifest_sha256`, `image_bytes`, `partitions`. Version is 1 and format is
`gpt`. The specification uses the public `DiskSpec` field order, partitions by
entry number, and fixed GUID/hash byte arrays; input records contain `number`,
`chunk_manifest_sha256`, `content_sha256`, `bytes`. Image/input pins are lowercase
SHA-256 hex strings. `BuiltRaw::publish_root` retains this manifest, the complete
RAW stream and all partition input closures. Source build/tree provenance and
generation signatures must be retained separately by their generation.

Tests cover invalid layouts, metadata integrity, deterministic bytes, exact
source identity/EOF, cancellation, Store corruption, input selection and GC.
An explicitly pinned util-linux `sfdisk` read disposable regular images with
both sector sizes and recovered their backup tables after deliberate primary
header corruption. Its reads do not install or repair anything. The test
payloads are opaque data: this establishes GPT interoperability, not valid
filesystems, an ESP, rootfs, Secure Boot, UKI or firmware boot. CLI wiring,
filesystem population and installation/rescue ISO construction remain
pending.

## Standalone qcow2

[`syrox-system::qcow2`](../crates/syrox-system/src/qcow2/mod.rs) emits
[qcow2 v3](https://www.qemu.org/docs/master/interop/qcow2.html) with 64 KiB
clusters and 16-bit refcounts. It fully allocates guest clusters, including
zero data, and zero-pads the final partial cluster. Backing files, external data,
encryption, compression, internal snapshots and lazy refcounts are absent.
Consequently the image has no host pathname dependency.

`Geometry::new` accepts a nonempty whole number of 512-byte sectors. It solves
refcount metadata sizes including their own allocations, checks arithmetic and
offset ranges, and respects QEMU's 32 MiB L1 / 8 MiB refcount-table limits. Its
fields are private; unchecked deserialization cannot create geometry. The writer
streams tables and payload using one 64 KiB buffer, without seeking or invoking
tools. It checks exact RAW size, SHA-256 and EOF, complete encoded output bytes,
writer memory/file bounds, cancellation and duration. Transport/process limits
have the same separate responsibilities described for RAW construction.

`image::build_qcow2` takes an engine-built `BuiltRaw` from the same Store and
streams it to chunked staging under an admitted budget. It checks encoded output,
artifact/root-reference limits and at least 32 MiB for bounded CAS transport.
Only successful writing admits the qcow2 chunk manifest and provenance metadata.
`BuiltQcow2::publish_root` retains the complete supplied RAW/GPT closure, including
its provenance manifest and partition streams, plus the qcow2 stream and metadata.
Unknown source build/tree/signature evidence is never invented.

The metadata domain is `syrox-qcow2-image` plus LF, compact JSON and a final LF.
Field order is `format`, `qcow2_version`, `cluster_bytes`,
`refcount_bits`, `raw_provenance_sha256`, `raw_manifest_sha256`, `raw_sha256`,
`virtual_bytes`, `image_manifest_sha256`, `image_sha256`, `image_bytes`.
Values are 1, `qcow2`, 3, 65536 and 16 for the first five fields; pins use
lowercase SHA-256 hexadecimal. The complete encoded stream, including metadata
and padding, consumes output bytes. Administrator ceilings do not enter identity.

Tests cover metadata/self-refcount geometry, cluster mapping, deterministic
encoding, padding, source integrity/EOF, cancellation, budget rejection, CAS
corruption and retention through GC. An explicitly selected `qemu-img` checks
refcounts and decodes images back to RAW for complete size/SHA comparison; it
also verifies that checking/conversion leave the original qcow2 unchanged.
The [reference-tool fixture](test-tools.md) records authentication and its host
library dependency. This establishes format interoperability, not boot, an
independent userspace/kernel or a qualified VM system. A VM must use its own
writable copy/overlay; immutable Store objects are not guest writable disks.
