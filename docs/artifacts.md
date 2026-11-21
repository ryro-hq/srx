# Authorized local artifacts

An artifact descriptor lets `srx build`, `run`, `shell`, and service preparation use
already qualified package bundles. The same resolver handles package outputs,
commands, service validators, and runtime libraries. Recipes continue to describe
how to build the package; the user's configuration chooses how to obtain it.

## Authorize a release

Keep the catalog checkout and its `Catalog.lock` and `Syrox.lock` from the release.
Put the release's `<identity>.bundle` files in one local directory, then run:

```sh
srx catalog authorize-artifacts ./syrox-pkgs \
  --release ./release/manifest.json \
  --evidence ./release \
  --output ./release/artifacts.json
```

The command verifies the inventory, exact source and standard-library pins,
toolchain declarations, successful qualification records, bundle digests,
manifests, and the selected command's complete runtime closure. It evaluates the
registered factory with the exact version, variant, and target; a historical
public alias does not replace that selection. It does not download sources or
execute a build. The current authorizer accepts catalogs with local module
inputs and writes a new descriptor beside their bundles.

Review the release provenance and the generated descriptor before trusting it.
The printed SHA-256 pins the complete descriptor in the consumer's user config:

```toml
[artifacts]
policy = "require"
descriptor = "/absolute/path/release/artifacts.json"
descriptor-sha256 = "<printed SHA-256>"
```

This is an explicit local trust decision. The descriptor is not a signature or a
remote publisher identity. Changing a release index cannot change this pinned
selection; adopting a new release requires a new descriptor and an explicit pin
update. Keep the descriptor and bundles with the release for offline use.

## Choose a policy

| Policy | Behavior |
| --- | --- |
| `compile` | Default. Use the existing build and action-cache path. |
| `prefer` | Import an exact authorized artifact when available; compile if no matching authorization or bundle exists. |
| `require` | Require a matching authorized artifact in the Store or local bundle directory; fail on a miss. |

Both importing policies require an absolute descriptor path and its SHA-256.
Malformed descriptors, changed pins, corrupt bundles or Store objects, conflicting
runtime outputs, and invalid manifests are errors under both policies. They never
trigger a fallback build. `--offline` permits local bundle imports and verified
Store reuse; it does not grant source downloads when `prefer` falls back.

## Select packages normally

This example assumes a locked [`srx-pkgs`](https://github.com/ryro-hq/srx-pkgs)
checkout beside your project, as in the [quickstart](../README.md#check-lock-and-plan-a-project).
Use the catalog snapshot that matches your authorized artifact descriptor.

```srx
inputs { pkgs = "path:../srx-pkgs"; }

let packages = pkgs.forPlatform { system = "linux-x86_64"; };
pub let hello = package_recipe(packages.hello { version = "2.12.1"; });
```

```sh
srx project lock .
srx build .#hello --config ./config.toml --offline
srx run .#hello --command hello --config ./config.toml --offline -- --version
```

`build --dry-run` previews the authorization without opening the Store or bundle.
Availability is checked when realizing the result. Imported build output prints
the manifest and artifact pins, and retains `Imported` provenance. It does not
invent a local build receipt. Once admitted, the pinned runtime closure can be
reused from the Store even when its transport bundle is absent.

The descriptor binds each selection to the authenticated catalog source snapshot,
std, locked recipe and contract inputs, normalized target, exact program and
dependency graph. A local recipe with the same package name or ID does not match.
Aliases of a catalog reference preserve its origin. Rebuilding a reference in a
consumer wrapper changes its origin and requires its own authorization.
Edits to unrelated consumer settings can retain the selected catalog artifact;
changing recipe bytes, ABI, version, build inputs, or std invalidates the match.

Libraries and the loader come from the qualified closure. When multiple selected
packages share an output, their authorizations must agree on its action and
artifact identity. GNU and musl remain separate selections. A bundle only carries
the outputs in its manifest: requesting an additional development output may
require a separate artifact or a build.

Runtime support remains the scope established by the release's qualification.
Importing a bundle does not establish support for another architecture, kernel,
distribution, or service manager. Remote transport, publisher signatures, and
automatic release discovery are separate future extensions.

## Large streams in the engine Store

The engine also provides a tagged container for large byte streams in
[`store::chunked`](../crates/syrox-engine/src/store/chunked.rs). This is a
foundation for system images. Ordinary package outputs, release bundles, build
protocols and recipe limits continue to use their current formats and budgets.
The artifact authorizer above does not yet consume this container; the explicit
system result/bundle APIs are described below.

`OperationLease::ingest_chunked` takes a reader, the expected SHA-256 of the
complete logical content, a byte budget and a cancellation token. It reads at
most 64 KiB per source call, forms 4 MiB chunks and publishes each under its own
SHA-256. The final chunk may be shorter. EOF, the byte budget and the complete
content hash must all pass before the manifest is published. Read boundaries and
transient `Interrupted` errors do not affect the resulting identities. Empty
streams have a manifest and no chunks.

The manifest has this canonical binary representation:

| Field, in order | Encoding |
|---|---|
| Format header | ASCII `syrox-chunked-artifact` followed by LF |
| Chunk size | Unsigned 32-bit little endian; exactly 4,194,304 |
| Logical length | Unsigned 64-bit little endian |
| Complete content digest | 32 raw SHA-256 bytes |
| Chunk count | Unsigned 32-bit little endian |
| Ordered chunk digests | 32 raw SHA-256 bytes per chunk, including repetitions |

Unknown headers, inconsistent lengths/counts, trailing bytes and oversized
manifests are rejected. The SHA-256 of these canonical bytes identifies the
container separately from the logical content digest. The format has a fixed
identity fixture; changing its encoding requires a new format tag.

The cap is 65,535 chunks, or 256 GiB minus 4 MiB of logical content. The manifest
is at most 2,097,194 bytes. These are storage format limits; callers must still
supply their own admitted byte budgets. A budget above the hard cap fails before
reading the source. An oversized stream consumes at most one byte beyond its
budget before failing. The individual Store blob cap stays at 1 GiB.

For push-based producers, `OperationLease::begin_chunked` returns bounded
`ChunkedStaging` with `append` and a `Write` implementation. Producer write
boundaries do not affect chunks or identities. It buffers one 4 MiB chunk and
checks cancellation at intervals of at most 64 KiB. `finish(expected_content_pin)`
verifies the complete logical hash before publishing the manifest and handing
off live retention. An append/flush failure permanently poisons staging;
subsequent finish cannot admit a silently shortened stream. Dropping staging or
failing its hash check leaves only unretained verified chunks for GC. `flush`
checks cancellation and writer state; only finish commits the logical artifact.

`RetainedChunkedArtifact::open_reader` provides a seekable view for artifact
indexes and bounded file ranges. It caches at most one verified 4 MiB chunk,
returns reads of at most 64 KiB and rechecks each uncached chunk's hash/length.
Start/current/end seeks may pass EOF, while negative or overflowing positions are
errors. Seeking and reading both observe cancellation. The reader shares granular
retention and holds global Store barriers only during chunk access, so GC can
run while the handle remains live. It does not add a new package artifact format
or change existing worker limits.

`OperationLease::open_chunked` takes the manifest pin and an admitted logical
byte budget. Only a missing manifest returns `None`. It verifies the manifest,
all referenced chunk hashes, exact chunk lengths, order and the complete content
hash before returning a `RetainedChunkedArtifact`. Missing or damaged chunks are
errors. Both admission and reopening retain the complete object set in an
`ObjectLease`; cloning the artifact shares that interest.

For a worker without Store path access, `prepare_descriptors` preflights an
explicit remaining FD-slot budget and returns `ChunkedDescriptorSet`: manifest
first, then one readonly CAS descriptor for each unique chunk digest in ascending
order. Repeated logical chunks share descriptors. The set holds the original
granular artifact interest and opens each object under a short Store barrier;
it publishes no root or result and defines no new manifest format.

`ChunkedDescriptorReader::from_received` accepts the independently selected
manifest pin, byte/slot limits and owned descriptors. It checks the complete
role count, readonly regular-file ownership/mode/link count, stable identity,
size and modification/change timestamps. It verifies the manifest, each chunk's
exact size/hash and the full logical content digest before returning. Positioned
reads ignore shared FD seek offsets. Reading uses one 4-MiB cache and 64-KiB
steps, with interrupted reads retried and cancellation observed. Seeks within
the same chunk reuse the cache; metadata/custody are still rechecked before
cached reads, and EOF checks all chunk roles. No pathname or Store lookup is
used by the receiver.

The reader owns descriptors, not an independent Store interest. Keep sender
custody until the authenticated handoff establishes receiver retention. Open
inodes or cached bytes do not replace that protocol; losing the interest and
letting GC unlink roles invalidates subsequent reads. These APIs establish
content evidence only, without peer authentication, namespace isolation,
worker execution authorization or settlement.

Use `RetainedChunkedArtifact::publish_root` for durable retention. It expands the
manifest and all unique chunk digests into a canonical Store root, verifies and
synchronizes them, then uses the existing immutable root publication protocol.
GC reads that complete set directly, preserving shared chunks until their last
root or live interest ends. No root schema or artifact identities are rewritten.
Retaining a manifest digest through the generic blob API alone does not retain
its chunks: that API intentionally treats blob contents as opaque.

`RetainedChunkedArtifact::copy_to` reconstructs the logical stream while checking
each chunk before emitting it and rechecking the complete content digest. Its
memory use is bounded by chunk and manifest sizes. The live object interest
protects every chunk while short operation barriers protect verified reads;
destination writes do not exclude GC. A slow transport must bound its own blocked
I/O calls, since cancellation is cooperative.

Copy errors can leave a verified prefix at the destination. A consumer that
publishes files or installs an image must stage the destination and commit only
after success. Failed or cancelled admission can leave verified unretained
chunks; normal GC collects them, while interrupted staging files use normal Store
recovery. Root publication keeps the existing conflict and uncertain-durability
errors. None of these storage APIs grants execution or installation authority.

The [system image builder](system-images.md) now composes explicit trees and
constructs initramfs from authenticated outputs using this container. Complete
system budget enforcement, worker integration and the system build CLI remain work in the [Linux system roadmap](design/linux-system-management.md).

## Budgeted system outputs and bundles

The engine's system result path now consumes large package outputs, in addition
to image archives. `result::ingest_system_output` takes a logical package stream,
its complete content pin, action/output identity, an `AdmittedBudget` and
cancellation. It checks the existing package record format while chunking and
hashing in one pass: sorted contained paths, regular-file modes, contained aliases,
exact lengths, EOF, expanded alias bytes, and files plus implicit directories.
A malformed stream or incorrect full hash cannot publish its chunk manifest.
Earlier completed chunks remain unrooted and collectible. The returned
`PreparedSystemOutput` holds live retention until a consumer result is admitted.
An action supplied here is consumption metadata; this API creates no local build
receipt or claim that the producer executed successfully.

`ResultManifest::for_system` and `admit_system_result` introduce canonical
`syrox-system-result\n` manifests. Alongside the outputs/commands of a package
result (`syrox-package-result\n`), a system result records positive
`system.bytes` and `system.files` limits. They must fit the caller's
administrator-admitted budget. Format caps are 256 GiB minus 4 MiB of aggregate
logical/expanded bytes, one million view entries, 128 outputs and 8 MiB of
manifest bytes. Admission charges each unique artifact once, using the greater
of its encoded and expanded size, and counts the view's files and directories.
Runtime commands still undergo the existing complete executable-closure checks.

A chunked output adds `chunked: { "manifest": "<lowercase hex>" }` to its
metadata. The hex encodes the exact canonical chunk-manifest bytes described
above. Its `artifact` field pins those bytes; the embedded manifest separately
pins the complete logical package content. Descriptors are checked against their
pins, actual Store manifests, every chunk and the complete logical content.
Embedding the chunk identities makes the complete portable GC closure available
from the result itself. The expanded root set is bounded by the existing 65,536
Store references, including the result manifest. Unknown fields, noncanonical
encodings and header/descriptor mismatches fail admission.

Materialization, bounded file reads, runtime inspection and initramfs construction
use the same authenticated artifact index over either storage form. Chunked
sources use a seekable reader with one cached chunk, without reconstructing a
whole artifact blob. `OutputOrigin::Imported` continues to identify the pinned
consumption manifest. Views and image roots retain the complete source closure,
including all chunks, after the input root is retired.

`bundle::export_system_bundle` and `import_system_bundle` use
`syrox-system-bundle\n` framing and require an admitted budget. The result
manifest travels first with its u32 little-endian byte length. A u32 object count
follows, then unique objects in raw-digest order: 32 digest bytes, u64
little-endian length, and the object bytes. This includes chunk manifests and
chunks, sharing repeated chunks once. Imports require an externally supplied
result pin, exactly the declared object set, per-object bounds, a bounded total
transport size and EOF. Only full result verification may publish a consumer
root. Truncation, corruption, cancellation or trailing objects leave no root;
verified unrooted uploads remain collectible. Export failures may leave a partial
destination, which callers must stage before publishing.

Package results and runtime bundles keep their 1 MiB manifests, 128 MiB
individual artifacts and 512 MiB aggregate artifacts. Their ordinary
admission/export APIs reject system results. A system result can contain
package blobs, which keep their individual package bounds. The managed worker
input/descriptor protocol explicitly refuses system results until the
system worker protocol and execution profile are implemented. Source budgets,
worker enforcement, disk scratch, build receipts and release authorization still
need their system integration; this result/transport increment does not enable
large ordinary builds or qualify a complete Linux image.

## Producing System output frames

`result::SystemOutputStream::from_directory` prepares a package frame from an
explicit, read-only directory descriptor and an `AdmittedBudget`. The caller
must first settle every possible writer. Enumeration and payload opens stay
beneath that pinned root and refuse mount crossings when opening directories
and payloads. Canonical paths, entry types, single-link regular files, modes,
contained direct aliases, encoded bytes and expanded alias bytes are checked.
The inode charge includes the root and empty directories, although empty
directories have no records in the existing package format.

The stream revalidates the complete metadata tree before its first byte and
before EOF. Payloads use positioned reads, at most 64 KiB each, and compare
device/inode, size, links, ownership, mode and modification/change timestamps
before and after reading. Replacements, truncation, growth, alias changes and
directory changes fail the stream; it cannot resume after a substantive failure.
These observations detect changes, without establishing filesystem exclusivity
or process settlement. Memory holds bounded metadata, one payload descriptor
and small framing buffers; it never contains an entire package or large file.

`stage_system_output` connects this producer directly to the canonical scanner
and chunk staging. It computes the complete content hash while streaming and
publishes the chunk manifest only after successful scan and EOF. It returns the
existing `PreparedSystemOutput` retention handle. It creates neither a consumer
root nor a build receipt. The external producer API `ingest_system_output`
continues requiring its caller's complete content pin.

`write_system_outputs` and `receive_system_outputs` provide a separately
tagged, one-shot worker transfer. Its bytes are:

1. `syrox-system-worker-outputs\n`, the 32-byte action digest, a 32-byte budget
   binding and a u16 little-endian output count (1–128).
2. Outputs in ASCII name order: u8 name length, name bytes, u64 little-endian
   package length, the exact package bytes, then their 32-byte SHA-256.
3. EOF, without additional frames or trailing bytes.

The budget binding hashes `syrox-system-output-budget\n`, the admitted
administrator policy fingerprint, then eight u64 little-endian request values:
memory, CPU percentage, processes, descriptors, scratch bytes, files, output
bytes and duration seconds. This binds the exact request/policy; it does not
prove runtime enforcement of those resources.

The sender checks all names, trees and aggregate charges before emitting its
header. The receiver independently requires the caller's exact selected action,
budget and output names, bounds each frame before CAS staging, and checks its
canonical package, hash trailer and final EOF. Both sides charge each frame,
including repeated content, by the greater of encoded and expanded bytes.
The receiver charges reconstructed entries plus each output root; empty
directories omitted from the package cannot be independently observed there.
The per-frame scanner uses the remaining aggregate byte/inode budget.

Short and interrupted I/O remains bounded and cancellable. Callers must also
bound transport blocking with their execution deadline. A failed receive
returns no prepared set and publishes no consumer root or receipt. Individually
verified unrooted uploads remain collectible. A later sender failure can leave
a partial destination, which the caller must not publish. Authentication of the
worker/transport, execution settlement, System action receipts and the complete
System executor remain required. The legacy managed-worker dispatch cannot
select this new framing implicitly.
