# System consumption artifacts

> The [format reset](format-reset.md) later renamed these formats: result v2
> became the package result (`syrox-package-result`), result v3 the system
> result (`syrox-system-result`) and system bundle v2 `syrox-system-bundle`.
> Bytes written before the reset are refused; the notes below describe the
> engine API, not compatibility with those bytes.

The engine adds explicitly budgeted system result and system bundle APIs. The
[artifact contract](../artifacts.md#budgeted-system-outputs-and-bundles) specifies
their wire formats, bounds, retention and authority. This increment enables large
consumption artifacts and image inputs; system build workers and receipts remain
under implementation.

Rust callers constructing `ResultOutput` directly must add `chunked: None` for
package blobs. Serialized package result outputs omit that field. `ResultManifest::from_views`, `admit_result`,
`export_bundle` and `import_bundle` retain their legacy policy. There is no
implicit upgrade from a legacy result or bundle.

For system streams, use `ingest_system_output` with the full logical content pin
and an administrator-admitted budget, keep its `PreparedSystemOutput` alive,
collect its metadata with `ResultManifest::for_system`, then authorize the exact
manifest pin with `admit_system_result`. `export_system_bundle` and
`import_system_bundle` require an explicit admitted budget and use the new
transport header. A manifest/bundle is consumption evidence, not a local build
receipt, source-availability guarantee, installation approval or boot qualification.

`MAX_RESULT_MANIFEST_BYTES` now describes the largest supported manifest (8 MiB).
Package result parsing still enforces its 1 MiB cap; ordinary outputs and
aggregate limits remain unchanged. Chunked outputs pin a container manifest in
`ResultOutput.artifact` and embed its canonical bytes; their complete content pin
remains inside that manifest. Persist the full result references rather than
retaining just its opaque chunk-manifest blob.

Previously published result, bundle, chunk and package bytes are never rewritten.
The new versions produce separate explicit identities. Existing profile and
journal formats are unchanged. The bundled std migration is documented separately
in [Services](services.md); refresh dependency projects before consumer locks.
