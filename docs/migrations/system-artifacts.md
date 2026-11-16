# System consumption artifacts

The engine adds explicitly budgeted result v3 and system bundle v2 APIs. The
[artifact contract](../artifacts.md#budgeted-system-outputs-and-bundles) specifies
their wire formats, bounds, retention and authority. This increment enables large
consumption artifacts and image inputs; system build workers and receipts remain
under implementation.

Rust callers constructing `ResultOutput` directly must add `chunked: None` for
legacy blobs. Existing serialized result v2 outputs omit that field and keep the
same bytes and identity. `ResultManifest::from_views`, `admit_result`,
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
Legacy v2 parsing still enforces its original 1 MiB cap; ordinary outputs and
aggregate limits remain unchanged. Chunked outputs pin a container manifest in
`ResultOutput.artifact` and embed its canonical bytes; their complete content pin
remains inside that manifest. Persist the full result references rather than
retaining just its opaque chunk-manifest blob.

Previously published result, bundle, chunk and package bytes are never rewritten.
The new versions produce separate explicit identities. Existing profile and
journal formats are unchanged. The bundled std migration is documented separately
in [Services](services.md); refresh dependency projects before consumer locks.
