# Import a pinned source for offline builds

`srx project import-source` admits bytes from an explicitly selected local file
against an existing locked acquisition request. It does not change the request's
URL, SHA-256, maximum size, recipe identity or project lock. Network access and
network configuration are unnecessary.

```sh
srx project import-source ./project package_export 0 \
  --file /downloads/source.tar.gz --store /builder/store --root source_archive
srx build ./project#package_export --config /builder/build.toml --offline
```

The package argument selects its public export, independently of its internal
package ID. The source index is zero-based. Project authentication, lock and
source selection are checked before opening the source or initializing the
Store. The selected file must already exist and be regular; symlinks in any path
component are refused. Reads, including EOF, are checked against the locked size
and SHA-256 even when the same object is already cached.

The engine's `acquire::local::import_source_stream` accepts a caller-authorized
stream, checks cancellation between bounded reads, and uses the existing Store
staging/publication protocol. A wrong digest, excessive size, read failure or
observed cancellation leaves no new retained root. Root conflicts are reported
by the normal Store publication rules. An interrupted or uncertain durable
publication must be inspected using the existing Store recovery contracts.

Relative `--file` and `--store` paths use the command's working directory.
Store initialization still rejects parent traversal and applies its existing
bounded location/ownership rules; resolving a relative path grants no wider scope.

Import verifies the identity of the bytes; it does not qualify a build or verify
an upstream developer signature. Such signatures must be verified separately
when admitting or updating source pins. Build isolation, input admission and
receipt verification still apply to an offline build.

The existing gzip source profile accepts regular files and directories only.
The xz profile additionally accepts relative links to regular members below
the link's own directory. The complete archive must establish the target as a
regular file; missing targets, directory targets, chains, absolute paths, `.`
and `..` components remain rejected. Extraction writes aliases only after
validating and writing all regular files, and never traverses an alias as a
destination directory. Resource ceilings remain unchanged.

The xz profile also admits GNU tar long-name records for the immediately
following regular file or directory. The complete ASCII name must fit the
existing 255-byte path bound; it undergoes the same traversal, collision and
parent checks as an ordinary name. The following header must repeat its first
100 bytes. Nested or dangling metadata, link-name extensions, mismatched headers,
embedded NULs and nonzero padding are rejected. Each metadata record and payload
counts against the existing entry and expanded-byte limits. Gzip retains its
previous regular-file/directory format rules.
