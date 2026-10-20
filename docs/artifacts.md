# Authorized local artifacts

An artifact descriptor lets `srx build`, `run`, `shell`, and OS preparation use
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
