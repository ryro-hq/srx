# Install Syrox

Syrox is experimental. The command is `srx`; the core repository is
[`ryro-hq/srx`](https://github.com/ryro-hq/srx) and the package catalog is
[`ryro-hq/srx-pkgs`](https://github.com/ryro-hq/srx-pkgs).

## Supported Linux hosts

| Use | Architecture and distribution | Kernel | libc | systemd |
| --- | --- | --- | --- | --- |
| Install the CLI; check, lock or plan | Linux x86-64; the core CI guest uses Debian 13 (trixie) | Core CI uses Linux `6.12.109`; no older baseline is claimed | Both GNU and musl archives are static: neither requires a matching host libc | Not needed |
| Build and run the quickstart; apply a `Services` generation | The pinned Debian 13 CI guest with the [quickstart tools](first-ten-minutes.md) | Linux `6.12.109` in CI with cgroup v2, user and cgroup namespaces and Landlock ABI 6 | Debian glibc userspace with `musl-gcc` for the demo, whichever CLI archive you install | Running `systemd --user`, with the managed baseline of systemd 254 and the required D-Bus interfaces |

CI pins the guest base image and kernel firmware in
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml). The Ubuntu 24.04
runner builds the archives; it is not the core onboarding guest. The
[catalog's separate qualification](https://github.com/ryro-hq/srx-pkgs#qualification-and-publication)
covers Debian and Ubuntu 24.04 userspaces with a custom kernel and provisioned
tools. Neither matrix implies a stock distro kernel, ARM64, 32-bit Linux, macOS,
Windows or a non-systemd service manager is supported.

## Quick install

Once a stable release is published, download the installer, inspect it and
run it. This requires Bash, curl, Git, `sha256sum`, `tar` and a current
GitHub CLI (`gh`) with attestation support. If `gh` is not authenticated,
run `gh auth login` first.
No compiler or `sudo` is needed.

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/ryro-hq/srx/releases/latest/download/install.sh \
  -o install-srx.sh
```

```sh
bash install-srx.sh
export PATH="$HOME/.local/srx/bin:$PATH"
srx --version
```

The script resolves the latest stable release, checks the archive checksum
and verifies the build provenance and SPDX attestations online before
installing the CLI and its worker. The script itself is not covered by
those archive attestations. Use the manual instructions below if you prefer
not to run a downloaded script or need offline verification.

Use `bash install-srx.sh --help` for options. Pass `--version vX.Y.Z` to
select an exact published tag (including its suffix for a prerelease),
`--libc musl` for the musl archive or
`--prefix /absolute/path` for a dedicated alternate install location.
To upgrade, repeat the quick install with the same prefix. If no release is
published yet, use the [source-build instructions](../README.md#build-the-cli).

## Download and verify

Use Bash, Git, `sha256sum`, `tar`, and a current GitHub CLI (`gh`) with
`gh attestation verify --custom-trusted-root` support. Authenticate `gh` for
the online commands if needed. No Rust toolchain or compiler is needed to
install the CLI. Run the blocks in the same shell; stop if a command fails.

Choose an explicit, published tag from
[GitHub Releases](https://github.com/ryro-hq/srx/releases). Do not use a CI ZIP
or a source archive. If no release is listed, there is no verified binary to
download yet; use the [source-build instructions](../README.md#build-the-cli)
or wait for a release. Replace `vX.Y.Z` below with the reviewed tag. The GNU
archive is the default; set `target=x86_64-unknown-linux-musl` to use the musl
archive instead. The tag versions the assets even though their filenames
do not contain the version.

```sh
set -eu
repo=ryro-hq/srx
tag=vX.Y.Z
target=x86_64-unknown-linux-gnu
artifact="srx-$target.tar.gz"
mkdir "srx-$tag-$target"
cd "srx-$tag-$target"
gh release download "$tag" --repo "$repo" \
  --pattern "$artifact" --pattern "$artifact.sha256" \
  --pattern "srx-$target.spdx.json"
expected_commit=$(git ls-remote --exit-code "https://github.com/$repo.git" \
  "refs/tags/$tag" "refs/tags/$tag^{}" | awk 'END {print $1}')
test "${#expected_commit}" -eq 40
```

Obtain the trust roots separately from the release assets before verifying.
Record the tag and its expected commit from the official repository; do not
derive them from the archive or an untrusted copy of the bundle.

```sh
gh attestation trusted-root > trusted_root.jsonl
digest=$(sha256sum "$artifact" | cut -d ' ' -f 1)
bundle="sha256-$digest.jsonl"
gh release download "$tag" --repo "$repo" --pattern "$bundle"
```

This check works online or offline. It checks both the build provenance and
the SPDX SBOM binding against the expected repository, workflow, tag and
commit. SHA-256 alone does not authenticate a download.

<!-- onboarding: attest -->
```sh
set -eu
sha256sum --strict --check "$artifact.sha256"
for predicate in https://slsa.dev/provenance/v1 https://spdx.dev/Document; do
  gh attestation verify "$artifact" --repo ryro-hq/srx \
    --bundle "$bundle" --custom-trusted-root trusted_root.jsonl \
    --signer-workflow ryro-hq/srx/.github/workflows/release.yml \
    --source-ref "refs/tags/$tag" --source-digest "$expected_commit" \
    --deny-self-hosted-runners --predicate-type "$predicate"
done
```

## Install and upgrade

Only after verification, extract and install the CLI and its embedded worker
into a dedicated user-owned prefix. The archive also includes the SPDX SBOM,
license texts and notices, source evidence and vulnerability report.

<!-- onboarding: install -->
```sh
prefix="$HOME/.local/srx"
mkdir -p "$HOME/.local"
payload=$(mktemp -d)
tar -xzf "$artifact" -C "$payload"
(cd "$payload" && sha256sum --strict --quiet --check SHA256SUMS)
"$payload/srx" install-self --prefix "$prefix"
export PATH="$prefix/bin:$PATH"
srx --version
```

The version must match the selected release tag (without `v`). Add
`export PATH="$HOME/.local/srx/bin:$PATH"` to your shell startup file to keep it
on `PATH`. Next, follow [First ten minutes](first-ten-minutes.md).

To upgrade, download and verify the new tag in a new directory. Run the same
install commands with the **same** prefix. `install-self` switches the CLI and
worker together and leaves older releases in the prefix. Read the release
notes and [format reset](migrations/format-reset.md) before upgrading a
pre-release installation; a retained binary is not a backup of the Store.

## Verify an installation offline

Before disconnecting, save the archive, its `.sha256`, the matching `$bundle`,
the independently obtained `trusted_root.jsonl`, the expected tag and commit,
and a copy of `gh` that supports the flags above. On the offline machine, change
to the directory containing those files, set `artifact`, `tag`,
`expected_commit`, `bundle` and `prefix` to their recorded values and rerun the
attestation block. No GitHub login or API calls are needed for that block.

To check the installation itself, extract the verified archive into a fresh
`$payload` directory as above (but do **not** rerun `install-self`), then compare
the selected CLI and worker byte for byte:

<!-- onboarding: compare -->
```sh
cmp "$prefix/bin/srx" "$payload/srx"
cmp "$prefix/current/syrox-worker" "$payload/syrox-worker"
```

Both `cmp` commands must succeed. Prefer the archive's verified copy of
`sbom.spdx.json` to any unchecked external copy. Offline verification cannot
discover a later compromise or revocation; see
[Releases and recovery](security/releases.md) before importing new material.

## Uninstall

Stop any active `srx` service profiles first (for example,
`srx services stop --profile hello-web`). The following removes the CLI and
all versions of the worker for the **default dedicated prefix** only. Do not
use it if you've stored unrelated files there.

<!-- onboarding: uninstall -->
```sh
rm -r -- "$HOME/.local/srx"
hash -r
```

Remove the corresponding `PATH` entry from your shell startup file. A custom
prefix should be removed separately after confirming it contains only `srx`
installation files. Uninstalling the CLI does not remove projects, Stores or
service profile state.
