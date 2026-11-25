#!/usr/bin/env bash
set -euo pipefail

repo=ryro-hq/srx
tag=
variant=gnu
prefix=

die() { printf 'srx installer: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    -h|--help)
      printf 'Usage: bash install.sh [--version TAG] [--libc gnu|musl] [--prefix PATH]\n'
      exit 0
      ;;
    --version|--libc|--prefix)
      [[ $# -ge 2 && -n $2 && $2 != --* ]] || die "missing value for $1"
      case "$1" in
        --version) tag=$2 ;;
        --libc) variant=$2 ;;
        --prefix) prefix=$2 ;;
      esac
      shift 2
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] ||
  die 'published binaries support only Linux x86-64'
[[ $variant == gnu || $variant == musl ]] || die 'use --libc gnu or --libc musl'
[[ -n $prefix ]] || prefix="${HOME:?HOME is not set}/.local/srx"
[[ $prefix == /* && -n ${prefix//\//} ]] ||
  die 'the install prefix must be an absolute path other than /'

stable_tag='^v[0-9]+\.[0-9]+\.[0-9]+$'
release_tag='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
[[ -z $tag || $tag =~ $release_tag ]] || die "invalid release tag: $tag"
for cmd in curl gh git sha256sum tar mktemp mkdir rm; do
  command -v "$cmd" >/dev/null || die "required command not found: $cmd"
done
gh attestation verify --help >/dev/null 2>&1 ||
  die 'install a current GitHub CLI with attestation support'

if [[ -z $tag ]]; then
  tag=$(gh release view --repo "$repo" --json tagName --jq .tagName) ||
    die "could not find a published release at https://github.com/$repo/releases; check GitHub CLI authentication and connectivity"
  [[ $tag =~ $stable_tag ]] || die "expected a stable vX.Y.Z tag, got: $tag"
fi

ref="refs/tags/$tag"
refs=$(git ls-remote --exit-code "https://github.com/$repo.git" "$ref" "$ref^{}") ||
  die "could not resolve official tag $tag"
commit=
peeled=
while IFS=$'\t' read -r sha name; do
  case "$name" in
    "$ref") commit=$sha ;;
    "$ref^{}") peeled=$sha ;;
  esac
done <<< "$refs"
commit=${peeled:-$commit}
[[ $commit =~ ^[0-9a-f]{40}$ ]] || die "invalid commit for $tag"

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
artifact="srx-x86_64-unknown-linux-$variant.tar.gz"
url="https://github.com/$repo/releases/download/$tag"
(
  cd -- "$work"
  for asset in "$artifact" "$artifact.sha256"; do
    curl --disable --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
      --output "$asset" "$url/$asset" || die "could not download $asset for $tag"
  done
  [[ $(sha256sum "$artifact") == "$(<"$artifact.sha256")" ]] ||
    die "checksum mismatch for $artifact"

  for predicate in https://slsa.dev/provenance/v1 https://spdx.dev/Document; do
    gh attestation verify "$artifact" --repo "$repo" \
      --signer-workflow "$repo/.github/workflows/release.yml" \
      --source-ref "$ref" --source-digest "$commit" \
      --deny-self-hosted-runners --predicate-type "$predicate" ||
      die "could not verify $predicate for $tag"
  done

  mkdir payload
  tar -xzf "$artifact" -C payload || die "could not extract $artifact"
  (cd payload && sha256sum --strict --quiet --check SHA256SUMS) ||
    die "payload checksum verification failed for $artifact"
  [[ $(payload/srx --version) == "srx ${tag#v}" ]] ||
    die "binary version does not match $tag"
  payload/srx install-self --prefix "$prefix"
)
printf 'Installed srx %s. Add %s/bin to PATH if needed.\n' "$tag" "$prefix"
