#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
installer=$PWD/install.sh
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
mkdir -p "$fixture"/{bin,payload,assets,home}
export fixture PATH="$fixture/bin:$PATH" HOME="$fixture/home"
unset GH_TOKEN GITHUB_TOKEN
test_tag=v0.1.0
candidate=
if (($#)); then
  [[ $# -eq 2 && $1 =~ ^x86_64-unknown-linux-(gnu|musl)$ ]] ||
    { echo "usage: $0 [TARGET DIRECTORY_WITH_RELEASE_BINARIES]" >&2; exit 2; }
  candidate=$1
  cp -- "$2/srx" "$2/syrox-worker" "$fixture/payload/"
  version=$("$fixture/payload/srx" --version)
  test_tag="v${version#srx }"
fi
export test_tag

cat > "$fixture/bin/uname" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  -s) echo Linux ;;
  -m) echo "${test_arch:-x86_64}" ;;
  *) exit 1 ;;
esac
EOF
cat > "$fixture/bin/git" <<'EOF'
#!/usr/bin/env bash
set -eu
[[ $* == "ls-remote --exit-code https://github.com/ryro-hq/srx.git refs/tags/$test_tag refs/tags/$test_tag^{}" ]]
[[ ${missing_tag:-0} == 0 ]]
printf '%040d\trefs/tags/%s\n' 1 "$test_tag"
if [[ ${lightweight:-0} == 0 ]]; then
  printf '%040d\trefs/tags/%s^{}\n' 2 "$test_tag"
fi
EOF
cat > "$fixture/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -eu
[[ $* == "--disable --proto =https --tlsv1.2 --fail --silent --show-error --location --output ${10} https://github.com/ryro-hq/srx/releases/download/$test_tag/${10}" ]]
cp -- "$fixture/assets/${10}" "${10}"
EOF
cat > "$fixture/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -eu
case "$*" in
  'release view --repo ryro-hq/srx --json tagName --jq .tagName')
    [[ ${no_release:-0} == 0 ]]
    echo "$test_tag" ;;
  'attestation verify --help') [[ ${old_gh:-0} == 0 ]] ;;
  *)
    commit=$(printf '%040d' "$((2 - ${lightweight:-0}))")
    [[ $* == "attestation verify srx-x86_64-unknown-linux-"*".tar.gz --repo ryro-hq/srx --signer-workflow ryro-hq/srx/.github/workflows/release.yml --source-ref refs/tags/$test_tag --source-digest $commit --deny-self-hosted-runners --predicate-type ${*: -1}" ]]
    predicate=${*: -1}
    [[ $predicate == https://slsa.dev/provenance/v1 || $predicate == https://spdx.dev/Document/v2.3 ]]
    [[ $predicate != "${reject_predicate:-}" ]]
    printf '%s\n' "$predicate" >> "$fixture/verified" ;;
esac
EOF
chmod +x "$fixture/bin/"*

pack() {
  local artifact="srx-$1.tar.gz"
  (cd "$fixture/assets"
   tar -czf "$artifact" -C "$fixture/payload" .
   sha256sum "$artifact" > "$artifact.sha256")
}

if [[ -n $candidate ]]; then
  (cd "$fixture/payload" && sha256sum srx syrox-worker > SHA256SUMS)
  pack "$candidate"
  for _ in 1 2; do
    rm -f "$fixture/verified"
    bash "$installer" --version "$test_tag" --libc "${candidate##*-}"
    cmp "$fixture/verified" <(printf '%s\n' https://slsa.dev/provenance/v1 https://spdx.dev/Document/v2.3)
    cmp "$HOME/.local/srx/bin/srx" "$fixture/payload/srx"
    cmp "$HOME/.local/srx/current/syrox-worker" "$fixture/payload/syrox-worker"
    test "$("$HOME/.local/srx/bin/srx" --version)" = "$version"
  done
  exit 0
fi

cat > "$fixture/payload/srx" <<'EOF'
#!/usr/bin/env bash
set -eu
[[ $(cat "$fixture/verified") == $'https://slsa.dev/provenance/v1\nhttps://spdx.dev/Document/v2.3' ]]
if [[ $* == --version ]]; then
  printf 'srx %s\n' "${binary_version:-${test_tag#v}}"
  exit 0
fi
[[ $1 == install-self && $2 == --prefix && $# == 3 ]]
mkdir -p "$3/bin"
printf 'installed\n' > "$3/bin/srx"
EOF
chmod +x "$fixture/payload/srx"
(cd "$fixture/payload" && sha256sum srx > SHA256SUMS)
pack x86_64-unknown-linux-gnu
pack x86_64-unknown-linux-musl

bash "$installer" --help | grep -F 'Usage:'
bash "$installer"
test -f "$HOME/.local/srx/bin/srx"
rm "$fixture/verified"
no_release=1 lightweight=1 bash "$installer" --version v0.1.0 --libc musl \
  --prefix "$fixture/custom prefix/srx"
test -f "$fixture/custom prefix/srx/bin/srx"
rm "$fixture/verified"
test_tag=v0.1.0-rc.1 bash "$installer" --version v0.1.0-rc.1 --prefix "$fixture/prerelease"
test -f "$fixture/prerelease/bin/srx"
rm "$fixture/verified"
mkdir -p "$fixture/relative/tmp"
(cd "$fixture/relative" && TMPDIR=tmp bash "$installer")
test -z "$(ls -A "$fixture/relative/tmp")"

expect_failure() {
  local message=$1
  shift
  rm -f "$fixture/verified"
  if "$@" > "$fixture/output" 2>&1; then
    echo "expected failure: $message" >&2
    exit 1
  fi
  grep -F -- "$message" "$fixture/output"
  test ! -e "$fixture/rejected"
}

reject() {
  local message=$1
  shift
  expect_failure "$message" "$@" "$installer" --prefix "$fixture/rejected"
}
reject 'support only Linux x86-64' env test_arch=aarch64 bash
reject 'install a current GitHub CLI' env old_gh=1 bash
reject 'could not find a published release' env no_release=1 bash
reject 'expected a stable vX.Y.Z tag' env test_tag=v0.1.0-rc.1 bash
reject 'could not resolve official tag' env missing_tag=1 bash
expect_failure 'missing value' bash "$installer" --version
expect_failure 'invalid release tag' bash "$installer" --version ../invalid
expect_failure 'absolute path other than /' bash "$installer" --prefix /
expect_failure 'use --libc gnu or --libc musl' bash "$installer" --libc other
reject 'could not verify https://spdx.dev/Document/v2.3' env reject_predicate=https://spdx.dev/Document/v2.3 bash
reject 'binary version does not match' env binary_version=9.9.9 bash

artifact=srx-x86_64-unknown-linux-gnu.tar.gz
printf x >> "$fixture/assets/$artifact"
reject 'checksum mismatch' bash
test ! -e "$fixture/verified"
(cd "$fixture/assets" && sha256sum "$artifact" > "$artifact.sha256")
reject 'could not verify https://slsa.dev/provenance/v1' \
  env reject_predicate=https://slsa.dev/provenance/v1 bash
printf x >> "$fixture/payload/srx"
pack x86_64-unknown-linux-gnu
reject 'payload checksum verification failed' bash
rm "$fixture/assets/$artifact"
reject 'could not download' bash
