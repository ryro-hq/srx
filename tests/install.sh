#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
installer=$PWD/install.sh
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT
export fixture
mkdir -p "$fixture"/{bin,payload,assets,home}
export PATH="$fixture/bin:$PATH" HOME="$fixture/home"
unset GH_TOKEN GITHUB_TOKEN

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
[[ $* == 'ls-remote --exit-code https://github.com/ryro-hq/srx.git refs/tags/v0.1.0 refs/tags/v0.1.0^{}' ]]
printf '%040d\trefs/tags/v0.1.0\n%040d\trefs/tags/v0.1.0^{}\n' 1 2
EOF
cat > "$fixture/bin/curl" <<'EOF'
#!/usr/bin/env bash
set -eu
[[ $* == "--proto =https --tlsv1.2 --fail --silent --show-error --location --output $9 https://github.com/ryro-hq/srx/releases/download/v0.1.0/$9" ]]
cp -- "$fixture/assets/$9" "$9"
EOF
cat > "$fixture/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -eu
case "$*" in
  'release view --repo ryro-hq/srx --json tagName --jq .tagName')
    [[ ${no_release:-0} == 0 ]]
    echo v0.1.0 ;;
  'attestation verify --help') ;;
  *)
    commit=$(printf '%040d' 2)
    [[ $* == "attestation verify srx-x86_64-unknown-linux-"*".tar.gz --repo ryro-hq/srx --signer-workflow ryro-hq/srx/.github/workflows/release.yml --source-ref refs/tags/v0.1.0 --source-digest $commit --deny-self-hosted-runners --predicate-type ${*: -1}" ]]
    [[ ${*: -1} != "${reject_predicate:-}" ]]
    printf '%s\n' "${*: -1}" >> "$fixture/verified" ;;
esac
EOF
cat > "$fixture/payload/srx" <<'EOF'
#!/usr/bin/env bash
set -eu
[[ $1 == install-self && $2 == --prefix && $# == 3 ]]
[[ $(cat "$fixture/verified") == $'https://slsa.dev/provenance/v1\nhttps://spdx.dev/Document' ]]
mkdir -p "$3/bin"
printf 'installed\n' > "$3/bin/srx"
EOF
chmod +x "$fixture/bin/"* "$fixture/payload/srx"
(cd "$fixture/payload" && sha256sum srx > SHA256SUMS)
for variant in gnu musl; do
  artifact="srx-x86_64-unknown-linux-$variant.tar.gz"
  (cd "$fixture/assets" && tar -czf "$artifact" -C "$fixture/payload" . &&
    sha256sum "$artifact" > "$artifact.sha256")
done

bash "$installer"
test -f "$HOME/.local/srx/bin/srx"
rm "$fixture/verified"
bash "$installer" --version v0.1.0 --libc musl --prefix "$fixture/custom prefix/srx"
test -f "$fixture/custom prefix/srx/bin/srx"

expect_failure() {
  local message=$1
  shift
  rm -f "$fixture/verified"
  if "$@" --prefix "$fixture/rejected" > "$fixture/output" 2>&1; then
    echo "expected failure: $message" >&2
    exit 1
  fi
  grep -F -- "$message" "$fixture/output"
  test ! -e "$fixture/rejected"
}

expect_failure 'support only Linux x86-64' env test_arch=aarch64 bash "$installer"
expect_failure 'could not find a published release' env no_release=1 bash "$installer"
expect_failure 'could not verify https://spdx.dev/Document' \
  env reject_predicate=https://spdx.dev/Document bash "$installer"
printf x >> "$fixture/assets/srx-x86_64-unknown-linux-gnu.tar.gz"
expect_failure 'checksum mismatch' bash "$installer"
test ! -e "$fixture/verified"
