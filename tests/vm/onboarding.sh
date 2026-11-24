#!/usr/bin/env bash
set -euo pipefail

# Execute the user-facing shell blocks verbatim; missing or duplicate markers
# must fail CI, not silently reduce coverage.
snippet() {
    awk -v marker="<!-- onboarding: $2 -->" '
        $0 == marker {
            if (++seen != 1 || state != 0) exit 1
            state = 1
            next
        }
        state == 1 {
            if ($0 != "```sh") exit 1
            state = 2
            next
        }
        state == 2 && $0 == "```" { state = 0; next }
        state == 2 { print; ++lines }
        END { if (seen != 1 || state != 0 || lines == 0) exit 1 }
    ' "$1"
}

journey() {
    local docs=$1
    local install compare project hello services uninstall
    install=$(snippet "$docs/install.md" install)
    compare=$(snippet "$docs/install.md" compare)
    uninstall=$(snippet "$docs/install.md" uninstall)
    project=$(snippet "$docs/first-ten-minutes.md" project)
    hello=$(snippet "$docs/first-ten-minutes.md" hello)
    services=$(snippet "$docs/first-ten-minutes.md" services)

    cat <<'SH'
test "$(id -u)" -ne 0
if command -v srx || command -v rustc; then
    echo "expected no srx or Rust toolchain on PATH" >&2
    exit 1
fi
test ! -e "$HOME/.local/srx"
cd /evidence/download
read -r artifact < artifact-name
sha256sum --strict --check "$artifact.sha256"

# These CI candidates have no GitHub attestation. Check the checksum both ways;
# the official archives are tested with the attestation block at publication.
tampered=$(mktemp -d)
cp -- "$artifact" "$artifact.sha256" "$tampered/"
printf x >> "$tampered/$artifact"
if (cd "$tampered" && sha256sum --strict --check "$artifact.sha256"); then
    echo "unexpectedly accepted a modified archive" >&2
    exit 1
fi
rm -r -- "$tampered"
SH
    printf '%s\n' "$install" "$compare"
    cat <<'SH'
# A single candidate allows a reinstall check, not a cross-version upgrade.
"$payload/srx" install-self --prefix "$prefix"
rm -r -- "$payload"
SH
    printf '%s\n' "$project"
    cat <<'SH'
hello_output=$(
    set -e
SH
    printf '%s\n' "$hello"
    cat <<'SH'
)
printf '%s\n' "$hello_output"
grep -Fxq 'Hello from Syrox!' <<< "$hello_output"
SH
    printf '%s\n' "$services"
    cat <<'SH'
if curl --silent --noproxy '*' --max-time 2 http://127.0.0.1:18080/healthz; then
    echo "the demo service is still listening after stop" >&2
    exit 1
fi
SH
    printf '%s\n' "$uninstall"
    cat <<'SH'
test ! -e "$HOME/.local/srx"
if command -v srx; then
    echo "srx is still on PATH after uninstall" >&2
    exit 1
fi
test -f main.srx
test -d store
SH
}

case "$1" in
    snippet)
        snippet "$2" "$3"
        ;;
    journey)
        journey "$2"
        ;;
    guest)
        # The acceptance VM boots with the example's preinstalled OS tools, but
        # not an srx installation, catalog, Store or Services profile.
        test "$(cat /proc/1/comm)" = systemd
        timeout 30 bash -c 'until systemctl show -p Version --value >/dev/null 2>&1; do sleep .1; done'
        uid=$(id -u syrox)
        systemctl start "user@$uid.service"
        for _ in {1..100}; do
            test -S "/run/user/$uid/bus" && break
            sleep .1
        done
        test -S "/run/user/$uid/bus"
        cat /etc/os-release
        uname -r
        getconf GNU_LIBC_VERSION
        systemctl show -p Version --value
        script=$(journey /sources/docs)
        /usr/sbin/runuser -u syrox -- env \
            PATH=/usr/bin:/bin TMPDIR=/home/syrox XDG_RUNTIME_DIR="/run/user/$uid" \
            DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
            bash -seuxo pipefail <<< "$script"
        ;;
    *)
        echo "usage: $0 snippet FILE NAME | journey DOCS | guest" >&2
        exit 2
        ;;
esac
