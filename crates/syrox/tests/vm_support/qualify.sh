#!/bin/bash
set -euxo pipefail
test "$(cat /proc/1/comm)" = systemd
test "$(id -u)" -ne 0
test "$(stat -f -c %T /work)" = tmpfs
test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs
test -S "$XDG_RUNTIME_DIR/bus"
version=$(busctl --user get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Version)
version=${version#*\"}; version=${version%%[^0-9]*}; test "$version" -ge 254
unshare --user --map-root-user --mount --pid --fork --mount-proc /usr/bin/true
systemd-run --user --scope --collect --quiet -p Delegate=yes bash -euxo pipefail -c '
parent=/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup)
test "$parent" != /sys/fs/cgroup/
test -w "$parent/cgroup.procs"
mkdir "$parent/syrox-probe"
sleep 20 & child=$!
trap "kill $child 2>/dev/null || true; wait $child 2>/dev/null || true; rmdir $parent/syrox-probe" EXIT
echo "$child" > "$parent/syrox-probe/cgroup.procs"
grep -qx "populated 1" "$parent/syrox-probe/cgroup.events"
'
uname -a
systemctl --user show --property=Version
gcc --version
test "$(setpriv --version)" = 'setpriv from util-linux 2.42'
setpriv --help | grep ioctl-dev
if test -f /evidence/ecosystem-plan.json; then
    rustc --version --verbose
    test "$(node --version)" = v26.10.0
    test "$(nvim --version | head -1)" = 'NVIM v0.11.5'
fi
