# First ten minutes with Syrox

Use an unprivileged login on a [supported host](install.md#supported-linux-hosts).
First [download, verify and install `srx`](install.md). The demo builds GNU Hello
and nginx from source; download and compilation time depend on your machine.

On the pinned Debian guest, ensure Git, curl, CA certificates, a native C
toolchain and Make (`build-essential`), `musl-tools`, Bubblewrap, `systemd` and
`dbus-user-session` are installed. The guest uses `setpriv` from util-linux
2.42 with Landlock `ioctl-dev` support; the stock package on an older host may
not support it. The signed CLI is static, but these are **host tools for
building and applying services**, not for installing `srx`. Check that
`systemctl --user show --property=Version --value` can reach your manager.
Port `18080` must be free for the example.

## 1. Create and lock a project

Run these blocks in the same Bash session from a writable directory. The demo
uses a disposable workspace and a catalog revision fixed by commit. It uses
musl packages even when `srx` itself came from the GNU archive.

<!-- onboarding: project -->
```sh
set -eu
workspace=$(mktemp -d "${TMPDIR:-/tmp}/srx-first-use.XXXXXXXX")
cd "$workspace"
git init -q srx-pkgs
git -C srx-pkgs fetch --quiet --depth 1 \
  https://github.com/ryro-hq/srx-pkgs.git fa061bf30399571661f9cf52601707dad9d554a2
git -C srx-pkgs checkout --quiet --detach FETCH_HEAD
test "$(git -C srx-pkgs rev-parse HEAD)" = fa061bf30399571661f9cf52601707dad9d554a2
mkdir hello-demo
cd hello-demo
cat > main.srx <<'SRX'
inputs { pkgs = "path:../srx-pkgs"; }
let packages = pkgs.forPlatform { system = "linux-x86_64"; libc = "musl"; };

pub let hello = package_recipe(packages.hello { version = "2.12.1"; });

services.nginx = {
    package = packages.nginx { version = "1.30.6"; };
    settings = {
        listen = 18080;
        extraConfig = "allow 127.0.0.1; deny all; location = /healthz { empty_gif; }";
    };
};
SRX

srx project lock ../srx-pkgs
srx project check .
srx project lock .
srx project plan . --output os
```

Locking the disposable catalog checkout can refresh its `Syrox.lock` for the
installed CLI. The `hello` export selects a catalog recipe; the `services.nginx`
declaration creates the `os` output of type `Services`.

## 2. Build and run Hello

Allow only the two HTTPS source URLs needed for the demo. The catalog locks
the source hashes; the build tools come from `/usr`.

<!-- onboarding: hello -->
```sh
cat > build.toml <<'TOML'
[build]
host-toolchain = "/usr"

[network]
allow-https = [
    "https://ftp.gnu.org/gnu/hello/hello-2.12.1.tar.gz",
    "https://nginx.org/download/nginx-1.30.6.tar.gz",
]
TOML

srx build .#hello --config ./build.toml --store ./store
srx run .#hello --command hello --offline --config ./build.toml --store ./store \
  -- --greeting 'Hello from Syrox!'
```

The run prints `Hello from Syrox!`. It uses the retained build rather than
downloading the source again.

## 3. Apply and stop a Services generation

The `hello-web` profile must not already exist. This uses your user manager;
it does not enable boot startup. If the session is interrupted after apply,
stop the profile with the last command.

<!-- onboarding: services -->
```sh
srx services init .#os --name hello-web --user --config ./build.toml --store ./store
srx services apply --profile hello-web --locked
srx services status --profile hello-web
curl --fail --silent --show-error --noproxy '*' --max-time 5 \
  --retry 5 --retry-connrefused --output health.gif http://127.0.0.1:18080/healthz
test "$(head -c 6 health.gif)" = GIF89a
srx services stop --profile hello-web
```

The HTTP check confirms that nginx served a response, not just that systemd
accepted its unit. Stopping selects an empty generation and preserves the
profile, project and Store. See [installation profiles](services-profiles.md)
for cleanup, logs and recovery.
