# Editor compatibility

Syrox ships the stdio language server in `srx lsp`. This is the pre-release
compatibility baseline for **Linux x86-64**, not a guarantee for every checkout
of `main` or every build reporting the same version number. The baseline was
checked with a GNU/Linux build of `srx` on Ubuntu 26.04.1 under WSL2, not with
Windows binaries or the VS Code Remote extension.

The baseline server is **`srx 0.1.0`** with its bundled standard library, based
on [`4402d94`](https://github.com/ryro-hq/srx/tree/4402d94e960f360d2d73dcbe8d6a8ffb351d452d).
It implements the LSP 3.17 methods listed below over JSON-RPC 2.0 on stdin/stdout,
not the full protocol. It uses UTF-16 positions unless the client offers UTF-8.
For extensions, it advertises `syroxVirtualSource` revision 1
(`syrox-source:` URIs and `syrox/readSource`) and `syroxProjectStatus` revision 1.
The [protocol fixture](../tests/fixtures/lsp-contract.json) records the descriptors
separately from the version reported by `srx --version`.

| Integration | Supported client revision | Tested host |
| --- | --- | --- |
| [srx-vscode](https://github.com/ryro-hq/srx-vscode) | Extension `0.1.0`, [`8578a98`](https://github.com/ryro-hq/srx-vscode/tree/8578a98545b9b6d4e2dbe98b43e710cfd2ba676c) | VS Code `1.90.2` (Extension Host) |
| [srx.nvim](https://github.com/ryro-hq/srx.nvim) | Untagged snapshot [`b1f26f5`](https://github.com/ryro-hq/srx.nvim/tree/b1f26f5628b5a7ce6aefb53d828c99c18f19d94c) | Neovim `0.11.5` (headless) |
| [srx-opencode](https://github.com/ryro-hq/srx-opencode) | Plugin `0.1.0`, [`2c0b2e9`](https://github.com/ryro-hq/srx-opencode/tree/2c0b2e95a7d2c712fb6712871736cbc56fd937a7) | OpenCode V2 `2.0.12` (packaged plugin loads; tool calls exercised separately) |

| Feature exercised by the shared fixture | VS Code | Neovim | OpenCode |
| --- | --- | --- | --- |
| Typed diagnostics and clearing after a fix | Live buffer | Live buffer | Saved file via `syrox_diagnostics` |
| Typed YAML field completion | Editor completion | Built-in LSP completion | `syrox_completion` |
| Go to the factory of a published recipe | Go to Definition | LSP definition | `syrox_definition` |
| Format the open document | Format Document | `vim.lsp.buf.format()` | Not exposed; use `srx fmt` separately |
| Follow a definition into bundled `std` | Read-only virtual document | Read-only virtual buffer | `syrox_definition`, then `syrox_source` |

## Install

Use the `srx` checkout containing this guide and its matching test fixture.
With the pinned Rust toolchain and native build tools (see
[Get started](../README.md#get-started)), run
`cargo build --locked -p syrox --bin srx` to build the language server. Put
`target/debug/srx` on the editor process's `PATH` by adding its containing
directory, or configure its absolute path as below. Keep the server and project
in the same Linux environment. The language server does not need `syrox-worker`.

- **VS Code:** in the pinned `srx-vscode` checkout, run `npm ci --ignore-scripts`
  and `npm run package`, then `code --install-extension ./syrox.vsix`. If `srx`
  is not on the extension host's `PATH`, set `syrox.serverPath` to the absolute
  binary path. Open the folder containing `main.srx`.
- **Neovim:** add the pinned `srx.nvim` checkout to `runtimepath`, then call
  `require("syrox").setup({ cmd = { "srx", "lsp" } })` in `init.lua`. Replace
  `"srx"` with the absolute binary path if needed. Use `:help syrox-setup`
  for client settings.
- **OpenCode:** install the pinned plugin with
  `opencode plugin add 'github:ryro-hq/srx-opencode#2c0b2e95a7d2c712fb6712871736cbc56fd937a7'`,
  or add the pinned local checkout to `plugins` in `opencode.jsonc`. Set
  `SYROX_LSP_BIN` to the absolute binary path if `srx` is not on the server's
  `PATH`. Tool positions are one-based UTF-16 line/column pairs; LSP locations
  returned by the tools use zero-based coordinates.

## Known limitations

- The baseline covers project editing against bundled `std`, not editing the
  standard library checkout itself. The separate `srx.nvim` std authoring test
  uses an older server pin and expects catalog symbols since removed from `std`.
- Virtual sources are read-only and tied to a server analysis generation. If a
  URI expires, request a new definition from the project file.
- Document formatting operates on the open buffer and returns no edits for
  syntax-invalid documents or virtual sources.
- Semantic results require an analyzable project graph. Save changes to imports
  or input declarations; use `syrox_reload` in OpenCode after external graph
  changes. OpenCode semantic tools only query saved `.srx` files within the
  workspace and do not apply edits. `srx fmt` writes to stdout, not the file.
- No verification is claimed for Windows/macOS server binaries, ARM64, remote
  editor setups, other client versions, or package builds. The fixture uses
  only local modules and bundled `std`, not the external package catalog.

## Rerun the checks

The shared [fixture project](../tests/fixtures/editor-compat/project) uses a
typed YAML patch and a published local recipe. All three integrations use the
[same cases](../tests/fixtures/editor-compat/case.json) on disposable copies.
The fixture also runs over stdio in the portable suite without any editors.

Run the editor checks on Linux x86-64 with Node.js `26.10.0` and npm, the Neovim
and OpenCode hosts in the table, and VS Code's Electron runtime dependencies
and an X display (for headless Linux, prefix the command with `xvfb-run -a`).
Build the candidate `srx`, check out the three clients at the table revisions,
and run `npm ci --ignore-scripts` in `srx-vscode`. The test runner downloads
VS Code `1.90.2` if needed. An existing Linux executable of that same version
can be passed via `VSCODE_TEST_EXECUTABLE`; use `OPENCODE_BIN` if the pinned
OpenCode binary is not first on `PATH`.

From the `srx` checkout with its client checkouts as siblings:

```sh
clients="$PWD/.."
cargo run --locked -p syrox --example check_editors -- \
  --binary "$PWD/target/debug/srx" \
  --vscode "$clients/srx-vscode" \
  --neovim "$clients/srx.nvim" \
  --opencode "$clients/srx-opencode" \
  --hosts
```

Set `--binary` to the release candidate when qualifying a release. The runner
writes command logs and a report with the candidate SHA-256 to
`target/test-evidence/editors-*/`. Without `--hosts`, the VS Code Extension Host
and packaged OpenCode host remain pending. The OpenCode packaged-host test
checks loading and registration, not model-driven tool invocation; the shared
fixture invokes the plugin's tools directly against the real server.
