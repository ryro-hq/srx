# Migrating Os declarations and commands to Services

The service manager now uses `Services` in `.srx` and `srx services` on the CLI.
`Os`, `std::Os`, `std::deployment::Os` and the `srx os` command are removed.
This change frees the name `Os` for the planned full-system and
host-configuration contracts.

## Project declarations

Replace the type and constructor, including imports and function signatures:

```srx
outputs {
    os: Services = Services {
        pkgs = [];
        services = [];
    };
}
```

The qualified names are `std::Services` and `std::deployment::Services`. Keep
the output name (`os` above) so existing profile selectors continue to work.
The `services.NAME = { ... };` shorthand still produces the output named `os`,
now with type `Services`. Its settings and package integration are unchanged.
Package and module identifiers that happen to contain `os` do not need renaming.

Update any local dependency that exposes the old contract, including a catalog
checkout, before checking the consumer. With the new executable, check and lock
changed dependency projects first, then the root project:

```sh
srx project check .
srx project lock .
srx project lock --check .
srx project plan . --output os
```

The bundled standard library has a new identity. Its pin must be updated with
the explicit `project lock` command, even for projects that only use `Shell`.
Profile apply's automatic root-file refresh rejects an old standard-library pin
and leaves the lock untouched. Locking does not build packages or apply services.

## Commands and existing installations

Replace the command prefix in scripts and interactive use:

| Former command | Current command |
|---|---|
| `srx os init .#os --name web --user` | `srx services init .#os --name web --user` |
| `srx os prepare .#os …` | `srx services prepare .#os …` |
| `srx os apply --profile web` | `srx services apply --profile web` |
| `srx os status --profile web` | `srx services status --profile web` |
| `srx os logs nginx --profile web` | `srx services logs nginx --profile web` |
| `srx os stop --profile web` | `srx services stop --profile web` |
| `srx os rollback PIN --profile web` | `srx services rollback PIN --profile web` |
| `srx os recover --profile web` | `srx services recover --profile web` |

The same prefix change applies to `list`, `inspect`, `diff` and `abandon`.
There is no compatibility alias for the former command.

Existing version-1 profiles keep their schema and paths:

- `$XDG_CONFIG_HOME/syrox/os/NAME.json` (default `~/.config/syrox/os/NAME.json`).
- `$XDG_STATE_HOME/syrox/os/NAME/` (default `~/.local/state/syrox/os/NAME/`).

Use the existing profile directly; do not rerun `init` or move its state.
Installation identities, ownership, retained generations, journals and launcher
protocols keep their existing formats. Recorded status and list do not need a
migrated project or a refreshed lock. Recovery continues to use the explicit
manager and identity checks described in [installation profiles](../os-profiles.md).

Previously published artifacts keep their content identities. New builds remain
subject to the current authenticated inputs and produce their corresponding
identities; this migration does not rewrite old artifacts or journals.

## Engine callers and authority

Rust callers must replace `PlanConsumerKind::Os` with
`PlanConsumerKind::Services`. The existing `deployment::os` module, `OsProfile`
and other `Os`-prefixed engine handles remain at their current Rust paths in
this increment. Their persistence and execution protocols have not been renamed.

Services still require the existing matching non-root execution identity.
Systemd system scope continues to require its existing delegated authority.
This migration adds no authority to manage disks, boot entries, kernel settings
or full-system generations.
