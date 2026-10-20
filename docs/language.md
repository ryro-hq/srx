# Language reference

These examples are complete source files in [`examples/language`](../examples/language).
The `language_reference` CLI test checks their formatting, their source diagnostics
and the exact examples printed here. Run it with:

```sh
cargo test --locked -p syrox --no-default-features --test language_reference
```

## Names, bindings and literals

The public interface of authenticated `std` is a prelude. Write `Recipe`,
`BuildStep::Run` or `package_traits::Package` directly. `std::Recipe` remains
available. Local declarations and explicit `use` imports take precedence over
prelude names. `--std none` supplies no implicit names.

A `value` declares a nominal scalar type. Literals acquire their expected type;
`Port` and another integer-backed value type remain distinct. Refinements check
literal ranges and known values. Struct fields may have computed defaults.
Anonymous records require an expected struct type.

Module `let` bindings are immutable, private by default, independent of textual
order and shared within one evaluation session. Use `pub let` to export a
binding and `let name: Type = expression;` when an annotation helps inference.
Cycles are errors. Function/block bindings use the same literal contextualization.

<!-- example: bindings.srx -->

```srx
value Port(int) where 1 ..= 65535;
struct Settings {
    port: Port = fallback;
    label: ConfigText = "web";
}
let settings: Settings = {
    port = 8080;
};
let fallback: Port = 3000;
pub let label: ConfigText = "${settings.label}:${settings.port}";
outputs {
    result: ConfigText = label;
}
```

## Functions and records

A call with one record argument can use parentheses or braces directly. Names,
qualified functions, namespace calls and callable bindings follow the same rule.
`Settings { listen = 8080; }` constructs a struct; `make { listen = 8080; }`
passes a record to the resolved callable. This distinction follows name
resolution, not spelling or capitalization. Calls with several arguments use
parentheses. Explicit generic arguments use `function<Type>(argument)`.

<!-- example: calls.srx -->

```srx
struct Settings {
    listen: ListenPort = 8080;
}
value ListenPort(int) where 1 ..= 65535;
fn make(settings: Settings) -> Settings {
    settings
}
mod api {
    pub fn make(settings: Settings) -> Settings {
        settings
    }
}
let callback: fn(Settings) -> Settings = make;
let a = make({
        listen = 8080;
    });
let b = make {
    listen = 8081;
};
let c = api::make {
    listen = 8082;
};
let d = api.make {
    listen = 8083;
};
let e = callback {
    listen = 8084;
};
outputs {
    result: ConfigText = "${a.listen},${b.listen},${c.listen},${d.listen},${e.listen}";
}
```

## Platform conditions and specialization

Use `if condition { expression } else { expression }`, or `match` with typed
patterns. With known conditions, module initializers and configuration values
check the selected branch's contract. Every branch must still parse and resolve
its names. Pattern types and duplicate patterns are validated before selection.
An unknown condition checks every branch normally.

A `const` parameter specializes a recipe or selector using known arguments.
Its result may depend on the selected branch, including nominal settings types.
An unsupported known selection fails at the external call, before acquisition.
Ordinary functions require compatible branch types and normal match coverage.
Use this distinction to keep unsupported package calls behind a platform condition.

<!-- example: selection.srx -->

```srx
struct GnuSettings {
    listen: Port;
}
struct MuslSettings {
    socket: ConfigText;
}
value Port(int) where 1 ..= 65535;
value Libc(str);
fn select(const libc: Libc) -> _ {
    match libc {
        "gnu" => GnuSettings {
            listen = 8080;
        },
        "musl" => MuslSettings {
            socket = "/tmp/web.sock";
        },
    }
}
let libc: Libc = "musl";
let settings = if libc == "musl" {
    select("musl")
}
else {
    select("gnu")
};
outputs {
    result: ConfigText = settings.socket;
}
```

## Lazy recipes and public package references

A `Recipe` describes acquisition, typed build steps and declared commands.
Evaluation constructs plans; execution occurs only through an explicit CLI
consumer. A `RecipeRef<Recipe>` defers a factory and memoizes its result.
Aliases retain the same identity; calling `recipe_ref` twice creates two instances.
Select outputs with `recipe_output`, and commands with `recipe_command`.
A public recipe reference is available to `srx info .#example`. Add acquisition,
a build program and declared outputs before selecting it in an `Os`/`Shell`
consumer or running `srx build .#example`. Locks are required before planning or
realization.

<!-- example: recipes.srx -->

```srx
fn make() -> Recipe {
    Recipe {
        package = Package {
            id = "example";
            dependencies = [];
        };
    }
}
pub let example = recipe_ref(make);
pub let alias = example;
outputs {
    reference: RecipeRef<Recipe> = alias;
}
```

## Modules and public interfaces

Use `inputs { pkgs = "path:../syrox-pkgs"; }` to consume another locked project.
`modules:recipes` maps recipe files into modules. A directory's `package.srx`
defines that directory's module; other files define named child modules.
`pub use` reexports a name without duplicating its identity. A private declaration
stays private across project boundaries. `std` qualification always resolves to
its authenticated source, even when a local name shadows a prelude entry.

Traits declare associated types and static method signatures. Implementations
provide every required method. A bound such as `<P: package_traits::Package>`
allows referring to `P::Settings` and dispatching `P::reference(package)`.
For ordinary catalog packages, the typed `templates::configured::Definition<C>`
helper constructs `PackageRef<C>` directly; a separate trait adapter per platform
is unnecessary. Keep custom traits for interfaces that need additional operations.

## Resources and effects

`resource` introduces an affine scalar: it cannot be duplicated or reused after
consumption. Structs containing affine fields inherit that restriction. Global
initializers must be reusable and cannot consume affine resources. The checker
also follows invoked callbacks and reports the initializer and call path. Creating
a closure is deferred work; a factory may consume a resource when a permitted
consumer invokes it. The evaluator repeats the global-initializer safeguard.
The callback analysis is bounded and conservative: an initializer whose invoked
callback cannot be identified is rejected rather than assumed resource-free.
For example, sorting by interpolated keys can lose a callback's symbolic
identity when it is carried through a fold. Keep that callback choice explicit,
or invoke it in the appropriate output consumer instead of a global initializer.

A `RecipeRef` is reusable and lazy. Share one binding for a dependency used by
several packages. Do not eagerly evaluate `recipe_value` into a global when that
factory performs affine work; retain the reference until the consumer needs it.

## Maintaining several package versions

Select the platform once with `pkgs.forPlatform { system = "linux-x86_64"; }`.
GNU is the default; `libc = "musl";` selects musl. Inspect
`packages.platform.system`, `packages.platform.libc` and `packages.buildPlatform`
in conditions. `linux-aarch64` can be represented, but this catalog has no ARM64
package implementations. Tooling currently uses Linux x86_64 GNU.

Keep exact source releases in `releases.srx`, platform differences in `variants.srx`
and builds in `build.srx`/`steps.srx`. Reuse one settings contract when its meaning
is unchanged; add a new nominal contract when the accepted configuration changes.
A new version adds verified source metadata and compatibility data, rather than
copying the package tree. The catalog's `docs/recipes.md` explains authoring,
source verification and qualification. Existing full target tags, historical lock
entries and release evidence remain intact when source organization changes.

`PackageRef<C>` binds the chosen recipe to settings type `C`. Thus
`services.nginx = { package = packages.nginx { version = "1.30.6"; };
settings = { listen = 8080; }; };` checks settings against that exact selection.
Unknown versions, contradictory platform overrides and unsupported targets fail
before source acquisition. Formatting and editor analysis perform no downloads.
