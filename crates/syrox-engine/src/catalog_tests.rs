//! Pure catalog failure cases, including fixed-origin release parsing.

use super::catalog::{Catalog, CatalogLock, Channel, LockedVersion, PackageVersion};
use std::collections::BTreeMap;

fn channel(policy: &str) -> Channel {
    Channel {
        name: "nginx".into(),
        releases: "https://nginx.org/en/download.html".into(),
        origin: "https://nginx.org/".into(),
        archive_prefix: "nginx-".into(),
        archive_suffix: ".tar.gz".into(),
        signing_key: None,
        key_file: None,
        release_policy: policy.into(),
    }
}

#[test]
fn stable_discovery_excludes_mainline_prerelease_and_overflow_versions() {
    let html = "nginx-1.30.5.tar.gz nginx-1.31.7.tar.gz nginx-1.30.6.tar.gz nginx-1.32.0-rc1.tar.gz nginx-99999999999999999999999.2.tar.gz";
    assert_eq!(
        channel("even-minor").latest(html).as_deref(),
        Some("1.30.6")
    );
    assert_eq!(
        channel("numeric").latest(html).as_deref(),
        Some("1.31.7")
    );
}

#[test]
fn malformed_inventory_is_rejected_before_network_access() {
    let root = tempfile::tempdir().unwrap();
    for text in [
        "schema = 2\ndefaults = {}\nchannels = []\npackages = []",
        "schema = 1\ndefaults = {}\nchannels = []\npackages = []\nunknown = true",
    ] {
        std::fs::write(root.path().join("catalog.toml"), text).unwrap();
        assert!(Catalog::load(root.path()).is_err());
    }
}

fn lock(identity: &str) -> CatalogLock {
    CatalogLock {
        schema: 1,
        index_sha256: "a".repeat(64),
        retained: vec![],
        versions: vec![LockedVersion {
            identity: identity.repeat(64),
            inputs: BTreeMap::from([("@signing-authority".into(), "b".repeat(64))]),
            package: PackageVersion {
                name: "nginx".into(),
                version: "1.30.5".into(),
                variant: "minimal".into(),
                system: "linux-x86_64-gnu".into(),
                source_url: "https://nginx.org/download/nginx-1.30.5.tar.gz".into(),
                source_sha256: "c".repeat(64),
                source_maximum_bytes: 2_097_152,
                signature_url: Some("https://nginx.org/download/nginx-1.30.5.tar.gz.asc".into()),
                recipe: "recipe.srx".into(),
                factory: "nginx".into(),
                export: "nginx_1_30_5".into(),
                source: "source.srx".into(),
                contract: "contract.srx".into(),
                contract_type: "Settings".into(),
                toolchain: "toolchain.toml".into(),
                recipe_inputs: vec![],
            },
        }],
    }
}

#[test]
fn successive_recipe_revisions_preserve_every_previous_identity() {
    let first = lock("1");
    let mut second = lock("2");
    second.retain_previous(&first, false).unwrap();
    let mut third = lock("3");
    third.retain_previous(&second, false).unwrap();
    third.preserves(&first).unwrap();
    third.preserves(&second).unwrap();
    assert_eq!(third.retained.len(), 2);
}

#[test]
fn removing_a_combination_or_replacing_upstream_content_is_rejected() {
    let previous = lock("1");
    let mut removed = lock("2");
    removed.versions.clear();
    assert!(removed.retain_previous(&previous, true).is_err());
    let mut changed = lock("2");
    changed.versions[0].package.source_sha256 = "d".repeat(64);
    assert!(changed.retain_previous(&previous, true).is_err());
}

#[test]
fn signing_authority_changes_require_explicit_admission() {
    let previous = lock("1");
    let mut changed = lock("2");
    changed.versions[0]
        .inputs
        .insert("@signing-authority".into(), "d".repeat(64));
    assert!(changed.retain_previous(&previous, false).is_err());
    changed.retain_previous(&previous, true).unwrap();
    changed.preserves(&previous).unwrap();
}

#[test]
fn factory_must_return_the_contract_registered_in_the_inventory() {
    let root = tempfile::tempdir().unwrap();
    let package = lock("1").versions.remove(0).package;
    let catalog = Catalog {
        schema: 1,
        defaults: BTreeMap::from([("nginx".into(), "1.30.5".into())]),
        channels: vec![channel("even-minor")],
        packages: vec![package.clone()],
    };
    std::fs::write(
        root.path().join("catalog.toml"),
        toml::to_string(&catalog).unwrap(),
    )
    .unwrap();
    std::fs::write(
        root.path().join("source.srx"),
        format!(
            "\"{}\" \"{}\"",
            package.source_url, package.source_sha256
        ),
    )
    .unwrap();
    std::fs::write(
        root.path().join("contract.srx"),
        "pub struct Settings {}",
    )
    .unwrap();
    std::fs::write(root.path().join("toolchain.toml"), "").unwrap();
    let factory = "pub fn nginx() -> std::PackageRef<contract::Settings> { missing() }";
    std::fs::write(root.path().join("recipe.srx"), factory).unwrap();
    assert!(catalog.lock(root.path()).is_ok());
    std::fs::write(
        root.path().join("recipe.srx"),
        factory.replace("contract::Settings", "other::Settings"),
    )
    .unwrap();
    assert!(catalog.lock(root.path()).is_err());
}

fn release_catalog() -> Catalog {
    let gnu = lock("1").versions.remove(0).package;
    let mut musl = gnu.clone();
    musl.system = "linux-x86_64-musl".into();
    Catalog {
        schema: 2,
        defaults: BTreeMap::from([("nginx".into(), "1.30.5".into())]),
        channels: vec![channel("even-minor")],
        packages: vec![gnu, musl],
    }
}

#[test]
fn release_schema_stores_one_origin_and_explicit_combinations() {
    let catalog = release_catalog();
    let text = toml::to_string(&catalog).unwrap();
    assert_eq!(text.matches("source_url =").count(), 1);
    assert_eq!(
        text.matches("[[releases.combinations]]").count(),
        2
    );
    assert_eq!(toml::from_str::<Catalog>(&text).unwrap(), catalog);
    let mut inconsistent = catalog;
    inconsistent.packages[1].source = "other.srx".into();
    assert!(inconsistent.validate().is_err());
}

#[test]
fn generated_release_data_is_deterministic_and_contract_sensitive() {
    let root = tempfile::tempdir().unwrap();
    let catalog = release_catalog();
    std::fs::write(
        root.path().join("contract.srx"),
        "pub struct Settings {}\n",
    )
    .unwrap();
    std::fs::write(
        root.path().join("recipe.srx"),
        "// shared recipe\n",
    )
    .unwrap();
    catalog
        .generate_releases(root.path(), false)
        .unwrap();
    catalog
        .generate_releases(root.path(), true)
        .unwrap();
    let original = std::fs::read(root.path().join("source.srx")).unwrap();
    let mut reordered = catalog.clone();
    reordered.packages.reverse();
    reordered
        .generate_releases(root.path(), false)
        .unwrap();
    assert_eq!(
        original,
        std::fs::read(root.path().join("source.srx")).unwrap()
    );
    std::fs::write(
        root.path().join("contract.srx"),
        "pub struct Settings { port: std::Port; }\n",
    )
    .unwrap();
    assert!(
        catalog
            .generate_releases(root.path(), true)
            .is_err()
    );
    catalog
        .generate_releases(root.path(), false)
        .unwrap();
    assert_ne!(
        original,
        std::fs::read(root.path().join("source.srx")).unwrap()
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("recipe.srx")).unwrap(),
        "// shared recipe\n"
    );
}
