//! Pure catalog failure cases, including fixed-origin release parsing.

use super::catalog::{Catalog, Channel};

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
