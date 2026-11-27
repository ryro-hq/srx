use super::{
    Catalog, CatalogError, Channel,
    files::{bounded_file, invalid},
};
use crate::store::ContentDigest;
use std::{collections::BTreeSet, fs, path::Path};

impl Catalog {
    pub fn verify_sources(&self, root: &Path) -> Result<Vec<String>, CatalogError> {
        self.validate()?;
        let mut checked = BTreeSet::new();
        let mut evidence = Vec::new();
        for package in &self.packages {
            if !checked.insert((&package.name, &package.version)) {
                continue;
            }
            let channel = self
                .channels
                .iter()
                .find(|channel| channel.name == package.name)
                .expect("validated channel");
            let bytes = download(
                &package.source_url,
                package.source_maximum_bytes,
                channel,
            )?;
            if ContentDigest::sha256(&bytes).to_string() != package.source_sha256 {
                return Err(invalid(
                    "existing upstream version has changed content",
                ));
            }
            if let Some(signature) = &package.signature_url {
                let signature = download(signature, 64 * 1024, channel)?;
                verify_signature(root, channel, &bytes, &signature)?;
                evidence.push(format!(
                    "{} {} sha256={} signing-key={}",
                    package.name,
                    package.version,
                    package.source_sha256,
                    channel.signing_key.as_deref().unwrap_or_default()
                ));
            } else {
                evidence.push(format!(
                    "{} {} sha256={} provenance=official-https",
                    package.name, package.version, package.source_sha256
                ));
            }
        }
        Ok(evidence)
    }
}

pub(super) fn redirect_origins(channel: &Channel) -> Result<Vec<url::Origin>, CatalogError> {
    use crate::acquire::https::validate_https_origin;

    if channel.redirect_origins.len() > 8
        || (!channel.redirect_origins.is_empty() && channel.signing_key.is_none())
    {
        return Err(invalid(
            "only signed channels may pin up to eight redirect origins",
        ));
    }
    let root = url::Url::parse(&channel.origin).map_err(|error| invalid(error.to_string()))?;
    let mut origins = vec![root.origin()];
    for value in &channel.redirect_origins {
        let origin = validate_https_origin(value).map_err(|error| invalid(error.to_string()))?;
        if origins.contains(&origin) {
            return Err(invalid("duplicate channel redirect origin"));
        }
        origins.push(origin);
    }
    Ok(origins)
}

pub(super) fn download(url: &str, limit: u64, channel: &Channel) -> Result<Vec<u8>, CatalogError> {
    let host = url::Url::parse(&channel.origin).map_err(|error| invalid(error.to_string()))?;
    let initial = url::Url::parse(url).map_err(|error| invalid(error.to_string()))?;
    if initial.origin() != host.origin() {
        return Err(invalid(
            "download URL is outside the channel origin",
        ));
    }
    let host = host
        .host_str()
        .ok_or_else(|| invalid("origin has no host"))?;
    let hosts = [host];
    let origins = redirect_origins(channel)?;
    crate::acquire::https::download_authenticated(
        crate::acquire::https::DownloadRequest {
            url,
            maximum_bytes: limit,
            policy: crate::acquire::https::HttpsTransportPolicy::default(),
            test_certificate: None,
            accept: None,
            hosts: channel
                .redirect_origins
                .is_empty()
                .then_some(&hosts[..]),
            redirect_origins: Some(&origins),
        },
        std::time::Instant::now(),
        &crate::cancellation::Cancellation::default(),
    )
    .map_err(|error| invalid(error.to_string()))
}

pub(super) fn verify_signature(
    root: &Path,
    channel: &Channel,
    archive: &[u8],
    signature: &[u8],
) -> Result<(), CatalogError> {
    let fingerprint = channel
        .signing_key
        .as_deref()
        .ok_or_else(|| invalid("signature has no previously pinned signing key"))?;
    let key_file = channel
        .key_file
        .as_deref()
        .ok_or_else(|| invalid("signature has no pinned key file"))?;
    let home = tempfile::tempdir()?;
    let key = home.path().join("key.asc");
    let source = home.path().join("source");
    let detached = home.path().join("signature");
    fs::write(&key, bounded_file(root, key_file)?)?;
    fs::write(&source, archive)?;
    fs::write(&detached, signature)?;
    let import = std::process::Command::new("gpg")
        .arg("--no-autostart")
        .args(["--no-options", "--batch", "--homedir"])
        .arg(home.path())
        .arg("--import")
        .arg(key)
        .output()?;
    if !import.status.success() {
        return Err(invalid("pinned key import failed"));
    }
    let verification = std::process::Command::new("gpg")
        .args([
            "--no-options",
            "--batch",
            "--no-auto-key-retrieve",
            "--homedir",
        ])
        .arg(home.path())
        .args(["--status-fd", "1", "--verify"])
        .arg(detached)
        .arg(source)
        .output()?;
    let status = std::str::from_utf8(&verification.stdout)
        .map_err(|_| invalid("invalid verifier status"))?;
    let valid = status.lines().any(|line| {
        line.strip_prefix("[GNUPG:] VALIDSIG ")
            .is_some_and(|fields| fields.split_whitespace().last() == Some(fingerprint))
    });
    if !verification.status.success() || !valid {
        return Err(invalid(
            "signature rejected or signing key changed",
        ));
    }
    Ok(())
}
