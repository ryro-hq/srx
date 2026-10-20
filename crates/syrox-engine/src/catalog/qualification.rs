//! Package-owned qualification descriptions, authenticated by the catalog lock.
use super::{
    CatalogError, PackageVersion,
    files::{bounded_file, invalid},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Qualification {
    pub command: String,
    pub version_arguments: Vec<String>,
    pub http: Option<HttpQualification>,
    pub service: Option<ServiceQualification>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpQualification {
    pub filename: String,
    pub configuration: String,
    pub invalid_configuration: String,
    pub validate_arguments: Vec<String>,
    pub run_arguments: Vec<String>,
    pub response: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceQualification {
    pub project: String,
    pub valid_settings: String,
    pub invalid_settings: String,
}

impl Qualification {
    pub fn load(root: &Path, package: &PackageVersion) -> Result<Self, CatalogError> {
        let Some(path) = &package.qualification else {
            return Ok(Self {
                command: package.name.clone(),
                version_arguments: vec!["--version".into()],
                http: None,
                service: None,
            });
        };
        let bytes = bounded_file(root, path)?;
        let result: Self = toml::from_str(
            std::str::from_utf8(&bytes).map_err(|_| invalid("qualification is not UTF-8"))?,
        )
        .map_err(|error| invalid(error.to_string()))?;
        let arguments = |arguments: &[String]| {
            !arguments.is_empty()
                && arguments.len() <= 64
                && arguments
                    .iter()
                    .all(|arg| arg.len() <= 4096 && !arg.contains('\0'))
        };
        let filename = |name: &str| super::files::component(name) && !matches!(name, "." | "..");
        if !filename(&result.command) || !arguments(&result.version_arguments) {
            return Err(invalid(
                "invalid qualification command or arguments",
            ));
        }
        if let Some(http) = &result.http
            && (!filename(&http.filename)
                || http.filename == "index.html"
                || !arguments(&http.validate_arguments)
                || !arguments(&http.run_arguments)
                || http.response.is_empty()
                || http.response.len() > 1024)
        {
            return Err(invalid("invalid HTTP qualification"));
        }
        for file in result.files() {
            bounded_file(root, file)?;
        }
        Ok(result)
    }

    pub fn files(&self) -> Vec<&str> {
        let mut files = Vec::new();
        if let Some(http) = &self.http {
            files.extend([
                http.configuration.as_str(),
                http.invalid_configuration.as_str(),
            ]);
        }
        if let Some(service) = &self.service {
            files.extend([
                service.project.as_str(),
                service.valid_settings.as_str(),
                service.invalid_settings.as_str(),
            ]);
        }
        files
    }

    pub fn text(root: &Path, path: &str) -> Result<String, CatalogError> {
        String::from_utf8(bounded_file(root, path)?)
            .map_err(|_| invalid("qualification fixture is not UTF-8"))
    }
}
