use super::{GenerationError, ManifestResult as Result};
use crate::{result::OutputIdentity, result::OutputOrigin, store::ContentDigest};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

pub(in crate::deployment) const MAX_BYTES: usize = 64 * 1024 * 1024;
pub(in crate::deployment) const MAX_ITEMS: usize = 65_536;
const HEADER: &[u8] = b"syrox-generation-v2\n";
const SHELL_HEADER: &[u8] = b"syrox-shell-session-v2\n";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LauncherIdentity {
    pub(in crate::deployment) digest: String,
    pub(in crate::deployment) protocol: u32,
}
impl LauncherIdentity {
    pub(crate) fn new(digest: ContentDigest, protocol: u32) -> Result<Self> {
        if protocol != 1 {
            return Err(GenerationError::Invalid(
                "unsupported launcher protocol",
            ));
        }
        Ok(Self {
            digest: digest.to_string(),
            protocol,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::deployment) struct Output {
    pub action: String,
    pub origin: Origin,
    pub artifact: String,
    #[serde(rename = "output")]
    pub name: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::deployment) enum Origin {
    Built {
        receipt: String,
    },
    Imported {
        manifest: String,
    },
}
impl Output {
    pub fn from_identity(identity: &OutputIdentity) -> Self {
        Self {
            action: identity.action.to_string(),
            origin: match identity.origin {
                OutputOrigin::Built {
                    receipt,
                } => Origin::Built {
                    receipt: receipt.to_string(),
                },
                OutputOrigin::Imported {
                    manifest,
                } => Origin::Imported {
                    manifest: manifest.to_string(),
                },
            },
            artifact: identity.artifact.to_string(),
            name: identity.output.clone(),
        }
    }
    pub fn key(&self) -> Result<String> {
        Ok(ContentDigest::sha256(&serde_json::to_vec(self)?).to_string())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::deployment) struct Provenance {
    pub label: String,
    pub path: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::deployment) struct Selection {
    pub service: Option<String>,
    pub output: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::deployment) struct Role {
    pub output: String,
    pub path: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(in crate::deployment) enum Argument {
    StateDirectory,
    SecretFile(String),
    Literal(String),
    File(String),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::deployment) struct Invocation {
    pub service: Option<String>,
    pub name: String,
    pub application: Role,
    pub loader: Option<Role>,
    pub libraries: BTreeSet<String>,
    pub arguments: Vec<Argument>,
    pub environment: BTreeMap<String, Argument>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::deployment) struct Config {
    pub service: String,
    pub path: String,
    pub text: String,
    pub digest: String,
    pub mode: u32,
}

/// Structural integrity and a matching content pin do not admit a generation or
/// verify its output bytes. Only freeze has a live verified preparation behind it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::deployment) struct Process {
    pub command: String,
    pub restart: crate::execution::restart::ProcessRestart,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GenerationManifest {
    pub(in crate::deployment) launcher: LauncherIdentity,
    pub(in crate::deployment) outputs: BTreeMap<String, Output>,
    pub(in crate::deployment) provenance: BTreeMap<String, BTreeSet<Provenance>>,
    pub(in crate::deployment) services: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(in crate::deployment) session_states: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(in crate::deployment) secrets: BTreeMap<String, BTreeSet<String>>,
    pub(in crate::deployment) selections: BTreeSet<Selection>,
    pub(in crate::deployment) commands: BTreeMap<String, Invocation>,
    pub(in crate::deployment) exposures: BTreeMap<String, String>,
    pub(in crate::deployment) configs: BTreeMap<String, Config>,
    pub(in crate::deployment) processes: BTreeMap<String, Process>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(in crate::deployment) validators: BTreeSet<String>,
}
impl GenerationManifest {
    pub(in crate::deployment) fn empty(launcher: LauncherIdentity) -> Self {
        Self {
            launcher,
            outputs: BTreeMap::new(),
            provenance: BTreeMap::new(),
            services: BTreeSet::new(),
            session_states: BTreeSet::new(),
            secrets: BTreeMap::new(),
            selections: BTreeSet::new(),
            commands: BTreeMap::new(),
            exposures: BTreeMap::new(),
            configs: BTreeMap::new(),
            processes: BTreeMap::new(),
            validators: BTreeSet::new(),
        }
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.canonical_with_header(HEADER)
    }
    fn canonical_with_header(&self, header: &[u8]) -> Result<Vec<u8>> {
        if header == SHELL_HEADER
            && self
                .processes
                .values()
                .any(|process| process.restart != crate::execution::restart::ProcessRestart::Never)
        {
            return Err(GenerationError::Invalid(
                "Shell process restart is unsupported",
            ));
        }
        if header == HEADER && (!self.session_states.is_empty() || !self.secrets.is_empty()) {
            return Err(GenerationError::Invalid(
                "session state and secrets are not supported by Os",
            ));
        }
        super::validate_manifest::manifest(self)?;
        let mut writer = BoundedWriter(header.to_vec());
        serde_json::to_writer(&mut writer, self)?;
        Ok(writer.0)
    }
    pub(crate) fn decode_bounded(bytes: &[u8], expected_pin: ContentDigest) -> Result<Self> {
        Self::decode_with_header(bytes, expected_pin, HEADER)
    }
    fn decode_with_header(
        bytes: &[u8],
        expected_pin: ContentDigest,
        header: &[u8],
    ) -> Result<Self> {
        if bytes.len() > MAX_BYTES {
            return Err(GenerationError::Invalid(
                "generation byte bound exceeded",
            ));
        }
        if ContentDigest::sha256(bytes) != expected_pin {
            return Err(GenerationError::Invalid(
                "generation pin mismatch",
            ));
        }
        let json = bytes
            .strip_prefix(header)
            .ok_or(GenerationError::Invalid(
                "unsupported generation version",
            ))?;
        json_budget(json)?;
        let manifest: Self = serde_json::from_slice(json)?;
        if manifest.canonical_with_header(header)? != bytes {
            return Err(GenerationError::Invalid(
                "noncanonical generation encoding",
            ));
        }
        Ok(manifest)
    }
}
/// A structurally verified Shell snapshot remains inert data. Its distinct wire
/// domain prevents it from being accepted as an Os generation or vice versa.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ShellSessionManifest {
    operational: GenerationManifest,
}
impl ShellSessionManifest {
    pub(in crate::deployment) const fn new(operational: GenerationManifest) -> Self {
        Self {
            operational,
        }
    }
    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.operational
            .canonical_with_header(SHELL_HEADER)
    }
    pub(crate) fn decode_bounded(bytes: &[u8], expected_pin: ContentDigest) -> Result<Self> {
        Ok(Self::new(GenerationManifest::decode_with_header(
            bytes,
            expected_pin,
            SHELL_HEADER,
        )?))
    }
}

struct BoundedWriter(Vec<u8>);
impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_BYTES - self.0.len() {
            return Err(io::Error::other("generation byte bound exceeded"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(in crate::deployment) fn command_key(service: Option<&str>, name: &str) -> String {
    service.map_or_else(
        || format!("root/{name}"),
        |service| format!("service/{service}/{name}"),
    )
}

// Bound structural allocations before serde constructs maps or vectors. Text
// payloads are separately bounded by MAX_BYTES and validated config budgets.
fn json_budget(bytes: &[u8]) -> Result<()> {
    let mut string = false;
    let mut escaped = false;
    let mut depth = 0usize;
    let mut nodes = 0usize;
    for byte in bytes {
        if string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                string = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                string = true;
                nodes += 1;
            }
            b'{' | b'[' => {
                depth += 1;
                nodes += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
            }
            b',' => nodes += 1,
            _ => {}
        }
        if depth > 16 || nodes > MAX_ITEMS * 16 {
            return Err(GenerationError::Invalid(
                "generation structural allocation bound exceeded",
            ));
        }
    }
    Ok(())
}
