use super::{Action, AdmittedBudget, BuildError, BuildProfile, InputIdentity};
use crate::{
    build::BuildProgram, result::OutputOrigin, store::ContentDigest, system::budget::BuildBudget,
};
use serde::{Deserialize, Serialize};

const HEADER: &[u8] = b"syrox-system-build-action-v1\n";
const PROFILE: &str = "syrox-system-managed-x86_64-v1";
const MAX_BYTES: usize = 2 * crate::build::MAX_BUILD_PROGRAM_BYTES + 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    profile: String,
    source: String,
    source_limit: u64,
    worker: String,
    directory: String,
    inputs: Vec<Input>,
    program: String,
    budget: BuildBudget,
    policy: String,
    output_protocol: String,
    settlement: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    origin: String,
    origin_pin: String,
    action: String,
    artifact: String,
    output: String,
}

/// Versioned effective System action, distinct from ordinary v5 actions. Parsing
/// must receive an independently admitted budget and grants no Plan membership,
/// worker authenticity or execution authority. It cannot enter a legacy worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemBuildAction {
    template: Action,
    source_limit: u64,
    budget: AdmittedBudget,
}

impl SystemBuildAction {
    pub(in crate::build) fn new(
        template: Action,
        source_limit: u64,
        budget: AdmittedBudget,
    ) -> Result<Self, BuildError> {
        template.program.validate()?;
        if template.program.profile != BuildProfile::Managed
            || template.toolchain.is_some()
            || source_limit == 0
            || source_limit > crate::store::MAX_STORE_BLOB_BYTES
            || source_limit > budget.request().scratch_bytes
            || !crate::build::relative_path(&template.directory)
            || template.directory.contains('/')
            || template.inputs.len() > 64
            || template
                .inputs
                .iter()
                .any(|i| !crate::result::valid_name(&i.output))
            || template
                .program
                .input_indices()
                .iter()
                .any(|i| usize::try_from(*i).expect("bounded input") >= template.inputs.len())
        {
            return Err(BuildError::InvalidRequest);
        }
        let action = Self {
            template,
            source_limit,
            budget,
        };
        if action.encode().len() > MAX_BYTES {
            return Err(BuildError::InvalidRequest);
        }
        Ok(action)
    }

    pub fn digest(&self) -> ContentDigest {
        ContentDigest::sha256(&self.encode())
    }
    pub const fn budget(&self) -> &AdmittedBudget {
        &self.budget
    }
    pub const fn source_limit(&self) -> u64 {
        self.source_limit
    }
    pub const fn source_digest(&self) -> ContentDigest {
        self.template.source
    }
    pub const fn worker_digest(&self) -> ContentDigest {
        self.template.worker
    }
    pub const fn program(&self) -> &BuildProgram {
        &self.template.program
    }
    pub fn source_directory(&self) -> &str {
        &self.template.directory
    }
    pub(in crate::build) fn selected_inputs(&self) -> &[InputIdentity] {
        &self.template.inputs
    }

    pub fn encode(&self) -> Vec<u8> {
        let wire = Wire {
            profile: PROFILE.into(),
            source: self.template.source.to_string(),
            source_limit: self.source_limit,
            worker: self.template.worker.to_string(),
            directory: self.template.directory.clone(),
            inputs: self
                .template
                .inputs
                .iter()
                .map(|i| Input {
                    origin: match i.origin {
                        OutputOrigin::Built {
                            ..
                        } => "built",
                        OutputOrigin::Imported {
                            ..
                        } => "imported",
                    }
                    .into(),
                    origin_pin: crate::build::records::origin_pin(&i.origin).to_string(),
                    action: i.action.to_string(),
                    artifact: i.artifact.to_string(),
                    output: i.output.clone(),
                })
                .collect(),
            program: syrox_encoding::hex(&self.template.program.encode()),
            budget: *self.budget.request(),
            policy: syrox_encoding::hex(self.budget.policy_fingerprint()),
            output_protocol: "syrox-system-worker-outputs-v1".into(),
            settlement: "subreaper-echild".into(),
        };
        let mut bytes = HEADER.to_vec();
        bytes.extend(serde_json::to_vec(&wire).expect("bounded integer/string action"));
        bytes
    }

    pub fn parse(bytes: &[u8], budget: &AdmittedBudget) -> Result<Self, BuildError> {
        if bytes.len() > MAX_BYTES {
            return Err(BuildError::InvalidRequest);
        }
        let wire: Wire = serde_json::from_slice(
            bytes
                .strip_prefix(HEADER)
                .ok_or(BuildError::InvalidRequest)?,
        )
        .map_err(|_| BuildError::InvalidRequest)?;
        if wire.profile != PROFILE
            || wire.budget != *budget.request()
            || wire.policy != syrox_encoding::hex(budget.policy_fingerprint())
            || wire.output_protocol != "syrox-system-worker-outputs-v1"
            || wire.settlement != "subreaper-echild"
        {
            return Err(BuildError::InvalidRequest);
        }
        if wire.program.len() > 2 * crate::build::MAX_BUILD_PROGRAM_BYTES {
            return Err(BuildError::InvalidRequest);
        }
        let program = BuildProgram::decode(
            &syrox_encoding::decode_lower_hex(&wire.program).ok_or(BuildError::InvalidRequest)?,
        )?;
        let inputs = wire
            .inputs
            .into_iter()
            .map(|i| {
                Ok(InputIdentity {
                    origin: match i.origin.as_str() {
                        "built" => OutputOrigin::Built {
                            receipt: pin(&i.origin_pin)?,
                        },
                        "imported" => OutputOrigin::Imported {
                            manifest: pin(&i.origin_pin)?,
                        },
                        _ => return Err(BuildError::InvalidRequest),
                    },
                    action: pin(&i.action)?,
                    artifact: pin(&i.artifact)?,
                    output: i.output,
                })
            })
            .collect::<Result<_, BuildError>>()?;
        let action = Self::new(
            Action {
                program,
                source: pin(&wire.source)?,
                toolchain: None,
                worker: pin(&wire.worker)?,
                directory: wire.directory,
                inputs,
            },
            wire.source_limit,
            *budget,
        )?;
        if action.encode() != bytes {
            return Err(BuildError::InvalidRequest);
        }
        Ok(action)
    }
}

fn pin(value: &str) -> Result<ContentDigest, BuildError> {
    value
        .parse()
        .map_err(|_| BuildError::InvalidRequest)
}

#[cfg(test)]
mod tests;
