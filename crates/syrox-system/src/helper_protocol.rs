//! Versioned scratch-helper requests, shared without language/build dependencies.
//!
//! Decoding grants no authority. The server independently checks kernel peer
//! credentials, administrator policy, versions and resource identities.

use crate::budget::BuildBudget;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Request {
    #[serde(rename = "prepare_workspace")]
    PrepareWorkspace {
        version: u32,
        id: String,
        budget: BuildBudget,
        layout_sha256: String,
    },
    #[serde(rename = "release_workspace")]
    ReleaseWorkspace {
        version: u32,
        id: String,
        authorization: String,
    },
    #[serde(rename = "inspect_workspace")]
    InspectWorkspace {
        version: u32,
        id: String,
    },
    #[serde(rename = "recover_workspace")]
    RecoverWorkspace {
        version: u32,
        id: String,
        plan_sha256: String,
    },
    #[serde(rename = "prepare_scratch")]
    Prepare {
        version: u32,
        id: String,
        budget: BuildBudget,
    },
    #[serde(rename = "release_scratch")]
    Release {
        version: u32,
        id: String,
        authorization: String,
    },
    #[serde(rename = "inspect_scratch")]
    Inspect {
        version: u32,
        id: String,
    },
    #[serde(rename = "recover_scratch")]
    Recover {
        version: u32,
        id: String,
        plan_sha256: String,
    },
}
