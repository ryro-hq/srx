//! Inspect and reconcile retained scratch evidence without formatting or detaching.
//!
//! Recovery changes only the journal, after independent proof of quiescence and
//! an exact plan-hash match. Missing evidence remains uncertain.

use super::{journal::Journal, policy::refused, wire};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt as _;

mod evidence;
mod runtime;
mod workspace;

pub(super) use workspace::serve as serve_workspace;

#[cfg(test)]
mod tests;

pub(super) fn runtime() -> io::Result<serde_json::Value> {
    Ok(serde_json::to_value(runtime::Runtime::observe()?)?)
}

#[derive(Debug, Serialize)]
pub(super) struct Plan {
    version: u32,
    id: String,
    action: &'static str,
    reasons: Vec<&'static str>,
    policy_sha256: String,
    journal_sha256: String,
    operation: evidence::Identity,
    state_directory: evidence::Identity,
    image: Option<evidence::Identity>,
    boot_id: String,
    pid_namespace: u64,
    original_session: runtime::Runtime,
    loop_observation: Option<serde_json::Value>,
    image_retained: bool,
    filesystem_health_verified: bool,
}

impl Plan {
    pub fn sha256(&self) -> io::Result<String> {
        let mut hash = Sha256::new();
        hash.update(b"syrox-private-scratch-recovery-plan-v1\n");
        hash.update(serde_json::to_vec(self)?);
        Ok(crate::hex(&hash.finalize()))
    }
}

pub(super) fn inspect(
    state: &File,
    id: &str,
    policy_sha256: [u8; 32],
) -> io::Result<(Plan, File, u32)> {
    let evidence = evidence::load(state, &format!("op-{id}"))?;
    if evidence.records[0].details["request"]["operation"] == "prepare_workspace" {
        return Err(refused(
            "workspace recovery requires its separate inspection operation",
        ));
    }
    let now = runtime::Runtime::observe()?;
    let mut reasons = Vec::new();
    let origin: runtime::Runtime =
        serde_json::from_value(evidence.records[0].details["runtime"].clone())?;
    if !origin.previous_session_ended(&now)? {
        reasons.push("original helper session is still alive");
    }
    if evidence
        .records
        .iter()
        .any(|r| matches!(r.state.as_str(), "released" | "reconciled"))
    {
        reasons.push("operation already has a terminal record");
    }
    let mut tool_pending = None;
    for record in &evidence.records {
        if record.state == "tool-intent" {
            if tool_pending.is_some() {
                return Err(refused("overlapping scratch tool intents"));
            }
            tool_pending = Some(
                record.details["stage"]
                    .as_str()
                    .ok_or_else(|| refused("missing tool stage"))?,
            );
        } else if record.state == "tool-result" {
            if tool_pending != record.details["stage"].as_str() || tool_pending.is_none() {
                return Err(refused("unmatched scratch tool result"));
            }
            tool_pending = None;
        }
    }
    if tool_pending.is_some() {
        reasons.push("tool exit was not recorded; quiescence is unproven");
    }
    let allocated = evidence
        .records
        .iter()
        .filter(|r| r.state == "image-allocated")
        .collect::<Vec<_>>();
    let image = if allocated.len() == 1 {
        let image = evidence::open(&evidence.directory, "scratch.img", false)?;
        let identity = evidence::Identity::read(&image, evidence.identity.uid, false)?;
        let record = &allocated[0].details;
        if record["device"].as_u64() != Some(identity.device)
            || record["inode"].as_u64() != Some(identity.inode)
            || record["bytes"].as_u64() != Some(identity.bytes)
        {
            return Err(refused(
                "scratch image identity changed since allocation",
            ));
        }
        Some(identity)
    } else {
        reasons.push("scratch allocation identity is missing or ambiguous");
        None
    };
    let intents = evidence
        .records
        .iter()
        .filter(|r| r.state == "loop-configure-intent")
        .collect::<Vec<_>>();
    let loop_observation = if intents.len() == 1 {
        let number = intents[0].details["loop_number"]
            .as_u64()
            .filter(|n| u32::try_from(*n).is_ok())
            .ok_or_else(|| refused("invalid recorded loop number"))?;
        if runtime::bounded("/sys/module/loop/parameters/max_part")? != b"0\n" {
            return Err(refused("loop partition scanning policy changed"));
        }
        let base = format!("/sys/dev/block/7:{number}");
        let backing_present =
            std::path::Path::new(&format!("{base}/loop/backing_file")).try_exists()?;
        let size = runtime::bounded(&format!("{base}/size"))?;
        if backing_present || size != b"0\n" {
            reasons.push("recorded loop has not completed teardown");
        }
        Some(
            serde_json::json!({ "number": number, "backing_present": backing_present,
            "size_sectors": std::str::from_utf8(&size).map_err(|_| refused("invalid loop size"))? }),
        )
    } else if intents.is_empty() {
        None
    } else {
        return Err(refused("ambiguous loop configuration intents"));
    };
    let plan = Plan {
        version: 1,
        id: id.to_owned(),
        action: if reasons.is_empty() {
            "reconcile-retained-image"
        } else {
            "blocked"
        },
        reasons,
        policy_sha256: crate::hex(&policy_sha256),
        journal_sha256: evidence.sha256,
        operation: evidence.identity,
        state_directory: evidence::Identity::read(
            state,
            evidence.directory.metadata()?.uid(),
            true,
        )?,
        image,
        boot_id: now.boot_id,
        pid_namespace: now.pid_namespace,
        original_session: origin,
        loop_observation,
        image_retained: true,
        filesystem_health_verified: false,
    };
    Ok((
        plan,
        evidence.directory,
        u32::try_from(evidence.records.len()).expect("evidence::load admits at most 64 records"),
    ))
}

pub(super) fn serve(
    socket: &File,
    state: &File,
    policy_sha256: [u8; 32],
    id: &str,
    authorization: Option<&str>,
) -> io::Result<()> {
    let (plan, directory, sequence) = inspect(state, id, policy_sha256)?;
    let sha256 = plan.sha256()?;
    let Some(authorization) = authorization else {
        return wire::reply_value(
            socket,
            &serde_json::json!({ "version": 1, "plan": plan, "plan_sha256": sha256 }),
        );
    };
    if plan.action != "reconcile-retained-image" || authorization != sha256 {
        return Err(refused(
            "recovery plan is blocked or its authorization changed",
        ));
    }
    if inspect(state, id, policy_sha256)?.0.sha256()? != sha256 {
        return Err(refused(
            "recovery evidence changed during authorization",
        ));
    }
    let mut journal = Journal::resume(directory, sequence);
    let record = journal.record(
        "reconciled",
        serde_json::json!({ "id": id, "plan_sha256": sha256,
        "plan": plan, "image_retained": true, "filesystem_health_verified": false }),
    )?;
    wire::reply(socket, record)
}

pub(super) fn settled(state: &File, name: &str) -> io::Result<bool> {
    let evidence = evidence::load(state, name)?;
    if evidence.records[0].details["request"]["operation"] == "prepare_workspace" {
        return workspace::settled(&evidence);
    }
    let last = evidence
        .records
        .last()
        .expect("evidence::load rejects a journal without its authorization record");
    if last.state == "released" {
        return Ok(true);
    }
    if last.state == "response-undelivered" {
        return Ok(evidence.records.len() >= 2
            && evidence.records[evidence.records.len() - 2].state == "released");
    }
    if last.state == "reconciled" {
        return Ok(last.details["image_retained"] == true
            && last.details["filesystem_health_verified"] == false
            && last.details["plan"]["action"] == "reconcile-retained-image"
            && last.details["plan_sha256"]
                .as_str()
                .is_some_and(|value| super::policy::digest(value).is_ok()));
    }
    Ok(false)
}
