//! Reconcile only quiescent same-boot two-image attempts; never replay formatting.

use super::{
    evidence::{self, Evidence, Identity},
    runtime,
};
use crate::{
    journal::Journal,
    policy::{digest, refused},
    wire,
};
use sha2::{Digest as _, Sha256};
use std::{fs::File, io, os::unix::fs::MetadataExt as _};
use syrox_system::helper_protocol::Request;

fn request(evidence: &Evidence) -> io::Result<(String, String, syrox_system::budget::BuildBudget)> {
    match serde_json::from_value(evidence.records[0].details["request"].clone())? {
        Request::PrepareWorkspace {
            version: 1,
            id,
            layout_sha256,
            budget,
        } => {
            crate::session::validate_id(&id)?;
            digest(&layout_sha256)?;
            budget.validate().map_err(io::Error::other)?;
            Ok((id, layout_sha256, budget))
        }
        _ => Err(refused(
            "expected original version-1 workspace authorization",
        )),
    }
}

pub(super) fn settled(evidence: &Evidence) -> io::Result<bool> {
    let (id, layout, _) = request(evidence)?;
    let mut last = evidence
        .records
        .last()
        .expect("evidence::load rejects a journal without its authorization record");
    if last.state == "response-undelivered" && evidence.records.len() >= 2 {
        last = &evidence.records[evidence.records.len() - 2];
    }
    if last.state == "released" {
        return Ok(last.details["id"] == id
            && last.details["layout_sha256"] == layout
            && last.details["authorization"] == evidence.records[0].details["authorization"]
            && last.details["images"] == 2
            && last.details["image_retained"] == true);
    }
    if last.state == "reconciled" {
        return Ok(last.details["id"] == id
            && last.details["image_retained"] == true
            && last.details["filesystem_health_verified"] == false
            && last.details["plan"]["action"] == "reconcile-retained-workspace"
            && last.details["plan_sha256"]
                .as_str()
                .is_some_and(|s| digest(s).is_ok()));
    }
    Ok(false)
}

fn inspect(
    state: &File,
    id: &str,
    policy_sha256: [u8; 32],
) -> io::Result<(serde_json::Value, File, u32)> {
    let evidence = evidence::load(state, &format!("op-{id}"))?;
    let (original_id, layout_sha256, budget) = request(&evidence)?;
    if original_id != id {
        return Err(refused(
            "workspace journal ID differs from directory",
        ));
    }
    let now = runtime::Runtime::observe()?;
    let original: runtime::Runtime =
        serde_json::from_value(evidence.records[0].details["runtime"].clone())?;
    let mut reasons = Vec::new();
    if !original.previous_session_ended(&now)? {
        reasons.push("original helper session is still alive");
    }
    if evidence.records[0].details["policy_sha256"] != serde_json::to_value(policy_sha256)? {
        reasons.push("helper policy changed since authorization");
    }
    if evidence
        .records
        .iter()
        .any(|r| matches!(r.state.as_str(), "released" | "reconciled"))
    {
        reasons.push("operation already has a terminal record");
    }
    let mut pending = None;
    for record in &evidence.records {
        if record.state == "tool-intent" {
            if pending.is_some() {
                return Err(refused("overlapping workspace tool intents"));
            }
            let phase = record.details["stage"]
                .as_str()
                .ok_or_else(|| refused("workspace tool stage missing"))?;
            if !matches!(
                phase,
                "scratch-format"
                    | "scratch-check-before"
                    | "scratch-check-after"
                    | "output-format"
                    | "output-check-before"
                    | "output-check-after"
            ) {
                return Err(refused("unknown workspace tool stage"));
            }
            pending = Some(phase);
        } else if record.state == "tool-result" {
            if pending.is_none() || pending != record.details["stage"].as_str() {
                return Err(refused("unmatched workspace tool result"));
            }
            pending = None;
        }
    }
    if pending.is_some() {
        reasons.push("tool exit was not recorded; quiescence is unproven");
    }
    let owner = evidence.identity.uid;
    let mut images = serde_json::Map::new();
    let mut loops = serde_json::Map::new();
    let mut numbers = Vec::new();
    for role in ["scratch", "output"] {
        let allocations: Vec<_> = evidence
            .records
            .iter()
            .filter(|r| r.state == "image-allocated" && r.details["role"] == role)
            .collect();
        if allocations.len() > 1 {
            return Err(refused("ambiguous workspace allocation identity"));
        }
        if let Some(record) = allocations.first() {
            let image = evidence::open(&evidence.directory, &format!("{role}.img"), false)?;
            let identity = Identity::read(&image, owner, false)?;
            let expected_bytes = if role == "scratch" {
                budget.scratch_bytes
            } else {
                budget.output_bytes
            };
            if record.details["device"].as_u64() != Some(identity.device)
                || record.details["inode"].as_u64() != Some(identity.inode)
                || record.details["bytes"].as_u64() != Some(identity.bytes)
                || identity.bytes != expected_bytes
            {
                return Err(refused(
                    "workspace image changed since allocation",
                ));
            }
            images.insert(role.into(), serde_json::to_value(identity)?);
        } else {
            reasons.push("workspace allocation identity is missing");
        }
        let intents: Vec<_> = evidence
            .records
            .iter()
            .filter(|r| r.state == "loop-configure-intent" && r.details["role"] == role)
            .collect();
        if intents.len() > 1 {
            return Err(refused("ambiguous workspace loop intent"));
        }
        if let Some(record) = intents.first() {
            let number = record.details["loop_number"]
                .as_u64()
                .filter(|n| u32::try_from(*n).is_ok())
                .ok_or_else(|| refused("invalid workspace loop number"))?;
            if numbers.contains(&number) {
                return Err(refused("aliased workspace loop records"));
            }
            numbers.push(number);
            if runtime::bounded("/sys/module/loop/parameters/max_part")? != b"0\n" {
                return Err(refused("loop partition policy changed"));
            }
            let base = format!("/sys/dev/block/7:{number}");
            let backing =
                std::path::Path::new(&format!("{base}/loop/backing_file")).try_exists()?;
            let size = runtime::bounded(&format!("{base}/size"))?;
            if backing || size != b"0\n" {
                reasons.push("workspace loop has not completed teardown");
            }
            loops.insert(role.into(),serde_json::json!({"number":number,"backing_present":backing,"size_sectors":std::str::from_utf8(&size).map_err(io::Error::other)?}));
        }
    }
    for record in &evidence.records {
        if matches!(
            record.state.as_str(),
            "image-allocated" | "loop-configure-intent"
        ) && !matches!(
            record.details["role"].as_str(),
            Some("scratch" | "output")
        ) {
            return Err(refused("workspace evidence has an unknown role"));
        }
    }
    let plan = serde_json::json!({"version":1,"id":id,"action":if reasons.is_empty() {"reconcile-retained-workspace"} else {"blocked"},"reasons":reasons,"policy_sha256":crate::hex(&policy_sha256),"journal_sha256":evidence.sha256,"operation":evidence.identity,"state_directory":Identity::read(state,state.metadata()?.uid(),true)?,"images":images,"loops":loops,"layout_sha256":layout_sha256,"boot_id":now.boot_id,"pid_namespace":now.pid_namespace,"original_session":original,"image_retained":true,"filesystem_health_verified":false});
    Ok((
        plan,
        evidence.directory,
        u32::try_from(evidence.records.len()).map_err(io::Error::other)?,
    ))
}

fn hash(plan: &serde_json::Value) -> io::Result<String> {
    let mut hash = Sha256::new();
    hash.update(b"syrox-private-workspace-recovery-plan-v1\n");
    hash.update(serde_json::to_vec(plan)?);
    Ok(crate::hex(&hash.finalize()))
}

#[cfg(test)]
mod tests;

pub(crate) fn serve(
    socket: &File,
    state: &File,
    policy_sha256: [u8; 32],
    id: &str,
    authorization: Option<&str>,
) -> io::Result<()> {
    let (plan, directory, sequence) = inspect(state, id, policy_sha256)?;
    let pin = hash(&plan)?;
    let Some(authorization) = authorization else {
        return wire::reply_value(
            socket,
            &serde_json::json!({"version":1,"plan":plan,"plan_sha256":pin}),
        );
    };
    if plan["action"] != "reconcile-retained-workspace" || authorization != pin {
        return Err(refused(
            "workspace recovery plan is blocked or stale",
        ));
    }
    if hash(&inspect(state, id, policy_sha256)?.0)? != pin {
        return Err(refused(
            "workspace recovery evidence changed during authorization",
        ));
    }
    let mut journal = Journal::resume(directory, sequence);
    let record = journal.record("reconciled",serde_json::json!({"id":id,"plan_sha256":pin,"plan":plan,"image_retained":true,"filesystem_health_verified":false}))?;
    wire::reply(socket, record)
}
