//! Both roots travel to the worker; the one-shot control lease stays outside.

use super::{
    HelperClient, RecoveryInspection, connection::Connection, hash, invalid, record, validate_hash,
    validate_id,
};
use crate::{
    helper_protocol::Request,
    workspace::{ReceivedWorkspace, WorkspaceLayout, WorkspaceObservation},
};
use std::{fs::File, io, time::Instant};

#[derive(Debug)]
pub struct WorkspaceGrant {
    scratch: File,
    output: File,
    observation: WorkspaceObservation,
    lease: WorkspaceLease,
}

#[derive(Debug)]
pub struct WorkspaceLease {
    connection: Connection,
    id: String,
    authorization: String,
    layout: WorkspaceLayout,
}

impl HelperClient {
    /// Root independently admits the same request under its own policy. The
    /// caller layout binds its separately admitted policy; echoing its digest
    /// never permits larger helper geometry or changes root authorization.
    pub fn prepare_workspace(
        self,
        id: &str,
        layout: &WorkspaceLayout,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<WorkspaceGrant> {
        validate_id(id)?;
        let layout_sha256 = hex(layout.digest());
        self.connection.send(
            &Request::PrepareWorkspace {
                version: 1,
                id: id.into(),
                budget: *layout.budget().request(),
                layout_sha256,
            },
            &mut check,
            deadline,
        )?;
        let response = self.connection.response(&mut check, deadline)?;
        let details = record(&response, "offered", id)?;
        let authorization = hash(&details["authorization"])?;
        let budget: crate::budget::BuildBudget = serde_json::from_value(details["budget"].clone())?;
        if budget != *layout.budget().request() {
            return Err(invalid(
                "helper workspace budget differs from request",
            ));
        }
        let observation: WorkspaceObservation =
            serde_json::from_value(details["observation"].clone())?;
        if observation.layout_sha256 != layout.digest() {
            return Err(invalid(
                "helper workspace layout differs from request",
            ));
        }
        let scratch = File::from(self.connection.receive(&mut check, deadline)?);
        let output = File::from(self.connection.receive(&mut check, deadline)?);
        ReceivedWorkspace::from_authorized_roots(
            layout,
            &observation,
            scratch.try_clone()?,
            output.try_clone()?,
        )?;
        check()?;
        Ok(WorkspaceGrant {
            scratch,
            output,
            observation,
            lease: WorkspaceLease {
                connection: self.connection,
                id: id.into(),
                authorization,
                layout: *layout,
            },
        })
    }

    pub fn inspect_workspace(
        self,
        id: &str,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<RecoveryInspection> {
        validate_id(id)?;
        self.connection.send(
            &Request::InspectWorkspace {
                version: 1,
                id: id.into(),
            },
            &mut check,
            deadline,
        )?;
        let response = self.connection.response(&mut check, deadline)?;
        let plan = &response["plan"];
        if response["version"] != 1
            || plan["version"] != 1
            || plan["id"] != id
            || !matches!(
                plan["action"].as_str(),
                Some("blocked" | "reconcile-retained-workspace")
            )
            || plan["image_retained"] != true
            || plan["filesystem_health_verified"] != false
        {
            return Err(invalid(
                "inconsistent workspace recovery inspection",
            ));
        }
        Ok(RecoveryInspection {
            plan: plan.clone(),
            plan_sha256: hash(&response["plan_sha256"])?,
        })
    }

    pub fn recover_workspace(
        self,
        id: &str,
        plan_sha256: &str,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<serde_json::Value> {
        validate_id(id)?;
        validate_hash(plan_sha256)?;
        self.connection.send(
            &Request::RecoverWorkspace {
                version: 1,
                id: id.into(),
                plan_sha256: plan_sha256.into(),
            },
            &mut check,
            deadline,
        )?;
        let response = self.connection.response(&mut check, deadline)?;
        let details = record(&response, "reconciled", id)?;
        if details["plan_sha256"] != plan_sha256
            || details["image_retained"] != true
            || details["filesystem_health_verified"] != false
            || details["plan"]["action"] != "reconcile-retained-workspace"
        {
            return Err(invalid(
                "workspace reconciliation differs from authorization",
            ));
        }
        Ok(response)
    }
}

impl WorkspaceGrant {
    pub const fn observation(&self) -> &WorkspaceObservation {
        &self.observation
    }
    /// Save the authenticated observation before splitting. Close every root,
    /// file, copied description and worker namespace before releasing control.
    pub fn into_parts(self) -> (File, File, WorkspaceLease) {
        (self.scratch, self.output, self.lease)
    }
}
impl WorkspaceLease {
    pub const fn layout(&self) -> &WorkspaceLayout {
        &self.layout
    }
    /// Drop never sends release or retries. A failed call consumes the lease;
    /// inspect/reconcile uncertain evidence explicitly through a new session.
    pub fn release(
        self,
        mut check: impl FnMut() -> io::Result<()>,
        deadline: Instant,
    ) -> io::Result<serde_json::Value> {
        self.connection.send(
            &Request::ReleaseWorkspace {
                version: 1,
                id: self.id.clone(),
                authorization: self.authorization.clone(),
            },
            &mut check,
            deadline,
        )?;
        let response = self.connection.response(&mut check, deadline)?;
        let details = record(&response, "released", &self.id)?;
        if details["authorization"] != self.authorization
            || details["layout_sha256"] != hex(self.layout.digest())
            || details["image_retained"] != true
            || details["images"] != 2
        {
            return Err(invalid(
                "workspace release receipt differs from authorization",
            ));
        }
        Ok(response)
    }
}
fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(64);
    for byte in bytes {
        write!(&mut text, "{byte:02x}").unwrap();
    }
    text
}
