//! Comparing descriptors retained by the manager in its FD store.
//!
//! The dump allows inode and flag checks. It identifies neither the open file
//! description nor who holds the flock. Retention still requires checking the
//! descriptor and the interest that was transferred.
//!
//! Reference: <https://raw.githubusercontent.com/systemd/systemd/v254/src/core/dbus-service.c>.

use super::bus::Reply;
use super::{Budget, SERVICE_INTERFACE, SystemdError, SystemdManager, SystemdUnitName};
use crate::cancellation::Cancellation;
use std::time::Duration;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FdStoreEntry {
    pub(crate) name: String,
    pub(crate) mode: u32,
    pub(crate) device_major: u32,
    pub(crate) device_minor: u32,
    pub(crate) inode: u64,
    pub(crate) special_major: u32,
    pub(crate) special_minor: u32,
    pub(crate) flags: u32,
}
#[derive(Debug)]
pub(crate) struct FdStoreEntries {
    pub(crate) invocation: Vec<u8>,
    pub(crate) entries: Vec<FdStoreEntry>,
}
impl SystemdManager {
    /// Bounded read-only metadata observation. Unsupported managers fail closed;
    /// count-only observations are never substituted for descriptor metadata.
    pub(crate) fn query_fd_store_entries(
        &mut self,
        unit: &SystemdUnitName,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<FdStoreEntries, SystemdError> {
        let budget = Budget::new(timeout, cancellation)?;
        let identity = self.observe_identity_with(&budget)?;
        let before = self
            .query_with(unit, &budget)?
            .ok_or_else(changed)?;
        let mut call = self.bus.manager_method("GetUnit")?;
        call.string(unit.as_str())?;
        let path = self.bus.call(call, &budget)?.single_object()?;
        if !path.starts_with("/org/freedesktop/systemd1/unit/") {
            return Err(changed());
        }
        let call = self.bus.method(
            identity.owner(),
            &path,
            SERVICE_INTERFACE,
            "DumpFileDescriptorStore",
        )?;
        let reply = self.bus.call(call, &budget).map_err(capability)?;
        let entries = decode(&reply)?;
        let after = self
            .query_with(unit, &budget)?
            .ok_or_else(changed)?;
        if before.invocation.len() != 16
            || before.invocation.iter().all(|byte| *byte == 0)
            || before.invocation != after.invocation
            || before.main_pid != after.main_pid
            || before.control_group != after.control_group
            || self.observe_identity_with(&budget)? != identity
        {
            return Err(changed());
        }
        budget.check()?;
        Ok(FdStoreEntries {
            invocation: after.invocation,
            entries,
        })
    }
}
fn decode(reply: &Reply) -> Result<Vec<FdStoreEntry>, SystemdError> {
    if reply.0.signature != "a(suuutuusu)" {
        return Err(changed());
    }
    let mut reader = reply.0.reader();
    let end = reader.array_end(8)?;
    let mut entries = Vec::new();
    while reader.pos < end {
        if entries.len() >= 2 {
            return Err(changed());
        }
        reader.align(8)?;
        let name = reader.string()?.to_owned();
        if name.is_empty()
            || name.len() > 255
            || name
                .bytes()
                .any(|byte| !byte.is_ascii_graphic() || byte == b':')
        {
            return Err(changed());
        }
        let entry = FdStoreEntry {
            name,
            mode: reader.u32()?,
            device_major: reader.u32()?,
            device_minor: reader.u32()?,
            inode: reader.u64()?,
            special_major: reader.u32()?,
            special_minor: reader.u32()?,
            flags: {
                // Informational path is bounded by the wire decoder and deliberately
                // discarded: it is neither identity nor filesystem authority.
                reader.string()?;
                reader.u32()?
            },
        };
        if entries
            .iter()
            .any(|previous: &FdStoreEntry| previous.name == entry.name)
        {
            return Err(changed());
        }
        entries.push(entry);
    }
    if reader.pos != end {
        return Err(changed());
    }
    reader.end()?;
    Ok(entries)
}
fn capability(error: SystemdError) -> SystemdError {
    if matches!(&error,SystemdError::Remote{name,..} if name=="org.freedesktop.DBus.Error.UnknownMethod")
    {
        SystemdError::Invalid(
            "Managed build FD store identity requires DumpFileDescriptorStore (systemd >=254)",
        )
    } else {
        error
    }
}
fn changed() -> SystemdError {
    SystemdError::Protocol("FD store identity observation is malformed or changed")
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::systemd::wire::{Frame, Writer};
    fn reply(names: &[&str]) -> Reply {
        let mut w = Writer::default();
        w.array(8, |w| {
            for name in names {
                w.align(8);
                w.string(name)?;
                w.u32(0o100_400);
                w.u32(8);
                w.u32(1);
                w.align(8);
                w.0.extend(123_u64.to_le_bytes());
                w.u32(0);
                w.u32(0);
                w.string("/untrusted/path/hint")?;
                w.u32(0);
            }
            Ok(())
        })
        .unwrap();
        Reply(Frame {
            kind: 2,
            reply: 1,
            sender: ":1.2".into(),
            path: String::new(),
            interface: String::new(),
            member: String::new(),
            error: String::new(),
            signature: "a(suuutuusu)".into(),
            body: w.0,
            little: true,
        })
    }
    #[test]
    fn decoder_keeps_identity_and_discards_path_authority() {
        let entries = decode(&reply(&["retention"])).unwrap();
        assert_eq!(
            entries,
            vec![FdStoreEntry {
                name: "retention".into(),
                mode: 0o100_400,
                device_major: 8,
                device_minor: 1,
                inode: 123,
                special_major: 0,
                special_minor: 0,
                flags: 0
            }]
        );
        assert!(decode(&reply(&[])).unwrap().is_empty());
        assert_eq!(
            decode(&reply(&["retention", "namespace"]))
                .unwrap()
                .len(),
            2
        );
    }
    #[test]
    fn decoder_rejects_surplus_duplicate_malformed_and_truncated_entries() {
        assert!(decode(&reply(&["a", "b", "c"])).is_err());
        assert!(decode(&reply(&["a", "a"])).is_err());
        assert!(decode(&reply(&["bad:name"])).is_err());
        assert!(decode(&reply(&[""])).is_err());
        let mut bad = reply(&["a"]);
        bad.0.signature = "a(st)".into();
        assert!(decode(&bad).is_err());
        let mut bad = reply(&["a"]);
        bad.0.body.pop();
        assert!(decode(&bad).is_err());
        let mut bad = reply(&["a"]);
        bad.0.body.push(0);
        assert!(decode(&bad).is_err());
    }
    #[test]
    fn missing_capability_is_explicit_and_never_count_fallback() {
        let missing = capability(SystemdError::Remote {
            name: "org.freedesktop.DBus.Error.UnknownMethod".into(),
            message: "not supported".into(),
        });
        assert!(missing.to_string().contains("systemd >=254"));
        assert!(matches!(
            capability(SystemdError::Cancelled),
            SystemdError::Cancelled
        ));
        assert!(matches!(
            capability(SystemdError::Remote {
                name: "denied".into(),
                message: String::new()
            }),
            SystemdError::Remote { .. }
        ));
    }
}
