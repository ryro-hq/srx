use crate::system::image::{LayoutEntry, LayoutKind, validate_layout};

use super::{
    BTreeSet, Decoder, PlanError, PlanOutputRef, PlanSystem, Value, absolute,
    decode_nominal_string, name,
};
use super::{PlanSystemBoot, PlanSystemHealth, PlanSystemIdentity, PlanSystemUser};

impl Decoder<'_, '_> {
    pub(super) fn system(
        &mut self,
        component: &super::super::recipes::Component<'_>,
    ) -> Result<PlanSystem, PlanError> {
        let fields = self.fields(
            component.value(),
            "System",
            &[
                "platform",
                "kernel",
                "userspace",
                "identity",
                "directories",
                "exposures",
                "links",
                "boot",
                "storage",
                "services",
                "health",
                "budget",
            ],
        )?;
        if !matches!(
            self.variant(&fields[0].1, "SystemPlatform")?,
            (0, [])
        ) {
            return Err(self.error("platform", "only Linux x86_64 is supported"));
        }
        let kernel = self.kernel(&fields[1].1)?;
        let values = self.list(&fields[2].1, "userspace", 4096)?;
        let mut userspace = self
            .budget
            .collection::<PlanOutputRef>(values.len())?;
        for value in values {
            userspace.push(self.output(value)?);
        }
        if userspace.is_empty()
            || userspace.iter().collect::<BTreeSet<_>>().len() != userspace.len()
        {
            return Err(self.error(
                "userspace",
                "expected unique explicit component outputs",
            ));
        }
        let identity = self.identity(&fields[3].1)?;
        let layout = self.tree_paths(&fields[4].1, &fields[5].1, &fields[6].1)?;
        let boot = self.fields(
            &fields[7].1,
            "SystemBoot",
            &["signing_credential", "attempts"],
        )?;
        let credential = self.string(&boot[0].1, "CredentialReference")?;
        let attempts = self.u32(&boot[1].1, "SystemCount")?;
        if !name(&credential) || !(1..=15).contains(&attempts) {
            return Err(self.error(
                "boot",
                "expected a signing credential reference and 1..=15 attempts",
            ));
        }
        let boot = PlanSystemBoot {
            signing_credential: credential,
            attempts,
        };
        let super::storage::StorageSelection {
            layout: storage,
            root_a,
            root_b,
            esp,
            persistent,
        } = self.storage(&fields[8].1)?;
        let services = self.services(component, &fields[9].1)?;
        let health = self.fields(
            &fields[10].1,
            "SystemHealth",
            &[
                "timeout_seconds",
                "essential_services",
                "require_network",
            ],
        )?;
        let timeout = self.u32(&health[0].1, "SystemSeconds")?;
        if timeout == 0 || timeout > 3600 {
            return Err(self.error(
                "health.timeout_seconds",
                "expected 1..=3600 seconds",
            ));
        }
        let mut essential = BTreeSet::new();
        let values = self.list(&health[1].1, "health.essential_services", 4096)?;
        let mut essential_services = self.budget.collection::<String>(values.len())?;
        for value in values {
            let id = decode_nominal_string(value, &["std", "deployment", "ServiceId"])
                .ok_or_else(|| self.error("health", "expected a typed service id"))?;
            if !essential.insert(id)
                || !services
                    .services()
                    .iter()
                    .any(|service| service.id() == id)
            {
                return Err(self.error(
                    "health.essential_services",
                    "unknown or duplicate essential service",
                ));
            }
            essential_services.push(self.budget.string(id)?);
        }
        let health = PlanSystemHealth {
            timeout_seconds: timeout,
            essential_services,
            require_network: self.boolean(&health[2].1)?,
        };
        let budget = self.build_budget(&fields[11].1)?;
        Ok(PlanSystem {
            name: self.budget.string(component.name())?,
            kernel,
            userspace,
            identity,
            layout,
            storage,
            root_a,
            root_b,
            esp,
            persistent,
            boot,
            health,
            budget,
            services,
        })
    }

    fn identity(&mut self, value: &Value) -> Result<PlanSystemIdentity, PlanError> {
        let fields = self.fields(value, "SystemIdentity", &["hostname", "users"])?;
        let hostname = self.string(&fields[0].1, "SystemName")?;
        if hostname.is_empty()
            || hostname.len() > 253
            || !hostname.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(self.error(
                "identity.hostname",
                "expected a lowercase DNS hostname",
            ));
        }
        let mut names = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let values = self.list(&fields[1].1, "identity.users", 1024)?;
        let mut users = self
            .budget
            .collection::<PlanSystemUser>(values.len())?;
        for value in values {
            let fields = self.fields(
                value,
                "SystemUser",
                &[
                    "name",
                    "uid",
                    "gid",
                    "home",
                    "shell",
                    "authorized_keys",
                    "password",
                ],
            )?;
            let user = self.string(&fields[0].1, "SystemName")?;
            let uid = self.u32(&fields[1].1, "SystemUserId")?;
            let gid = self.u32(&fields[2].1, "SystemUserId")?;
            if !name(&user)
                || !names.insert(user.clone())
                || !ids.insert(uid)
                || uid == u32::MAX
                || gid == u32::MAX
                || (uid == 0) != (user == "root")
            {
                return Err(self.error(
                    "identity.users",
                    "invalid or duplicate user identity",
                ));
            }
            let home = self.string(&fields[3].1, "SystemPath")?;
            let shell = self.string(&fields[4].1, "SystemPath")?;
            for path in [&home, &shell] {
                if !absolute(path) {
                    return Err(self.error(
                        "identity.users",
                        "home and shell require canonical absolute paths",
                    ));
                }
            }
            let values = self.list(&fields[5].1, "identity.authorized_keys", 128)?;
            let mut authorized_keys = self.budget.collection::<String>(values.len())?;
            for key in values {
                let key = self.string(key, "SystemText")?;
                if key.is_empty() || key.chars().any(char::is_control) {
                    return Err(self.error(
                        "identity.authorized_keys",
                        "expected one public key per entry",
                    ));
                }
                authorized_keys.push(key);
            }
            let password_credential = self
                .optional(&fields[6].1)?
                .map(|value| self.string(value, "CredentialReference"))
                .transpose()?;
            if password_credential
                .as_deref()
                .is_some_and(|value| !name(value))
            {
                return Err(self.error(
                    "identity.password",
                    "expected a credential reference",
                ));
            }
            users.push(PlanSystemUser {
                name: user,
                uid,
                gid,
                home,
                shell,
                authorized_keys,
                password_credential,
            });
        }
        Ok(PlanSystemIdentity {
            hostname,
            users,
        })
    }

    fn tree_paths(
        &mut self,
        directories: &Value,
        exposures: &Value,
        links: &Value,
    ) -> Result<super::PlanSystemLayout, PlanError> {
        let mut paths = std::collections::BTreeMap::new();
        let values = self.list(directories, "directories", 65536)?;
        let mut planned_directories = self
            .budget
            .collection::<super::PlanSystemDirectory>(values.len())?;
        for value in values {
            let fields = self.fields(
                value,
                "SystemDirectory",
                &["path", "uid", "gid", "mode"],
            )?;
            let path = self.string(&fields[0].1, "SystemPath")?;
            let metadata = self.metadata(&fields[1..], true)?;
            if !absolute(&path) || paths.insert(path.clone(), true).is_some() {
                return Err(self.error("directories", "invalid or duplicate destination"));
            }
            planned_directories.push(super::PlanSystemDirectory {
                path,
                metadata,
            });
        }
        let values = self.list(exposures, "exposures", 65536)?;
        let mut planned_exposures = self
            .budget
            .collection::<super::PlanSystemExposure>(values.len())?;
        for value in values {
            let fields = self.fields(
                value,
                "SystemExposure",
                &[
                    "source",
                    "destination",
                    "uid",
                    "gid",
                    "mode",
                ],
            )?;
            let source = self.file(&fields[0].1)?;
            let path = self.string(&fields[1].1, "SystemPath")?;
            let metadata = self.metadata(&fields[2..], true)?;
            if !absolute(&path) || paths.insert(path.clone(), false).is_some() {
                return Err(self.error("exposures", "invalid or colliding destination"));
            }
            planned_exposures.push(super::PlanSystemExposure {
                source,
                destination: path,
                metadata,
            });
        }
        let values = self.list(links, "links", 65536)?;
        let mut planned_links = self
            .budget
            .collection::<super::PlanSystemLink>(values.len())?;
        for value in values {
            let fields = self.fields(
                value,
                "SystemLink",
                &["path", "target", "uid", "gid"],
            )?;
            let path = self.string(&fields[0].1, "SystemPath")?;
            let target = self.string(&fields[1].1, "SystemPath")?;
            let metadata = self.metadata(&fields[2..], false)?;
            if !absolute(&path)
                || target.is_empty()
                || target.chars().any(char::is_control)
                || paths.insert(path.clone(), false).is_some()
            {
                return Err(self.error("links", "invalid or colliding link destination"));
            }
            planned_links.push(super::PlanSystemLink {
                path,
                target,
                uid: metadata.uid,
                gid: metadata.gid,
            });
        }
        if paths.get("/") != Some(&true) {
            return Err(self.error(
                "directories",
                "the root directory must be declared",
            ));
        }
        for path in paths.keys().filter(|path| path.as_str() != "/") {
            let parent = path.rsplit_once('/').expect("absolute path").0;
            let parent = if parent.is_empty() {
                "/"
            } else {
                parent
            };
            if paths.get(parent) != Some(&true) {
                return Err(self.error(
                    "directories",
                    "every exposure/link/directory requires an explicit directory parent",
                ));
            }
        }
        let layout = super::PlanSystemLayout {
            directories: planned_directories,
            exposures: planned_exposures,
            links: planned_links,
        };
        let paths = layout
            .directories
            .iter()
            .map(|entry| LayoutEntry {
                path: &entry.path,
                kind: LayoutKind::Directory,
            })
            .chain(layout.exposures.iter().map(|entry| LayoutEntry {
                path: &entry.destination,
                kind: LayoutKind::File,
            }))
            .chain(layout.links.iter().map(|entry| LayoutEntry {
                path: &entry.path,
                kind: LayoutKind::Symlink(&entry.target),
            }));
        validate_layout(paths).map_err(|error| self.error("layout", error.to_string()))?;
        Ok(layout)
    }

    fn metadata(
        &mut self,
        fields: &[(String, Value)],
        mode: bool,
    ) -> Result<super::FileMetadata, PlanError> {
        let uid = self.u32(&fields[0].1, "SystemUserId")?;
        let gid = self.u32(&fields[1].1, "SystemUserId")?;
        if uid == u32::MAX || gid == u32::MAX {
            return Err(self.error("ownership", "invalid uid/gid sentinel"));
        }
        let mode = if mode {
            self.u32(&fields[2].1, "SystemMode")?
        } else {
            0o777
        };
        if mode > 0o7777 {
            return Err(self.error("permissions", "mode contains non-permission bits"));
        }
        Ok(super::FileMetadata {
            uid,
            gid,
            mode,
        })
    }
}
