use std::path::{Path, PathBuf};
use syrox_engine::{
    cancellation::Cancellation,
    config::UserConfiguration,
    deployment::os::{
        self,
        profile::{self, OsProfile, ProfileScope},
    },
    store::ContentDigest,
};

#[derive(Debug, clap::Args)]
pub(crate) struct InitArguments {
    /// Project and Os output, for example .#os.
    reference: String,
    #[arg(long)]
    name: String,
    #[arg(long, conflicts_with = "system")]
    user: bool,
    /// Use the system manager with the current non-root delegated identity.
    #[arg(long)]
    system: bool,
    #[arg(long)]
    installation: Option<PathBuf>,
    #[arg(long)]
    store: Option<PathBuf>,
    #[arg(long)]
    units: Option<PathBuf>,
    #[arg(long)]
    cwd: Option<PathBuf>,
    #[arg(long, conflicts_with = "system")]
    systemd_user_bus: Option<PathBuf>,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    start_timeout_seconds: u64,
    #[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=60))]
    stop_timeout_seconds: u64,
    #[arg(long)]
    json: bool,
}

pub(super) struct Loaded {
    pub profile: OsProfile,
    path: PathBuf,
}
impl Loaded {
    pub fn check_manager_paths(&self, cancel: &Cancellation) -> Result<(), String> {
        let timeout = std::time::Duration::from_secs(5);
        let mut manager = syrox_engine::systemd::SystemdManager::connect(
            self.profile.manager_scope(),
            timeout,
            cancel,
        )
        .map_err(|error| format!("profile manager is unavailable: {error}"))?;
        let paths = manager
            .unit_paths(timeout, cancel)
            .map_err(|error| error.to_string())?;
        if !paths.contains(&self.profile.units) {
            return Err(format!(
                "profile units directory {} is absent from the manager UnitPath",
                self.profile.units.display()
            ));
        }
        Ok(())
    }
    pub fn load(name: &str, cancel: &Cancellation) -> Result<Self, String> {
        let path = profile_path(name)?;
        let profile = profile::read_os_profile(&path)
            .map_err(|e| format!("cannot load profile {name}: {e}"))?;
        if profile.name != name {
            return Err("profile name differs from its filename".into());
        }
        let loaded = Self {
            profile,
            path,
        };
        loaded.revalidate(cancel)?;
        Ok(loaded)
    }
    pub fn revalidate(&self, cancel: &Cancellation) -> Result<(), String> {
        let current = profile::read_os_profile(&self.path).map_err(|e| e.to_string())?;
        if current != self.profile {
            return Err("profile changed during the operation; retry explicitly".into());
        }
        let installation = os::open_os_installation(
            &self.profile.installation,
            cancel,
            super::deadline(),
        )
        .map_err(|e| e.to_string())?;
        if installation.id() != self.profile.installation_id {
            return Err(
                "profile installation identity differs; existing evidence preserved".into(),
            );
        }
        Ok(())
    }
    pub fn status(&self, cancel: &Cancellation) -> Result<os::OsStatus, String> {
        self.revalidate(cancel)?;
        let status = os::inspect_os_status(
            &self.profile.installation,
            cancel,
            super::deadline(),
        )
        .map_err(|e| e.to_string())?;
        if status.installation != self.profile.installation_id {
            return Err("profile installation identity differs".into());
        }
        Ok(status)
    }
    pub fn authority(&self, status: &os::OsStatus) -> os::OsSelectionAuthority {
        os::OsSelectionAuthority {
            installation: self.profile.installation_id.clone(),
            active_operation: status.active_operation.clone(),
        }
    }
    pub fn request(
        &self,
        candidate: ContentDigest,
        expected: Option<ContentDigest>,
    ) -> os::OsApplyRequest {
        let profile = &self.profile;
        os::OsApplyRequest {
            installation: profile.installation.clone(),
            store: profile.store.clone(),
            units: profile.units.clone(),
            cwd: profile.cwd.clone(),
            candidate,
            expected,
            scope: profile.manager_scope(),
            uid: profile.uid,
            gid: profile.gid,
            start_timeout: std::time::Duration::from_secs(profile.start_timeout_seconds),
            stop_timeout: std::time::Duration::from_secs(profile.stop_timeout_seconds),
        }
    }
}

pub(crate) fn init(arguments: &InitArguments, cancel: &Cancellation) -> Result<u8, String> {
    let syrox_engine::project::reference::ProjectReference::Project {
        path,
        export: Some(output),
    } = syrox_engine::project::reference::parse_project_reference(&arguments.reference)
        .map_err(|e| e.to_string())?
    else {
        return Err("os init requires a project and Os output, for example .#os".into());
    };
    let destination = profile_path(&arguments.name)?;
    if destination
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Err("profile already exists; configuration preserved".into());
    }
    let project = absolute(path)?;
    if !project.is_dir() {
        return Err("profile project directory does not exist".into());
    }
    let (uid, gid) = profile::profile_credentials().map_err(|e| e.to_string())?;
    let state = xdg("XDG_STATE_HOME", ".local/state")?
        .join("syrox/os")
        .join(&arguments.name);
    let installation = absolute(
        arguments
            .installation
            .as_deref()
            .unwrap_or(&state.join("installation")),
    )?;
    let cwd = absolute(
        arguments
            .cwd
            .as_deref()
            .unwrap_or(&state.join("work")),
    )?;
    let units = if let Some(path) = &arguments.units {
        absolute(path)?
    } else if arguments.system {
        return Err("--system requires an explicit delegated --units directory".into());
    } else {
        xdg("XDG_CONFIG_HOME", ".config")?.join("systemd/user")
    };
    let config = arguments
        .config
        .as_deref()
        .map(absolute)
        .transpose()?;
    let store = arguments
        .store
        .as_deref()
        .map(absolute)
        .transpose()?;
    let user = UserConfiguration::load_with_store(config.as_deref(), store.as_deref())
        .map_err(|e| e.to_string())?;
    let scope = if arguments.system {
        ProfileScope::System
    } else {
        ProfileScope::User {
            bus_socket: absolute(
                arguments
                    .systemd_user_bus
                    .as_deref()
                    .unwrap_or(Path::new(&format!("/run/user/{uid}/bus"))),
            )?,
        }
    };
    let mut profile = OsProfile {
        version: 1,
        name: arguments.name.clone(),
        project,
        output: output.into(),
        config,
        installation,
        installation_id: "11111111111111111111111111111111".into(),
        store: absolute(user.store())?,
        units,
        cwd,
        scope,
        uid,
        gid,
        start_timeout_seconds: arguments.start_timeout_seconds,
        stop_timeout_seconds: arguments.stop_timeout_seconds,
    };
    profile.validate().map_err(|e| e.to_string())?;
    for directory in [
        &profile.installation,
        &profile.cwd,
        &profile.units,
    ] {
        profile::ensure_profile_directory(directory).map_err(|e| e.to_string())?;
    }
    let installation =
        os::initialize_os_installation(&profile.installation, cancel, super::deadline())
            .map_err(|e| e.to_string())?;
    profile.installation_id = installation.id().into();
    profile::create_os_profile(&destination, &profile).map_err(|e| e.to_string())?;
    if arguments.json {
        println!(
            "{}",
            serde_json::json!({"profile":profile.name,"path":destination,"installation":profile.installation_id,"configured":true,"applied":false,"manager_verified":false})
        );
    } else {
        println!(
            "profile {} configured at {}\ninstallation {}\napply with: srx os apply --profile {}",
            profile.name,
            destination.display(),
            profile.installation_id,
            profile.name
        );
    }
    Ok(0)
}

fn profile_path(name: &str) -> Result<PathBuf, String> {
    profile::validate_profile_name(name).map_err(|e| e.to_string())?;
    Ok(xdg("XDG_CONFIG_HOME", ".config")?
        .join("syrox/os")
        .join(format!("{name}.json")))
}
fn xdg(variable: &str, fallback: &str) -> Result<PathBuf, String> {
    let path = match std::env::var_os(variable).filter(|s| !s.is_empty()) {
        Some(path) => PathBuf::from(path),
        None => PathBuf::from(
            std::env::var_os("HOME").ok_or("HOME is required when XDG paths are unset")?,
        )
        .join(fallback),
    };
    profile::validate_profile_path(&path).map_err(|e| e.to_string())?;
    Ok(path)
}
fn absolute(path: &Path) -> Result<PathBuf, String> {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("profile paths cannot contain '..'".into());
    }
    let path = std::path::absolute(path)
        .map_err(|e| e.to_string())?
        .components()
        .collect::<PathBuf>();
    profile::validate_profile_path(&path).map_err(|e| e.to_string())?;
    Ok(path)
}
