use super::error::{RuntimeError, invalid};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::File;
use std::os::fd::{AsFd as _, BorrowedFd};
use std::path::{Path, PathBuf};

pub(crate) const MAX_CONFIGURATION_ENTRIES: usize = 1024;
pub(crate) const MAX_CONFIGURATION_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_CONFIGURATION_DEPTH: usize = 32;
pub(crate) const MAX_RUNTIME_ENVIRONMENT_ENTRIES: usize = 128;
pub(crate) const MAX_RUNTIME_ENVIRONMENT_VALUE: usize = 4096;
pub(crate) const MAX_RUNTIME_ENVIRONMENT_BYTES: usize = 64 * 1024;

/// Public, immutable configuration files. Managed sessions attach private
/// sealed descriptors internally; environment values remain public configuration.
#[derive(Default)]
pub struct RuntimeConfiguration {
    pub(crate) directory: Option<crate::platform::linux::fd::OpenedPath>,
    prefix: Option<String>,
    pub(crate) secrets: Vec<(String, File)>,
    pub(crate) state: Option<(String, crate::platform::linux::fd::OpenedPath)>,
    pub(crate) environment: BTreeMap<String, String>,
}
impl std::fmt::Debug for RuntimeConfiguration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeConfiguration")
            .field("has_directory", &self.directory.is_some())
            .field("environment_entries", &self.environment.len())
            .field("secret_entries", &self.secrets.len())
            .finish_non_exhaustive()
    }
}
impl RuntimeConfiguration {
    pub fn new(
        service: impl Into<String>,
        directory: File,
        environment: BTreeMap<String, String>,
    ) -> Result<Self, RuntimeError> {
        let service = service.into();
        if !valid_service_name(&service) {
            return Err(invalid("invalid configuration service name"));
        }
        validate_environment(&environment)?;
        let pinned = validate_configuration_directory(directory.as_fd())?;
        drop(directory);
        Ok(Self {
            directory: Some(pinned),
            prefix: Some(format!("/syrox/config/{service}")),
            environment,
            state: None,
            secrets: Vec::new(),
        })
    }
    /// Internal session-owned mutable data; never a public configuration file.
    pub(crate) fn with_session_state(
        mut self,
        service: &str,
        descriptor: BorrowedFd<'_>,
    ) -> Result<Self, RuntimeError> {
        if !valid_service_name(service) || self.state.is_some() {
            return Err(invalid("invalid session state attachment"));
        }
        let directory = validate_state_directory(descriptor)?;
        self.state = Some((format!("/syrox/state/{service}"), directory));
        Ok(self)
    }
    pub(crate) fn with_secret(
        mut self,
        service: &str,
        name: &str,
        fd: BorrowedFd<'_>,
    ) -> Result<Self, RuntimeError> {
        let target = format!("/syrox/secrets/{service}/{name}");
        if !valid_secret_target(Path::new(&target))
            || self.secrets.len() >= 32
            || self
                .secrets
                .iter()
                .any(|(path, _)| path == &target)
        {
            return Err(invalid("invalid secret attachment"));
        }
        crate::platform::linux::fd::sealed_file::validate(fd)?;
        self.secrets
            .push((target, File::from(fd.try_clone_to_owned()?)));
        Ok(self)
    }
    pub fn prefix(&self) -> Option<&str> {
        self.prefix.as_deref()
    }
    pub(crate) fn validate_cwd(&self, cwd: &Path) -> Result<(), RuntimeError> {
        if let Some(directory) = &self.directory {
            let path = crate::platform::linux::fd::directory_path(directory)
                .map_err(|_| invalid("configuration directory identity changed"))?;
            if paths_overlap(cwd, &path) {
                return Err(invalid(
                    "runtime working directory would expose configuration",
                ));
            }
        }
        if let Some((_, directory)) = &self.state {
            let path = crate::platform::linux::fd::directory_path(directory)?;
            if paths_overlap(cwd, &path) {
                return Err(invalid(
                    "working directory overlaps session state",
                ));
            }
        }
        Ok(())
    }
}
pub(crate) fn validate_state_directory(
    descriptor: BorrowedFd<'_>,
) -> Result<crate::platform::linux::fd::OpenedPath, RuntimeError> {
    let directory = crate::platform::linux::fd::open_beneath(descriptor, Path::new("."), true)
        .map_err(|_| invalid("invalid session state directory"))?;
    if !directory.metadata().is_trusted_directory() || directory.metadata().mode() & 0o7777 != 0o700
    {
        return Err(invalid(
            "session state must be an owned mode 0700 directory",
        ));
    }
    crate::execution::resources::validate_managed_working_descriptor(directory.fd())?;
    Ok(directory)
}
pub(crate) fn valid_runtime_environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i != 0 && b.is_ascii_digit()))
        && ![
            "PATH",
            "LANG",
            "LANGUAGE",
            "LOCPATH",
            "GCONV_PATH",
            "GLIBC_TUNABLES",
            "NOTIFY_SOCKET",
            "INVOCATION_ID",
        ]
        .contains(&name)
        && ![
            "LD_",
            "DYLD_",
            "LC_",
            "SYROX_",
            "LISTEN_",
            "WATCHDOG_",
            "MALLOC_",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}
fn validate_environment(environment: &BTreeMap<String, String>) -> Result<(), RuntimeError> {
    if environment.len() > MAX_RUNTIME_ENVIRONMENT_ENTRIES {
        return Err(invalid("runtime environment count exceeded"));
    }
    let mut total = 0;
    for (name, value) in environment {
        if !valid_runtime_environment_name(name)
            || value.len() > MAX_RUNTIME_ENVIRONMENT_VALUE
            || value.as_bytes().contains(&0)
        {
            return Err(invalid("invalid runtime environment entry"));
        }
        total += name.len() + value.len() + 2;
    }
    if total > MAX_RUNTIME_ENVIRONMENT_BYTES {
        return Err(invalid("runtime environment byte limit exceeded"));
    }
    Ok(())
}
fn valid_service_name(service: &str) -> bool {
    !service.is_empty()
        && service.len() <= 128
        && (service.as_bytes()[0].is_ascii_lowercase() || service.as_bytes()[0].is_ascii_digit())
        && service.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
}

pub(crate) fn paths_overlap(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
pub(crate) fn validate_configuration_directory(
    fd: BorrowedFd<'_>,
) -> Result<crate::platform::linux::fd::OpenedPath, RuntimeError> {
    let root = crate::platform::linux::fd::open_beneath(fd, Path::new("."), true)
        .map_err(|_| invalid("configuration root must be an opened directory"))?;
    let mut entries = 0;
    let mut bytes = 0;
    validate_tree(&root, 0, &mut entries, &mut bytes)?;
    Ok(root)
}
fn validate_tree(
    directory: &crate::platform::linux::fd::OpenedPath,
    depth: usize,
    entries: &mut usize,
    bytes: &mut u64,
) -> Result<(), RuntimeError> {
    let metadata = directory.metadata();
    if depth > MAX_CONFIGURATION_DEPTH
        || !metadata.is_trusted_directory()
        || metadata.mode() & 0o777 != 0o500
    {
        return Err(invalid(
            "configuration directory must be private and immutable",
        ));
    }
    let names = crate::platform::linux::fd::read_directory(directory, |_| {
        *entries += 1;
        if *entries > MAX_CONFIGURATION_ENTRIES {
            Err(())
        } else {
            Ok(())
        }
    })
    .map_err(|_| invalid("configuration entry limit or directory read failed"))?;
    for name in names {
        let opened =
            crate::platform::linux::fd::open_beneath(directory.fd(), Path::new(&name), false)
                .map_err(|_| invalid("invalid configuration file"))?;
        let metadata = opened.metadata();
        match metadata.file_type() {
            crate::platform::linux::fd::FileType::Directory => {
                validate_tree(&opened, depth + 1, entries, bytes)?;
            }
            crate::platform::linux::fd::FileType::Regular => {
                if !metadata.is_trusted_regular() || metadata.mode() & 0o777 != 0o400 {
                    return Err(invalid(
                        "configuration file must be private, immutable and not hard linked",
                    ));
                }
                *bytes = bytes
                    .checked_add(metadata.size())
                    .filter(|size| *size <= MAX_CONFIGURATION_BYTES)
                    .ok_or_else(|| invalid("configuration byte limit exceeded"))?;
            }
            crate::platform::linux::fd::FileType::Other => {
                return Err(invalid(
                    "configuration supports only regular files and directories",
                ));
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MountKind {
    Output,
    Configuration,
    Secret,
    Working,
    State,
    Mask,
}
#[derive(Debug)]
pub(crate) struct WorkerMount {
    pub kind: MountKind,
    pub source: PathBuf,
    pub target: PathBuf,
}
#[derive(Debug)]
pub(crate) struct WorkerRequest {
    pub terminal: Option<i32>,
    pub mounts: Vec<WorkerMount>,
    pub cwd: PathBuf,
    pub locale: Option<OsString>,
    pub environment: BTreeMap<String, String>,
    pub program: OsString,
    pub arguments: Vec<OsString>,
}
fn absolute(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && !path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}
fn descriptor_path(path: &Path) -> bool {
    path.to_str()
        .and_then(|s| s.strip_prefix("/proc/self/fd/"))
        .and_then(|s| {
            s.parse::<u32>()
                .ok()
                .map(|n| n >= 3 && n.to_string() == s)
        })
        .unwrap_or(false)
}
fn output_path(path: &Path) -> bool {
    let Some(parts) = path
        .to_str()
        .and_then(|s| s.strip_prefix("/syrox/store/"))
    else {
        return false;
    };
    let Some((digest, output)) = parts.split_once('/') else {
        return false;
    };
    digest.len() == 64
        && digest.bytes().all(|b| b.is_ascii_hexdigit())
        && !output.is_empty()
        && output
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        && output != "."
        && output != ".."
}
impl WorkerRequest {
    pub fn parse(args: &[OsString]) -> Result<Self, RuntimeError> {
        let terminal = terminal_descriptor(args)?;
        let mut at = 0;
        let mut cwd = None;
        let mut locale = None;
        let mut environment = BTreeMap::new();
        let mut mounts = Vec::new();
        let mut targets = BTreeSet::new();
        let mut config = false;
        while at < args.len() && args[at] != "--" {
            let option = args[at]
                .to_str()
                .ok_or_else(|| invalid("invalid runtime option"))?;
            let value = args
                .get(at + 1)
                .ok_or_else(|| invalid("truncated runtime option"))?;
            match option {
                "--terminal" => {
                    at += 2;
                }
                "--cwd" => {
                    if cwd.replace(PathBuf::from(value)).is_some() {
                        return Err(invalid("duplicate runtime cwd"));
                    }
                    at += 2;
                }
                "--locale" => {
                    if locale.replace(value.clone()).is_some() {
                        return Err(invalid("duplicate runtime locale"));
                    }
                    at += 2;
                }
                "--env" => {
                    insert_environment(&mut environment, value)?;
                    at += 2;
                }
                "--ro" | "--secret-ro" | "--config-ro" | "--state-rw" | "--rw" | "--mask" => {
                    if mounts.len() >= MAX_CONFIGURATION_ENTRIES {
                        return Err(invalid("runtime mount count exceeded"));
                    }
                    let kind = match option {
                        "--ro" => MountKind::Output,
                        "--config-ro" => MountKind::Configuration,
                        "--secret-ro" => MountKind::Secret,
                        "--state-rw" => MountKind::State,
                        "--rw" => MountKind::Working,
                        _ => MountKind::Mask,
                    };
                    let target = if kind == MountKind::Mask {
                        PathBuf::from(value)
                    } else {
                        PathBuf::from(
                            args.get(at + 2)
                                .ok_or_else(|| invalid("missing runtime mount target"))?,
                        )
                    };
                    if !absolute(&target)
                        || !targets.insert(target.clone())
                        || (kind != MountKind::Mask && !descriptor_path(Path::new(value)))
                    {
                        return Err(invalid("invalid or duplicate runtime mount"));
                    }
                    if kind == MountKind::Output && !output_path(&target) {
                        return Err(invalid("invalid output mount target"));
                    }
                    validate_private_mount(kind, &target, &mounts, &mut config)?;
                    at += if kind == MountKind::Mask {
                        2
                    } else {
                        3
                    };
                    mounts.push(WorkerMount {
                        kind,
                        source: PathBuf::from(value),
                        target,
                    });
                }
                _ => return Err(invalid("unknown runtime option")),
            }
        }
        let cwd = cwd.ok_or_else(|| invalid("runtime cwd missing"))?;
        validate_mounts(&mounts, &cwd, locale.as_deref())?;
        let program = parse_program(args, at, &mounts)?;
        Ok(Self {
            terminal,
            mounts,
            cwd,
            locale,
            environment,
            program,
            arguments: args[at + 2..].to_vec(),
        })
    }
}

pub(crate) fn valid_secret_target(target: &Path) -> bool {
    let Some(rest) = target
        .to_str()
        .and_then(|s| s.strip_prefix("/syrox/secrets/"))
    else {
        return false;
    };
    let Some((service, name)) = rest.split_once('/') else {
        return false;
    };
    crate::config::secrets::valid_name(service) && crate::config::secrets::valid_name(name)
}
fn validate_private_mount(
    kind: MountKind,
    target: &Path,
    mounts: &[WorkerMount],
    config: &mut bool,
) -> Result<(), RuntimeError> {
    if kind == MountKind::Secret
        && (!valid_secret_target(target)
            || mounts
                .iter()
                .filter(|m| m.kind == MountKind::Secret)
                .count()
                >= 32)
    {
        return Err(invalid("invalid secret mount"));
    }
    if kind == MountKind::State {
        let service = target
            .to_str()
            .and_then(|s| s.strip_prefix("/syrox/state/"))
            .filter(|s| valid_service_name(s));
        if service.is_none()
            || mounts
                .iter()
                .any(|m: &WorkerMount| m.kind == MountKind::State)
        {
            return Err(invalid(
                "invalid or duplicate session state mount",
            ));
        }
    }
    if kind == MountKind::Configuration {
        let service = target
            .to_str()
            .and_then(|s| s.strip_prefix("/syrox/config/"))
            .filter(|s| valid_service_name(s));
        if *config || service.is_none() {
            return Err(invalid("invalid configuration mount target"));
        }
        *config = true;
    }
    Ok(())
}

/// Scan only worker options, stopping before literal payload arguments.
pub(crate) fn terminal_descriptor(args: &[OsString]) -> Result<Option<i32>, RuntimeError> {
    let mut terminal = None;
    let mut at = 0;
    while at < args.len() && args[at] != "--" {
        let option = args[at]
            .to_str()
            .ok_or_else(|| invalid("invalid runtime option"))?;
        let count = match option {
            "--ro" | "--secret-ro" | "--config-ro" | "--state-rw" | "--rw" => 3,
            "--cwd" | "--locale" | "--env" | "--mask" => 2,
            "--terminal" => {
                let fd = args
                    .get(at + 1)
                    .and_then(|v| v.to_str())
                    .and_then(|v| v.parse::<i32>().ok())
                    .filter(|fd| *fd >= 3)
                    .ok_or_else(|| invalid("invalid terminal descriptor"))?;
                if terminal.replace(fd).is_some() {
                    return Err(invalid("duplicate terminal descriptor"));
                }
                2
            }
            _ => return Err(invalid("invalid runtime option")),
        };
        at += count;
    }
    Ok(terminal)
}

fn parse_program(
    args: &[OsString],
    at: usize,
    mounts: &[WorkerMount],
) -> Result<OsString, RuntimeError> {
    if args.get(at).is_none_or(|value| value != "--") {
        return Err(invalid("runtime command separator missing"));
    }
    let program = args
        .get(at + 1)
        .ok_or_else(|| invalid("runtime program missing"))?;
    if !absolute(Path::new(program))
        || !mounts.iter().any(|mount| {
            mount.kind == MountKind::Output && Path::new(program).starts_with(&mount.target)
        })
    {
        return Err(invalid(
            "program must belong to a verified output",
        ));
    }
    Ok(program.clone())
}

fn insert_environment(
    environment: &mut BTreeMap<String, String>,
    value: &std::ffi::OsStr,
) -> Result<(), RuntimeError> {
    let (name, value) = value
        .to_str()
        .and_then(|v| v.split_once('='))
        .ok_or_else(|| invalid("invalid runtime environment entry"))?;
    if !valid_runtime_environment_name(name)
        || value.len() > MAX_RUNTIME_ENVIRONMENT_VALUE
        || value.contains('\0')
    {
        return Err(invalid("invalid runtime environment entry"));
    }
    if environment
        .insert(name.to_owned(), value.to_owned())
        .is_some()
    {
        return Err(invalid("duplicate runtime environment entry"));
    }
    validate_environment(environment)
}

fn validate_mounts(
    mounts: &[WorkerMount],
    cwd: &Path,
    locale: Option<&std::ffi::OsStr>,
) -> Result<(), RuntimeError> {
    if !absolute(cwd) || cwd.starts_with("/syrox") {
        return Err(invalid("invalid runtime cwd"));
    }
    let mut writable = 0;
    for mount in mounts {
        match mount.kind {
            MountKind::Working => {
                writable += 1;
                if mount.target != *cwd {
                    return Err(invalid("writable mount must equal cwd"));
                }
            }
            MountKind::Mask => {
                if mount.target == *cwd || !mount.target.starts_with(cwd) {
                    return Err(invalid("mask must be beneath cwd"));
                }
            }
            _ => {
                if paths_overlap(&mount.target, cwd) {
                    return Err(invalid("mount overlaps cwd"));
                }
            }
        }
    }
    if writable != 1 {
        return Err(invalid("exactly one writable cwd mount required"));
    }
    if let Some(locale) = locale {
        let locale = Path::new(locale);
        if !absolute(locale)
            || !mounts
                .iter()
                .any(|m| m.kind == MountKind::Output && locale.starts_with(&m.target))
        {
            return Err(invalid("locale must belong to a verified output"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    fn arguments() -> Vec<OsString> {
        let prefix = format!("/syrox/store/{}/out", "a".repeat(64));
        [
            "--ro".into(),
            "/proc/self/fd/7".into(),
            prefix.clone(),
            "--rw".into(),
            "/proc/self/fd/8".into(),
            "/work".into(),
            "--cwd".into(),
            "/work".into(),
            "--".into(),
            format!("{prefix}/bin/app"),
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }
    fn option(args: &mut Vec<OsString>, values: &[&str]) {
        args.splice(0..0, values.iter().map(OsString::from));
    }
    #[test]
    fn session_state_parser_rejects_ambient_paths_duplicates_and_invalid_targets() {
        let mut valid = arguments();
        option(
            &mut valid,
            &[
                "--state-rw",
                "/proc/self/fd/10",
                "/syrox/state/database",
            ],
        );
        let request = WorkerRequest::parse(&valid).unwrap();
        assert!(
            request
                .mounts
                .iter()
                .any(|mount| mount.kind == MountKind::State)
        );
        for target in [
            "/host/state",
            "/syrox/state/../other",
            "/syrox/state/a/b",
            "/syrox/config/database",
        ] {
            let mut args = arguments();
            option(
                &mut args,
                &["--state-rw", "/proc/self/fd/10", target],
            );
            assert!(WorkerRequest::parse(&args).is_err());
        }
        option(
            &mut valid,
            &[
                "--state-rw",
                "/proc/self/fd/11",
                "/syrox/state/other",
            ],
        );
        assert!(WorkerRequest::parse(&valid).is_err());
        let mut args = arguments();
        option(
            &mut args,
            &[
                "--state-rw",
                "/host/state",
                "/syrox/state/database",
            ],
        );
        assert!(WorkerRequest::parse(&args).is_err());
    }

    #[test]
    fn terminal_descriptor_is_explicit_unique_and_not_a_payload_argument() {
        let mut args = arguments();
        option(&mut args, &["--terminal", "9"]);
        assert_eq!(
            WorkerRequest::parse(&args).unwrap().terminal,
            Some(9)
        );
        option(&mut args, &["--terminal", "10"]);
        assert!(WorkerRequest::parse(&args).is_err());
        for value in [
            "-1",
            "0",
            "1",
            "2",
            "invalid",
            "2147483648",
        ] {
            let mut args = arguments();
            option(&mut args, &["--terminal", value]);
            assert!(WorkerRequest::parse(&args).is_err());
        }
        let mut args = arguments();
        args.extend(["--terminal".into(), "2".into()]);
        let parsed = WorkerRequest::parse(&args).unwrap();
        assert_eq!(parsed.terminal, None);
        assert_eq!(
            parsed.arguments,
            vec![
                OsString::from("--terminal"),
                OsString::from("2")
            ]
        );
    }

    #[test]
    fn explicit_environment_is_bounded_and_cannot_replace_runtime_authority() {
        let mut args = arguments();
        option(
            &mut args,
            &[
                "--env",
                "APP_CONFIG=/syrox/config/service/config",
            ],
        );
        let parsed = WorkerRequest::parse(&args).unwrap();
        assert_eq!(
            parsed.environment["APP_CONFIG"],
            "/syrox/config/service/config"
        );
        for name in [
            "PATH",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "LC_ALL",
            "LANG",
            "LANGUAGE",
            "LOCPATH",
            "GCONV_PATH",
            "GLIBC_TUNABLES",
            "MALLOC_CHECK_",
            "SYROX_CONFIG",
            "LISTEN_FDS",
            "NOTIFY_SOCKET",
            "WATCHDOG_USEC",
            "INVOCATION_ID",
            "1BAD",
        ] {
            let mut args = arguments();
            option(
                &mut args,
                &[
                    "--env",
                    &format!("{name}=private-value"),
                ],
            );
            let error = WorkerRequest::parse(&args).unwrap_err();
            assert!(!error.to_string().contains("private-value"));
        }
        let mut args = arguments();
        option(&mut args, &["--env", "APP=X", "--env", "APP=Y"]);
        assert!(WorkerRequest::parse(&args).is_err());
        let mut env = BTreeMap::from([(
            "APP".into(),
            "x".repeat(MAX_RUNTIME_ENVIRONMENT_VALUE + 1),
        )]);
        assert!(validate_environment(&env).is_err());
        env = BTreeMap::from([("APP".into(), "nul\0".into())]);
        assert!(validate_environment(&env).is_err());
        for n in 0..=MAX_RUNTIME_ENVIRONMENT_ENTRIES {
            env.insert(format!("KEY{n}"), String::new());
        }
        assert!(validate_environment(&env).is_err());
    }
    #[test]
    fn configuration_mounts_cannot_escape_or_overlap_runtime_targets() {
        for target in [
            "/outside",
            "/syrox/config/../store",
            "/syrox/config/a/b",
            "/syrox/config/.",
            "/syrox/config/..",
        ] {
            let mut args = arguments();
            option(
                &mut args,
                &["--config-ro", "/proc/self/fd/9", target],
            );
            assert!(WorkerRequest::parse(&args).is_err());
        }
        let mut args = arguments();
        option(
            &mut args,
            &[
                "--config-ro",
                "/host/mutable",
                "/syrox/config/service",
            ],
        );
        assert!(WorkerRequest::parse(&args).is_err());
        let mut args = arguments();
        option(
            &mut args,
            &[
                "--config-ro",
                "/proc/self/fd/9",
                "/syrox/config/a.b",
            ],
        );
        assert!(WorkerRequest::parse(&args).is_ok());
        option(
            &mut args,
            &[
                "--config-ro",
                "/proc/self/fd/10",
                "/syrox/config/other",
            ],
        );
        assert!(WorkerRequest::parse(&args).is_err());
        let mut args = arguments();
        option(&mut args, &["--locale", "/host/locale"]);
        assert!(WorkerRequest::parse(&args).is_err());
        let mut args = arguments();
        *args.last_mut().unwrap() = format!(
            "/syrox/store/{}/out/../../../config/a",
            "a".repeat(64)
        )
        .into();
        assert!(WorkerRequest::parse(&args).is_err());
    }
    #[test]
    fn configuration_pins_private_read_only_files_and_redacts_debug() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("config");
        std::fs::create_dir(&root).unwrap();
        let path = root.join("app.conf");
        std::fs::write(&path, "public configuration").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
        let config = RuntimeConfiguration::new(
            "service",
            File::open(&root).unwrap(),
            BTreeMap::from([("APP_CONFIG".into(), "do-not-log-value".into())]),
        )
        .unwrap();
        assert_eq!(config.prefix(), Some("/syrox/config/service"));
        assert!(!format!("{config:?}").contains("do-not-log-value"));
        assert!(config.validate_cwd(temp.path()).is_err());
        assert!(config.validate_cwd(&root.join("nested")).is_err());
        assert!(
            config
                .validate_cwd(Path::new("/unrelated"))
                .is_ok()
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(
            RuntimeConfiguration::new(
                "service",
                File::open(&root).unwrap(),
                BTreeMap::new()
            )
            .is_err()
        );
    }
}

#[cfg(test)]
mod filesystem_tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    #[test]
    fn pinned_configuration_does_not_follow_a_replaced_host_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config");
        std::fs::create_dir(&path).unwrap();
        let file = path.join("value");
        std::fs::write(&file, "original").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        let configuration = RuntimeConfiguration::new(
            "service",
            File::open(&path).unwrap(),
            BTreeMap::new(),
        )
        .unwrap();
        let moved = temp.path().join("pinned");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("value"), "replacement").unwrap();
        let directory = configuration.directory.as_ref().unwrap();
        let mut original =
            crate::platform::linux::fd::open_beneath(directory.fd(), Path::new("value"), false)
                .unwrap()
                .into_file();
        let mut bytes = String::new();
        original.read_to_string(&mut bytes).unwrap();
        assert_eq!(bytes, "original");
        configuration.validate_cwd(&path).unwrap();
        assert!(configuration.validate_cwd(&moved).is_err());
        std::fs::set_permissions(&moved, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[test]
    fn linked_configuration_files_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("config");
        std::fs::create_dir(&root).unwrap();
        let source = temp.path().join("external");
        std::fs::write(&source, "data").unwrap();
        std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o400)).unwrap();
        for symbolic in [false, true] {
            let target = root.join("linked");
            if symbolic {
                symlink(&source, &target).unwrap();
            } else {
                std::fs::hard_link(&source, &target).unwrap();
            }
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).unwrap();
            assert!(
                RuntimeConfiguration::new(
                    "service",
                    File::open(&root).unwrap(),
                    BTreeMap::new()
                )
                .is_err()
            );
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::remove_file(&target).unwrap();
        }
    }
}
