use crate::result::artifact;
use std::io::{self, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{
    BuildError, BuildPart, BuildPath, BuildProfile, BuildProgram, BuildSourceFormat, BuildStep,
    BuildText, group,
};

mod files;
mod operations;
mod system;
pub(crate) use system::run as run_system;

#[cfg(test)]
mod tests;

/// Runs only in the supervisor's private root. stdout carries framed artifacts;
/// process output and diagnostics go exclusively to stderr.
pub(crate) fn run(source_directory: &str, action: &str) -> Result<(), BuildError> {
    verify_confinement()
        .map_err(|error| BuildError::Execution(format!("build confinement: {error}")))?;
    run_profile(
        source_directory,
        action,
        BuildProfile::HostBootstrap,
        || Ok(()),
    )
}

/// Executes only in a dedicated worker child, never the supervisor or PID 1.
/// This establishes confinement, not journal or result-publication authority.
///
/// # Safety
/// The caller must be a dedicated single-threaded process and exit after return.
#[expect(
    unsafe_code,
    reason = "unsafe fn: installs process-wide managed build confinement policy"
)]
pub(crate) unsafe fn run_managed(source_directory: &str, action: &str) -> Result<(), BuildError> {
    crate::execution::native::build_policy::validate_environment()?;
    run_profile(
        source_directory,
        action,
        BuildProfile::Managed,
        || {
            // SAFETY: inherited dedicated-process contract; no payload has run.
            unsafe {
                crate::execution::native::build_policy::install()?;
            }
            verify_confinement()
        },
    )
}

fn verify_confinement() -> Result<(), BuildError> {
    let status = std::fs::read_to_string("/proc/self/status")?;
    for required in [
        "NoNewPrivs:\t1",
        "Seccomp:\t2",
        "CapEff:\t0000000000000000",
        "CapBnd:\t0000000000000000",
    ] {
        if !status.lines().any(|line| line == required) {
            return Err(BuildError::UnsupportedPlatform);
        }
    }
    Ok(())
}

fn run_profile(
    source_directory: &str,
    action: &str,
    expected: BuildProfile,
    install_policy: impl FnOnce() -> Result<(), BuildError>,
) -> Result<(), BuildError> {
    if !super::relative_path(source_directory) || source_directory.contains('/') {
        return Err(BuildError::InvalidRequest);
    }
    let mut bytes = Vec::new();
    std::fs::File::open("/build-program")
        .map_err(|error| BuildError::Execution(format!("open build program: {error}")))?
        .take(super::MAX_BUILD_PROGRAM_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let program = BuildProgram::decode(&bytes)?;
    if program.profile != expected {
        return Err(BuildError::UnsupportedProfile);
    }
    let action: crate::store::ContentDigest = action
        .parse()
        .map_err(|_| BuildError::InvalidRequest)?;
    let mut bindings = Vec::new();
    std::fs::File::open("/build-action")
        .map_err(|error| BuildError::Execution(format!("open build action: {error}")))?
        .take(super::records::MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bindings)?;
    let description = super::records::Action::parse(&bindings)?;
    if description.digest() != action
        || description.program != program
        || description.directory != source_directory
    {
        return Err(BuildError::InvalidRequest);
    }
    verify_profile(&program, description.toolchain, expected)?;
    install_policy()?;
    let paths = Paths {
        work: "/work".into(),
        source: "/source".into(),
        output: format!("/out/syrox/store/{action}").into(),
        installed: format!("/syrox/store/{action}").into(),
        inputs: description
            .inputs
            .iter()
            .map(|input| format!("/syrox/store/{}/{}", input.action, input.output).into())
            .collect(),
    };
    crate::platform::linux::fd::become_build_subreaper()
        .map_err(|error| BuildError::Execution(format!("build subreaper: {error}")))?;
    execute(&program, &paths, settle_build_descendants)
        .map_err(|error| BuildError::Execution(format!("build instructions: {error}")))?;
    verify_install_layout(&action.to_string(), &program.outputs)
        .map_err(|error| BuildError::Execution(format!("build output layout: {error}")))?;
    let outputs = program
        .outputs
        .iter()
        .filter(|name| *name == "out")
        .chain(
            program
                .outputs
                .iter()
                .filter(|name| *name != "out"),
        )
        .map(|name| (name.as_str(), paths.output.join(name)))
        .collect::<Vec<_>>();
    for (_, directory) in &outputs {
        normalize_hardlinks(directory).map_err(|error| {
            BuildError::Execution(format!("build hardlink normalization: {error}"))
        })?;
    }
    group::pack(
        &outputs
            .iter()
            .map(|(name, path)| (*name, path.as_path()))
            .collect::<Vec<_>>(),
        &mut io::stdout().lock(),
    )
    .map_err(|error| BuildError::Execution(format!("build artifact collection: {error}")))
}

fn verify_profile(
    program: &BuildProgram,
    toolchain: Option<crate::store::ContentDigest>,
    expected: BuildProfile,
) -> Result<(), BuildError> {
    if program.profile != expected
        || toolchain.is_some() != (expected == BuildProfile::HostBootstrap)
    {
        return Err(BuildError::UnsupportedProfile);
    }
    program.validate()
}

pub(in crate::build) struct Paths {
    pub work: PathBuf,
    pub source: PathBuf,
    pub output: PathBuf,
    pub installed: PathBuf,
    pub inputs: Vec<PathBuf>,
}
impl Paths {
    fn path(&self, value: &BuildPath) -> Result<PathBuf, BuildError> {
        let join = |root: PathBuf, relative: &str| {
            if relative.is_empty() {
                root
            } else {
                root.join(relative)
            }
        };
        Ok(match value {
            BuildPath::Host(value) => value.into(),
            BuildPath::Work(value) => join(self.work.clone(), value),
            BuildPath::Source => self.source.clone(),
            BuildPath::Output {
                name,
                path,
            } => join(self.output.join(name), path),
            BuildPath::Installed {
                name,
                path,
            } => join(self.installed.join(name), path),
            BuildPath::Input {
                index,
                path,
            } => join(
                self.inputs
                    .get(*index as usize)
                    .ok_or(BuildError::UnsupportedInputs)?
                    .clone(),
                path,
            ),
        })
    }
    fn text(&self, value: &BuildText) -> Result<String, BuildError> {
        let mut text = String::new();
        for part in &value.0 {
            match part {
                BuildPart::Literal(value) => text.push_str(value),
                BuildPart::Path(value) => text.push_str(
                    self.path(value)?
                        .to_str()
                        .ok_or(BuildError::InvalidRequest)?,
                ),
            }
        }
        Ok(text)
    }
}

pub(in crate::build) fn execute(
    program: &BuildProgram,
    paths: &Paths,
    settle: impl FnMut() -> Result<(), BuildError>,
) -> Result<(), BuildError> {
    execute_with_limits(
        program,
        paths,
        None,
        &crate::cancellation::Cancellation::default(),
        settle,
    )
}

pub(in crate::build) fn execute_system_program(
    action: &crate::build::system::SystemBuildAction,
    paths: &Paths,
    cancellation: &crate::cancellation::Cancellation,
    settle: impl FnMut() -> Result<(), BuildError>,
) -> Result<(), BuildError> {
    execute_with_limits(
        action.program(),
        paths,
        Some(action),
        cancellation,
        settle,
    )
}

fn system_geometry(
    layout: &crate::system::workspace::WorkspaceLayout,
    destination: &BuildPath,
) -> Result<crate::system::ext4_tool::Geometry, BuildError> {
    match destination {
        BuildPath::Work(_) => Ok(layout.scratch_geometry()),
        BuildPath::Output {
            ..
        } => Ok(layout.output_geometry()),
        _ => Err(BuildError::InvalidRequest),
    }
}

fn execute_with_limits(
    program: &BuildProgram,
    paths: &Paths,
    system: Option<&crate::build::system::SystemBuildAction>,
    cancellation: &crate::cancellation::Cancellation,
    mut settle: impl FnMut() -> Result<(), BuildError>,
) -> Result<(), BuildError> {
    cancellation.check()?;
    program.validate()?;
    let layout = system
        .map(crate::build::system::SystemBuildAction::workspace_layout)
        .transpose()?;
    for output in &program.outputs {
        std::fs::create_dir_all(paths.output.join(output))?;
    }
    for step in &program.steps {
        cancellation.check()?;
        match step {
            BuildStep::Run(process) => {
                let mut command = command(program.profile, paths.path(&process.executable)?);
                for arg in &process.arguments {
                    command.arg(paths.text(arg)?);
                }
                for (key, value) in &process.environment {
                    command.env(key, paths.text(value)?);
                }
                command.current_dir(paths.path(&process.directory)?);
                run_command(&command)?;
            }
            BuildStep::Write {
                path,
                text,
                executable,
            } => {
                let text = paths.text(text)?;
                if let Some(layout) = &layout
                    && text.len() as u64 > system_geometry(layout, path)?.image_bytes()
                {
                    return Err(BuildError::Output);
                }
                let path = paths.path(path)?;
                std::fs::create_dir_all(path.parent().ok_or(BuildError::InvalidRequest)?)?;
                std::fs::write(&path, text)?;
                std::fs::set_permissions(
                    path,
                    std::fs::Permissions::from_mode(if *executable {
                        0o755
                    } else {
                        0o644
                    }),
                )?;
            }
            BuildStep::Directory(path) => std::fs::create_dir_all(paths.path(path)?)?,
            BuildStep::Copy {
                source,
                destination,
            }
            | BuildStep::Move {
                source,
                destination,
            } => {
                let check = &mut || {
                    if cancellation.is_cancelled() {
                        Err(crate::cancellation::cancellation_io())
                    } else {
                        Ok(())
                    }
                };
                if let Some(layout) = &layout {
                    let geometry = system_geometry(layout, destination)?;
                    files::transfer_bounded(
                        &paths.path(source)?,
                        &paths.path(destination)?,
                        matches!(step, BuildStep::Move { .. }),
                        files::TransferLimits {
                            entries: usize::try_from(geometry.requested_inodes().min(1_000_000))
                                .map_err(|_| BuildError::Output)?,
                            bytes: geometry.image_bytes(),
                        },
                        check,
                    )?;
                } else {
                    files::transfer(
                        &paths.path(source)?,
                        &paths.path(destination)?,
                        matches!(step, BuildStep::Move { .. }),
                        program.resources,
                        check,
                    )?;
                }
            }
            BuildStep::ValidateStaticElf(path) => {
                operations::validate_static_elf(&paths.path(path)?)?;
            }
            BuildStep::ReplaceShebang {
                path,
                expected,
                interpreter,
            } => {
                operations::replace_shebang(
                    &paths.path(path)?,
                    expected,
                    &paths.path(interpreter)?,
                )?;
            }
            BuildStep::Extract(destination) => {
                let destination_kind = destination;
                let destination = paths.path(destination)?;
                let directory = crate::platform::linux::fd::tree::Directory::ensure(&destination)?;
                let (parent, name) =
                    crate::platform::linux::fd::tree::Directory::parent(&paths.source)?;
                if let Some(action) = system {
                    use crate::acquire::archive::{
                        ArchiveFormat, SystemArchiveLimits, SystemArchiveRole,
                        extract_system_archive,
                    };
                    let role = match destination_kind {
                        BuildPath::Work(_) => SystemArchiveRole::Scratch,
                        BuildPath::Output {
                            ..
                        } => SystemArchiveRole::Output,
                        _ => return Err(BuildError::InvalidRequest),
                    };
                    let format = match program.source_format {
                        BuildSourceFormat::Gzip => ArchiveFormat::GzipTar,
                        BuildSourceFormat::Xz => ArchiveFormat::XzTar,
                        BuildSourceFormat::Raw => return Err(BuildError::InvalidRequest),
                    };
                    let limits = SystemArchiveLimits::for_role(
                        action.budget(),
                        action.source_limit(),
                        format,
                        role,
                    )?;
                    extract_system_archive(
                        parent.read_file(&name)?,
                        &limits,
                        directory.as_fd(),
                        cancellation,
                    )?;
                    settle()?;
                    continue;
                }
                let (format, limits) = match program.source_format {
                    BuildSourceFormat::Gzip => (
                        crate::acquire::archive::ArchiveFormat::GzipTar,
                        crate::acquire::archive::ArchiveLimits::small_gzip(),
                    ),
                    BuildSourceFormat::Xz => (
                        crate::acquire::archive::ArchiveFormat::XzTar,
                        crate::acquire::archive::ArchiveLimits::large_xz(),
                    ),
                    BuildSourceFormat::Raw => return Err(BuildError::InvalidRequest),
                };
                crate::acquire::archive::extract::extract_archive(
                    parent.read_file(&name)?,
                    format,
                    limits,
                    directory.as_fd(),
                    &crate::cancellation::Cancellation::default(),
                )?;
            }
        }
        // No following filesystem operation or publication races a background
        // descendant. The supervisor applies cancellation and the total deadline.
        settle()?;
    }
    cancellation.check()?;
    Ok(())
}

fn command(profile: BuildProfile, program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env(
            "PATH",
            match profile {
                BuildProfile::HostBootstrap => "/usr/bin:/bin",
                BuildProfile::Managed => "",
            },
        )
        .env("LC_ALL", "C")
        .env("HOME", "/tmp")
        .env("SOURCE_DATE_EPOCH", "0");
    command
}
fn run_command(command: &Command) -> Result<(), BuildError> {
    let status = crate::platform::linux::fd::run_build_command(command)?;
    if !status.success() {
        return Err(BuildError::Execution(format!(
            "{}: {status}",
            command.get_program().to_string_lossy()
        )));
    }
    Ok(())
}
fn settle_build_descendants() -> Result<(), BuildError> {
    while let Some(status) = crate::platform::linux::fd::reap_build_descendant()? {
        if !status.success() {
            return Err(BuildError::Execution(format!(
                "background build descendant: {status}"
            )));
        }
    }
    Ok(())
}

fn normalize_hardlinks(root: &Path) -> Result<(), BuildError> {
    normalize_hardlinks_bounded(root, artifact::MAX_FILES, &mut 0)
}
fn normalize_hardlinks_bounded(
    root: &Path,
    maximum: usize,
    visited: &mut usize,
) -> Result<(), BuildError> {
    use std::os::unix::fs::MetadataExt as _;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            *visited += 1;
            if *visited > maximum {
                return Err(BuildError::Output);
            }
            let path = entry?.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() && metadata.nlink() > 1 {
                let temporary = path.with_extension("syrox-copy");
                let mut output = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&temporary)?;
                io::copy(&mut std::fs::File::open(&path)?, &mut output)?;
                output.set_permissions(std::fs::Permissions::from_mode(
                    metadata.mode() & 0o777,
                ))?;
                output.sync_all()?;
                std::fs::rename(temporary, path)?;
            }
        }
    }
    Ok(())
}

fn verify_install_layout(action: &str, outputs: &[String]) -> Result<(), BuildError> {
    verify_install_layout_with_metadata(action, outputs, false)
}

fn verify_system_install_layout(action: &str, outputs: &[String]) -> Result<(), BuildError> {
    verify_install_layout_with_metadata(action, outputs, true)
}

fn verify_install_layout_with_metadata(
    action: &str,
    outputs: &[String],
    ext4_metadata: bool,
) -> Result<(), BuildError> {
    let overflow = if ext4_metadata {
        let value = |path| -> Result<u32, BuildError> {
            std::fs::read_to_string(path)?
                .trim()
                .parse()
                .map_err(|_| BuildError::Output)
        };
        Some((
            value("/proc/sys/kernel/overflowuid")?,
            value("/proc/sys/kernel/overflowgid")?,
        ))
    } else {
        None
    };
    let mut path = PathBuf::from("/out");
    for name in ["syrox", "store", action] {
        let mut entries = std::fs::read_dir(&path)?.filter_map(|entry| {
            if ext4_metadata
                && path == Path::new("/out")
                && entry
                    .as_ref()
                    .is_ok_and(|e| e.file_name() == "lost+found")
            {
                use std::os::unix::fs::MetadataExt as _;
                let validated = entry
                    .and_then(|e| std::fs::symlink_metadata(e.path()))
                    .and_then(|m| {
                        if m.is_dir()
                            && m.ino() == 11
                            && m.mode() & 0o7777 == 0o700
                            && overflow == Some((m.uid(), m.gid()))
                        {
                            Ok(())
                        } else {
                            Err(io::Error::other(
                                "unexpected ext4 recovery directory",
                            ))
                        }
                    });
                match validated {
                    Ok(()) => None,
                    Err(e) => Some(Err(e)),
                }
            } else {
                Some(entry)
            }
        });
        let entry = entries.next().ok_or(BuildError::Output)??;
        if entry.file_name() != name || entries.next().is_some() {
            return Err(BuildError::Output);
        }
        path.push(name);
        if !std::fs::symlink_metadata(&path)?.is_dir() {
            return Err(BuildError::Output);
        }
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            return Err(BuildError::Output);
        }
        names.push(
            entry
                .file_name()
                .into_string()
                .map_err(|_| BuildError::Output)?,
        );
    }
    names.sort();
    if names != outputs {
        return Err(BuildError::Output);
    }
    Ok(())
}
